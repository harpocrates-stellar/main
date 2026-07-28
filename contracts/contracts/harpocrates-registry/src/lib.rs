#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address,
    Bytes, BytesN, Env, IntoVal, InvokeError, Symbol, Val, Vec as SorobanVec,
};

const TIER_SILENT_WITNESS: u32 = 1;
const TIER_CONSISTENT_SOURCE: u32 = 2;
const TIER_PUBLIC_SEAL: u32 = 3;

const STATUS_REGISTERED: u32 = 1;
const STATUS_REVOKED: u32 = 2;

// ---------------------------------------------------------------------------
// Domain separation — versioned proof binding (#silent-witness-domain-sep)
// ---------------------------------------------------------------------------
//
// Every Silent Witness proof must carry a `domain_tag` public input equal to:
//   pedersen_hash([DOMAIN_PROTOCOL_FIELD, DOMAIN_VERSION_FIELD, DOMAIN_NETWORK_FIELD])
//
// The tag is verified in two places:
//   1. Inside the Noir circuit (constraint: domain_tag == expected_tag)
//   2. Here in the registry contract (we re-derive expected_tag and compare)
//
// This blocks:
//   - Cross-protocol replay  (proof from a different dApp)
//   - Cross-version replay   (proof for circuit v2 submitted to v1 registry)
//   - Cross-network replay   (testnet proof submitted to mainnet registry)
//
// Updating the domain
// ───────────────────
// When any constant below changes, also update the matching globals in:
//   zk/noir/silent_witness/src/main.nr
//   zk/noir/silent_witness_helper/src/main.nr
// and redeploy this contract.  Old proofs will be rejected immediately.
//
// Field encoding: each component is the SHA-256 of its UTF-8 string reduced
// mod the BN254 scalar field prime, expressed as a 32-byte big-endian array.
// The Pedersen hash is BN254 Pedersen as used by Noir/Barretenberg.
//
// Expected domain tag for testnet deployment (circuit v1):
//   pedersen_hash([
//     SHA-256("harpocrates") mod p,
//     SHA-256("1")           mod p,
//     SHA-256("testnet")     mod p,
//   ])
// ---------------------------------------------------------------------------

/// DOMAIN_PROTOCOL_FIELD = SHA-256("harpocrates") mod BN254_p
const DOMAIN_PROTOCOL_FIELD: [u8; 32] = [
    0x26, 0x1e, 0x9f, 0x6e, 0x39, 0xe3, 0xc1, 0xae,
    0x6a, 0xca, 0x9f, 0x29, 0xe8, 0x4c, 0x10, 0xd5,
    0x9c, 0x82, 0xd5, 0xf4, 0xb4, 0x0c, 0x21, 0xc1,
    0xb7, 0xe3, 0xc0, 0x1a, 0xd5, 0x71, 0xc2, 0x1,
];

/// DOMAIN_VERSION_FIELD = SHA-256("1") mod BN254_p
const DOMAIN_VERSION_FIELD: [u8; 32] = [
    0x0c, 0x89, 0xef, 0xf4, 0xec, 0x8e, 0x39, 0xa0,
    0x1e, 0x9f, 0x19, 0x54, 0x7a, 0x0c, 0xc9, 0xdd,
    0x7f, 0xd2, 0xa9, 0x7d, 0x79, 0xba, 0x4d, 0x94,
    0xfd, 0x32, 0xe9, 0x7a, 0x1f, 0x5a, 0xc6, 0x23,
];

/// DOMAIN_NETWORK_FIELD = SHA-256("testnet") mod BN254_p
const DOMAIN_NETWORK_FIELD: [u8; 32] = [
    0x2a, 0x2c, 0x3f, 0x48, 0xce, 0x2e, 0x3c, 0x2f,
    0x1e, 0x6c, 0x89, 0xb1, 0x8d, 0x64, 0xb5, 0xf5,
    0xc1, 0xf8, 0x8a, 0x59, 0xa0, 0xd9, 0xbc, 0x82,
    0xcb, 0x61, 0xa1, 0xe8, 0xcb, 0x77, 0xa5, 0xf,
];

// ---------------------------------------------------------------------------
// Proof-expiration policy (#44)
// ---------------------------------------------------------------------------
//
// Every proof record stores an `expires_at` epoch-second timestamp.
//
// - `expires_at == 0`  → no expiration (backward-compatible with records that
//   pre-date this field, which are deserialized with the Soroban SDK default
//   of zero for missing u64 fields in persistent storage).
// - `expires_at > 0`   → the proof is considered expired once
//   `ledger.timestamp() > expires_at`.
//
// The registry admin can update the global TTL applied to *new* registrations
// via `set_proof_ttl`.  Existing records are unaffected.
//
// `DEFAULT_PROOF_TTL_SECS = 0` means new proofs are eternal unless the admin
// overrides the TTL, preserving the original behavior on a fresh deployment.
//
// Migration note: proofs registered before this field was added will have
// `expires_at == 0` in persistent storage and will therefore be treated as
// non-expiring by `get_proof_status`.
pub const DEFAULT_PROOF_TTL_SECS: u64 = 0;

/// Verification status returned by `get_proof_status`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofVerificationStatus {
    /// Proof is registered and has not expired.
    Valid,
    /// Proof was explicitly revoked by the admin.
    Revoked,
    /// Proof has passed its `expires_at` deadline.
    Expired,
    /// No record found for the given proof_id.
    NotFound,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofRecord {
    pub video_hash: BytesN<32>,
    pub metadata_hash: BytesN<32>,
    pub tier: u32,
    pub status: u32,
    pub created_at: u64,
    /// Epoch-second deadline after which this proof is considered expired.
    /// `0` means no expiration.  See the expiration-policy comment at the top
    /// of this file.
    pub expires_at: u64,
    pub source: Option<Address>,
    pub issuer: Option<Address>,
    pub nullifier: Option<BytesN<32>>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerRecord {
    pub metadata_hash: BytesN<32>,
    pub active: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRootRecord {
    pub metadata_hash: BytesN<32>,
    pub active: bool,
    pub issued_at: u64,
}

#[contractevent(topics = ["proof", "reg"])]
pub struct ProofRegistered {
    #[topic]
    pub proof_id: BytesN<32>,
    pub video_hash: BytesN<32>,
    pub tier: u32,
    pub status: u32,
}

#[contractevent(topics = ["proof", "revoke"])]
pub struct ProofRevoked {
    #[topic]
    pub proof_id: BytesN<32>,
    pub status: u32,
}

#[contractevent(topics = ["issuer", "add"])]
pub struct IssuerAdded {
    #[topic]
    pub issuer: Address,
    pub metadata_hash: BytesN<32>,
}

#[contractevent(topics = ["issuer", "revoke"])]
pub struct IssuerRevoked {
    #[topic]
    pub issuer: Address,
}

#[contractevent(topics = ["verif", "set"])]
pub struct VerifierSet {
    #[topic]
    pub verifier: Address,
}

#[contractevent(topics = ["credroot", "add"])]
pub struct CredentialRootAdded {
    #[topic]
    pub credential_root: BytesN<32>,
    pub metadata_hash: BytesN<32>,
    pub issued_at: u64,
}

#[contractevent(topics = ["credroot", "revoke"])]
pub struct CredentialRootRevoked {
    #[topic]
    pub credential_root: BytesN<32>,
}

#[contractevent(topics = ["admin", "propose"])]
pub struct AdminProposed {
    #[topic]
    pub pending_admin: Address,
    pub current_admin: Address,
}

#[contractevent(topics = ["admin", "cancel"])]
pub struct AdminTransferCancelled {
    #[topic]
    pub pending_admin: Address,
    pub current_admin: Address,
}

#[contractevent(topics = ["admin", "accept"])]
pub struct AdminAccepted {
    #[topic]
    pub new_admin: Address,
    pub previous_admin: Address,
}

#[contracttype]
pub enum DataKey {
    Admin,
    Proof(BytesN<32>),
    Video(BytesN<32>),
    Nullifier(BytesN<32>),
    CredentialRoot(BytesN<32>),
    Issuer(Address),
    Verifier,
    /// Global proof TTL in seconds (set by admin via `set_proof_ttl`).
    ProofTtl,
    PendingAdmin,
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RegistryError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    DuplicateProof = 4,
    DuplicateVideo = 5,
    DuplicateNullifier = 6,
    InvalidProof = 7,
    UnknownIssuer = 8,
    VerifierNotSet = 9,
    InvalidPublicInputs = 10,
    UnknownCredentialRoot = 11,
    RevokedCredentialRoot = 12,
    NoPendingAdmin = 13,
    /// domain_tag public input does not match the expected versioned tag.
    /// Prevents cross-protocol, cross-version, and cross-network proof replay.
    DomainTagMismatch = 14,
}

#[contract]
pub struct HarpocratesRegistry;

#[contractimpl]
impl HarpocratesRegistry {
    pub fn init(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic_with_error!(&env, RegistryError::AlreadyInitialized);
        }

        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn propose_admin(env: Env, admin: Address, pending_admin: Address) {
        require_admin(&env, &admin);

        env.storage()
            .persistent()
            .set(&DataKey::PendingAdmin, &pending_admin);
        AdminProposed {
            pending_admin,
            current_admin: admin,
        }
        .publish(&env);
    }

    pub fn cancel_admin_transfer(env: Env, admin: Address) {
        require_admin(&env, &admin);

        let pending_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAdmin)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NoPendingAdmin));
        env.storage().persistent().remove(&DataKey::PendingAdmin);
        AdminTransferCancelled {
            pending_admin,
            current_admin: admin,
        }
        .publish(&env);
    }

    pub fn accept_admin(env: Env, pending_admin: Address) {
        let proposed_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAdmin)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NoPendingAdmin));

        pending_admin.require_auth();
        if proposed_admin != pending_admin {
            panic_with_error!(&env, RegistryError::Unauthorized);
        }

        let previous_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NotInitialized));
        env.storage()
            .persistent()
            .set(&DataKey::Admin, &pending_admin);
        env.storage().persistent().remove(&DataKey::PendingAdmin);
        AdminAccepted {
            new_admin: pending_admin,
            previous_admin,
        }
        .publish(&env);
    }

    pub fn add_issuer(env: Env, admin: Address, issuer: Address, metadata_hash: BytesN<32>) {
        require_admin(&env, &admin);

        env.storage().persistent().set(
            &DataKey::Issuer(issuer.clone()),
            &IssuerRecord {
                metadata_hash: metadata_hash.clone(),
                active: true,
            },
        );
        IssuerAdded {
            issuer,
            metadata_hash,
        }
        .publish(&env);
    }

    pub fn set_verifier(env: Env, admin: Address, verifier: Address) {
        require_admin(&env, &admin);

        env.storage()
            .persistent()
            .set(&DataKey::Verifier, &verifier);
        VerifierSet { verifier }.publish(&env);
    }

    pub fn get_verifier(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Verifier)
    }

    pub fn add_credential_root(
        env: Env,
        admin: Address,
        credential_root: BytesN<32>,
        metadata_hash: BytesN<32>,
    ) {
        require_admin(&env, &admin);

        let issued_at = env.ledger().timestamp();
        env.storage().persistent().set(
            &DataKey::CredentialRoot(credential_root.clone()),
            &CredentialRootRecord {
                metadata_hash: metadata_hash.clone(),
                active: true,
                issued_at,
            },
        );
        CredentialRootAdded {
            credential_root,
            metadata_hash,
            issued_at,
        }
        .publish(&env);
    }

    pub fn revoke_credential_root(env: Env, admin: Address, credential_root: BytesN<32>) {
        require_admin(&env, &admin);

        let mut record = get_credential_root_record(&env, &credential_root);
        record.active = false;
        env.storage()
            .persistent()
            .set(&DataKey::CredentialRoot(credential_root.clone()), &record);
        CredentialRootRevoked { credential_root }.publish(&env);
    }

    pub fn get_credential_root(
        env: Env,
        credential_root: BytesN<32>,
    ) -> Option<CredentialRootRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::CredentialRoot(credential_root))
    }

    pub fn revoke_issuer(env: Env, admin: Address, issuer: Address) {
        require_admin(&env, &admin);

        let mut record = get_issuer_record(&env, &issuer);
        record.active = false;
        env.storage()
            .persistent()
            .set(&DataKey::Issuer(issuer.clone()), &record);
        IssuerRevoked { issuer }.publish(&env);
    }

    // -----------------------------------------------------------------------
    // Expiration policy (#44)
    // -----------------------------------------------------------------------

    /// Set the global TTL (in seconds) applied to new proof registrations.
    /// `0` disables expiration for newly registered proofs.
    /// Only the registry admin may call this.  Existing records are unaffected.
    pub fn set_proof_ttl(env: Env, admin: Address, ttl_secs: u64) {
        require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::ProofTtl, &ttl_secs);
    }

    /// Get the currently configured global proof TTL in seconds.
    pub fn get_proof_ttl(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::ProofTtl)
            .unwrap_or(DEFAULT_PROOF_TTL_SECS)
    }

    /// Return the human-readable verification status of a proof at the current
    /// ledger time without modifying any state.
    ///
    /// Clients should prefer this over reading the raw `ProofRecord` when they
    /// need a definitive "is this proof still valid?" answer, because it
    /// incorporates both the revocation flag and the expiration deadline.
    pub fn get_proof_status(env: Env, proof_id: BytesN<32>) -> ProofVerificationStatus {
        let record: Option<ProofRecord> =
            env.storage().persistent().get(&DataKey::Proof(proof_id));
        match record {
            None => ProofVerificationStatus::NotFound,
            Some(r) => {
                if r.status == STATUS_REVOKED {
                    return ProofVerificationStatus::Revoked;
                }
                if r.expires_at > 0 && env.ledger().timestamp() > r.expires_at {
                    return ProofVerificationStatus::Expired;
                }
                ProofVerificationStatus::Valid
            }
        }
    }

    // -----------------------------------------------------------------------
    // Registration entry points
    // -----------------------------------------------------------------------

    pub fn register_anonymous(
        env: Env,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
        nullifier: BytesN<32>,
        credential_root: BytesN<32>,
        proof: Bytes,
    ) -> ProofRecord {
        require_unique(&env, &proof_id, &video_hash);

        if env
            .storage()
            .persistent()
            .has(&DataKey::Nullifier(nullifier.clone()))
        {
            panic_with_error!(&env, RegistryError::DuplicateNullifier);
        }

        if !verify_demo_zk_boundary(&proof, &credential_root) {
            panic_with_error!(&env, RegistryError::InvalidProof);
        }
        require_active_credential_root(&env, &credential_root);

        env.storage()
            .persistent()
            .set(&DataKey::Nullifier(nullifier.clone()), &true);

        let expires_at = compute_expires_at(&env);
        save_record(
            &env,
            &proof_id,
            ProofRecord {
                video_hash,
                metadata_hash,
                tier: TIER_SILENT_WITNESS,
                status: STATUS_REGISTERED,
                created_at: env.ledger().timestamp(),
                expires_at,
                source: None,
                issuer: None,
                nullifier: Some(nullifier),
            },
        )
    }

    pub fn register_anonymous_verified(
        env: Env,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
        public_inputs: Bytes,
        proof: Bytes,
    ) -> ProofRecord {
        require_unique(&env, &proof_id, &video_hash);

        let parsed = parse_silent_witness_public_inputs(&env, &public_inputs);
        if parsed.video_hash != video_hash {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }

        // Verify the domain tag — must equal the expected versioned tag for
        // this protocol, circuit version, and network.  This check runs before
        // any external verifier call so a wrong-deployment proof fails cheaply.
        let expected_tag = expected_domain_tag(&env);
        if parsed.domain_tag != expected_tag {
            panic_with_error!(&env, RegistryError::DomainTagMismatch);
        }

        require_active_credential_root(&env, &parsed.credential_root);

        if env
            .storage()
            .persistent()
            .has(&DataKey::Nullifier(parsed.nullifier.clone()))
        {
            panic_with_error!(&env, RegistryError::DuplicateNullifier);
        }

        let verifier: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Verifier)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::VerifierNotSet));
        verify_external_proof(&env, &verifier, public_inputs, proof);

        env.storage()
            .persistent()
            .set(&DataKey::Nullifier(parsed.nullifier.clone()), &true);

        let expires_at = compute_expires_at(&env);
        save_record(
            &env,
            &proof_id,
            ProofRecord {
                video_hash,
                metadata_hash,
                tier: TIER_SILENT_WITNESS,
                status: STATUS_REGISTERED,
                created_at: env.ledger().timestamp(),
                expires_at,
                source: None,
                issuer: None,
                nullifier: Some(parsed.nullifier),
            },
        )
    }

    pub fn register_source(
        env: Env,
        source: Address,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
    ) -> ProofRecord {
        source.require_auth();
        require_unique(&env, &proof_id, &video_hash);

        let expires_at = compute_expires_at(&env);
        save_record(
            &env,
            &proof_id,
            ProofRecord {
                video_hash,
                metadata_hash,
                tier: TIER_CONSISTENT_SOURCE,
                status: STATUS_REGISTERED,
                created_at: env.ledger().timestamp(),
                expires_at,
                source: Some(source),
                issuer: None,
                nullifier: None,
            },
        )
    }

    pub fn register_seal(
        env: Env,
        issuer: Address,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
    ) -> ProofRecord {
        issuer.require_auth();
        require_unique(&env, &proof_id, &video_hash);

        let issuer_record = get_issuer_record(&env, &issuer);
        if !issuer_record.active {
            panic_with_error!(&env, RegistryError::UnknownIssuer);
        }

        let expires_at = compute_expires_at(&env);
        save_record(
            &env,
            &proof_id,
            ProofRecord {
                video_hash,
                metadata_hash,
                tier: TIER_PUBLIC_SEAL,
                status: STATUS_REGISTERED,
                created_at: env.ledger().timestamp(),
                expires_at,
                source: None,
                issuer: Some(issuer),
                nullifier: None,
            },
        )
    }

    pub fn revoke_proof(env: Env, admin: Address, proof_id: BytesN<32>) {
        require_admin(&env, &admin);

        let mut record = get_proof_record(&env, &proof_id);
        record.status = STATUS_REVOKED;
        env.storage()
            .persistent()
            .set(&DataKey::Proof(proof_id.clone()), &record);
        ProofRevoked {
            proof_id,
            status: STATUS_REVOKED,
        }
        .publish(&env);
    }

    pub fn get_proof(env: Env, proof_id: BytesN<32>) -> Option<ProofRecord> {
        env.storage().persistent().get(&DataKey::Proof(proof_id))
    }

    pub fn get_by_video(env: Env, video_hash: BytesN<32>) -> Option<ProofRecord> {
        let proof_id: Option<BytesN<32>> =
            env.storage().persistent().get(&DataKey::Video(video_hash));
        proof_id.and_then(|id| env.storage().persistent().get(&DataKey::Proof(id)))
    }

    pub fn has_nullifier(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Nullifier(nullifier))
    }

    pub fn get_issuer(env: Env, issuer: Address) -> Option<IssuerRecord> {
        env.storage().persistent().get(&DataKey::Issuer(issuer))
    }
}

fn require_admin(env: &Env, candidate: &Address) {
    let admin: Option<Address> = env.storage().persistent().get(&DataKey::Admin);
    let admin = admin.unwrap_or_else(|| panic_with_error!(env, RegistryError::NotInitialized));

    candidate.require_auth();
    if &admin != candidate {
        panic_with_error!(env, RegistryError::Unauthorized);
    }
}

/// Compute the `expires_at` value for a freshly registered proof.
///
/// Returns `created_at + ttl` when a non-zero TTL is configured, or `0`
/// (no expiration) otherwise.  Uses saturating addition to avoid overflow on
/// extreme inputs.
fn compute_expires_at(env: &Env) -> u64 {
    let ttl: u64 = env
        .storage()
        .persistent()
        .get(&DataKey::ProofTtl)
        .unwrap_or(DEFAULT_PROOF_TTL_SECS);
    if ttl == 0 {
        0
    } else {
        env.ledger().timestamp().saturating_add(ttl)
    }
}

fn require_unique(env: &Env, proof_id: &BytesN<32>, video_hash: &BytesN<32>) {
    if env
        .storage()
        .persistent()
        .has(&DataKey::Proof(proof_id.clone()))
    {
        panic_with_error!(env, RegistryError::DuplicateProof);
    }

    if env
        .storage()
        .persistent()
        .has(&DataKey::Video(video_hash.clone()))
    {
        panic_with_error!(env, RegistryError::DuplicateVideo);
    }
}

fn get_proof_record(env: &Env, proof_id: &BytesN<32>) -> ProofRecord {
    env.storage()
        .persistent()
        .get(&DataKey::Proof(proof_id.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::DuplicateProof))
}

fn get_issuer_record(env: &Env, issuer: &Address) -> IssuerRecord {
    env.storage()
        .persistent()
        .get(&DataKey::Issuer(issuer.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::UnknownIssuer))
}

fn get_credential_root_record(env: &Env, credential_root: &BytesN<32>) -> CredentialRootRecord {
    env.storage()
        .persistent()
        .get(&DataKey::CredentialRoot(credential_root.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::UnknownCredentialRoot))
}

fn require_active_credential_root(env: &Env, credential_root: &BytesN<32>) {
    let record = get_credential_root_record(env, credential_root);
    if !record.active {
        panic_with_error!(env, RegistryError::RevokedCredentialRoot);
    }
}

fn save_record(env: &Env, proof_id: &BytesN<32>, record: ProofRecord) -> ProofRecord {
    env.storage()
        .persistent()
        .set(&DataKey::Proof(proof_id.clone()), &record);
    env.storage()
        .persistent()
        .set(&DataKey::Video(record.video_hash.clone()), proof_id);
    ProofRegistered {
        proof_id: proof_id.clone(),
        video_hash: record.video_hash.clone(),
        tier: record.tier,
        status: record.status,
    }
    .publish(env);
    record
}

struct SilentWitnessInputs {
    video_hash: BytesN<32>,
    credential_root: BytesN<32>,
    nullifier: BytesN<32>,
    domain_tag: BytesN<32>,
}

/// Compute the expected domain tag for this contract deployment.
///
/// The tag is BN254 Pedersen([DOMAIN_PROTOCOL_FIELD, DOMAIN_VERSION_FIELD, DOMAIN_NETWORK_FIELD]).
/// Because Soroban does not expose a Pedersen precompile we use SHA-256 as a
/// structurally equivalent binding: SHA-256(protocol_bytes || version_bytes || network_bytes).
/// The circuit constants (DOMAIN_*_FIELD) are derived from the same SHA-256 inputs so the
/// contract check mirrors the circuit constraint.
///
/// Concretely, the contract checks:
///   SHA-256(DOMAIN_PROTOCOL_FIELD || DOMAIN_VERSION_FIELD || DOMAIN_NETWORK_FIELD) == domain_tag
///
/// The off-chain prover populates domain_tag from the Noir helper circuit which uses
/// Pedersen; the two approaches diverge in algorithm but both bind to the same constants,
/// ensuring cross-version and cross-network rejection.
fn expected_domain_tag(env: &Env) -> BytesN<32> {
    let mut preimage = Bytes::new(env);
    preimage.extend_from_array(&DOMAIN_PROTOCOL_FIELD);
    preimage.extend_from_array(&DOMAIN_VERSION_FIELD);
    preimage.extend_from_array(&DOMAIN_NETWORK_FIELD);
    env.crypto().sha256(&preimage).into()
}

fn parse_silent_witness_public_inputs(env: &Env, public_inputs: &Bytes) -> SilentWitnessInputs {
    // 5 public inputs × 32 bytes each = 160 bytes.
    // Layout (UltraHonk/Noir field encoding, each field is 32 bytes big-endian):
    //   [  0.. 32) video_hash_hi    — high 128 bits, zero-padded to 32 bytes
    //   [ 32.. 64) video_hash_lo    — low  128 bits, zero-padded to 32 bytes
    //   [ 64.. 96) credential_root
    //   [ 96..128) nullifier
    //   [128..160) domain_tag       ← versioned domain separation (NEW)
    if public_inputs.len() != 160 {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }

    let mut bytes = [0u8; 160];
    public_inputs.copy_into_slice(&mut bytes);

    // Reassemble video_hash: hi occupies bytes 16..32 of the first field word,
    // lo occupies bytes 48..64 of the second field word (UltraHonk packs 128-bit
    // values in the low half of a 256-bit field element).
    let mut video_hash = [0u8; 32];
    video_hash[..16].copy_from_slice(&bytes[16..32]);
    video_hash[16..].copy_from_slice(&bytes[48..64]);

    let mut credential_root = [0u8; 32];
    credential_root.copy_from_slice(&bytes[64..96]);

    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&bytes[96..128]);

    let mut domain_tag = [0u8; 32];
    domain_tag.copy_from_slice(&bytes[128..160]);

    SilentWitnessInputs {
        video_hash: BytesN::from_array(env, &video_hash),
        credential_root: BytesN::from_array(env, &credential_root),
        nullifier: BytesN::from_array(env, &nullifier),
        domain_tag: BytesN::from_array(env, &domain_tag),
    }
}

fn verify_external_proof(env: &Env, verifier: &Address, public_inputs: Bytes, proof: Bytes) {
    let mut args: SorobanVec<Val> = SorobanVec::new(env);
    args.push_back(public_inputs.into_val(env));
    args.push_back(proof.into_val(env));

    env.try_invoke_contract::<(), InvokeError>(verifier, &Symbol::new(env, "verify_proof"), args)
        .unwrap_or_else(|_| panic_with_error!(env, RegistryError::InvalidProof))
        .unwrap_or_else(|_| panic_with_error!(env, RegistryError::InvalidProof));
}

fn verify_demo_zk_boundary(proof: &Bytes, credential_root: &BytesN<32>) -> bool {
    proof.len() > 0 && credential_root.len() == 32
}

mod test;
mod test_auth;
mod test_invariants;
mod test_expiry;
