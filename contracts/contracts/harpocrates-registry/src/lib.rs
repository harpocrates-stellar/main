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

const STATUS_POLICY_ACTIVE: u32 = 1;
const STATUS_POLICY_CANCELLED: u32 = 2;

const MAX_SIGNERS: u32 = 16;
const DEFAULT_APPROVAL_TTL_SECS: u64 = 86_400;

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

/// Versioned m-of-n threshold policy for high-assurance Public Seals.
///
/// Each policy defines a required number of approvals (`required_approvals`)
/// from a bounded set of distinct active issuers (`max_signers`). Policies
/// are versioned; superseding a policy creates a new version and cancels the
/// old one. Individual approvals carry their own TTL and are discarded once
/// expired or once the approving issuer is revoked.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealPolicy {
    pub version: u32,
    pub required_approvals: u32,
    pub max_signers: u32,
    pub approval_ttl: u64,
    pub expires_at: u64,
    pub status: u32,
}

/// Records a single issuer's approval for a proof under a specific policy
/// version. An approval is idempotent per (proof_id, signer) pair and expires
/// after `approved_at + policy.approval_ttl`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealApproval {
    pub proof_id: BytesN<32>,
    pub policy_version: u32,
    pub signer: Address,
    pub approved_at: u64,
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

/// Domain separator that binds non‑revocation proofs to the Harpocrates
/// revocation witness circuit version.  Both the Noir circuit and this
/// contract use the same constant.  Changing the circuit requires updating
/// this value to prevent proof replay across protocol versions.
///
/// Format: 32‑byte big‑endian BN254 field element serialization of
///   `0x484152504f4352415445535f5245564f434154494f4e5f5631`
/// which represents the ASCII string "HARPOCRATES_REVOCATION_V1" as a
/// 192‑bit integer.  The 8 leading zero bytes come from the BN254 field
/// serialisation (field elements are padded to 32 bytes).
///
/// Layout:
///   [ 0.. 8)  leading zeros (BN254 field padding)
///   [ 8..32)  "HARPOCRATES_REVOCATION_V1" (24 ASCII bytes)
const REVOCATION_DOMAIN_SEPARATOR: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 7 leading zeros (BN254 padding)
    0x48, 0x41, 0x52, 0x50, 0x4f, 0x43, 0x52, 0x41, // HARPOCRA
    0x54, 0x45, 0x53, 0x5f, 0x52, 0x45, 0x56, 0x4f, // TES_REVO
    0x43, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x56, // CATION_V
    0x31, // 1
];

#[contractevent(topics = ["revroot", "set"])]
pub struct RevocationRootSet {
    #[topic]
    pub revocation_root: BytesN<32>,
}

#[contractevent(topics = ["nonrev", "check"])]
pub struct NonRevocationChecked {
    #[topic]
    pub credential_root: BytesN<32>,
    pub nullifier: BytesN<32>,
    pub revocation_root: BytesN<32>,
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

#[contractevent(topics = ["sealpolicy", "create"])]
pub struct SealPolicyCreated {
    #[topic]
    pub version: u32,
    pub required_approvals: u32,
    pub max_signers: u32,
}

#[contractevent(topics = ["sealpolicy", "cancel"])]
pub struct SealPolicyCancelled {
    #[topic]
    pub version: u32,
}

#[contractevent(topics = ["sealapproval", "record"])]
pub struct SealApprovalRecorded {
    #[topic]
    pub proof_id: BytesN<32>,
    pub signer: Address,
    pub policy_version: u32,
}

#[contractevent(topics = ["sealfinalize", "ok"])]
pub struct SealFinalized {
    #[topic]
    pub proof_id: BytesN<32>,
    pub approval_count: u32,
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
    /// Merkle root of the credential-revocation tree (set by admin).
    RevocationRoot,
    /// Current seal-policy version counter (set by admin).
    SealPolicyCount,
    /// Seal policy by version number.
    SealPolicy(u32),
    /// Bounded signer set for a seal policy version.
    SealPolicySigners(u32),
    /// Individual approval per (proof_id, signer).
    SealApproval(BytesN<32>, Address),
    /// Bounded signer set for a finalized threshold seal.
    ThresholdSigners(BytesN<32>),
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
    UnknownSealPolicy = 14,
    InactiveSealPolicy = 15,
    UnknownPolicySigner = 16,
    DuplicateApproval = 17,
    ApprovalExpired = 18,
    ThresholdNotMet = 19,
    InvalidThreshold = 20,
    SignerSetTooLarge = 21,
    PolicyExpired = 22,
    AlreadyFinalized = 23,
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

    // -----------------------------------------------------------------------
    // Revocation-witness root management (#98)
    // -----------------------------------------------------------------------

    /// Publish the current Merkle root of the credential-revocation tree.
    /// Only the registry admin may call this.
    pub fn set_revocation_root(env: Env, admin: Address, revocation_root: BytesN<32>) {
        require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::RevocationRoot, &revocation_root);
        RevocationRootSet { revocation_root }.publish(&env);
    }

    /// Return the currently-published revocation tree root, if any.
    pub fn get_revocation_root(env: Env) -> Option<BytesN<32>> {
        env.storage()
            .persistent()
            .get(&DataKey::RevocationRoot)
    }

    /// Verify a non‑revocation proof produced by the `revocation_witness`
    /// Noir circuit.
    ///
    /// The proof demonstrates that `credential_root` is **not** a member of
    /// the currently‑published revocation tree (`revocation_root`) without
    /// revealing which revoked credentials exist or which identity is acting.
    ///
    /// # Public input layout (128 bytes, 4 × BN254 field elements)
    ///
    /// ```text
    /// [  0.. 32)  revocation_root   – must match the on‑chain stored root
    /// [ 32.. 64)  nullifier         – one‑use replay guard
    /// [ 64.. 96)  domain_separator  – must match REVOCATION_DOMAIN_SEPARATOR
    /// [ 96..128)  credential_root   – must be registered & active on‑chain
    /// ```
    ///
    /// # Reverts
    ///
    /// - `NotInitialized`      if no revocation root has been published yet
    /// - `VerifierNotSet`       if no external verifier contract is configured
    /// - `InvalidPublicInputs`  if the domain separator or layout is wrong
    /// - `UnknownCredentialRoot` if the credential has not been registered
    /// - `RevokedCredentialRoot` if the credential root has been revoked
    /// - `DuplicateNullifier`   if this nullifier was already consumed
    /// - `InvalidProof`         if the external verifier rejects the proof
    pub fn check_non_revocation(env: Env, public_inputs: Bytes, proof: Bytes) {
        let parsed = parse_revocation_public_inputs(&env, &public_inputs);

        // 1. Domain binding — must match the expected version tag.
        let expected_domain = BytesN::from_array(&env, &REVOCATION_DOMAIN_SEPARATOR);
        if parsed.domain_separator != expected_domain {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }

        // 2. Revocation root — must match the currently published root.
        let stored_root: BytesN<32> = env
            .storage()
            .persistent()
            .get(&DataKey::RevocationRoot)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NotInitialized));
        if parsed.revocation_root != stored_root {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }

        // 3. Credential must be registered and active.
        require_active_credential_root(&env, &parsed.credential_root);

        // 4. Nullifier must be fresh (prevents replay of this proof).
        if env
            .storage()
            .persistent()
            .has(&DataKey::Nullifier(parsed.nullifier.clone()))
        {
            panic_with_error!(&env, RegistryError::DuplicateNullifier);
        }

        // 5. Verify the Noir proof through the external UltraHonk verifier.
        let verifier: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Verifier)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::VerifierNotSet));
        verify_external_proof(&env, &verifier, public_inputs, proof);

        // 6. Consume the nullifier so this proof cannot be replayed.
        env.storage()
            .persistent()
            .set(&DataKey::Nullifier(parsed.nullifier.clone()), &true);

        NonRevocationChecked {
            credential_root: parsed.credential_root,
            nullifier: parsed.nullifier,
            revocation_root: parsed.revocation_root,
        }
        .publish(&env);
    }

    // -----------------------------------------------------------------------
    // Threshold Seal Policy (#124)
    // -----------------------------------------------------------------------

    /// Create a versioned m-of-n threshold seal policy.
    ///
    /// `required_approvals` (m) must be > 0 and ≤ `max_signers` (n).
    /// `max_signers` must be ≤ `MAX_SIGNERS` (16).
    /// `approval_ttl` is per-approval TTL in seconds; `0` uses the default.
    /// `policy_expiry` is absolute epoch-second deadline; `0` means no expiry.
    ///
    /// Cancels any previously-active policy by incrementing the version counter.
    /// Only the registry admin may call this.
    pub fn create_seal_policy(
        env: Env,
        admin: Address,
        required_approvals: u32,
        max_signers: u32,
        approval_ttl: u64,
        policy_expiry: u64,
    ) -> u32 {
        require_admin(&env, &admin);

        if required_approvals == 0 || required_approvals > max_signers {
            panic_with_error!(&env, RegistryError::InvalidThreshold);
        }
        if max_signers > MAX_SIGNERS {
            panic_with_error!(&env, RegistryError::SignerSetTooLarge);
        }

        let version: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::SealPolicyCount)
            .unwrap_or(0u32)
            + 1;
        env.storage()
            .persistent()
            .set(&DataKey::SealPolicyCount, &version);

        let effective_ttl = if approval_ttl == 0 {
            DEFAULT_APPROVAL_TTL_SECS
        } else {
            approval_ttl
        };

        let expires_at = if policy_expiry == 0 {
            0u64
        } else {
            policy_expiry
        };

        env.storage().persistent().set(
            &DataKey::SealPolicy(version),
            &SealPolicy {
                version,
                required_approvals,
                max_signers,
                approval_ttl: effective_ttl,
                expires_at,
                status: STATUS_POLICY_ACTIVE,
            },
        );

        // Cancel any previously active policy
        if version > 1 {
            let prev_version = version - 1;
            let mut prev_policy = get_seal_policy(&env, &prev_version);
            if prev_policy.status == STATUS_POLICY_ACTIVE {
                prev_policy.status = STATUS_POLICY_CANCELLED;
                env.storage()
                    .persistent()
                    .set(&DataKey::SealPolicy(prev_version), &prev_policy);
                SealPolicyCancelled {
                    version: prev_version,
                }
                .publish(&env);
            }
        }

        env.storage().persistent().set(
            &DataKey::SealPolicySigners(version),
            &SorobanVec::<Address>::new(&env),
        );

        SealPolicyCreated {
            version,
            required_approvals,
            max_signers,
        }
        .publish(&env);

        version
    }

    /// Add an issuer address to a seal policy's signer set.
    ///
    /// The signer must be an active issuer in the registry. The policy must be
    /// active and its signer set must not exceed `max_signers`. Only the
    /// registry admin may call this.
    pub fn add_seal_policy_signer(
        env: Env,
        admin: Address,
        policy_version: u32,
        signer: Address,
    ) {
        require_admin(&env, &admin);

        let policy = get_seal_policy_active(&env, &policy_version);

        let record = get_issuer_record(&env, &signer);
        if !record.active {
            panic_with_error!(&env, RegistryError::UnknownIssuer);
        }

        let mut signers: SorobanVec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::SealPolicySigners(policy_version))
            .unwrap_or_else(|| SorobanVec::new(&env));

        if signers.len() >= policy.max_signers {
            panic_with_error!(&env, RegistryError::SignerSetTooLarge);
        }

        // Idempotent: skip if already present
        for i in 0..signers.len() {
            let s: Address = signers.get_unchecked(i);
            if s == signer {
                return;
            }
        }

        signers.push_back(signer);
        env.storage().persistent().set(
            &DataKey::SealPolicySigners(policy_version),
            &signers,
        );
    }

    /// Remove an issuer from a seal policy's signer set.
    ///
    /// Only the registry admin may call this. The policy must be active.
    pub fn remove_seal_policy_signer(
        env: Env,
        admin: Address,
        policy_version: u32,
        signer: Address,
    ) {
        require_admin(&env, &admin);

        let _policy = get_seal_policy_active(&env, &policy_version);

        let signers: SorobanVec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::SealPolicySigners(policy_version))
            .unwrap_or_else(|| SorobanVec::new(&env));

        let mut new_signers = SorobanVec::<Address>::new(&env);
        for i in 0..signers.len() {
            let s: Address = signers.get_unchecked(i);
            if s != signer {
                new_signers.push_back(s);
            }
        }

        env.storage().persistent().set(
            &DataKey::SealPolicySigners(policy_version),
            &new_signers,
        );
    }

    /// Cancel an active seal policy. Only the registry admin may call this.
    pub fn cancel_seal_policy(env: Env, admin: Address, policy_version: u32) {
        require_admin(&env, &admin);

        let mut policy = get_seal_policy_active(&env, &policy_version);
        policy.status = STATUS_POLICY_CANCELLED;
        env.storage()
            .persistent()
            .set(&DataKey::SealPolicy(policy_version), &policy);

        SealPolicyCancelled {
            version: policy_version,
        }
        .publish(&env);
    }

    /// Record a signer's approval for a proof under the active seal policy.
    ///
    /// - The signer must be an active issuer and a member of the active
    ///   policy's signer set.
    /// - The proof must not already be registered.
    /// - The approval is idempotent per (proof_id, signer).
    /// - The approval expires after `policy.approval_ttl` seconds.
    ///
    /// If this approval causes the threshold to be met, the proof is
    /// finalized atomically in the same transaction.
    pub fn approve_seal(
        env: Env,
        signer: Address,
        proof_id: BytesN<32>,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
    ) -> bool {
        signer.require_auth();

        let policy_version = get_active_policy_version(&env);
        let policy = get_seal_policy_active(&env, &policy_version);

        // Check signer is active issuer
        let record = get_issuer_record(&env, &signer);
        if !record.active {
            panic_with_error!(&env, RegistryError::UnknownIssuer);
        }

        // Check signer is in the policy's signer set
        require_policy_signer(&env, policy_version, &signer);

        // Check proof not already registered
        if env
            .storage()
            .persistent()
            .has(&DataKey::Proof(proof_id.clone()))
        {
            panic_with_error!(&env, RegistryError::AlreadyFinalized);
        }

        // Idempotent: skip if already approved
        if env
            .storage()
            .persistent()
            .has(&DataKey::SealApproval(
                proof_id.clone(),
                signer.clone(),
            ))
        {
            return false;
        }

        let now = env.ledger().timestamp();
        env.storage().persistent().set(
            &DataKey::SealApproval(proof_id.clone(), signer.clone()),
            &SealApproval {
                proof_id: proof_id.clone(),
                policy_version,
                signer: signer.clone(),
                approved_at: now,
            },
        );

        SealApprovalRecorded {
            proof_id: proof_id.clone(),
            signer,
            policy_version,
        }
        .publish(&env);

        // Check if threshold is now met and finalize atomically
        let approvals = count_active_approvals(&env, &proof_id, &policy);
        if approvals >= policy.required_approvals {
            finalize_threshold_seal(&env, &proof_id, &video_hash, &metadata_hash, &policy);
            return true;
        }

        false
    }

    /// Atomically finalize a threshold seal when enough approvals exist.
    ///
    /// This can be called explicitly by any caller after sufficient
    /// approvals are collected, or is called automatically by `approve_seal`.
    pub fn finalize_seal(
        env: Env,
        proof_id: BytesN<32>,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
    ) -> ProofRecord {
        let policy_version = get_active_policy_version(&env);
        let policy = get_seal_policy_active(&env, &policy_version);

        if env
            .storage()
            .persistent()
            .has(&DataKey::Proof(proof_id.clone()))
        {
            panic_with_error!(&env, RegistryError::AlreadyFinalized);
        }

        let approvals = count_active_approvals(&env, &proof_id, &policy);
        if approvals < policy.required_approvals {
            panic_with_error!(&env, RegistryError::ThresholdNotMet);
        }

        finalize_threshold_seal(&env, &proof_id, &video_hash, &metadata_hash, &policy)
    }

    /// Return the current active seal-policy version, if any.
    pub fn get_active_seal_policy(env: Env) -> Option<SealPolicy> {
        let version: Option<u32> =
            env.storage().persistent().get(&DataKey::SealPolicyCount);
        match version {
            None => None,
            Some(v) => {
                let policy: Option<SealPolicy> =
                    env.storage().persistent().get(&DataKey::SealPolicy(v));
                policy.filter(|p| p.status == STATUS_POLICY_ACTIVE)
            }
        }
    }

    /// Return a specific seal policy by version.
    pub fn get_seal_policy_by_version(env: Env, version: u32) -> Option<SealPolicy> {
        env.storage()
            .persistent()
            .get(&DataKey::SealPolicy(version))
    }

    /// Return the number of approvals currently recorded for a proof under
    /// the active seal policy. Only counts approvals from active issuers
    /// whose approvals have not expired.
    pub fn get_seal_approval_count(env: Env, proof_id: BytesN<32>) -> u32 {
        let policy_version = match get_active_policy_version_opt(&env) {
            Some(v) => v,
            None => return 0,
        };
        let policy = match get_seal_policy_opt(&env, &policy_version) {
            Some(p) if p.status == STATUS_POLICY_ACTIVE => p,
            _ => return 0,
        };
        count_active_approvals(&env, &proof_id, &policy)
    }

    /// Return the approval record for a (proof_id, signer) pair, if any.
    pub fn get_seal_approval(
        env: Env,
        proof_id: BytesN<32>,
        signer: Address,
    ) -> Option<SealApproval> {
        env.storage()
            .persistent()
            .get(&DataKey::SealApproval(proof_id, signer))
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
}

fn parse_silent_witness_public_inputs(env: &Env, public_inputs: &Bytes) -> SilentWitnessInputs {
    if public_inputs.len() != 128 {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }

    let mut bytes = [0u8; 128];
    public_inputs.copy_into_slice(&mut bytes);

    let mut video_hash = [0u8; 32];
    video_hash[..16].copy_from_slice(&bytes[16..32]);
    video_hash[16..].copy_from_slice(&bytes[48..64]);

    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&bytes[96..128]);

    let mut credential_root = [0u8; 32];
    credential_root.copy_from_slice(&bytes[64..96]);

    SilentWitnessInputs {
        video_hash: BytesN::from_array(env, &video_hash),
        credential_root: BytesN::from_array(env, &credential_root),
        nullifier: BytesN::from_array(env, &nullifier),
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

struct RevocationPublicInputs {
    revocation_root: BytesN<32>,
    nullifier: BytesN<32>,
    domain_separator: BytesN<32>,
    credential_root: BytesN<32>,
}

/// Parse the 128‑byte public‑input blob produced by the revocation_witness
/// Noir circuit.
///
/// Layout (4 × BN254 field elements, 32 bytes each):
///   [  0.. 32)  revocation_root
///   [ 32.. 64)  nullifier
///   [ 64.. 96)  domain_separator
///   [ 96..128)  credential_root
fn parse_revocation_public_inputs(
    env: &Env,
    public_inputs: &Bytes,
) -> RevocationPublicInputs {
    if public_inputs.len() != 128 {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }

    let mut bytes = [0u8; 128];
    public_inputs.copy_into_slice(&mut bytes);

    // Each field is a contiguous 32‑byte slice.
    let mut revocation_root = [0u8; 32];
    revocation_root.copy_from_slice(&bytes[0..32]);

    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&bytes[32..64]);

    let mut domain_separator = [0u8; 32];
    domain_separator.copy_from_slice(&bytes[64..96]);

    let mut credential_root = [0u8; 32];
    credential_root.copy_from_slice(&bytes[96..128]);

    RevocationPublicInputs {
        revocation_root: BytesN::from_array(env, &revocation_root),
        nullifier: BytesN::from_array(env, &nullifier),
        domain_separator: BytesN::from_array(env, &domain_separator),
        credential_root: BytesN::from_array(env, &credential_root),
    }
}

fn verify_demo_zk_boundary(proof: &Bytes, credential_root: &BytesN<32>) -> bool {
    proof.len() > 0 && credential_root.len() == 32
}

// ---------------------------------------------------------------------------
// Threshold seal helpers
// ---------------------------------------------------------------------------

fn get_seal_policy(env: &Env, version: &u32) -> SealPolicy {
    env.storage()
        .persistent()
        .get(&DataKey::SealPolicy(*version))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::UnknownSealPolicy))
}

fn get_seal_policy_opt(env: &Env, version: &u32) -> Option<SealPolicy> {
    env.storage().persistent().get(&DataKey::SealPolicy(*version))
}

fn get_seal_policy_active(env: &Env, version: &u32) -> SealPolicy {
    let policy = get_seal_policy(env, version);
    if policy.status != STATUS_POLICY_ACTIVE {
        panic_with_error!(env, RegistryError::InactiveSealPolicy);
    }
    if policy.expires_at > 0 && env.ledger().timestamp() > policy.expires_at {
        panic_with_error!(env, RegistryError::PolicyExpired);
    }
    policy
}

fn get_active_policy_version(env: &Env) -> u32 {
    get_active_policy_version_opt(env)
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::UnknownSealPolicy))
}

fn get_active_policy_version_opt(env: &Env) -> Option<u32> {
    let version: Option<u32> =
        env.storage().persistent().get(&DataKey::SealPolicyCount);
    version.filter(|v| *v > 0)
}

fn require_policy_signer(env: &Env, policy_version: u32, signer: &Address) {
    let signers: SorobanVec<Address> = env
        .storage()
        .persistent()
        .get(&DataKey::SealPolicySigners(policy_version))
        .unwrap_or_else(|| SorobanVec::new(env));

    for i in 0..signers.len() {
        let s: Address = signers.get_unchecked(i);
        if s == *signer {
            return;
        }
    }
    panic_with_error!(env, RegistryError::UnknownPolicySigner);
}

fn count_active_approvals(env: &Env, proof_id: &BytesN<32>, policy: &SealPolicy) -> u32 {
    let now = env.ledger().timestamp();
    let mut count = 0u32;

    let signers: SorobanVec<Address> = env
        .storage()
        .persistent()
        .get(&DataKey::SealPolicySigners(policy.version))
        .unwrap_or_else(|| SorobanVec::new(env));

    for i in 0..signers.len() {
        let s: Address = signers.get_unchecked(i);

        // Skip revoked issuers
        if let Some(record) = env
            .storage()
            .persistent()
            .get::<_, IssuerRecord>(&DataKey::Issuer(s.clone()))
        {
            if !record.active {
                continue;
            }
        } else {
            continue;
        }

        // Check if this signer has an approval
        let approval_key = DataKey::SealApproval(proof_id.clone(), s);
        let approval: Option<SealApproval> =
            env.storage().persistent().get(&approval_key);
        if let Some(a) = approval {
            // Check approval has not expired
            if policy.approval_ttl > 0 {
                let expires = a.approved_at.saturating_add(policy.approval_ttl);
                if now > expires {
                    continue;
                }
            }
            count += 1;
        }
    }

    count
}

fn finalize_threshold_seal(
    env: &Env,
    proof_id: &BytesN<32>,
    video_hash: &BytesN<32>,
    metadata_hash: &BytesN<32>,
    policy: &SealPolicy,
) -> ProofRecord {
    let mut signers_vec = SorobanVec::<Address>::new(env);

    let policy_signers: SorobanVec<Address> = env
        .storage()
        .persistent()
        .get(&DataKey::SealPolicySigners(policy.version))
        .unwrap_or_else(|| SorobanVec::new(env));

    for i in 0..policy_signers.len() {
        let s: Address = policy_signers.get_unchecked(i);

        // Only include signers who have an active (non-expired) approval
        if let Some(record) = env
            .storage()
            .persistent()
            .get::<_, IssuerRecord>(&DataKey::Issuer(s.clone()))
        {
            if !record.active {
                continue;
            }
        } else {
            continue;
        }

        let approval_key = DataKey::SealApproval(proof_id.clone(), s.clone());
        let approval: Option<SealApproval> =
            env.storage().persistent().get(&approval_key);
        if let Some(a) = approval {
            if policy.approval_ttl > 0 {
                let expires = a.approved_at.saturating_add(policy.approval_ttl);
                if env.ledger().timestamp() > expires {
                    continue;
                }
            }
            signers_vec.push_back(s);
        }
    }

    let approval_count = signers_vec.len();

    // Use the first signer as the primary issuer (for backward compatibility)
    let primary_issuer: Option<Address> = if signers_vec.len() > 0 {
        Some(signers_vec.get_unchecked(0))
    } else {
        None
    };

    let expires_at = compute_expires_at(env);

    env.storage()
        .persistent()
        .set(&DataKey::ThresholdSigners(proof_id.clone()), &signers_vec);

    save_record(
        env,
        proof_id,
        ProofRecord {
            video_hash: video_hash.clone(),
            metadata_hash: metadata_hash.clone(),
            tier: TIER_PUBLIC_SEAL,
            status: STATUS_REGISTERED,
            created_at: env.ledger().timestamp(),
            expires_at,
            source: None,
            issuer: primary_issuer,
            nullifier: None,
        },
    );

    let record = get_proof_record(env, proof_id);

    SealFinalized {
        proof_id: proof_id.clone(),
        approval_count,
    }
    .publish(env);

    record
}

mod test;
mod test_auth;
mod test_budget;
mod test_invariants;
mod test_expiry;
mod test_revocation;
mod test_threshold_seal;
