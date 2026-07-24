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

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierState {
    pub active_verifier: Option<Address>,
    pub pending_verifier: Option<Address>,
    pub previous_verifier: Option<Address>,
    pub activation_ledger: u64,
    pub overlap_window: u64,
    pub rollback_window: u64,
    pub rollback_window_end: u64,
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

#[contractevent(topics = ["verif", "schedule"])]
pub struct VerifierRotationScheduled {
    #[topic]
    pub active_verifier: Address,
    pub pending_verifier: Address,
    pub activation_ledger: u64,
    pub overlap_window: u64,
    pub rollback_window: u64,
}

#[contractevent(topics = ["verif", "activate"])]
pub struct VerifierRotationActivated {
    #[topic]
    pub active_verifier: Address,
    pub previous_verifier: Address,
    pub rollback_window_end: u64,
}

#[contractevent(topics = ["verif", "rollback"])]
pub struct VerifierRotationRolledBack {
    #[topic]
    pub active_verifier: Address,
    pub previous_verifier: Address,
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
    VerifierState,
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
    RotationNotScheduled = 14,
    RotationNotReady = 15,
    RotationWindowClosed = 16,
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

        env.storage().persistent().set(&DataKey::Verifier, &verifier);
        env.storage().persistent().remove(&DataKey::VerifierState);
        VerifierSet { verifier }.publish(&env);
    }

    pub fn get_verifier(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Verifier)
    }

    pub fn schedule_verifier_rotation(
        env: Env,
        admin: Address,
        verifier: Address,
        activation_ledger: u64,
        overlap_window: u64,
        rollback_window: u64,
    ) {
        require_admin(&env, &admin);

        let active_verifier = get_active_verifier(&env);
        let state = VerifierState {
            active_verifier: Some(active_verifier.clone()),
            pending_verifier: Some(verifier.clone()),
            previous_verifier: Some(active_verifier.clone()),
            activation_ledger,
            overlap_window,
            rollback_window,
            rollback_window_end: activation_ledger.saturating_add(rollback_window),
        };
        env.storage().persistent().set(&DataKey::VerifierState, &state);
        VerifierRotationScheduled {
            active_verifier: active_verifier.clone(),
            pending_verifier: verifier.clone(),
            activation_ledger,
            overlap_window,
            rollback_window,
        }
        .publish(&env);
    }

    pub fn activate_verifier_rotation(env: Env, admin: Address) {
        require_admin(&env, &admin);

        let mut state = get_verifier_rotation_state(&env);
        let pending_verifier = state.pending_verifier.clone().unwrap_or_else(|| {
            panic_with_error!(&env, RegistryError::RotationNotScheduled)
        });
        let active_verifier = state.active_verifier.clone().unwrap_or_else(|| {
            panic_with_error!(&env, RegistryError::RotationNotScheduled)
        });
        let current_ledger = u64::from(env.ledger().sequence());
        if current_ledger < state.activation_ledger {
            panic_with_error!(&env, RegistryError::RotationNotReady);
        }

        state.active_verifier = Some(pending_verifier.clone());
        state.pending_verifier = None;
        state.rollback_window_end = current_ledger.saturating_add(state.rollback_window.max(0));
        env.storage().persistent().set(&DataKey::VerifierState, &state);
        env.storage().persistent().set(&DataKey::Verifier, &pending_verifier);
        VerifierRotationActivated {
            active_verifier: pending_verifier,
            previous_verifier: active_verifier,
            rollback_window_end: state.rollback_window_end,
        }
        .publish(&env);
    }

    pub fn rollback_verifier_rotation(env: Env, admin: Address) {
        require_admin(&env, &admin);

        let state = get_verifier_rotation_state(&env);
        let active_verifier = state.active_verifier.clone().unwrap_or_else(|| {
            panic_with_error!(&env, RegistryError::RotationNotScheduled)
        });
        let previous_verifier = state.previous_verifier.clone().unwrap_or_else(|| {
            panic_with_error!(&env, RegistryError::RotationNotScheduled)
        });
        let current_ledger = u64::from(env.ledger().sequence());
        if state.rollback_window_end == 0 || current_ledger > state.rollback_window_end {
            panic_with_error!(&env, RegistryError::RotationWindowClosed);
        }

        env.storage().persistent().set(&DataKey::Verifier, &previous_verifier);
        env.storage().persistent().remove(&DataKey::VerifierState);
        VerifierRotationRolledBack {
            active_verifier: previous_verifier.clone(),
            previous_verifier: active_verifier,
        }
        .publish(&env);
    }

    pub fn get_verifier_state(env: Env) -> VerifierState {
        get_verifier_rotation_state(&env)
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

        verify_external_proof_with_overlap(&env, public_inputs, proof);

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

fn get_active_verifier(env: &Env) -> Address {
    env.storage()
        .persistent()
        .get(&DataKey::Verifier)
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::VerifierNotSet))
}

fn get_verifier_rotation_state(env: &Env) -> VerifierState {
    env.storage()
        .persistent()
        .get(&DataKey::VerifierState)
        .unwrap_or(VerifierState {
            active_verifier: env.storage().persistent().get(&DataKey::Verifier),
            pending_verifier: None,
            previous_verifier: None,
            activation_ledger: 0,
            overlap_window: 0,
            rollback_window: 0,
            rollback_window_end: 0,
        })
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

fn verify_external_proof_with_overlap(env: &Env, public_inputs: Bytes, proof: Bytes) {
    let state = get_verifier_rotation_state(env);
    let active_verifier = state.active_verifier.clone().unwrap_or_else(|| get_active_verifier(env));
    let mut candidates = SorobanVec::new(env);
    candidates.push_back(active_verifier.clone());

    let overlap_end = state.activation_ledger.saturating_add(state.overlap_window);
    let current_ledger = u64::from(env.ledger().sequence());
    if state.pending_verifier.is_none()
        && state.previous_verifier.is_some()
        && current_ledger <= overlap_end
        && state.previous_verifier.as_ref() != Some(&active_verifier)
    {
        candidates.push_back(state.previous_verifier.clone().unwrap());
    }

    let mut verified = false;
    for candidate in candidates {
        if verify_external_proof(env, &candidate, public_inputs.clone(), proof.clone()) {
            verified = true;
            break;
        }
    }

    if !verified {
        panic_with_error!(env, RegistryError::InvalidProof);
    }
}

fn verify_external_proof(env: &Env, verifier: &Address, public_inputs: Bytes, proof: Bytes) -> bool {
    let mut args: SorobanVec<Val> = SorobanVec::new(env);
    args.push_back(public_inputs.into_val(env));
    args.push_back(proof.into_val(env));

    match env.try_invoke_contract::<(), InvokeError>(verifier, &Symbol::new(env, "verify_proof"), args) {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

fn verify_demo_zk_boundary(proof: &Bytes, credential_root: &BytesN<32>) -> bool {
    proof.len() > 0 && credential_root.len() == 32
}

mod test;
mod test_auth;
mod test_invariants;
mod test_expiry;
