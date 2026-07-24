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
const STATUS_EXPIRED: u32 = 3;

pub const DEFAULT_PROOF_TTL_SECS: u64 = 0;

// ---------------------------------------------------------------------------
// Proof-history bounds (#90)
// ---------------------------------------------------------------------------
//
// Every proof carries an append-only history of lifecycle transitions.
// Each entry is bounded in size and the total number of entries per proof
// is capped to prevent storage exhaustion under hostile inputs.
//
// - MAX_HISTORY_ENTRIES_PER_PROOF limits total entries per proof.
// - MAX_HISTORY_LIMIT bounds the maximum number of entries returned by a
//   single query, protecting callers from unbounded iteration costs.
pub const MAX_HISTORY_ENTRIES_PER_PROOF: u32 = 256;
pub const MAX_HISTORY_LIMIT: u32 = 50;

/// Verification status returned by `get_proof_status`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofVerificationStatus {
    Valid,
    Revoked,
    Expired,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ProofLifecycleAction {
    Registered = 1,
    Verified = 2,
    Revoked = 3,
    Expired = 4,
    Corrected = 5,
    TtlUpdated = 6,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofHistoryEntry {
    pub action: u32,
    pub timestamp: u64,
    pub actor: Option<Address>,
    pub reason_code: u32,
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

#[contractevent(topics = ["proof", "history"])]
pub struct ProofHistoryEvent {
    #[topic]
    pub proof_id: BytesN<32>,
    pub action: u32,
    pub timestamp: u64,
    pub actor: Option<Address>,
    pub reason_code: u32,
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
    ProofTtl,
    ProofHistorySeq(BytesN<32>),
    ProofHistoryEntry(BytesN<32>, u32),
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
    HistorySaturated = 13,
    InvalidHistoryAction = 14,
    InvalidReasonCode = 15,
    HistoryLimitExceeded = 16,
    AlreadyExpired = 17,
    NoCorrectionChange = 18,
    HistoryCorruption = 19,
    NoPendingAdmin = 20,
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

    pub fn set_proof_ttl(env: Env, admin: Address, ttl_secs: u64) {
        require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::ProofTtl, &ttl_secs);
    }

    pub fn get_proof_ttl(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::ProofTtl)
            .unwrap_or(DEFAULT_PROOF_TTL_SECS)
    }

    pub fn get_proof_status(env: Env, proof_id: BytesN<32>) -> ProofVerificationStatus {
        let record: Option<ProofRecord> =
            env.storage().persistent().get(&DataKey::Proof(proof_id));
        match record {
            None => ProofVerificationStatus::NotFound,
            Some(r) => {
                if r.status == STATUS_REVOKED {
                    return ProofVerificationStatus::Revoked;
                }
                if r.status == STATUS_EXPIRED {
                    return ProofVerificationStatus::Expired;
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
        let record = ProofRecord {
            video_hash,
            metadata_hash,
            tier: TIER_SILENT_WITNESS,
            status: STATUS_REGISTERED,
            created_at: env.ledger().timestamp(),
            expires_at,
            source: None,
            issuer: None,
            nullifier: Some(nullifier),
        };
        save_record(&env, &proof_id, record.clone(), None);
        record_proof_history(
            &env,
            &proof_id,
            ProofLifecycleAction::Registered as u32,
            None,
            record.tier,
        );
        record
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
        let record = ProofRecord {
            video_hash,
            metadata_hash,
            tier: TIER_SILENT_WITNESS,
            status: STATUS_REGISTERED,
            created_at: env.ledger().timestamp(),
            expires_at,
            source: None,
            issuer: None,
            nullifier: Some(parsed.nullifier),
        };
        save_record(&env, &proof_id, record.clone(), None);
        record_proof_history(
            &env,
            &proof_id,
            ProofLifecycleAction::Registered as u32,
            None,
            record.tier,
        );
        record
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
        let record = ProofRecord {
            video_hash,
            metadata_hash,
            tier: TIER_CONSISTENT_SOURCE,
            status: STATUS_REGISTERED,
            created_at: env.ledger().timestamp(),
            expires_at,
            source: Some(source.clone()),
            issuer: None,
            nullifier: None,
        };
        save_record(&env, &proof_id, record.clone(), Some(source.clone()));
        record_proof_history(
            &env,
            &proof_id,
            ProofLifecycleAction::Registered as u32,
            Some(source),
            record.tier,
        );
        record
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
        let record = ProofRecord {
            video_hash,
            metadata_hash,
            tier: TIER_PUBLIC_SEAL,
            status: STATUS_REGISTERED,
            created_at: env.ledger().timestamp(),
            expires_at,
            source: None,
            issuer: Some(issuer.clone()),
            nullifier: None,
        };
        save_record(&env, &proof_id, record.clone(), Some(issuer.clone()));
        record_proof_history(
            &env,
            &proof_id,
            ProofLifecycleAction::Registered as u32,
            Some(issuer),
            record.tier,
        );
        record
    }

    pub fn revoke_proof(env: Env, admin: Address, proof_id: BytesN<32>) {
        require_admin(&env, &admin);

        let mut record = get_proof_record(&env, &proof_id);
        record.status = STATUS_REVOKED;
        env.storage()
            .persistent()
            .set(&DataKey::Proof(proof_id.clone()), &record);
        ProofRevoked {
            proof_id: proof_id.clone(),
            status: STATUS_REVOKED,
        }
        .publish(&env);
        record_proof_history(
            &env,
            &proof_id,
            ProofLifecycleAction::Revoked as u32,
            Some(admin),
            1,
        );
    }

    // -----------------------------------------------------------------------
    // Lifecycle history (#90)
    // -----------------------------------------------------------------------

    pub fn verify_proof(env: Env, actor: Address, proof_id: BytesN<32>, reason_code: u32) {
        require_admin(&env, &actor);

        let _record = get_proof_record(&env, &proof_id);

        if reason_code > 255 {
            panic_with_error!(&env, RegistryError::InvalidReasonCode);
        }

        record_proof_history(
            &env,
            &proof_id,
            ProofLifecycleAction::Verified as u32,
            Some(actor),
            reason_code,
        );
    }

    pub fn expire_proof(env: Env, admin: Address, proof_id: BytesN<32>, reason_code: u32) {
        require_admin(&env, &admin);

        let mut record = get_proof_record(&env, &proof_id);
        if record.status == STATUS_REVOKED {
            panic_with_error!(&env, RegistryError::Unauthorized);
        }
        if record.status == STATUS_EXPIRED {
            panic_with_error!(&env, RegistryError::AlreadyExpired);
        }

        record.status = STATUS_EXPIRED;
        env.storage()
            .persistent()
            .set(&DataKey::Proof(proof_id.clone()), &record);

        record_proof_history(
            &env,
            &proof_id,
            ProofLifecycleAction::Expired as u32,
            Some(admin),
            reason_code,
        );
    }

    pub fn correct_proof(
        env: Env,
        admin: Address,
        proof_id: BytesN<32>,
        new_metadata_hash: BytesN<32>,
        reason_code: u32,
    ) {
        require_admin(&env, &admin);

        let mut record = get_proof_record(&env, &proof_id);
        if record.metadata_hash == new_metadata_hash {
            panic_with_error!(&env, RegistryError::NoCorrectionChange);
        }

        record.metadata_hash = new_metadata_hash;
        env.storage()
            .persistent()
            .set(&DataKey::Proof(proof_id.clone()), &record);

        record_proof_history(
            &env,
            &proof_id,
            ProofLifecycleAction::Corrected as u32,
            Some(admin),
            reason_code,
        );
    }

    pub fn get_proof_history_at(
        env: Env,
        proof_id: BytesN<32>,
        seq: u32,
    ) -> Option<ProofHistoryEntry> {
        let total: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ProofHistorySeq(proof_id.clone()))
            .unwrap_or(0);

        if seq == 0 || seq > total {
            return None;
        }

        env.storage()
            .persistent()
            .get(&DataKey::ProofHistoryEntry(proof_id, seq))
    }

    pub fn get_proof_history_count(env: Env, proof_id: BytesN<32>) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ProofHistorySeq(proof_id))
            .unwrap_or(0)
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

fn save_record(
    env: &Env,
    proof_id: &BytesN<32>,
    record: ProofRecord,
    actor: Option<Address>,
) -> ProofRecord {
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

fn record_proof_history(
    env: &Env,
    proof_id: &BytesN<32>,
    action: u32,
    actor: Option<Address>,
    reason_code: u32,
) {
    if !(1..=6).contains(&action) {
        panic_with_error!(env, RegistryError::InvalidHistoryAction);
    }
    if reason_code > 255 {
        panic_with_error!(env, RegistryError::InvalidReasonCode);
    }

    let seq_key = DataKey::ProofHistorySeq(proof_id.clone());
    let seq: u32 = env.storage().persistent().get(&seq_key).unwrap_or(0);

    if seq >= MAX_HISTORY_ENTRIES_PER_PROOF {
        panic_with_error!(env, RegistryError::HistorySaturated);
    }

    let next_seq = seq + 1;
    env.storage().persistent().set(
        &DataKey::ProofHistoryEntry(proof_id.clone(), next_seq),
        &ProofHistoryEntry {
            action,
            timestamp: env.ledger().timestamp(),
            actor: actor.clone(),
            reason_code,
        },
    );
    env.storage().persistent().set(&seq_key, &next_seq);

    ProofHistoryEvent {
        proof_id: proof_id.clone(),
        action,
        timestamp: env.ledger().timestamp(),
        actor,
        reason_code,
    }
    .publish(env);
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

fn verify_demo_zk_boundary(proof: &Bytes, credential_root: &BytesN<32>) -> bool {
    proof.len() > 0 && credential_root.len() == 32
}

mod test;
mod test_auth;
mod test_budget;
mod test_invariants;
mod test_expiry;
mod test_lifecycle;
