#![no_std]

#[cfg(test)]
extern crate std;

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

/// Default epoch for unscoped or legacy proofs.
pub const DEFAULT_SCOPE_EPOCH: u64 = 0;

/// Maximum scope string length (bytes) accepted by `register_scoped_proof`.
/// Prevents abuse through arbitrarily large scope identifiers.
pub const MAX_SCOPE_LENGTH: u32 = 64;

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

/// Domain separator that binds non-revocation proofs to the Harpocrates
/// revocation witness circuit version.  Both the Noir circuit and this
/// contract use the same constant.  Changing the circuit requires updating
/// this value to prevent proof replay across protocol versions.
///
/// Format: 32-byte big-endian BN254 field element serialization of
///   `0x484152504f4352415445535f5245564f434154494f4e5f5631`
/// which represents the ASCII string "HARPOCRATES_REVOCATION_V1" as a
/// 192-bit integer.  The 8 leading zero bytes come from the BN254 field
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

/// Domain separator for the scoped nullifier v1 circuit.
/// "HARPOCRATES_SCOPED_NULLIFIER_V1" encoded as a 32-byte BN254 field element
/// (31 ASCII bytes with a leading 0x00 pad).
#[allow(dead_code)]
const SCOPED_NULLIFIER_V1_DOMAIN: [u8; 32] = [
    0x00, // leading zero (BN254 field padding)
    0x48, 0x41, 0x52, 0x50, 0x4f, 0x43, 0x52, 0x41, // HARPOCRA
    0x54, 0x45, 0x53, 0x5f, 0x53, 0x43, 0x4f, 0x50, // TES_SCOP
    0x45, 0x44, 0x5f, 0x4e, 0x55, 0x4c, 0x4c, 0x49, // ED_NULLI
    0x46, 0x49, 0x45, 0x52, 0x5f, 0x56, 0x31, // FIER_V1
];

/// Expected length of v1 public inputs (4 × 32 = 128 bytes).
const SILENT_WITNESS_V1_INPUT_LEN: u32 = 128;

/// Expected length of v2 scoped public inputs (6 × 32 = 192 bytes).
const SILENT_WITNESS_V2_INPUT_LEN: u32 = 192;

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

#[contractevent(topics = ["scope", "epoch"])]
pub struct ScopeEpochSet {
    #[topic]
    pub scope: BytesN<32>,
    pub epoch: u64,
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
    PendingAdmin,
    /// Merkle root of the credential-revocation tree (set by admin).
    RevocationRoot,
    /// Per-scope epoch counter for scoped nullifier replay prevention.
    ScopeEpoch(BytesN<32>),
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
    /// The epoch in the scoped proof does not match the current epoch for that scope.
    StaleEpoch = 14,
    /// The scope identifier is invalid (empty, too long, or not registered).
    InvalidScope = 15,
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
        let record: Option<ProofRecord> = env.storage().persistent().get(&DataKey::Proof(proof_id));
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
    // Scope epoch management (scoped nullifier v1)
    // -----------------------------------------------------------------------

    /// Set the current epoch for a given scope identifier.
    ///
    /// When the admin advances the epoch for a scope, all proofs generated
    /// under the previous epoch for that scope will have stale epoch values
    /// and will be rejected by `register_anonymous_verified`.
    ///
    /// The scope is a 32-byte identifier derived from the scope string
    /// (e.g., SHA-256 hash mod BN254 field).  An empty (zero) scope
    /// represents the global/unscoped context.
    ///
    /// Only the registry admin may call this.
    pub fn set_scope_epoch(env: Env, admin: Address, scope: BytesN<32>, epoch: u64) {
        require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::ScopeEpoch(scope.clone()), &epoch);
        ScopeEpochSet { scope, epoch }.publish(&env);
    }

    /// Get the current epoch for a given scope.
    /// Returns `DEFAULT_SCOPE_EPOCH` (0) if no epoch has been set.
    pub fn get_scope_epoch(env: Env, scope: BytesN<32>) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::ScopeEpoch(scope))
            .unwrap_or(DEFAULT_SCOPE_EPOCH)
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

        let input_len = public_inputs.len();

        if input_len == SILENT_WITNESS_V2_INPUT_LEN {
            // v2 scoped nullifier path
            let parsed = parse_scoped_silent_witness_public_inputs(&env, &public_inputs);
            if parsed.video_hash != video_hash {
                panic_with_error!(&env, RegistryError::InvalidPublicInputs);
            }
            require_active_credential_root(&env, &parsed.credential_root);

            // Epoch validation: the proof's epoch must match the current epoch for its scope.
            let current_epoch = get_scope_epoch_raw(&env, &parsed.verifier_scope);
            if parsed.epoch != current_epoch {
                panic_with_error!(&env, RegistryError::StaleEpoch);
            }

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
        } else if input_len == SILENT_WITNESS_V1_INPUT_LEN {
            // v1 legacy path (backward compatible)
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
        } else {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }
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
        env.storage().persistent().get(&DataKey::RevocationRoot)
    }

    /// Verify a non-revocation proof produced by the `revocation_witness`
    /// Noir circuit.
    ///
    /// The proof demonstrates that `credential_root` is **not** a member of
    /// the currently-published revocation tree (`revocation_root`) without
    /// revealing which revoked credentials exist or which identity is acting.
    ///
    /// # Public input layout (128 bytes, 4 x BN254 field elements)
    ///
    /// ```text
    /// [  0.. 32)  revocation_root   - must match the on-chain stored root
    /// [ 32.. 64)  nullifier         - one-use replay guard
    /// [ 64.. 96)  domain_separator  - must match REVOCATION_DOMAIN_SEPARATOR
    /// [ 96..128)  credential_root   - must be registered & active on-chain
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

        // 1. Domain binding - must match the expected version tag.
        let expected_domain = BytesN::from_array(&env, &REVOCATION_DOMAIN_SEPARATOR);
        if parsed.domain_separator != expected_domain {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }

        // 2. Revocation root - must match the currently published root.
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

// ---------------------------------------------------------------------------
// Silent Witness v1 public input parsing (backward compatible)
// ---------------------------------------------------------------------------

struct SilentWitnessInputs {
    video_hash: BytesN<32>,
    credential_root: BytesN<32>,
    nullifier: BytesN<32>,
}

/// Parse the 128-byte public-input blob produced by the v1 silent_witness
/// Noir circuit.
///
/// Layout (4 x BN254 field elements, 32 bytes each):
///   [  0.. 32)  video_hash_hi + video_hash_lo (packed)
///   [ 32.. 64)  video_hash_lo continued
///   [ 64.. 96)  credential_root
///   [ 96..128)  nullifier
fn parse_silent_witness_public_inputs(env: &Env, public_inputs: &Bytes) -> SilentWitnessInputs {
    if public_inputs.len() != SILENT_WITNESS_V1_INPUT_LEN {
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

// ---------------------------------------------------------------------------
// Silent Witness v2 (scoped) public input parsing
// ---------------------------------------------------------------------------

struct ScopedSilentWitnessInputs {
    video_hash: BytesN<32>,
    credential_root: BytesN<32>,
    nullifier: BytesN<32>,
    verifier_scope: BytesN<32>,
    epoch: u64,
}

/// Parse the 192-byte public-input blob produced by the v2 scoped
/// silent_witness Noir circuit.
///
/// Layout (6 x BN254 field elements, 32 bytes each):
///   [  0.. 32)  video_hash_hi + video_hash_lo (packed)
///   [ 32.. 64)  video_hash_lo continued
///   [ 64.. 96)  credential_root
///   [ 96..128)  nullifier
///   [128..160)  verifier_scope
///   [160..192)  epoch
fn parse_scoped_silent_witness_public_inputs(
    env: &Env,
    public_inputs: &Bytes,
) -> ScopedSilentWitnessInputs {
    if public_inputs.len() != SILENT_WITNESS_V2_INPUT_LEN {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }

    let mut bytes = [0u8; 192];
    public_inputs.copy_into_slice(&mut bytes);

    let mut video_hash = [0u8; 32];
    video_hash[..16].copy_from_slice(&bytes[16..32]);
    video_hash[16..].copy_from_slice(&bytes[48..64]);

    let mut credential_root = [0u8; 32];
    credential_root.copy_from_slice(&bytes[64..96]);

    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&bytes[96..128]);

    let mut verifier_scope = [0u8; 32];
    verifier_scope.copy_from_slice(&bytes[128..160]);

    let mut epoch_bytes = [0u8; 32];
    epoch_bytes.copy_from_slice(&bytes[160..192]);
    let epoch = bytes_to_u64_be(&epoch_bytes);

    ScopedSilentWitnessInputs {
        video_hash: BytesN::from_array(env, &video_hash),
        credential_root: BytesN::from_array(env, &credential_root),
        nullifier: BytesN::from_array(env, &nullifier),
        verifier_scope: BytesN::from_array(env, &verifier_scope),
        epoch,
    }
}

/// Convert a 32-byte big-endian value to a u64.
/// Only the last 8 bytes are used; upper bytes must be zero for valid epochs.
fn bytes_to_u64_be(bytes: &[u8; 32]) -> u64 {
    // Check that upper bytes are zero (epoch must fit in u64)
    for b in &bytes[..24] {
        if *b != 0 {
            // Epoch value overflows u64 — treat as invalid (max)
            return u64::MAX;
        }
    }
    let mut val: u64 = 0;
    for b in &bytes[24..32] {
        val = (val << 8) | (*b as u64);
    }
    val
}

/// Get the raw scope epoch value for a scope field element.
fn get_scope_epoch_raw(env: &Env, scope: &BytesN<32>) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::ScopeEpoch(scope.clone()))
        .unwrap_or(DEFAULT_SCOPE_EPOCH)
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

/// Parse the 128-byte public-input blob produced by the revocation_witness
/// Noir circuit.
///
/// Layout (4 x BN254 field elements, 32 bytes each):
///   [  0.. 32)  revocation_root
///   [ 32.. 64)  nullifier
///   [ 64.. 96)  domain_separator
///   [ 96..128)  credential_root
fn parse_revocation_public_inputs(env: &Env, public_inputs: &Bytes) -> RevocationPublicInputs {
    if public_inputs.len() != 128 {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }

    let mut bytes = [0u8; 128];
    public_inputs.copy_into_slice(&mut bytes);

    // Each field is a contiguous 32-byte slice.
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
    !proof.is_empty() && credential_root.len() == 32
}

#[cfg(test)]
mod test;
#[cfg(test)]
mod test_auth;
#[cfg(test)]
mod test_budget;
#[cfg(test)]
mod test_expiry;
#[cfg(test)]
mod test_invariants;
#[cfg(test)]
mod test_revocation;
#[cfg(test)]
mod test_scoped_nullifier;
#[cfg(test)]
mod test_state_machine;
#[cfg(test)]
mod test_lifecycle;
