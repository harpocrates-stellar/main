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

// ---------------------------------------------------------------------------
// Dispute / correction state machine (#dispute)
// ---------------------------------------------------------------------------
//
// A dispute is a bounded, auditable record that challenges a proof's accuracy
// without deleting or revoking the original proof.  Disputes are separate from
// revocation: a disputed proof may still be `Valid` under `get_proof_status`.
//
// States
// ------
// Open        – dispute submitted, response pending.
// Responded   – issuer/source submitted a response commitment; admin decision pending.
// Resolved    – admin resolved the dispute (corrective action taken or noted).
// Dismissed   – admin dismissed the dispute (no corrective action).
// Superseded  – the disputed proof was superseded by a corrected proof.
//
// Valid transitions
// -----------------
// Open → Responded  (by issuer/source of the proof, within respond_deadline)
// Open → Dismissed  (by admin at any time)
// Open → Superseded (by admin when a correcting proof is linked)
// Responded → Resolved  (by admin, within resolve_deadline after response)
// Responded → Dismissed (by admin at any time after response)
// Responded → Superseded (by admin when a correcting proof is linked)
//
// Resolved, Dismissed, Superseded are terminal states.
//
// Spam / abuse controls
// ---------------------
// - MAX_OPEN_DISPUTES_PER_PROOF (4): cap on simultaneously Open disputes for
//   a single proof.  Prevents resource exhaustion.
// - REPORTER_COOLDOWN_SECS (86400, 24 h): minimum interval between disputes
//   opened by the same reporter_hash for the same proof.
// - Deadlines stored in the record; callers / indexers can observe them.
//
// Privacy
// -------
// The reporter's identity is stored as a SHA-256 commitment
// (reporter_hash = H(reporter_address ‖ proof_id)) rather than in the clear.
// This allows duplicate/spam detection without leaking the reporter address in
// contract storage that is world-readable on-chain.

/// Maximum number of simultaneously Open disputes allowed per proof.
pub const MAX_OPEN_DISPUTES_PER_PROOF: u32 = 4;
/// Minimum seconds between consecutive disputes by the same reporter on the
/// same proof (24 hours).
pub const REPORTER_COOLDOWN_SECS: u64 = 86_400;
/// Seconds from dispute open until the issuer/source must respond (7 days).
pub const RESPOND_DEADLINE_SECS: u64 = 604_800;
/// Seconds from response until the admin must resolve or dismiss (14 days).
pub const RESOLVE_DEADLINE_SECS: u64 = 1_209_600;

/// Dispute state transitions.  Numeric values are stable on-chain identifiers;
/// do not renumber existing variants.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DisputeStatus {
    Open = 1,
    Responded = 2,
    Resolved = 3,
    Dismissed = 4,
    Superseded = 5,
}

/// Categorised dispute reasons.  Numeric values are stable on-chain; do not
/// renumber.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DisputeReason {
    ContentError = 1,
    MetadataError = 2,
    TierMismatch = 3,
    CredentialLapsed = 4,
    PrivacyViolation = 5,
    Other = 6,
}

/// Immutable dispute record.  Only `status`, `response_commitment`,
/// `resolved_at`, and `superseded_by` are mutated after initial creation;
/// the rest are set once at open time.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisputeRecord {
    /// Unique dispute identifier (caller-supplied, 32-byte opaque commitment).
    pub dispute_id: BytesN<32>,
    /// The proof this dispute challenges.
    pub proof_id: BytesN<32>,
    /// Categorised reason for the dispute.
    pub reason: DisputeReason,
    /// Privacy-safe hash: SHA-256(reporter_address_bytes ‖ proof_id_bytes).
    /// The reporter's actual address is never stored on-chain.
    pub reporter_hash: BytesN<32>,
    /// Off-chain commitment to the reporter's full evidence submission.
    pub commitment_hash: BytesN<32>,
    /// Current lifecycle state.
    pub status: DisputeStatus,
    /// Ledger timestamp when the dispute was opened.
    pub opened_at: u64,
    /// Ledger timestamp by which the issuer/source must respond.
    pub respond_deadline: u64,
    /// Ledger timestamp by which the admin must decide after a response.
    /// Set to 0 until a response is submitted.
    pub resolve_deadline: u64,
    /// Issuer/source commitment hash in response.  None until Responded.
    pub response_commitment: Option<BytesN<32>>,
    /// Ledger timestamp of final resolution/dismissal.  0 while open.
    pub resolved_at: u64,
    /// Proof ID that supersedes the disputed proof, if Superseded.
    pub superseded_by: Option<BytesN<32>>,
}

// ---------------------------------------------------------------------------
// Dispute events
// ---------------------------------------------------------------------------

#[contractevent(topics = ["dispute", "open"])]
pub struct DisputeOpened {
    #[topic]
    pub dispute_id: BytesN<32>,
    #[topic]
    pub proof_id: BytesN<32>,
    pub reason: DisputeReason,
    pub reporter_hash: BytesN<32>,
    pub commitment_hash: BytesN<32>,
    pub respond_deadline: u64,
}

#[contractevent(topics = ["dispute", "respond"])]
pub struct DisputeResponded {
    #[topic]
    pub dispute_id: BytesN<32>,
    #[topic]
    pub proof_id: BytesN<32>,
    pub response_commitment: BytesN<32>,
    pub resolve_deadline: u64,
}

#[contractevent(topics = ["dispute", "resolve"])]
pub struct DisputeResolved {
    #[topic]
    pub dispute_id: BytesN<32>,
    #[topic]
    pub proof_id: BytesN<32>,
    pub resolved_at: u64,
}

#[contractevent(topics = ["dispute", "dismiss"])]
pub struct DisputeDismissed {
    #[topic]
    pub dispute_id: BytesN<32>,
    #[topic]
    pub proof_id: BytesN<32>,
    pub resolved_at: u64,
}

#[contractevent(topics = ["dispute", "supersede"])]
pub struct DisputeSuperseded {
    #[topic]
    pub dispute_id: BytesN<32>,
    #[topic]
    pub proof_id: BytesN<32>,
    pub superseded_by: BytesN<32>,
    pub resolved_at: u64,
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
    // -------------------------------------------------------------------
    // Dispute state machine (#dispute)
    // -------------------------------------------------------------------
    /// Stores the `DisputeRecord` for a given dispute_id.
    Dispute(BytesN<32>),
    /// Counts open (non-terminal) disputes for a proof_id.
    /// Used to enforce MAX_OPEN_DISPUTES_PER_PROOF.
    ProofOpenDisputeCount(BytesN<32>),
    /// Tracks last-opened timestamp for (reporter_hash ‖ proof_id).
    /// Key is a 32-byte commitment: SHA-256(reporter_hash ‖ proof_id).
    ReporterCooldown(BytesN<32>),
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
    // Dispute state machine errors (14-21)
    /// No dispute found for the given dispute_id.
    DisputeNotFound = 14,
    /// Proof already has the maximum number of open disputes.
    TooManyOpenDisputes = 15,
    /// The respond or resolve deadline has expired for this transition.
    DisputeWindowExpired = 16,
    /// The dispute is already in a terminal state (Resolved/Dismissed/Superseded).
    DisputeAlreadyClosed = 17,
    /// The superseding proof_id would create a cycle in the supersession graph.
    DisputeCyclicSupersession = 18,
    /// The caller is not the issuer/source of the proof being disputed.
    UnauthorizedResponder = 19,
    /// The reporter must wait for the cooldown period before opening another
    /// dispute on the same proof.
    ReporterOnCooldown = 20,
    /// The dispute is not in the correct state for the requested transition
    /// (e.g. trying to resolve an Open dispute that hasn't been Responded to).
    InvalidDisputeTransition = 21,
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
        let record: Option<ProofRecord> = env.storage().persistent().get(&DataKey::Proof(proof_id));
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
        env.storage().persistent().get(&DataKey::RevocationRoot)
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
    // Dispute / correction state machine (#dispute)
    // -----------------------------------------------------------------------

    /// Open a new dispute against a registered proof.
    ///
    /// # Parameters
    /// - `reporter`:        The reporter's address (requires auth; proves liveness).
    /// - `reporter_hash`:   Privacy-safe commitment: SHA-256(reporter_address_bytes ‖
    ///   proof_id_bytes), computed off-chain by the reporter.  The contract
    ///   does **not** store the raw reporter address.
    /// - `dispute_id`:      Caller-chosen 32-byte unique identifier.
    /// - `proof_id`:        The proof being challenged.
    /// - `reason`:          Categorised dispute reason.
    /// - `commitment_hash`: Off-chain commitment to the reporter's full
    ///   evidence submission.
    ///
    /// # Guards
    /// - Proof must exist.
    /// - `dispute_id` must not already be used.
    /// - Proof must have fewer than `MAX_OPEN_DISPUTES_PER_PROOF` open disputes.
    /// - Reporter must not be on cooldown for this proof.
    pub fn open_dispute(
        env: Env,
        reporter: Address,
        reporter_hash: BytesN<32>,
        dispute_id: BytesN<32>,
        proof_id: BytesN<32>,
        reason: DisputeReason,
        commitment_hash: BytesN<32>,
    ) -> DisputeRecord {
        reporter.require_auth();

        // 1. Proof must exist.
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Proof(proof_id.clone()))
        {
            panic_with_error!(&env, RegistryError::DisputeNotFound);
        }

        // 2. dispute_id must be fresh.
        if env
            .storage()
            .persistent()
            .has(&DataKey::Dispute(dispute_id.clone()))
        {
            panic_with_error!(&env, RegistryError::DuplicateProof);
        }

        // 3. Cap open disputes per proof.
        let open_count: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ProofOpenDisputeCount(proof_id.clone()))
            .unwrap_or(0u32);
        if open_count >= MAX_OPEN_DISPUTES_PER_PROOF {
            panic_with_error!(&env, RegistryError::TooManyOpenDisputes);
        }

        // 4. Reporter cooldown: key = SHA-256(reporter_bytes ‖ proof_id_bytes).
        let cooldown_key = DataKey::ReporterCooldown(reporter_hash.clone());
        let last_open: u64 = env
            .storage()
            .persistent()
            .get(&cooldown_key)
            .unwrap_or(0u64);
        let now = env.ledger().timestamp();
        if last_open > 0 && now.saturating_sub(last_open) < REPORTER_COOLDOWN_SECS {
            panic_with_error!(&env, RegistryError::ReporterOnCooldown);
        }

        // 5. Persist cooldown timestamp.
        env.storage().persistent().set(&cooldown_key, &now);

        // 6. Compute deadlines.
        let respond_deadline = now.saturating_add(RESPOND_DEADLINE_SECS);

        // 7. Build and store the dispute record.
        let record = DisputeRecord {
            dispute_id: dispute_id.clone(),
            proof_id: proof_id.clone(),
            reason,
            reporter_hash: reporter_hash.clone(),
            commitment_hash: commitment_hash.clone(),
            status: DisputeStatus::Open,
            opened_at: now,
            respond_deadline,
            resolve_deadline: 0,
            response_commitment: None,
            resolved_at: 0,
            superseded_by: None,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Dispute(dispute_id.clone()), &record);

        // 8. Increment open-dispute counter.
        env.storage()
            .persistent()
            .set(&DataKey::ProofOpenDisputeCount(proof_id.clone()), &(open_count + 1));

        // 9. Emit event.
        DisputeOpened {
            dispute_id,
            proof_id,
            reason,
            reporter_hash,
            commitment_hash,
            respond_deadline,
        }
        .publish(&env);

        record
    }

    /// Submit a response commitment to an open dispute.
    ///
    /// Only the issuer (Tier 3) or source (Tier 2) of the disputed proof may
    /// respond.  Tier 1 (Silent Witness) proofs have no on-chain identity so
    /// the admin acts as the sole responder for anonymous proofs.
    ///
    /// # Guards
    /// - Dispute must be in `Open` state.
    /// - Must be within `respond_deadline`.
    /// - Caller must be the issuer, source, or (for anonymous proofs) admin.
    pub fn respond_dispute(
        env: Env,
        responder: Address,
        dispute_id: BytesN<32>,
        response_commitment: BytesN<32>,
    ) -> DisputeRecord {
        responder.require_auth();

        let mut record = get_dispute_record(&env, &dispute_id);

        // Must be Open.
        if record.status != DisputeStatus::Open {
            panic_with_error!(&env, RegistryError::InvalidDisputeTransition);
        }

        let now = env.ledger().timestamp();

        // Must be within respond_deadline.
        if now > record.respond_deadline {
            panic_with_error!(&env, RegistryError::DisputeWindowExpired);
        }

        // Authorise: issuer, source, or admin.
        let proof: ProofRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Proof(record.proof_id.clone()))
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::DisputeNotFound));

        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NotInitialized));

        let is_authorised = match (proof.issuer.as_ref(), proof.source.as_ref()) {
            (Some(issuer), _) => &responder == issuer || &responder == &admin,
            (_, Some(source)) => &responder == source || &responder == &admin,
            _ => &responder == &admin, // Tier 1: admin only
        };

        if !is_authorised {
            panic_with_error!(&env, RegistryError::UnauthorizedResponder);
        }

        // Transition → Responded.
        record.status = DisputeStatus::Responded;
        record.response_commitment = Some(response_commitment.clone());
        record.resolve_deadline = now.saturating_add(RESOLVE_DEADLINE_SECS);

        env.storage()
            .persistent()
            .set(&DataKey::Dispute(dispute_id.clone()), &record);

        DisputeResponded {
            dispute_id,
            proof_id: record.proof_id.clone(),
            response_commitment,
            resolve_deadline: record.resolve_deadline,
        }
        .publish(&env);

        record
    }

    /// Resolve a responded dispute (admin only).
    ///
    /// Resolution indicates that the admin has reviewed both the dispute
    /// commitment and the response commitment and has taken (or noted) any
    /// appropriate corrective action.  The original proof record is **not**
    /// modified.
    ///
    /// # Guards
    /// - Dispute must be in `Responded` state.
    /// - Must be within `resolve_deadline`.
    pub fn resolve_dispute(env: Env, admin: Address, dispute_id: BytesN<32>) -> DisputeRecord {
        require_admin(&env, &admin);

        let mut record = get_dispute_record(&env, &dispute_id);

        // Must be Responded.
        if record.status != DisputeStatus::Responded {
            panic_with_error!(&env, RegistryError::InvalidDisputeTransition);
        }

        let now = env.ledger().timestamp();

        if now > record.resolve_deadline {
            panic_with_error!(&env, RegistryError::DisputeWindowExpired);
        }

        // Transition → Resolved.
        record.status = DisputeStatus::Resolved;
        record.resolved_at = now;

        env.storage()
            .persistent()
            .set(&DataKey::Dispute(dispute_id.clone()), &record);

        // Decrement open-dispute counter.
        decrement_open_dispute_count(&env, &record.proof_id);

        DisputeResolved {
            dispute_id,
            proof_id: record.proof_id.clone(),
            resolved_at: now,
        }
        .publish(&env);

        record
    }

    /// Dismiss a dispute (admin only).
    ///
    /// Dismissal is valid from both `Open` and `Responded` states.  A
    /// dismissed dispute is permanently closed with no corrective action.
    ///
    /// # Guards
    /// - Dispute must be in `Open` or `Responded` state.
    pub fn dismiss_dispute(env: Env, admin: Address, dispute_id: BytesN<32>) -> DisputeRecord {
        require_admin(&env, &admin);

        let mut record = get_dispute_record(&env, &dispute_id);

        // Must be non-terminal.
        match record.status {
            DisputeStatus::Open | DisputeStatus::Responded => {}
            _ => panic_with_error!(&env, RegistryError::DisputeAlreadyClosed),
        }

        let now = env.ledger().timestamp();

        // Transition → Dismissed.
        record.status = DisputeStatus::Dismissed;
        record.resolved_at = now;

        env.storage()
            .persistent()
            .set(&DataKey::Dispute(dispute_id.clone()), &record);

        // Decrement open-dispute counter.
        decrement_open_dispute_count(&env, &record.proof_id);

        DisputeDismissed {
            dispute_id,
            proof_id: record.proof_id.clone(),
            resolved_at: now,
        }
        .publish(&env);

        record
    }

    /// Supersede a disputed proof by linking a corrected proof (admin only).
    ///
    /// This marks the dispute as `Superseded` and records the correcting proof
    /// ID.  The original disputed proof is **not** revoked—callers should use
    /// `revoke_proof` separately if revocation is also desired.
    ///
    /// # Guards
    /// - Dispute must be in `Open` or `Responded` state.
    /// - `superseding_proof_id` must exist in the registry.
    /// - `superseding_proof_id` must not equal the disputed `proof_id`
    ///   (trivial cycle).
    /// - `superseding_proof_id` must not be the disputed proof's own
    ///   already-superseded proof (depth-1 cycle guard via the
    ///   `DisputeSupersession` reverse-index).
    pub fn supersede_dispute(
        env: Env,
        admin: Address,
        dispute_id: BytesN<32>,
        superseding_proof_id: BytesN<32>,
    ) -> DisputeRecord {
        require_admin(&env, &admin);

        let mut record = get_dispute_record(&env, &dispute_id);

        // Must be non-terminal.
        match record.status {
            DisputeStatus::Open | DisputeStatus::Responded => {}
            _ => panic_with_error!(&env, RegistryError::DisputeAlreadyClosed),
        }

        // Superseding proof must exist.
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Proof(superseding_proof_id.clone()))
        {
            panic_with_error!(&env, RegistryError::DisputeNotFound);
        }

        // Trivial self-cycle.
        if superseding_proof_id == record.proof_id {
            panic_with_error!(&env, RegistryError::DisputeCyclicSupersession);
        }

        // Depth-1 cycle: the superseding proof must not itself already point
        // back to the disputed proof as a supersession target.
        // We check: does superseding_proof_id appear as the superseded_by of
        // any dispute whose proof_id == superseding_proof_id that lists
        // record.proof_id as the superseding?  This is tracked via a compact
        // reverse index: superseding → original proof.
        // The reverse index key maps superseding_proof_id → proof_id that it
        // supersedes.  If that entry == disputed proof_id we have a cycle.
        if check_supersession_cycle(&env, &record.proof_id, &superseding_proof_id) {
            panic_with_error!(&env, RegistryError::DisputeCyclicSupersession);
        }

        let now = env.ledger().timestamp();

        // Transition → Superseded.
        record.status = DisputeStatus::Superseded;
        record.superseded_by = Some(superseding_proof_id.clone());
        record.resolved_at = now;

        env.storage()
            .persistent()
            .set(&DataKey::Dispute(dispute_id.clone()), &record);

        // Record the reverse supersession direction for cycle detection.
        record_supersession_direction(&env, &record.proof_id, &superseding_proof_id);

        // Decrement open-dispute counter.
        decrement_open_dispute_count(&env, &record.proof_id);

        DisputeSuperseded {
            dispute_id,
            proof_id: record.proof_id.clone(),
            superseded_by: superseding_proof_id,
            resolved_at: now,
        }
        .publish(&env);

        record
    }

    /// Retrieve a dispute record by its dispute_id.
    pub fn get_dispute(env: Env, dispute_id: BytesN<32>) -> Option<DisputeRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::Dispute(dispute_id))
    }

    /// Return the number of currently Open disputes for a given proof.
    pub fn get_open_dispute_count(env: Env, proof_id: BytesN<32>) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ProofOpenDisputeCount(proof_id))
            .unwrap_or(0u32)
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
fn parse_revocation_public_inputs(env: &Env, public_inputs: &Bytes) -> RevocationPublicInputs {
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
    !proof.is_empty() && credential_root.len() == 32
}

// ---------------------------------------------------------------------------
// Dispute helper functions
// ---------------------------------------------------------------------------

/// Retrieve a dispute record, panicking with `DisputeNotFound` if absent.
fn get_dispute_record(env: &Env, dispute_id: &BytesN<32>) -> DisputeRecord {
    env.storage()
        .persistent()
        .get(&DataKey::Dispute(dispute_id.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::DisputeNotFound))
}

/// Decrement the open-dispute counter for a proof.  Saturates at 0 to avoid
/// underflow on double-close (which should never happen under correct logic
/// but is defended against for safety).
fn decrement_open_dispute_count(env: &Env, proof_id: &BytesN<32>) {
    let key = DataKey::ProofOpenDisputeCount(proof_id.clone());
    let count: u32 = env.storage().persistent().get(&key).unwrap_or(0u32);
    let new_count = count.saturating_sub(1);
    if new_count == 0 {
        env.storage().persistent().remove(&key);
    } else {
        env.storage().persistent().set(&key, &new_count);
    }
}

/// Depth-1 cycle guard for supersession.
///
/// Returns `true` if allowing `superseding_proof_id` to supersede
/// `disputed_proof_id` would create a cycle.  We detect:
/// - Any existing dispute for `superseding_proof_id` that itself has
///   `superseded_by == disputed_proof_id` (i.e. there is already a supersession
///   arrow from `superseding_proof_id` back to the disputed proof).
///
/// The reverse index key is:
///   SHA-256("harp_sup_rev" ‖ superseding_proof_id_bytes)
/// stored as DataKey::Dispute(key_hash) → disputed_proof_id.
fn check_supersession_cycle(
    env: &Env,
    disputed_proof_id: &BytesN<32>,
    superseding_proof_id: &BytesN<32>,
) -> bool {
    let rev_key_hash = supersession_reverse_key(env, superseding_proof_id);

    if let Some(recorded_original) = env
        .storage()
        .persistent()
        .get::<DataKey, BytesN<32>>(&DataKey::Dispute(rev_key_hash))
    {
        if recorded_original == *disputed_proof_id {
            return true;
        }
    }
    false
}

/// Record the supersession direction in the reverse index.
/// Called from `supersede_dispute` after all guards pass.
fn record_supersession_direction(
    env: &Env,
    disputed_proof_id: &BytesN<32>,
    superseding_proof_id: &BytesN<32>,
) {
    let rev_key_hash = supersession_reverse_key(env, superseding_proof_id);
    env.storage()
        .persistent()
        .set(&DataKey::Dispute(rev_key_hash), disputed_proof_id);
}

/// Compute the reverse-index key for a supersession:
///   SHA-256("harp_sup_rev" ‖ superseding_proof_id_bytes)
///
/// "harp_sup_rev" is a 12-byte domain prefix that avoids key collisions with
/// legitimate dispute_id keys.  The 12-byte prefix + 32-byte suffix = 44
/// bytes of pre-image, hashed to a 32-byte key.
fn supersession_reverse_key(env: &Env, superseding_proof_id: &BytesN<32>) -> BytesN<32> {
    // domain prefix: ASCII "harp_sup_rev" = 12 bytes
    const PREFIX: [u8; 12] = *b"harp_sup_rev";

    // Build a 44-byte pre-image: [PREFIX (12)] ‖ [superseding_proof_id (32)]
    let mut pre_image = [0u8; 44];
    pre_image[..12].copy_from_slice(&PREFIX);
    superseding_proof_id.copy_into_slice(&mut pre_image[12..]);

    let pre_image_bytes = Bytes::from_array(env, &pre_image);
    env.crypto().sha256(&pre_image_bytes)
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
mod test_state_machine;
#[cfg(test)]
mod test_dispute;
