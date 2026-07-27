#![no_std]

#[cfg(test)]
extern crate std;

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address,
    Bytes, BytesN, Env, IntoVal, InvokeError, Symbol, Val, Vec as SorobanVec,
};

pub mod verifier_inputs;

use verifier_inputs::{RejectCode, PUBLIC_INPUTS_LEN};

/// Schema selectors accepted by [`HarpocratesRegistry::classify_public_inputs`].
pub const SCHEMA_ID_SILENT_WITNESS: u32 = 1;
pub const SCHEMA_ID_REVOCATION_WITNESS: u32 = 2;

const TIER_SILENT_WITNESS: u32 = 1;
const TIER_CONSISTENT_SOURCE: u32 = 2;
const TIER_PUBLIC_SEAL: u32 = 3;

const STATUS_REGISTERED: u32 = 1;
const STATUS_REVOKED: u32 = 2;
const STATUS_EXPIRED: u32 = 3;

pub const DEFAULT_PROOF_TTL_SECS: u64 = 0;

const STATUS_POLICY_ACTIVE: u32 = 1;
const STATUS_POLICY_CANCELLED: u32 = 2;

const MAX_SIGNERS: u32 = 16;
const DEFAULT_APPROVAL_TTL_SECS: u64 = 86_400;

const MAX_LINEAGE_DEPTH: u32 = 4;
const MAX_LINEAGE_FANOUT: u32 = 4;
const MAX_LINEAGE_PAYLOAD_BYTES: u32 = 4096;

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

// ---------------------------------------------------------------------------
// Scoped emergency pause controls (#87)
// ---------------------------------------------------------------------------
//
// Pauses are scoped per registration domain (one bit per identity tier) so a
// compromised path can be contained without freezing unaffected tiers or any
// read entry point. Reads (`get_proof`, `get_proof_status`, `get_by_video`,
// `has_nullifier`, `get_issuer`, `get_credential_root`, `get_verifier`,
// `is_paused`, `get_pause_state`) are never gated by pause state. Admin
// remediation entry points (`revoke_proof`, `revoke_issuer`,
// `revoke_credential_root`, `set_verifier`) also stay callable while paused,
// since incident response depends on them.
//
// Every pause is bounded: callers supply a `duration_secs` capped by
// `MAX_PAUSE_DURATION_SECS` (admin) or `MAX_GUARDIAN_PAUSE_DURATION_SECS`
// (guardian). A pause auto-expires once `ledger().timestamp() >=
// expires_at`, so a lost admin/guardian key cannot brick registration
// forever. `pause` is idempotent (re-pausing overwrites/extends the
// existing record); `unpause` on an already-unpaused domain is a no-op.
// Only the admin can lift a pause early — a compromised guardian key can
// raise the alarm but cannot stand it down before the bounded expiry.
//
// Migration: `Guardian` and `Pause(domain)` are new, additive storage keys.
// Existing deployments read as "no guardian set" / "nothing paused" until
// the admin opts in, so upgrading is backward compatible and requires no
// migration step. Rolling back to a pre-#87 wasm simply ignores these keys.
pub const PAUSE_DOMAIN_TIER1_REGISTRATION: u32 = 1 << 0;
pub const PAUSE_DOMAIN_TIER2_REGISTRATION: u32 = 1 << 1;
pub const PAUSE_DOMAIN_TIER3_REGISTRATION: u32 = 1 << 2;
/// Convenience alias that expands to all three registration domains at once.
pub const PAUSE_DOMAIN_ALL_REGISTRATION: u32 = PAUSE_DOMAIN_TIER1_REGISTRATION
    | PAUSE_DOMAIN_TIER2_REGISTRATION
    | PAUSE_DOMAIN_TIER3_REGISTRATION;

const PAUSE_DOMAIN_SINGLE_BITS: [u32; 3] = [
    PAUSE_DOMAIN_TIER1_REGISTRATION,
    PAUSE_DOMAIN_TIER2_REGISTRATION,
    PAUSE_DOMAIN_TIER3_REGISTRATION,
];

/// Maximum pause duration an admin may set in a single call (7 days).
pub const MAX_PAUSE_DURATION_SECS: u64 = 7 * 24 * 60 * 60;
/// Maximum pause duration a guardian may set in a single call (24 hours).
/// Kept shorter than the admin cap so a compromised guardian key cannot
/// freeze registration for longer than a day without admin involvement.
pub const MAX_GUARDIAN_PAUSE_DURATION_SECS: u64 = 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Constrained issuer and source delegation (#192)
// ---------------------------------------------------------------------------
//
// A source or issuer often needs an assistant, a scheduler, or a CI job to
// register on its behalf without handing over the key. A delegation grants
// exactly one capability, for a bounded time, and nothing else.
//
// What a delegation is NOT:
//
// - It is not issuer or source authority. A delegate cannot add or revoke
//   issuers, cannot add or revoke credential roots, cannot set the verifier,
//   pause a domain, or touch admin state. Those paths still require the
//   grantor's own key.
// - It is not transitive. `grant_delegation` requires the grantor's own
//   signature, and the delegated registration entry points are not grant entry
//   points, so there is no call path by which a delegate can re-delegate the
//   authority it received. A delegate that grants to a third party grants only
//   *its own* authority; the third party still cannot act for the original
//   grantor. This is enforced by construction, not by a runtime scan, so it
//   holds without bounding a delegation graph walk.
// - It is not attribution laundering. The registered `ProofRecord` still names
//   the grantor as source/issuer; the delegate appears only in the proof's
//   lifecycle history, so an auditor can see who actually acted.
//
// Bounds. `scope` must be a non-empty subset of the known scope bits.
// `duration_secs` must be non-zero and at most `MAX_DELEGATION_DURATION_SECS`.
// A grantor may hold at most `MAX_DELEGATIONS_PER_GRANTOR` distinct delegate
// addresses; re-granting to an existing delegate overwrites its record and does
// not consume another slot, so retries and renewals are idempotent in storage.
//
// Expiry. A delegation lapses on its own at `expires_at` — a forgotten grant
// cannot become permanent authority. An expired record still occupies its slot
// until `revoke_delegation` prunes it, which keeps the cap a simple, auditable
// count of distinct delegates rather than a time-dependent quantity.
//
// Migration. `Delegation` and `DelegationCount` are new, additive storage keys
// and the delegated entry points are new functions. Existing deployments read
// as "no delegations" until a grantor opts in; no migration step is required.
// Rolling back to a pre-#192 wasm ignores these keys, which fails closed: the
// delegated entry points disappear and only direct-key registration remains.

/// A delegate may call `register_source_delegated` for the grantor.
pub const DELEGATION_SCOPE_REGISTER_SOURCE: u32 = 1 << 0;
/// A delegate may call `register_seal_delegated` for the grantor.
pub const DELEGATION_SCOPE_REGISTER_SEAL: u32 = 1 << 1;
/// Every known scope bit. Used to reject unknown bits in `scope`.
pub const DELEGATION_SCOPE_ALL: u32 =
    DELEGATION_SCOPE_REGISTER_SOURCE | DELEGATION_SCOPE_REGISTER_SEAL;

/// Longest delegation a grantor may issue in a single call (30 days).
pub const MAX_DELEGATION_DURATION_SECS: u64 = 30 * 24 * 60 * 60;

/// Maximum number of distinct delegate addresses a single grantor may hold.
/// Bounds per-grantor storage growth under a hostile or buggy client.
pub const MAX_DELEGATIONS_PER_GRANTOR: u32 = 32;

/// A narrowly scoped, expiring authority to act for `grantor`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationRecord {
    pub grantor: Address,
    pub delegate: Address,
    /// Bitwise-OR of `DELEGATION_SCOPE_*`.
    pub scope: u32,
    pub granted_at: u64,
    /// Epoch seconds after which the delegation is inert. Never zero.
    pub expires_at: u64,
}

#[contractevent(topics = ["deleg", "grant"])]
pub struct DelegationGranted {
    #[topic]
    pub grantor: Address,
    #[topic]
    pub delegate: Address,
    pub scope: u32,
    pub granted_at: u64,
    pub expires_at: u64,
}

#[contractevent(topics = ["deleg", "revoke"])]
pub struct DelegationRevoked {
    #[topic]
    pub grantor: Address,
    #[topic]
    pub delegate: Address,
    pub revoked_by: Address,
    pub revoked_at: u64,
}

#[contractevent(topics = ["deleg", "used"])]
pub struct DelegationUsed {
    #[topic]
    pub grantor: Address,
    #[topic]
    pub delegate: Address,
    pub scope: u32,
    pub proof_id: BytesN<32>,
}

/// Threshold in ledgers below which we extend the TTL of records (approx 14 days)
pub const BUMP_THRESHOLD_LEDGERS: u32 = 241_920;

/// Target TTL in ledgers when extending the TTL of records (approx 30 days)
pub const BUMP_TARGET_LEDGERS: u32 = 518_400;

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
pub struct LineageRecord {
    pub parent_proof_ids: SorobanVec<BytesN<32>>,
    pub manifest_digest: BytesN<32>,
    pub actor: Address,
    pub operation_type: Symbol,
    pub output_digest: BytesN<32>,
    pub depth: u32,
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

/// Pause record for a single registration domain bit. Presence of a record
/// does not by itself mean "paused" — see `domain_is_paused`, which also
/// checks `expires_at` against the current ledger time so pauses expire on
/// their own without requiring a follow-up transaction.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseRecord {
    pub paused_by: Address,
    pub paused_at: u64,
    pub expires_at: u64,
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

#[contractevent(topics = ["pause", "set"])]
pub struct DomainPaused {
    #[topic]
    pub domain: u32,
    pub paused_by: Address,
    pub paused_at: u64,
    pub expires_at: u64,
}

#[contractevent(topics = ["pause", "clear"])]
pub struct DomainUnpaused {
    #[topic]
    pub domain: u32,
    pub unpaused_by: Address,
    pub unpaused_at: u64,
}

#[contractevent(topics = ["guardian", "set"])]
pub struct GuardianSet {
    #[topic]
    pub guardian: Address,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SchemaVersion {
    V1 = 1,
}

#[contractevent(topics = ["schema", "upgrade"])]
pub struct SchemaUpgraded {
    pub previous: u32,
    pub current: u32,
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
    /// Optional emergency-pause guardian, distinct from admin (#87).
    Guardian,
    /// Pause record for a single registration domain bit (#87).
    Pause(u32),
    PendingAdmin,
    /// Merkle root of the credential-revocation tree (set by admin).
    RevocationRoot,
    ProofHistorySeq(BytesN<32>),
    ProofHistoryEntry(BytesN<32>, u32),
    /// Scoped, expiring delegation from a grantor to a delegate (#192).
    Delegation(Address, Address),
    /// Count of distinct delegate addresses held by a grantor (#192).
    DelegationCount(Address),
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
    /// The requested operation is blocked by an active domain pause (#87).
    Paused = 21,
    /// `domain` was zero or contained bits outside the known pause domains.
    InvalidPauseDomain = 22,
    /// `duration_secs` was zero or exceeded the caller's role cap.
    InvalidPauseDuration = 23,
    /// `scope` was zero or contained bits outside `DELEGATION_SCOPE_ALL` (#192).
    InvalidDelegationScope = 24,
    /// `duration_secs` was zero or above `MAX_DELEGATION_DURATION_SECS` (#192).
    InvalidDelegationDuration = 25,
    /// No delegation exists from the named grantor to the caller (#192).
    DelegationNotFound = 26,
    /// The delegation exists but its `expires_at` has passed (#192).
    DelegationExpired = 27,
    /// The delegation exists and is live, but does not carry the scope the
    /// attempted operation requires (#192).
    DelegationScopeExceeded = 28,
    /// The grantor already holds `MAX_DELEGATIONS_PER_GRANTOR` delegates (#192).
    DelegationsSaturated = 29,
    /// A grantor may not delegate to itself (#192).
    SelfDelegation = 30,
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
        env.storage()
            .persistent()
            .set(&DataKey::SchemaVersion, &(SchemaVersion::V1 as u32));
    }

    pub fn upgrade_storage(env: Env, admin: Address) {
        require_admin(&env, &admin);

        let current_version: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::SchemaVersion)
            .unwrap_or(SchemaVersion::V1 as u32);

        let target_version = SchemaVersion::V1 as u32;

        if current_version < target_version {
            // Migrations will be added here when moving to V2, V3, etc.
            
            env.storage()
                .persistent()
                .set(&DataKey::SchemaVersion, &target_version);

            SchemaUpgraded {
                previous: current_version,
                current: target_version,
            }
            .publish(&env);
        }
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

    /// Return the human-readable verification status of multiple proofs in a single
    /// batch query, efficiently retrieving them without exceeding Soroban read budgets.
    ///
    /// The maximum number of proof IDs in a single batch is bounded (e.g. 100) to
    /// ensure the query always completes within resource limits.
    pub fn get_proof_statuses(env: Env, proof_ids: SorobanVec<BytesN<32>>) -> SorobanVec<ProofVerificationStatus> {
        let max_batch_size = 100;
        if proof_ids.len() > max_batch_size {
            panic_with_error!(&env, RegistryError::BatchTooLarge);
        }
        
        let mut statuses = SorobanVec::new(&env);
        for proof_id in proof_ids.iter() {
            statuses.push_back(Self::get_proof_status(env.clone(), proof_id));
        }
        statuses
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
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER1_REGISTRATION);
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
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER1_REGISTRATION);
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
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER2_REGISTRATION);
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
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER3_REGISTRATION);
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

    // -----------------------------------------------------------------------
    // Constrained issuer and source delegation (#192)
    // -----------------------------------------------------------------------

    /// Grant `delegate` a narrowly scoped, expiring authority to register on
    /// the caller's behalf.
    ///
    /// Requires the grantor's own signature — a delegate can never create or
    /// extend a delegation, which is what makes the mechanism non-transitive.
    ///
    /// `scope` is a non-empty subset of `DELEGATION_SCOPE_ALL`.
    /// `duration_secs` is non-zero and at most `MAX_DELEGATION_DURATION_SECS`.
    ///
    /// Idempotent: re-granting to an existing delegate overwrites that
    /// delegate's record — narrowing or widening scope, extending or shortening
    /// expiry — and does not consume another storage slot. Returns the epoch
    /// second at which the delegation lapses on its own.
    ///
    /// # Reverts
    ///
    /// - `SelfDelegation`              if `grantor == delegate`
    /// - `InvalidDelegationScope`      if `scope` is zero or has unknown bits
    /// - `InvalidDelegationDuration`   if `duration_secs` is zero or over the cap
    /// - `DelegationsSaturated`        if the grantor already holds the maximum
    pub fn grant_delegation(
        env: Env,
        grantor: Address,
        delegate: Address,
        scope: u32,
        duration_secs: u64,
    ) -> u64 {
        grantor.require_auth();

        if grantor == delegate {
            panic_with_error!(&env, RegistryError::SelfDelegation);
        }
        validate_delegation_scope(&env, scope);
        if duration_secs == 0 || duration_secs > MAX_DELEGATION_DURATION_SECS {
            panic_with_error!(&env, RegistryError::InvalidDelegationDuration);
        }

        let key = DataKey::Delegation(grantor.clone(), delegate.clone());
        let is_new = !env.storage().persistent().has(&key);

        if is_new {
            let count = delegation_count(&env, &grantor);
            if count >= MAX_DELEGATIONS_PER_GRANTOR {
                panic_with_error!(&env, RegistryError::DelegationsSaturated);
            }
            env.storage()
                .persistent()
                .set(&DataKey::DelegationCount(grantor.clone()), &(count + 1));
        }

        let granted_at = env.ledger().timestamp();
        let expires_at = granted_at.saturating_add(duration_secs);

        env.storage().persistent().set(
            &key,
            &DelegationRecord {
                grantor: grantor.clone(),
                delegate: delegate.clone(),
                scope,
                granted_at,
                expires_at,
            },
        );

        DelegationGranted {
            grantor,
            delegate,
            scope,
            granted_at,
            expires_at,
        }
        .publish(&env);

        expires_at
    }

    /// Revoke a delegation ahead of its expiry.
    ///
    /// Callable by the grantor (withdrawing authority it issued) or by the
    /// admin (incident response against a compromised delegate). Revoking a
    /// delegation that does not exist is a no-op rather than an error, so
    /// retries and concurrent revocations converge.
    pub fn revoke_delegation(env: Env, revoker: Address, grantor: Address, delegate: Address) {
        revoker.require_auth();

        if revoker != grantor {
            let admin: Address = env
                .storage()
                .persistent()
                .get(&DataKey::Admin)
                .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NotInitialized));
            if revoker != admin {
                panic_with_error!(&env, RegistryError::Unauthorized);
            }
        }

        let key = DataKey::Delegation(grantor.clone(), delegate.clone());
        if !env.storage().persistent().has(&key) {
            return;
        }

        env.storage().persistent().remove(&key);

        // Free the slot so the grantor can delegate to someone else. Saturating
        // so a corrupted counter can never underflow into a huge allowance.
        let count = delegation_count(&env, &grantor);
        env.storage().persistent().set(
            &DataKey::DelegationCount(grantor.clone()),
            &count.saturating_sub(1),
        );

        DelegationRevoked {
            grantor,
            delegate,
            revoked_by: revoker,
            revoked_at: env.ledger().timestamp(),
        }
        .publish(&env);
    }

    /// Read-only: the raw delegation record, if one is stored. A record past
    /// its `expires_at` is still returned so operators can see and prune it;
    /// use `is_delegation_active` to ask whether it currently grants anything.
    pub fn get_delegation(
        env: Env,
        grantor: Address,
        delegate: Address,
    ) -> Option<DelegationRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::Delegation(grantor, delegate))
    }

    /// Read-only: does a live delegation from `grantor` to `delegate` carry
    /// every bit of `scope`? Returns `false` for unknown, expired, or
    /// insufficiently scoped delegations rather than erroring, so callers can
    /// pre-flight without a trial transaction.
    pub fn is_delegation_active(
        env: Env,
        grantor: Address,
        delegate: Address,
        scope: u32,
    ) -> bool {
        if scope == 0 || scope & !DELEGATION_SCOPE_ALL != 0 {
            return false;
        }
        let record: Option<DelegationRecord> = env
            .storage()
            .persistent()
            .get(&DataKey::Delegation(grantor, delegate));
        match record {
            Some(record) => {
                env.ledger().timestamp() < record.expires_at && record.scope & scope == scope
            }
            None => false,
        }
    }

    /// Read-only: how many distinct delegates a grantor currently holds,
    /// against `MAX_DELEGATIONS_PER_GRANTOR`.
    pub fn get_delegation_count(env: Env, grantor: Address) -> u32 {
        delegation_count(&env, &grantor)
    }

    /// Register a Tier 2 consistent-source proof on `source`'s behalf.
    ///
    /// Authorizes the *delegate*, not the source: the source's key is never
    /// required at call time. The stored `ProofRecord` still names `source`,
    /// while the delegate is recorded in the proof's lifecycle history, so the
    /// audit trail distinguishes authority from actor.
    ///
    /// Subject to the same Tier 2 pause domain and uniqueness rules as
    /// `register_source`.
    pub fn register_source_delegated(
        env: Env,
        delegate: Address,
        source: Address,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
    ) -> ProofRecord {
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER2_REGISTRATION);
        delegate.require_auth();
        require_delegation(&env, &source, &delegate, DELEGATION_SCOPE_REGISTER_SOURCE);
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
            Some(delegate.clone()),
            record.tier,
        );
        DelegationUsed {
            grantor: source,
            delegate,
            scope: DELEGATION_SCOPE_REGISTER_SOURCE,
            proof_id,
        }
        .publish(&env);
        record
    }

    /// Register a Tier 3 public-seal proof on `issuer`'s behalf.
    ///
    /// The issuer must still be a registered, active issuer — a delegation
    /// never substitutes for issuer standing, it only lets someone else
    /// exercise it. Subject to the same Tier 3 pause domain and uniqueness
    /// rules as `register_seal`.
    pub fn register_seal_delegated(
        env: Env,
        delegate: Address,
        issuer: Address,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
    ) -> ProofRecord {
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER3_REGISTRATION);
        delegate.require_auth();
        require_delegation(&env, &issuer, &delegate, DELEGATION_SCOPE_REGISTER_SEAL);
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
            Some(delegate.clone()),
            record.tier,
        );
        DelegationUsed {
            grantor: issuer,
            delegate,
            scope: DELEGATION_SCOPE_REGISTER_SEAL,
            proof_id,
        }
        .publish(&env);
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

    pub fn register_lineage(
        env: Env,
        actor: Address,
        parent_proof_ids: SorobanVec<BytesN<32>>,
        manifest_digest: BytesN<32>,
        operation_type: Symbol,
        output_digest: BytesN<32>,
        depth: u32,
    ) -> LineageRecord {
        actor.require_auth();
        validate_lineage(&env, &parent_proof_ids, &output_digest, depth);

        let record = LineageRecord {
            parent_proof_ids: parent_proof_ids.clone(),
            manifest_digest: manifest_digest.clone(),
            actor: actor.clone(),
            operation_type: operation_type.clone(),
            output_digest: output_digest.clone(),
            depth,
        };
        env.storage().persistent().set(&DataKey::Lineage(output_digest.clone()), &record);
        record
    }

    pub fn get_lineage(env: Env, output_digest: BytesN<32>) -> Option<LineageRecord> {
        env.storage().persistent().get(&DataKey::Lineage(output_digest))
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

    // -----------------------------------------------------------------------
    // Scoped emergency pause controls (#87)
    // -----------------------------------------------------------------------

    /// Assign the address permitted to trigger emergency pauses without
    /// holding the admin key. Admin-only. Pass the admin's own address to
    /// revoke the guardian role.
    pub fn set_guardian(env: Env, admin: Address, guardian: Address) {
        require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::Guardian, &guardian);
        GuardianSet { guardian }.publish(&env);
    }

    /// The currently configured guardian, if any.
    pub fn get_guardian(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Guardian)
    }

    /// Pause one or more registration domains (`PAUSE_DOMAIN_*`, or their
    /// bitwise-OR combination) for `duration_secs`. Callable by the admin or
    /// the guardian; the admin is capped at `MAX_PAUSE_DURATION_SECS`, the
    /// guardian at `MAX_GUARDIAN_PAUSE_DURATION_SECS`. Re-pausing an
    /// already-paused domain extends (overwrites) its expiry rather than
    /// erroring, so retries are idempotent. Reads and non-registration admin
    /// entry points are never affected. Returns the epoch-second timestamp
    /// at which the pause auto-expires.
    pub fn pause(env: Env, caller: Address, domain: u32, duration_secs: u64) -> u64 {
        validate_domain(&env, domain);
        let is_admin = require_pauser(&env, &caller);
        let max_duration = if is_admin {
            MAX_PAUSE_DURATION_SECS
        } else {
            MAX_GUARDIAN_PAUSE_DURATION_SECS
        };
        if duration_secs == 0 || duration_secs > max_duration {
            panic_with_error!(&env, RegistryError::InvalidPauseDuration);
        }

        let paused_at = env.ledger().timestamp();
        let expires_at = paused_at.saturating_add(duration_secs);

        for bit in domain_bits(domain) {
            env.storage().persistent().set(
                &DataKey::Pause(bit),
                &PauseRecord {
                    paused_by: caller.clone(),
                    paused_at,
                    expires_at,
                },
            );
        }

        DomainPaused {
            domain,
            paused_by: caller,
            paused_at,
            expires_at,
        }
        .publish(&env);

        expires_at
    }

    /// Lift a pause early. Admin-only — a guardian can raise the alarm but
    /// only the admin can stand it down before the bounded expiry. Unpausing
    /// a domain that is not currently stored as paused is a no-op.
    pub fn unpause(env: Env, admin: Address, domain: u32) {
        validate_domain(&env, domain);
        require_admin(&env, &admin);

        let unpaused_at = env.ledger().timestamp();
        let mut changed = false;
        for bit in domain_bits(domain) {
            if env.storage().persistent().has(&DataKey::Pause(bit)) {
                env.storage().persistent().remove(&DataKey::Pause(bit));
                changed = true;
            }
        }

        if changed {
            DomainUnpaused {
                domain,
                unpaused_by: admin,
                unpaused_at,
            }
            .publish(&env);
        }
    }

    /// Read-only: is any bit of `domain` currently paused (i.e. has an
    /// unexpired pause record)? A domain past its `expires_at` is treated as
    /// unpaused even if a stale record has not yet been cleared.
    pub fn is_paused(env: Env, domain: u32) -> bool {
        validate_domain(&env, domain);
        let now = env.ledger().timestamp();
        domain_bits(domain).any(|bit| domain_is_paused(&env, bit, now))
    }

    /// Read-only: the raw pause record for a single domain bit, if one is
    /// currently stored (including a stale record past its `expires_at`
    /// that has not yet been cleared by `unpause`).
    pub fn get_pause_state(env: Env, domain: u32) -> Option<PauseRecord> {
        validate_single_domain(&env, domain);
        env.storage().persistent().get(&DataKey::Pause(domain))
    }

    // -----------------------------------------------------------------------
    // Cross-layer verifier-input conformance
    // -----------------------------------------------------------------------

    /// Classify verifier material against the canonical `hpx-vi/1` codec.
    ///
    /// Read-only, side-effect free, and bounded: the work is O(1) in the frame
    /// size and no storage is touched, so it is safe to expose publicly and
    /// safe to call while any domain is paused.
    ///
    /// `schema_id` is [`SCHEMA_ID_SILENT_WITNESS`] or
    /// [`SCHEMA_ID_REVOCATION_WITNESS`]. `proof_len` is the length of the proof
    /// blob the caller intends to submit — passed as a length rather than the
    /// blob itself so classification never transports proof material.
    ///
    /// Returns [`verifier_inputs::ACCEPTED_CODE`] (`0`) when the material is
    /// canonical, otherwise the stable [`RejectCode::as_code`] value. This is
    /// the on-chain half of the cross-layer conformance corpus in
    /// `zk/vectors/verifier_conformance_v1.json`.
    ///
    /// Compatibility: this entry point is purely additive. The registration
    /// paths still apply the v1-lenient rules described in
    /// `docs/zk-conformance-vectors.md`; promoting the codec to enforcement is
    /// a separate, versioned migration.
    pub fn classify_public_inputs(
        env: Env,
        schema_id: u32,
        public_inputs: Bytes,
        proof_len: u32,
    ) -> u32 {
        // Schema dispatch precedes the length check, matching the Python and
        // TypeScript layers: an unrecognised schema is reported as such even
        // when the frame is also the wrong length.
        if schema_id != SCHEMA_ID_SILENT_WITNESS && schema_id != SCHEMA_ID_REVOCATION_WITNESS {
            return RejectCode::UnknownSchema.as_code();
        }

        if public_inputs.len() as usize != PUBLIC_INPUTS_LEN {
            return RejectCode::Length.as_code();
        }

        let mut frame = [0u8; PUBLIC_INPUTS_LEN];
        public_inputs.copy_into_slice(&mut frame);

        let parsed = if schema_id == SCHEMA_ID_SILENT_WITNESS {
            verifier_inputs::parse_silent_witness(&frame).map(|_| ())
        } else {
            verifier_inputs::parse_revocation_witness(&frame, &REVOCATION_DOMAIN_SEPARATOR)
                .map(|_| ())
        };

        if let Err(code) = parsed {
            return code.as_code();
        }

        match verifier_inputs::check_proof_bounds(proof_len) {
            Ok(()) => verifier_inputs::ACCEPTED_CODE,
            Err(code) => code.as_code(),
        }
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

/// Require that `caller` is either the admin or the configured guardian, and
/// authorize the call. Returns `true` when the caller is the admin, so
/// callers can apply role-specific limits (e.g. pause duration caps).
fn require_pauser(env: &Env, caller: &Address) -> bool {
    let admin: Address = env
        .storage()
        .persistent()
        .get(&DataKey::Admin)
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::NotInitialized));

    caller.require_auth();

    if caller == &admin {
        return true;
    }

    let guardian: Option<Address> = env.storage().persistent().get(&DataKey::Guardian);
    match guardian {
        Some(g) if &g == caller => false,
        _ => panic_with_error!(env, RegistryError::Unauthorized),
    }
}

/// Reject `scope` unless it is nonzero and composed only of known
/// `DELEGATION_SCOPE_*` bits.
fn validate_delegation_scope(env: &Env, scope: u32) {
    if scope == 0 || scope & !DELEGATION_SCOPE_ALL != 0 {
        panic_with_error!(env, RegistryError::InvalidDelegationScope);
    }
}

fn delegation_count(env: &Env, grantor: &Address) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::DelegationCount(grantor.clone()))
        .unwrap_or(0)
}

/// Require a live delegation from `grantor` to `delegate` carrying every bit of
/// `scope`, and authorize the call.
///
/// The three failure modes are kept distinct — absent, expired, and
/// insufficiently scoped — because an operator responding to a failed
/// registration needs to know which one happened, and none of the three
/// discloses anything about the media or the proof.
fn require_delegation(env: &Env, grantor: &Address, delegate: &Address, scope: u32) {
    validate_delegation_scope(env, scope);

    let record: DelegationRecord = env
        .storage()
        .persistent()
        .get(&DataKey::Delegation(grantor.clone(), delegate.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::DelegationNotFound));

    if env.ledger().timestamp() >= record.expires_at {
        panic_with_error!(env, RegistryError::DelegationExpired);
    }

    if record.scope & scope != scope {
        panic_with_error!(env, RegistryError::DelegationScopeExceeded);
    }
}

/// Reject `domain` unless it is nonzero and composed only of known
/// `PAUSE_DOMAIN_*` bits. Accepts single domains and their bitwise-OR
/// combination (e.g. `PAUSE_DOMAIN_ALL_REGISTRATION`).
fn validate_domain(env: &Env, domain: u32) {
    if domain == 0 || domain & !PAUSE_DOMAIN_ALL_REGISTRATION != 0 {
        panic_with_error!(env, RegistryError::InvalidPauseDomain);
    }
}

/// Reject `domain` unless it is exactly one known `PAUSE_DOMAIN_*` bit.
fn validate_single_domain(env: &Env, domain: u32) {
    if !PAUSE_DOMAIN_SINGLE_BITS.contains(&domain) {
        panic_with_error!(env, RegistryError::InvalidPauseDomain);
    }
}

/// Iterate the single-bit domains present in `domain` (already validated by
/// `validate_domain`/`validate_single_domain`).
fn domain_bits(domain: u32) -> impl Iterator<Item = u32> {
    PAUSE_DOMAIN_SINGLE_BITS
        .into_iter()
        .filter(move |bit| domain & bit != 0)
}

fn domain_is_paused(env: &Env, domain_bit: u32, now: u64) -> bool {
    let record: Option<PauseRecord> = env.storage().persistent().get(&DataKey::Pause(domain_bit));
    match record {
        Some(r) => now < r.expires_at,
        None => false,
    }
}

fn require_domain_unpaused(env: &Env, domain_bit: u32) {
    let now = env.ledger().timestamp();
    if domain_is_paused(env, domain_bit, now) {
        panic_with_error!(env, RegistryError::Paused);
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

/// Read a 128-byte public-input frame out of `Bytes`, rejecting any other
/// length before allocating.
fn read_public_input_frame(env: &Env, public_inputs: &Bytes) -> [u8; PUBLIC_INPUTS_LEN] {
    if public_inputs.len() as usize != PUBLIC_INPUTS_LEN {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }
    let mut frame = [0u8; PUBLIC_INPUTS_LEN];
    public_inputs.copy_into_slice(&mut frame);
    frame
}

/// Parse the legacy (v1-lenient) silent-witness layout.
///
/// Behaviour is unchanged from the pre-codec implementation: only the frame
/// length is enforced. Field-level canonicity, half padding, and zero-field
/// rules are defined by [`verifier_inputs`] and surfaced through
/// [`HarpocratesRegistry::classify_public_inputs`]; see
/// `docs/zk-conformance-vectors.md` for the migration that promotes them to
/// enforcement on this path.
fn parse_silent_witness_public_inputs(env: &Env, public_inputs: &Bytes) -> SilentWitnessInputs {
    let frame = read_public_input_frame(env, public_inputs);

    let mut video_hash = [0u8; 32];
    video_hash[..16].copy_from_slice(&frame[16..32]);
    video_hash[16..].copy_from_slice(&frame[48..64]);

    let mut credential_root = [0u8; 32];
    credential_root.copy_from_slice(&frame[64..96]);

    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&frame[96..128]);

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
    let frame = read_public_input_frame(env, public_inputs);

    let mut revocation_root = [0u8; 32];
    revocation_root.copy_from_slice(&frame[0..32]);

    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&frame[32..64]);

    let mut domain_separator = [0u8; 32];
    domain_separator.copy_from_slice(&frame[64..96]);

    let mut credential_root = [0u8; 32];
    credential_root.copy_from_slice(&frame[96..128]);

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
mod test_conformance;
#[cfg(test)]
mod test_delegation;
#[cfg(test)]
mod test_expiry;
#[cfg(test)]
mod test_fuzz;
#[cfg(test)]
mod test_invariants;
#[cfg(test)]
mod test_pause;
#[cfg(test)]
mod test_revocation;
#[cfg(test)]
mod test_scoped_nullifier;
#[cfg(test)]
mod test_state_machine;
#[cfg(test)]
mod test_dispute;
