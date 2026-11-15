import { Buffer } from "buffer";
import { Address } from "@stellar/stellar-sdk";
import {
  AssembledTransaction,
  Client as ContractClient,
  ClientOptions as ContractClientOptions,
  MethodOptions,
  Result,
  Spec as ContractSpec,
} from "@stellar/stellar-sdk/contract";
import type {
  u32,
  i32,
  u64,
  i64,
  u128,
  i128,
  u256,
  i256,
  Option,
  Timepoint,
  Duration,
} from "@stellar/stellar-sdk/contract";
export * from "@stellar/stellar-sdk";
export * as contract from "@stellar/stellar-sdk/contract";
export * as rpc from "@stellar/stellar-sdk/rpc";

if (typeof window !== "undefined") {
  //@ts-ignore Buffer exists
  window.Buffer = window.Buffer || Buffer;
}




export type DataKey = {tag: "Admin", values: void} | {tag: "Proof", values: readonly [Buffer]} | {tag: "Video", values: readonly [Buffer]} | {tag: "Nullifier", values: readonly [Buffer]} | {tag: "CredentialRoot", values: readonly [Buffer]} | {tag: "CredentialRootV2", values: readonly [Buffer]} | {tag: "CredentialRootSeq", values: void} | {tag: "CredentialRootIndex", values: readonly [u32]} | {tag: "CredentialRootIndexed", values: readonly [Buffer]} | {tag: "CredentialRootsBackfillQueue", values: void} | {tag: "CredentialRootsBackfillCursor", values: void} | {tag: "CredentialRootsBackfill", values: void} | {tag: "Issuer", values: readonly [string]} | {tag: "IssuerRotation", values: readonly [string]} | {tag: "Verifier", values: void} | {tag: "ProofTtl", values: void} | {tag: "Guardian", values: void} | {tag: "Pause", values: readonly [u32]} | {tag: "PendingAdmin", values: void} | {tag: "RevocationRoot", values: void} | {tag: "RevocationRoots", values: void} | {tag: "RevocationRootGraceWindow", values: void} | {tag: "ProofHistorySeq", values: readonly [Buffer]} | {tag: "ProofHistoryEntry", values: readonly [Buffer, u32]} | {tag: "Delegation", values: readonly [string, string]} | {tag: "DelegationCount", values: readonly [string]} | {tag: "VerifierState", values: void} | {tag: "VerifierCircuitVersions", values: void} | {tag: "SchemaVersion", values: void} | {tag: "WasmHash", values: void} | {tag: "ScopeEpoch", values: readonly [Buffer]} | {tag: "ProposalSeq", values: void} | {tag: "Proposal", values: readonly [u32]} | {tag: "TimelockMinDelay", values: void} | {tag: "AdminCouncil", values: void} | {tag: "CouncilProposalSeq", values: void} | {tag: "CouncilProposal", values: readonly [u32]} | {tag: "Schema", values: readonly [Buffer]} | {tag: "Lineage", values: readonly [Buffer]} | {tag: "LineageChildCount", values: readonly [Buffer]} | {tag: "TimestampClaim", values: readonly [Buffer]} | {tag: "LineageChildSeq", values: readonly [Buffer]} | {tag: "LineageChild", values: readonly [Buffer, u32]} | {tag: "MetadataEnvelope", values: readonly [Buffer]} | {tag: "Dispute", values: readonly [Buffer]} | {tag: "ProofOpenDisputeCount", values: readonly [Buffer]} | {tag: "ReporterOpenDisputeCount", values: readonly [string]} | {tag: "ReporterCooldown", values: readonly [Buffer]} | {tag: "VerifierNullifier", values: readonly [string, Buffer]} | {tag: "ProofDisputeSeq", values: readonly [Buffer]} | {tag: "ProofDispute", values: readonly [Buffer, u32]} | {tag: "SourceBatch", values: readonly [Buffer]} | {tag: "IssuerQuota", values: readonly [string]} | {tag: "IssuerQuotaUsage", values: readonly [string]} | {tag: "ReceiptSigner", values: readonly [Buffer]} | {tag: "ReceiptSignerCount", values: void} | {tag: "ReceiptCommitment", values: readonly [Buffer]} | {tag: "SealPolicySeq", values: void} | {tag: "ActiveSealPolicyVersion", values: void} | {tag: "SealPolicy", values: readonly [u32]} | {tag: "SealApproval", values: readonly [Buffer, string]} | {tag: "SealSigners", values: readonly [Buffer]} | {tag: "SealExplicitFinalized", values: readonly [Buffer]} | {tag: "AdminIntentDigest", values: void} | {tag: "AdminIntentMeta", values: void} | {tag: "TimelockIntentDigest", values: readonly [u32]} | {tag: "CouncilIntentDigest", values: readonly [u32]};


export interface SealPolicy {
  approval_ttl: u64;
  created_at: u64;
  expires_at: u64;
  max_signers: u32;
  required_approvals: u32;
  signers: Array<string>;
  status: u32;
  version: u32;
}


/**
 * Tier 2 source batch root record.
 */
export interface BatchRecord {
  count: u32;
  created_at: u64;
  metadata_hash: Buffer;
  root: Buffer;
  source: string;
}


/**
 * Pause record for a single registration domain bit. Presence of a record
 * does not by itself mean "paused" — see `domain_is_paused`, which also
 * checks `expires_at` against the current ledger time so pauses expire on
 * their own without requiring a follow-up transaction.
 */
export interface PauseRecord {
  expires_at: u64;
  paused_at: u64;
  paused_by: string;
}


export interface ProofRecord {
  /**
 * Optional batch size when this proof was registered as part of an
 * aggregated batch (0 = not part of a batch).
 */
batch_size: u32;
  created_at: u64;
  expires_at: u64;
  issuer: Option<string>;
  metadata_hash: Buffer;
  nullifier: Option<Buffer>;
  source: Option<string>;
  status: u32;
  tier: u32;
  video_hash: Buffer;
}






export interface AdminCouncil {
  created_at: u64;
  effective_at: u64;
  members: Array<string>;
  threshold: u32;
}


export interface IssuerRecord {
  active: boolean;
  metadata_hash: Buffer;
}


/**
 * Schema record for issuer-certified attribute schemas.
 */
export interface SchemaRecord {
  active: boolean;
  attribute_count: u32;
  created_at: u64;
  issuer_namespace: Buffer;
  schema_hash: Buffer;
  version: u32;
}


export interface SealApproval {
  approved_at: u64;
  expires_at: u64;
  metadata_hash: Buffer;
  policy_version: u32;
  proof_id: Buffer;
  signer: string;
  video_hash: Buffer;
}


/**
 * Paginated result from `list_verifiers`.
 * 
 * `entries` contains up to `limit` `VerifierEntry` items in slot order
 * (Active → Pending → Previous). Only non-None slots are included.
 * 
 * `next_cursor` is `Some(offset)` when more items exist beyond this page,
 * or `None` when the page is the last (or only) page. Pass `next_cursor`
 * as the `cursor` argument in the subsequent call.
 * 
 * `total_populated` is the total count of populated (non-None) verifier
 * slots at the time of the query. It is always ≤ 3.
 */
export interface VerifierPage {
  entries: Array<VerifierEntry>;
  next_cursor: Option<u32>;
  total_populated: u32;
}

/**
 * The role of a verifier address in the current rotation state.
 */
export enum VerifierRole {
  Active = 1,
  Pending = 2,
  Previous = 3,
}



/**
 * Categorised dispute reasons. Numeric values are stable on-chain; do not
 * renumber.
 */
export enum DisputeReason {
  ContentError = 1,
  MetadataError = 2,
  TierMismatch = 3,
  CredentialLapsed = 4,
  PrivacyViolation = 5,
  Other = 6,
}


/**
 * Immutable dispute record. Only `status`, `response_commitment`,
 * `resolve_deadline`, `resolved_at`, and `superseded_by` are mutated after
 * initial creation; the rest are set once at open time.
 */
export interface DisputeRecord {
  /**
 * Off-chain commitment to the reporter's full evidence submission.
 */
commitment_hash: Buffer;
  /**
 * Unique dispute identifier (caller-supplied, 32-byte opaque commitment).
 */
dispute_id: Buffer;
  /**
 * Ledger timestamp when the dispute was opened.
 */
opened_at: u64;
  /**
 * The proof this dispute challenges.
 */
proof_id: Buffer;
  /**
 * Categorised reason for the dispute.
 */
reason: DisputeReason;
  /**
 * Address of the reporter who opened this dispute.
 */
reporter: string;
  /**
 * Privacy-safe commitment: H(reporter_address_bytes || proof_id_bytes).
 * Used for the per-proof cooldown and emitted in events.
 */
reporter_hash: Buffer;
  /**
 * Ledger timestamp by which the admin must decide after a response.
 * Set to 0 until a response is submitted.
 */
resolve_deadline: u64;
  /**
 * Ledger timestamp of final resolution/dismissal. 0 while open.
 */
resolved_at: u64;
  /**
 * Ledger timestamp by which the issuer/source must respond.
 */
respond_deadline: u64;
  /**
 * Issuer/source commitment hash in response. None until Responded.
 */
response_commitment: Option<Buffer>;
  /**
 * Current lifecycle state.
 */
status: DisputeStatus;
  /**
 * Proof ID that supersedes the disputed proof, if Superseded.
 */
superseded_by: Option<Buffer>;
}

/**
 * Dispute state transitions. Numeric values are stable on-chain identifiers;
 * do not renumber existing variants.
 */
export enum DisputeStatus {
  Open = 1,
  Responded = 2,
  Resolved = 3,
  Dismissed = 4,
  Superseded = 5,
}


/**
 * On-chain lineage edge for a verifiable derivative.
 * 
 * `parent_proof_ids` retain graph topology for cycle/depth checks.
 * `parent_commitments` store domain-separated content bindings for each
 * parent so public boundaries (events / interop) can cite parents without
 * relying on raw proof identifiers alone. Derived as
 * `SHA-256("harp_lin_pc" || binding_a || binding_b)` where a proof parent
 * binds `(video_hash, metadata_hash)` and a lineage parent binds
 * `(manifest_digest, output_digest)`.
 * 
 * Migration: additive field on new registrations. Pre-existing lineage
 * rows (if any) lack commitments and must be re-registered after upgrade;
 * rolling back to a pre-#332 wasm ignores the new event / getter and leaves
 * stored records readable only by matching wasm.
 */
export interface LineageRecord {
  actor: string;
  depth: u32;
  manifest_digest: Buffer;
  operation_type: string;
  output_digest: Buffer;
  parent_commitments: Array<Buffer>;
  parent_proof_ids: Array<Buffer>;
}

export const RegistryError = {
  1: {message:"AlreadyInitialized"},
  2: {message:"NotInitialized"},
  3: {message:"Unauthorized"},
  4: {message:"DuplicateProof"},
  5: {message:"DuplicateVideo"},
  6: {message:"DuplicateNullifier"},
  7: {message:"InvalidProof"},
  8: {message:"UnknownIssuer"},
  9: {message:"VerifierNotSet"},
  10: {message:"InvalidPublicInputs"},
  11: {message:"UnknownCredentialRoot"},
  12: {message:"RevokedCredentialRoot"},
  13: {message:"HistorySaturated"},
  14: {message:"InvalidHistoryAction"},
  15: {message:"InvalidReasonCode"},
  16: {message:"HistoryLimitExceeded"},
  17: {message:"AlreadyExpired"},
  18: {message:"NoCorrectionChange"},
  19: {message:"HistoryCorruption"},
  20: {message:"NoPendingAdmin"},
  /**
   * The requested operation is blocked by an active domain pause (#87).
   */
  21: {message:"Paused"},
  /**
   * `domain` was zero or contained bits outside the known pause domains.
   */
  22: {message:"InvalidPauseDomain"},
  /**
   * `duration_secs` was zero or exceeded the caller's role cap.
   */
  23: {message:"InvalidPauseDuration"},
  /**
   * `scope` was zero or contained bits outside `DELEGATION_SCOPE_ALL` (#192).
   */
  24: {message:"InvalidDelegationScope"},
  /**
   * `duration_secs` was zero or above `MAX_DELEGATION_DURATION_SECS` (#192).
   */
  25: {message:"InvalidDelegationDuration"},
  /**
   * No delegation exists from the named grantor to the caller (#192).
   */
  26: {message:"DelegationNotFound"},
  /**
   * The delegation exists but its `expires_at` has passed (#192).
   */
  27: {message:"DelegationExpired"},
  /**
   * The delegation exists and is live, but does not carry the scope the
   * attempted operation requires (#192).
   */
  28: {message:"DelegationScopeExceeded"},
  /**
   * The grantor already holds `MAX_DELEGATIONS_PER_GRANTOR` delegates (#192).
   */
  29: {message:"DelegationsSaturated"},
  /**
   * A grantor may not delegate to itself (#192).
   */
  30: {message:"SelfDelegation"},
  /**
   * The requested timelock proposal does not exist (#86).
   */
  31: {message:"ProposalNotFound"},
  32: {message:"ProposalNotReady"},
  33: {message:"ProposalAlreadyExecuted"},
  34: {message:"ProposalCancelled"},
  35: {message:"InvalidProposalAction"},
  36: {message:"InvalidProposalPayload"},
  37: {message:"ProposalsSaturated"},
  38: {message:"InvalidTimelockDelay"},
  39: {message:"AlreadyCancelled"},
  40: {message:"RotationNotScheduled"},
  41: {message:"RotationNotReady"},
  42: {message:"RotationWindowClosed"},
  43: {message:"BatchTooLarge"},
  44: {message:"InvalidScopeEpoch"},
  45: {message:"DisputeNotFound"},
  46: {message:"DisputeAlreadyResolved"},
  47: {message:"SupersessionCycleDetected"},
  48: {message:"SupersessionNotFound"},
  49: {message:"DomainTagMismatch"},
  50: {message:"UnknownSchema"},
  51: {message:"InactiveSchema"},
  52: {message:"SchemaVersionMismatch"},
  /**
   * A scoped-nullifier proof was generated for a stale scope epoch.
   */
  53: {message:"StaleEpoch"},
  /**
   * Batch aggregation was requested with zero or too many elements.
   */
  54: {message:"BatchSizeExceeded"},
  /**
   * Credential roots in a batch were not all identical.
   */
  55: {message:"BatchCredentialRootMismatch"},
  /**
   * The batch element count did not match the supplied video-hash list.
   */
  56: {message:"BatchCountMismatch"},
  /**
   * A lineage parent proof/lineage record was not found or repeated.
   */
  57: {message:"InvalidLineage"},
  /**
   * A lineage edge would introduce a cycle.
   */
  58: {message:"LineageCycle"},
  /**
   * The requested lineage depth exceeds `MAX_LINEAGE_DEPTH`.
   */
  59: {message:"LineageTooDeep"},
  /**
   * The requested lineage fan-out exceeds `MAX_LINEAGE_FANOUT`.
   */
  60: {message:"LineageFanOutExceeded"},
  /**
   * The proof already has `MAX_OPEN_DISPUTES_PER_PROOF` open disputes.
   */
  61: {message:"TooManyOpenDisputes"},
  /**
   * The respond/resolve deadline for this dispute transition has passed.
   */
  62: {message:"DisputeWindowExpired"},
  /**
   * The dispute is already in a terminal state.
   */
  63: {message:"DisputeAlreadyClosed"},
  /**
   * Supersession would create a cycle (direct or depth-1).
   */
  64: {message:"DisputeCyclicSupersession"},
  /**
   * The caller is not the proof's issuer/source (or admin for Tier 1).
   */
  65: {message:"UnauthorizedResponder"},
  /**
   * The reporter must wait out `REPORTER_COOLDOWN_SECS` before re-reporting.
   */
  66: {message:"ReporterOnCooldown"},
  /**
   * The dispute is not in the state this transition requires.
   */
  67: {message:"InvalidDisputeTransition"},
  /**
   * Metadata envelope version is zero or above `METADATA_ENVELOPE_VERSION_MAX` (#317).
   */
  68: {message:"UnsupportedMetadataEnvelopeVersion"},
  /**
   * Metadata envelope hash is zero / malformed (#317).
   */
  69: {message:"InvalidMetadataEnvelope"},
  /**
   * No metadata envelope (and no proof) for the requested id (#317).
   */
  70: {message:"MetadataEnvelopeNotFound"},
  /**
   * Bound envelope hash does not match the proof's `metadata_hash` (#317).
   */
  71: {message:"MetadataEnvelopeHashMismatch"},
  /**
   * Timestamp claim is malformed, far-future, or missing required digest (#339).
   */
  72: {message:"InvalidTimestampClaim"},
  /**
   * No timestamp claim exists for the requested proof (#339).
   */
  73: {message:"TimestampClaimNotFound"},
  /**
   * A timestamp claim is already anchored and the update is not an upgrade (#339).
   */
  74: {message:"TimestampClaimAlreadyAnchored"},
  /**
   * Caller is neither admin nor the proof's source/issuer (#339).
   */
  75: {message:"UnauthorizedTimestampActor"},
  /**
   * Lineage registration supplied zero parents (commitments require ≥1).
   */
  76: {message:"LineageEmptyParents"},
  /**
   * A lineage parent proof is revoked or expired and cannot anchor a derivative.
   */
  77: {message:"LineageParentUnavailable"},
  /**
   * Lineage output digest is already registered.
   */
  78: {message:"DuplicateLineage"},
  /**
   * `list_lineage_children` limit was zero or above the page cap (#335).
   */
  79: {message:"LineageChildrenLimitExceeded"},
  /**
   * Parent already holds MAX_LINEAGE_CHILDREN_PER_PARENT children (#335).
   */
  80: {message:"LineageChildrenSaturated"},
  /**
   * Proof declares a circuit version outside the active verifier's window (#343).
   */
  81: {message:"UnsupportedCircuitVersion"},
  /**
   * Requested circuit-version window is empty or outside the wasm range (#343).
   */
  82: {message:"InvalidCircuitVersionRange"},
  /**
   * Requested rotation grace window is above `MAX_ISSUER_ROTATION_GRACE_SECS`
   * or overflows ledger time (#323).
   */
  83: {message:"InvalidIssuerRotationGrace"},
  /**
   * A rotation named the same issuer key twice; absent or inactive keys
   * report `UnknownIssuer` instead (#323).
   */
  84: {message:"InvalidIssuerRotation"},
  /**
   * No issuer rotation grace record exists for the requested key (#323).
   */
  85: {message:"IssuerRotationNotFound"},
  /**
   * The issuer rotation grace window has not lapsed yet (#323).
   */
  86: {message:"IssuerRotationGraceStillActive"},
  /**
   * A scoped-nullifier envelope carried a `circuit_version` trailer other
   * than [`verifier_inputs::EXPECTED_CIRCUIT_VERSION`], or was the superseded
   * bare 224-byte frame that commits no circuit version at all (#368).
   */
  87: {message:"CircuitVersionMismatch"},
  /**
   * The reporter reached `MAX_OPEN_DISPUTES_PER_REPORTER`.
   */
  88: {message:"ReporterDisputesSaturated"},
  /**
   * The action requires admin council threshold approvals.
   */
  89: {message:"InsufficientApprovals"},
  /**
   * The pagination cursor is out of range, malformed, or bound to a different query scope.
   */
  90: {message:"InvalidCursor"},
  /**
   * The `limit` supplied to a paginated list method is zero or exceeds its maximum page cap.
   */
  91: {message:"ListLimitExceeded"},
  /**
   * The credential root has expired and can no longer anchor new proofs.
   */
  92: {message:"ExpiredCredentialRoot"},
  /**
   * Admin and active issuer roles are mutually exclusive for the same address.
   */
  93: {message:"RoleConflict"},
  /**
   * The Tier 2 source batch Merkle inclusion proof failed validation.
   */
  94: {message:"InvalidInclusionProof"},
  /**
   * The key reached `max_registrations` in the current ledger-time window bucket (#806).
   */
  95: {message:"IssuerQuotaExhausted"},
  /**
   * The caller-supplied lineage depth does not match the depth derived from its parents (#333).
   */
  96: {message:"LineageDepthMismatch"},
  /**
   * A lineage parent already reached its `MAX_LINEAGE_FANOUT` derivative out-degree cap (#333).
   */
  97: {message:"LineageFanOutSaturated"},
  /**
   * No proof exists for the requested receipt commitment (#337).
   */
  98: {message:"ReceiptProofNotFound"},
  /**
   * A receipt digest cannot be committed for a revoked or expired proof (#337).
   */
  99: {message:"ReceiptProofNotActive"},
  /**
   * A different receipt digest is already committed for this proof (#337).
   */
  100: {message:"ReceiptAlreadyCommitted"},
  /**
   * The receipt digest is all-zero or structurally invalid (#337).
   */
  101: {message:"InvalidReceiptDigest"},
  /**
   * The receipt-signing public key is not registered in the allowlist (#337).
   */
  102: {message:"UnknownReceiptSigner"},
  /**
   * The receipt-signing public key has been revoked (#337).
   */
  103: {message:"RevokedReceiptSigner"},
  /**
   * The registry reached `MAX_RECEIPT_SIGNERS` active receipt-signing keys (#337).
   */
  104: {message:"ReceiptSignersSaturated"},
  /**
   * `reactivate_schema` was called on a schema that is already active.
   */
  105: {message:"SchemaAlreadyActive"},
  /**
   * No active threshold seal policy is configured (#124).
   */
  106: {message:"NoActiveSealPolicy"},
  /**
   * The referenced threshold seal policy is cancelled, expired, or absent (#124).
   */
  107: {message:"SealPolicyCancelled"},
  /**
   * The caller is not in the threshold seal policy signer set (#124).
   */
  108: {message:"UnknownPolicySigner"},
  /**
   * Valid unexpired seal approvals do not meet the required threshold (#124).
   */
  109: {message:"SealThresholdNotMet"},
  /**
   * `required_approvals` is zero or exceeds `max_signers` (#124).
   */
  110: {message:"InvalidSealThreshold"},
  /**
   * `max_signers` or the signer set exceeds the configured limit (#124).
   */
  111: {message:"SealSignerSetTooLarge"},
  /**
   * The threshold seal for this proof has already been finalized (#124).
   */
  112: {message:"SealAlreadyFinalized"},
  /**
   * Privileged transition parameters or target role failed intent digest verification (#1184).
   */
  113: {message:"RoleIntentDigestMismatch"}
}


/**
 * A single verifier slot returned by `list_verifiers`.
 */
export interface VerifierEntry {
  /**
 * The verifier contract address for this slot.
 */
address: string;
  /**
 * The role of this verifier in the current configuration.
 */
role: VerifierRole;
}


export interface VerifierState {
  activation_ledger: u64;
  active_verifier: Option<string>;
  overlap_window: u64;
  pending_verifier: Option<string>;
  previous_verifier: Option<string>;
  rollback_window: u64;
  rollback_window_end: u64;
}










/**
 * Comprehensive proof assurance view combining status, tier, timestamp assurance,
 * dispute count, envelope version, and issuer verifiability in a single call.
 */
export interface ProofAssurance {
  envelope_version: u32;
  issuer_verifiable: boolean;
  open_dispute_count: u32;
  status: ProofVerificationStatus;
  tier: u32;
  timestamp_assurance_level: u32;
}


/**
 * Aggregate snapshot of the registry's operational configuration (#721).
 * 
 * Combines the individual configuration getters and the currently paused
 * registration domains bitmask into a single read-only response so clients
 * can inspect the operational state in one simulation.
 */
export interface RegistryConfig {
  guardian: Option<string>;
  paused_domains: u32;
  proof_ttl: u64;
  revocation_root: Option<Buffer>;
  schema_version: u32;
  timelock_min_delay_secs: u64;
  verifier: Option<string>;
  verifier_state: VerifierState;
}


/**
 * On-chain independent timestamp claim for a registered proof (#339).
 * 
 * Stores commitments and ledger-derived anchors only — never TSA token
 * bytes, media, witness values, or private keys.
 */
export interface TimestampClaim {
  /**
 * Authenticated actor who submitted the claim.
 */
actor: string;
  /**
 * Ledger timestamp when this claim was anchored (independent observed time).
 */
anchored_at: u64;
  /**
 * Derived assurance level (`TIMESTAMP_ASSURANCE_*`).
 */
assurance: u32;
  /**
 * Digest of the off-chain `harpocrates-time-attestation/v1` envelope.
 */
attestation_digest: Buffer;
  /**
 * Optional claimed capture time (unix seconds). `0` means absent.
 */
claimed_time: u64;
  /**
 * Ledger sequence at anchor time for external cross-checks.
 */
ledger_sequence: u32;
  /**
 * Proof this claim is bound to.
 */
proof_id: Buffer;
  /**
 * Commitment to an RFC 3161 token (`[0;32]` if absent).
 */
rfc3161_commitment: Buffer;
  /**
 * Combinable `TIMESTAMP_SOURCE_*` bitflags.
 */
sources: u32;
}






export interface CouncilProposal {
  action: u32;
  approvals: Array<string>;
  cancelled: boolean;
  created_at: u64;
  executed: boolean;
  expires_at: u64;
  id: u32;
  payload: Buffer;
  proposer: string;
  target: string;
}






/**
 * A narrowly scoped, expiring authority to act for `grantor`.
 */
export interface DelegationRecord {
  delegate: string;
  /**
 * Epoch seconds after which the delegation is inert. Never zero.
 */
expires_at: u64;
  granted_at: u64;
  grantor: string;
  /**
 * Bitwise-OR of `DELEGATION_SCOPE_*`.
 */
scope: u32;
}


/**
 * One small usage record per keyed address: the current ledger-time window
 * bucket and how many registrations have been charged inside it (#806).
 * A stored `bucket` behind the current one is treated as empty, so counts
 * need no explicit reset and the storage stays a single compact record.
 */
export interface IssuerQuotaUsage {
  /**
 * `ledger timestamp / window_secs` at the time of the last charge.
 */
bucket: u64;
  /**
 * Registrations charged inside `bucket`.
 */
count: u32;
}


/**
 * Versioned on-chain metadata envelope binding (#317).
 * 
 * Stores only `(version, metadata_hash)` commitments — never raw envelope
 * bytes, media, witnesses, or secrets. Aligns with backend `envelope.py`.
 */
export interface MetadataEnvelope {
  /**
 * Ledger timestamp when this envelope binding was written.
 */
bound_at: u64;
  /**
 * Canonical metadata hash (same value stored on `ProofRecord`).
 */
metadata_hash: Buffer;
  /**
 * Proof this envelope is bound to.
 */
proof_id: Buffer;
  /**
 * Envelope schema version (`METADATA_ENVELOPE_V1` / `V2`).
 */
version: u32;
}


export interface TimelockProposal {
  action: u32;
  cancelled: boolean;
  created_at: u64;
  executed: boolean;
  min_execution_at: u64;
  payload: Buffer;
  proposer: string;
  target: string;
}






/**
 * Admin-set registration quota for one key, measured in ledger-time window
 * buckets (#806). Absence of a record means unlimited, so deployments that
 * never call `set_issuer_quota` behave exactly as before.
 */
export interface IssuerQuotaRecord {
  /**
 * Registrations allowed per key per window bucket. Never zero while the
 * record exists; zero clears the quota.
 */
max_registrations: u32;
  /**
 * Window-bucket width in seconds. Bucket index is `timestamp /
 * window_secs`, so a rollover into the next bucket resets the count.
 */
window_secs: u64;
}


export interface ProofHistoryEntry {
  action: u32;
  actor: Option<string>;
  reason_code: u32;
  timestamp: u64;
}










/**
 * Paginated result from `list_credential_roots` (#731).
 */
export interface CredentialRootPage {
  /**
 * Cursor for the next page (`Some(next_cursor)`), or `None` if end reached.
 */
next_cursor: Option<u32>;
  roots: Array<CredentialRootEntry>;
}



/**
 * An entry in a `CredentialRootPage` (#731).
 */
export interface CredentialRootEntry {
  root_hash: Buffer;
  status: u32;
}


/**
 * One page of child output digests for a lineage parent (#335).
 */
export interface LineageChildrenPage {
  children: Array<Buffer>;
  /**
 * Absolute offset of the next unread child (equals `total` when exhausted).
 */
next_offset: u32;
  total: u32;
}


/**
 * Admin-managed receipt-signing key record. `public_key` is a SEC-1
 * encoded uncompressed P-256 point (`0x04 || X || Y`); public keys are not
 * secrets, and no private key material is ever stored.
 */
export interface ReceiptSignerRecord {
  /**
 * False once revoked. Revocation is recorded rather than deleted so an
 * operator can distinguish "revoked" from "never registered".
 */
active: boolean;
  added_at: u64;
  public_key: Buffer;
  /**
 * 0 while the signer is active.
 */
revoked_at: u64;
}


/**
 * A revocation root entry stored in the bounded history ring buffer.
 */
export interface RevocationRootEntry {
  /**
 * Ledger sequence at which this root was activated.
 */
activation_ledger: u32;
  /**
 * Merkle root of the revocation tree.
 */
root: Buffer;
}




export interface CredentialRootRecord {
  expires_at: u64;
  issued_at: u64;
  metadata_hash: Buffer;
  status: u32;
}


/**
 * Rotation grace record for an issuer key that has rotated out (#323).
 * 
 * Keyed by the *previous* (retired) key at `DataKey::IssuerRotation(Address)`
 * so the stored `IssuerRecord` keeps its byte-identical `{metadata_hash,
 * active}` shape and records written by an earlier wasm still decode.
 * Presence means "this key was rotated, not revoked, and the evidence it
 * already signed stays verifiable until `grace_expires_at`".
 */
export interface IssuerRotationRecord {
  /**
 * Epoch seconds after which the grace window has lapsed. A reader at
 * exactly this timestamp sees the window as already closed.
 */
grace_expires_at: u64;
  /**
 * Resolved window length (the protocol default when the caller passed 0).
 */
grace_secs: u64;
  /**
 * The key that rotated out — also the record's storage key.
 */
previous_issuer: string;
  /**
 * The active key that replaced it.
 */
replacement_issuer: string;
  /**
 * Ledger timestamp at which the rotation was accepted.
 */
rotated_at: u64;
}


/**
 * Paginated result from `list_timelock_proposals`.
 */
export interface TimelockProposalPage {
  /**
 * Cursor for the next page (`Some(next_cursor)`), or `None` if end reached.
 */
next_cursor: Option<u32>;
  proposals: Array<TimelockProposal>;
}















/**
 * Verification status returned by `get_proof_status`.
 */
export type ProofVerificationStatus = {tag: "Valid", values: void} | {tag: "Revoked", values: void} | {tag: "Expired", values: void} | {tag: "NotFound", values: void};


/**
 * Immutable commitment to a signed verification receipt for one proof.
 * 
 * Privacy: every field is a commitment, an address, an identifier, or a
 * timestamp. No receipt bytes, media, metadata hashes, witness values,
 * signatures, or private keys are stored.
 */
export interface ReceiptCommitmentRecord {
  committed_at: u64;
  /**
 * Address that authorized the commit (proof subject or admin).
 */
committed_by: string;
  proof_id: Buffer;
  /**
 * The attesting receipt-signing public key.
 */
public_key: Buffer;
  /**
 * `sha256(canonical_json(signed_verification_receipt))`.
 */
receipt_digest: Buffer;
  /**
 * Identity tier of the committed proof at commit time (1, 2, or 3).
 */
tier: u32;
}


/**
 * A verifier's declared circuit-version window (#343).
 * 
 * Immutable record of what the active verifier was told it may check, plus
 * who declared it and when. When no record exists the window is the full
 * built-in `[MIN_SUPPORTED_CIRCUIT_VERSION, MAX_SUPPORTED_CIRCUIT_VERSION]`
 * range, which is the pre-#343 behaviour.
 */
export interface VerifierCircuitVersions {
  max_version: u32;
  min_version: u32;
  set_at: u64;
  set_by: string;
}

















export interface Client {
  /**
   * Construct and simulate a init transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  init: ({admin}: {admin: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a pause transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Pause one or more registration domains (`PAUSE_DOMAIN_*`, or their
   * bitwise-OR combination) for `duration_secs`. Callable by the admin or
   * the guardian; the admin is capped at `MAX_PAUSE_DURATION_SECS`, the
   * guardian at `MAX_GUARDIAN_PAUSE_DURATION_SECS`. Re-pausing an
   * already-paused domain extends (overwrites) its expiry rather than
   * erroring, so retries are idempotent. Reads and non-registration admin
   * entry points are never affected. Returns the epoch-second timestamp
   * at which the pause auto-expires.
   */
  pause: ({caller, domain, duration_secs}: {caller: string, domain: u32, duration_secs: u64}, options?: MethodOptions) => Promise<AssembledTransaction<u64>>

  /**
   * Construct and simulate a unpause transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Lift a pause early. Admin-only — a guardian can raise the alarm but
   * only the admin can stand it down before the bounded expiry. Unpausing
   * a domain that is not currently stored as paused is a no-op.
   */
  unpause: ({admin, domain}: {admin: string, domain: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a version transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the crate package version string.
   */
  version: (options?: MethodOptions) => Promise<AssembledTransaction<string>>

  /**
   * Construct and simulate a is_admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Read-only check whether `addr` currently holds registry administrator authority.
   */
  is_admin: ({addr}: {addr: string}, options?: MethodOptions) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a get_admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the current admin address, if initialized.
   */
  get_admin: (options?: MethodOptions) => Promise<AssembledTransaction<Option<string>>>

  /**
   * Construct and simulate a get_proof transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_proof: ({proof_id}: {proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<ProofRecord>>>

  /**
   * Construct and simulate a is_issuer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Read-only check whether `addr` currently holds active issuer authority.
   * 
   * Admin and active issuer roles are disjoint: even if a legacy V1 record
   * exists on the current admin address before `upgrade_storage` runs, it
   * cannot exercise issuer authority.
   */
  is_issuer: ({addr}: {addr: string}, options?: MethodOptions) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a is_paused transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Read-only: is any bit of `domain` currently paused (i.e. has an
   * unexpired pause record)? A domain past its `expires_at` is treated as
   * unpaused even if a stale record has not yet been cleared.
   */
  is_paused: ({domain}: {domain: u32}, options?: MethodOptions) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a add_issuer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  add_issuer: ({admin, issuer, metadata_hash}: {admin: string, issuer: string, metadata_hash: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a add_schema transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  add_schema: ({admin, schema_hash, issuer_namespace, version, attribute_count}: {admin: string, schema_hash: Buffer, issuer_namespace: Buffer, version: u32, attribute_count: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_config transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the registry's operational configuration in one read-only call (#721).
   * 
   * Safe to call both before and after `init`. Every field matches the
   * corresponding individual getter, and `paused_domains` is the bitwise-OR
   * of all registration domains that are currently paused (unexpired).
   */
  get_config: (options?: MethodOptions) => Promise<AssembledTransaction<RegistryConfig>>

  /**
   * Construct and simulate a get_issuer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_issuer: ({issuer}: {issuer: string}, options?: MethodOptions) => Promise<AssembledTransaction<Option<IssuerRecord>>>

  /**
   * Construct and simulate a get_schema transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_schema: ({schema_hash}: {schema_hash: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<SchemaRecord>>>

  /**
   * Construct and simulate a get_dispute transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Retrieve a dispute record by its dispute_id.
   */
  get_dispute: ({dispute_id}: {dispute_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<DisputeRecord>>>

  /**
   * Construct and simulate a get_lineage transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_lineage: ({output_digest}: {output_digest: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<LineageRecord>>>

  /**
   * Construct and simulate a accept_admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  accept_admin: ({pending_admin}: {pending_admin: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a approve_seal transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Record an authorized signer's approval for a threshold seal and finalize if met (#124).
   */
  approve_seal: ({signer, proof_id, video_hash, metadata_hash}: {signer: string, proof_id: Buffer, video_hash: Buffer, metadata_hash: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a expire_proof transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  expire_proof: ({admin, proof_id, reason_code}: {admin: string, proof_id: Buffer, reason_code: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_by_video transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_by_video: ({video_hash}: {video_hash: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<ProofRecord>>>

  /**
   * Construct and simulate a get_guardian transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * The currently configured guardian, if any.
   */
  get_guardian: (options?: MethodOptions) => Promise<AssembledTransaction<Option<string>>>

  /**
   * Construct and simulate a get_verifier transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_verifier: (options?: MethodOptions) => Promise<AssembledTransaction<Option<string>>>

  /**
   * Construct and simulate a open_dispute transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Open a new dispute against a registered proof.
   * 
   * # Parameters
   * - `reporter`:        The reporter's address (requires auth; proves liveness).
   * - `reporter_hash`:   Privacy-safe commitment H(reporter_address || proof_id),
   * computed off-chain by the reporter. The raw reporter address is never
   * stored in contract state or events.
   * - `dispute_id`:      Caller-chosen 32-byte unique identifier.
   * - `proof_id`:        The proof being challenged.
   * - `reason`:          Categorised dispute reason.
   * - `commitment_hash`: Off-chain commitment to the reporter's submission.
   * 
   * # Guards
   * - Proof must exist.
   * - `dispute_id` must not already be used.
   * - Proof must have fewer than `MAX_OPEN_DISPUTES_PER_PROOF` open disputes.
   * - Reporter must not be on cooldown for this proof.
   */
  open_dispute: ({reporter, reporter_hash, dispute_id, proof_id, reason, commitment_hash}: {reporter: string, reporter_hash: Buffer, dispute_id: Buffer, proof_id: Buffer, reason: DisputeReason, commitment_hash: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<DisputeRecord>>

  /**
   * Construct and simulate a revoke_proof transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  revoke_proof: ({admin, proof_id}: {admin: string, proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a set_guardian transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Assign the address permitted to trigger emergency pauses without
   * holding the admin key. Admin-only. Pass the admin's own address to
   * revoke the guardian role.
   */
  set_guardian: ({admin, guardian}: {admin: string, guardian: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a set_verifier transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_verifier: ({admin, verifier}: {admin: string, verifier: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a verify_proof transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  verify_proof: ({actor, proof_id, reason_code}: {actor: string, proof_id: Buffer, reason_code: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a correct_proof transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  correct_proof: ({admin, proof_id, new_metadata_hash, reason_code}: {admin: string, proof_id: Buffer, new_metadata_hash: Buffer, reason_code: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a finalize_seal transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Explicitly finalize a threshold seal once valid approvals meet the policy threshold (#124).
   */
  finalize_seal: ({proof_id, video_hash, metadata_hash}: {proof_id: Buffer, video_hash: Buffer, metadata_hash: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<ProofRecord>>

  /**
   * Construct and simulate a get_proof_ttl transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_proof_ttl: (options?: MethodOptions) => Promise<AssembledTransaction<u64>>

  /**
   * Construct and simulate a has_nullifier transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  has_nullifier: ({verifier, nullifier}: {verifier: string, nullifier: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a propose_admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  propose_admin: ({admin, pending_admin}: {admin: string, pending_admin: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a register_seal transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  register_seal: ({issuer, video_hash, metadata_hash, proof_id}: {issuer: string, video_hash: Buffer, metadata_hash: Buffer, proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<ProofRecord>>

  /**
   * Construct and simulate a revoke_issuer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  revoke_issuer: ({admin, issuer}: {admin: string, issuer: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a revoke_proofs transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Revoke multiple proofs in a single transaction during incident response.
   * 
   * Reuses the single-revoke path so history entries and events are identical per proof.
   * Bounded by [`MAX_REVOKE_PROOFS_BATCH_SIZE`] against the execution budget.
   * Fails atomically on any invalid proof.
   */
  revoke_proofs: ({admin, proof_ids, reason_code}: {admin: string, proof_ids: Array<Buffer>, reason_code: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a rotate_issuer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Rotate an active issuer key to a replacement, opening a bounded grace
   * window over the retiring key's pre-rotation evidence (#323).
   * 
   * Admin-only. `previous_issuer` and `replacement_issuer` must be distinct,
   * both registered, and both active. The rotation retires `previous_issuer`
   * immediately — it can no longer sign new seals, directly or through a
   * delegation — while the evidence it already signed stays verifiable until
   * `grace_expires_at`, after which [`Self::is_issuer_verifiable`] fails
   * closed.
   * 
   * `grace_secs == 0` selects [`DEFAULT_ISSUER_ROTATION_GRACE_SECS`].
   * Returns the absolute `grace_expires_at` so a caller can record the
   * deadline without re-reading storage. The window is lazy — it lapses with
   * no transaction — and [`Self::finalize_issuer_rotation`] settles the
   * record afterwards.
   * 
   * # Reverts
   * 
   * - `Unauthorized`               if the caller is not the admin
   * - `InvalidIssuerRotation`      if previous and replacement are equal
   * - `UnknownIssuer`              if either key is absent or inactive
   * - `InvalidIssue
   */
  rotate_issuer: ({admin, previous_issuer, replacement_issuer, grace_secs}: {admin: string, previous_issuer: string, replacement_issuer: string, grace_secs: u64}, options?: MethodOptions) => Promise<AssembledTransaction<u64>>

  /**
   * Construct and simulate a set_proof_ttl transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_proof_ttl: ({admin, ttl_secs}: {admin: string, ttl_secs: u64}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a clear_guardian transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Remove the emergency-pause guardian role. Admin-only.
   */
  clear_guardian: ({admin}: {admin: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_delegation transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Read-only: the raw delegation record, if one is stored. A record past
   * its `expires_at` is still returned so operators can see and prune it;
   * use `is_delegation_active` to ask whether it currently grants anything.
   */
  get_delegation: ({grantor, delegate}: {grantor: string, delegate: string}, options?: MethodOptions) => Promise<AssembledTransaction<Option<DelegationRecord>>>

  /**
   * Construct and simulate a list_verifiers transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return a bounded, stable page of the current verifier configuration.
   * 
   * Slots are ordered: **Active → Pending → Previous**. Only non-None
   * slots appear in `entries`. `cursor` is a 0-based slot index; pass
   * `next_cursor` from the previous response to continue paging.
   * 
   * # Arguments
   * 
   * * `cursor` – starting slot index (0 = first populated slot). A cursor
   * beyond the end of the populated list returns an empty page.
   * * `limit`  – maximum entries per page. Must be non-zero and at most
   * `MAX_VERIFIER_LIST_LIMIT`. Returns `ListLimitExceeded` otherwise.
   * 
   * # Privacy
   * 
   * This is a read-only query equivalent to `get_verifier` — no private
   * witness values, credential secrets, nullifiers, or video hashes are
   * surfaced. An out-of-range cursor produces an empty page rather than a
   * revealing error, so a scanner cannot enumerate capacity by probing.
   * 
   * # Migration / compatibility
   * 
   * Additive: before any verifier is configured, returns an empty page.
   * Callers that only need the active verifier should use `get_verifier`.
   */
  list_verifiers: ({cursor, limit}: {cursor: u32, limit: u32}, options?: MethodOptions) => Promise<AssembledTransaction<VerifierPage>>

  /**
   * Construct and simulate a dismiss_dispute transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Dismiss a dispute (admin only).
   * 
   * Dismissal is valid from both `Open` and `Responded` states. A dismissed
   * dispute is permanently closed with no corrective action.
   */
  dismiss_dispute: ({admin, dispute_id}: {admin: string, dispute_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<DisputeRecord>>

  /**
   * Construct and simulate a get_pause_state transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Read-only: the raw pause record for a single domain bit, if one is
   * currently stored (including a stale record past its `expires_at`
   * that has not yet been cleared by `unpause`).
   */
  get_pause_state: ({domain}: {domain: u32}, options?: MethodOptions) => Promise<AssembledTransaction<Option<PauseRecord>>>

  /**
   * Construct and simulate a get_scope_epoch transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Get the current epoch for a given scope.
   * Returns `DEFAULT_SCOPE_EPOCH` (0) if no epoch has been set.
   */
  get_scope_epoch: ({scope}: {scope: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<u64>>

  /**
   * Construct and simulate a register_source transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  register_source: ({source, video_hash, metadata_hash, proof_id}: {source: string, video_hash: Buffer, metadata_hash: Buffer, proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<ProofRecord>>

  /**
   * Construct and simulate a resolve_dispute transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Resolve a responded dispute (admin only).
   * 
   * Resolution indicates that the admin has reviewed both the dispute and
   * the response commitments and has taken (or noted) any appropriate
   * corrective action. The original proof record is **not** modified.
   * 
   * # Guards
   * - Dispute must be in `Responded` state.
   * - Must be within `resolve_deadline`.
   */
  resolve_dispute: ({admin, dispute_id}: {admin: string, dispute_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<DisputeRecord>>

  /**
   * Construct and simulate a respond_dispute transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Submit a response commitment to an open dispute.
   * 
   * Only the issuer (Tier 3) or source (Tier 2) of the disputed proof may
   * respond. Tier 1 (Silent Witness) proofs have no on-chain identity, so
   * the admin acts as the sole responder for anonymous proofs.
   * 
   * # Guards
   * - Dispute must be in `Open` state.
   * - Must be within `respond_deadline`.
   * - Caller must be the issuer, source, or (for anonymous proofs) admin.
   */
  respond_dispute: ({responder, dispute_id, response_commitment}: {responder: string, dispute_id: Buffer, response_commitment: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<DisputeRecord>>

  /**
   * Construct and simulate a set_scope_epoch transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Set the current epoch for a given scope identifier.
   * 
   * When the admin advances the epoch for a scope, all proofs generated
   * under the previous epoch for that scope will have stale epoch values
   * and will be rejected by `register_anonymous_verified`.
   * 
   * Epochs are strictly monotonic (`epoch > current`). Setting an epoch
   * less than or equal to the current epoch panics with `RegistryError::StaleEpoch`
   * to prevent epoch rollback and re-enabling previously consumed nullifiers.
   * Non-increasing transitions (including equal) are rejected rather than
   * treated idempotently to ensure every update explicitly advances the epoch.
   * 
   * The scope is a 32-byte identifier derived from the scope string
   * (e.g., SHA-256 hash mod BN254 field).  An empty (zero) scope
   * represents the global/unscoped context.
   * 
   * Only the registry admin may call this.
   */
  set_scope_epoch: ({admin, scope, epoch}: {admin: string, scope: Buffer, epoch: u64}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a upgrade_storage transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Apply sequential storage migrations up to the current target schema.
   * 
   * - Admin-only; unauthorized callers fail with `Unauthorized`.
   * - Idempotent at the current target (V1): repeated calls are no-ops and
   * do not emit `SchemaUpgraded`.
   * - Legacy deployments without `DataKey::SchemaVersion` are stamped to V1
   * without emitting `SchemaUpgraded` (layout already matches V1).
   * - Future V2+ migrations land in the `current < target` branch and MUST
   * preserve existing proof / video / nullifier records and never log
   * media, secrets, witnesses, or private keys.
   * 
   * Rollback: redeploying a prior wasm that ignores unknown keys leaves
   * stamped `SchemaVersion` intact; V1 readers treat it as authoritative.
   */
  upgrade_storage: ({admin}: {admin: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a deprecate_schema transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  deprecate_schema: ({admin, schema_hash}: {admin: string, schema_hash: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_issuer_quota transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the configured registration quota for `issuer`, if any.
   */
  get_issuer_quota: ({issuer}: {issuer: string}, options?: MethodOptions) => Promise<AssembledTransaction<Option<IssuerQuotaRecord>>>

  /**
   * Construct and simulate a get_proof_status transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_proof_status: ({proof_id}: {proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<ProofVerificationStatus>>

  /**
   * Construct and simulate a get_source_batch transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Read-only query for a stored source batch record.
   */
  get_source_batch: ({root}: {root: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<BatchRecord>>>

  /**
   * Construct and simulate a grant_delegation transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Grant `delegate` a narrowly scoped, expiring authority to register on
   * the caller's behalf.
   * 
   * Requires the grantor's own signature — a delegate can never create or
   * extend a delegation, which is what makes the mechanism non-transitive.
   * 
   * `scope` is a non-empty subset of `DELEGATION_SCOPE_ALL`.
   * `duration_secs` is non-zero and at most `MAX_DELEGATION_DURATION_SECS`.
   * 
   * Idempotent: re-granting to an existing delegate overwrites that
   * delegate's record — narrowing or widening scope, extending or shortening
   * expiry — and does not consume another storage slot. Returns the epoch
   * second at which the delegation lapses on its own.
   * 
   * # Reverts
   * 
   * - `SelfDelegation`              if `grantor == delegate`
   * - `InvalidDelegationScope`      if `scope` is zero or has unknown bits
   * - `InvalidDelegationDuration`   if `duration_secs` is zero or over the cap
   * - `DelegationsSaturated`        if the grantor already holds the maximum
   */
  grant_delegation: ({grantor, delegate, scope, duration_secs}: {grantor: string, delegate: string, scope: u32, duration_secs: u64}, options?: MethodOptions) => Promise<AssembledTransaction<u64>>

  /**
   * Construct and simulate a register_lineage transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Record a verifiable derivative of one or more existing artefacts, and
   * persist the parent content commitments for privacy-preserving public
   * boundaries (#332, #333).
   * 
   * Parent commitments are derived on-chain from each parent's stored public
   * fields so callers cannot supply forged bindings. `depth` is the depth the
   * caller believes this derivative sits at: it is checked against the depth
   * implied by the parents rather than trusted, so a caller cannot claim a
   * shallow position to slip past `MAX_LINEAGE_DEPTH`; the stored record and
   * the published event always carry the derived depth.
   * 
   * Fails with `LineageFanOutExceeded` (#60) when the parent set exceeds
   * `MAX_LINEAGE_FANOUT`, `LineageFanOutSaturated` (#79) when a parent
   * already has `MAX_LINEAGE_FANOUT` derivatives, `LineageCycle` (#58) for a
   * self-referential edge, `LineageTooDeep` (#59) past `MAX_LINEAGE_DEPTH`,
   * `LineageDepthMismatch` (#80) for a forged depth, `DuplicateLineage` (#78)
   * for an output digest that is already recorded, `LineageEmptyParents`
   * (#76) for an empty
   */
  register_lineage: ({actor, parent_proof_ids, manifest_digest, operation_type, output_digest, depth}: {actor: string, parent_proof_ids: Array<Buffer>, manifest_digest: Buffer, operation_type: string, output_digest: Buffer, depth: u32}, options?: MethodOptions) => Promise<AssembledTransaction<LineageRecord>>

  /**
   * Construct and simulate a set_issuer_quota transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Configure or clear the per-window registration quota for `issuer` (or
   * Tier 2 source key). Passing `0` for `max_registrations` or `window_secs`
   * clears the quota and any accrued counter, restoring unlimited capacity.
   */
  set_issuer_quota: ({admin, issuer, max_registrations, window_secs}: {admin: string, issuer: string, max_registrations: u32, window_secs: u64}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_admin_council transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the active admin council, or None if no council is configured or still in timelock delay.
   */
  get_admin_council: (options?: MethodOptions) => Promise<AssembledTransaction<Option<AdminCouncil>>>

  /**
   * Construct and simulate a get_pending_admin transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the pending admin address, if an admin transfer is proposed.
   */
  get_pending_admin: (options?: MethodOptions) => Promise<AssembledTransaction<Option<string>>>

  /**
   * Construct and simulate a get_seal_approval transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return a signer's approval record for `proof_id`, if any (#124).
   */
  get_seal_approval: ({proof_id, signer}: {proof_id: Buffer, signer: string}, options?: MethodOptions) => Promise<AssembledTransaction<Option<SealApproval>>>

  /**
   * Construct and simulate a reactivate_schema transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  reactivate_schema: ({admin, schema_hash}: {admin: string, schema_hash: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a revoke_delegation transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Revoke a delegation ahead of its expiry.
   * 
   * Callable by the grantor (withdrawing authority it issued) or by the
   * admin (incident response against a compromised delegate). Revoking a
   * delegation that does not exist is a no-op rather than an error, so
   * retries and concurrent revocations converge.
   */
  revoke_delegation: ({revoker, grantor, delegate}: {revoker: string, grantor: string, delegate: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a set_admin_council transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Configure an optional multi-party admin council guarded by current admin
   * and the timelock min delay.
   */
  set_admin_council: ({admin, members, threshold}: {admin: string, members: Array<string>, threshold: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a supersede_dispute transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Supersede a disputed proof by linking a corrected proof (admin only).
   * 
   * This marks the dispute as `Superseded` and records the correcting proof
   * ID. The original disputed proof is **not** revoked - callers should use
   * `revoke_proof` separately if revocation is also desired.
   * 
   * # Guards
   * - Dispute must be in `Open` or `Responded` state.
   * - `superseding_proof_id` must exist in the registry.
   * - It must not equal the disputed `proof_id` (trivial cycle).
   * - It must not already point back to the disputed proof (depth-1 cycle).
   */
  supersede_dispute: ({admin, dispute_id, superseding_proof_id}: {admin: string, dispute_id: Buffer, superseding_proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<DisputeRecord>>

  /**
   * Construct and simulate a add_receipt_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Register or reactivate an uncompressed SEC-1 P-256 receipt-signing public key.
   */
  add_receipt_signer: ({admin, public_key}: {admin: string, public_key: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<ReceiptSignerRecord>>

  /**
   * Construct and simulate a cancel_seal_policy transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Cancel a threshold seal policy (#124).
   */
  cancel_seal_policy: ({admin, version}: {admin: string, version: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a create_seal_policy transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Create a new versioned threshold seal policy and cancel any prior active policy (#124).
   */
  create_seal_policy: ({admin, required_approvals, max_signers, approval_ttl, expires_at}: {admin: string, required_approvals: u32, max_signers: u32, approval_ttl: u64, expires_at: u64}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a get_proof_statuses transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the human-readable verification status of multiple proofs in a single
   * batch query, efficiently retrieving them without exceeding Soroban read budgets.
   * 
   * The maximum number of proof IDs in a single batch is bounded (e.g. 100) to
   * ensure the query always completes within resource limits.
   */
  get_proof_statuses: ({proof_ids}: {proof_ids: Array<Buffer>}, options?: MethodOptions) => Promise<AssembledTransaction<Array<ProofVerificationStatus>>>

  /**
   * Construct and simulate a get_receipt_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Inspect a receipt-signing public key record, if ever registered.
   */
  get_receipt_signer: ({public_key}: {public_key: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<ReceiptSignerRecord>>>

  /**
   * Construct and simulate a get_schema_version transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the active storage schema version. Legacy deployments that have
   * not called `upgrade_storage` report `V1`; fresh V2 deployments report `V2`.
   */
  get_schema_version: (options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a get_verifier_state transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_verifier_state: (options?: MethodOptions) => Promise<AssembledTransaction<VerifierState>>

  /**
   * Construct and simulate a register_anonymous transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  register_anonymous: ({video_hash, metadata_hash, proof_id, nullifier, credential_root, proof}: {video_hash: Buffer, metadata_hash: Buffer, proof_id: Buffer, nullifier: Buffer, credential_root: Buffer, proof: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<ProofRecord>>

  /**
   * Construct and simulate a add_credential_root transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  add_credential_root: ({admin, credential_root, metadata_hash}: {admin: string, credential_root: Buffer, metadata_hash: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a extend_instance_ttl transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Extend the contract instance storage TTL and emit `InstanceTTLMaintained`.
   */
  extend_instance_ttl: (options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_credential_root transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_credential_root: ({credential_root}: {credential_root: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<CredentialRootRecord>>>

  /**
   * Construct and simulate a get_issuer_rotation transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * The rotation grace record for `issuer`, when the key has rotated out and
   * the window has not been settled yet (#323).
   * 
   * `None` for an unknown key, an active key, a revoked key, and a key whose
   * lapsed window was already finalized. In each of those cases
   * [`Self::is_issuer_verifiable`] is the read that decides standing.
   */
  get_issuer_rotation: ({issuer}: {issuer: string}, options?: MethodOptions) => Promise<AssembledTransaction<Option<IssuerRotationRecord>>>

  /**
   * Construct and simulate a get_proof_assurance transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Single read call that summarises everything a verifier needs to trust a proof:
   * verification status, tier, timestamp assurance level, open dispute count,
   * metadata envelope version, and issuer verifiability.
   * 
   * Returns `None` if the proof is not found.
   */
  get_proof_assurance: ({proof_id}: {proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<ProofAssurance>>>

  /**
   * Construct and simulate a get_revocation_root transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_revocation_root: (options?: MethodOptions) => Promise<AssembledTransaction<Option<Buffer>>>

  /**
   * Construct and simulate a get_timestamp_claim transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the timestamp claim for `proof_id`, if any.
   */
  get_timestamp_claim: ({proof_id}: {proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<TimestampClaim>>>

  /**
   * Construct and simulate a list_proof_disputes transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return dispute IDs for a proof in creation order with pagination.
   * 
   * - `cursor` is the zero-based offset into the proof's disputes.
   * - `limit` is the maximum number of dispute IDs to return, capped by
   * `MAX_PROOF_DISPUTES_PAGE`.
   * - Missing proofs or proofs without disputes yield an empty list (privacy-safe).
   */
  list_proof_disputes: ({proof_id, cursor, limit}: {proof_id: Buffer, cursor: u32, limit: u32}, options?: MethodOptions) => Promise<AssembledTransaction<Array<Buffer>>>

  /**
   * Construct and simulate a set_revocation_root transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_revocation_root: ({admin, revocation_root}: {admin: string, revocation_root: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a check_non_revocation transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Verify a non-revocation proof produced by the `revocation_witness`
   * Noir circuit.
   * 
   * The proof demonstrates that `credential_root` is **not** a member of
   * the currently-published revocation tree (`revocation_root`) — or a
   * recent previous root still within the configured grace window — without
   * revealing which revoked credentials exist or which identity is acting.
   * 
   * # Public input layout (128 bytes, 4 x BN254 field elements)
   * 
   * ```text
   * [  0.. 32)  revocation_root   - must match the current root or a recent root within the grace window
   * [ 32.. 64)  nullifier         - one-use replay guard
   * [ 64.. 96)  domain_separator  - must match REVOCATION_DOMAIN_SEPARATOR
   * [ 96..128)  credential_root   - must be registered & active on-chain
   * ```
   * 
   * # Reverts
   * 
   * - `NotInitialized`      if no revocation root has been published yet
   * - `VerifierNotSet`       if no external verifier contract is configured
   * - `InvalidPublicInputs`  if the domain separator, layout, or revocation root (unknown/outside grace window) is invalid
   * - `UnknownCredentia
   */
  check_non_revocation: ({public_inputs, proof}: {public_inputs: Buffer, proof: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_council_proposal transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_council_proposal: ({proposal_id}: {proposal_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<Option<CouncilProposal>>>

  /**
   * Construct and simulate a get_delegation_count transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Read-only: how many distinct delegates a grantor currently holds,
   * against `MAX_DELEGATIONS_PER_GRANTOR`.
   */
  get_delegation_count: ({grantor}: {grantor: string}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a get_proof_history_at transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_proof_history_at: ({proof_id, seq}: {proof_id: Buffer, seq: u32}, options?: MethodOptions) => Promise<AssembledTransaction<Option<ProofHistoryEntry>>>

  /**
   * Construct and simulate a get_revocation_roots transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the bounded history of recent revocation roots in chronological
   * order (oldest first, current active root last), up to
   * [`MAX_REVOCATION_ROOT_HISTORY`] entries.
   */
  get_revocation_roots: (options?: MethodOptions) => Promise<AssembledTransaction<Array<RevocationRootEntry>>>

  /**
   * Construct and simulate a is_delegation_active transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Read-only: does a live delegation from `grantor` to `delegate` carry
   * every bit of `scope`? Returns `false` for unknown, expired, or
   * insufficiently scoped delegations rather than erroring, so callers can
   * pre-flight without a trial transaction.
   */
  is_delegation_active: ({grantor, delegate, scope}: {grantor: string, delegate: string, scope: u32}, options?: MethodOptions) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a is_issuer_verifiable transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Whether `issuer` may still anchor verification of evidence it issued
   * (#323).
   * 
   * True while the registry lists the issuer as active, and true for a
   * rotated-out key until its grace window lapses. False for an unknown key,
   * a revoked key, and a key at or past `grace_expires_at` — a lapsed window
   * fails closed rather than being silently extended. Never panics, so a
   * caller can pre-flight an unknown, revoked, or unsupported issuer without
   * risking a reverted transaction.
   */
  is_issuer_verifiable: ({issuer}: {issuer: string}, options?: MethodOptions) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a cancel_admin_transfer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  cancel_admin_transfer: ({admin}: {admin: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a commit_receipt_digest transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Anchor a signed verification receipt digest for `proof_id`.
   * 
   * Idempotent when retried with the exact committed `receipt_digest`.
   */
  commit_receipt_digest: ({caller, proof_id, receipt_digest, public_key, signature}: {caller: string, proof_id: Buffer, receipt_digest: Buffer, public_key: Buffer, signature: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<ReceiptCommitmentRecord>>

  /**
   * Construct and simulate a get_current_wasm_hash transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_current_wasm_hash: (options?: MethodOptions) => Promise<AssembledTransaction<Option<Buffer>>>

  /**
   * Construct and simulate a get_metadata_envelope transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the versioned metadata envelope for `proof_id`, if stored.
   */
  get_metadata_envelope: ({proof_id}: {proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<MetadataEnvelope>>>

  /**
   * Construct and simulate a get_statuses_by_video transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the verification status of multiple videos in a single batch query,
   * resolving video hashes to their underlying proof verification statuses.
   * 
   * Unknown video hashes return `ProofVerificationStatus::NotFound` instead of failing the batch.
   * The maximum number of video hashes in a single batch is bounded (100) to match `get_proof_statuses`.
   */
  get_statuses_by_video: ({video_hashes}: {video_hashes: Array<Buffer>}, options?: MethodOptions) => Promise<AssembledTransaction<Array<ProofVerificationStatus>>>

  /**
   * Construct and simulate a get_timelock_proposal transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_timelock_proposal: ({proposal_id}: {proposal_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<Option<TimelockProposal>>>

  /**
   * Construct and simulate a list_credential_roots transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Enumerate credential roots and their current statuses across sequential IDs (#731).
   * 
   * - `cursor`: ID offset to start scanning from (1-based sequential IDs).
   * If `cursor == 0`, scanning begins at ID 1.
   * - `limit`: maximum number of roots to return; capped at `MAX_CREDENTIAL_ROOTS_PAGE`.
   * If 0 or exceeding the cap, `limit` is clamped to `MAX_CREDENTIAL_ROOTS_PAGE`.
   * - Non-existent/deleted entries are skipped.
   * - Read-only query; no auth required.
   */
  list_credential_roots: ({cursor, limit}: {cursor: u32, limit: u32}, options?: MethodOptions) => Promise<AssembledTransaction<CredentialRootPage>>

  /**
   * Construct and simulate a list_lineage_children transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Paginate child output digests for a parent proof or lineage digest (#335).
   * 
   * - `offset` is 0-based into the stable registration order.
   * - `limit` must be in `1..=MAX_LINEAGE_CHILDREN_PAGE`.
   * - Missing parents yield an empty page with `total == 0` (privacy-safe).
   */
  list_lineage_children: ({parent_proof_id, offset, limit}: {parent_proof_id: Buffer, offset: u32, limit: u32}, options?: MethodOptions) => Promise<AssembledTransaction<LineageChildrenPage>>

  /**
   * Construct and simulate a revoke_receipt_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Revoke an existing receipt-signing public key. Idempotent if already revoked.
   */
  revoke_receipt_signer: ({admin, public_key}: {admin: string, public_key: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<ReceiptSignerRecord>>

  /**
   * Construct and simulate a add_seal_policy_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Add an active issuer to a threshold seal policy's signer set (#124).
   */
  add_seal_policy_signer: ({admin, version, signer}: {admin: string, version: u32, signer: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a anchor_timestamp_claim transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Anchor an independent timestamp claim for an existing proof.
   * 
   * Always records the current ledger timestamp/sequence as a Stellar
   * independent source. Optional `claimed_time` and RFC 3161 commitment
   * raise assurance without storing raw tokens or private material.
   * 
   * Re-anchoring is allowed only when the new claim is a strict assurance
   * upgrade (or adds an RFC 3161 commitment). Compatible callers that omit
   * timestamp claims are unaffected.
   */
  anchor_timestamp_claim: ({actor, proof_id, attestation_digest, claimed_time, rfc3161_commitment}: {actor: string, proof_id: Buffer, attestation_digest: Buffer, claimed_time: u64, rfc3161_commitment: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<TimestampClaim>>

  /**
   * Construct and simulate a bind_metadata_envelope transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Bind or upgrade a versioned metadata envelope for an existing proof.
   * 
   * Compatible callers that only use `register_*` with a bare
   * `metadata_hash` continue to work: `save_record` stamps V1 automatically.
   * This entry point is for explicit V2 (or future) bindings and upgrades.
   * 
   * Rules:
   * - `version` must be in `1..=METADATA_ENVELOPE_VERSION_MAX`
   * - `metadata_hash` must be non-zero and match the proof's stored hash
   * - first bind may set any supported version
   * - re-bind may only upgrade version (never downgrade)
   * 
   * Auth: admin, or the proof's source/issuer when present.
   */
  bind_metadata_envelope: ({actor, proof_id, version, metadata_hash}: {actor: string, proof_id: Buffer, version: u32, metadata_hash: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<MetadataEnvelope>>

  /**
   * Construct and simulate a classify_public_inputs transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Classify verifier material against the canonical `hpx-vi/1` codec.
   * 
   * Read-only, side-effect free, and bounded: the work is O(1) in the frame
   * size and no storage is touched, so it is safe to expose publicly and
   * safe to call while any domain is paused.
   * 
   * `schema_id` is [`SCHEMA_ID_SILENT_WITNESS`],
   * [`SCHEMA_ID_SILENT_WITNESS_V2`], or [`SCHEMA_ID_REVOCATION_WITNESS`].
   * `proof_len` is the length of the proof blob the caller intends to submit
   * — passed as a length rather than the blob itself so classification never
   * transports proof material.
   * 
   * Returns [`verifier_inputs::ACCEPTED_CODE`] (`0`) when the material is
   * canonical, otherwise the stable [`RejectCode::as_code`] value. This is
   * the on-chain half of the cross-layer conformance corpus in
   * `zk/vectors/verifier_conformance_v1.json`.
   * 
   * Compatibility: this entry point is purely additive. The registration
   * paths still apply the v1-lenient rules described in
   * `docs/zk-conformance-vectors.md`; promoting the codec to enforcement is
   * a separate, versioned migration.
   */
  classify_public_inputs: ({schema_id, public_inputs, proof_len}: {schema_id: u32, public_inputs: Buffer, proof_len: u32}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a expire_credential_root transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  expire_credential_root: ({admin, credential_root}: {admin: string, credential_root: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a extend_persistent_ttls transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Extend persistent storage TTLs for a bounded batch (`1..=50`) of keys.
   */
  extend_persistent_ttls: ({keys}: {keys: Array<DataKey>}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_active_seal_policy transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the currently active, unexpired threshold seal policy (#124).
   */
  get_active_seal_policy: (options?: MethodOptions) => Promise<AssembledTransaction<Option<SealPolicy>>>

  /**
   * Construct and simulate a get_issuer_quota_usage transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the current window-bucket usage for `issuer`.
   * 
   * Automatically resolves ledger-time window rollover so callers see `count == 0`
   * for a fresh bucket without requiring an admin reset transaction.
   */
  get_issuer_quota_usage: ({issuer}: {issuer: string}, options?: MethodOptions) => Promise<AssembledTransaction<IssuerQuotaUsage>>

  /**
   * Construct and simulate a get_open_dispute_count transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the number of currently Open disputes for a given proof.
   */
  get_open_dispute_count: ({proof_id}: {proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a get_receipt_commitment transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the committed receipt digest record for `proof_id`, if any.
   */
  get_receipt_commitment: ({proof_id}: {proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<ReceiptCommitmentRecord>>>

  /**
   * Construct and simulate a propose_council_action transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Propose a critical action to the active admin council.
   */
  propose_council_action: ({proposer, action, target, payload}: {proposer: string, action: u32, target: string, payload: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a revoke_credential_root transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  revoke_credential_root: ({admin, credential_root}: {admin: string, credential_root: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a update_issuer_metadata transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Update an active issuer's metadata hash.
   * 
   * Requires admin auth and that `issuer` is active.
   * Only the metadata hash changes; active status and any rotation grace
   * records are preserved.
   * 
   * # Reverts
   * 
   * - `Unauthorized` if `admin` is not the current admin
   * - `UnknownIssuer` if `issuer` does not exist or is inactive
   */
  update_issuer_metadata: ({admin, issuer, metadata_hash}: {admin: string, issuer: string, metadata_hash: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a cancel_council_proposal transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Cancel a council proposal.
   */
  cancel_council_proposal: ({caller, proposal_id}: {caller: string, proposal_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_admin_intent_digest transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the bound role-change intent digest for the pending admin transfer, if any (#1184).
   */
  get_admin_intent_digest: (options?: MethodOptions) => Promise<AssembledTransaction<Option<Buffer>>>

  /**
   * Construct and simulate a get_lineage_child_count transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return how many derivatives have charged `parent_proof_id`'s out-degree budget (#333).
   */
  get_lineage_child_count: ({parent_proof_id}: {parent_proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a get_proof_dispute_count transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the total number of disputes ever opened for a given proof.
   */
  get_proof_dispute_count: ({proof_id}: {proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a get_proof_history_count transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_proof_history_count: ({proof_id}: {proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a get_seal_approval_count transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the count of currently valid, unexpired approvals from active signers (#124).
   */
  get_seal_approval_count: ({proof_id}: {proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a list_timelock_proposals transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Enumerate timelocked proposals across sequential IDs.
   * 
   * - `cursor`: ID offset to start scanning from (e.g. 0 or 1 starts at first proposal).
   * Proposals use 1-based sequential IDs. If `cursor == 0`, scanning begins at ID 1.
   * - `limit`: maximum number of proposals to return; capped at `MAX_TIMELOCK_PROPOSALS_PAGE`.
   * If 0 or exceeding the cap, `limit` is clamped to `MAX_TIMELOCK_PROPOSALS_PAGE`.
   * - Non-existent/deleted proposals are skipped.
   * - Read-only query; no auth required.
   */
  list_timelock_proposals: ({cursor, limit}: {cursor: u32, limit: u32}, options?: MethodOptions) => Promise<AssembledTransaction<TimelockProposalPage>>

  /**
   * Construct and simulate a register_batch_verified transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Register multiple video hashes under the same credential using a
   * single aggregated UltraHonk proof produced by the Silent Witness
   * Aggregator circuit.
   * 
   * # Arguments
   * 
   * * `env` – Soroban environment
   * * `batch_id` – Unique batch identifier (serves as the batch proof_id)
   * * `metadata_hash` – Shared metadata hash for all elements in the batch
   * * `public_inputs` – Aggregated public inputs (1 domain separator +
   * MAX_AGGREGATION_SIZE × 4 field elements; see AGGREGATED_PUBLIC_INPUT_SIZE)
   * * `proof` – Aggregated UltraHonk proof bytes
   * * `video_hashes` – Ordered list of video hashes in the batch (must
   * match the order in public_inputs)
   * 
   * # Panics
   * 
   * - `BatchSizeExceeded` if `video_hashes.len() > MAX_AGGREGATION_SIZE`
   * - `BatchCountMismatch` if the number of video hashes doesn't match
   * the parsed batch count from public inputs
   * - `InvalidPublicInputs` if the domain separator or public input layout
   * is wrong
   * - `UnknownCredentialRoot` if the credential root is not registered
   * - `RevokedCredentialRoot` if the credential root has
   */
  register_batch_verified: ({batch_id, metadata_hash, public_inputs, proof, video_hashes}: {batch_id: Buffer, metadata_hash: Buffer, public_inputs: Buffer, proof: Buffer, video_hashes: Array<Buffer>}, options?: MethodOptions) => Promise<AssembledTransaction<Array<ProofRecord>>>

  /**
   * Construct and simulate a register_seal_delegated transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Register a Tier 3 public-seal proof on `issuer`'s behalf.
   * 
   * The issuer must still be a registered, active issuer — a delegation
   * never substitutes for issuer standing, it only lets someone else
   * exercise it. Subject to the same Tier 3 pause domain and uniqueness
   * rules as `register_seal`.
   */
  register_seal_delegated: ({delegate, issuer, video_hash, metadata_hash, proof_id}: {delegate: string, issuer: string, video_hash: Buffer, metadata_hash: Buffer, proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<ProofRecord>>

  /**
   * Construct and simulate a accept_admin_with_intent transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Accept a pending admin transfer while explicitly binding the expected
   * target role and on-chain intent digest (#1184).
   */
  accept_admin_with_intent: ({pending_admin, expected_role, expected_digest}: {pending_admin: string, expected_role: u32, expected_digest: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a approve_council_proposal transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Record a council member's approval for a proposal.
   */
  approve_council_proposal: ({member, proposal_id}: {member: string, proposal_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a exec_council_with_intent transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Execute a council proposal while explicitly verifying the expected target
   * role, target address, and bound intent digest (#1184).
   */
  exec_council_with_intent: ({caller, proposal_id, expected_role, expected_target, expected_digest}: {caller: string, proposal_id: u32, expected_role: u32, expected_target: string, expected_digest: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a execute_council_proposal transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Execute a council proposal once threshold distinct member approvals are gathered.
   */
  execute_council_proposal: ({caller, proposal_id}: {caller: string, proposal_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a finalize_issuer_rotation transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Settle a lapsed issuer-rotation grace window (#323).
   * 
   * Permissionless by design: the transition is fully determined by the
   * stored `grace_expires_at`, so any caller may close the record once the
   * window has lapsed, and no admin key is needed to stop a retired key from
   * holding standing. Callable at exactly `grace_expires_at` and after it;
   * the record is removed and `IssuerRotationGraceExpired` is published.
   * 
   * # Reverts
   * 
   * - `IssuerRotationNotFound`         if no rotation record exists
   * - `IssuerRotationGraceStillActive` if the window has not lapsed
   */
  finalize_issuer_rotation: ({issuer}: {issuer: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a exec_timelock_with_intent transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Execute a matured timelock proposal while verifying the caller's expected
   * target role, target address, and bound intent digest (#1184).
   */
  exec_timelock_with_intent: ({caller, proposal_id, expected_role, expected_target, expected_digest}: {caller: string, proposal_id: u32, expected_role: u32, expected_target: string, expected_digest: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_council_intent_digest transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the bound role-change intent digest for `proposal_id` in the council queue (#1184).
   */
  get_council_intent_digest: ({proposal_id}: {proposal_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<Option<Buffer>>>

  /**
   * Construct and simulate a get_credential_root_count transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the total number of indexed credential roots (#731).
   */
  get_credential_root_count: (options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a get_pending_admin_council transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the pending admin council currently in timelock delay, or None.
   */
  get_pending_admin_council: (options?: MethodOptions) => Promise<AssembledTransaction<Option<AdminCouncil>>>

  /**
   * Construct and simulate a propose_timelocked_action transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  propose_timelocked_action: ({admin, action, target, payload}: {admin: string, action: u32, target: string, payload: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a register_source_delegated transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Register a Tier 2 consistent-source proof on `source`'s behalf.
   * 
   * Authorizes the *delegate*, not the source: the source's key is never
   * required at call time. The stored `ProofRecord` still names `source`,
   * while the delegate is recorded in the proof's lifecycle history, so the
   * audit trail distinguishes authority from actor.
   * 
   * Subject to the same Tier 2 pause domain and uniqueness rules as
   * `register_source`.
   */
  register_source_delegated: ({delegate, source, video_hash, metadata_hash, proof_id}: {delegate: string, source: string, video_hash: Buffer, metadata_hash: Buffer, proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<ProofRecord>>

  /**
   * Construct and simulate a remove_seal_policy_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Remove a signer from a threshold seal policy (#124).
   */
  remove_seal_policy_signer: ({admin, version, signer}: {admin: string, version: u32, signer: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a activate_verifier_rotation transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  activate_verifier_rotation: ({admin}: {admin: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a cancel_timelocked_proposal transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  cancel_timelocked_proposal: ({admin, proposal_id}: {admin: string, proposal_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a compute_role_intent_digest transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Deterministically compute the canonical domain-separated role-change intent digest (#1184).
   */
  compute_role_intent_digest: ({queue_domain, proposal_id, target_role, proposer, target, payload, created_at}: {queue_domain: u32, proposal_id: u32, target_role: u32, proposer: string, target: string, payload: Buffer, created_at: u64}, options?: MethodOptions) => Promise<AssembledTransaction<Buffer>>

  /**
   * Construct and simulate a emergency_execute_timelock transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  emergency_execute_timelock: ({admin, proposal_id}: {admin: string, proposal_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_council_proposal_count transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_council_proposal_count: (options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a get_lineage_children_count transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return how many child digests are indexed under `parent_proof_id` (#335).
   */
  get_lineage_children_count: ({parent_proof_id}: {parent_proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a get_seal_policy_by_version transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return a threshold seal policy by version number (#124).
   */
  get_seal_policy_by_version: ({version}: {version: u32}, options?: MethodOptions) => Promise<AssembledTransaction<Option<SealPolicy>>>

  /**
   * Construct and simulate a get_storage_schema_version transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the persistent storage schema version.
   * 
   * Missing keys (pre-#85 deployments) are treated as V1 so callers and
   * the upgrade harness stay compatible without a forced rewrite.
   */
  get_storage_schema_version: (options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a get_timelock_intent_digest transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the bound role-change intent digest for `proposal_id` in the timelock queue (#1184).
   */
  get_timelock_intent_digest: ({proposal_id}: {proposal_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<Option<Buffer>>>

  /**
   * Construct and simulate a register_source_batch_root transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Register a Tier 2 source batch root.
   * 
   * Allows high-volume Tier 2 sources to anchor many items in a single transaction
   * by committing the root of a binary Merkle tree.
   */
  register_source_batch_root: ({source, root, count, metadata_hash}: {source: string, root: Buffer, count: u32, metadata_hash: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<BatchRecord>>

  /**
   * Construct and simulate a rollback_verifier_rotation transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  rollback_verifier_rotation: ({admin}: {admin: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a schedule_verifier_rotation transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  schedule_verifier_rotation: ({admin, verifier, activation_ledger, overlap_window, rollback_window}: {admin: string, verifier: string, activation_ledger: u64, overlap_window: u64, rollback_window: u64}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a execute_timelocked_proposal transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  execute_timelocked_proposal: ({caller, proposal_id}: {caller: string, proposal_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_timelock_min_delay_secs transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_timelock_min_delay_secs: (options?: MethodOptions) => Promise<AssembledTransaction<u64>>

  /**
   * Construct and simulate a get_timelock_proposal_count transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_timelock_proposal_count: (options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a register_anonymous_verified transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  register_anonymous_verified: ({video_hash, metadata_hash, proof_id, public_inputs, proof}: {video_hash: Buffer, metadata_hash: Buffer, proof_id: Buffer, public_inputs: Buffer, proof: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<ProofRecord>>

  /**
   * Construct and simulate a set_timelock_min_delay_secs transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  set_timelock_min_delay_secs: ({admin, delay_secs}: {admin: string, delay_secs: u64}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a verify_selective_disclosure transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  verify_selective_disclosure: ({public_inputs, proof}: {public_inputs: Buffer, proof: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a cancel_pending_admin_council transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Cancel a pending admin council before its timelock delay expires.
   */
  cancel_pending_admin_council: ({admin}: {admin: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a is_supported_circuit_version transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Read-only: may a proof carrying `version` be accepted right now?
   * 
   * True only when `version` is both framable by this wasm build and inside
   * the active verifier's declared window. Callers can pre-flight without a
   * trial transaction.
   */
  is_supported_circuit_version: ({version}: {version: u32}, options?: MethodOptions) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a get_verifier_circuit_versions transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * The active verifier's circuit-version window (#343).
   * 
   * An undeclared window answers as the full built-in range, so a pre-#343
   * deployment reports what it actually enforces instead of erroring.
   */
  get_verifier_circuit_versions: (options?: MethodOptions) => Promise<AssembledTransaction<VerifierCircuitVersions>>

  /**
   * Construct and simulate a is_supported_envelope_version transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Whether `version` is accepted by this wasm build.
   */
  is_supported_envelope_version: ({version}: {version: u32}, options?: MethodOptions) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a resolve_metadata_envelope_ver transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Resolve the envelope version for a proof.
   * 
   * Returns the stored envelope version when present; otherwise
   * `METADATA_ENVELOPE_VERSION_DEFAULT` for proofs that exist without an
   * explicit envelope row (pre-#317 / stamped callers). Returns `0` when
   * the proof is unknown (callers must treat 0 as not-found).
   */
  resolve_metadata_envelope_ver: ({proof_id}: {proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a set_verifier_circuit_versions transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Declare the circuit-version window the active verifier can check (#343).
   * 
   * Admin-only and additive. `min_version..=max_version` must lie inside
   * this wasm build's own supported range; an empty or out-of-range window
   * fails with the stable `InvalidCircuitVersionRange` code rather than
   * being silently clamped. Once declared, every proof-verifying entry point
   * refuses a proof whose circuit version falls outside the window *before*
   * the external verifier is invoked, so an unsupported version can never
   * reach a dependency that cannot answer.
   * 
   * Restore the default by setting the window back to
   * `MIN_SUPPORTED_CIRCUIT_VERSION..=MAX_SUPPORTED_CIRCUIT_VERSION`.
   */
  set_verifier_circuit_versions: ({admin, min_version, max_version}: {admin: string, min_version: u32, max_version: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a verify_source_batch_inclusion transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Verify cryptographic inclusion of a leaf in a source batch root.
   * 
   * Evaluates a binary Merkle inclusion proof using SHA-256 with domain-separated
   * leaf (`0x00`) and node (`0x01`) hashing to prevent second-preimage attacks
   * by construction.
   */
  verify_source_batch_inclusion: ({root, leaf, proof, index}: {root: Buffer, leaf: Buffer, proof: Array<Buffer>, index: u32}, options?: MethodOptions) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a get_lineage_parent_commitments transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return only the stored parent commitments for `output_digest` (#332).
   * 
   * Useful for interoperable consumers that must not pull full lineage
   * topology (parent proof ids) across a trust boundary.
   */
  get_lineage_parent_commitments: ({output_digest}: {output_digest: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<Array<Buffer>>>>

  /**
   * Construct and simulate a get_reporter_open_dispute_count transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the number of currently open (non-terminal) disputes opened by
   * `reporter` across all proofs.
   */
  get_reporter_open_dispute_count: ({reporter}: {reporter: string}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a stage_credential_roots_backfill transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Stage or queue legacy credential roots for bounded backfill during `upgrade_storage` (#731).
   */
  stage_credential_roots_backfill: ({admin, roots}: {admin: string, roots: Array<Buffer>}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_revocation_root_grace_window transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Return the configured grace window (in ledgers) for accepting previous
   * revocation roots, defaulting to [`DEFAULT_REVOCATION_ROOT_GRACE_LEDGERS`].
   */
  get_revocation_root_grace_window: (options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a has_independent_timestamp_anchor transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Whether the proof has an independently verifiable on-chain timestamp
   * source (Stellar ledger and/or RFC 3161 commitment).
   */
  has_independent_timestamp_anchor: ({proof_id}: {proof_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<boolean>>

  /**
   * Construct and simulate a set_revocation_root_grace_window transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Configure the grace window (in ledgers) during which recent previous
   * revocation roots in the ring buffer remain accepted by
   * [`Self::check_non_revocation`].
   * 
   * Admin-only. Setting `grace_ledgers == 0` disables the grace window so
   * only the current root is accepted. Values above
   * [`MAX_REVOCATION_ROOT_GRACE_LEDGERS`] are rejected with
   * [`RegistryError::InvalidPublicInputs`].
   */
  set_revocation_root_grace_window: ({admin, grace_ledgers}: {admin: string, grace_ledgers: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

}
export class Client extends ContractClient {
  static async deploy<T = Client>(
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options: MethodOptions &
      Omit<ContractClientOptions, "contractId"> & {
        /** The hash of the Wasm blob, which must already be installed on-chain. */
        wasmHash: Buffer | string;
        /** Salt used to generate the contract's ID. Passed through to {@link Operation.createCustomContract}. Default: random. */
        salt?: Buffer | Uint8Array;
        /** The format used to decode `wasmHash`, if it's provided as a string. */
        format?: "hex" | "base64";
      }
  ): Promise<AssembledTransaction<T>> {
    return ContractClient.deploy(null, options)
  }
  constructor(public readonly options: ContractClientOptions) {
    super(
      new ContractSpec([ "AAAAAgAAAAAAAAAAAAAAB0RhdGFLZXkAAAAAQwAAAAAAAAAAAAAABUFkbWluAAAAAAAAAQAAAAAAAAAFUHJvb2YAAAAAAAABAAAD7gAAACAAAAABAAAAAAAAAAVWaWRlbwAAAAAAAAEAAAPuAAAAIAAAAAEAAAAAAAAACU51bGxpZmllcgAAAAAAAAEAAAPuAAAAIAAAAAEAAAAAAAAADkNyZWRlbnRpYWxSb290AAAAAAABAAAD7gAAACAAAAABAAAAAAAAABBDcmVkZW50aWFsUm9vdFYyAAAAAQAAA+4AAAAgAAAAAAAAADRTZXF1ZW50aWFsIGNvdW50ZXIgZm9yIGNyZWRlbnRpYWwgcm9vdCBpbmRleCAoIzczMSkuAAAAEUNyZWRlbnRpYWxSb290U2VxAAAAAAAAAQAAAD5DcmVkZW50aWFsIHJvb3QgaW5kZXggZW50cnkgYnkgc2VxdWVudGlhbCBJRCAoMS1iYXNlZCkgKCM3MzEpLgAAAAAAE0NyZWRlbnRpYWxSb290SW5kZXgAAAAAAQAAAAQAAAABAAAAPFRyYWNraW5nIGluZGV4IHByZXNlbmNlIGJ5IHJvb3QgaGFzaCBmb3IgaWRlbXBvdGVuY3kgKCM3MzEpLgAAABVDcmVkZW50aWFsUm9vdEluZGV4ZWQAAAAAAAABAAAD7gAAACAAAAAAAAAAQ1N0YWdlZCBjcmVkZW50aWFsIHJvb3RzIGZvciBiYWNrZmlsbCBkdXJpbmcgdXBncmFkZV9zdG9yYWdlICgjNzMxKS4AAAAAHENyZWRlbnRpYWxSb290c0JhY2tmaWxsUXVldWUAAAAAAAAAMkN1cnNvciBmb3IgYmFja2ZpbGwgZHVyaW5nIHVwZ3JhZGVfc3RvcmFnZSAoIzczMSkuAAAAAAAdQ3JlZGVudGlhbFJvb3RzQmFja2ZpbGxDdXJzb3IAAAAAAAAAAAAALkFsaWFzIGZvciBiYWNrZmlsbCBxdWV1ZSBjb21wYXRpYmlsaXR5ICgjNzMxKS4AAAAAABdDcmVkZW50aWFsUm9vdHNCYWNrZmlsbAAAAAABAAAAAAAAAAZJc3N1ZXIAAAAAAAEAAAATAAAAAQAAAERSb3RhdGlvbiBncmFjZSByZWNvcmQgZm9yIGFuIGlzc3VlciBrZXkgdGhhdCBoYXMgcm90YXRlZCBvdXQgKCMzMjMpLgAAAA5Jc3N1ZXJSb3RhdGlvbgAAAAAAAQAAABMAAAAAAAAAAAAAAAhWZXJpZmllcgAAAAAAAAAAAAAACFByb29mVHRsAAAAAAAAAD1PcHRpb25hbCBlbWVyZ2VuY3ktcGF1c2UgZ3VhcmRpYW4sIGRpc3RpbmN0IGZyb20gYWRtaW4gKCM4NykuAAAAAAAACEd1YXJkaWFuAAAAAQAAADhQYXVzZSByZWNvcmQgZm9yIGEgc2luZ2xlIHJlZ2lzdHJhdGlvbiBkb21haW4gYml0ICgjODcpLgAAAAVQYXVzZQAAAAAAAAEAAAAEAAAAAAAAAAAAAAAMUGVuZGluZ0FkbWluAAAAAAAAAD1NZXJrbGUgcm9vdCBvZiB0aGUgY3JlZGVudGlhbC1yZXZvY2F0aW9uIHRyZWUgKHNldCBieSBhZG1pbikuAAAAAAAADlJldm9jYXRpb25Sb290AAAAAAAAAAAANkJvdW5kZWQgcmluZyBidWZmZXIgb2YgcmVjZW50IHJldm9jYXRpb24gcm9vdHMgKCM4ODApLgAAAAAAD1Jldm9jYXRpb25Sb290cwAAAAAAAAAAPUdyYWNlIHdpbmRvdyBpbiBsZWRnZXJzIGZvciBwcmV2aW91cyByZXZvY2F0aW9uIHJvb3RzICgjODgwKS4AAAAAAAAZUmV2b2NhdGlvblJvb3RHcmFjZVdpbmRvdwAAAAAAAAEAAAAAAAAAD1Byb29mSGlzdG9yeVNlcQAAAAABAAAD7gAAACAAAAABAAAAAAAAABFQcm9vZkhpc3RvcnlFbnRyeQAAAAAAAAIAAAPuAAAAIAAAAAQAAAABAAAAQFNjb3BlZCwgZXhwaXJpbmcgZGVsZWdhdGlvbiBmcm9tIGEgZ3JhbnRvciB0byBhIGRlbGVnYXRlICgjMTkyKS4AAAAKRGVsZWdhdGlvbgAAAAAAAgAAABMAAAATAAAAAQAAAD5Db3VudCBvZiBkaXN0aW5jdCBkZWxlZ2F0ZSBhZGRyZXNzZXMgaGVsZCBieSBhIGdyYW50b3IgKCMxOTIpLgAAAAAAD0RlbGVnYXRpb25Db3VudAAAAAABAAAAEwAAAAAAAAA1VmVyaWZpZXIgcm90YXRpb24gc3RhdGUgKHNjaGVkdWxlL2FjdGl2YXRlL3JvbGxiYWNrKS4AAAAAAAANVmVyaWZpZXJTdGF0ZQAAAAAAAAAAAAA/RGVjbGFyZWQgY2lyY3VpdC12ZXJzaW9uIHdpbmRvdyBmb3IgdGhlIGFjdGl2ZSB2ZXJpZmllciAoIzM0MykuAAAAABdWZXJpZmllckNpcmN1aXRWZXJzaW9ucwAAAAAAAAAAF1N0b3JhZ2Ugc2NoZW1hIHZlcnNpb24uAAAAAA1TY2hlbWFWZXJzaW9uAAAAAAAAAAAAADJIYXNoIG9mIHRoZSBjdXJyZW50IGFjdGl2ZSBjb250cmFjdCBXYXNtIGJ5dGVjb2RlLgAAAAAACFdhc21IYXNoAAAAAQAAACdTY29wZSBlcG9jaCBmb3IgdmVyaWZpZXItc2NvcGUgYmluZGluZy4AAAAAClNjb3BlRXBvY2gAAAAAAAEAAAPuAAAAIAAAAAAAAAAzU2VxdWVudGlhbCBjb3VudGVyIGZvciB0aW1lbG9jayBwcm9wb3NhbCBJRHMgKCM4NikuAAAAAAtQcm9wb3NhbFNlcQAAAAABAAAAKVRpbWVsb2NrIHByb3Bvc2FsIGJ5IHNlcXVlbnRpYWwgSUQgKCM4NikuAAAAAAAACFByb3Bvc2FsAAAAAQAAAAQAAAAAAAAAKE1pbmltdW0gdGltZWxvY2sgZGVsYXkgaW4gc2Vjb25kcyAoIzg2KS4AAAAQVGltZWxvY2tNaW5EZWxheQAAAAAAAAAqT3B0aW9uYWwgbXVsdGktcGFydHkgYWRtaW4gY291bmNpbCByZWNvcmQuAAAAAAAMQWRtaW5Db3VuY2lsAAAAAAAAACxTZXF1ZW50aWFsIGNvdW50ZXIgZm9yIGNvdW5jaWwgcHJvcG9zYWwgSURzLgAAABJDb3VuY2lsUHJvcG9zYWxTZXEAAAAAAAEAAAAiQ291bmNpbCBwcm9wb3NhbCBieSBzZXF1ZW50aWFsIElELgAAAAAAD0NvdW5jaWxQcm9wb3NhbAAAAAABAAAABAAAAAEAAAAhU2NoZW1hIGRlZmluaXRpb24gYnkgc2NoZW1hIGhhc2guAAAAAAAABlNjaGVtYQAAAAAAAQAAA+4AAAAgAAAAAQAAADxWZXJpZmlhYmxlIGRlcml2YXRpdmUgbGluZWFnZSByZWNvcmQga2V5ZWQgYnkgb3V0cHV0IGRpZ2VzdC4AAAAHTGluZWFnZQAAAAABAAAD7gAAACAAAAABAAAANk91dC1kZWdyZWUgYnVkZ2V0IGNvdW50ZXIgZm9yIGEgbGluZWFnZSBwYXJlbnQgKCMzMzMpLgAAAAAAEUxpbmVhZ2VDaGlsZENvdW50AAAAAAAAAQAAA+4AAAAgAAAAAQAAADVJbmRlcGVuZGVudCB0aW1lc3RhbXAgY2xhaW0ga2V5ZWQgYnkgcHJvb2ZfaWQgKCMzMzkpLgAAAAAAAA5UaW1lc3RhbXBDbGFpbQAAAAAAAQAAA+4AAAAgAAAAAQAAADtDb3VudCBvZiBpbmRleGVkIGNoaWxkcmVuIGZvciBhIHBhcmVudCBwcm9vZi9kaWdlc3QgKCMzMzUpLgAAAAAPTGluZWFnZUNoaWxkU2VxAAAAAAEAAAPuAAAAIAAAAAEAAAA8Q2hpbGQgb3V0cHV0IGRpZ2VzdCBhdCAxLWJhc2VkIHNlcXVlbmNlIGZvciBhIHBhcmVudCAoIzMzNSkuAAAADExpbmVhZ2VDaGlsZAAAAAIAAAPuAAAAIAAAAAQAAAABAAAAPVZlcnNpb25lZCBtZXRhZGF0YSBlbnZlbG9wZSBiaW5kaW5nIGtleWVkIGJ5IHByb29mX2lkICgjMzE3KS4AAAAAAAAQTWV0YWRhdGFFbnZlbG9wZQAAAAEAAAPuAAAAIAAAAAEAAAA9U3RvcmVzIHRoZSBgRGlzcHV0ZVJlY29yZGAgZm9yIGEgZ2l2ZW4gZGlzcHV0ZV9pZCAoI2Rpc3B1dGUpLgAAAAAAAAdEaXNwdXRlAAAAAAEAAAPuAAAAIAAAAAEAAABrQ291bnRzIG9wZW4gKG5vbi10ZXJtaW5hbCkgZGlzcHV0ZXMgZm9yIGEgcHJvb2ZfaWQgKCNkaXNwdXRlKS4KVXNlZCB0byBlbmZvcmNlIE1BWF9PUEVOX0RJU1BVVEVTX1BFUl9QUk9PRi4AAAAAFVByb29mT3BlbkRpc3B1dGVDb3VudAAAAAAAAAEAAAPuAAAAIAAAAAEAAAB9Q291bnRzIG9wZW4gKG5vbi10ZXJtaW5hbCkgZGlzcHV0ZXMgYWNyb3NzIGFsbCBwcm9vZnMgZm9yIGEgcmVwb3J0ZXIgQWRkcmVzcy4KVXNlZCB0byBlbmZvcmNlIE1BWF9PUEVOX0RJU1BVVEVTX1BFUl9SRVBPUlRFUi4AAAAAAAAYUmVwb3J0ZXJPcGVuRGlzcHV0ZUNvdW50AAAAAQAAABMAAAABAAAAg1RyYWNrcyB0aGUgbGFzdC1vcGVuZWQgdGltZXN0YW1wIGZvciBhIHJlcG9ydGVyX2hhc2gvcHJvb2YgcGFpci4KS2V5IGlzIHRoZSBjYWxsZXItc3VwcGxpZWQgYHJlcG9ydGVyX2hhc2hgIChhIDMyLWJ5dGUgY29tbWl0bWVudCkuAAAAABBSZXBvcnRlckNvb2xkb3duAAAAAQAAA+4AAAAgAAAAAQAAAD5TY29wZWQgbnVsbGlmaWVyIHNlcGFyYXRlZCBieSB2ZXJpZmllciBhZGRyZXNzIGNvbnRleHQgKCMzMjUpLgAAAAAAEVZlcmlmaWVyTnVsbGlmaWVyAAAAAAAAAgAAABMAAAPuAAAAIAAAAAEAAABEU2VxdWVudGlhbCBjb3VudGVyIGZvciBkaXNwdXRlcyBpbmRleGVkIHVuZGVyIGEgcHJvb2ZfaWQgKCNkaXNwdXRlKS4AAAAPUHJvb2ZEaXNwdXRlU2VxAAAAAAEAAAPuAAAAIAAAAAEAAAA5RGlzcHV0ZSBJRCBhdCAxLWJhc2VkIHNlcXVlbmNlIGZvciBhIHByb29mX2lkICgjZGlzcHV0ZSkuAAAAAAAADFByb29mRGlzcHV0ZQAAAAIAAAPuAAAAIAAAAAQAAAABAAAANVRpZXIgMiBzb3VyY2UgYmF0Y2ggcm9vdCByZWNvcmQga2V5ZWQgYnkgTWVya2xlIHJvb3QuAAAAAAAAC1NvdXJjZUJhdGNoAAAAAAEAAAPuAAAAIAAAAAEAAABBQWRtaW4tbWFuYWdlZCByZWdpc3RyYXRpb24gcXVvdGEgZm9yIGFuIGlzc3Vlci9zb3VyY2Uga2V5ICgjODA2KS4AAAAAAAALSXNzdWVyUXVvdGEAAAAAAQAAABMAAAABAAAANldpbmRvd2VkIHVzYWdlIHJlY29yZCBmb3IgYW4gaXNzdWVyL3NvdXJjZSBrZXkgKCM4MDYpLgAAAAAAEElzc3VlclF1b3RhVXNhZ2UAAAABAAAAEwAAAAEAAAAyUmVjZWlwdC1zaWduaW5nIHB1YmxpYyBrZXkgYWxsb3dsaXN0IGVudHJ5ICgjMzM3KS4AAAAAAA1SZWNlaXB0U2lnbmVyAAAAAAAAAQAAA+4AAABBAAAAAAAAADZDb3VudCBvZiBjdXJyZW50bHkgYWN0aXZlIHJlY2VpcHQtc2lnbmluZyBrZXlzICgjMzM3KS4AAAAAABJSZWNlaXB0U2lnbmVyQ291bnQAAAAAAAEAAAA9SW1tdXRhYmxlIGNvbW1pdG1lbnQgdG8gYSBzaWduZWQgdmVyaWZpY2F0aW9uIHJlY2VpcHQgKCMzMzcpLgAAAAAAABFSZWNlaXB0Q29tbWl0bWVudAAAAAAAAAEAAAPuAAAAIAAAAAAAAAA2U2VxdWVudGlhbCBjb3VudGVyIGZvciB0aHJlc2hvbGQgc2VhbCBwb2xpY2llcyAoIzEyNCkuAAAAAAANU2VhbFBvbGljeVNlcQAAAAAAAAAAAAAsQWN0aXZlIHRocmVzaG9sZCBzZWFsIHBvbGljeSB2ZXJzaW9uICgjMTI0KS4AAAAXQWN0aXZlU2VhbFBvbGljeVZlcnNpb24AAAAAAQAAAC9UaHJlc2hvbGQgc2VhbCBwb2xpY3kgcmVjb3JkIGJ5IHZlcnNpb24gKCMxMjQpLgAAAAAKU2VhbFBvbGljeQAAAAAAAQAAAAQAAAABAAAAMEFwcHJvdmFsIHJlY29yZCBmb3IgYChwcm9vZl9pZCwgc2lnbmVyKWAgKCMxMjQpLgAAAAxTZWFsQXBwcm92YWwAAAACAAAD7gAAACAAAAATAAAAAQAAADJGaW5hbGl6ZWQgdGhyZXNob2xkIHNpZ25lciBzZXQgZm9yIGEgcHJvb2YgKCMxMjQpLgAAAAAAC1NlYWxTaWduZXJzAAAAAAEAAAPuAAAAIAAAAAEAAABJVHJhY2tzIHdoZXRoZXIgZXhwbGljaXQgYGZpbmFsaXplX3NlYWxgIGhhcyBjb21wbGV0ZWQgZm9yIGEgcHJvb2YgKCMxMjQpLgAAAAAAABVTZWFsRXhwbGljaXRGaW5hbGl6ZWQAAAAAAAABAAAD7gAAACAAAAAAAAAAO0JvdW5kIHJvbGUtY2hhbmdlIGludGVudCBkaWdlc3QgZm9yIGBQZW5kaW5nQWRtaW5gICgjMTE4NCkuAAAAABFBZG1pbkludGVudERpZ2VzdAAAAAAAAAAAAABJYChwcm9wb3NlciwgY3JlYXRlZF9hdClgIG1ldGFkYXRhIGJvdW5kIGludG8gYEFkbWluSW50ZW50RGlnZXN0YCAoIzExODQpLgAAAAAAAA9BZG1pbkludGVudE1ldGEAAAAAAQAAAERCb3VuZCByb2xlLWNoYW5nZSBpbnRlbnQgZGlnZXN0IGZvciBgUHJvcG9zYWwocHJvcG9zYWxfaWQpYCAoIzExODQpLgAAABRUaW1lbG9ja0ludGVudERpZ2VzdAAAAAEAAAAEAAAAAQAAAEtCb3VuZCByb2xlLWNoYW5nZSBpbnRlbnQgZGlnZXN0IGZvciBgQ291bmNpbFByb3Bvc2FsKHByb3Bvc2FsX2lkKWAgKCMxMTg0KS4AAAAAE0NvdW5jaWxJbnRlbnREaWdlc3QAAAAAAQAAAAQ=",
        "AAAAAQAAAAAAAAAAAAAAClNlYWxQb2xpY3kAAAAAAAgAAAAAAAAADGFwcHJvdmFsX3R0bAAAAAYAAAAAAAAACmNyZWF0ZWRfYXQAAAAAAAYAAAAAAAAACmV4cGlyZXNfYXQAAAAAAAYAAAAAAAAAC21heF9zaWduZXJzAAAAAAQAAAAAAAAAEnJlcXVpcmVkX2FwcHJvdmFscwAAAAAABAAAAAAAAAAHc2lnbmVycwAAAAPqAAAAEwAAAAAAAAAGc3RhdHVzAAAAAAAEAAAAAAAAAAd2ZXJzaW9uAAAAAAQ=",
        "AAAAAQAAACBUaWVyIDIgc291cmNlIGJhdGNoIHJvb3QgcmVjb3JkLgAAAAAAAAALQmF0Y2hSZWNvcmQAAAAABQAAAAAAAAAFY291bnQAAAAAAAAEAAAAAAAAAApjcmVhdGVkX2F0AAAAAAAGAAAAAAAAAA1tZXRhZGF0YV9oYXNoAAAAAAAD7gAAACAAAAAAAAAABHJvb3QAAAPuAAAAIAAAAAAAAAAGc291cmNlAAAAAAAT",
        "AAAAAQAAAQxQYXVzZSByZWNvcmQgZm9yIGEgc2luZ2xlIHJlZ2lzdHJhdGlvbiBkb21haW4gYml0LiBQcmVzZW5jZSBvZiBhIHJlY29yZApkb2VzIG5vdCBieSBpdHNlbGYgbWVhbiAicGF1c2VkIiDigJQgc2VlIGBkb21haW5faXNfcGF1c2VkYCwgd2hpY2ggYWxzbwpjaGVja3MgYGV4cGlyZXNfYXRgIGFnYWluc3QgdGhlIGN1cnJlbnQgbGVkZ2VyIHRpbWUgc28gcGF1c2VzIGV4cGlyZSBvbgp0aGVpciBvd24gd2l0aG91dCByZXF1aXJpbmcgYSBmb2xsb3ctdXAgdHJhbnNhY3Rpb24uAAAAAAAAAAtQYXVzZVJlY29yZAAAAAADAAAAAAAAAApleHBpcmVzX2F0AAAAAAAGAAAAAAAAAAlwYXVzZWRfYXQAAAAAAAAGAAAAAAAAAAlwYXVzZWRfYnkAAAAAAAAT",
        "AAAAAQAAAAAAAAAAAAAAC1Byb29mUmVjb3JkAAAAAAoAAABsT3B0aW9uYWwgYmF0Y2ggc2l6ZSB3aGVuIHRoaXMgcHJvb2Ygd2FzIHJlZ2lzdGVyZWQgYXMgcGFydCBvZiBhbgphZ2dyZWdhdGVkIGJhdGNoICgwID0gbm90IHBhcnQgb2YgYSBiYXRjaCkuAAAACmJhdGNoX3NpemUAAAAAAAQAAAAAAAAACmNyZWF0ZWRfYXQAAAAAAAYAAAAAAAAACmV4cGlyZXNfYXQAAAAAAAYAAAAAAAAABmlzc3VlcgAAAAAD6AAAABMAAAAAAAAADW1ldGFkYXRhX2hhc2gAAAAAAAPuAAAAIAAAAAAAAAAJbnVsbGlmaWVyAAAAAAAD6AAAA+4AAAAgAAAAAAAAAAZzb3VyY2UAAAAAA+gAAAATAAAAAAAAAAZzdGF0dXMAAAAAAAQAAAAAAAAABHRpZXIAAAAEAAAAAAAAAAp2aWRlb19oYXNoAAAAAAPuAAAAIA==",
        "AAAABQAAAAAAAAAAAAAAC0d1YXJkaWFuU2V0AAAAAAIAAAAIZ3VhcmRpYW4AAAADc2V0AAAAAAEAAAAAAAAACGd1YXJkaWFuAAAAEwAAAAEAAAAC",
        "AAAABQAAAAAAAAAAAAAAC0lzc3VlckFkZGVkAAAAAAIAAAAGaXNzdWVyAAAAAAADYWRkAAAAAAIAAAAAAAAABmlzc3VlcgAAAAAAEwAAAAEAAAAAAAAADW1ldGFkYXRhX2hhc2gAAAAAAAPuAAAAIAAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAAC1NjaGVtYUFkZGVkAAAAAAIAAAAGc2NoZW1hAAAAAAADYWRkAAAAAAQAAAAAAAAAC3NjaGVtYV9oYXNoAAAAA+4AAAAgAAAAAQAAAAAAAAAQaXNzdWVyX25hbWVzcGFjZQAAA+4AAAAgAAAAAAAAAAAAAAAHdmVyc2lvbgAAAAAEAAAAAAAAAAAAAAAPYXR0cmlidXRlX2NvdW50AAAAAAQAAAAAAAAAAg==",
        "AAAABQAAAAAAAAAAAAAAC1ZlcmlmaWVyU2V0AAAAAAIAAAAFdmVyaWYAAAAAAAADc2V0AAAAAAEAAAAAAAAACHZlcmlmaWVyAAAAEwAAAAEAAAAC",
        "AAAAAQAAAAAAAAAAAAAADEFkbWluQ291bmNpbAAAAAQAAAAAAAAACmNyZWF0ZWRfYXQAAAAAAAYAAAAAAAAADGVmZmVjdGl2ZV9hdAAAAAYAAAAAAAAAB21lbWJlcnMAAAAD6gAAABMAAAAAAAAACXRocmVzaG9sZAAAAAAAAAQ=",
        "AAAAAQAAAAAAAAAAAAAADElzc3VlclJlY29yZAAAAAIAAAAAAAAABmFjdGl2ZQAAAAAAAQAAAAAAAAANbWV0YWRhdGFfaGFzaAAAAAAAA+4AAAAg",
        "AAAAAQAAADVTY2hlbWEgcmVjb3JkIGZvciBpc3N1ZXItY2VydGlmaWVkIGF0dHJpYnV0ZSBzY2hlbWFzLgAAAAAAAAAAAAAMU2NoZW1hUmVjb3JkAAAABgAAAAAAAAAGYWN0aXZlAAAAAAABAAAAAAAAAA9hdHRyaWJ1dGVfY291bnQAAAAABAAAAAAAAAAKY3JlYXRlZF9hdAAAAAAABgAAAAAAAAAQaXNzdWVyX25hbWVzcGFjZQAAA+4AAAAgAAAAAAAAAAtzY2hlbWFfaGFzaAAAAAPuAAAAIAAAAAAAAAAHdmVyc2lvbgAAAAAE",
        "AAAAAQAAAAAAAAAAAAAADFNlYWxBcHByb3ZhbAAAAAcAAAAAAAAAC2FwcHJvdmVkX2F0AAAAAAYAAAAAAAAACmV4cGlyZXNfYXQAAAAAAAYAAAAAAAAADW1ldGFkYXRhX2hhc2gAAAAAAAPuAAAAIAAAAAAAAAAOcG9saWN5X3ZlcnNpb24AAAAAAAQAAAAAAAAACHByb29mX2lkAAAD7gAAACAAAAAAAAAABnNpZ25lcgAAAAAAEwAAAAAAAAAKdmlkZW9faGFzaAAAAAAD7gAAACA=",
        "AAAAAQAAAe5QYWdpbmF0ZWQgcmVzdWx0IGZyb20gYGxpc3RfdmVyaWZpZXJzYC4KCmBlbnRyaWVzYCBjb250YWlucyB1cCB0byBgbGltaXRgIGBWZXJpZmllckVudHJ5YCBpdGVtcyBpbiBzbG90IG9yZGVyCihBY3RpdmUg4oaSIFBlbmRpbmcg4oaSIFByZXZpb3VzKS4gT25seSBub24tTm9uZSBzbG90cyBhcmUgaW5jbHVkZWQuCgpgbmV4dF9jdXJzb3JgIGlzIGBTb21lKG9mZnNldClgIHdoZW4gbW9yZSBpdGVtcyBleGlzdCBiZXlvbmQgdGhpcyBwYWdlLApvciBgTm9uZWAgd2hlbiB0aGUgcGFnZSBpcyB0aGUgbGFzdCAob3Igb25seSkgcGFnZS4gUGFzcyBgbmV4dF9jdXJzb3JgCmFzIHRoZSBgY3Vyc29yYCBhcmd1bWVudCBpbiB0aGUgc3Vic2VxdWVudCBjYWxsLgoKYHRvdGFsX3BvcHVsYXRlZGAgaXMgdGhlIHRvdGFsIGNvdW50IG9mIHBvcHVsYXRlZCAobm9uLU5vbmUpIHZlcmlmaWVyCnNsb3RzIGF0IHRoZSB0aW1lIG9mIHRoZSBxdWVyeS4gSXQgaXMgYWx3YXlzIOKJpCAzLgAAAAAAAAAAAAxWZXJpZmllclBhZ2UAAAADAAAAAAAAAAdlbnRyaWVzAAAAA+oAAAfQAAAADVZlcmlmaWVyRW50cnkAAAAAAAAAAAAAC25leHRfY3Vyc29yAAAAA+gAAAAEAAAAAAAAAA90b3RhbF9wb3B1bGF0ZWQAAAAABA==",
        "AAAAAwAAAD1UaGUgcm9sZSBvZiBhIHZlcmlmaWVyIGFkZHJlc3MgaW4gdGhlIGN1cnJlbnQgcm90YXRpb24gc3RhdGUuAAAAAAAAAAAAAAxWZXJpZmllclJvbGUAAAADAAAAAAAAAAZBY3RpdmUAAAAAAAEAAAAAAAAAB1BlbmRpbmcAAAAAAgAAAAAAAAAIUHJldmlvdXMAAAAD",
        "AAAABQAAAAAAAAAAAAAADERvbWFpblBhdXNlZAAAAAIAAAAFcGF1c2UAAAAAAAADc2V0AAAAAAQAAAAAAAAABmRvbWFpbgAAAAAABAAAAAEAAAAAAAAACXBhdXNlZF9ieQAAAAAAABMAAAAAAAAAAAAAAAlwYXVzZWRfYXQAAAAAAAAGAAAAAAAAAAAAAAAKZXhwaXJlc19hdAAAAAAABgAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAADFByb29mUmV2b2tlZAAAAAIAAAAFcHJvb2YAAAAAAAAGcmV2b2tlAAAAAAACAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAQAAAAAAAAAGc3RhdHVzAAAAAAAEAAAAAAAAAAI=",
        "AAAAAwAAAFFDYXRlZ29yaXNlZCBkaXNwdXRlIHJlYXNvbnMuIE51bWVyaWMgdmFsdWVzIGFyZSBzdGFibGUgb24tY2hhaW47IGRvIG5vdApyZW51bWJlci4AAAAAAAAAAAAADURpc3B1dGVSZWFzb24AAAAAAAAGAAAAAAAAAAxDb250ZW50RXJyb3IAAAABAAAAAAAAAA1NZXRhZGF0YUVycm9yAAAAAAAAAgAAAAAAAAAMVGllck1pc21hdGNoAAAAAwAAAAAAAAAQQ3JlZGVudGlhbExhcHNlZAAAAAQAAAAAAAAAEFByaXZhY3lWaW9sYXRpb24AAAAFAAAAAAAAAAVPdGhlcgAAAAAAAAY=",
        "AAAAAQAAAL5JbW11dGFibGUgZGlzcHV0ZSByZWNvcmQuIE9ubHkgYHN0YXR1c2AsIGByZXNwb25zZV9jb21taXRtZW50YCwKYHJlc29sdmVfZGVhZGxpbmVgLCBgcmVzb2x2ZWRfYXRgLCBhbmQgYHN1cGVyc2VkZWRfYnlgIGFyZSBtdXRhdGVkIGFmdGVyCmluaXRpYWwgY3JlYXRpb247IHRoZSByZXN0IGFyZSBzZXQgb25jZSBhdCBvcGVuIHRpbWUuAAAAAAAAAAAADURpc3B1dGVSZWNvcmQAAAAAAAANAAAAQE9mZi1jaGFpbiBjb21taXRtZW50IHRvIHRoZSByZXBvcnRlcidzIGZ1bGwgZXZpZGVuY2Ugc3VibWlzc2lvbi4AAAAPY29tbWl0bWVudF9oYXNoAAAAA+4AAAAgAAAAR1VuaXF1ZSBkaXNwdXRlIGlkZW50aWZpZXIgKGNhbGxlci1zdXBwbGllZCwgMzItYnl0ZSBvcGFxdWUgY29tbWl0bWVudCkuAAAAAApkaXNwdXRlX2lkAAAAAAPuAAAAIAAAAC1MZWRnZXIgdGltZXN0YW1wIHdoZW4gdGhlIGRpc3B1dGUgd2FzIG9wZW5lZC4AAAAAAAAJb3BlbmVkX2F0AAAAAAAABgAAACJUaGUgcHJvb2YgdGhpcyBkaXNwdXRlIGNoYWxsZW5nZXMuAAAAAAAIcHJvb2ZfaWQAAAPuAAAAIAAAACNDYXRlZ29yaXNlZCByZWFzb24gZm9yIHRoZSBkaXNwdXRlLgAAAAAGcmVhc29uAAAAAAfQAAAADURpc3B1dGVSZWFzb24AAAAAAAAwQWRkcmVzcyBvZiB0aGUgcmVwb3J0ZXIgd2hvIG9wZW5lZCB0aGlzIGRpc3B1dGUuAAAACHJlcG9ydGVyAAAAEwAAAHxQcml2YWN5LXNhZmUgY29tbWl0bWVudDogSChyZXBvcnRlcl9hZGRyZXNzX2J5dGVzIHx8IHByb29mX2lkX2J5dGVzKS4KVXNlZCBmb3IgdGhlIHBlci1wcm9vZiBjb29sZG93biBhbmQgZW1pdHRlZCBpbiBldmVudHMuAAAADXJlcG9ydGVyX2hhc2gAAAAAAAPuAAAAIAAAAGlMZWRnZXIgdGltZXN0YW1wIGJ5IHdoaWNoIHRoZSBhZG1pbiBtdXN0IGRlY2lkZSBhZnRlciBhIHJlc3BvbnNlLgpTZXQgdG8gMCB1bnRpbCBhIHJlc3BvbnNlIGlzIHN1Ym1pdHRlZC4AAAAAAAAQcmVzb2x2ZV9kZWFkbGluZQAAAAYAAAA9TGVkZ2VyIHRpbWVzdGFtcCBvZiBmaW5hbCByZXNvbHV0aW9uL2Rpc21pc3NhbC4gMCB3aGlsZSBvcGVuLgAAAAAAAAtyZXNvbHZlZF9hdAAAAAAGAAAAOUxlZGdlciB0aW1lc3RhbXAgYnkgd2hpY2ggdGhlIGlzc3Vlci9zb3VyY2UgbXVzdCByZXNwb25kLgAAAAAAABByZXNwb25kX2RlYWRsaW5lAAAABgAAAEBJc3N1ZXIvc291cmNlIGNvbW1pdG1lbnQgaGFzaCBpbiByZXNwb25zZS4gTm9uZSB1bnRpbCBSZXNwb25kZWQuAAAAE3Jlc3BvbnNlX2NvbW1pdG1lbnQAAAAD6AAAA+4AAAAgAAAAGEN1cnJlbnQgbGlmZWN5Y2xlIHN0YXRlLgAAAAZzdGF0dXMAAAAAB9AAAAANRGlzcHV0ZVN0YXR1cwAAAAAAADtQcm9vZiBJRCB0aGF0IHN1cGVyc2VkZXMgdGhlIGRpc3B1dGVkIHByb29mLCBpZiBTdXBlcnNlZGVkLgAAAAANc3VwZXJzZWRlZF9ieQAAAAAAA+gAAAPuAAAAIA==",
        "AAAAAwAAAG1EaXNwdXRlIHN0YXRlIHRyYW5zaXRpb25zLiBOdW1lcmljIHZhbHVlcyBhcmUgc3RhYmxlIG9uLWNoYWluIGlkZW50aWZpZXJzOwpkbyBub3QgcmVudW1iZXIgZXhpc3RpbmcgdmFyaWFudHMuAAAAAAAAAAAAAA1EaXNwdXRlU3RhdHVzAAAAAAAABQAAAAAAAAAET3BlbgAAAAEAAAAAAAAACVJlc3BvbmRlZAAAAAAAAAIAAAAAAAAACFJlc29sdmVkAAAAAwAAAAAAAAAJRGlzbWlzc2VkAAAAAAAABAAAAAAAAAAKU3VwZXJzZWRlZAAAAAAABQ==",
        "AAAAAQAAAudPbi1jaGFpbiBsaW5lYWdlIGVkZ2UgZm9yIGEgdmVyaWZpYWJsZSBkZXJpdmF0aXZlLgoKYHBhcmVudF9wcm9vZl9pZHNgIHJldGFpbiBncmFwaCB0b3BvbG9neSBmb3IgY3ljbGUvZGVwdGggY2hlY2tzLgpgcGFyZW50X2NvbW1pdG1lbnRzYCBzdG9yZSBkb21haW4tc2VwYXJhdGVkIGNvbnRlbnQgYmluZGluZ3MgZm9yIGVhY2gKcGFyZW50IHNvIHB1YmxpYyBib3VuZGFyaWVzIChldmVudHMgLyBpbnRlcm9wKSBjYW4gY2l0ZSBwYXJlbnRzIHdpdGhvdXQKcmVseWluZyBvbiByYXcgcHJvb2YgaWRlbnRpZmllcnMgYWxvbmUuIERlcml2ZWQgYXMKYFNIQS0yNTYoImhhcnBfbGluX3BjIiB8fCBiaW5kaW5nX2EgfHwgYmluZGluZ19iKWAgd2hlcmUgYSBwcm9vZiBwYXJlbnQKYmluZHMgYCh2aWRlb19oYXNoLCBtZXRhZGF0YV9oYXNoKWAgYW5kIGEgbGluZWFnZSBwYXJlbnQgYmluZHMKYChtYW5pZmVzdF9kaWdlc3QsIG91dHB1dF9kaWdlc3QpYC4KCk1pZ3JhdGlvbjogYWRkaXRpdmUgZmllbGQgb24gbmV3IHJlZ2lzdHJhdGlvbnMuIFByZS1leGlzdGluZyBsaW5lYWdlCnJvd3MgKGlmIGFueSkgbGFjayBjb21taXRtZW50cyBhbmQgbXVzdCBiZSByZS1yZWdpc3RlcmVkIGFmdGVyIHVwZ3JhZGU7CnJvbGxpbmcgYmFjayB0byBhIHByZS0jMzMyIHdhc20gaWdub3JlcyB0aGUgbmV3IGV2ZW50IC8gZ2V0dGVyIGFuZCBsZWF2ZXMKc3RvcmVkIHJlY29yZHMgcmVhZGFibGUgb25seSBieSBtYXRjaGluZyB3YXNtLgAAAAAAAAAADUxpbmVhZ2VSZWNvcmQAAAAAAAAHAAAAAAAAAAVhY3RvcgAAAAAAABMAAAAAAAAABWRlcHRoAAAAAAAABAAAAAAAAAAPbWFuaWZlc3RfZGlnZXN0AAAAA+4AAAAgAAAAAAAAAA5vcGVyYXRpb25fdHlwZQAAAAAAEQAAAAAAAAANb3V0cHV0X2RpZ2VzdAAAAAAAA+4AAAAgAAAAAAAAABJwYXJlbnRfY29tbWl0bWVudHMAAAAAA+oAAAPuAAAAIAAAAAAAAAAQcGFyZW50X3Byb29mX2lkcwAAA+oAAAPuAAAAIA==",
        "AAAABAAAAAAAAAAAAAAADVJlZ2lzdHJ5RXJyb3IAAAAAAABxAAAAAAAAABJBbHJlYWR5SW5pdGlhbGl6ZWQAAAAAAAEAAAAAAAAADk5vdEluaXRpYWxpemVkAAAAAAACAAAAAAAAAAxVbmF1dGhvcml6ZWQAAAADAAAAAAAAAA5EdXBsaWNhdGVQcm9vZgAAAAAABAAAAAAAAAAORHVwbGljYXRlVmlkZW8AAAAAAAUAAAAAAAAAEkR1cGxpY2F0ZU51bGxpZmllcgAAAAAABgAAAAAAAAAMSW52YWxpZFByb29mAAAABwAAAAAAAAANVW5rbm93bklzc3VlcgAAAAAAAAgAAAAAAAAADlZlcmlmaWVyTm90U2V0AAAAAAAJAAAAAAAAABNJbnZhbGlkUHVibGljSW5wdXRzAAAAAAoAAAAAAAAAFVVua25vd25DcmVkZW50aWFsUm9vdAAAAAAAAAsAAAAAAAAAFVJldm9rZWRDcmVkZW50aWFsUm9vdAAAAAAAAAwAAAAAAAAAEEhpc3RvcnlTYXR1cmF0ZWQAAAANAAAAAAAAABRJbnZhbGlkSGlzdG9yeUFjdGlvbgAAAA4AAAAAAAAAEUludmFsaWRSZWFzb25Db2RlAAAAAAAADwAAAAAAAAAUSGlzdG9yeUxpbWl0RXhjZWVkZWQAAAAQAAAAAAAAAA5BbHJlYWR5RXhwaXJlZAAAAAAAEQAAAAAAAAASTm9Db3JyZWN0aW9uQ2hhbmdlAAAAAAASAAAAAAAAABFIaXN0b3J5Q29ycnVwdGlvbgAAAAAAABMAAAAAAAAADk5vUGVuZGluZ0FkbWluAAAAAAAUAAAAQ1RoZSByZXF1ZXN0ZWQgb3BlcmF0aW9uIGlzIGJsb2NrZWQgYnkgYW4gYWN0aXZlIGRvbWFpbiBwYXVzZSAoIzg3KS4AAAAABlBhdXNlZAAAAAAAFQAAAERgZG9tYWluYCB3YXMgemVybyBvciBjb250YWluZWQgYml0cyBvdXRzaWRlIHRoZSBrbm93biBwYXVzZSBkb21haW5zLgAAABJJbnZhbGlkUGF1c2VEb21haW4AAAAAABYAAAA7YGR1cmF0aW9uX3NlY3NgIHdhcyB6ZXJvIG9yIGV4Y2VlZGVkIHRoZSBjYWxsZXIncyByb2xlIGNhcC4AAAAAFEludmFsaWRQYXVzZUR1cmF0aW9uAAAAFwAAAElgc2NvcGVgIHdhcyB6ZXJvIG9yIGNvbnRhaW5lZCBiaXRzIG91dHNpZGUgYERFTEVHQVRJT05fU0NPUEVfQUxMYCAoIzE5MikuAAAAAAAAFkludmFsaWREZWxlZ2F0aW9uU2NvcGUAAAAAABgAAABIYGR1cmF0aW9uX3NlY3NgIHdhcyB6ZXJvIG9yIGFib3ZlIGBNQVhfREVMRUdBVElPTl9EVVJBVElPTl9TRUNTYCAoIzE5MikuAAAAGUludmFsaWREZWxlZ2F0aW9uRHVyYXRpb24AAAAAAAAZAAAAQU5vIGRlbGVnYXRpb24gZXhpc3RzIGZyb20gdGhlIG5hbWVkIGdyYW50b3IgdG8gdGhlIGNhbGxlciAoIzE5MikuAAAAAAAAEkRlbGVnYXRpb25Ob3RGb3VuZAAAAAAAGgAAAD1UaGUgZGVsZWdhdGlvbiBleGlzdHMgYnV0IGl0cyBgZXhwaXJlc19hdGAgaGFzIHBhc3NlZCAoIzE5MikuAAAAAAAAEURlbGVnYXRpb25FeHBpcmVkAAAAAAAAGwAAAGhUaGUgZGVsZWdhdGlvbiBleGlzdHMgYW5kIGlzIGxpdmUsIGJ1dCBkb2VzIG5vdCBjYXJyeSB0aGUgc2NvcGUgdGhlCmF0dGVtcHRlZCBvcGVyYXRpb24gcmVxdWlyZXMgKCMxOTIpLgAAABdEZWxlZ2F0aW9uU2NvcGVFeGNlZWRlZAAAAAAcAAAASVRoZSBncmFudG9yIGFscmVhZHkgaG9sZHMgYE1BWF9ERUxFR0FUSU9OU19QRVJfR1JBTlRPUmAgZGVsZWdhdGVzICgjMTkyKS4AAAAAAAAURGVsZWdhdGlvbnNTYXR1cmF0ZWQAAAAdAAAALEEgZ3JhbnRvciBtYXkgbm90IGRlbGVnYXRlIHRvIGl0c2VsZiAoIzE5MikuAAAADlNlbGZEZWxlZ2F0aW9uAAAAAAAeAAAANVRoZSByZXF1ZXN0ZWQgdGltZWxvY2sgcHJvcG9zYWwgZG9lcyBub3QgZXhpc3QgKCM4NikuAAAAAAAAEFByb3Bvc2FsTm90Rm91bmQAAAAfAAAAAAAAABBQcm9wb3NhbE5vdFJlYWR5AAAAIAAAAAAAAAAXUHJvcG9zYWxBbHJlYWR5RXhlY3V0ZWQAAAAAIQAAAAAAAAARUHJvcG9zYWxDYW5jZWxsZWQAAAAAAAAiAAAAAAAAABVJbnZhbGlkUHJvcG9zYWxBY3Rpb24AAAAAAAAjAAAAAAAAABZJbnZhbGlkUHJvcG9zYWxQYXlsb2FkAAAAAAAkAAAAAAAAABJQcm9wb3NhbHNTYXR1cmF0ZWQAAAAAACUAAAAAAAAAFEludmFsaWRUaW1lbG9ja0RlbGF5AAAAJgAAAAAAAAAQQWxyZWFkeUNhbmNlbGxlZAAAACcAAAAAAAAAFFJvdGF0aW9uTm90U2NoZWR1bGVkAAAAKAAAAAAAAAAQUm90YXRpb25Ob3RSZWFkeQAAACkAAAAAAAAAFFJvdGF0aW9uV2luZG93Q2xvc2VkAAAAKgAAAAAAAAANQmF0Y2hUb29MYXJnZQAAAAAAACsAAAAAAAAAEUludmFsaWRTY29wZUVwb2NoAAAAAAAALAAAAAAAAAAPRGlzcHV0ZU5vdEZvdW5kAAAAAC0AAAAAAAAAFkRpc3B1dGVBbHJlYWR5UmVzb2x2ZWQAAAAAAC4AAAAAAAAAGVN1cGVyc2Vzc2lvbkN5Y2xlRGV0ZWN0ZWQAAAAAAAAvAAAAAAAAABRTdXBlcnNlc3Npb25Ob3RGb3VuZAAAADAAAAAAAAAAEURvbWFpblRhZ01pc21hdGNoAAAAAAAAMQAAAAAAAAANVW5rbm93blNjaGVtYQAAAAAAADIAAAAAAAAADkluYWN0aXZlU2NoZW1hAAAAAAAzAAAAAAAAABVTY2hlbWFWZXJzaW9uTWlzbWF0Y2gAAAAAAAA0AAAAP0Egc2NvcGVkLW51bGxpZmllciBwcm9vZiB3YXMgZ2VuZXJhdGVkIGZvciBhIHN0YWxlIHNjb3BlIGVwb2NoLgAAAAAKU3RhbGVFcG9jaAAAAAAANQAAAD9CYXRjaCBhZ2dyZWdhdGlvbiB3YXMgcmVxdWVzdGVkIHdpdGggemVybyBvciB0b28gbWFueSBlbGVtZW50cy4AAAAAEUJhdGNoU2l6ZUV4Y2VlZGVkAAAAAAAANgAAADNDcmVkZW50aWFsIHJvb3RzIGluIGEgYmF0Y2ggd2VyZSBub3QgYWxsIGlkZW50aWNhbC4AAAAAG0JhdGNoQ3JlZGVudGlhbFJvb3RNaXNtYXRjaAAAAAA3AAAAQ1RoZSBiYXRjaCBlbGVtZW50IGNvdW50IGRpZCBub3QgbWF0Y2ggdGhlIHN1cHBsaWVkIHZpZGVvLWhhc2ggbGlzdC4AAAAAEkJhdGNoQ291bnRNaXNtYXRjaAAAAAAAOAAAAEBBIGxpbmVhZ2UgcGFyZW50IHByb29mL2xpbmVhZ2UgcmVjb3JkIHdhcyBub3QgZm91bmQgb3IgcmVwZWF0ZWQuAAAADkludmFsaWRMaW5lYWdlAAAAAAA5AAAAJ0EgbGluZWFnZSBlZGdlIHdvdWxkIGludHJvZHVjZSBhIGN5Y2xlLgAAAAAMTGluZWFnZUN5Y2xlAAAAOgAAADhUaGUgcmVxdWVzdGVkIGxpbmVhZ2UgZGVwdGggZXhjZWVkcyBgTUFYX0xJTkVBR0VfREVQVEhgLgAAAA5MaW5lYWdlVG9vRGVlcAAAAAAAOwAAADtUaGUgcmVxdWVzdGVkIGxpbmVhZ2UgZmFuLW91dCBleGNlZWRzIGBNQVhfTElORUFHRV9GQU5PVVRgLgAAAAAVTGluZWFnZUZhbk91dEV4Y2VlZGVkAAAAAAAAPAAAAEJUaGUgcHJvb2YgYWxyZWFkeSBoYXMgYE1BWF9PUEVOX0RJU1BVVEVTX1BFUl9QUk9PRmAgb3BlbiBkaXNwdXRlcy4AAAAAABNUb29NYW55T3BlbkRpc3B1dGVzAAAAAD0AAABEVGhlIHJlc3BvbmQvcmVzb2x2ZSBkZWFkbGluZSBmb3IgdGhpcyBkaXNwdXRlIHRyYW5zaXRpb24gaGFzIHBhc3NlZC4AAAAURGlzcHV0ZVdpbmRvd0V4cGlyZWQAAAA+AAAAK1RoZSBkaXNwdXRlIGlzIGFscmVhZHkgaW4gYSB0ZXJtaW5hbCBzdGF0ZS4AAAAAFERpc3B1dGVBbHJlYWR5Q2xvc2VkAAAAPwAAADZTdXBlcnNlc3Npb24gd291bGQgY3JlYXRlIGEgY3ljbGUgKGRpcmVjdCBvciBkZXB0aC0xKS4AAAAAABlEaXNwdXRlQ3ljbGljU3VwZXJzZXNzaW9uAAAAAAAAQAAAAEJUaGUgY2FsbGVyIGlzIG5vdCB0aGUgcHJvb2YncyBpc3N1ZXIvc291cmNlIChvciBhZG1pbiBmb3IgVGllciAxKS4AAAAAABVVbmF1dGhvcml6ZWRSZXNwb25kZXIAAAAAAABBAAAASFRoZSByZXBvcnRlciBtdXN0IHdhaXQgb3V0IGBSRVBPUlRFUl9DT09MRE9XTl9TRUNTYCBiZWZvcmUgcmUtcmVwb3J0aW5nLgAAABJSZXBvcnRlck9uQ29vbGRvd24AAAAAAEIAAAA5VGhlIGRpc3B1dGUgaXMgbm90IGluIHRoZSBzdGF0ZSB0aGlzIHRyYW5zaXRpb24gcmVxdWlyZXMuAAAAAAAAGEludmFsaWREaXNwdXRlVHJhbnNpdGlvbgAAAEMAAABSTWV0YWRhdGEgZW52ZWxvcGUgdmVyc2lvbiBpcyB6ZXJvIG9yIGFib3ZlIGBNRVRBREFUQV9FTlZFTE9QRV9WRVJTSU9OX01BWGAgKCMzMTcpLgAAAAAAIlVuc3VwcG9ydGVkTWV0YWRhdGFFbnZlbG9wZVZlcnNpb24AAAAAAEQAAAAyTWV0YWRhdGEgZW52ZWxvcGUgaGFzaCBpcyB6ZXJvIC8gbWFsZm9ybWVkICgjMzE3KS4AAAAAABdJbnZhbGlkTWV0YWRhdGFFbnZlbG9wZQAAAABFAAAAQE5vIG1ldGFkYXRhIGVudmVsb3BlIChhbmQgbm8gcHJvb2YpIGZvciB0aGUgcmVxdWVzdGVkIGlkICgjMzE3KS4AAAAYTWV0YWRhdGFFbnZlbG9wZU5vdEZvdW5kAAAARgAAAEZCb3VuZCBlbnZlbG9wZSBoYXNoIGRvZXMgbm90IG1hdGNoIHRoZSBwcm9vZidzIGBtZXRhZGF0YV9oYXNoYCAoIzMxNykuAAAAAAAcTWV0YWRhdGFFbnZlbG9wZUhhc2hNaXNtYXRjaAAAAEcAAABMVGltZXN0YW1wIGNsYWltIGlzIG1hbGZvcm1lZCwgZmFyLWZ1dHVyZSwgb3IgbWlzc2luZyByZXF1aXJlZCBkaWdlc3QgKCMzMzkpLgAAABVJbnZhbGlkVGltZXN0YW1wQ2xhaW0AAAAAAABIAAAAOU5vIHRpbWVzdGFtcCBjbGFpbSBleGlzdHMgZm9yIHRoZSByZXF1ZXN0ZWQgcHJvb2YgKCMzMzkpLgAAAAAAABZUaW1lc3RhbXBDbGFpbU5vdEZvdW5kAAAAAABJAAAATkEgdGltZXN0YW1wIGNsYWltIGlzIGFscmVhZHkgYW5jaG9yZWQgYW5kIHRoZSB1cGRhdGUgaXMgbm90IGFuIHVwZ3JhZGUgKCMzMzkpLgAAAAAAHVRpbWVzdGFtcENsYWltQWxyZWFkeUFuY2hvcmVkAAAAAAAASgAAAD1DYWxsZXIgaXMgbmVpdGhlciBhZG1pbiBub3IgdGhlIHByb29mJ3Mgc291cmNlL2lzc3VlciAoIzMzOSkuAAAAAAAAGlVuYXV0aG9yaXplZFRpbWVzdGFtcEFjdG9yAAAAAABLAAAARkxpbmVhZ2UgcmVnaXN0cmF0aW9uIHN1cHBsaWVkIHplcm8gcGFyZW50cyAoY29tbWl0bWVudHMgcmVxdWlyZSDiiaUxKS4AAAAAABNMaW5lYWdlRW1wdHlQYXJlbnRzAAAAAEwAAABMQSBsaW5lYWdlIHBhcmVudCBwcm9vZiBpcyByZXZva2VkIG9yIGV4cGlyZWQgYW5kIGNhbm5vdCBhbmNob3IgYSBkZXJpdmF0aXZlLgAAABhMaW5lYWdlUGFyZW50VW5hdmFpbGFibGUAAABNAAAALExpbmVhZ2Ugb3V0cHV0IGRpZ2VzdCBpcyBhbHJlYWR5IHJlZ2lzdGVyZWQuAAAAEER1cGxpY2F0ZUxpbmVhZ2UAAABOAAAARGBsaXN0X2xpbmVhZ2VfY2hpbGRyZW5gIGxpbWl0IHdhcyB6ZXJvIG9yIGFib3ZlIHRoZSBwYWdlIGNhcCAoIzMzNSkuAAAAHExpbmVhZ2VDaGlsZHJlbkxpbWl0RXhjZWVkZWQAAABPAAAARVBhcmVudCBhbHJlYWR5IGhvbGRzIE1BWF9MSU5FQUdFX0NISUxEUkVOX1BFUl9QQVJFTlQgY2hpbGRyZW4gKCMzMzUpLgAAAAAAABhMaW5lYWdlQ2hpbGRyZW5TYXR1cmF0ZWQAAABQAAAATVByb29mIGRlY2xhcmVzIGEgY2lyY3VpdCB2ZXJzaW9uIG91dHNpZGUgdGhlIGFjdGl2ZSB2ZXJpZmllcidzIHdpbmRvdyAoIzM0MykuAAAAAAAAGVVuc3VwcG9ydGVkQ2lyY3VpdFZlcnNpb24AAAAAAABRAAAAS1JlcXVlc3RlZCBjaXJjdWl0LXZlcnNpb24gd2luZG93IGlzIGVtcHR5IG9yIG91dHNpZGUgdGhlIHdhc20gcmFuZ2UgKCMzNDMpLgAAAAAaSW52YWxpZENpcmN1aXRWZXJzaW9uUmFuZ2UAAAAAAFIAAABqUmVxdWVzdGVkIHJvdGF0aW9uIGdyYWNlIHdpbmRvdyBpcyBhYm92ZSBgTUFYX0lTU1VFUl9ST1RBVElPTl9HUkFDRV9TRUNTYApvciBvdmVyZmxvd3MgbGVkZ2VyIHRpbWUgKCMzMjMpLgAAAAAAGkludmFsaWRJc3N1ZXJSb3RhdGlvbkdyYWNlAAAAAABTAAAAakEgcm90YXRpb24gbmFtZWQgdGhlIHNhbWUgaXNzdWVyIGtleSB0d2ljZTsgYWJzZW50IG9yIGluYWN0aXZlIGtleXMKcmVwb3J0IGBVbmtub3duSXNzdWVyYCBpbnN0ZWFkICgjMzIzKS4AAAAAABVJbnZhbGlkSXNzdWVyUm90YXRpb24AAAAAAABUAAAARE5vIGlzc3VlciByb3RhdGlvbiBncmFjZSByZWNvcmQgZXhpc3RzIGZvciB0aGUgcmVxdWVzdGVkIGtleSAoIzMyMykuAAAAFklzc3VlclJvdGF0aW9uTm90Rm91bmQAAAAAAFUAAAA7VGhlIGlzc3VlciByb3RhdGlvbiBncmFjZSB3aW5kb3cgaGFzIG5vdCBsYXBzZWQgeWV0ICgjMzIzKS4AAAAAHklzc3VlclJvdGF0aW9uR3JhY2VTdGlsbEFjdGl2ZQAAAAAAVgAAANJBIHNjb3BlZC1udWxsaWZpZXIgZW52ZWxvcGUgY2FycmllZCBhIGBjaXJjdWl0X3ZlcnNpb25gIHRyYWlsZXIgb3RoZXIKdGhhbiBbYHZlcmlmaWVyX2lucHV0czo6RVhQRUNURURfQ0lSQ1VJVF9WRVJTSU9OYF0sIG9yIHdhcyB0aGUgc3VwZXJzZWRlZApiYXJlIDIyNC1ieXRlIGZyYW1lIHRoYXQgY29tbWl0cyBubyBjaXJjdWl0IHZlcnNpb24gYXQgYWxsICgjMzY4KS4AAAAAABZDaXJjdWl0VmVyc2lvbk1pc21hdGNoAAAAAABXAAAANlRoZSByZXBvcnRlciByZWFjaGVkIGBNQVhfT1BFTl9ESVNQVVRFU19QRVJfUkVQT1JURVJgLgAAAAAAGVJlcG9ydGVyRGlzcHV0ZXNTYXR1cmF0ZWQAAAAAAABYAAAANlRoZSBhY3Rpb24gcmVxdWlyZXMgYWRtaW4gY291bmNpbCB0aHJlc2hvbGQgYXBwcm92YWxzLgAAAAAAFUluc3VmZmljaWVudEFwcHJvdmFscwAAAAAAAFkAAABWVGhlIHBhZ2luYXRpb24gY3Vyc29yIGlzIG91dCBvZiByYW5nZSwgbWFsZm9ybWVkLCBvciBib3VuZCB0byBhIGRpZmZlcmVudCBxdWVyeSBzY29wZS4AAAAAAA1JbnZhbGlkQ3Vyc29yAAAAAAAAWgAAAFhUaGUgYGxpbWl0YCBzdXBwbGllZCB0byBhIHBhZ2luYXRlZCBsaXN0IG1ldGhvZCBpcyB6ZXJvIG9yIGV4Y2VlZHMgaXRzIG1heGltdW0gcGFnZSBjYXAuAAAAEUxpc3RMaW1pdEV4Y2VlZGVkAAAAAAAAWwAAAERUaGUgY3JlZGVudGlhbCByb290IGhhcyBleHBpcmVkIGFuZCBjYW4gbm8gbG9uZ2VyIGFuY2hvciBuZXcgcHJvb2ZzLgAAABVFeHBpcmVkQ3JlZGVudGlhbFJvb3QAAAAAAABcAAAASkFkbWluIGFuZCBhY3RpdmUgaXNzdWVyIHJvbGVzIGFyZSBtdXR1YWxseSBleGNsdXNpdmUgZm9yIHRoZSBzYW1lIGFkZHJlc3MuAAAAAAAMUm9sZUNvbmZsaWN0AAAAXQAAAEFUaGUgVGllciAyIHNvdXJjZSBiYXRjaCBNZXJrbGUgaW5jbHVzaW9uIHByb29mIGZhaWxlZCB2YWxpZGF0aW9uLgAAAAAAABVJbnZhbGlkSW5jbHVzaW9uUHJvb2YAAAAAAABeAAAAVFRoZSBrZXkgcmVhY2hlZCBgbWF4X3JlZ2lzdHJhdGlvbnNgIGluIHRoZSBjdXJyZW50IGxlZGdlci10aW1lIHdpbmRvdyBidWNrZXQgKCM4MDYpLgAAABRJc3N1ZXJRdW90YUV4aGF1c3RlZAAAAF8AAABbVGhlIGNhbGxlci1zdXBwbGllZCBsaW5lYWdlIGRlcHRoIGRvZXMgbm90IG1hdGNoIHRoZSBkZXB0aCBkZXJpdmVkIGZyb20gaXRzIHBhcmVudHMgKCMzMzMpLgAAAAAUTGluZWFnZURlcHRoTWlzbWF0Y2gAAABgAAAAW0EgbGluZWFnZSBwYXJlbnQgYWxyZWFkeSByZWFjaGVkIGl0cyBgTUFYX0xJTkVBR0VfRkFOT1VUYCBkZXJpdmF0aXZlIG91dC1kZWdyZWUgY2FwICgjMzMzKS4AAAAAFkxpbmVhZ2VGYW5PdXRTYXR1cmF0ZWQAAAAAAGEAAAA8Tm8gcHJvb2YgZXhpc3RzIGZvciB0aGUgcmVxdWVzdGVkIHJlY2VpcHQgY29tbWl0bWVudCAoIzMzNykuAAAAFFJlY2VpcHRQcm9vZk5vdEZvdW5kAAAAYgAAAEtBIHJlY2VpcHQgZGlnZXN0IGNhbm5vdCBiZSBjb21taXR0ZWQgZm9yIGEgcmV2b2tlZCBvciBleHBpcmVkIHByb29mICgjMzM3KS4AAAAAFVJlY2VpcHRQcm9vZk5vdEFjdGl2ZQAAAAAAAGMAAABGQSBkaWZmZXJlbnQgcmVjZWlwdCBkaWdlc3QgaXMgYWxyZWFkeSBjb21taXR0ZWQgZm9yIHRoaXMgcHJvb2YgKCMzMzcpLgAAAAAAF1JlY2VpcHRBbHJlYWR5Q29tbWl0dGVkAAAAAGQAAAA+VGhlIHJlY2VpcHQgZGlnZXN0IGlzIGFsbC16ZXJvIG9yIHN0cnVjdHVyYWxseSBpbnZhbGlkICgjMzM3KS4AAAAAABRJbnZhbGlkUmVjZWlwdERpZ2VzdAAAAGUAAABJVGhlIHJlY2VpcHQtc2lnbmluZyBwdWJsaWMga2V5IGlzIG5vdCByZWdpc3RlcmVkIGluIHRoZSBhbGxvd2xpc3QgKCMzMzcpLgAAAAAAABRVbmtub3duUmVjZWlwdFNpZ25lcgAAAGYAAAA3VGhlIHJlY2VpcHQtc2lnbmluZyBwdWJsaWMga2V5IGhhcyBiZWVuIHJldm9rZWQgKCMzMzcpLgAAAAAUUmV2b2tlZFJlY2VpcHRTaWduZXIAAABnAAAATlRoZSByZWdpc3RyeSByZWFjaGVkIGBNQVhfUkVDRUlQVF9TSUdORVJTYCBhY3RpdmUgcmVjZWlwdC1zaWduaW5nIGtleXMgKCMzMzcpLgAAAAAAF1JlY2VpcHRTaWduZXJzU2F0dXJhdGVkAAAAAGgAAABCYHJlYWN0aXZhdGVfc2NoZW1hYCB3YXMgY2FsbGVkIG9uIGEgc2NoZW1hIHRoYXQgaXMgYWxyZWFkeSBhY3RpdmUuAAAAAAATU2NoZW1hQWxyZWFkeUFjdGl2ZQAAAABpAAAANU5vIGFjdGl2ZSB0aHJlc2hvbGQgc2VhbCBwb2xpY3kgaXMgY29uZmlndXJlZCAoIzEyNCkuAAAAAAAAEk5vQWN0aXZlU2VhbFBvbGljeQAAAAAAagAAAE1UaGUgcmVmZXJlbmNlZCB0aHJlc2hvbGQgc2VhbCBwb2xpY3kgaXMgY2FuY2VsbGVkLCBleHBpcmVkLCBvciBhYnNlbnQgKCMxMjQpLgAAAAAAABNTZWFsUG9saWN5Q2FuY2VsbGVkAAAAAGsAAABBVGhlIGNhbGxlciBpcyBub3QgaW4gdGhlIHRocmVzaG9sZCBzZWFsIHBvbGljeSBzaWduZXIgc2V0ICgjMTI0KS4AAAAAAAATVW5rbm93blBvbGljeVNpZ25lcgAAAABsAAAASVZhbGlkIHVuZXhwaXJlZCBzZWFsIGFwcHJvdmFscyBkbyBub3QgbWVldCB0aGUgcmVxdWlyZWQgdGhyZXNob2xkICgjMTI0KS4AAAAAAAATU2VhbFRocmVzaG9sZE5vdE1ldAAAAABtAAAAPWByZXF1aXJlZF9hcHByb3ZhbHNgIGlzIHplcm8gb3IgZXhjZWVkcyBgbWF4X3NpZ25lcnNgICgjMTI0KS4AAAAAAAAUSW52YWxpZFNlYWxUaHJlc2hvbGQAAABuAAAARGBtYXhfc2lnbmVyc2Agb3IgdGhlIHNpZ25lciBzZXQgZXhjZWVkcyB0aGUgY29uZmlndXJlZCBsaW1pdCAoIzEyNCkuAAAAFVNlYWxTaWduZXJTZXRUb29MYXJnZQAAAAAAAG8AAABEVGhlIHRocmVzaG9sZCBzZWFsIGZvciB0aGlzIHByb29mIGhhcyBhbHJlYWR5IGJlZW4gZmluYWxpemVkICgjMTI0KS4AAAAUU2VhbEFscmVhZHlGaW5hbGl6ZWQAAABwAAAAWlByaXZpbGVnZWQgdHJhbnNpdGlvbiBwYXJhbWV0ZXJzIG9yIHRhcmdldCByb2xlIGZhaWxlZCBpbnRlbnQgZGlnZXN0IHZlcmlmaWNhdGlvbiAoIzExODQpLgAAAAAAGFJvbGVJbnRlbnREaWdlc3RNaXNtYXRjaAAAAHE=",
        "AAAAAQAAADRBIHNpbmdsZSB2ZXJpZmllciBzbG90IHJldHVybmVkIGJ5IGBsaXN0X3ZlcmlmaWVyc2AuAAAAAAAAAA1WZXJpZmllckVudHJ5AAAAAAAAAgAAACxUaGUgdmVyaWZpZXIgY29udHJhY3QgYWRkcmVzcyBmb3IgdGhpcyBzbG90LgAAAAdhZGRyZXNzAAAAABMAAAA3VGhlIHJvbGUgb2YgdGhpcyB2ZXJpZmllciBpbiB0aGUgY3VycmVudCBjb25maWd1cmF0aW9uLgAAAAAEcm9sZQAAB9AAAAAMVmVyaWZpZXJSb2xl",
        "AAAAAQAAAAAAAAAAAAAADVZlcmlmaWVyU3RhdGUAAAAAAAAHAAAAAAAAABFhY3RpdmF0aW9uX2xlZGdlcgAAAAAAAAYAAAAAAAAAD2FjdGl2ZV92ZXJpZmllcgAAAAPoAAAAEwAAAAAAAAAOb3ZlcmxhcF93aW5kb3cAAAAAAAYAAAAAAAAAEHBlbmRpbmdfdmVyaWZpZXIAAAPoAAAAEwAAAAAAAAARcHJldmlvdXNfdmVyaWZpZXIAAAAAAAPoAAAAEwAAAAAAAAAPcm9sbGJhY2tfd2luZG93AAAAAAYAAAAAAAAAE3JvbGxiYWNrX3dpbmRvd19lbmQAAAAABg==",
        "AAAABQAAAAAAAAAAAAAADUFkbWluQWNjZXB0ZWQAAAAAAAACAAAABWFkbWluAAAAAAAABmFjY2VwdAAAAAAAAgAAAAAAAAAJbmV3X2FkbWluAAAAAAAAEwAAAAEAAAAAAAAADnByZXZpb3VzX2FkbWluAAAAAAATAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAADUFkbWluUHJvcG9zZWQAAAAAAAACAAAABWFkbWluAAAAAAAAB3Byb3Bvc2UAAAAAAgAAAAAAAAANcGVuZGluZ19hZG1pbgAAAAAAABMAAAABAAAAAAAAAA1jdXJyZW50X2FkbWluAAAAAAAAEwAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAADURpc3B1dGVPcGVuZWQAAAAAAAACAAAAB2Rpc3B1dGUAAAAABG9wZW4AAAAGAAAAAAAAAApkaXNwdXRlX2lkAAAAAAPuAAAAIAAAAAEAAAAAAAAACHByb29mX2lkAAAD7gAAACAAAAABAAAAAAAAAAZyZWFzb24AAAAAB9AAAAANRGlzcHV0ZVJlYXNvbgAAAAAAAAAAAAAAAAAADXJlcG9ydGVyX2hhc2gAAAAAAAPuAAAAIAAAAAAAAAAAAAAAD2NvbW1pdG1lbnRfaGFzaAAAAAPuAAAAIAAAAAAAAAAAAAAAEHJlc3BvbmRfZGVhZGxpbmUAAAAGAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAADUlzc3VlclJldm9rZWQAAAAAAAACAAAABmlzc3VlcgAAAAAABnJldm9rZQAAAAAAAQAAAAAAAAAGaXNzdWVyAAAAAAATAAAAAQAAAAI=",
        "AAAABQAAAMZFbWl0dGVkIHdoZW4gYW4gYWN0aXZlIGlzc3VlciBrZXkgcm90YXRlcyB0byBhIHJlcGxhY2VtZW50ICgjMzIzKS4KCkNhcnJpZXMgYWRkcmVzc2VzLCBsZWRnZXIgdGltZSwgYW5kIHRoZSBncmFjZSBib3VuZCBvbmx5IOKAlCBuZXZlciBrZXkKbWF0ZXJpYWwsIG1ldGFkYXRhIHByZWltYWdlcywgd2l0bmVzc2VzLCBtZWRpYSwgb3Igc2VjcmV0cy4AAAAAAAAAAAANSXNzdWVyUm90YXRlZAAAAAAAAAIAAAAGaXNzdWVyAAAAAAAGcm90YXRlAAAAAAAFAAAAAAAAAA9wcmV2aW91c19pc3N1ZXIAAAAAEwAAAAEAAAAAAAAAEnJlcGxhY2VtZW50X2lzc3VlcgAAAAAAEwAAAAAAAAAAAAAACnJvdGF0ZWRfYXQAAAAAAAYAAAAAAAAAAAAAABBncmFjZV9leHBpcmVzX2F0AAAABgAAAAAAAAAAAAAACmdyYWNlX3NlY3MAAAAAAAYAAAAAAAAAAg==",
        "AAAABQAAAAAAAAAAAAAADVNjb3BlRXBvY2hTZXQAAAAAAAACAAAABXNjb3BlAAAAAAAABWVwb2NoAAAAAAAAAgAAAAAAAAAFc2NvcGUAAAAAAAPuAAAAIAAAAAEAAAAAAAAABWVwb2NoAAAAAAAABgAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAADVNlYWxGaW5hbGl6ZWQAAAAAAAACAAAABHNlYWwAAAAIZmluYWxpemUAAAADAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAQAAAAAAAAAOcG9saWN5X3ZlcnNpb24AAAAAAAQAAAAAAAAAAAAAAA5hcHByb3ZhbF9jb3VudAAAAAAABAAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAADVRUTE1haW50YWluZWQAAAAAAAACAAAAA3R0bAAAAAAIbWFpbnRhaW4AAAABAAAAAAAAAAVjb3VudAAAAAAAAAQAAAAAAAAAAg==",
        "AAAAAQAAAJtDb21wcmVoZW5zaXZlIHByb29mIGFzc3VyYW5jZSB2aWV3IGNvbWJpbmluZyBzdGF0dXMsIHRpZXIsIHRpbWVzdGFtcCBhc3N1cmFuY2UsCmRpc3B1dGUgY291bnQsIGVudmVsb3BlIHZlcnNpb24sIGFuZCBpc3N1ZXIgdmVyaWZpYWJpbGl0eSBpbiBhIHNpbmdsZSBjYWxsLgAAAAAAAAAADlByb29mQXNzdXJhbmNlAAAAAAAGAAAAAAAAABBlbnZlbG9wZV92ZXJzaW9uAAAABAAAAAAAAAARaXNzdWVyX3ZlcmlmaWFibGUAAAAAAAABAAAAAAAAABJvcGVuX2Rpc3B1dGVfY291bnQAAAAAAAQAAAAAAAAABnN0YXR1cwAAAAAH0AAAABdQcm9vZlZlcmlmaWNhdGlvblN0YXR1cwAAAAAAAAAABHRpZXIAAAAEAAAAAAAAABl0aW1lc3RhbXBfYXNzdXJhbmNlX2xldmVsAAAAAAAABA==",
        "AAAAAQAAAQxBZ2dyZWdhdGUgc25hcHNob3Qgb2YgdGhlIHJlZ2lzdHJ5J3Mgb3BlcmF0aW9uYWwgY29uZmlndXJhdGlvbiAoIzcyMSkuCgpDb21iaW5lcyB0aGUgaW5kaXZpZHVhbCBjb25maWd1cmF0aW9uIGdldHRlcnMgYW5kIHRoZSBjdXJyZW50bHkgcGF1c2VkCnJlZ2lzdHJhdGlvbiBkb21haW5zIGJpdG1hc2sgaW50byBhIHNpbmdsZSByZWFkLW9ubHkgcmVzcG9uc2Ugc28gY2xpZW50cwpjYW4gaW5zcGVjdCB0aGUgb3BlcmF0aW9uYWwgc3RhdGUgaW4gb25lIHNpbXVsYXRpb24uAAAAAAAAAA5SZWdpc3RyeUNvbmZpZwAAAAAACAAAAAAAAAAIZ3VhcmRpYW4AAAPoAAAAEwAAAAAAAAAOcGF1c2VkX2RvbWFpbnMAAAAAAAQAAAAAAAAACXByb29mX3R0bAAAAAAAAAYAAAAAAAAAD3Jldm9jYXRpb25fcm9vdAAAAAPoAAAD7gAAACAAAAAAAAAADnNjaGVtYV92ZXJzaW9uAAAAAAAEAAAAAAAAABd0aW1lbG9ja19taW5fZGVsYXlfc2VjcwAAAAAGAAAAAAAAAAh2ZXJpZmllcgAAA+gAAAATAAAAAAAAAA52ZXJpZmllcl9zdGF0ZQAAAAAH0AAAAA1WZXJpZmllclN0YXRlAAAA",
        "AAAAAQAAALpPbi1jaGFpbiBpbmRlcGVuZGVudCB0aW1lc3RhbXAgY2xhaW0gZm9yIGEgcmVnaXN0ZXJlZCBwcm9vZiAoIzMzOSkuCgpTdG9yZXMgY29tbWl0bWVudHMgYW5kIGxlZGdlci1kZXJpdmVkIGFuY2hvcnMgb25seSDigJQgbmV2ZXIgVFNBIHRva2VuCmJ5dGVzLCBtZWRpYSwgd2l0bmVzcyB2YWx1ZXMsIG9yIHByaXZhdGUga2V5cy4AAAAAAAAAAAAOVGltZXN0YW1wQ2xhaW0AAAAAAAkAAAAsQXV0aGVudGljYXRlZCBhY3RvciB3aG8gc3VibWl0dGVkIHRoZSBjbGFpbS4AAAAFYWN0b3IAAAAAAAATAAAASkxlZGdlciB0aW1lc3RhbXAgd2hlbiB0aGlzIGNsYWltIHdhcyBhbmNob3JlZCAoaW5kZXBlbmRlbnQgb2JzZXJ2ZWQgdGltZSkuAAAAAAALYW5jaG9yZWRfYXQAAAAABgAAADJEZXJpdmVkIGFzc3VyYW5jZSBsZXZlbCAoYFRJTUVTVEFNUF9BU1NVUkFOQ0VfKmApLgAAAAAACWFzc3VyYW5jZQAAAAAAAAQAAABDRGlnZXN0IG9mIHRoZSBvZmYtY2hhaW4gYGhhcnBvY3JhdGVzLXRpbWUtYXR0ZXN0YXRpb24vdjFgIGVudmVsb3BlLgAAAAASYXR0ZXN0YXRpb25fZGlnZXN0AAAAAAPuAAAAIAAAAD9PcHRpb25hbCBjbGFpbWVkIGNhcHR1cmUgdGltZSAodW5peCBzZWNvbmRzKS4gYDBgIG1lYW5zIGFic2VudC4AAAAADGNsYWltZWRfdGltZQAAAAYAAAA5TGVkZ2VyIHNlcXVlbmNlIGF0IGFuY2hvciB0aW1lIGZvciBleHRlcm5hbCBjcm9zcy1jaGVja3MuAAAAAAAAD2xlZGdlcl9zZXF1ZW5jZQAAAAAEAAAAHVByb29mIHRoaXMgY2xhaW0gaXMgYm91bmQgdG8uAAAAAAAACHByb29mX2lkAAAD7gAAACAAAAA1Q29tbWl0bWVudCB0byBhbiBSRkMgMzE2MSB0b2tlbiAoYFswOzMyXWAgaWYgYWJzZW50KS4AAAAAAAAScmZjMzE2MV9jb21taXRtZW50AAAAAAPuAAAAIAAAAClDb21iaW5hYmxlIGBUSU1FU1RBTVBfU09VUkNFXypgIGJpdGZsYWdzLgAAAAAAAAdzb3VyY2VzAAAAAAQ=",
        "AAAABQAAAAAAAAAAAAAADkRlbGVnYXRpb25Vc2VkAAAAAAACAAAABWRlbGVnAAAAAAAABHVzZWQAAAAEAAAAAAAAAAdncmFudG9yAAAAABMAAAABAAAAAAAAAAhkZWxlZ2F0ZQAAABMAAAABAAAAAAAAAAVzY29wZQAAAAAAAAQAAAAAAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAADkRvbWFpblVucGF1c2VkAAAAAAACAAAABXBhdXNlAAAAAAAABWNsZWFyAAAAAAAAAwAAAAAAAAAGZG9tYWluAAAAAAAEAAAAAQAAAAAAAAALdW5wYXVzZWRfYnkAAAAAEwAAAAAAAAAAAAAAC3VucGF1c2VkX2F0AAAAAAYAAAAAAAAAAg==",
        "AAAABQAAAOJFbWl0dGVkIHdoZW4gdGhlIGFkbWluIHNldHMgb3IgY2xlYXJzIG9uZSBrZXkncyByZWdpc3RyYXRpb24gcXVvdGEgKCM4MDYpLgpBIGBtYXhfcmVnaXN0cmF0aW9uc2AgKG9yIGB3aW5kb3dfc2Vjc2ApIG9mIHplcm8gcHVibGlzaGVzIHRoZSBjbGVhciwgc28gYW4KaW5kZXhlciBjYW4gdGVsbCAidW5saW1pdGVkIiBmcm9tICJubyBjb25maWd1cmF0aW9uIGV2ZXIiIGJ5IHRoZSBldmVudCBsb2cuAAAAAAAAAAAADklzc3VlclF1b3RhU2V0AAAAAAACAAAABXF1b3RhAAAAAAAAA3NldAAAAAAEAAAAAAAAAAZpc3N1ZXIAAAAAABMAAAABAAAAAAAAABFtYXhfcmVnaXN0cmF0aW9ucwAAAAAAAAQAAAAAAAAAAAAAAAt3aW5kb3dfc2VjcwAAAAAGAAAAAAAAAAAAAAAGc2V0X2J5AAAAAAATAAAAAQAAAAI=",
        "AAAABQAAAAAAAAAAAAAADlNjaGVtYVVwZ3JhZGVkAAAAAAACAAAABnNjaGVtYQAAAAAAB3VwZ3JhZGUAAAAAAgAAAAAAAAAIcHJldmlvdXMAAAAEAAAAAAAAAAAAAAAHY3VycmVudAAAAAAEAAAAAAAAAAI=",
        "AAAAAQAAAAAAAAAAAAAAD0NvdW5jaWxQcm9wb3NhbAAAAAAKAAAAAAAAAAZhY3Rpb24AAAAAAAQAAAAAAAAACWFwcHJvdmFscwAAAAAAA+oAAAATAAAAAAAAAAljYW5jZWxsZWQAAAAAAAABAAAAAAAAAApjcmVhdGVkX2F0AAAAAAAGAAAAAAAAAAhleGVjdXRlZAAAAAEAAAAAAAAACmV4cGlyZXNfYXQAAAAAAAYAAAAAAAAAAmlkAAAAAAAEAAAAAAAAAAdwYXlsb2FkAAAAA+4AAAAgAAAAAAAAAAhwcm9wb3NlcgAAABMAAAAAAAAABnRhcmdldAAAAAAAEw==",
        "AAAABQAAAAAAAAAAAAAAD0FkbWluQ291bmNpbFNldAAAAAACAAAAB2NvdW5jaWwAAAAAA3NldAAAAAADAAAAAAAAAAl0aHJlc2hvbGQAAAAAAAAEAAAAAAAAAAAAAAAMbWVtYmVyX2NvdW50AAAABAAAAAAAAAAAAAAADGVmZmVjdGl2ZV9hdAAAAAYAAAAAAAAAAg==",
        "AAAABQAAAAAAAAAAAAAAD0Rpc3B1dGVSZXNvbHZlZAAAAAACAAAAB2Rpc3B1dGUAAAAAB3Jlc29sdmUAAAAAAwAAAAAAAAAKZGlzcHV0ZV9pZAAAAAAD7gAAACAAAAABAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAQAAAAAAAAALcmVzb2x2ZWRfYXQAAAAABgAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAAD0d1YXJkaWFuQ2xlYXJlZAAAAAACAAAACGd1YXJkaWFuAAAABWNsZWFyAAAAAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAAD1Byb29mUmVnaXN0ZXJlZAAAAAACAAAABXByb29mAAAAAAAAA3JlZwAAAAAFAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAQAAAAAAAAAKdmlkZW9faGFzaAAAAAAD7gAAACAAAAAAAAAAAAAAAAR0aWVyAAAABAAAAAAAAAAAAAAABnN0YXR1cwAAAAAABAAAAAAAAAAAAAAACmJhdGNoX3NpemUAAAAAAAQAAAAAAAAAAg==",
        "AAAAAQAAADtBIG5hcnJvd2x5IHNjb3BlZCwgZXhwaXJpbmcgYXV0aG9yaXR5IHRvIGFjdCBmb3IgYGdyYW50b3JgLgAAAAAAAAAAEERlbGVnYXRpb25SZWNvcmQAAAAFAAAAAAAAAAhkZWxlZ2F0ZQAAABMAAAA+RXBvY2ggc2Vjb25kcyBhZnRlciB3aGljaCB0aGUgZGVsZWdhdGlvbiBpcyBpbmVydC4gTmV2ZXIgemVyby4AAAAAAApleHBpcmVzX2F0AAAAAAAGAAAAAAAAAApncmFudGVkX2F0AAAAAAAGAAAAAAAAAAdncmFudG9yAAAAABMAAAAjQml0d2lzZS1PUiBvZiBgREVMRUdBVElPTl9TQ09QRV8qYC4AAAAABXNjb3BlAAAAAAAABA==",
        "AAAAAQAAARxPbmUgc21hbGwgdXNhZ2UgcmVjb3JkIHBlciBrZXllZCBhZGRyZXNzOiB0aGUgY3VycmVudCBsZWRnZXItdGltZSB3aW5kb3cKYnVja2V0IGFuZCBob3cgbWFueSByZWdpc3RyYXRpb25zIGhhdmUgYmVlbiBjaGFyZ2VkIGluc2lkZSBpdCAoIzgwNikuCkEgc3RvcmVkIGBidWNrZXRgIGJlaGluZCB0aGUgY3VycmVudCBvbmUgaXMgdHJlYXRlZCBhcyBlbXB0eSwgc28gY291bnRzCm5lZWQgbm8gZXhwbGljaXQgcmVzZXQgYW5kIHRoZSBzdG9yYWdlIHN0YXlzIGEgc2luZ2xlIGNvbXBhY3QgcmVjb3JkLgAAAAAAAAAQSXNzdWVyUXVvdGFVc2FnZQAAAAIAAABAYGxlZGdlciB0aW1lc3RhbXAgLyB3aW5kb3dfc2Vjc2AgYXQgdGhlIHRpbWUgb2YgdGhlIGxhc3QgY2hhcmdlLgAAAAZidWNrZXQAAAAAAAYAAAAmUmVnaXN0cmF0aW9ucyBjaGFyZ2VkIGluc2lkZSBgYnVja2V0YC4AAAAAAAVjb3VudAAAAAAAAAQ=",
        "AAAAAQAAAMdWZXJzaW9uZWQgb24tY2hhaW4gbWV0YWRhdGEgZW52ZWxvcGUgYmluZGluZyAoIzMxNykuCgpTdG9yZXMgb25seSBgKHZlcnNpb24sIG1ldGFkYXRhX2hhc2gpYCBjb21taXRtZW50cyDigJQgbmV2ZXIgcmF3IGVudmVsb3BlCmJ5dGVzLCBtZWRpYSwgd2l0bmVzc2VzLCBvciBzZWNyZXRzLiBBbGlnbnMgd2l0aCBiYWNrZW5kIGBlbnZlbG9wZS5weWAuAAAAAAAAAAAQTWV0YWRhdGFFbnZlbG9wZQAAAAQAAAA4TGVkZ2VyIHRpbWVzdGFtcCB3aGVuIHRoaXMgZW52ZWxvcGUgYmluZGluZyB3YXMgd3JpdHRlbi4AAAAIYm91bmRfYXQAAAAGAAAAPUNhbm9uaWNhbCBtZXRhZGF0YSBoYXNoIChzYW1lIHZhbHVlIHN0b3JlZCBvbiBgUHJvb2ZSZWNvcmRgKS4AAAAAAAANbWV0YWRhdGFfaGFzaAAAAAAAA+4AAAAgAAAAIFByb29mIHRoaXMgZW52ZWxvcGUgaXMgYm91bmQgdG8uAAAACHByb29mX2lkAAAD7gAAACAAAAA4RW52ZWxvcGUgc2NoZW1hIHZlcnNpb24gKGBNRVRBREFUQV9FTlZFTE9QRV9WMWAgLyBgVjJgKS4AAAAHdmVyc2lvbgAAAAAE",
        "AAAAAQAAAAAAAAAAAAAAEFRpbWVsb2NrUHJvcG9zYWwAAAAIAAAAAAAAAAZhY3Rpb24AAAAAAAQAAAAAAAAACWNhbmNlbGxlZAAAAAAAAAEAAAAAAAAACmNyZWF0ZWRfYXQAAAAAAAYAAAAAAAAACGV4ZWN1dGVkAAAAAQAAAAAAAAAQbWluX2V4ZWN1dGlvbl9hdAAAAAYAAAAAAAAAB3BheWxvYWQAAAAD7gAAACAAAAAAAAAACHByb3Bvc2VyAAAAEwAAAAAAAAAGdGFyZ2V0AAAAAAAT",
        "AAAABQAAAAAAAAAAAAAAEENvbnRyYWN0VXBncmFkZWQAAAACAAAACGNvbnRyYWN0AAAAB3VwZ3JhZGUAAAAAAgAAAAAAAAANb2xkX3dhc21faGFzaAAAAAAAA+4AAAAgAAAAAAAAAAAAAAANbmV3X3dhc21faGFzaAAAAAAAA+4AAAAgAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAAEERpc3B1dGVEaXNtaXNzZWQAAAACAAAAB2Rpc3B1dGUAAAAAB2Rpc21pc3MAAAAAAwAAAAAAAAAKZGlzcHV0ZV9pZAAAAAAD7gAAACAAAAABAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAQAAAAAAAAALcmVzb2x2ZWRfYXQAAAAABgAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAAEERpc3B1dGVSZXNwb25kZWQAAAACAAAAB2Rpc3B1dGUAAAAAB3Jlc3BvbmQAAAAABAAAAAAAAAAKZGlzcHV0ZV9pZAAAAAAD7gAAACAAAAABAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAQAAAAAAAAATcmVzcG9uc2VfY29tbWl0bWVudAAAAAPuAAAAIAAAAAAAAAAAAAAAEHJlc29sdmVfZGVhZGxpbmUAAAAGAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAAEFNjaGVtYURlcHJlY2F0ZWQAAAACAAAABnNjaGVtYQAAAAAACWRlcHJlY2F0ZQAAAAAAAAEAAAAAAAAAC3NjaGVtYV9oYXNoAAAAA+4AAAAgAAAAAQAAAAI=",
        "AAAAAQAAAMlBZG1pbi1zZXQgcmVnaXN0cmF0aW9uIHF1b3RhIGZvciBvbmUga2V5LCBtZWFzdXJlZCBpbiBsZWRnZXItdGltZSB3aW5kb3cKYnVja2V0cyAoIzgwNikuIEFic2VuY2Ugb2YgYSByZWNvcmQgbWVhbnMgdW5saW1pdGVkLCBzbyBkZXBsb3ltZW50cyB0aGF0Cm5ldmVyIGNhbGwgYHNldF9pc3N1ZXJfcXVvdGFgIGJlaGF2ZSBleGFjdGx5IGFzIGJlZm9yZS4AAAAAAAAAAAAAEUlzc3VlclF1b3RhUmVjb3JkAAAAAAAAAgAAAGtSZWdpc3RyYXRpb25zIGFsbG93ZWQgcGVyIGtleSBwZXIgd2luZG93IGJ1Y2tldC4gTmV2ZXIgemVybyB3aGlsZSB0aGUKcmVjb3JkIGV4aXN0czsgemVybyBjbGVhcnMgdGhlIHF1b3RhLgAAAAARbWF4X3JlZ2lzdHJhdGlvbnMAAAAAAAAEAAAAf1dpbmRvdy1idWNrZXQgd2lkdGggaW4gc2Vjb25kcy4gQnVja2V0IGluZGV4IGlzIGB0aW1lc3RhbXAgLwp3aW5kb3dfc2Vjc2AsIHNvIGEgcm9sbG92ZXIgaW50byB0aGUgbmV4dCBidWNrZXQgcmVzZXRzIHRoZSBjb3VudC4AAAAAC3dpbmRvd19zZWNzAAAAAAY=",
        "AAAAAQAAAAAAAAAAAAAAEVByb29mSGlzdG9yeUVudHJ5AAAAAAAABAAAAAAAAAAGYWN0aW9uAAAAAAAEAAAAAAAAAAVhY3RvcgAAAAAAA+gAAAATAAAAAAAAAAtyZWFzb25fY29kZQAAAAAEAAAAAAAAAAl0aW1lc3RhbXAAAAAAAAAG",
        "AAAABQAAAAAAAAAAAAAAEURlbGVnYXRpb25HcmFudGVkAAAAAAAAAgAAAAVkZWxlZwAAAAAAAAVncmFudAAAAAAAAAUAAAAAAAAAB2dyYW50b3IAAAAAEwAAAAEAAAAAAAAACGRlbGVnYXRlAAAAEwAAAAEAAAAAAAAABXNjb3BlAAAAAAAABAAAAAAAAAAAAAAACmdyYW50ZWRfYXQAAAAAAAYAAAAAAAAAAAAAAApleHBpcmVzX2F0AAAAAAAGAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAAEURlbGVnYXRpb25SZXZva2VkAAAAAAAAAgAAAAVkZWxlZwAAAAAAAAZyZXZva2UAAAAAAAQAAAAAAAAAB2dyYW50b3IAAAAAEwAAAAEAAAAAAAAACGRlbGVnYXRlAAAAEwAAAAEAAAAAAAAACnJldm9rZWRfYnkAAAAAABMAAAAAAAAAAAAAAApyZXZva2VkX2F0AAAAAAAGAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAAEURpc3B1dGVTdXBlcnNlZGVkAAAAAAAAAgAAAAdkaXNwdXRlAAAAAAlzdXBlcnNlZGUAAAAAAAAEAAAAAAAAAApkaXNwdXRlX2lkAAAAAAPuAAAAIAAAAAEAAAAAAAAACHByb29mX2lkAAAD7gAAACAAAAABAAAAAAAAAA1zdXBlcnNlZGVkX2J5AAAAAAAD7gAAACAAAAAAAAAAAAAAAAtyZXNvbHZlZF9hdAAAAAAGAAAAAAAAAAI=",
        "AAAABQAAAPZQcml2YWN5LXNhZmUgbGluZWFnZSByZWdpc3RyYXRpb24gc2lnbmFsICgjMzMyKS4KClB1Ymxpc2hlcyBwYXJlbnQgKmNvbW1pdG1lbnRzKiAobm90IHJhdyBwYXJlbnQgcHJvb2YgaWRzKSBzbyBpbmRleGVycyBhbmQKaW50ZXJvcGVyYWJsZSBjb25zdW1lcnMgY2FuIG9ic2VydmUgZGVyaXZhdGl2ZSBsaW5rYWdlIHdpdGhvdXQgZXhwYW5kaW5nCnRoZSBwdWJsaWMgc3VyZmFjZSBiZXlvbmQgb3BhcXVlIDMyLWJ5dGUgZGlnZXN0cy4AAAAAAAAAAAARTGluZWFnZVJlZ2lzdGVyZWQAAAAAAAACAAAAB2xpbmVhZ2UAAAAAA3JlZwAAAAAGAAAAAAAAAA1vdXRwdXRfZGlnZXN0AAAAAAAD7gAAACAAAAABAAAAAAAAAA9tYW5pZmVzdF9kaWdlc3QAAAAD7gAAACAAAAAAAAAAAAAAAAVhY3RvcgAAAAAAABMAAAAAAAAAAAAAAA5vcGVyYXRpb25fdHlwZQAAAAAAEQAAAAAAAAAAAAAABWRlcHRoAAAAAAAABAAAAAAAAAAAAAAAEnBhcmVudF9jb21taXRtZW50cwAAAAAD6gAAA+4AAAAgAAAAAAAAAAI=",
        "AAAABQAAAQlEb21haW4tc2VwYXJhdGVkLCBwcml2YWN5LXNhZmUgcHJvb2YgbGlmZWN5Y2xlIGhpc3RvcnkgZXZlbnQgKCM5MCkuCgpUb3BpY3M6IGBbInByb29mIiwgImhpc3RvcnkiLCBwcm9vZl9pZF1gLiBUaGUgcGF5bG9hZCBjYXJyaWVzIG9ubHkgYm91bmRlZAptZXRhZGF0YSAoYWN0aW9uLCB0aW1lc3RhbXAsIGFjdG9yLCByZWFzb25fY29kZSkg4oCUIG5ldmVyIG1lZGlhLCBwcm9vZiBieXRlcywKd2l0bmVzc2VzLCBudWxsaWZpZXJzLCBvciBtZXRhZGF0YSBoYXNoZXMuAAAAAAAAAAAAABFQcm9vZkhpc3RvcnlFdmVudAAAAAAAAAIAAAAFcHJvb2YAAAAAAAAHaGlzdG9yeQAAAAAFAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAQAAAAAAAAAGYWN0aW9uAAAAAAAEAAAAAAAAAAAAAAAJdGltZXN0YW1wAAAAAAAABgAAAAAAAAAAAAAABWFjdG9yAAAAAAAD6AAAABMAAAAAAAAAAAAAAAtyZWFzb25fY29kZQAAAAAEAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAAEVJldm9jYXRpb25Sb290U2V0AAAAAAAAAgAAAAdyZXZyb290AAAAAANzZXQAAAAAAQAAAAAAAAAPcmV2b2NhdGlvbl9yb290AAAAA+4AAAAgAAAAAQAAAAI=",
        "AAAABQAAAAAAAAAAAAAAEVNjaGVtYVJlYWN0aXZhdGVkAAAAAAAAAgAAAAZzY2hlbWEAAAAAAApyZWFjdGl2YXRlAAAAAAABAAAAAAAAAAtzY2hlbWFfaGFzaAAAAAPuAAAAIAAAAAEAAAAC",
        "AAAABQAAAAAAAAAAAAAAEVNlYWxQb2xpY3lDcmVhdGVkAAAAAAAAAgAAAAhzZWFsX3BvbAAAAAZjcmVhdGUAAAAAAAUAAAAAAAAAB3ZlcnNpb24AAAAABAAAAAEAAAAAAAAAEnJlcXVpcmVkX2FwcHJvdmFscwAAAAAABAAAAAAAAAAAAAAAC21heF9zaWduZXJzAAAAAAQAAAAAAAAAAAAAAAxhcHByb3ZhbF90dGwAAAAGAAAAAAAAAAAAAAAKZXhwaXJlc19hdAAAAAAABgAAAAAAAAAC",
        "AAAAAQAAADVQYWdpbmF0ZWQgcmVzdWx0IGZyb20gYGxpc3RfY3JlZGVudGlhbF9yb290c2AgKCM3MzEpLgAAAAAAAAAAAAASQ3JlZGVudGlhbFJvb3RQYWdlAAAAAAACAAAASUN1cnNvciBmb3IgdGhlIG5leHQgcGFnZSAoYFNvbWUobmV4dF9jdXJzb3IpYCksIG9yIGBOb25lYCBpZiBlbmQgcmVhY2hlZC4AAAAAAAALbmV4dF9jdXJzb3IAAAAD6AAAAAQAAAAAAAAABXJvb3RzAAAAAAAD6gAAB9AAAAATQ3JlZGVudGlhbFJvb3RFbnRyeQA=",
        "AAAABQAAAAAAAAAAAAAAElJlY2VpcHRTaWduZXJBZGRlZAAAAAAAAgAAAAZzaWduZXIAAAAAAANhZGQAAAAAAgAAAAAAAAAKcHVibGljX2tleQAAAAAD7gAAAEEAAAABAAAAAAAAAAhhZGRlZF9hdAAAAAYAAAAAAAAAAg==",
        "AAAAAQAAACpBbiBlbnRyeSBpbiBhIGBDcmVkZW50aWFsUm9vdFBhZ2VgICgjNzMxKS4AAAAAAAAAAAATQ3JlZGVudGlhbFJvb3RFbnRyeQAAAAACAAAAAAAAAAlyb290X2hhc2gAAAAAAAPuAAAAIAAAAAAAAAAGc3RhdHVzAAAAAAAE",
        "AAAAAQAAAD1PbmUgcGFnZSBvZiBjaGlsZCBvdXRwdXQgZGlnZXN0cyBmb3IgYSBsaW5lYWdlIHBhcmVudCAoIzMzNSkuAAAAAAAAAAAAABNMaW5lYWdlQ2hpbGRyZW5QYWdlAAAAAAMAAAAAAAAACGNoaWxkcmVuAAAD6gAAA+4AAAAgAAAASUFic29sdXRlIG9mZnNldCBvZiB0aGUgbmV4dCB1bnJlYWQgY2hpbGQgKGVxdWFscyBgdG90YWxgIHdoZW4gZXhoYXVzdGVkKS4AAAAAAAALbmV4dF9vZmZzZXQAAAAABAAAAAAAAAAFdG90YWwAAAAAAAAE",
        "AAAAAQAAAL9BZG1pbi1tYW5hZ2VkIHJlY2VpcHQtc2lnbmluZyBrZXkgcmVjb3JkLiBgcHVibGljX2tleWAgaXMgYSBTRUMtMQplbmNvZGVkIHVuY29tcHJlc3NlZCBQLTI1NiBwb2ludCAoYDB4MDQgfHwgWCB8fCBZYCk7IHB1YmxpYyBrZXlzIGFyZSBub3QKc2VjcmV0cywgYW5kIG5vIHByaXZhdGUga2V5IG1hdGVyaWFsIGlzIGV2ZXIgc3RvcmVkLgAAAAAAAAAAE1JlY2VpcHRTaWduZXJSZWNvcmQAAAAABAAAAIBGYWxzZSBvbmNlIHJldm9rZWQuIFJldm9jYXRpb24gaXMgcmVjb3JkZWQgcmF0aGVyIHRoYW4gZGVsZXRlZCBzbyBhbgpvcGVyYXRvciBjYW4gZGlzdGluZ3Vpc2ggInJldm9rZWQiIGZyb20gIm5ldmVyIHJlZ2lzdGVyZWQiLgAAAAZhY3RpdmUAAAAAAAEAAAAAAAAACGFkZGVkX2F0AAAABgAAAAAAAAAKcHVibGljX2tleQAAAAAD7gAAAEEAAAAdMCB3aGlsZSB0aGUgc2lnbmVyIGlzIGFjdGl2ZS4AAAAAAAAKcmV2b2tlZF9hdAAAAAAABg==",
        "AAAAAQAAAEJBIHJldm9jYXRpb24gcm9vdCBlbnRyeSBzdG9yZWQgaW4gdGhlIGJvdW5kZWQgaGlzdG9yeSByaW5nIGJ1ZmZlci4AAAAAAAAAAAATUmV2b2NhdGlvblJvb3RFbnRyeQAAAAACAAAAMUxlZGdlciBzZXF1ZW5jZSBhdCB3aGljaCB0aGlzIHJvb3Qgd2FzIGFjdGl2YXRlZC4AAAAAAAARYWN0aXZhdGlvbl9sZWRnZXIAAAAAAAAEAAAAI01lcmtsZSByb290IG9mIHRoZSByZXZvY2F0aW9uIHRyZWUuAAAAAARyb290AAAD7gAAACA=",
        "AAAABQAAAAAAAAAAAAAAE0NyZWRlbnRpYWxSb290QWRkZWQAAAAAAgAAAAhjcmVkcm9vdAAAAANhZGQAAAAAAwAAAAAAAAAPY3JlZGVudGlhbF9yb290AAAAA+4AAAAgAAAAAQAAAAAAAAANbWV0YWRhdGFfaGFzaAAAAAAAA+4AAAAgAAAAAAAAAAAAAAAJaXNzdWVkX2F0AAAAAAAABgAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAAE1RpbWVsb2NrTWluRGVsYXlTZXQAAAAAAgAAAAh0aW1lbG9jawAAAAVkZWxheQAAAAAAAAQAAAAAAAAADnByZXZpb3VzX2RlbGF5AAAAAAAGAAAAAAAAAAAAAAAJbmV3X2RlbGF5AAAAAAAABgAAAAAAAAAAAAAAA3NldAAAAAARAAAAAQAAAAAAAAAGc2V0X2J5AAAAAAATAAAAAQAAAAI=",
        "AAAAAQAAAAAAAAAAAAAAFENyZWRlbnRpYWxSb290UmVjb3JkAAAABAAAAAAAAAAKZXhwaXJlc19hdAAAAAAABgAAAAAAAAAJaXNzdWVkX2F0AAAAAAAABgAAAAAAAAANbWV0YWRhdGFfaGFzaAAAAAAAA+4AAAAgAAAAAAAAAAZzdGF0dXMAAAAAAAQ=",
        "AAAAAQAAAZ5Sb3RhdGlvbiBncmFjZSByZWNvcmQgZm9yIGFuIGlzc3VlciBrZXkgdGhhdCBoYXMgcm90YXRlZCBvdXQgKCMzMjMpLgoKS2V5ZWQgYnkgdGhlICpwcmV2aW91cyogKHJldGlyZWQpIGtleSBhdCBgRGF0YUtleTo6SXNzdWVyUm90YXRpb24oQWRkcmVzcylgCnNvIHRoZSBzdG9yZWQgYElzc3VlclJlY29yZGAga2VlcHMgaXRzIGJ5dGUtaWRlbnRpY2FsIGB7bWV0YWRhdGFfaGFzaCwKYWN0aXZlfWAgc2hhcGUgYW5kIHJlY29yZHMgd3JpdHRlbiBieSBhbiBlYXJsaWVyIHdhc20gc3RpbGwgZGVjb2RlLgpQcmVzZW5jZSBtZWFucyAidGhpcyBrZXkgd2FzIHJvdGF0ZWQsIG5vdCByZXZva2VkLCBhbmQgdGhlIGV2aWRlbmNlIGl0CmFscmVhZHkgc2lnbmVkIHN0YXlzIHZlcmlmaWFibGUgdW50aWwgYGdyYWNlX2V4cGlyZXNfYXRgIi4AAAAAAAAAAAAUSXNzdWVyUm90YXRpb25SZWNvcmQAAAAFAAAAfEVwb2NoIHNlY29uZHMgYWZ0ZXIgd2hpY2ggdGhlIGdyYWNlIHdpbmRvdyBoYXMgbGFwc2VkLiBBIHJlYWRlciBhdApleGFjdGx5IHRoaXMgdGltZXN0YW1wIHNlZXMgdGhlIHdpbmRvdyBhcyBhbHJlYWR5IGNsb3NlZC4AAAAQZ3JhY2VfZXhwaXJlc19hdAAAAAYAAABHUmVzb2x2ZWQgd2luZG93IGxlbmd0aCAodGhlIHByb3RvY29sIGRlZmF1bHQgd2hlbiB0aGUgY2FsbGVyIHBhc3NlZCAwKS4AAAAACmdyYWNlX3NlY3MAAAAAAAYAAAA7VGhlIGtleSB0aGF0IHJvdGF0ZWQgb3V0IOKAlCBhbHNvIHRoZSByZWNvcmQncyBzdG9yYWdlIGtleS4AAAAAD3ByZXZpb3VzX2lzc3VlcgAAAAATAAAAIFRoZSBhY3RpdmUga2V5IHRoYXQgcmVwbGFjZWQgaXQuAAAAEnJlcGxhY2VtZW50X2lzc3VlcgAAAAAAEwAAADRMZWRnZXIgdGltZXN0YW1wIGF0IHdoaWNoIHRoZSByb3RhdGlvbiB3YXMgYWNjZXB0ZWQuAAAACnJvdGF0ZWRfYXQAAAAAAAY=",
        "AAAAAQAAADBQYWdpbmF0ZWQgcmVzdWx0IGZyb20gYGxpc3RfdGltZWxvY2tfcHJvcG9zYWxzYC4AAAAAAAAAFFRpbWVsb2NrUHJvcG9zYWxQYWdlAAAAAgAAAElDdXJzb3IgZm9yIHRoZSBuZXh0IHBhZ2UgKGBTb21lKG5leHRfY3Vyc29yKWApLCBvciBgTm9uZWAgaWYgZW5kIHJlYWNoZWQuAAAAAAAAC25leHRfY3Vyc29yAAAAA+gAAAAEAAAAAAAAAAlwcm9wb3NhbHMAAAAAAAPqAAAH0AAAABBUaW1lbG9ja1Byb3Bvc2Fs",
        "AAAABQAAAAAAAAAAAAAAFEJhdGNoUHJvb2ZSZWdpc3RlcmVkAAAAAgAAAAVwcm9vZgAAAAAAAAViYXRjaAAAAAAAAAYAAAAAAAAAA3JlZwAAAAARAAAAAQAAAAAAAAAIYmF0Y2hfaWQAAAPuAAAAIAAAAAEAAAAAAAAAD2NyZWRlbnRpYWxfcm9vdAAAAAPuAAAAIAAAAAAAAAAAAAAABWNvdW50AAAAAAAABAAAAAAAAAAAAAAABHRpZXIAAAAEAAAAAAAAAAAAAAAGc3RhdHVzAAAAAAAEAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAAFE5vblJldm9jYXRpb25DaGVja2VkAAAAAgAAAAZub25yZXYAAAAAAAVjaGVjawAAAAAAAAMAAAAAAAAAD2NyZWRlbnRpYWxfcm9vdAAAAAPuAAAAIAAAAAEAAAAAAAAACW51bGxpZmllcgAAAAAAA+4AAAAgAAAAAAAAAAAAAAAPcmV2b2NhdGlvbl9yb290AAAAA+4AAAAgAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAAFFNlYWxBcHByb3ZhbFJlY29yZGVkAAAAAgAAAARzZWFsAAAAB2FwcHJvdmUAAAAABAAAAAAAAAAIcHJvb2ZfaWQAAAPuAAAAIAAAAAEAAAAAAAAABnNpZ25lcgAAAAAAEwAAAAEAAAAAAAAADnBvbGljeV92ZXJzaW9uAAAAAAAEAAAAAAAAAAAAAAAKZXhwaXJlc19hdAAAAAAABgAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAAFUFkbWluQ291bmNpbENhbmNlbGxlZAAAAAAAAAIAAAAHY291bmNpbAAAAAAKY2FuY2VsX3NldAAAAAAAAgAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAQAAAAAAAAAMY2FuY2VsbGVkX2F0AAAABgAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAAFUNyZWRlbnRpYWxSb290RXhwaXJlZAAAAAAAAAIAAAAIY3JlZHJvb3QAAAAGZXhwaXJlAAAAAAACAAAAAAAAAA9jcmVkZW50aWFsX3Jvb3QAAAAD7gAAACAAAAABAAAAAAAAAApleHBpcmVkX2F0AAAAAAAGAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAAFUNyZWRlbnRpYWxSb290UmV2b2tlZAAAAAAAAAIAAAAIY3JlZHJvb3QAAAAGcmV2b2tlAAAAAAABAAAAAAAAAA9jcmVkZW50aWFsX3Jvb3QAAAAD7gAAACAAAAABAAAAAg==",
        "AAAABQAAAAAAAAAAAAAAFUluc3RhbmNlVFRMTWFpbnRhaW5lZAAAAAAAAAIAAAADdHRsAAAAAAhpbnN0YW5jZQAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAAFUlzc3Vlck1ldGFkYXRhVXBkYXRlZAAAAAAAAAIAAAAGaXNzdWVyAAAAAAAIbWV0YWRhdGEAAAADAAAAAAAAAAZpc3N1ZXIAAAAAABMAAAABAAAAAAAAABZwcmV2aW91c19tZXRhZGF0YV9oYXNoAAAAAAPuAAAAIAAAAAAAAAAAAAAAEW5ld19tZXRhZGF0YV9oYXNoAAAAAAAD7gAAACAAAAAAAAAAAg==",
        "AAAABQAAAAAAAAAAAAAAFU1ldGFkYXRhRW52ZWxvcGVCb3VuZAAAAAAAAAIAAAAIbWV0YWRhdGEAAAAIZW52ZWxvcGUAAAAFAAAAAAAAAAVib3VuZAAAAAAAABEAAAABAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAQAAAAAAAAAHdmVyc2lvbgAAAAAEAAAAAAAAAAAAAAANbWV0YWRhdGFfaGFzaAAAAAAAA+4AAAAgAAAAAAAAAAAAAAAIYm91bmRfYXQAAAAGAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAAFVRpbWVsb2NrRW1lcmdlbmN5RXhlYwAAAAAAAAIAAAAIdGltZWxvY2sAAAAJZW1lcmdlbmN5AAAAAAAABAAAAAAAAAALcHJvcG9zYWxfaWQAAAAABAAAAAEAAAAAAAAABmFjdGlvbgAAAAAABAAAAAAAAAAAAAAAC2V4ZWN1dGVkX2J5AAAAABMAAAABAAAAAAAAAAtleGVjdXRlZF9hdAAAAAAGAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAAFkFkbWluVHJhbnNmZXJDYW5jZWxsZWQAAAAAAAIAAAAFYWRtaW4AAAAAAAAGY2FuY2VsAAAAAAACAAAAAAAAAA1wZW5kaW5nX2FkbWluAAAAAAAAEwAAAAEAAAAAAAAADWN1cnJlbnRfYWRtaW4AAAAAAAATAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAAFkNvdW5jaWxQcm9wb3NhbENyZWF0ZWQAAAAAAAIAAAAHY291bmNpbAAAAAAHcHJvcG9zZQAAAAAGAAAAAAAAAAtwcm9wb3NhbF9pZAAAAAAEAAAAAQAAAAAAAAAGYWN0aW9uAAAAAAAEAAAAAAAAAAAAAAAIcHJvcG9zZXIAAAATAAAAAQAAAAAAAAAGdGFyZ2V0AAAAAAATAAAAAAAAAAAAAAAKY3JlYXRlZF9hdAAAAAAABgAAAAAAAAAAAAAACmV4cGlyZXNfYXQAAAAAAAYAAAAAAAAAAg==",
        "AAAABQAAAI1FbWl0dGVkIG9uIHRoZSBmaXJzdCBzdWNjZXNzZnVsIGNvbW1pdCBmb3IgYSBwcm9vZi4gSWRlbXBvdGVudCByZXRyaWVzCmVtaXQgbm90aGluZywgc28gZXhhY3RseSBvbmUgYFsicmVjZWlwdCIsICJjb21taXQiXWAgZXhpc3RzIHBlciBwcm9vZi4AAAAAAAAAAAAAFlJlY2VpcHREaWdlc3RDb21taXR0ZWQAAAAAAAIAAAAHcmVjZWlwdAAAAAAGY29tbWl0AAAAAAAFAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAQAAAAAAAAAOcmVjZWlwdF9kaWdlc3QAAAAAA+4AAAAgAAAAAAAAAAAAAAAEdGllcgAAAAQAAAAAAAAAAAAAAApwdWJsaWNfa2V5AAAAAAPuAAAAQQAAAAAAAAAAAAAADGNvbW1pdHRlZF9hdAAAAAYAAAAAAAAAAg==",
        "AAAABQAAAAAAAAAAAAAAFlRpbWVzdGFtcENsYWltQW5jaG9yZWQAAAAAAAIAAAAJdGltZXN0YW1wAAAAAAAABmFuY2hvcgAAAAAABgAAAAAAAAAIcHJvb2ZfaWQAAAPuAAAAIAAAAAEAAAAAAAAAEmF0dGVzdGF0aW9uX2RpZ2VzdAAAAAAD7gAAACAAAAAAAAAAAAAAAAdzb3VyY2VzAAAAAAQAAAAAAAAAAAAAAAlhc3N1cmFuY2UAAAAAAAAEAAAAAAAAAAAAAAALYW5jaG9yZWRfYXQAAAAABgAAAAAAAAAAAAAAD2xlZGdlcl9zZXF1ZW5jZQAAAAAEAAAAAAAAAAI=",
        "AAAAAgAAADNWZXJpZmljYXRpb24gc3RhdHVzIHJldHVybmVkIGJ5IGBnZXRfcHJvb2Zfc3RhdHVzYC4AAAAAAAAAABdQcm9vZlZlcmlmaWNhdGlvblN0YXR1cwAAAAAEAAAAAAAAAAAAAAAFVmFsaWQAAAAAAAAAAAAAAAAAAAdSZXZva2VkAAAAAAAAAAAAAAAAB0V4cGlyZWQAAAAAAAAAAAAAAAAITm90Rm91bmQ=",
        "AAAAAQAAAPhJbW11dGFibGUgY29tbWl0bWVudCB0byBhIHNpZ25lZCB2ZXJpZmljYXRpb24gcmVjZWlwdCBmb3Igb25lIHByb29mLgoKUHJpdmFjeTogZXZlcnkgZmllbGQgaXMgYSBjb21taXRtZW50LCBhbiBhZGRyZXNzLCBhbiBpZGVudGlmaWVyLCBvciBhCnRpbWVzdGFtcC4gTm8gcmVjZWlwdCBieXRlcywgbWVkaWEsIG1ldGFkYXRhIGhhc2hlcywgd2l0bmVzcyB2YWx1ZXMsCnNpZ25hdHVyZXMsIG9yIHByaXZhdGUga2V5cyBhcmUgc3RvcmVkLgAAAAAAAAAXUmVjZWlwdENvbW1pdG1lbnRSZWNvcmQAAAAABgAAAAAAAAAMY29tbWl0dGVkX2F0AAAABgAAADxBZGRyZXNzIHRoYXQgYXV0aG9yaXplZCB0aGUgY29tbWl0IChwcm9vZiBzdWJqZWN0IG9yIGFkbWluKS4AAAAMY29tbWl0dGVkX2J5AAAAEwAAAAAAAAAIcHJvb2ZfaWQAAAPuAAAAIAAAAClUaGUgYXR0ZXN0aW5nIHJlY2VpcHQtc2lnbmluZyBwdWJsaWMga2V5LgAAAAAAAApwdWJsaWNfa2V5AAAAAAPuAAAAQQAAADZgc2hhMjU2KGNhbm9uaWNhbF9qc29uKHNpZ25lZF92ZXJpZmljYXRpb25fcmVjZWlwdCkpYC4AAAAAAA5yZWNlaXB0X2RpZ2VzdAAAAAAD7gAAACAAAABBSWRlbnRpdHkgdGllciBvZiB0aGUgY29tbWl0dGVkIHByb29mIGF0IGNvbW1pdCB0aW1lICgxLCAyLCBvciAzKS4AAAAAAAAEdGllcgAAAAQ=",
        "AAAAAQAAATdBIHZlcmlmaWVyJ3MgZGVjbGFyZWQgY2lyY3VpdC12ZXJzaW9uIHdpbmRvdyAoIzM0MykuCgpJbW11dGFibGUgcmVjb3JkIG9mIHdoYXQgdGhlIGFjdGl2ZSB2ZXJpZmllciB3YXMgdG9sZCBpdCBtYXkgY2hlY2ssIHBsdXMKd2hvIGRlY2xhcmVkIGl0IGFuZCB3aGVuLiBXaGVuIG5vIHJlY29yZCBleGlzdHMgdGhlIHdpbmRvdyBpcyB0aGUgZnVsbApidWlsdC1pbiBgW01JTl9TVVBQT1JURURfQ0lSQ1VJVF9WRVJTSU9OLCBNQVhfU1VQUE9SVEVEX0NJUkNVSVRfVkVSU0lPTl1gCnJhbmdlLCB3aGljaCBpcyB0aGUgcHJlLSMzNDMgYmVoYXZpb3VyLgAAAAAAAAAAF1ZlcmlmaWVyQ2lyY3VpdFZlcnNpb25zAAAAAAQAAAAAAAAAC21heF92ZXJzaW9uAAAAAAQAAAAAAAAAC21pbl92ZXJzaW9uAAAAAAQAAAAAAAAABnNldF9hdAAAAAAABgAAAAAAAAAGc2V0X2J5AAAAAAAT",
        "AAAABQAAAAAAAAAAAAAAF0NvdW5jaWxQcm9wb3NhbEFwcHJvdmVkAAAAAAIAAAAHY291bmNpbAAAAAAHYXBwcm92ZQAAAAAEAAAAAAAAAAtwcm9wb3NhbF9pZAAAAAAEAAAAAQAAAAAAAAAGbWVtYmVyAAAAAAATAAAAAQAAAAAAAAAOYXBwcm92YWxfY291bnQAAAAAAAQAAAAAAAAAAAAAAAl0aHJlc2hvbGQAAAAAAAAEAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAAF0NvdW5jaWxQcm9wb3NhbEV4ZWN1dGVkAAAAAAIAAAAHY291bmNpbAAAAAAEZXhlYwAAAAQAAAAAAAAAC3Byb3Bvc2FsX2lkAAAAAAQAAAABAAAAAAAAAAZhY3Rpb24AAAAAAAQAAAAAAAAAAAAAAAtleGVjdXRlZF9ieQAAAAATAAAAAQAAAAAAAAALZXhlY3V0ZWRfYXQAAAAABgAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAAF1JlY2VpcHRTaWduZXJSZXZvY2F0aW9uAAAAAAIAAAAGc2lnbmVyAAAAAAAGcmV2b2tlAAAAAAACAAAAAAAAAApwdWJsaWNfa2V5AAAAAAPuAAAAQQAAAAEAAAAAAAAACnJldm9rZWRfYXQAAAAAAAYAAAAAAAAAAg==",
        "AAAABQAAAAAAAAAAAAAAF1RpbWVsb2NrUHJvcG9zYWxDcmVhdGVkAAAAAAIAAAAIdGltZWxvY2sAAAAHcHJvcG9zZQAAAAAGAAAAAAAAAAtwcm9wb3NhbF9pZAAAAAAEAAAAAQAAAAAAAAAGYWN0aW9uAAAAAAAEAAAAAAAAAAAAAAAIcHJvcG9zZXIAAAATAAAAAQAAAAAAAAAGdGFyZ2V0AAAAAAATAAAAAAAAAAAAAAAKY3JlYXRlZF9hdAAAAAAABgAAAAAAAAAAAAAAEG1pbl9leGVjdXRpb25fYXQAAAAGAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAAGENvdW5jaWxQcm9wb3NhbENhbmNlbGxlZAAAAAIAAAAHY291bmNpbAAAAAAGY2FuY2VsAAAAAAADAAAAAAAAAAtwcm9wb3NhbF9pZAAAAAAEAAAAAQAAAAAAAAAMY2FuY2VsbGVkX2J5AAAAEwAAAAEAAAAAAAAADGNhbmNlbGxlZF9hdAAAAAYAAAAAAAAAAg==",
        "AAAABQAAAAAAAAAAAAAAGE1ldGFkYXRhRW52ZWxvcGVVcGdyYWRlZAAAAAIAAAAIbWV0YWRhdGEAAAAIZW52ZWxvcGUAAAAFAAAAAAAAAAh1cGdyYWRlZAAAABEAAAABAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAQAAAAAAAAAIcHJldmlvdXMAAAAEAAAAAAAAAAAAAAAHY3VycmVudAAAAAAEAAAAAAAAAAAAAAANbWV0YWRhdGFfaGFzaAAAAAAAA+4AAAAgAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAAGFNlYWxQb2xpY3lDYW5jZWxsZWRFdmVudAAAAAIAAAAIc2VhbF9wb2wAAAAGY2FuY2VsAAAAAAABAAAAAAAAAAd2ZXJzaW9uAAAAAAQAAAABAAAAAg==",
        "AAAABQAAAAAAAAAAAAAAGFRpbWVsb2NrUHJvcG9zYWxFeGVjdXRlZAAAAAIAAAAIdGltZWxvY2sAAAAEZXhlYwAAAAQAAAAAAAAAC3Byb3Bvc2FsX2lkAAAAAAQAAAABAAAAAAAAAAZhY3Rpb24AAAAAAAQAAAAAAAAAAAAAAAtleGVjdXRlZF9ieQAAAAATAAAAAQAAAAAAAAALZXhlY3V0ZWRfYXQAAAAABgAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAAGVNvdXJjZUJhdGNoUm9vdFJlZ2lzdGVyZWQAAAAAAAACAAAABWJhdGNoAAAAAAAABHJvb3QAAAAFAAAAAAAAAARyb290AAAD7gAAACAAAAABAAAAAAAAAAZzb3VyY2UAAAAAABMAAAABAAAAAAAAAAVjb3VudAAAAAAAAAQAAAAAAAAAAAAAAA1tZXRhZGF0YV9oYXNoAAAAAAAD7gAAACAAAAAAAAAAAAAAAA1yZWdpc3RlcmVkX2F0AAAAAAAABgAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAAGVRpbWVsb2NrUHJvcG9zYWxDYW5jZWxsZWQAAAAAAAACAAAACHRpbWVsb2NrAAAABmNhbmNlbAAAAAAABAAAAAAAAAALcHJvcG9zYWxfaWQAAAAABAAAAAEAAAAAAAAABmFjdGlvbgAAAAAABAAAAAAAAAAAAAAADGNhbmNlbGxlZF9ieQAAABMAAAABAAAAAAAAAAxjYW5jZWxsZWRfYXQAAAAGAAAAAAAAAAI=",
        "AAAABQAAAAAAAAAAAAAAGVZlcmlmaWVyUm90YXRpb25BY3RpdmF0ZWQAAAAAAAACAAAABXZlcmlmAAAAAAAACGFjdGl2YXRlAAAAAwAAAAAAAAAPYWN0aXZlX3ZlcmlmaWVyAAAAABMAAAABAAAAAAAAABFwcmV2aW91c192ZXJpZmllcgAAAAAAABMAAAAAAAAAAAAAABNyb2xsYmFja193aW5kb3dfZW5kAAAAAAYAAAAAAAAAAg==",
        "AAAABQAAAAAAAAAAAAAAGVZlcmlmaWVyUm90YXRpb25TY2hlZHVsZWQAAAAAAAACAAAABXZlcmlmAAAAAAAACHNjaGVkdWxlAAAABQAAAAAAAAAPYWN0aXZlX3ZlcmlmaWVyAAAAABMAAAABAAAAAAAAABBwZW5kaW5nX3ZlcmlmaWVyAAAAEwAAAAAAAAAAAAAAEWFjdGl2YXRpb25fbGVkZ2VyAAAAAAAABgAAAAAAAAAAAAAADm92ZXJsYXBfd2luZG93AAAAAAAGAAAAAAAAAAAAAAAPcm9sbGJhY2tfd2luZG93AAAAAAYAAAAAAAAAAg==",
        "AAAABQAAAEdFbWl0dGVkIHdoZW4gYSByb3RhdGlvbiBncmFjZSB3aW5kb3cgaXMgc2V0dGxlZCBhZnRlciBpdCBsYXBzZXMgKCMzMjMpLgAAAAAAAAAAGklzc3VlclJvdGF0aW9uR3JhY2VFeHBpcmVkAAAAAAACAAAABmlzc3VlcgAAAAAABWdyYWNlAAAAAAAAAwAAAAAAAAAGaXNzdWVyAAAAAAATAAAAAQAAAAAAAAAScmVwbGFjZW1lbnRfaXNzdWVyAAAAAAATAAAAAAAAAAAAAAAQZ3JhY2VfZXhwaXJlc19hdAAAAAYAAAAAAAAAAg==",
        "AAAABQAAAJVFbWl0dGVkIHdoZW4gdGhlIGFkbWluIG5hcnJvd3Mgb3Igd2lkZW5zIHRoZSBhY3RpdmUgdmVyaWZpZXIncyBzdXBwb3J0ZWQKY2lyY3VpdC12ZXJzaW9uIHdpbmRvdyAoIzM0MykuIFZlcnNpb24gbnVtYmVycyBvbmx5IOKAlCBubyB3aXRuZXNzIG1hdGVyaWFsLgAAAAAAAAAAAAAaVmVyaWZpZXJDaXJjdWl0VmVyc2lvbnNTZXQAAAAAAAIAAAAFdmVyaWYAAAAAAAAIdmVyc2lvbnMAAAADAAAAAAAAAAh2ZXJpZmllcgAAABMAAAABAAAAAAAAAAttaW5fdmVyc2lvbgAAAAAEAAAAAAAAAAAAAAALbWF4X3ZlcnNpb24AAAAABAAAAAAAAAAC",
        "AAAABQAAAAAAAAAAAAAAGlZlcmlmaWVyUm90YXRpb25Sb2xsZWRCYWNrAAAAAAACAAAABXZlcmlmAAAAAAAACHJvbGxiYWNrAAAAAgAAAAAAAAAPYWN0aXZlX3ZlcmlmaWVyAAAAABMAAAABAAAAAAAAABFwcmV2aW91c192ZXJpZmllcgAAAAAAABMAAAAAAAAAAg==",
        "AAAABQAAAAAAAAAAAAAAG1NlbGVjdGl2ZURpc2Nsb3N1cmVWZXJpZmllZAAAAAACAAAAB3NlbGRpc2MAAAAABnZlcmlmeQAAAAAABAAAAAAAAAALc2NoZW1hX2hhc2gAAAAD7gAAACAAAAABAAAAAAAAAA9jcmVkZW50aWFsX3Jvb3QAAAAD7gAAACAAAAAAAAAAAAAAAAludWxsaWZpZXIAAAAAAAPuAAAAIAAAAAAAAAAAAAAAD2V2aWRlbmNlX2RpZ2VzdAAAAAPuAAAAIAAAAAAAAAAC",
        "AAAAAAAAAAAAAAAEaW5pdAAAAAEAAAAAAAAABWFkbWluAAAAAAAAEwAAAAA=",
        "AAAAAAAAAfdQYXVzZSBvbmUgb3IgbW9yZSByZWdpc3RyYXRpb24gZG9tYWlucyAoYFBBVVNFX0RPTUFJTl8qYCwgb3IgdGhlaXIKYml0d2lzZS1PUiBjb21iaW5hdGlvbikgZm9yIGBkdXJhdGlvbl9zZWNzYC4gQ2FsbGFibGUgYnkgdGhlIGFkbWluIG9yCnRoZSBndWFyZGlhbjsgdGhlIGFkbWluIGlzIGNhcHBlZCBhdCBgTUFYX1BBVVNFX0RVUkFUSU9OX1NFQ1NgLCB0aGUKZ3VhcmRpYW4gYXQgYE1BWF9HVUFSRElBTl9QQVVTRV9EVVJBVElPTl9TRUNTYC4gUmUtcGF1c2luZyBhbgphbHJlYWR5LXBhdXNlZCBkb21haW4gZXh0ZW5kcyAob3ZlcndyaXRlcykgaXRzIGV4cGlyeSByYXRoZXIgdGhhbgplcnJvcmluZywgc28gcmV0cmllcyBhcmUgaWRlbXBvdGVudC4gUmVhZHMgYW5kIG5vbi1yZWdpc3RyYXRpb24gYWRtaW4KZW50cnkgcG9pbnRzIGFyZSBuZXZlciBhZmZlY3RlZC4gUmV0dXJucyB0aGUgZXBvY2gtc2Vjb25kIHRpbWVzdGFtcAphdCB3aGljaCB0aGUgcGF1c2UgYXV0by1leHBpcmVzLgAAAAAFcGF1c2UAAAAAAAADAAAAAAAAAAZjYWxsZXIAAAAAABMAAAAAAAAABmRvbWFpbgAAAAAABAAAAAAAAAANZHVyYXRpb25fc2VjcwAAAAAAAAYAAAABAAAABg==",
        "AAAAAAAAAMdMaWZ0IGEgcGF1c2UgZWFybHkuIEFkbWluLW9ubHkg4oCUIGEgZ3VhcmRpYW4gY2FuIHJhaXNlIHRoZSBhbGFybSBidXQKb25seSB0aGUgYWRtaW4gY2FuIHN0YW5kIGl0IGRvd24gYmVmb3JlIHRoZSBib3VuZGVkIGV4cGlyeS4gVW5wYXVzaW5nCmEgZG9tYWluIHRoYXQgaXMgbm90IGN1cnJlbnRseSBzdG9yZWQgYXMgcGF1c2VkIGlzIGEgbm8tb3AuAAAAAAd1bnBhdXNlAAAAAAIAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAAGZG9tYWluAAAAAAAEAAAAAA==",
        "AAAAAAAAAChSZXR1cm4gdGhlIGNyYXRlIHBhY2thZ2UgdmVyc2lvbiBzdHJpbmcuAAAAB3ZlcnNpb24AAAAAAAAAAAEAAAAQ",
        "AAAAAAAAAFBSZWFkLW9ubHkgY2hlY2sgd2hldGhlciBgYWRkcmAgY3VycmVudGx5IGhvbGRzIHJlZ2lzdHJ5IGFkbWluaXN0cmF0b3IgYXV0aG9yaXR5LgAAAAhpc19hZG1pbgAAAAEAAAAAAAAABGFkZHIAAAATAAAAAQAAAAE=",
        "AAAAAAAAADFSZXR1cm4gdGhlIGN1cnJlbnQgYWRtaW4gYWRkcmVzcywgaWYgaW5pdGlhbGl6ZWQuAAAAAAAACWdldF9hZG1pbgAAAAAAAAAAAAABAAAD6AAAABM=",
        "AAAAAAAAAAAAAAAJZ2V0X3Byb29mAAAAAAAAAQAAAAAAAAAIcHJvb2ZfaWQAAAPuAAAAIAAAAAEAAAPoAAAH0AAAAAtQcm9vZlJlY29yZAA=",
        "AAAAAAAAAPdSZWFkLW9ubHkgY2hlY2sgd2hldGhlciBgYWRkcmAgY3VycmVudGx5IGhvbGRzIGFjdGl2ZSBpc3N1ZXIgYXV0aG9yaXR5LgoKQWRtaW4gYW5kIGFjdGl2ZSBpc3N1ZXIgcm9sZXMgYXJlIGRpc2pvaW50OiBldmVuIGlmIGEgbGVnYWN5IFYxIHJlY29yZApleGlzdHMgb24gdGhlIGN1cnJlbnQgYWRtaW4gYWRkcmVzcyBiZWZvcmUgYHVwZ3JhZGVfc3RvcmFnZWAgcnVucywgaXQKY2Fubm90IGV4ZXJjaXNlIGlzc3VlciBhdXRob3JpdHkuAAAAAAlpc19pc3N1ZXIAAAAAAAABAAAAAAAAAARhZGRyAAAAEwAAAAEAAAAB",
        "AAAAAAAAAL9SZWFkLW9ubHk6IGlzIGFueSBiaXQgb2YgYGRvbWFpbmAgY3VycmVudGx5IHBhdXNlZCAoaS5lLiBoYXMgYW4KdW5leHBpcmVkIHBhdXNlIHJlY29yZCk/IEEgZG9tYWluIHBhc3QgaXRzIGBleHBpcmVzX2F0YCBpcyB0cmVhdGVkIGFzCnVucGF1c2VkIGV2ZW4gaWYgYSBzdGFsZSByZWNvcmQgaGFzIG5vdCB5ZXQgYmVlbiBjbGVhcmVkLgAAAAAJaXNfcGF1c2VkAAAAAAAAAQAAAAAAAAAGZG9tYWluAAAAAAAEAAAAAQAAAAE=",
        "AAAAAAAAAAAAAAAKYWRkX2lzc3VlcgAAAAAAAwAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAAZpc3N1ZXIAAAAAABMAAAAAAAAADW1ldGFkYXRhX2hhc2gAAAAAAAPuAAAAIAAAAAA=",
        "AAAAAAAAAAAAAAAKYWRkX3NjaGVtYQAAAAAABQAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAAtzY2hlbWFfaGFzaAAAAAPuAAAAIAAAAAAAAAAQaXNzdWVyX25hbWVzcGFjZQAAA+4AAAAgAAAAAAAAAAd2ZXJzaW9uAAAAAAQAAAAAAAAAD2F0dHJpYnV0ZV9jb3VudAAAAAAEAAAAAA==",
        "AAAAAAAAARxSZXR1cm4gdGhlIHJlZ2lzdHJ5J3Mgb3BlcmF0aW9uYWwgY29uZmlndXJhdGlvbiBpbiBvbmUgcmVhZC1vbmx5IGNhbGwgKCM3MjEpLgoKU2FmZSB0byBjYWxsIGJvdGggYmVmb3JlIGFuZCBhZnRlciBgaW5pdGAuIEV2ZXJ5IGZpZWxkIG1hdGNoZXMgdGhlCmNvcnJlc3BvbmRpbmcgaW5kaXZpZHVhbCBnZXR0ZXIsIGFuZCBgcGF1c2VkX2RvbWFpbnNgIGlzIHRoZSBiaXR3aXNlLU9SCm9mIGFsbCByZWdpc3RyYXRpb24gZG9tYWlucyB0aGF0IGFyZSBjdXJyZW50bHkgcGF1c2VkICh1bmV4cGlyZWQpLgAAAApnZXRfY29uZmlnAAAAAAAAAAAAAQAAB9AAAAAOUmVnaXN0cnlDb25maWcAAA==",
        "AAAAAAAAAAAAAAAKZ2V0X2lzc3VlcgAAAAAAAQAAAAAAAAAGaXNzdWVyAAAAAAATAAAAAQAAA+gAAAfQAAAADElzc3VlclJlY29yZA==",
        "AAAAAAAAAAAAAAAKZ2V0X3NjaGVtYQAAAAAAAQAAAAAAAAALc2NoZW1hX2hhc2gAAAAD7gAAACAAAAABAAAD6AAAB9AAAAAMU2NoZW1hUmVjb3Jk",
        "AAAAAAAAACxSZXRyaWV2ZSBhIGRpc3B1dGUgcmVjb3JkIGJ5IGl0cyBkaXNwdXRlX2lkLgAAAAtnZXRfZGlzcHV0ZQAAAAABAAAAAAAAAApkaXNwdXRlX2lkAAAAAAPuAAAAIAAAAAEAAAPoAAAH0AAAAA1EaXNwdXRlUmVjb3JkAAAA",
        "AAAAAAAAAAAAAAALZ2V0X2xpbmVhZ2UAAAAAAQAAAAAAAAANb3V0cHV0X2RpZ2VzdAAAAAAAA+4AAAAgAAAAAQAAA+gAAAfQAAAADUxpbmVhZ2VSZWNvcmQAAAA=",
        "AAAAAAAAAAAAAAAMYWNjZXB0X2FkbWluAAAAAQAAAAAAAAANcGVuZGluZ19hZG1pbgAAAAAAABMAAAAA",
        "AAAAAAAAAFdSZWNvcmQgYW4gYXV0aG9yaXplZCBzaWduZXIncyBhcHByb3ZhbCBmb3IgYSB0aHJlc2hvbGQgc2VhbCBhbmQgZmluYWxpemUgaWYgbWV0ICgjMTI0KS4AAAAADGFwcHJvdmVfc2VhbAAAAAQAAAAAAAAABnNpZ25lcgAAAAAAEwAAAAAAAAAIcHJvb2ZfaWQAAAPuAAAAIAAAAAAAAAAKdmlkZW9faGFzaAAAAAAD7gAAACAAAAAAAAAADW1ldGFkYXRhX2hhc2gAAAAAAAPuAAAAIAAAAAEAAAAB",
        "AAAAAAAAAAAAAAAMZXhwaXJlX3Byb29mAAAAAwAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAAAAAAtyZWFzb25fY29kZQAAAAAEAAAAAA==",
        "AAAAAAAAAAAAAAAMZ2V0X2J5X3ZpZGVvAAAAAQAAAAAAAAAKdmlkZW9faGFzaAAAAAAD7gAAACAAAAABAAAD6AAAB9AAAAALUHJvb2ZSZWNvcmQA",
        "AAAAAAAAACpUaGUgY3VycmVudGx5IGNvbmZpZ3VyZWQgZ3VhcmRpYW4sIGlmIGFueS4AAAAAAAxnZXRfZ3VhcmRpYW4AAAAAAAAAAQAAA+gAAAAT",
        "AAAAAAAAAAAAAAAMZ2V0X3ZlcmlmaWVyAAAAAAAAAAEAAAPoAAAAEw==",
        "AAAAAAAAAu5PcGVuIGEgbmV3IGRpc3B1dGUgYWdhaW5zdCBhIHJlZ2lzdGVyZWQgcHJvb2YuCgojIFBhcmFtZXRlcnMKLSBgcmVwb3J0ZXJgOiAgICAgICAgVGhlIHJlcG9ydGVyJ3MgYWRkcmVzcyAocmVxdWlyZXMgYXV0aDsgcHJvdmVzIGxpdmVuZXNzKS4KLSBgcmVwb3J0ZXJfaGFzaGA6ICAgUHJpdmFjeS1zYWZlIGNvbW1pdG1lbnQgSChyZXBvcnRlcl9hZGRyZXNzIHx8IHByb29mX2lkKSwKY29tcHV0ZWQgb2ZmLWNoYWluIGJ5IHRoZSByZXBvcnRlci4gVGhlIHJhdyByZXBvcnRlciBhZGRyZXNzIGlzIG5ldmVyCnN0b3JlZCBpbiBjb250cmFjdCBzdGF0ZSBvciBldmVudHMuCi0gYGRpc3B1dGVfaWRgOiAgICAgIENhbGxlci1jaG9zZW4gMzItYnl0ZSB1bmlxdWUgaWRlbnRpZmllci4KLSBgcHJvb2ZfaWRgOiAgICAgICAgVGhlIHByb29mIGJlaW5nIGNoYWxsZW5nZWQuCi0gYHJlYXNvbmA6ICAgICAgICAgIENhdGVnb3Jpc2VkIGRpc3B1dGUgcmVhc29uLgotIGBjb21taXRtZW50X2hhc2hgOiBPZmYtY2hhaW4gY29tbWl0bWVudCB0byB0aGUgcmVwb3J0ZXIncyBzdWJtaXNzaW9uLgoKIyBHdWFyZHMKLSBQcm9vZiBtdXN0IGV4aXN0LgotIGBkaXNwdXRlX2lkYCBtdXN0IG5vdCBhbHJlYWR5IGJlIHVzZWQuCi0gUHJvb2YgbXVzdCBoYXZlIGZld2VyIHRoYW4gYE1BWF9PUEVOX0RJU1BVVEVTX1BFUl9QUk9PRmAgb3BlbiBkaXNwdXRlcy4KLSBSZXBvcnRlciBtdXN0IG5vdCBiZSBvbiBjb29sZG93biBmb3IgdGhpcyBwcm9vZi4AAAAAAAxvcGVuX2Rpc3B1dGUAAAAGAAAAAAAAAAhyZXBvcnRlcgAAABMAAAAAAAAADXJlcG9ydGVyX2hhc2gAAAAAAAPuAAAAIAAAAAAAAAAKZGlzcHV0ZV9pZAAAAAAD7gAAACAAAAAAAAAACHByb29mX2lkAAAD7gAAACAAAAAAAAAABnJlYXNvbgAAAAAH0AAAAA1EaXNwdXRlUmVhc29uAAAAAAAAAAAAAA9jb21taXRtZW50X2hhc2gAAAAD7gAAACAAAAABAAAH0AAAAA1EaXNwdXRlUmVjb3JkAAAA",
        "AAAAAAAAAAAAAAAMcmV2b2tlX3Byb29mAAAAAgAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAA==",
        "AAAAAAAAAJ1Bc3NpZ24gdGhlIGFkZHJlc3MgcGVybWl0dGVkIHRvIHRyaWdnZXIgZW1lcmdlbmN5IHBhdXNlcyB3aXRob3V0CmhvbGRpbmcgdGhlIGFkbWluIGtleS4gQWRtaW4tb25seS4gUGFzcyB0aGUgYWRtaW4ncyBvd24gYWRkcmVzcyB0bwpyZXZva2UgdGhlIGd1YXJkaWFuIHJvbGUuAAAAAAAADHNldF9ndWFyZGlhbgAAAAIAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAAIZ3VhcmRpYW4AAAATAAAAAA==",
        "AAAAAAAAAAAAAAAMc2V0X3ZlcmlmaWVyAAAAAgAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAAh2ZXJpZmllcgAAABMAAAAA",
        "AAAAAAAAAAAAAAAMdmVyaWZ5X3Byb29mAAAAAwAAAAAAAAAFYWN0b3IAAAAAAAATAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAAAAAAtyZWFzb25fY29kZQAAAAAEAAAAAA==",
        "AAAAAAAAAAAAAAANY29ycmVjdF9wcm9vZgAAAAAAAAQAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAAIcHJvb2ZfaWQAAAPuAAAAIAAAAAAAAAARbmV3X21ldGFkYXRhX2hhc2gAAAAAAAPuAAAAIAAAAAAAAAALcmVhc29uX2NvZGUAAAAABAAAAAA=",
        "AAAAAAAAAFtFeHBsaWNpdGx5IGZpbmFsaXplIGEgdGhyZXNob2xkIHNlYWwgb25jZSB2YWxpZCBhcHByb3ZhbHMgbWVldCB0aGUgcG9saWN5IHRocmVzaG9sZCAoIzEyNCkuAAAAAA1maW5hbGl6ZV9zZWFsAAAAAAAAAwAAAAAAAAAIcHJvb2ZfaWQAAAPuAAAAIAAAAAAAAAAKdmlkZW9faGFzaAAAAAAD7gAAACAAAAAAAAAADW1ldGFkYXRhX2hhc2gAAAAAAAPuAAAAIAAAAAEAAAfQAAAAC1Byb29mUmVjb3JkAA==",
        "AAAAAAAAAAAAAAANZ2V0X3Byb29mX3R0bAAAAAAAAAAAAAABAAAABg==",
        "AAAAAAAAAAAAAAANaGFzX251bGxpZmllcgAAAAAAAAIAAAAAAAAACHZlcmlmaWVyAAAAEwAAAAAAAAAJbnVsbGlmaWVyAAAAAAAD7gAAACAAAAABAAAAAQ==",
        "AAAAAAAAAAAAAAANcHJvcG9zZV9hZG1pbgAAAAAAAAIAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAANcGVuZGluZ19hZG1pbgAAAAAAABMAAAAA",
        "AAAAAAAAAAAAAAANcmVnaXN0ZXJfc2VhbAAAAAAAAAQAAAAAAAAABmlzc3VlcgAAAAAAEwAAAAAAAAAKdmlkZW9faGFzaAAAAAAD7gAAACAAAAAAAAAADW1ldGFkYXRhX2hhc2gAAAAAAAPuAAAAIAAAAAAAAAAIcHJvb2ZfaWQAAAPuAAAAIAAAAAEAAAfQAAAAC1Byb29mUmVjb3JkAA==",
        "AAAAAAAAAAAAAAANcmV2b2tlX2lzc3VlcgAAAAAAAAIAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAAGaXNzdWVyAAAAAAATAAAAAA==",
        "AAAAAAAAAQ9SZXZva2UgbXVsdGlwbGUgcHJvb2ZzIGluIGEgc2luZ2xlIHRyYW5zYWN0aW9uIGR1cmluZyBpbmNpZGVudCByZXNwb25zZS4KClJldXNlcyB0aGUgc2luZ2xlLXJldm9rZSBwYXRoIHNvIGhpc3RvcnkgZW50cmllcyBhbmQgZXZlbnRzIGFyZSBpZGVudGljYWwgcGVyIHByb29mLgpCb3VuZGVkIGJ5IFtgTUFYX1JFVk9LRV9QUk9PRlNfQkFUQ0hfU0laRWBdIGFnYWluc3QgdGhlIGV4ZWN1dGlvbiBidWRnZXQuCkZhaWxzIGF0b21pY2FsbHkgb24gYW55IGludmFsaWQgcHJvb2YuAAAAAA1yZXZva2VfcHJvb2ZzAAAAAAAAAwAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAAlwcm9vZl9pZHMAAAAAAAPqAAAD7gAAACAAAAAAAAAAC3JlYXNvbl9jb2RlAAAAAAQAAAAA",
        "AAAAAAAABABSb3RhdGUgYW4gYWN0aXZlIGlzc3VlciBrZXkgdG8gYSByZXBsYWNlbWVudCwgb3BlbmluZyBhIGJvdW5kZWQgZ3JhY2UKd2luZG93IG92ZXIgdGhlIHJldGlyaW5nIGtleSdzIHByZS1yb3RhdGlvbiBldmlkZW5jZSAoIzMyMykuCgpBZG1pbi1vbmx5LiBgcHJldmlvdXNfaXNzdWVyYCBhbmQgYHJlcGxhY2VtZW50X2lzc3VlcmAgbXVzdCBiZSBkaXN0aW5jdCwKYm90aCByZWdpc3RlcmVkLCBhbmQgYm90aCBhY3RpdmUuIFRoZSByb3RhdGlvbiByZXRpcmVzIGBwcmV2aW91c19pc3N1ZXJgCmltbWVkaWF0ZWx5IOKAlCBpdCBjYW4gbm8gbG9uZ2VyIHNpZ24gbmV3IHNlYWxzLCBkaXJlY3RseSBvciB0aHJvdWdoIGEKZGVsZWdhdGlvbiDigJQgd2hpbGUgdGhlIGV2aWRlbmNlIGl0IGFscmVhZHkgc2lnbmVkIHN0YXlzIHZlcmlmaWFibGUgdW50aWwKYGdyYWNlX2V4cGlyZXNfYXRgLCBhZnRlciB3aGljaCBbYFNlbGY6OmlzX2lzc3Vlcl92ZXJpZmlhYmxlYF0gZmFpbHMKY2xvc2VkLgoKYGdyYWNlX3NlY3MgPT0gMGAgc2VsZWN0cyBbYERFRkFVTFRfSVNTVUVSX1JPVEFUSU9OX0dSQUNFX1NFQ1NgXS4KUmV0dXJucyB0aGUgYWJzb2x1dGUgYGdyYWNlX2V4cGlyZXNfYXRgIHNvIGEgY2FsbGVyIGNhbiByZWNvcmQgdGhlCmRlYWRsaW5lIHdpdGhvdXQgcmUtcmVhZGluZyBzdG9yYWdlLiBUaGUgd2luZG93IGlzIGxhenkg4oCUIGl0IGxhcHNlcyB3aXRoCm5vIHRyYW5zYWN0aW9uIOKAlCBhbmQgW2BTZWxmOjpmaW5hbGl6ZV9pc3N1ZXJfcm90YXRpb25gXSBzZXR0bGVzIHRoZQpyZWNvcmQgYWZ0ZXJ3YXJkcy4KCiMgUmV2ZXJ0cwoKLSBgVW5hdXRob3JpemVkYCAgICAgICAgICAgICAgIGlmIHRoZSBjYWxsZXIgaXMgbm90IHRoZSBhZG1pbgotIGBJbnZhbGlkSXNzdWVyUm90YXRpb25gICAgICAgaWYgcHJldmlvdXMgYW5kIHJlcGxhY2VtZW50IGFyZSBlcXVhbAotIGBVbmtub3duSXNzdWVyYCAgICAgICAgICAgICAgaWYgZWl0aGVyIGtleSBpcyBhYnNlbnQgb3IgaW5hY3RpdmUKLSBgSW52YWxpZElzc3VlAAAADXJvdGF0ZV9pc3N1ZXIAAAAAAAAEAAAAAAAAAAVhZG1pbgAAAAAAABMAAAAAAAAAD3ByZXZpb3VzX2lzc3VlcgAAAAATAAAAAAAAABJyZXBsYWNlbWVudF9pc3N1ZXIAAAAAABMAAAAAAAAACmdyYWNlX3NlY3MAAAAAAAYAAAABAAAABg==",
        "AAAAAAAAAAAAAAANc2V0X3Byb29mX3R0bAAAAAAAAAIAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAAIdHRsX3NlY3MAAAAGAAAAAA==",
        "AAAAAAAAADVSZW1vdmUgdGhlIGVtZXJnZW5jeS1wYXVzZSBndWFyZGlhbiByb2xlLiBBZG1pbi1vbmx5LgAAAAAAAA5jbGVhcl9ndWFyZGlhbgAAAAAAAQAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAA==",
        "AAAAAAAAANNSZWFkLW9ubHk6IHRoZSByYXcgZGVsZWdhdGlvbiByZWNvcmQsIGlmIG9uZSBpcyBzdG9yZWQuIEEgcmVjb3JkIHBhc3QKaXRzIGBleHBpcmVzX2F0YCBpcyBzdGlsbCByZXR1cm5lZCBzbyBvcGVyYXRvcnMgY2FuIHNlZSBhbmQgcHJ1bmUgaXQ7CnVzZSBgaXNfZGVsZWdhdGlvbl9hY3RpdmVgIHRvIGFzayB3aGV0aGVyIGl0IGN1cnJlbnRseSBncmFudHMgYW55dGhpbmcuAAAAAA5nZXRfZGVsZWdhdGlvbgAAAAAAAgAAAAAAAAAHZ3JhbnRvcgAAAAATAAAAAAAAAAhkZWxlZ2F0ZQAAABMAAAABAAAD6AAAB9AAAAAQRGVsZWdhdGlvblJlY29yZA==",
        "AAAAAAAAA+xSZXR1cm4gYSBib3VuZGVkLCBzdGFibGUgcGFnZSBvZiB0aGUgY3VycmVudCB2ZXJpZmllciBjb25maWd1cmF0aW9uLgoKU2xvdHMgYXJlIG9yZGVyZWQ6ICoqQWN0aXZlIOKGkiBQZW5kaW5nIOKGkiBQcmV2aW91cyoqLiBPbmx5IG5vbi1Ob25lCnNsb3RzIGFwcGVhciBpbiBgZW50cmllc2AuIGBjdXJzb3JgIGlzIGEgMC1iYXNlZCBzbG90IGluZGV4OyBwYXNzCmBuZXh0X2N1cnNvcmAgZnJvbSB0aGUgcHJldmlvdXMgcmVzcG9uc2UgdG8gY29udGludWUgcGFnaW5nLgoKIyBBcmd1bWVudHMKCiogYGN1cnNvcmAg4oCTIHN0YXJ0aW5nIHNsb3QgaW5kZXggKDAgPSBmaXJzdCBwb3B1bGF0ZWQgc2xvdCkuIEEgY3Vyc29yCmJleW9uZCB0aGUgZW5kIG9mIHRoZSBwb3B1bGF0ZWQgbGlzdCByZXR1cm5zIGFuIGVtcHR5IHBhZ2UuCiogYGxpbWl0YCAg4oCTIG1heGltdW0gZW50cmllcyBwZXIgcGFnZS4gTXVzdCBiZSBub24temVybyBhbmQgYXQgbW9zdApgTUFYX1ZFUklGSUVSX0xJU1RfTElNSVRgLiBSZXR1cm5zIGBMaXN0TGltaXRFeGNlZWRlZGAgb3RoZXJ3aXNlLgoKIyBQcml2YWN5CgpUaGlzIGlzIGEgcmVhZC1vbmx5IHF1ZXJ5IGVxdWl2YWxlbnQgdG8gYGdldF92ZXJpZmllcmAg4oCUIG5vIHByaXZhdGUKd2l0bmVzcyB2YWx1ZXMsIGNyZWRlbnRpYWwgc2VjcmV0cywgbnVsbGlmaWVycywgb3IgdmlkZW8gaGFzaGVzIGFyZQpzdXJmYWNlZC4gQW4gb3V0LW9mLXJhbmdlIGN1cnNvciBwcm9kdWNlcyBhbiBlbXB0eSBwYWdlIHJhdGhlciB0aGFuIGEKcmV2ZWFsaW5nIGVycm9yLCBzbyBhIHNjYW5uZXIgY2Fubm90IGVudW1lcmF0ZSBjYXBhY2l0eSBieSBwcm9iaW5nLgoKIyBNaWdyYXRpb24gLyBjb21wYXRpYmlsaXR5CgpBZGRpdGl2ZTogYmVmb3JlIGFueSB2ZXJpZmllciBpcyBjb25maWd1cmVkLCByZXR1cm5zIGFuIGVtcHR5IHBhZ2UuCkNhbGxlcnMgdGhhdCBvbmx5IG5lZWQgdGhlIGFjdGl2ZSB2ZXJpZmllciBzaG91bGQgdXNlIGBnZXRfdmVyaWZpZXJgLgAAAA5saXN0X3ZlcmlmaWVycwAAAAAAAgAAAAAAAAAGY3Vyc29yAAAAAAAEAAAAAAAAAAVsaW1pdAAAAAAAAAQAAAABAAAH0AAAAAxWZXJpZmllclBhZ2U=",
        "AAAAAAAAAKFEaXNtaXNzIGEgZGlzcHV0ZSAoYWRtaW4gb25seSkuCgpEaXNtaXNzYWwgaXMgdmFsaWQgZnJvbSBib3RoIGBPcGVuYCBhbmQgYFJlc3BvbmRlZGAgc3RhdGVzLiBBIGRpc21pc3NlZApkaXNwdXRlIGlzIHBlcm1hbmVudGx5IGNsb3NlZCB3aXRoIG5vIGNvcnJlY3RpdmUgYWN0aW9uLgAAAAAAAA9kaXNtaXNzX2Rpc3B1dGUAAAAAAgAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAApkaXNwdXRlX2lkAAAAAAPuAAAAIAAAAAEAAAfQAAAADURpc3B1dGVSZWNvcmQAAAA=",
        "AAAAAAAAALBSZWFkLW9ubHk6IHRoZSByYXcgcGF1c2UgcmVjb3JkIGZvciBhIHNpbmdsZSBkb21haW4gYml0LCBpZiBvbmUgaXMKY3VycmVudGx5IHN0b3JlZCAoaW5jbHVkaW5nIGEgc3RhbGUgcmVjb3JkIHBhc3QgaXRzIGBleHBpcmVzX2F0YAp0aGF0IGhhcyBub3QgeWV0IGJlZW4gY2xlYXJlZCBieSBgdW5wYXVzZWApLgAAAA9nZXRfcGF1c2Vfc3RhdGUAAAAAAQAAAAAAAAAGZG9tYWluAAAAAAAEAAAAAQAAA+gAAAfQAAAAC1BhdXNlUmVjb3JkAA==",
        "AAAAAAAAAGRHZXQgdGhlIGN1cnJlbnQgZXBvY2ggZm9yIGEgZ2l2ZW4gc2NvcGUuClJldHVybnMgYERFRkFVTFRfU0NPUEVfRVBPQ0hgICgwKSBpZiBubyBlcG9jaCBoYXMgYmVlbiBzZXQuAAAAD2dldF9zY29wZV9lcG9jaAAAAAABAAAAAAAAAAVzY29wZQAAAAAAA+4AAAAgAAAAAQAAAAY=",
        "AAAAAAAAAAAAAAAPcmVnaXN0ZXJfc291cmNlAAAAAAQAAAAAAAAABnNvdXJjZQAAAAAAEwAAAAAAAAAKdmlkZW9faGFzaAAAAAAD7gAAACAAAAAAAAAADW1ldGFkYXRhX2hhc2gAAAAAAAPuAAAAIAAAAAAAAAAIcHJvb2ZfaWQAAAPuAAAAIAAAAAEAAAfQAAAAC1Byb29mUmVjb3JkAA==",
        "AAAAAAAAAUtSZXNvbHZlIGEgcmVzcG9uZGVkIGRpc3B1dGUgKGFkbWluIG9ubHkpLgoKUmVzb2x1dGlvbiBpbmRpY2F0ZXMgdGhhdCB0aGUgYWRtaW4gaGFzIHJldmlld2VkIGJvdGggdGhlIGRpc3B1dGUgYW5kCnRoZSByZXNwb25zZSBjb21taXRtZW50cyBhbmQgaGFzIHRha2VuIChvciBub3RlZCkgYW55IGFwcHJvcHJpYXRlCmNvcnJlY3RpdmUgYWN0aW9uLiBUaGUgb3JpZ2luYWwgcHJvb2YgcmVjb3JkIGlzICoqbm90KiogbW9kaWZpZWQuCgojIEd1YXJkcwotIERpc3B1dGUgbXVzdCBiZSBpbiBgUmVzcG9uZGVkYCBzdGF0ZS4KLSBNdXN0IGJlIHdpdGhpbiBgcmVzb2x2ZV9kZWFkbGluZWAuAAAAAA9yZXNvbHZlX2Rpc3B1dGUAAAAAAgAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAApkaXNwdXRlX2lkAAAAAAPuAAAAIAAAAAEAAAfQAAAADURpc3B1dGVSZWNvcmQAAAA=",
        "AAAAAAAAAZBTdWJtaXQgYSByZXNwb25zZSBjb21taXRtZW50IHRvIGFuIG9wZW4gZGlzcHV0ZS4KCk9ubHkgdGhlIGlzc3VlciAoVGllciAzKSBvciBzb3VyY2UgKFRpZXIgMikgb2YgdGhlIGRpc3B1dGVkIHByb29mIG1heQpyZXNwb25kLiBUaWVyIDEgKFNpbGVudCBXaXRuZXNzKSBwcm9vZnMgaGF2ZSBubyBvbi1jaGFpbiBpZGVudGl0eSwgc28KdGhlIGFkbWluIGFjdHMgYXMgdGhlIHNvbGUgcmVzcG9uZGVyIGZvciBhbm9ueW1vdXMgcHJvb2ZzLgoKIyBHdWFyZHMKLSBEaXNwdXRlIG11c3QgYmUgaW4gYE9wZW5gIHN0YXRlLgotIE11c3QgYmUgd2l0aGluIGByZXNwb25kX2RlYWRsaW5lYC4KLSBDYWxsZXIgbXVzdCBiZSB0aGUgaXNzdWVyLCBzb3VyY2UsIG9yIChmb3IgYW5vbnltb3VzIHByb29mcykgYWRtaW4uAAAAD3Jlc3BvbmRfZGlzcHV0ZQAAAAADAAAAAAAAAAlyZXNwb25kZXIAAAAAAAATAAAAAAAAAApkaXNwdXRlX2lkAAAAAAPuAAAAIAAAAAAAAAATcmVzcG9uc2VfY29tbWl0bWVudAAAAAPuAAAAIAAAAAEAAAfQAAAADURpc3B1dGVSZWNvcmQAAAA=",
        "AAAAAAAAAzJTZXQgdGhlIGN1cnJlbnQgZXBvY2ggZm9yIGEgZ2l2ZW4gc2NvcGUgaWRlbnRpZmllci4KCldoZW4gdGhlIGFkbWluIGFkdmFuY2VzIHRoZSBlcG9jaCBmb3IgYSBzY29wZSwgYWxsIHByb29mcyBnZW5lcmF0ZWQKdW5kZXIgdGhlIHByZXZpb3VzIGVwb2NoIGZvciB0aGF0IHNjb3BlIHdpbGwgaGF2ZSBzdGFsZSBlcG9jaCB2YWx1ZXMKYW5kIHdpbGwgYmUgcmVqZWN0ZWQgYnkgYHJlZ2lzdGVyX2Fub255bW91c192ZXJpZmllZGAuCgpFcG9jaHMgYXJlIHN0cmljdGx5IG1vbm90b25pYyAoYGVwb2NoID4gY3VycmVudGApLiBTZXR0aW5nIGFuIGVwb2NoCmxlc3MgdGhhbiBvciBlcXVhbCB0byB0aGUgY3VycmVudCBlcG9jaCBwYW5pY3Mgd2l0aCBgUmVnaXN0cnlFcnJvcjo6U3RhbGVFcG9jaGAKdG8gcHJldmVudCBlcG9jaCByb2xsYmFjayBhbmQgcmUtZW5hYmxpbmcgcHJldmlvdXNseSBjb25zdW1lZCBudWxsaWZpZXJzLgpOb24taW5jcmVhc2luZyB0cmFuc2l0aW9ucyAoaW5jbHVkaW5nIGVxdWFsKSBhcmUgcmVqZWN0ZWQgcmF0aGVyIHRoYW4KdHJlYXRlZCBpZGVtcG90ZW50bHkgdG8gZW5zdXJlIGV2ZXJ5IHVwZGF0ZSBleHBsaWNpdGx5IGFkdmFuY2VzIHRoZSBlcG9jaC4KClRoZSBzY29wZSBpcyBhIDMyLWJ5dGUgaWRlbnRpZmllciBkZXJpdmVkIGZyb20gdGhlIHNjb3BlIHN0cmluZwooZS5nLiwgU0hBLTI1NiBoYXNoIG1vZCBCTjI1NCBmaWVsZCkuICBBbiBlbXB0eSAoemVybykgc2NvcGUKcmVwcmVzZW50cyB0aGUgZ2xvYmFsL3Vuc2NvcGVkIGNvbnRleHQuCgpPbmx5IHRoZSByZWdpc3RyeSBhZG1pbiBtYXkgY2FsbCB0aGlzLgAAAAAAD3NldF9zY29wZV9lcG9jaAAAAAADAAAAAAAAAAVhZG1pbgAAAAAAABMAAAAAAAAABXNjb3BlAAAAAAAD7gAAACAAAAAAAAAABWVwb2NoAAAAAAAABgAAAAA=",
        "AAAAAAAAAq5BcHBseSBzZXF1ZW50aWFsIHN0b3JhZ2UgbWlncmF0aW9ucyB1cCB0byB0aGUgY3VycmVudCB0YXJnZXQgc2NoZW1hLgoKLSBBZG1pbi1vbmx5OyB1bmF1dGhvcml6ZWQgY2FsbGVycyBmYWlsIHdpdGggYFVuYXV0aG9yaXplZGAuCi0gSWRlbXBvdGVudCBhdCB0aGUgY3VycmVudCB0YXJnZXQgKFYxKTogcmVwZWF0ZWQgY2FsbHMgYXJlIG5vLW9wcyBhbmQKZG8gbm90IGVtaXQgYFNjaGVtYVVwZ3JhZGVkYC4KLSBMZWdhY3kgZGVwbG95bWVudHMgd2l0aG91dCBgRGF0YUtleTo6U2NoZW1hVmVyc2lvbmAgYXJlIHN0YW1wZWQgdG8gVjEKd2l0aG91dCBlbWl0dGluZyBgU2NoZW1hVXBncmFkZWRgIChsYXlvdXQgYWxyZWFkeSBtYXRjaGVzIFYxKS4KLSBGdXR1cmUgVjIrIG1pZ3JhdGlvbnMgbGFuZCBpbiB0aGUgYGN1cnJlbnQgPCB0YXJnZXRgIGJyYW5jaCBhbmQgTVVTVApwcmVzZXJ2ZSBleGlzdGluZyBwcm9vZiAvIHZpZGVvIC8gbnVsbGlmaWVyIHJlY29yZHMgYW5kIG5ldmVyIGxvZwptZWRpYSwgc2VjcmV0cywgd2l0bmVzc2VzLCBvciBwcml2YXRlIGtleXMuCgpSb2xsYmFjazogcmVkZXBsb3lpbmcgYSBwcmlvciB3YXNtIHRoYXQgaWdub3JlcyB1bmtub3duIGtleXMgbGVhdmVzCnN0YW1wZWQgYFNjaGVtYVZlcnNpb25gIGludGFjdDsgVjEgcmVhZGVycyB0cmVhdCBpdCBhcyBhdXRob3JpdGF0aXZlLgAAAAAAD3VwZ3JhZGVfc3RvcmFnZQAAAAABAAAAAAAAAAVhZG1pbgAAAAAAABMAAAAA",
        "AAAAAAAAAAAAAAAQZGVwcmVjYXRlX3NjaGVtYQAAAAIAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAALc2NoZW1hX2hhc2gAAAAD7gAAACAAAAAA",
        "AAAAAAAAAD5SZXR1cm4gdGhlIGNvbmZpZ3VyZWQgcmVnaXN0cmF0aW9uIHF1b3RhIGZvciBgaXNzdWVyYCwgaWYgYW55LgAAAAAAEGdldF9pc3N1ZXJfcXVvdGEAAAABAAAAAAAAAAZpc3N1ZXIAAAAAABMAAAABAAAD6AAAB9AAAAARSXNzdWVyUXVvdGFSZWNvcmQAAAA=",
        "AAAAAAAAAAAAAAAQZ2V0X3Byb29mX3N0YXR1cwAAAAEAAAAAAAAACHByb29mX2lkAAAD7gAAACAAAAABAAAH0AAAABdQcm9vZlZlcmlmaWNhdGlvblN0YXR1cwA=",
        "AAAAAAAAADFSZWFkLW9ubHkgcXVlcnkgZm9yIGEgc3RvcmVkIHNvdXJjZSBiYXRjaCByZWNvcmQuAAAAAAAAEGdldF9zb3VyY2VfYmF0Y2gAAAABAAAAAAAAAARyb290AAAD7gAAACAAAAABAAAD6AAAB9AAAAALQmF0Y2hSZWNvcmQA",
        "AAAAAAAAA5JHcmFudCBgZGVsZWdhdGVgIGEgbmFycm93bHkgc2NvcGVkLCBleHBpcmluZyBhdXRob3JpdHkgdG8gcmVnaXN0ZXIgb24KdGhlIGNhbGxlcidzIGJlaGFsZi4KClJlcXVpcmVzIHRoZSBncmFudG9yJ3Mgb3duIHNpZ25hdHVyZSDigJQgYSBkZWxlZ2F0ZSBjYW4gbmV2ZXIgY3JlYXRlIG9yCmV4dGVuZCBhIGRlbGVnYXRpb24sIHdoaWNoIGlzIHdoYXQgbWFrZXMgdGhlIG1lY2hhbmlzbSBub24tdHJhbnNpdGl2ZS4KCmBzY29wZWAgaXMgYSBub24tZW1wdHkgc3Vic2V0IG9mIGBERUxFR0FUSU9OX1NDT1BFX0FMTGAuCmBkdXJhdGlvbl9zZWNzYCBpcyBub24temVybyBhbmQgYXQgbW9zdCBgTUFYX0RFTEVHQVRJT05fRFVSQVRJT05fU0VDU2AuCgpJZGVtcG90ZW50OiByZS1ncmFudGluZyB0byBhbiBleGlzdGluZyBkZWxlZ2F0ZSBvdmVyd3JpdGVzIHRoYXQKZGVsZWdhdGUncyByZWNvcmQg4oCUIG5hcnJvd2luZyBvciB3aWRlbmluZyBzY29wZSwgZXh0ZW5kaW5nIG9yIHNob3J0ZW5pbmcKZXhwaXJ5IOKAlCBhbmQgZG9lcyBub3QgY29uc3VtZSBhbm90aGVyIHN0b3JhZ2Ugc2xvdC4gUmV0dXJucyB0aGUgZXBvY2gKc2Vjb25kIGF0IHdoaWNoIHRoZSBkZWxlZ2F0aW9uIGxhcHNlcyBvbiBpdHMgb3duLgoKIyBSZXZlcnRzCgotIGBTZWxmRGVsZWdhdGlvbmAgICAgICAgICAgICAgIGlmIGBncmFudG9yID09IGRlbGVnYXRlYAotIGBJbnZhbGlkRGVsZWdhdGlvblNjb3BlYCAgICAgIGlmIGBzY29wZWAgaXMgemVybyBvciBoYXMgdW5rbm93biBiaXRzCi0gYEludmFsaWREZWxlZ2F0aW9uRHVyYXRpb25gICAgaWYgYGR1cmF0aW9uX3NlY3NgIGlzIHplcm8gb3Igb3ZlciB0aGUgY2FwCi0gYERlbGVnYXRpb25zU2F0dXJhdGVkYCAgICAgICAgaWYgdGhlIGdyYW50b3IgYWxyZWFkeSBob2xkcyB0aGUgbWF4aW11bQAAAAAAEGdyYW50X2RlbGVnYXRpb24AAAAEAAAAAAAAAAdncmFudG9yAAAAABMAAAAAAAAACGRlbGVnYXRlAAAAEwAAAAAAAAAFc2NvcGUAAAAAAAAEAAAAAAAAAA1kdXJhdGlvbl9zZWNzAAAAAAAABgAAAAEAAAAG",
        "AAAAAAAABABSZWNvcmQgYSB2ZXJpZmlhYmxlIGRlcml2YXRpdmUgb2Ygb25lIG9yIG1vcmUgZXhpc3RpbmcgYXJ0ZWZhY3RzLCBhbmQKcGVyc2lzdCB0aGUgcGFyZW50IGNvbnRlbnQgY29tbWl0bWVudHMgZm9yIHByaXZhY3ktcHJlc2VydmluZyBwdWJsaWMKYm91bmRhcmllcyAoIzMzMiwgIzMzMykuCgpQYXJlbnQgY29tbWl0bWVudHMgYXJlIGRlcml2ZWQgb24tY2hhaW4gZnJvbSBlYWNoIHBhcmVudCdzIHN0b3JlZCBwdWJsaWMKZmllbGRzIHNvIGNhbGxlcnMgY2Fubm90IHN1cHBseSBmb3JnZWQgYmluZGluZ3MuIGBkZXB0aGAgaXMgdGhlIGRlcHRoIHRoZQpjYWxsZXIgYmVsaWV2ZXMgdGhpcyBkZXJpdmF0aXZlIHNpdHMgYXQ6IGl0IGlzIGNoZWNrZWQgYWdhaW5zdCB0aGUgZGVwdGgKaW1wbGllZCBieSB0aGUgcGFyZW50cyByYXRoZXIgdGhhbiB0cnVzdGVkLCBzbyBhIGNhbGxlciBjYW5ub3QgY2xhaW0gYQpzaGFsbG93IHBvc2l0aW9uIHRvIHNsaXAgcGFzdCBgTUFYX0xJTkVBR0VfREVQVEhgOyB0aGUgc3RvcmVkIHJlY29yZCBhbmQKdGhlIHB1Ymxpc2hlZCBldmVudCBhbHdheXMgY2FycnkgdGhlIGRlcml2ZWQgZGVwdGguCgpGYWlscyB3aXRoIGBMaW5lYWdlRmFuT3V0RXhjZWVkZWRgICgjNjApIHdoZW4gdGhlIHBhcmVudCBzZXQgZXhjZWVkcwpgTUFYX0xJTkVBR0VfRkFOT1VUYCwgYExpbmVhZ2VGYW5PdXRTYXR1cmF0ZWRgICgjNzkpIHdoZW4gYSBwYXJlbnQKYWxyZWFkeSBoYXMgYE1BWF9MSU5FQUdFX0ZBTk9VVGAgZGVyaXZhdGl2ZXMsIGBMaW5lYWdlQ3ljbGVgICgjNTgpIGZvciBhCnNlbGYtcmVmZXJlbnRpYWwgZWRnZSwgYExpbmVhZ2VUb29EZWVwYCAoIzU5KSBwYXN0IGBNQVhfTElORUFHRV9ERVBUSGAsCmBMaW5lYWdlRGVwdGhNaXNtYXRjaGAgKCM4MCkgZm9yIGEgZm9yZ2VkIGRlcHRoLCBgRHVwbGljYXRlTGluZWFnZWAgKCM3OCkKZm9yIGFuIG91dHB1dCBkaWdlc3QgdGhhdCBpcyBhbHJlYWR5IHJlY29yZGVkLCBgTGluZWFnZUVtcHR5UGFyZW50c2AKKCM3NikgZm9yIGFuIGVtcHR5AAAAEHJlZ2lzdGVyX2xpbmVhZ2UAAAAGAAAAAAAAAAVhY3RvcgAAAAAAABMAAAAAAAAAEHBhcmVudF9wcm9vZl9pZHMAAAPqAAAD7gAAACAAAAAAAAAAD21hbmlmZXN0X2RpZ2VzdAAAAAPuAAAAIAAAAAAAAAAOb3BlcmF0aW9uX3R5cGUAAAAAABEAAAAAAAAADW91dHB1dF9kaWdlc3QAAAAAAAPuAAAAIAAAAAAAAAAFZGVwdGgAAAAAAAAEAAAAAQAAB9AAAAANTGluZWFnZVJlY29yZAAAAA==",
        "AAAAAAAAANZDb25maWd1cmUgb3IgY2xlYXIgdGhlIHBlci13aW5kb3cgcmVnaXN0cmF0aW9uIHF1b3RhIGZvciBgaXNzdWVyYCAob3IKVGllciAyIHNvdXJjZSBrZXkpLiBQYXNzaW5nIGAwYCBmb3IgYG1heF9yZWdpc3RyYXRpb25zYCBvciBgd2luZG93X3NlY3NgCmNsZWFycyB0aGUgcXVvdGEgYW5kIGFueSBhY2NydWVkIGNvdW50ZXIsIHJlc3RvcmluZyB1bmxpbWl0ZWQgY2FwYWNpdHkuAAAAAAAQc2V0X2lzc3Vlcl9xdW90YQAAAAQAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAAGaXNzdWVyAAAAAAATAAAAAAAAABFtYXhfcmVnaXN0cmF0aW9ucwAAAAAAAAQAAAAAAAAAC3dpbmRvd19zZWNzAAAAAAYAAAAA",
        "AAAAAAAAAGBSZXR1cm4gdGhlIGFjdGl2ZSBhZG1pbiBjb3VuY2lsLCBvciBOb25lIGlmIG5vIGNvdW5jaWwgaXMgY29uZmlndXJlZCBvciBzdGlsbCBpbiB0aW1lbG9jayBkZWxheS4AAAARZ2V0X2FkbWluX2NvdW5jaWwAAAAAAAAAAAAAAQAAA+gAAAfQAAAADEFkbWluQ291bmNpbA==",
        "AAAAAAAAAENSZXR1cm4gdGhlIHBlbmRpbmcgYWRtaW4gYWRkcmVzcywgaWYgYW4gYWRtaW4gdHJhbnNmZXIgaXMgcHJvcG9zZWQuAAAAABFnZXRfcGVuZGluZ19hZG1pbgAAAAAAAAAAAAABAAAD6AAAABM=",
        "AAAAAAAAAEBSZXR1cm4gYSBzaWduZXIncyBhcHByb3ZhbCByZWNvcmQgZm9yIGBwcm9vZl9pZGAsIGlmIGFueSAoIzEyNCkuAAAAEWdldF9zZWFsX2FwcHJvdmFsAAAAAAAAAgAAAAAAAAAIcHJvb2ZfaWQAAAPuAAAAIAAAAAAAAAAGc2lnbmVyAAAAAAATAAAAAQAAA+gAAAfQAAAADFNlYWxBcHByb3ZhbA==",
        "AAAAAAAAAAAAAAARcmVhY3RpdmF0ZV9zY2hlbWEAAAAAAAACAAAAAAAAAAVhZG1pbgAAAAAAABMAAAAAAAAAC3NjaGVtYV9oYXNoAAAAA+4AAAAgAAAAAA==",
        "AAAAAAAAASJSZXZva2UgYSBkZWxlZ2F0aW9uIGFoZWFkIG9mIGl0cyBleHBpcnkuCgpDYWxsYWJsZSBieSB0aGUgZ3JhbnRvciAod2l0aGRyYXdpbmcgYXV0aG9yaXR5IGl0IGlzc3VlZCkgb3IgYnkgdGhlCmFkbWluIChpbmNpZGVudCByZXNwb25zZSBhZ2FpbnN0IGEgY29tcHJvbWlzZWQgZGVsZWdhdGUpLiBSZXZva2luZyBhCmRlbGVnYXRpb24gdGhhdCBkb2VzIG5vdCBleGlzdCBpcyBhIG5vLW9wIHJhdGhlciB0aGFuIGFuIGVycm9yLCBzbwpyZXRyaWVzIGFuZCBjb25jdXJyZW50IHJldm9jYXRpb25zIGNvbnZlcmdlLgAAAAAAEXJldm9rZV9kZWxlZ2F0aW9uAAAAAAAAAwAAAAAAAAAHcmV2b2tlcgAAAAATAAAAAAAAAAdncmFudG9yAAAAABMAAAAAAAAACGRlbGVnYXRlAAAAEwAAAAA=",
        "AAAAAAAAAGRDb25maWd1cmUgYW4gb3B0aW9uYWwgbXVsdGktcGFydHkgYWRtaW4gY291bmNpbCBndWFyZGVkIGJ5IGN1cnJlbnQgYWRtaW4KYW5kIHRoZSB0aW1lbG9jayBtaW4gZGVsYXkuAAAAEXNldF9hZG1pbl9jb3VuY2lsAAAAAAAAAwAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAAdtZW1iZXJzAAAAA+oAAAATAAAAAAAAAAl0aHJlc2hvbGQAAAAAAAAEAAAAAA==",
        "AAAAAAAAAgVTdXBlcnNlZGUgYSBkaXNwdXRlZCBwcm9vZiBieSBsaW5raW5nIGEgY29ycmVjdGVkIHByb29mIChhZG1pbiBvbmx5KS4KClRoaXMgbWFya3MgdGhlIGRpc3B1dGUgYXMgYFN1cGVyc2VkZWRgIGFuZCByZWNvcmRzIHRoZSBjb3JyZWN0aW5nIHByb29mCklELiBUaGUgb3JpZ2luYWwgZGlzcHV0ZWQgcHJvb2YgaXMgKipub3QqKiByZXZva2VkIC0gY2FsbGVycyBzaG91bGQgdXNlCmByZXZva2VfcHJvb2ZgIHNlcGFyYXRlbHkgaWYgcmV2b2NhdGlvbiBpcyBhbHNvIGRlc2lyZWQuCgojIEd1YXJkcwotIERpc3B1dGUgbXVzdCBiZSBpbiBgT3BlbmAgb3IgYFJlc3BvbmRlZGAgc3RhdGUuCi0gYHN1cGVyc2VkaW5nX3Byb29mX2lkYCBtdXN0IGV4aXN0IGluIHRoZSByZWdpc3RyeS4KLSBJdCBtdXN0IG5vdCBlcXVhbCB0aGUgZGlzcHV0ZWQgYHByb29mX2lkYCAodHJpdmlhbCBjeWNsZSkuCi0gSXQgbXVzdCBub3QgYWxyZWFkeSBwb2ludCBiYWNrIHRvIHRoZSBkaXNwdXRlZCBwcm9vZiAoZGVwdGgtMSBjeWNsZSkuAAAAAAAAEXN1cGVyc2VkZV9kaXNwdXRlAAAAAAAAAwAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAApkaXNwdXRlX2lkAAAAAAPuAAAAIAAAAAAAAAAUc3VwZXJzZWRpbmdfcHJvb2ZfaWQAAAPuAAAAIAAAAAEAAAfQAAAADURpc3B1dGVSZWNvcmQAAAA=",
        "AAAAAAAAAE5SZWdpc3RlciBvciByZWFjdGl2YXRlIGFuIHVuY29tcHJlc3NlZCBTRUMtMSBQLTI1NiByZWNlaXB0LXNpZ25pbmcgcHVibGljIGtleS4AAAAAABJhZGRfcmVjZWlwdF9zaWduZXIAAAAAAAIAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAAKcHVibGljX2tleQAAAAAD7gAAAEEAAAABAAAH0AAAABNSZWNlaXB0U2lnbmVyUmVjb3JkAA==",
        "AAAAAAAAACZDYW5jZWwgYSB0aHJlc2hvbGQgc2VhbCBwb2xpY3kgKCMxMjQpLgAAAAAAEmNhbmNlbF9zZWFsX3BvbGljeQAAAAAAAgAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAAd2ZXJzaW9uAAAAAAQAAAAA",
        "AAAAAAAAAFdDcmVhdGUgYSBuZXcgdmVyc2lvbmVkIHRocmVzaG9sZCBzZWFsIHBvbGljeSBhbmQgY2FuY2VsIGFueSBwcmlvciBhY3RpdmUgcG9saWN5ICgjMTI0KS4AAAAAEmNyZWF0ZV9zZWFsX3BvbGljeQAAAAAABQAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAABJyZXF1aXJlZF9hcHByb3ZhbHMAAAAAAAQAAAAAAAAAC21heF9zaWduZXJzAAAAAAQAAAAAAAAADGFwcHJvdmFsX3R0bAAAAAYAAAAAAAAACmV4cGlyZXNfYXQAAAAAAAYAAAABAAAABA==",
        "AAAAAAAAASNSZXR1cm4gdGhlIGh1bWFuLXJlYWRhYmxlIHZlcmlmaWNhdGlvbiBzdGF0dXMgb2YgbXVsdGlwbGUgcHJvb2ZzIGluIGEgc2luZ2xlCmJhdGNoIHF1ZXJ5LCBlZmZpY2llbnRseSByZXRyaWV2aW5nIHRoZW0gd2l0aG91dCBleGNlZWRpbmcgU29yb2JhbiByZWFkIGJ1ZGdldHMuCgpUaGUgbWF4aW11bSBudW1iZXIgb2YgcHJvb2YgSURzIGluIGEgc2luZ2xlIGJhdGNoIGlzIGJvdW5kZWQgKGUuZy4gMTAwKSB0bwplbnN1cmUgdGhlIHF1ZXJ5IGFsd2F5cyBjb21wbGV0ZXMgd2l0aGluIHJlc291cmNlIGxpbWl0cy4AAAAAEmdldF9wcm9vZl9zdGF0dXNlcwAAAAAAAQAAAAAAAAAJcHJvb2ZfaWRzAAAAAAAD6gAAA+4AAAAgAAAAAQAAA+oAAAfQAAAAF1Byb29mVmVyaWZpY2F0aW9uU3RhdHVzAA==",
        "AAAAAAAAAEBJbnNwZWN0IGEgcmVjZWlwdC1zaWduaW5nIHB1YmxpYyBrZXkgcmVjb3JkLCBpZiBldmVyIHJlZ2lzdGVyZWQuAAAAEmdldF9yZWNlaXB0X3NpZ25lcgAAAAAAAQAAAAAAAAAKcHVibGljX2tleQAAAAAD7gAAAEEAAAABAAAD6AAAB9AAAAATUmVjZWlwdFNpZ25lclJlY29yZAA=",
        "AAAAAAAAAJJSZXR1cm4gdGhlIGFjdGl2ZSBzdG9yYWdlIHNjaGVtYSB2ZXJzaW9uLiBMZWdhY3kgZGVwbG95bWVudHMgdGhhdCBoYXZlCm5vdCBjYWxsZWQgYHVwZ3JhZGVfc3RvcmFnZWAgcmVwb3J0IGBWMWA7IGZyZXNoIFYyIGRlcGxveW1lbnRzIHJlcG9ydCBgVjJgLgAAAAAAEmdldF9zY2hlbWFfdmVyc2lvbgAAAAAAAAAAAAEAAAAE",
        "AAAAAAAAAAAAAAASZ2V0X3ZlcmlmaWVyX3N0YXRlAAAAAAAAAAAAAQAAB9AAAAANVmVyaWZpZXJTdGF0ZQAAAA==",
        "AAAAAAAAAAAAAAAScmVnaXN0ZXJfYW5vbnltb3VzAAAAAAAGAAAAAAAAAAp2aWRlb19oYXNoAAAAAAPuAAAAIAAAAAAAAAANbWV0YWRhdGFfaGFzaAAAAAAAA+4AAAAgAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAAAAAAludWxsaWZpZXIAAAAAAAPuAAAAIAAAAAAAAAAPY3JlZGVudGlhbF9yb290AAAAA+4AAAAgAAAAAAAAAAVwcm9vZgAAAAAAAA4AAAABAAAH0AAAAAtQcm9vZlJlY29yZAA=",
        "AAAAAAAAAAAAAAATYWRkX2NyZWRlbnRpYWxfcm9vdAAAAAADAAAAAAAAAAVhZG1pbgAAAAAAABMAAAAAAAAAD2NyZWRlbnRpYWxfcm9vdAAAAAPuAAAAIAAAAAAAAAANbWV0YWRhdGFfaGFzaAAAAAAAA+4AAAAgAAAAAA==",
        "AAAAAAAAAEpFeHRlbmQgdGhlIGNvbnRyYWN0IGluc3RhbmNlIHN0b3JhZ2UgVFRMIGFuZCBlbWl0IGBJbnN0YW5jZVRUTE1haW50YWluZWRgLgAAAAAAE2V4dGVuZF9pbnN0YW5jZV90dGwAAAAAAAAAAAA=",
        "AAAAAAAAAAAAAAATZ2V0X2NyZWRlbnRpYWxfcm9vdAAAAAABAAAAAAAAAA9jcmVkZW50aWFsX3Jvb3QAAAAD7gAAACAAAAABAAAD6AAAB9AAAAAUQ3JlZGVudGlhbFJvb3RSZWNvcmQ=",
        "AAAAAAAAATxUaGUgcm90YXRpb24gZ3JhY2UgcmVjb3JkIGZvciBgaXNzdWVyYCwgd2hlbiB0aGUga2V5IGhhcyByb3RhdGVkIG91dCBhbmQKdGhlIHdpbmRvdyBoYXMgbm90IGJlZW4gc2V0dGxlZCB5ZXQgKCMzMjMpLgoKYE5vbmVgIGZvciBhbiB1bmtub3duIGtleSwgYW4gYWN0aXZlIGtleSwgYSByZXZva2VkIGtleSwgYW5kIGEga2V5IHdob3NlCmxhcHNlZCB3aW5kb3cgd2FzIGFscmVhZHkgZmluYWxpemVkLiBJbiBlYWNoIG9mIHRob3NlIGNhc2VzCltgU2VsZjo6aXNfaXNzdWVyX3ZlcmlmaWFibGVgXSBpcyB0aGUgcmVhZCB0aGF0IGRlY2lkZXMgc3RhbmRpbmcuAAAAE2dldF9pc3N1ZXJfcm90YXRpb24AAAAAAQAAAAAAAAAGaXNzdWVyAAAAAAATAAAAAQAAA+gAAAfQAAAAFElzc3VlclJvdGF0aW9uUmVjb3Jk",
        "AAAAAAAAAPhTaW5nbGUgcmVhZCBjYWxsIHRoYXQgc3VtbWFyaXNlcyBldmVyeXRoaW5nIGEgdmVyaWZpZXIgbmVlZHMgdG8gdHJ1c3QgYSBwcm9vZjoKdmVyaWZpY2F0aW9uIHN0YXR1cywgdGllciwgdGltZXN0YW1wIGFzc3VyYW5jZSBsZXZlbCwgb3BlbiBkaXNwdXRlIGNvdW50LAptZXRhZGF0YSBlbnZlbG9wZSB2ZXJzaW9uLCBhbmQgaXNzdWVyIHZlcmlmaWFiaWxpdHkuCgpSZXR1cm5zIGBOb25lYCBpZiB0aGUgcHJvb2YgaXMgbm90IGZvdW5kLgAAABNnZXRfcHJvb2ZfYXNzdXJhbmNlAAAAAAEAAAAAAAAACHByb29mX2lkAAAD7gAAACAAAAABAAAD6AAAB9AAAAAOUHJvb2ZBc3N1cmFuY2UAAA==",
        "AAAAAAAAAAAAAAATZ2V0X3Jldm9jYXRpb25fcm9vdAAAAAAAAAAAAQAAA+gAAAPuAAAAIA==",
        "AAAAAAAAADJSZXR1cm4gdGhlIHRpbWVzdGFtcCBjbGFpbSBmb3IgYHByb29mX2lkYCwgaWYgYW55LgAAAAAAE2dldF90aW1lc3RhbXBfY2xhaW0AAAAAAQAAAAAAAAAIcHJvb2ZfaWQAAAPuAAAAIAAAAAEAAAPoAAAH0AAAAA5UaW1lc3RhbXBDbGFpbQAA",
        "AAAAAAAAATBSZXR1cm4gZGlzcHV0ZSBJRHMgZm9yIGEgcHJvb2YgaW4gY3JlYXRpb24gb3JkZXIgd2l0aCBwYWdpbmF0aW9uLgoKLSBgY3Vyc29yYCBpcyB0aGUgemVyby1iYXNlZCBvZmZzZXQgaW50byB0aGUgcHJvb2YncyBkaXNwdXRlcy4KLSBgbGltaXRgIGlzIHRoZSBtYXhpbXVtIG51bWJlciBvZiBkaXNwdXRlIElEcyB0byByZXR1cm4sIGNhcHBlZCBieQpgTUFYX1BST09GX0RJU1BVVEVTX1BBR0VgLgotIE1pc3NpbmcgcHJvb2ZzIG9yIHByb29mcyB3aXRob3V0IGRpc3B1dGVzIHlpZWxkIGFuIGVtcHR5IGxpc3QgKHByaXZhY3ktc2FmZSkuAAAAE2xpc3RfcHJvb2ZfZGlzcHV0ZXMAAAAAAwAAAAAAAAAIcHJvb2ZfaWQAAAPuAAAAIAAAAAAAAAAGY3Vyc29yAAAAAAAEAAAAAAAAAAVsaW1pdAAAAAAAAAQAAAABAAAD6gAAA+4AAAAg",
        "AAAAAAAAAAAAAAATc2V0X3Jldm9jYXRpb25fcm9vdAAAAAACAAAAAAAAAAVhZG1pbgAAAAAAABMAAAAAAAAAD3Jldm9jYXRpb25fcm9vdAAAAAPuAAAAIAAAAAA=",
        "AAAAAAAABABWZXJpZnkgYSBub24tcmV2b2NhdGlvbiBwcm9vZiBwcm9kdWNlZCBieSB0aGUgYHJldm9jYXRpb25fd2l0bmVzc2AKTm9pciBjaXJjdWl0LgoKVGhlIHByb29mIGRlbW9uc3RyYXRlcyB0aGF0IGBjcmVkZW50aWFsX3Jvb3RgIGlzICoqbm90KiogYSBtZW1iZXIgb2YKdGhlIGN1cnJlbnRseS1wdWJsaXNoZWQgcmV2b2NhdGlvbiB0cmVlIChgcmV2b2NhdGlvbl9yb290YCkg4oCUIG9yIGEKcmVjZW50IHByZXZpb3VzIHJvb3Qgc3RpbGwgd2l0aGluIHRoZSBjb25maWd1cmVkIGdyYWNlIHdpbmRvdyDigJQgd2l0aG91dApyZXZlYWxpbmcgd2hpY2ggcmV2b2tlZCBjcmVkZW50aWFscyBleGlzdCBvciB3aGljaCBpZGVudGl0eSBpcyBhY3RpbmcuCgojIFB1YmxpYyBpbnB1dCBsYXlvdXQgKDEyOCBieXRlcywgNCB4IEJOMjU0IGZpZWxkIGVsZW1lbnRzKQoKYGBgdGV4dApbICAwLi4gMzIpICByZXZvY2F0aW9uX3Jvb3QgICAtIG11c3QgbWF0Y2ggdGhlIGN1cnJlbnQgcm9vdCBvciBhIHJlY2VudCByb290IHdpdGhpbiB0aGUgZ3JhY2Ugd2luZG93ClsgMzIuLiA2NCkgIG51bGxpZmllciAgICAgICAgIC0gb25lLXVzZSByZXBsYXkgZ3VhcmQKWyA2NC4uIDk2KSAgZG9tYWluX3NlcGFyYXRvciAgLSBtdXN0IG1hdGNoIFJFVk9DQVRJT05fRE9NQUlOX1NFUEFSQVRPUgpbIDk2Li4xMjgpICBjcmVkZW50aWFsX3Jvb3QgICAtIG11c3QgYmUgcmVnaXN0ZXJlZCAmIGFjdGl2ZSBvbi1jaGFpbgpgYGAKCiMgUmV2ZXJ0cwoKLSBgTm90SW5pdGlhbGl6ZWRgICAgICAgaWYgbm8gcmV2b2NhdGlvbiByb290IGhhcyBiZWVuIHB1Ymxpc2hlZCB5ZXQKLSBgVmVyaWZpZXJOb3RTZXRgICAgICAgIGlmIG5vIGV4dGVybmFsIHZlcmlmaWVyIGNvbnRyYWN0IGlzIGNvbmZpZ3VyZWQKLSBgSW52YWxpZFB1YmxpY0lucHV0c2AgIGlmIHRoZSBkb21haW4gc2VwYXJhdG9yLCBsYXlvdXQsIG9yIHJldm9jYXRpb24gcm9vdCAodW5rbm93bi9vdXRzaWRlIGdyYWNlIHdpbmRvdykgaXMgaW52YWxpZAotIGBVbmtub3duQ3JlZGVudGlhAAAAFGNoZWNrX25vbl9yZXZvY2F0aW9uAAAAAgAAAAAAAAANcHVibGljX2lucHV0cwAAAAAAAA4AAAAAAAAABXByb29mAAAAAAAADgAAAAA=",
        "AAAAAAAAAAAAAAAUZ2V0X2NvdW5jaWxfcHJvcG9zYWwAAAABAAAAAAAAAAtwcm9wb3NhbF9pZAAAAAAEAAAAAQAAA+gAAAfQAAAAD0NvdW5jaWxQcm9wb3NhbAA=",
        "AAAAAAAAAGhSZWFkLW9ubHk6IGhvdyBtYW55IGRpc3RpbmN0IGRlbGVnYXRlcyBhIGdyYW50b3IgY3VycmVudGx5IGhvbGRzLAphZ2FpbnN0IGBNQVhfREVMRUdBVElPTlNfUEVSX0dSQU5UT1JgLgAAABRnZXRfZGVsZWdhdGlvbl9jb3VudAAAAAEAAAAAAAAAB2dyYW50b3IAAAAAEwAAAAEAAAAE",
        "AAAAAAAAAAAAAAAUZ2V0X3Byb29mX2hpc3RvcnlfYXQAAAACAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAAAAAANzZXEAAAAABAAAAAEAAAPoAAAH0AAAABFQcm9vZkhpc3RvcnlFbnRyeQAAAA==",
        "AAAAAAAAAKVSZXR1cm4gdGhlIGJvdW5kZWQgaGlzdG9yeSBvZiByZWNlbnQgcmV2b2NhdGlvbiByb290cyBpbiBjaHJvbm9sb2dpY2FsCm9yZGVyIChvbGRlc3QgZmlyc3QsIGN1cnJlbnQgYWN0aXZlIHJvb3QgbGFzdCksIHVwIHRvCltgTUFYX1JFVk9DQVRJT05fUk9PVF9ISVNUT1JZYF0gZW50cmllcy4AAAAAAAAUZ2V0X3Jldm9jYXRpb25fcm9vdHMAAAAAAAAAAQAAA+oAAAfQAAAAE1Jldm9jYXRpb25Sb290RW50cnkA",
        "AAAAAAAAAPJSZWFkLW9ubHk6IGRvZXMgYSBsaXZlIGRlbGVnYXRpb24gZnJvbSBgZ3JhbnRvcmAgdG8gYGRlbGVnYXRlYCBjYXJyeQpldmVyeSBiaXQgb2YgYHNjb3BlYD8gUmV0dXJucyBgZmFsc2VgIGZvciB1bmtub3duLCBleHBpcmVkLCBvcgppbnN1ZmZpY2llbnRseSBzY29wZWQgZGVsZWdhdGlvbnMgcmF0aGVyIHRoYW4gZXJyb3JpbmcsIHNvIGNhbGxlcnMgY2FuCnByZS1mbGlnaHQgd2l0aG91dCBhIHRyaWFsIHRyYW5zYWN0aW9uLgAAAAAAFGlzX2RlbGVnYXRpb25fYWN0aXZlAAAAAwAAAAAAAAAHZ3JhbnRvcgAAAAATAAAAAAAAAAhkZWxlZ2F0ZQAAABMAAAAAAAAABXNjb3BlAAAAAAAABAAAAAEAAAAB",
        "AAAAAAAAAdJXaGV0aGVyIGBpc3N1ZXJgIG1heSBzdGlsbCBhbmNob3IgdmVyaWZpY2F0aW9uIG9mIGV2aWRlbmNlIGl0IGlzc3VlZAooIzMyMykuCgpUcnVlIHdoaWxlIHRoZSByZWdpc3RyeSBsaXN0cyB0aGUgaXNzdWVyIGFzIGFjdGl2ZSwgYW5kIHRydWUgZm9yIGEKcm90YXRlZC1vdXQga2V5IHVudGlsIGl0cyBncmFjZSB3aW5kb3cgbGFwc2VzLiBGYWxzZSBmb3IgYW4gdW5rbm93biBrZXksCmEgcmV2b2tlZCBrZXksIGFuZCBhIGtleSBhdCBvciBwYXN0IGBncmFjZV9leHBpcmVzX2F0YCDigJQgYSBsYXBzZWQgd2luZG93CmZhaWxzIGNsb3NlZCByYXRoZXIgdGhhbiBiZWluZyBzaWxlbnRseSBleHRlbmRlZC4gTmV2ZXIgcGFuaWNzLCBzbyBhCmNhbGxlciBjYW4gcHJlLWZsaWdodCBhbiB1bmtub3duLCByZXZva2VkLCBvciB1bnN1cHBvcnRlZCBpc3N1ZXIgd2l0aG91dApyaXNraW5nIGEgcmV2ZXJ0ZWQgdHJhbnNhY3Rpb24uAAAAAAAUaXNfaXNzdWVyX3ZlcmlmaWFibGUAAAABAAAAAAAAAAZpc3N1ZXIAAAAAABMAAAABAAAAAQ==",
        "AAAAAAAAAAAAAAAVY2FuY2VsX2FkbWluX3RyYW5zZmVyAAAAAAAAAQAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAA==",
        "AAAAAAAAAH9BbmNob3IgYSBzaWduZWQgdmVyaWZpY2F0aW9uIHJlY2VpcHQgZGlnZXN0IGZvciBgcHJvb2ZfaWRgLgoKSWRlbXBvdGVudCB3aGVuIHJldHJpZWQgd2l0aCB0aGUgZXhhY3QgY29tbWl0dGVkIGByZWNlaXB0X2RpZ2VzdGAuAAAAABVjb21taXRfcmVjZWlwdF9kaWdlc3QAAAAAAAAFAAAAAAAAAAZjYWxsZXIAAAAAABMAAAAAAAAACHByb29mX2lkAAAD7gAAACAAAAAAAAAADnJlY2VpcHRfZGlnZXN0AAAAAAPuAAAAIAAAAAAAAAAKcHVibGljX2tleQAAAAAD7gAAAEEAAAAAAAAACXNpZ25hdHVyZQAAAAAAA+4AAABAAAAAAQAAB9AAAAAXUmVjZWlwdENvbW1pdG1lbnRSZWNvcmQA",
        "AAAAAAAAAAAAAAAVZ2V0X2N1cnJlbnRfd2FzbV9oYXNoAAAAAAAAAAAAAAEAAAPoAAAD7gAAACA=",
        "AAAAAAAAAEFSZXR1cm4gdGhlIHZlcnNpb25lZCBtZXRhZGF0YSBlbnZlbG9wZSBmb3IgYHByb29mX2lkYCwgaWYgc3RvcmVkLgAAAAAAABVnZXRfbWV0YWRhdGFfZW52ZWxvcGUAAAAAAAABAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAQAAA+gAAAfQAAAAEE1ldGFkYXRhRW52ZWxvcGU=",
        "AAAAAAAAAVZSZXR1cm4gdGhlIHZlcmlmaWNhdGlvbiBzdGF0dXMgb2YgbXVsdGlwbGUgdmlkZW9zIGluIGEgc2luZ2xlIGJhdGNoIHF1ZXJ5LApyZXNvbHZpbmcgdmlkZW8gaGFzaGVzIHRvIHRoZWlyIHVuZGVybHlpbmcgcHJvb2YgdmVyaWZpY2F0aW9uIHN0YXR1c2VzLgoKVW5rbm93biB2aWRlbyBoYXNoZXMgcmV0dXJuIGBQcm9vZlZlcmlmaWNhdGlvblN0YXR1czo6Tm90Rm91bmRgIGluc3RlYWQgb2YgZmFpbGluZyB0aGUgYmF0Y2guClRoZSBtYXhpbXVtIG51bWJlciBvZiB2aWRlbyBoYXNoZXMgaW4gYSBzaW5nbGUgYmF0Y2ggaXMgYm91bmRlZCAoMTAwKSB0byBtYXRjaCBgZ2V0X3Byb29mX3N0YXR1c2VzYC4AAAAAABVnZXRfc3RhdHVzZXNfYnlfdmlkZW8AAAAAAAABAAAAAAAAAAx2aWRlb19oYXNoZXMAAAPqAAAD7gAAACAAAAABAAAD6gAAB9AAAAAXUHJvb2ZWZXJpZmljYXRpb25TdGF0dXMA",
        "AAAAAAAAAAAAAAAVZ2V0X3RpbWVsb2NrX3Byb3Bvc2FsAAAAAAAAAQAAAAAAAAALcHJvcG9zYWxfaWQAAAAABAAAAAEAAAPoAAAH0AAAABBUaW1lbG9ja1Byb3Bvc2Fs",
        "AAAAAAAAAbpFbnVtZXJhdGUgY3JlZGVudGlhbCByb290cyBhbmQgdGhlaXIgY3VycmVudCBzdGF0dXNlcyBhY3Jvc3Mgc2VxdWVudGlhbCBJRHMgKCM3MzEpLgoKLSBgY3Vyc29yYDogSUQgb2Zmc2V0IHRvIHN0YXJ0IHNjYW5uaW5nIGZyb20gKDEtYmFzZWQgc2VxdWVudGlhbCBJRHMpLgpJZiBgY3Vyc29yID09IDBgLCBzY2FubmluZyBiZWdpbnMgYXQgSUQgMS4KLSBgbGltaXRgOiBtYXhpbXVtIG51bWJlciBvZiByb290cyB0byByZXR1cm47IGNhcHBlZCBhdCBgTUFYX0NSRURFTlRJQUxfUk9PVFNfUEFHRWAuCklmIDAgb3IgZXhjZWVkaW5nIHRoZSBjYXAsIGBsaW1pdGAgaXMgY2xhbXBlZCB0byBgTUFYX0NSRURFTlRJQUxfUk9PVFNfUEFHRWAuCi0gTm9uLWV4aXN0ZW50L2RlbGV0ZWQgZW50cmllcyBhcmUgc2tpcHBlZC4KLSBSZWFkLW9ubHkgcXVlcnk7IG5vIGF1dGggcmVxdWlyZWQuAAAAAAAVbGlzdF9jcmVkZW50aWFsX3Jvb3RzAAAAAAAAAgAAAAAAAAAGY3Vyc29yAAAAAAAEAAAAAAAAAAVsaW1pdAAAAAAAAAQAAAABAAAH0AAAABJDcmVkZW50aWFsUm9vdFBhZ2UAAA==",
        "AAAAAAAAAQNQYWdpbmF0ZSBjaGlsZCBvdXRwdXQgZGlnZXN0cyBmb3IgYSBwYXJlbnQgcHJvb2Ygb3IgbGluZWFnZSBkaWdlc3QgKCMzMzUpLgoKLSBgb2Zmc2V0YCBpcyAwLWJhc2VkIGludG8gdGhlIHN0YWJsZSByZWdpc3RyYXRpb24gb3JkZXIuCi0gYGxpbWl0YCBtdXN0IGJlIGluIGAxLi49TUFYX0xJTkVBR0VfQ0hJTERSRU5fUEFHRWAuCi0gTWlzc2luZyBwYXJlbnRzIHlpZWxkIGFuIGVtcHR5IHBhZ2Ugd2l0aCBgdG90YWwgPT0gMGAgKHByaXZhY3ktc2FmZSkuAAAAABVsaXN0X2xpbmVhZ2VfY2hpbGRyZW4AAAAAAAADAAAAAAAAAA9wYXJlbnRfcHJvb2ZfaWQAAAAD7gAAACAAAAAAAAAABm9mZnNldAAAAAAABAAAAAAAAAAFbGltaXQAAAAAAAAEAAAAAQAAB9AAAAATTGluZWFnZUNoaWxkcmVuUGFnZQA=",
        "AAAAAAAAAE1SZXZva2UgYW4gZXhpc3RpbmcgcmVjZWlwdC1zaWduaW5nIHB1YmxpYyBrZXkuIElkZW1wb3RlbnQgaWYgYWxyZWFkeSByZXZva2VkLgAAAAAAABVyZXZva2VfcmVjZWlwdF9zaWduZXIAAAAAAAACAAAAAAAAAAVhZG1pbgAAAAAAABMAAAAAAAAACnB1YmxpY19rZXkAAAAAA+4AAABBAAAAAQAAB9AAAAATUmVjZWlwdFNpZ25lclJlY29yZAA=",
        "AAAAAAAAAERBZGQgYW4gYWN0aXZlIGlzc3VlciB0byBhIHRocmVzaG9sZCBzZWFsIHBvbGljeSdzIHNpZ25lciBzZXQgKCMxMjQpLgAAABZhZGRfc2VhbF9wb2xpY3lfc2lnbmVyAAAAAAADAAAAAAAAAAVhZG1pbgAAAAAAABMAAAAAAAAAB3ZlcnNpb24AAAAABAAAAAAAAAAGc2lnbmVyAAAAAAATAAAAAA==",
        "AAAAAAAAAbJBbmNob3IgYW4gaW5kZXBlbmRlbnQgdGltZXN0YW1wIGNsYWltIGZvciBhbiBleGlzdGluZyBwcm9vZi4KCkFsd2F5cyByZWNvcmRzIHRoZSBjdXJyZW50IGxlZGdlciB0aW1lc3RhbXAvc2VxdWVuY2UgYXMgYSBTdGVsbGFyCmluZGVwZW5kZW50IHNvdXJjZS4gT3B0aW9uYWwgYGNsYWltZWRfdGltZWAgYW5kIFJGQyAzMTYxIGNvbW1pdG1lbnQKcmFpc2UgYXNzdXJhbmNlIHdpdGhvdXQgc3RvcmluZyByYXcgdG9rZW5zIG9yIHByaXZhdGUgbWF0ZXJpYWwuCgpSZS1hbmNob3JpbmcgaXMgYWxsb3dlZCBvbmx5IHdoZW4gdGhlIG5ldyBjbGFpbSBpcyBhIHN0cmljdCBhc3N1cmFuY2UKdXBncmFkZSAob3IgYWRkcyBhbiBSRkMgMzE2MSBjb21taXRtZW50KS4gQ29tcGF0aWJsZSBjYWxsZXJzIHRoYXQgb21pdAp0aW1lc3RhbXAgY2xhaW1zIGFyZSB1bmFmZmVjdGVkLgAAAAAAFmFuY2hvcl90aW1lc3RhbXBfY2xhaW0AAAAAAAUAAAAAAAAABWFjdG9yAAAAAAAAEwAAAAAAAAAIcHJvb2ZfaWQAAAPuAAAAIAAAAAAAAAASYXR0ZXN0YXRpb25fZGlnZXN0AAAAAAPuAAAAIAAAAAAAAAAMY2xhaW1lZF90aW1lAAAABgAAAAAAAAAScmZjMzE2MV9jb21taXRtZW50AAAAAAPuAAAAIAAAAAEAAAfQAAAADlRpbWVzdGFtcENsYWltAAA=",
        "AAAAAAAAAjBCaW5kIG9yIHVwZ3JhZGUgYSB2ZXJzaW9uZWQgbWV0YWRhdGEgZW52ZWxvcGUgZm9yIGFuIGV4aXN0aW5nIHByb29mLgoKQ29tcGF0aWJsZSBjYWxsZXJzIHRoYXQgb25seSB1c2UgYHJlZ2lzdGVyXypgIHdpdGggYSBiYXJlCmBtZXRhZGF0YV9oYXNoYCBjb250aW51ZSB0byB3b3JrOiBgc2F2ZV9yZWNvcmRgIHN0YW1wcyBWMSBhdXRvbWF0aWNhbGx5LgpUaGlzIGVudHJ5IHBvaW50IGlzIGZvciBleHBsaWNpdCBWMiAob3IgZnV0dXJlKSBiaW5kaW5ncyBhbmQgdXBncmFkZXMuCgpSdWxlczoKLSBgdmVyc2lvbmAgbXVzdCBiZSBpbiBgMS4uPU1FVEFEQVRBX0VOVkVMT1BFX1ZFUlNJT05fTUFYYAotIGBtZXRhZGF0YV9oYXNoYCBtdXN0IGJlIG5vbi16ZXJvIGFuZCBtYXRjaCB0aGUgcHJvb2YncyBzdG9yZWQgaGFzaAotIGZpcnN0IGJpbmQgbWF5IHNldCBhbnkgc3VwcG9ydGVkIHZlcnNpb24KLSByZS1iaW5kIG1heSBvbmx5IHVwZ3JhZGUgdmVyc2lvbiAobmV2ZXIgZG93bmdyYWRlKQoKQXV0aDogYWRtaW4sIG9yIHRoZSBwcm9vZidzIHNvdXJjZS9pc3N1ZXIgd2hlbiBwcmVzZW50LgAAABZiaW5kX21ldGFkYXRhX2VudmVsb3BlAAAAAAAEAAAAAAAAAAVhY3RvcgAAAAAAABMAAAAAAAAACHByb29mX2lkAAAD7gAAACAAAAAAAAAAB3ZlcnNpb24AAAAABAAAAAAAAAANbWV0YWRhdGFfaGFzaAAAAAAAA+4AAAAgAAAAAQAAB9AAAAAQTWV0YWRhdGFFbnZlbG9wZQ==",
        "AAAAAAAAA/NDbGFzc2lmeSB2ZXJpZmllciBtYXRlcmlhbCBhZ2FpbnN0IHRoZSBjYW5vbmljYWwgYGhweC12aS8xYCBjb2RlYy4KClJlYWQtb25seSwgc2lkZS1lZmZlY3QgZnJlZSwgYW5kIGJvdW5kZWQ6IHRoZSB3b3JrIGlzIE8oMSkgaW4gdGhlIGZyYW1lCnNpemUgYW5kIG5vIHN0b3JhZ2UgaXMgdG91Y2hlZCwgc28gaXQgaXMgc2FmZSB0byBleHBvc2UgcHVibGljbHkgYW5kCnNhZmUgdG8gY2FsbCB3aGlsZSBhbnkgZG9tYWluIGlzIHBhdXNlZC4KCmBzY2hlbWFfaWRgIGlzIFtgU0NIRU1BX0lEX1NJTEVOVF9XSVRORVNTYF0sCltgU0NIRU1BX0lEX1NJTEVOVF9XSVRORVNTX1YyYF0sIG9yIFtgU0NIRU1BX0lEX1JFVk9DQVRJT05fV0lUTkVTU2BdLgpgcHJvb2ZfbGVuYCBpcyB0aGUgbGVuZ3RoIG9mIHRoZSBwcm9vZiBibG9iIHRoZSBjYWxsZXIgaW50ZW5kcyB0byBzdWJtaXQK4oCUIHBhc3NlZCBhcyBhIGxlbmd0aCByYXRoZXIgdGhhbiB0aGUgYmxvYiBpdHNlbGYgc28gY2xhc3NpZmljYXRpb24gbmV2ZXIKdHJhbnNwb3J0cyBwcm9vZiBtYXRlcmlhbC4KClJldHVybnMgW2B2ZXJpZmllcl9pbnB1dHM6OkFDQ0VQVEVEX0NPREVgXSAoYDBgKSB3aGVuIHRoZSBtYXRlcmlhbCBpcwpjYW5vbmljYWwsIG90aGVyd2lzZSB0aGUgc3RhYmxlIFtgUmVqZWN0Q29kZTo6YXNfY29kZWBdIHZhbHVlLiBUaGlzIGlzCnRoZSBvbi1jaGFpbiBoYWxmIG9mIHRoZSBjcm9zcy1sYXllciBjb25mb3JtYW5jZSBjb3JwdXMgaW4KYHprL3ZlY3RvcnMvdmVyaWZpZXJfY29uZm9ybWFuY2VfdjEuanNvbmAuCgpDb21wYXRpYmlsaXR5OiB0aGlzIGVudHJ5IHBvaW50IGlzIHB1cmVseSBhZGRpdGl2ZS4gVGhlIHJlZ2lzdHJhdGlvbgpwYXRocyBzdGlsbCBhcHBseSB0aGUgdjEtbGVuaWVudCBydWxlcyBkZXNjcmliZWQgaW4KYGRvY3MvemstY29uZm9ybWFuY2UtdmVjdG9ycy5tZGA7IHByb21vdGluZyB0aGUgY29kZWMgdG8gZW5mb3JjZW1lbnQgaXMKYSBzZXBhcmF0ZSwgdmVyc2lvbmVkIG1pZ3JhdGlvbi4AAAAAFmNsYXNzaWZ5X3B1YmxpY19pbnB1dHMAAAAAAAMAAAAAAAAACXNjaGVtYV9pZAAAAAAAAAQAAAAAAAAADXB1YmxpY19pbnB1dHMAAAAAAAAOAAAAAAAAAAlwcm9vZl9sZW4AAAAAAAAEAAAAAQAAAAQ=",
        "AAAAAAAAAAAAAAAWZXhwaXJlX2NyZWRlbnRpYWxfcm9vdAAAAAAAAgAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAA9jcmVkZW50aWFsX3Jvb3QAAAAD7gAAACAAAAAA",
        "AAAAAAAAAEZFeHRlbmQgcGVyc2lzdGVudCBzdG9yYWdlIFRUTHMgZm9yIGEgYm91bmRlZCBiYXRjaCAoYDEuLj01MGApIG9mIGtleXMuAAAAAAAWZXh0ZW5kX3BlcnNpc3RlbnRfdHRscwAAAAAAAQAAAAAAAAAEa2V5cwAAA+oAAAfQAAAAB0RhdGFLZXkAAAAAAA==",
        "AAAAAAAAAERSZXR1cm4gdGhlIGN1cnJlbnRseSBhY3RpdmUsIHVuZXhwaXJlZCB0aHJlc2hvbGQgc2VhbCBwb2xpY3kgKCMxMjQpLgAAABZnZXRfYWN0aXZlX3NlYWxfcG9saWN5AAAAAAAAAAAAAQAAA+gAAAfQAAAAClNlYWxQb2xpY3kAAA==",
        "AAAAAAAAAMVSZXR1cm4gdGhlIGN1cnJlbnQgd2luZG93LWJ1Y2tldCB1c2FnZSBmb3IgYGlzc3VlcmAuCgpBdXRvbWF0aWNhbGx5IHJlc29sdmVzIGxlZGdlci10aW1lIHdpbmRvdyByb2xsb3ZlciBzbyBjYWxsZXJzIHNlZSBgY291bnQgPT0gMGAKZm9yIGEgZnJlc2ggYnVja2V0IHdpdGhvdXQgcmVxdWlyaW5nIGFuIGFkbWluIHJlc2V0IHRyYW5zYWN0aW9uLgAAAAAAABZnZXRfaXNzdWVyX3F1b3RhX3VzYWdlAAAAAAABAAAAAAAAAAZpc3N1ZXIAAAAAABMAAAABAAAH0AAAABBJc3N1ZXJRdW90YVVzYWdl",
        "AAAAAAAAAD9SZXR1cm4gdGhlIG51bWJlciBvZiBjdXJyZW50bHkgT3BlbiBkaXNwdXRlcyBmb3IgYSBnaXZlbiBwcm9vZi4AAAAAFmdldF9vcGVuX2Rpc3B1dGVfY291bnQAAAAAAAEAAAAAAAAACHByb29mX2lkAAAD7gAAACAAAAABAAAABA==",
        "AAAAAAAAAEJSZXR1cm4gdGhlIGNvbW1pdHRlZCByZWNlaXB0IGRpZ2VzdCByZWNvcmQgZm9yIGBwcm9vZl9pZGAsIGlmIGFueS4AAAAAABZnZXRfcmVjZWlwdF9jb21taXRtZW50AAAAAAABAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAQAAA+gAAAfQAAAAF1JlY2VpcHRDb21taXRtZW50UmVjb3JkAA==",
        "AAAAAAAAADZQcm9wb3NlIGEgY3JpdGljYWwgYWN0aW9uIHRvIHRoZSBhY3RpdmUgYWRtaW4gY291bmNpbC4AAAAAABZwcm9wb3NlX2NvdW5jaWxfYWN0aW9uAAAAAAAEAAAAAAAAAAhwcm9wb3NlcgAAABMAAAAAAAAABmFjdGlvbgAAAAAABAAAAAAAAAAGdGFyZ2V0AAAAAAATAAAAAAAAAAdwYXlsb2FkAAAAA+4AAAAgAAAAAQAAAAQ=",
        "AAAAAAAAAAAAAAAWcmV2b2tlX2NyZWRlbnRpYWxfcm9vdAAAAAAAAgAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAA9jcmVkZW50aWFsX3Jvb3QAAAAD7gAAACAAAAAA",
        "AAAAAAAAATNVcGRhdGUgYW4gYWN0aXZlIGlzc3VlcidzIG1ldGFkYXRhIGhhc2guCgpSZXF1aXJlcyBhZG1pbiBhdXRoIGFuZCB0aGF0IGBpc3N1ZXJgIGlzIGFjdGl2ZS4KT25seSB0aGUgbWV0YWRhdGEgaGFzaCBjaGFuZ2VzOyBhY3RpdmUgc3RhdHVzIGFuZCBhbnkgcm90YXRpb24gZ3JhY2UKcmVjb3JkcyBhcmUgcHJlc2VydmVkLgoKIyBSZXZlcnRzCgotIGBVbmF1dGhvcml6ZWRgIGlmIGBhZG1pbmAgaXMgbm90IHRoZSBjdXJyZW50IGFkbWluCi0gYFVua25vd25Jc3N1ZXJgIGlmIGBpc3N1ZXJgIGRvZXMgbm90IGV4aXN0IG9yIGlzIGluYWN0aXZlAAAAABZ1cGRhdGVfaXNzdWVyX21ldGFkYXRhAAAAAAADAAAAAAAAAAVhZG1pbgAAAAAAABMAAAAAAAAABmlzc3VlcgAAAAAAEwAAAAAAAAANbWV0YWRhdGFfaGFzaAAAAAAAA+4AAAAgAAAAAA==",
        "AAAAAAAAABpDYW5jZWwgYSBjb3VuY2lsIHByb3Bvc2FsLgAAAAAAF2NhbmNlbF9jb3VuY2lsX3Byb3Bvc2FsAAAAAAIAAAAAAAAABmNhbGxlcgAAAAAAEwAAAAAAAAALcHJvcG9zYWxfaWQAAAAABAAAAAA=",
        "AAAAAAAAAFpSZXR1cm4gdGhlIGJvdW5kIHJvbGUtY2hhbmdlIGludGVudCBkaWdlc3QgZm9yIHRoZSBwZW5kaW5nIGFkbWluIHRyYW5zZmVyLCBpZiBhbnkgKCMxMTg0KS4AAAAAABdnZXRfYWRtaW5faW50ZW50X2RpZ2VzdAAAAAAAAAAAAQAAA+gAAAPuAAAAIA==",
        "AAAAAAAAAFZSZXR1cm4gaG93IG1hbnkgZGVyaXZhdGl2ZXMgaGF2ZSBjaGFyZ2VkIGBwYXJlbnRfcHJvb2ZfaWRgJ3Mgb3V0LWRlZ3JlZSBidWRnZXQgKCMzMzMpLgAAAAAAF2dldF9saW5lYWdlX2NoaWxkX2NvdW50AAAAAAEAAAAAAAAAD3BhcmVudF9wcm9vZl9pZAAAAAPuAAAAIAAAAAEAAAAE",
        "AAAAAAAAAEJSZXR1cm4gdGhlIHRvdGFsIG51bWJlciBvZiBkaXNwdXRlcyBldmVyIG9wZW5lZCBmb3IgYSBnaXZlbiBwcm9vZi4AAAAAABdnZXRfcHJvb2ZfZGlzcHV0ZV9jb3VudAAAAAABAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAQAAAAQ=",
        "AAAAAAAAAAAAAAAXZ2V0X3Byb29mX2hpc3RvcnlfY291bnQAAAAAAQAAAAAAAAAIcHJvb2ZfaWQAAAPuAAAAIAAAAAEAAAAE",
        "AAAAAAAAAFRSZXR1cm4gdGhlIGNvdW50IG9mIGN1cnJlbnRseSB2YWxpZCwgdW5leHBpcmVkIGFwcHJvdmFscyBmcm9tIGFjdGl2ZSBzaWduZXJzICgjMTI0KS4AAAAXZ2V0X3NlYWxfYXBwcm92YWxfY291bnQAAAAAAQAAAAAAAAAIcHJvb2ZfaWQAAAPuAAAAIAAAAAEAAAAE",
        "AAAAAAAAAdpFbnVtZXJhdGUgdGltZWxvY2tlZCBwcm9wb3NhbHMgYWNyb3NzIHNlcXVlbnRpYWwgSURzLgoKLSBgY3Vyc29yYDogSUQgb2Zmc2V0IHRvIHN0YXJ0IHNjYW5uaW5nIGZyb20gKGUuZy4gMCBvciAxIHN0YXJ0cyBhdCBmaXJzdCBwcm9wb3NhbCkuClByb3Bvc2FscyB1c2UgMS1iYXNlZCBzZXF1ZW50aWFsIElEcy4gSWYgYGN1cnNvciA9PSAwYCwgc2Nhbm5pbmcgYmVnaW5zIGF0IElEIDEuCi0gYGxpbWl0YDogbWF4aW11bSBudW1iZXIgb2YgcHJvcG9zYWxzIHRvIHJldHVybjsgY2FwcGVkIGF0IGBNQVhfVElNRUxPQ0tfUFJPUE9TQUxTX1BBR0VgLgpJZiAwIG9yIGV4Y2VlZGluZyB0aGUgY2FwLCBgbGltaXRgIGlzIGNsYW1wZWQgdG8gYE1BWF9USU1FTE9DS19QUk9QT1NBTFNfUEFHRWAuCi0gTm9uLWV4aXN0ZW50L2RlbGV0ZWQgcHJvcG9zYWxzIGFyZSBza2lwcGVkLgotIFJlYWQtb25seSBxdWVyeTsgbm8gYXV0aCByZXF1aXJlZC4AAAAAABdsaXN0X3RpbWVsb2NrX3Byb3Bvc2FscwAAAAACAAAAAAAAAAZjdXJzb3IAAAAAAAQAAAAAAAAABWxpbWl0AAAAAAAABAAAAAEAAAfQAAAAFFRpbWVsb2NrUHJvcG9zYWxQYWdl",
        "AAAAAAAABABSZWdpc3RlciBtdWx0aXBsZSB2aWRlbyBoYXNoZXMgdW5kZXIgdGhlIHNhbWUgY3JlZGVudGlhbCB1c2luZyBhCnNpbmdsZSBhZ2dyZWdhdGVkIFVsdHJhSG9uayBwcm9vZiBwcm9kdWNlZCBieSB0aGUgU2lsZW50IFdpdG5lc3MKQWdncmVnYXRvciBjaXJjdWl0LgoKIyBBcmd1bWVudHMKCiogYGVudmAg4oCTIFNvcm9iYW4gZW52aXJvbm1lbnQKKiBgYmF0Y2hfaWRgIOKAkyBVbmlxdWUgYmF0Y2ggaWRlbnRpZmllciAoc2VydmVzIGFzIHRoZSBiYXRjaCBwcm9vZl9pZCkKKiBgbWV0YWRhdGFfaGFzaGAg4oCTIFNoYXJlZCBtZXRhZGF0YSBoYXNoIGZvciBhbGwgZWxlbWVudHMgaW4gdGhlIGJhdGNoCiogYHB1YmxpY19pbnB1dHNgIOKAkyBBZ2dyZWdhdGVkIHB1YmxpYyBpbnB1dHMgKDEgZG9tYWluIHNlcGFyYXRvciArCk1BWF9BR0dSRUdBVElPTl9TSVpFIMOXIDQgZmllbGQgZWxlbWVudHM7IHNlZSBBR0dSRUdBVEVEX1BVQkxJQ19JTlBVVF9TSVpFKQoqIGBwcm9vZmAg4oCTIEFnZ3JlZ2F0ZWQgVWx0cmFIb25rIHByb29mIGJ5dGVzCiogYHZpZGVvX2hhc2hlc2Ag4oCTIE9yZGVyZWQgbGlzdCBvZiB2aWRlbyBoYXNoZXMgaW4gdGhlIGJhdGNoIChtdXN0Cm1hdGNoIHRoZSBvcmRlciBpbiBwdWJsaWNfaW5wdXRzKQoKIyBQYW5pY3MKCi0gYEJhdGNoU2l6ZUV4Y2VlZGVkYCBpZiBgdmlkZW9faGFzaGVzLmxlbigpID4gTUFYX0FHR1JFR0FUSU9OX1NJWkVgCi0gYEJhdGNoQ291bnRNaXNtYXRjaGAgaWYgdGhlIG51bWJlciBvZiB2aWRlbyBoYXNoZXMgZG9lc24ndCBtYXRjaAp0aGUgcGFyc2VkIGJhdGNoIGNvdW50IGZyb20gcHVibGljIGlucHV0cwotIGBJbnZhbGlkUHVibGljSW5wdXRzYCBpZiB0aGUgZG9tYWluIHNlcGFyYXRvciBvciBwdWJsaWMgaW5wdXQgbGF5b3V0CmlzIHdyb25nCi0gYFVua25vd25DcmVkZW50aWFsUm9vdGAgaWYgdGhlIGNyZWRlbnRpYWwgcm9vdCBpcyBub3QgcmVnaXN0ZXJlZAotIGBSZXZva2VkQ3JlZGVudGlhbFJvb3RgIGlmIHRoZSBjcmVkZW50aWFsIHJvb3QgaGFzAAAAF3JlZ2lzdGVyX2JhdGNoX3ZlcmlmaWVkAAAAAAUAAAAAAAAACGJhdGNoX2lkAAAD7gAAACAAAAAAAAAADW1ldGFkYXRhX2hhc2gAAAAAAAPuAAAAIAAAAAAAAAANcHVibGljX2lucHV0cwAAAAAAAA4AAAAAAAAABXByb29mAAAAAAAADgAAAAAAAAAMdmlkZW9faGFzaGVzAAAD6gAAA+4AAAAgAAAAAQAAA+oAAAfQAAAAC1Byb29mUmVjb3JkAA==",
        "AAAAAAAAAR9SZWdpc3RlciBhIFRpZXIgMyBwdWJsaWMtc2VhbCBwcm9vZiBvbiBgaXNzdWVyYCdzIGJlaGFsZi4KClRoZSBpc3N1ZXIgbXVzdCBzdGlsbCBiZSBhIHJlZ2lzdGVyZWQsIGFjdGl2ZSBpc3N1ZXIg4oCUIGEgZGVsZWdhdGlvbgpuZXZlciBzdWJzdGl0dXRlcyBmb3IgaXNzdWVyIHN0YW5kaW5nLCBpdCBvbmx5IGxldHMgc29tZW9uZSBlbHNlCmV4ZXJjaXNlIGl0LiBTdWJqZWN0IHRvIHRoZSBzYW1lIFRpZXIgMyBwYXVzZSBkb21haW4gYW5kIHVuaXF1ZW5lc3MKcnVsZXMgYXMgYHJlZ2lzdGVyX3NlYWxgLgAAAAAXcmVnaXN0ZXJfc2VhbF9kZWxlZ2F0ZWQAAAAABQAAAAAAAAAIZGVsZWdhdGUAAAATAAAAAAAAAAZpc3N1ZXIAAAAAABMAAAAAAAAACnZpZGVvX2hhc2gAAAAAA+4AAAAgAAAAAAAAAA1tZXRhZGF0YV9oYXNoAAAAAAAD7gAAACAAAAAAAAAACHByb29mX2lkAAAD7gAAACAAAAABAAAH0AAAAAtQcm9vZlJlY29yZAA=",
        "AAAAAAAAAHVBY2NlcHQgYSBwZW5kaW5nIGFkbWluIHRyYW5zZmVyIHdoaWxlIGV4cGxpY2l0bHkgYmluZGluZyB0aGUgZXhwZWN0ZWQKdGFyZ2V0IHJvbGUgYW5kIG9uLWNoYWluIGludGVudCBkaWdlc3QgKCMxMTg0KS4AAAAAAAAYYWNjZXB0X2FkbWluX3dpdGhfaW50ZW50AAAAAwAAAAAAAAANcGVuZGluZ19hZG1pbgAAAAAAABMAAAAAAAAADWV4cGVjdGVkX3JvbGUAAAAAAAAEAAAAAAAAAA9leHBlY3RlZF9kaWdlc3QAAAAD7gAAACAAAAAA",
        "AAAAAAAAADJSZWNvcmQgYSBjb3VuY2lsIG1lbWJlcidzIGFwcHJvdmFsIGZvciBhIHByb3Bvc2FsLgAAAAAAGGFwcHJvdmVfY291bmNpbF9wcm9wb3NhbAAAAAIAAAAAAAAABm1lbWJlcgAAAAAAEwAAAAAAAAALcHJvcG9zYWxfaWQAAAAABAAAAAEAAAAB",
        "AAAAAAAAAIBFeGVjdXRlIGEgY291bmNpbCBwcm9wb3NhbCB3aGlsZSBleHBsaWNpdGx5IHZlcmlmeWluZyB0aGUgZXhwZWN0ZWQgdGFyZ2V0CnJvbGUsIHRhcmdldCBhZGRyZXNzLCBhbmQgYm91bmQgaW50ZW50IGRpZ2VzdCAoIzExODQpLgAAABhleGVjX2NvdW5jaWxfd2l0aF9pbnRlbnQAAAAFAAAAAAAAAAZjYWxsZXIAAAAAABMAAAAAAAAAC3Byb3Bvc2FsX2lkAAAAAAQAAAAAAAAADWV4cGVjdGVkX3JvbGUAAAAAAAAEAAAAAAAAAA9leHBlY3RlZF90YXJnZXQAAAAAEwAAAAAAAAAPZXhwZWN0ZWRfZGlnZXN0AAAAA+4AAAAgAAAAAA==",
        "AAAAAAAAAFFFeGVjdXRlIGEgY291bmNpbCBwcm9wb3NhbCBvbmNlIHRocmVzaG9sZCBkaXN0aW5jdCBtZW1iZXIgYXBwcm92YWxzIGFyZSBnYXRoZXJlZC4AAAAAAAAYZXhlY3V0ZV9jb3VuY2lsX3Byb3Bvc2FsAAAAAgAAAAAAAAAGY2FsbGVyAAAAAAATAAAAAAAAAAtwcm9wb3NhbF9pZAAAAAAEAAAAAA==",
        "AAAAAAAAAiFTZXR0bGUgYSBsYXBzZWQgaXNzdWVyLXJvdGF0aW9uIGdyYWNlIHdpbmRvdyAoIzMyMykuCgpQZXJtaXNzaW9ubGVzcyBieSBkZXNpZ246IHRoZSB0cmFuc2l0aW9uIGlzIGZ1bGx5IGRldGVybWluZWQgYnkgdGhlCnN0b3JlZCBgZ3JhY2VfZXhwaXJlc19hdGAsIHNvIGFueSBjYWxsZXIgbWF5IGNsb3NlIHRoZSByZWNvcmQgb25jZSB0aGUKd2luZG93IGhhcyBsYXBzZWQsIGFuZCBubyBhZG1pbiBrZXkgaXMgbmVlZGVkIHRvIHN0b3AgYSByZXRpcmVkIGtleSBmcm9tCmhvbGRpbmcgc3RhbmRpbmcuIENhbGxhYmxlIGF0IGV4YWN0bHkgYGdyYWNlX2V4cGlyZXNfYXRgIGFuZCBhZnRlciBpdDsKdGhlIHJlY29yZCBpcyByZW1vdmVkIGFuZCBgSXNzdWVyUm90YXRpb25HcmFjZUV4cGlyZWRgIGlzIHB1Ymxpc2hlZC4KCiMgUmV2ZXJ0cwoKLSBgSXNzdWVyUm90YXRpb25Ob3RGb3VuZGAgICAgICAgICBpZiBubyByb3RhdGlvbiByZWNvcmQgZXhpc3RzCi0gYElzc3VlclJvdGF0aW9uR3JhY2VTdGlsbEFjdGl2ZWAgaWYgdGhlIHdpbmRvdyBoYXMgbm90IGxhcHNlZAAAAAAAABhmaW5hbGl6ZV9pc3N1ZXJfcm90YXRpb24AAAABAAAAAAAAAAZpc3N1ZXIAAAAAABMAAAAA",
        "AAAAAAAAAIdFeGVjdXRlIGEgbWF0dXJlZCB0aW1lbG9jayBwcm9wb3NhbCB3aGlsZSB2ZXJpZnlpbmcgdGhlIGNhbGxlcidzIGV4cGVjdGVkCnRhcmdldCByb2xlLCB0YXJnZXQgYWRkcmVzcywgYW5kIGJvdW5kIGludGVudCBkaWdlc3QgKCMxMTg0KS4AAAAAGWV4ZWNfdGltZWxvY2tfd2l0aF9pbnRlbnQAAAAAAAAFAAAAAAAAAAZjYWxsZXIAAAAAABMAAAAAAAAAC3Byb3Bvc2FsX2lkAAAAAAQAAAAAAAAADWV4cGVjdGVkX3JvbGUAAAAAAAAEAAAAAAAAAA9leHBlY3RlZF90YXJnZXQAAAAAEwAAAAAAAAAPZXhwZWN0ZWRfZGlnZXN0AAAAA+4AAAAgAAAAAA==",
        "AAAAAAAAAFpSZXR1cm4gdGhlIGJvdW5kIHJvbGUtY2hhbmdlIGludGVudCBkaWdlc3QgZm9yIGBwcm9wb3NhbF9pZGAgaW4gdGhlIGNvdW5jaWwgcXVldWUgKCMxMTg0KS4AAAAAABlnZXRfY291bmNpbF9pbnRlbnRfZGlnZXN0AAAAAAAAAQAAAAAAAAALcHJvcG9zYWxfaWQAAAAABAAAAAEAAAPoAAAD7gAAACA=",
        "AAAAAAAAADtSZXR1cm4gdGhlIHRvdGFsIG51bWJlciBvZiBpbmRleGVkIGNyZWRlbnRpYWwgcm9vdHMgKCM3MzEpLgAAAAAZZ2V0X2NyZWRlbnRpYWxfcm9vdF9jb3VudAAAAAAAAAAAAAABAAAABA==",
        "AAAAAAAAAEZSZXR1cm4gdGhlIHBlbmRpbmcgYWRtaW4gY291bmNpbCBjdXJyZW50bHkgaW4gdGltZWxvY2sgZGVsYXksIG9yIE5vbmUuAAAAAAAZZ2V0X3BlbmRpbmdfYWRtaW5fY291bmNpbAAAAAAAAAAAAAABAAAD6AAAB9AAAAAMQWRtaW5Db3VuY2ls",
        "AAAAAAAAAAAAAAAZcHJvcG9zZV90aW1lbG9ja2VkX2FjdGlvbgAAAAAAAAQAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAAGYWN0aW9uAAAAAAAEAAAAAAAAAAZ0YXJnZXQAAAAAABMAAAAAAAAAB3BheWxvYWQAAAAD7gAAACAAAAABAAAABA==",
        "AAAAAAAAAZdSZWdpc3RlciBhIFRpZXIgMiBjb25zaXN0ZW50LXNvdXJjZSBwcm9vZiBvbiBgc291cmNlYCdzIGJlaGFsZi4KCkF1dGhvcml6ZXMgdGhlICpkZWxlZ2F0ZSosIG5vdCB0aGUgc291cmNlOiB0aGUgc291cmNlJ3Mga2V5IGlzIG5ldmVyCnJlcXVpcmVkIGF0IGNhbGwgdGltZS4gVGhlIHN0b3JlZCBgUHJvb2ZSZWNvcmRgIHN0aWxsIG5hbWVzIGBzb3VyY2VgLAp3aGlsZSB0aGUgZGVsZWdhdGUgaXMgcmVjb3JkZWQgaW4gdGhlIHByb29mJ3MgbGlmZWN5Y2xlIGhpc3RvcnksIHNvIHRoZQphdWRpdCB0cmFpbCBkaXN0aW5ndWlzaGVzIGF1dGhvcml0eSBmcm9tIGFjdG9yLgoKU3ViamVjdCB0byB0aGUgc2FtZSBUaWVyIDIgcGF1c2UgZG9tYWluIGFuZCB1bmlxdWVuZXNzIHJ1bGVzIGFzCmByZWdpc3Rlcl9zb3VyY2VgLgAAAAAZcmVnaXN0ZXJfc291cmNlX2RlbGVnYXRlZAAAAAAAAAUAAAAAAAAACGRlbGVnYXRlAAAAEwAAAAAAAAAGc291cmNlAAAAAAATAAAAAAAAAAp2aWRlb19oYXNoAAAAAAPuAAAAIAAAAAAAAAANbWV0YWRhdGFfaGFzaAAAAAAAA+4AAAAgAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAQAAB9AAAAALUHJvb2ZSZWNvcmQA",
        "AAAAAAAAADRSZW1vdmUgYSBzaWduZXIgZnJvbSBhIHRocmVzaG9sZCBzZWFsIHBvbGljeSAoIzEyNCkuAAAAGXJlbW92ZV9zZWFsX3BvbGljeV9zaWduZXIAAAAAAAADAAAAAAAAAAVhZG1pbgAAAAAAABMAAAAAAAAAB3ZlcnNpb24AAAAABAAAAAAAAAAGc2lnbmVyAAAAAAATAAAAAA==",
        "AAAAAAAAAAAAAAAaYWN0aXZhdGVfdmVyaWZpZXJfcm90YXRpb24AAAAAAAEAAAAAAAAABWFkbWluAAAAAAAAEwAAAAA=",
        "AAAAAAAAAAAAAAAaY2FuY2VsX3RpbWVsb2NrZWRfcHJvcG9zYWwAAAAAAAIAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAALcHJvcG9zYWxfaWQAAAAABAAAAAA=",
        "AAAAAAAAAFtEZXRlcm1pbmlzdGljYWxseSBjb21wdXRlIHRoZSBjYW5vbmljYWwgZG9tYWluLXNlcGFyYXRlZCByb2xlLWNoYW5nZSBpbnRlbnQgZGlnZXN0ICgjMTE4NCkuAAAAABpjb21wdXRlX3JvbGVfaW50ZW50X2RpZ2VzdAAAAAAABwAAAAAAAAAMcXVldWVfZG9tYWluAAAABAAAAAAAAAALcHJvcG9zYWxfaWQAAAAABAAAAAAAAAALdGFyZ2V0X3JvbGUAAAAABAAAAAAAAAAIcHJvcG9zZXIAAAATAAAAAAAAAAZ0YXJnZXQAAAAAABMAAAAAAAAAB3BheWxvYWQAAAAD7gAAACAAAAAAAAAACmNyZWF0ZWRfYXQAAAAAAAYAAAABAAAD7gAAACA=",
        "AAAAAAAAAAAAAAAaZW1lcmdlbmN5X2V4ZWN1dGVfdGltZWxvY2sAAAAAAAIAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAALcHJvcG9zYWxfaWQAAAAABAAAAAA=",
        "AAAAAAAAAAAAAAAaZ2V0X2NvdW5jaWxfcHJvcG9zYWxfY291bnQAAAAAAAAAAAABAAAABA==",
        "AAAAAAAAAElSZXR1cm4gaG93IG1hbnkgY2hpbGQgZGlnZXN0cyBhcmUgaW5kZXhlZCB1bmRlciBgcGFyZW50X3Byb29mX2lkYCAoIzMzNSkuAAAAAAAAGmdldF9saW5lYWdlX2NoaWxkcmVuX2NvdW50AAAAAAABAAAAAAAAAA9wYXJlbnRfcHJvb2ZfaWQAAAAD7gAAACAAAAABAAAABA==",
        "AAAAAAAAADhSZXR1cm4gYSB0aHJlc2hvbGQgc2VhbCBwb2xpY3kgYnkgdmVyc2lvbiBudW1iZXIgKCMxMjQpLgAAABpnZXRfc2VhbF9wb2xpY3lfYnlfdmVyc2lvbgAAAAAAAQAAAAAAAAAHdmVyc2lvbgAAAAAEAAAAAQAAA+gAAAfQAAAAClNlYWxQb2xpY3kAAA==",
        "AAAAAAAAALBSZXR1cm4gdGhlIHBlcnNpc3RlbnQgc3RvcmFnZSBzY2hlbWEgdmVyc2lvbi4KCk1pc3Npbmcga2V5cyAocHJlLSM4NSBkZXBsb3ltZW50cykgYXJlIHRyZWF0ZWQgYXMgVjEgc28gY2FsbGVycyBhbmQKdGhlIHVwZ3JhZGUgaGFybmVzcyBzdGF5IGNvbXBhdGlibGUgd2l0aG91dCBhIGZvcmNlZCByZXdyaXRlLgAAABpnZXRfc3RvcmFnZV9zY2hlbWFfdmVyc2lvbgAAAAAAAAAAAAEAAAAE",
        "AAAAAAAAAFtSZXR1cm4gdGhlIGJvdW5kIHJvbGUtY2hhbmdlIGludGVudCBkaWdlc3QgZm9yIGBwcm9wb3NhbF9pZGAgaW4gdGhlIHRpbWVsb2NrIHF1ZXVlICgjMTE4NCkuAAAAABpnZXRfdGltZWxvY2tfaW50ZW50X2RpZ2VzdAAAAAAAAQAAAAAAAAALcHJvcG9zYWxfaWQAAAAABAAAAAEAAAPoAAAD7gAAACA=",
        "AAAAAAAAAKRSZWdpc3RlciBhIFRpZXIgMiBzb3VyY2UgYmF0Y2ggcm9vdC4KCkFsbG93cyBoaWdoLXZvbHVtZSBUaWVyIDIgc291cmNlcyB0byBhbmNob3IgbWFueSBpdGVtcyBpbiBhIHNpbmdsZSB0cmFuc2FjdGlvbgpieSBjb21taXR0aW5nIHRoZSByb290IG9mIGEgYmluYXJ5IE1lcmtsZSB0cmVlLgAAABpyZWdpc3Rlcl9zb3VyY2VfYmF0Y2hfcm9vdAAAAAAABAAAAAAAAAAGc291cmNlAAAAAAATAAAAAAAAAARyb290AAAD7gAAACAAAAAAAAAABWNvdW50AAAAAAAABAAAAAAAAAANbWV0YWRhdGFfaGFzaAAAAAAAA+4AAAAgAAAAAQAAB9AAAAALQmF0Y2hSZWNvcmQA",
        "AAAAAAAAAAAAAAAacm9sbGJhY2tfdmVyaWZpZXJfcm90YXRpb24AAAAAAAEAAAAAAAAABWFkbWluAAAAAAAAEwAAAAA=",
        "AAAAAAAAAAAAAAAac2NoZWR1bGVfdmVyaWZpZXJfcm90YXRpb24AAAAAAAUAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAAIdmVyaWZpZXIAAAATAAAAAAAAABFhY3RpdmF0aW9uX2xlZGdlcgAAAAAAAAYAAAAAAAAADm92ZXJsYXBfd2luZG93AAAAAAAGAAAAAAAAAA9yb2xsYmFja193aW5kb3cAAAAABgAAAAA=",
        "AAAAAAAAAAAAAAAbZXhlY3V0ZV90aW1lbG9ja2VkX3Byb3Bvc2FsAAAAAAIAAAAAAAAABmNhbGxlcgAAAAAAEwAAAAAAAAALcHJvcG9zYWxfaWQAAAAABAAAAAA=",
        "AAAAAAAAAAAAAAAbZ2V0X3RpbWVsb2NrX21pbl9kZWxheV9zZWNzAAAAAAAAAAABAAAABg==",
        "AAAAAAAAAAAAAAAbZ2V0X3RpbWVsb2NrX3Byb3Bvc2FsX2NvdW50AAAAAAAAAAABAAAABA==",
        "AAAAAAAAAAAAAAAbcmVnaXN0ZXJfYW5vbnltb3VzX3ZlcmlmaWVkAAAAAAUAAAAAAAAACnZpZGVvX2hhc2gAAAAAA+4AAAAgAAAAAAAAAA1tZXRhZGF0YV9oYXNoAAAAAAAD7gAAACAAAAAAAAAACHByb29mX2lkAAAD7gAAACAAAAAAAAAADXB1YmxpY19pbnB1dHMAAAAAAAAOAAAAAAAAAAVwcm9vZgAAAAAAAA4AAAABAAAH0AAAAAtQcm9vZlJlY29yZAA=",
        "AAAAAAAAAAAAAAAbc2V0X3RpbWVsb2NrX21pbl9kZWxheV9zZWNzAAAAAAIAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAAKZGVsYXlfc2VjcwAAAAAABgAAAAA=",
        "AAAAAAAAAAAAAAAbdmVyaWZ5X3NlbGVjdGl2ZV9kaXNjbG9zdXJlAAAAAAIAAAAAAAAADXB1YmxpY19pbnB1dHMAAAAAAAAOAAAAAAAAAAVwcm9vZgAAAAAAAA4AAAAA",
        "AAAAAAAAAEFDYW5jZWwgYSBwZW5kaW5nIGFkbWluIGNvdW5jaWwgYmVmb3JlIGl0cyB0aW1lbG9jayBkZWxheSBleHBpcmVzLgAAAAAAABxjYW5jZWxfcGVuZGluZ19hZG1pbl9jb3VuY2lsAAAAAQAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAA==",
        "AAAAAAAAAORSZWFkLW9ubHk6IG1heSBhIHByb29mIGNhcnJ5aW5nIGB2ZXJzaW9uYCBiZSBhY2NlcHRlZCByaWdodCBub3c/CgpUcnVlIG9ubHkgd2hlbiBgdmVyc2lvbmAgaXMgYm90aCBmcmFtYWJsZSBieSB0aGlzIHdhc20gYnVpbGQgYW5kIGluc2lkZQp0aGUgYWN0aXZlIHZlcmlmaWVyJ3MgZGVjbGFyZWQgd2luZG93LiBDYWxsZXJzIGNhbiBwcmUtZmxpZ2h0IHdpdGhvdXQgYQp0cmlhbCB0cmFuc2FjdGlvbi4AAAAcaXNfc3VwcG9ydGVkX2NpcmN1aXRfdmVyc2lvbgAAAAEAAAAAAAAAB3ZlcnNpb24AAAAABAAAAAEAAAAB",
        "AAAAAAAAAL5UaGUgYWN0aXZlIHZlcmlmaWVyJ3MgY2lyY3VpdC12ZXJzaW9uIHdpbmRvdyAoIzM0MykuCgpBbiB1bmRlY2xhcmVkIHdpbmRvdyBhbnN3ZXJzIGFzIHRoZSBmdWxsIGJ1aWx0LWluIHJhbmdlLCBzbyBhIHByZS0jMzQzCmRlcGxveW1lbnQgcmVwb3J0cyB3aGF0IGl0IGFjdHVhbGx5IGVuZm9yY2VzIGluc3RlYWQgb2YgZXJyb3JpbmcuAAAAAAAdZ2V0X3ZlcmlmaWVyX2NpcmN1aXRfdmVyc2lvbnMAAAAAAAAAAAAAAQAAB9AAAAAXVmVyaWZpZXJDaXJjdWl0VmVyc2lvbnMA",
        "AAAAAAAAADFXaGV0aGVyIGB2ZXJzaW9uYCBpcyBhY2NlcHRlZCBieSB0aGlzIHdhc20gYnVpbGQuAAAAAAAAHWlzX3N1cHBvcnRlZF9lbnZlbG9wZV92ZXJzaW9uAAAAAAAAAQAAAAAAAAAHdmVyc2lvbgAAAAAEAAAAAQAAAAE=",
        "AAAAAAAAASpSZXNvbHZlIHRoZSBlbnZlbG9wZSB2ZXJzaW9uIGZvciBhIHByb29mLgoKUmV0dXJucyB0aGUgc3RvcmVkIGVudmVsb3BlIHZlcnNpb24gd2hlbiBwcmVzZW50OyBvdGhlcndpc2UKYE1FVEFEQVRBX0VOVkVMT1BFX1ZFUlNJT05fREVGQVVMVGAgZm9yIHByb29mcyB0aGF0IGV4aXN0IHdpdGhvdXQgYW4KZXhwbGljaXQgZW52ZWxvcGUgcm93IChwcmUtIzMxNyAvIHN0YW1wZWQgY2FsbGVycykuIFJldHVybnMgYDBgIHdoZW4KdGhlIHByb29mIGlzIHVua25vd24gKGNhbGxlcnMgbXVzdCB0cmVhdCAwIGFzIG5vdC1mb3VuZCkuAAAAAAAdcmVzb2x2ZV9tZXRhZGF0YV9lbnZlbG9wZV92ZXIAAAAAAAABAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAQAAAAQ=",
        "AAAAAAAAAotEZWNsYXJlIHRoZSBjaXJjdWl0LXZlcnNpb24gd2luZG93IHRoZSBhY3RpdmUgdmVyaWZpZXIgY2FuIGNoZWNrICgjMzQzKS4KCkFkbWluLW9ubHkgYW5kIGFkZGl0aXZlLiBgbWluX3ZlcnNpb24uLj1tYXhfdmVyc2lvbmAgbXVzdCBsaWUgaW5zaWRlCnRoaXMgd2FzbSBidWlsZCdzIG93biBzdXBwb3J0ZWQgcmFuZ2U7IGFuIGVtcHR5IG9yIG91dC1vZi1yYW5nZSB3aW5kb3cKZmFpbHMgd2l0aCB0aGUgc3RhYmxlIGBJbnZhbGlkQ2lyY3VpdFZlcnNpb25SYW5nZWAgY29kZSByYXRoZXIgdGhhbgpiZWluZyBzaWxlbnRseSBjbGFtcGVkLiBPbmNlIGRlY2xhcmVkLCBldmVyeSBwcm9vZi12ZXJpZnlpbmcgZW50cnkgcG9pbnQKcmVmdXNlcyBhIHByb29mIHdob3NlIGNpcmN1aXQgdmVyc2lvbiBmYWxscyBvdXRzaWRlIHRoZSB3aW5kb3cgKmJlZm9yZSoKdGhlIGV4dGVybmFsIHZlcmlmaWVyIGlzIGludm9rZWQsIHNvIGFuIHVuc3VwcG9ydGVkIHZlcnNpb24gY2FuIG5ldmVyCnJlYWNoIGEgZGVwZW5kZW5jeSB0aGF0IGNhbm5vdCBhbnN3ZXIuCgpSZXN0b3JlIHRoZSBkZWZhdWx0IGJ5IHNldHRpbmcgdGhlIHdpbmRvdyBiYWNrIHRvCmBNSU5fU1VQUE9SVEVEX0NJUkNVSVRfVkVSU0lPTi4uPU1BWF9TVVBQT1JURURfQ0lSQ1VJVF9WRVJTSU9OYC4AAAAAHXNldF92ZXJpZmllcl9jaXJjdWl0X3ZlcnNpb25zAAAAAAAAAwAAAAAAAAAFYWRtaW4AAAAAAAATAAAAAAAAAAttaW5fdmVyc2lvbgAAAAAEAAAAAAAAAAttYXhfdmVyc2lvbgAAAAAEAAAAAA==",
        "AAAAAAAAAOtWZXJpZnkgY3J5cHRvZ3JhcGhpYyBpbmNsdXNpb24gb2YgYSBsZWFmIGluIGEgc291cmNlIGJhdGNoIHJvb3QuCgpFdmFsdWF0ZXMgYSBiaW5hcnkgTWVya2xlIGluY2x1c2lvbiBwcm9vZiB1c2luZyBTSEEtMjU2IHdpdGggZG9tYWluLXNlcGFyYXRlZApsZWFmIChgMHgwMGApIGFuZCBub2RlIChgMHgwMWApIGhhc2hpbmcgdG8gcHJldmVudCBzZWNvbmQtcHJlaW1hZ2UgYXR0YWNrcwpieSBjb25zdHJ1Y3Rpb24uAAAAAB12ZXJpZnlfc291cmNlX2JhdGNoX2luY2x1c2lvbgAAAAAAAAQAAAAAAAAABHJvb3QAAAPuAAAAIAAAAAAAAAAEbGVhZgAAA+4AAAAgAAAAAAAAAAVwcm9vZgAAAAAAA+oAAAPuAAAAIAAAAAAAAAAFaW5kZXgAAAAAAAAEAAAAAQAAAAE=",
        "AAAAAAAAAL5SZXR1cm4gb25seSB0aGUgc3RvcmVkIHBhcmVudCBjb21taXRtZW50cyBmb3IgYG91dHB1dF9kaWdlc3RgICgjMzMyKS4KClVzZWZ1bCBmb3IgaW50ZXJvcGVyYWJsZSBjb25zdW1lcnMgdGhhdCBtdXN0IG5vdCBwdWxsIGZ1bGwgbGluZWFnZQp0b3BvbG9neSAocGFyZW50IHByb29mIGlkcykgYWNyb3NzIGEgdHJ1c3QgYm91bmRhcnkuAAAAAAAeZ2V0X2xpbmVhZ2VfcGFyZW50X2NvbW1pdG1lbnRzAAAAAAABAAAAAAAAAA1vdXRwdXRfZGlnZXN0AAAAAAAD7gAAACAAAAABAAAD6AAAA+oAAAPuAAAAIA==",
        "AAAAAAAAAGNSZXR1cm4gdGhlIG51bWJlciBvZiBjdXJyZW50bHkgb3BlbiAobm9uLXRlcm1pbmFsKSBkaXNwdXRlcyBvcGVuZWQgYnkKYHJlcG9ydGVyYCBhY3Jvc3MgYWxsIHByb29mcy4AAAAAH2dldF9yZXBvcnRlcl9vcGVuX2Rpc3B1dGVfY291bnQAAAAAAQAAAAAAAAAIcmVwb3J0ZXIAAAATAAAAAQAAAAQ=",
        "AAAAAAAAAFxTdGFnZSBvciBxdWV1ZSBsZWdhY3kgY3JlZGVudGlhbCByb290cyBmb3IgYm91bmRlZCBiYWNrZmlsbCBkdXJpbmcgYHVwZ3JhZGVfc3RvcmFnZWAgKCM3MzEpLgAAAB9zdGFnZV9jcmVkZW50aWFsX3Jvb3RzX2JhY2tmaWxsAAAAAAIAAAAAAAAABWFkbWluAAAAAAAAEwAAAAAAAAAFcm9vdHMAAAAAAAPqAAAD7gAAACAAAAAA",
        "AAAAAAAAAJFSZXR1cm4gdGhlIGNvbmZpZ3VyZWQgZ3JhY2Ugd2luZG93IChpbiBsZWRnZXJzKSBmb3IgYWNjZXB0aW5nIHByZXZpb3VzCnJldm9jYXRpb24gcm9vdHMsIGRlZmF1bHRpbmcgdG8gW2BERUZBVUxUX1JFVk9DQVRJT05fUk9PVF9HUkFDRV9MRURHRVJTYF0uAAAAAAAAIGdldF9yZXZvY2F0aW9uX3Jvb3RfZ3JhY2Vfd2luZG93AAAAAAAAAAEAAAAE",
        "AAAAAAAAAHhXaGV0aGVyIHRoZSBwcm9vZiBoYXMgYW4gaW5kZXBlbmRlbnRseSB2ZXJpZmlhYmxlIG9uLWNoYWluIHRpbWVzdGFtcApzb3VyY2UgKFN0ZWxsYXIgbGVkZ2VyIGFuZC9vciBSRkMgMzE2MSBjb21taXRtZW50KS4AAAAgaGFzX2luZGVwZW5kZW50X3RpbWVzdGFtcF9hbmNob3IAAAABAAAAAAAAAAhwcm9vZl9pZAAAA+4AAAAgAAAAAQAAAAE=",
        "AAAAAAAAAXJDb25maWd1cmUgdGhlIGdyYWNlIHdpbmRvdyAoaW4gbGVkZ2VycykgZHVyaW5nIHdoaWNoIHJlY2VudCBwcmV2aW91cwpyZXZvY2F0aW9uIHJvb3RzIGluIHRoZSByaW5nIGJ1ZmZlciByZW1haW4gYWNjZXB0ZWQgYnkKW2BTZWxmOjpjaGVja19ub25fcmV2b2NhdGlvbmBdLgoKQWRtaW4tb25seS4gU2V0dGluZyBgZ3JhY2VfbGVkZ2VycyA9PSAwYCBkaXNhYmxlcyB0aGUgZ3JhY2Ugd2luZG93IHNvCm9ubHkgdGhlIGN1cnJlbnQgcm9vdCBpcyBhY2NlcHRlZC4gVmFsdWVzIGFib3ZlCltgTUFYX1JFVk9DQVRJT05fUk9PVF9HUkFDRV9MRURHRVJTYF0gYXJlIHJlamVjdGVkIHdpdGgKW2BSZWdpc3RyeUVycm9yOjpJbnZhbGlkUHVibGljSW5wdXRzYF0uAAAAAAAgc2V0X3Jldm9jYXRpb25fcm9vdF9ncmFjZV93aW5kb3cAAAACAAAAAAAAAAVhZG1pbgAAAAAAABMAAAAAAAAADWdyYWNlX2xlZGdlcnMAAAAAAAAEAAAAAA==" ]),
      options
    )
  }
  public readonly fromJSON = {
    init: this.txFromJSON<null>,
        pause: this.txFromJSON<u64>,
        unpause: this.txFromJSON<null>,
        version: this.txFromJSON<string>,
        is_admin: this.txFromJSON<boolean>,
        get_admin: this.txFromJSON<Option<string>>,
        get_proof: this.txFromJSON<Option<ProofRecord>>,
        is_issuer: this.txFromJSON<boolean>,
        is_paused: this.txFromJSON<boolean>,
        add_issuer: this.txFromJSON<null>,
        add_schema: this.txFromJSON<null>,
        get_config: this.txFromJSON<RegistryConfig>,
        get_issuer: this.txFromJSON<Option<IssuerRecord>>,
        get_schema: this.txFromJSON<Option<SchemaRecord>>,
        get_dispute: this.txFromJSON<Option<DisputeRecord>>,
        get_lineage: this.txFromJSON<Option<LineageRecord>>,
        accept_admin: this.txFromJSON<null>,
        approve_seal: this.txFromJSON<boolean>,
        expire_proof: this.txFromJSON<null>,
        get_by_video: this.txFromJSON<Option<ProofRecord>>,
        get_guardian: this.txFromJSON<Option<string>>,
        get_verifier: this.txFromJSON<Option<string>>,
        open_dispute: this.txFromJSON<DisputeRecord>,
        revoke_proof: this.txFromJSON<null>,
        set_guardian: this.txFromJSON<null>,
        set_verifier: this.txFromJSON<null>,
        verify_proof: this.txFromJSON<null>,
        correct_proof: this.txFromJSON<null>,
        finalize_seal: this.txFromJSON<ProofRecord>,
        get_proof_ttl: this.txFromJSON<u64>,
        has_nullifier: this.txFromJSON<boolean>,
        propose_admin: this.txFromJSON<null>,
        register_seal: this.txFromJSON<ProofRecord>,
        revoke_issuer: this.txFromJSON<null>,
        revoke_proofs: this.txFromJSON<null>,
        rotate_issuer: this.txFromJSON<u64>,
        set_proof_ttl: this.txFromJSON<null>,
        clear_guardian: this.txFromJSON<null>,
        get_delegation: this.txFromJSON<Option<DelegationRecord>>,
        list_verifiers: this.txFromJSON<VerifierPage>,
        dismiss_dispute: this.txFromJSON<DisputeRecord>,
        get_pause_state: this.txFromJSON<Option<PauseRecord>>,
        get_scope_epoch: this.txFromJSON<u64>,
        register_source: this.txFromJSON<ProofRecord>,
        resolve_dispute: this.txFromJSON<DisputeRecord>,
        respond_dispute: this.txFromJSON<DisputeRecord>,
        set_scope_epoch: this.txFromJSON<null>,
        upgrade_storage: this.txFromJSON<null>,
        deprecate_schema: this.txFromJSON<null>,
        get_issuer_quota: this.txFromJSON<Option<IssuerQuotaRecord>>,
        get_proof_status: this.txFromJSON<ProofVerificationStatus>,
        get_source_batch: this.txFromJSON<Option<BatchRecord>>,
        grant_delegation: this.txFromJSON<u64>,
        register_lineage: this.txFromJSON<LineageRecord>,
        set_issuer_quota: this.txFromJSON<null>,
        get_admin_council: this.txFromJSON<Option<AdminCouncil>>,
        get_pending_admin: this.txFromJSON<Option<string>>,
        get_seal_approval: this.txFromJSON<Option<SealApproval>>,
        reactivate_schema: this.txFromJSON<null>,
        revoke_delegation: this.txFromJSON<null>,
        set_admin_council: this.txFromJSON<null>,
        supersede_dispute: this.txFromJSON<DisputeRecord>,
        add_receipt_signer: this.txFromJSON<ReceiptSignerRecord>,
        cancel_seal_policy: this.txFromJSON<null>,
        create_seal_policy: this.txFromJSON<u32>,
        get_proof_statuses: this.txFromJSON<Array<ProofVerificationStatus>>,
        get_receipt_signer: this.txFromJSON<Option<ReceiptSignerRecord>>,
        get_schema_version: this.txFromJSON<u32>,
        get_verifier_state: this.txFromJSON<VerifierState>,
        register_anonymous: this.txFromJSON<ProofRecord>,
        add_credential_root: this.txFromJSON<null>,
        extend_instance_ttl: this.txFromJSON<null>,
        get_credential_root: this.txFromJSON<Option<CredentialRootRecord>>,
        get_issuer_rotation: this.txFromJSON<Option<IssuerRotationRecord>>,
        get_proof_assurance: this.txFromJSON<Option<ProofAssurance>>,
        get_revocation_root: this.txFromJSON<Option<Buffer>>,
        get_timestamp_claim: this.txFromJSON<Option<TimestampClaim>>,
        list_proof_disputes: this.txFromJSON<Array<Buffer>>,
        set_revocation_root: this.txFromJSON<null>,
        check_non_revocation: this.txFromJSON<null>,
        get_council_proposal: this.txFromJSON<Option<CouncilProposal>>,
        get_delegation_count: this.txFromJSON<u32>,
        get_proof_history_at: this.txFromJSON<Option<ProofHistoryEntry>>,
        get_revocation_roots: this.txFromJSON<Array<RevocationRootEntry>>,
        is_delegation_active: this.txFromJSON<boolean>,
        is_issuer_verifiable: this.txFromJSON<boolean>,
        cancel_admin_transfer: this.txFromJSON<null>,
        commit_receipt_digest: this.txFromJSON<ReceiptCommitmentRecord>,
        get_current_wasm_hash: this.txFromJSON<Option<Buffer>>,
        get_metadata_envelope: this.txFromJSON<Option<MetadataEnvelope>>,
        get_statuses_by_video: this.txFromJSON<Array<ProofVerificationStatus>>,
        get_timelock_proposal: this.txFromJSON<Option<TimelockProposal>>,
        list_credential_roots: this.txFromJSON<CredentialRootPage>,
        list_lineage_children: this.txFromJSON<LineageChildrenPage>,
        revoke_receipt_signer: this.txFromJSON<ReceiptSignerRecord>,
        add_seal_policy_signer: this.txFromJSON<null>,
        anchor_timestamp_claim: this.txFromJSON<TimestampClaim>,
        bind_metadata_envelope: this.txFromJSON<MetadataEnvelope>,
        classify_public_inputs: this.txFromJSON<u32>,
        expire_credential_root: this.txFromJSON<null>,
        extend_persistent_ttls: this.txFromJSON<null>,
        get_active_seal_policy: this.txFromJSON<Option<SealPolicy>>,
        get_issuer_quota_usage: this.txFromJSON<IssuerQuotaUsage>,
        get_open_dispute_count: this.txFromJSON<u32>,
        get_receipt_commitment: this.txFromJSON<Option<ReceiptCommitmentRecord>>,
        propose_council_action: this.txFromJSON<u32>,
        revoke_credential_root: this.txFromJSON<null>,
        update_issuer_metadata: this.txFromJSON<null>,
        cancel_council_proposal: this.txFromJSON<null>,
        get_admin_intent_digest: this.txFromJSON<Option<Buffer>>,
        get_lineage_child_count: this.txFromJSON<u32>,
        get_proof_dispute_count: this.txFromJSON<u32>,
        get_proof_history_count: this.txFromJSON<u32>,
        get_seal_approval_count: this.txFromJSON<u32>,
        list_timelock_proposals: this.txFromJSON<TimelockProposalPage>,
        register_batch_verified: this.txFromJSON<Array<ProofRecord>>,
        register_seal_delegated: this.txFromJSON<ProofRecord>,
        accept_admin_with_intent: this.txFromJSON<null>,
        approve_council_proposal: this.txFromJSON<boolean>,
        exec_council_with_intent: this.txFromJSON<null>,
        execute_council_proposal: this.txFromJSON<null>,
        finalize_issuer_rotation: this.txFromJSON<null>,
        exec_timelock_with_intent: this.txFromJSON<null>,
        get_council_intent_digest: this.txFromJSON<Option<Buffer>>,
        get_credential_root_count: this.txFromJSON<u32>,
        get_pending_admin_council: this.txFromJSON<Option<AdminCouncil>>,
        propose_timelocked_action: this.txFromJSON<u32>,
        register_source_delegated: this.txFromJSON<ProofRecord>,
        remove_seal_policy_signer: this.txFromJSON<null>,
        activate_verifier_rotation: this.txFromJSON<null>,
        cancel_timelocked_proposal: this.txFromJSON<null>,
        compute_role_intent_digest: this.txFromJSON<Buffer>,
        emergency_execute_timelock: this.txFromJSON<null>,
        get_council_proposal_count: this.txFromJSON<u32>,
        get_lineage_children_count: this.txFromJSON<u32>,
        get_seal_policy_by_version: this.txFromJSON<Option<SealPolicy>>,
        get_storage_schema_version: this.txFromJSON<u32>,
        get_timelock_intent_digest: this.txFromJSON<Option<Buffer>>,
        register_source_batch_root: this.txFromJSON<BatchRecord>,
        rollback_verifier_rotation: this.txFromJSON<null>,
        schedule_verifier_rotation: this.txFromJSON<null>,
        execute_timelocked_proposal: this.txFromJSON<null>,
        get_timelock_min_delay_secs: this.txFromJSON<u64>,
        get_timelock_proposal_count: this.txFromJSON<u32>,
        register_anonymous_verified: this.txFromJSON<ProofRecord>,
        set_timelock_min_delay_secs: this.txFromJSON<null>,
        verify_selective_disclosure: this.txFromJSON<null>,
        cancel_pending_admin_council: this.txFromJSON<null>,
        is_supported_circuit_version: this.txFromJSON<boolean>,
        get_verifier_circuit_versions: this.txFromJSON<VerifierCircuitVersions>,
        is_supported_envelope_version: this.txFromJSON<boolean>,
        resolve_metadata_envelope_ver: this.txFromJSON<u32>,
        set_verifier_circuit_versions: this.txFromJSON<null>,
        verify_source_batch_inclusion: this.txFromJSON<boolean>,
        get_lineage_parent_commitments: this.txFromJSON<Option<Array<Buffer>>>,
        get_reporter_open_dispute_count: this.txFromJSON<u32>,
        stage_credential_roots_backfill: this.txFromJSON<null>,
        get_revocation_root_grace_window: this.txFromJSON<u32>,
        has_independent_timestamp_anchor: this.txFromJSON<boolean>,
        set_revocation_root_grace_window: this.txFromJSON<null>
  }
}