# Issuer Key Transparency & Rotation History

## Overview

Harpocrates publishes an independently auditable **issuer key transparency directory** so institutional (Tier 3 / Public Seal) issuer identity and key history can be verified without trusting a single operator view. Private organization details are never required in public artifacts — only opaque identity hashes, key hashes, and policy hashes appear.

This document covers onboarding, compromise response, checkpoint signing, and recovery.

## Trust boundaries

| Artifact | Public | Private (never published) |
| --- | --- | --- |
| `organizationIdentityHash` | Yes | Raw legal / contact identity |
| Active key `publicKeyHash` + `keyId` | Yes | Private signing keys |
| `policyHash` | Yes | Full policy prose if sensitive |
| Append-only lifecycle events | Yes | Human reason text (use `reasonHash`) |
| Signed directory checkpoints | Yes | Operator credentials |

## Canonical issuer manifest

Each issuer publishes a versioned manifest (`protocol: harpocrates-issuer-key-transparency`, `version: 1`) containing:

- Organization identity hash
- Issuer Stellar address
- Active keys (algorithm, validity window, status)
- Policy hash
- Predecessor / successor manifest links for rotation history
- Detached `signatureHash` (signature over the unsigned canonical body)

Canonical encoding is deterministic JSON (`sort_keys`, compact separators). Digest = SHA-256 of the unsigned body.

Manifest `version` must be the integer `1`; booleans and non-integer values are rejected rather than coerced. An optional `criticalExtensions` list must be empty because manifest version 1 understands no extensions. Any non-empty list, or a non-list value, raises `TransparencyError` instead of being ignored, so an issuer cannot make a client accept a manifest whose required semantics it does not implement. Unknown top-level manifest fields remain forward-compatible and are ignored.

## Append-only lifecycle events

Event types: `activation`, `rotation`, `compromise`, `retirement`, `checkpoint`.

Each event carries a monotonic `sequence`, `previousEventHash` chain link, and opaque hashes only. Directory rebuild from the authoritative event log is deterministic: the same ordered events always yield the same key statuses and Merkle-style `treeHeadHash`.

## Directory checkpoints

A checkpoint binds:

- `treeHeadHash` — head of the event hash chain
- `eventCount`
- `manifestHash` — current published manifest
- `organizationIdentityHash`
- Optional `signatureHash` from the checkpoint signer

Clients detect **split views** (diverging heads at the same count), **rollback** (shrinking `eventCount` after a higher head was observed), **stale checkpoints**, **broken rotation links**, **conflicting manifests**, and **compromised keys**.

## Portable consistency proof bundles

A `ConsistencyProofBundle` (`protocol: harpocrates-issuer-key-transparency`, `version: 1`) binds an `earlierCheckpoint` and `laterCheckpoint` to the ordered `interveningEvents` slice between them.

- Build from an authoritative directory with `build_consistency_proof_bundle(directory, earlier, later)` (or `directory.make_consistency_proof_bundle(earlier, later)`).
- Serialize/deserialize canonically with `bundle.to_json()` / `ConsistencyProofBundle.from_json(raw)` and hash with `consistency_proof_bundle_hash(bundle)`.
- Verify continuity offline without trusting a live directory response via `verify_consistency_proof_bundle(bundle, expected_organization_identity_hash=..., expected_earlier_checkpoint=...)` or fail-closed `require_valid_consistency_proof_bundle(...)`.
- Verification confirms non-regression (`detect_rollback` and checkpoint timestamps), contiguous monotonic sequences, `previousEventHash` chaining, and `advance_tree_head(earlier.tree_head_hash, intervening_events) == later.tree_head_hash`.

## Bounded consistency verification

For untrusted event streams, use `verify_directory_consistency_bounded` with
`ConsistencyWorkBudget`. Event-count and canonical serialized-byte budgets are
checked before `rebuild_directory` runs. The result uses
`status: "incomplete_proof"` and `consistent: false` when a budget is exceeded
or the supplied events do not reach the checkpoint; stable `reason_code` values
identify the limit. Set `max_events`, `max_total_bytes`, and
`max_single_event_bytes` only within the module's hard limits. Ordinary
inconsistencies are reported separately as `status: "inconsistent"` with
`errors`; only a complete, error-free proof returns `status: "consistent"`.

## Caching & freshness (fail-closed)

| Mode | Max age | Behavior |
| --- | --- | --- |
| Standard | 24h (`DEFAULT_FRESHNESS_SECONDS`) | Reject stale cache on verify |
| High-assurance seals | 1h (`HIGH_ASSURANCE_FRESHNESS_SECONDS`) | **Fail-closed** — refuse seal acceptance if checkpoint is stale |

Use `require_fresh_checkpoint(..., high_assurance=True)` before accepting high-assurance Public Seal evidence.

## Historical signatures after rotation

Key rotation sets `validUntil` on the predecessor. Signatures whose timestamp falls inside the key’s validity window remain valid after rotation. Compromised keys similarly retain validity for pre-compromise timestamps; verifiers must surface compromise status for post-compromise risk decisions.

Use `explain_historical_key_validity(directory, key_id, signature_timestamp, max_events=MAX_EXPLANATION_EVENTS)` to obtain a bounded `HistoricalKeyValidityExplanation` record. It reuses `key_valid_for_historical_signature` and `key_was_compromised_at`, attaches a stable `HistoricalValidityReason` code (`valid_active_key`, `valid_before_rotation`, `valid_before_retirement`, `valid_before_compromise`, `unknown_key`, `before_activation`, `rotated_before_signature_time`, `retired_before_signature_time`, `compromised_at_signature_time`, `expired_before_signature_time`), and includes up to `MAX_EXPLANATION_EVENTS` (`16`) public `LifecycleEventRef` entries (capped at `MAX_EXPLANATION_BYTES = 4096` in canonical JSON). Private evidence identifiers, media digests, and raw organization fields are never included in the explanation record.

The registry expresses the same window on chain: `rotate_issuer` retires the predecessor key immediately (it can no longer sign new seals, directly or through a delegation) and records a bounded `grace_expires_at` during which `is_issuer_verifiable(predecessor)` keeps pre-rotation evidence verifiable. The window lapses on its own against ledger time and `finalize_issuer_rotation` settles the record. Because the on-chain window is capped by `MAX_ISSUER_ROTATION_GRACE_SECS`, a retired key’s manifest `validUntil` should not be set beyond that bound; `revoke_issuer` and `add_issuer` clear the on-chain record, so a compromised or re-onboarded key is never covered by a stale grace window.

## Trust changes across verification runs

Use `assess_issuer_trust(directory, key_id, ...)` to evaluate an issuer key for a single verification run and `compare_issuer_trust(previous, current, ...)` to explain why trust changed between runs without collapsing distinct causes into a generic invalid-issuer error.

- **States (`TrustState`)**: `trusted`, `historically_valid`, `untrusted`, `stale`.
- **Reasons (`TrustChangeReason`)**:
  - `unchanged` — trust state and reason did not change between runs.
  - `activated` — key is active and within its validity window.
  - `key_rotated` — key was rotated to a successor (`successorKeyId` populated); pre-rotation historical signatures remain `historically_valid`.
  - `key_expired` — key or manifest `validUntil` window elapsed.
  - `key_retired` — key was explicitly retired (optional opaque `reasonHash`).
  - `key_compromised` — key was marked compromised (optional opaque `reasonHash`); pre-compromise signatures remain `historically_valid` while surfacing compromise status.
  - `stale_directory` — cached checkpoint exceeded its standard or high-assurance freshness window (fail-closed `stale` state).
  - `directory_inconsistent` — checkpoint consistency check or cross-run rollback/equivocation check failed.
  - `unknown_key` / `not_yet_valid` — key missing from directory or signature predates `validFrom`.

## Operational procedures

### Onboarding an issuer

1. Derive `organizationIdentityHash` from the institution’s certified identity package (offline); do not upload raw PII to the directory.
2. Activate the first signing key (`activation` event, sequence 0).
3. Publish the initial signed manifest (no predecessor).
4. Sign and distribute a directory checkpoint.
5. Configure clients with the checkpoint signer’s public key and freshness policy.

### Compromise response

1. Emit a `compromise` event for the affected `keyId` with an opaque `reasonHash`.
2. Activate a replacement key (`activation` or `rotation` from a still-trusted predecessor if available).
3. Publish a new manifest linking `predecessorManifestHash`.
4. Sign a fresh checkpoint and push to all mirrors.
5. Revoke the issuer on-chain via `revoke_issuer` if institutional standing is withdrawn.
6. Notify relying parties; historical pre-compromise seals remain cryptographically valid but should be risk-flagged.

### Checkpoint signing

1. Rebuild the directory from the authoritative event log.
2. Confirm `treeHeadHash` and `manifestHash` match local state.
3. Canonicalize the unsigned checkpoint; sign; set `signatureHash`.
4. Publish to primary + at least one independent mirror.
5. Clients gossip-compare checkpoints to detect equivocation.

### Recovery

1. If a mirror serves a divergent head, prefer the view that extends a previously observed checkpoint without rollback.
2. Re-fetch the full event log from the authoritative source and `rebuild_directory`.
3. If the signer key is lost, rotate the checkpoint signer out-of-band and publish a recovery checkpoint attested by admin + remaining mirrors (document the ceremony in the change log).
4. Roll back application feature flags without rewriting the append-only log; never delete events.

## Privacy guarantees

- No email, legal name, phone, address, or employee identifiers in manifests, events, or checkpoints.
- Reason text for compromise/retirement stays off-directory; only `reasonHash` is published.
- Observability metrics should log event counts and freshness age — never raw organization payloads.

## Compatibility

- Module: `backend/issuer_key_transparency.py`
- Tests: `backend/test_issuer_key_transparency.py`
- On-chain issuer allowlist (`add_issuer` / `revoke_issuer` / `rotate_issuer`) remains the standing authority; this directory adds auditable key history beside it, not a parallel allowlist. `rotate_issuer` (#323) records a bounded on-chain grace window for a retired key, which is the contract-side counterpart of a manifest’s `validUntil`.
- Schema version is explicit (`version: 1`); future versions require migration notes in this document.

## Threat model notes

Adversaries may attempt split-view presentation, checkpoint rollback, stale cache reuse for high-assurance seals, broken rotation chains, conflicting manifests at one head, or continued use of compromised keys. The test suite encodes these failure paths; operators should alert on any consistency error returned by `verify_checkpoint_consistency` / `detect_rollback`.
