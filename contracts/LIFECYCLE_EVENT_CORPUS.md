# Canonical Lifecycle Event Interoperability Corpus (`hpx-ev/1`)

Corpus version: 1  
Codec identifier: `hpx-ev/1`  
Canonical vector file: [`vectors/lifecycle_events_v1.json`](vectors/lifecycle_events_v1.json)

## Overview

`contracts/vectors/lifecycle_events_v1.json` publishes the canonical event interoperability corpus for `HarpocratesRegistry` (`#1201`). It pins the ordered Soroban `ContractEvent` V0 topic list, typed `ScVal` map payload, and exact RFC-4506 big-endian XDR wire encoding for every existing proof, metadata envelope, timestamp anchor, lineage, dispute, batch, schema, credential-root, issuer, and revocation-root lifecycle transition, together with fail-closed negative boundary vectors.

Every layer decodes and validates the exact same file:

1. **Soroban Contract (Rust):** `contracts/harpocrates-registry/src/test_lifecycle_event_corpus.rs` executes real `HarpocratesRegistry` transitions in `Env::default()`, verifies byte-for-byte XDR parity against `vectors/lifecycle_events_v1.json`, cross-checks round-trip canonicality with `stellar_xdr::ScVal`, and asserts all negative cases fail closed.
2. **Backend / Indexer Client (Python):** `../backend/lifecycle_events.py` and `../backend/test_lifecycle_event_corpus.py` implement a standalone RFC-4506 XDR decoder and `hpx-ev/1` schema validator with zero Rust or `soroban-sdk` dependency.
3. **Browser / Frontend Client (TypeScript):** `../frontend/src/lifecycleEvents.ts` and `../frontend/src/lifecycleEvents.conformance.test.ts` implement an independent `Uint8Array` / `DataView` Stellar XDR decoder and `hpx-ev/1` schema validator.

## Published Transition Schemas

| Event Struct | Topic Vector (`ScVal::Vec`) | Required `ScMap` Payload Keys (Sorted) | Optional Keys |
|---|---|---|---|
| `CredentialRootAdded` | `["credroot", "add", bytes32]` | `issued_at: u64`, `metadata_hash: bytes32` | — |
| `CredentialRootRevoked` | `["credroot", "revoke", bytes32]` | *(empty map)* | — |
| `IssuerAdded` | `["issuer", "add", address_ed25519]` | `metadata_hash: bytes32` | — |
| `IssuerRevoked` | `["issuer", "revoke", address_ed25519]` | *(empty map)* | — |
| `ProofRegistered` | `["proof", "reg", bytes32]` | `batch_size: u32`, `status: u32`, `tier: u32`, `video_hash: bytes32` | — |
| `ProofHistoryEvent` | `["proof", "history", bytes32]` | `action: u32`, `reason_code: u32`, `timestamp: u64` | `actor: address_ed25519` (omitted when `None`) |
| `ProofRevoked` | `["proof", "revoke", bytes32]` | `status: u32` | — |
| `MetadataEnvelopeBound` | `["metadata", "envelope", "bound", bytes32]` | `bound_at: u64`, `metadata_hash: bytes32`, `version: u32` | — |
| `MetadataEnvelopeUpgraded` | `["metadata", "envelope", "upgraded", bytes32]` | `current: u32`, `metadata_hash: bytes32`, `previous: u32` | — |
| `TimestampClaimAnchored` | `["timestamp", "anchor", bytes32]` | `anchored_at: u64`, `assurance: u32`, `attestation_digest: bytes32`, `ledger_sequence: u32`, `sources: u32` | — |
| `LineageRegistered` | `["lineage", "reg", bytes32]` | `actor: address_ed25519`, `depth: u32`, `manifest_digest: bytes32`, `operation_type: symbol`, `parent_commitments: vec<bytes32>` | — |
| `DisputeOpened` | `["dispute", "open", bytes32, bytes32]` | `commitment_hash: bytes32`, `reason: u32`, `reporter_hash: bytes32`, `respond_deadline: u64` | — |
| `DisputeResponded` | `["dispute", "respond", bytes32, bytes32]` | `resolve_deadline: u64`, `response_commitment: bytes32` | — |
| `DisputeResolved` | `["dispute", "resolve", bytes32, bytes32]` | `resolved_at: u64` | — |
| `DisputeDismissed` | `["dispute", "dismiss", bytes32, bytes32]` | `resolved_at: u64` | — |
| `DisputeSuperseded` | `["dispute", "supersede", bytes32, bytes32]` | `resolved_at: u64`, `superseded_by: bytes32` | — |
| `SourceBatchRootRegistered` | `["batch", "root", bytes32, address_ed25519]` | `count: u32`, `metadata_hash: bytes32`, `registered_at: u64` | — |
| `SchemaAdded` | `["schema", "add", bytes32]` | `attribute_count: u32`, `issuer_namespace: bytes32`, `version: u32` | — |
| `SchemaDeprecated` | `["schema", "deprecate", bytes32]` | *(empty map)* | — |
| `SchemaReactivated` | `["schema", "reactivate", bytes32]` | *(empty map)* | — |
| `RevocationRootSet` | `["revroot", "set", bytes32]` | *(empty map)* | — |

## Fail-Closed Reject Taxonomy

Independent clients reject malformed or drifted event frames deterministically:

- `malformed_xdr`: truncated XDR stream, invalid hex, invalid symbol bytes, or unsupported `ScVal` discriminant.
- `trailing_xdr_bytes`: unconsumed bytes following a decoded `ScVal`.
- `non_canonical_padding`: non-zero RFC-4506 4-byte alignment padding in variable-length XDR bytes or symbols.
- `unknown_event_topic`: unrecognized leading symbol topic prefix.
- `topic_arity_mismatch`: wrong number of event topics for the matched prefix.
- `topic_type_mismatch`: non-matching `ScVal` type at any topic position.
- `payload_schema_mismatch`: missing required map key, unexpected extra key, or wrong value `ScVal` type.
- `non_canonical_map_order`: `ScMap` keys not strictly sorted in ascending ASCII byte order.

## Verification

```bash
cd contracts && cargo test -p harpocrates-registry test_lifecycle_event_corpus
python -m unittest backend/test_lifecycle_event_corpus.py
```

## Privacy & Compatibility

All corpus vectors use deterministic synthetic digests (`0x11..` .. `0x95..`) and synthetic Ed25519 public keys (`0xA1..` .. `0xD4..`). No real media, proof bytes, witnesses, nullifiers, or private keys appear in the corpus. Existing on-chain event topics, payload fields, and contract entry points remain completely unchanged.
