# On-chain Metadata Envelope Versioning

**Issue:** #317  
**Status:** Active  
**Aligns with:** `backend/envelope.py` (`HRPSTG1` / `HRPSTG2`)

## Goal

Record an explicit **envelope version** next to each proof's canonical
`metadata_hash` so Harpocrates stays privacy-preserving and interoperable at
its public contract boundary — without inventing a second protocol truth.

## What is stored on-chain

| Field | Meaning |
| --- | --- |
| `version` | `1` (`METADATA_ENVELOPE_V1`) or `2` (`METADATA_ENVELOPE_V2`) |
| `metadata_hash` | Same 32-byte canonical hash already on `ProofRecord` |
| `bound_at` | Ledger timestamp of the bind/upgrade |
| `proof_id` | Binding key |

Raw envelope bytes, media, witnesses, nullifiers, and private keys are **never**
stored or logged. Typed events emit only `(proof_id, version, metadata_hash, bound_at)`.

## Storage Bound

- Every evidence metadata commitment is exactly `MAX_EVIDENCE_METADATA_HASH_BYTES`
  bytes (32); contract entry points use the fixed-size `BytesN<32>` type, so
  oversized or short digests cannot be stored.
- At most one `MetadataEnvelope` row exists per proof. Binding or upgrading
  rewrites the row at `DataKey::MetadataEnvelope(proof_id)`; it does not append
  a version history. `ProofRecord` remains the canonical metadata hash.
- The bound is per proof, not a global cap on registered proofs. Expired or
  revoked proof records remain readable according to the existing lifecycle
  policy; this feature does not delete evidence or change retention.

## Compatibility

- Existing `register_*` entry points that take a bare `metadata_hash` keep working.
  `save_record` stamps a **V1** envelope automatically.
- Callers that understand V2 call `bind_metadata_envelope` after registration
  (admin, source, or issuer) to upgrade.
- `resolve_metadata_envelope_ver` returns the stored version, or `1` when a
  proof exists without a row (legacy), or `0` when the proof is unknown.
- Downgrades and unsupported versions (`0` or `> METADATA_ENVELOPE_VERSION_MAX`)
  fail closed with `UnsupportedMetadataEnvelopeVersion` (error `#68`).

## Migration & rollback

| Direction | Behavior |
| --- | --- |
| Forward | Additive `DataKey::MetadataEnvelope(proof_id)`. No `SchemaVersion` bump required. |
| Existing proofs | First read via `resolve_*` treats missing rows as V1; next `correct_proof` or `bind_*` materializes a row. New registrations stamp V1 immediately. |
| Rollback | Pre-#317 wasm ignores the new key. Re-deploying an older wasm leaves orphan envelope rows that newer builds can still read. |

The storage bound is documentation and type-level clarification of the existing
32-byte digest and single-key layout. It changes neither the contract ABI nor
the persistent storage encoding, so no migration or data rewrite is required.

## Threat model notes

- **Confidentiality:** only hashes and version integers cross the trust boundary.
- **Integrity:** bind requires the hash to match `ProofRecord.metadata_hash`;
  same-version hash edits go through `correct_proof` (admin) so history stays authoritative.
- **Availability / DoS:** fixed-size types; no unbounded decoding of off-chain envelopes.
- **Input bounds:** malformed digest lengths fail Soroban argument decoding
  before contract logic; the contract never logs rejected payloads.
- **Replay / confusion:** version is explicit on-chain so V1 and V2 digests cannot be silently reinterpreted.

## API surface

- `bind_metadata_envelope(actor, proof_id, version, metadata_hash)`
- `get_metadata_envelope(proof_id)`
- `resolve_metadata_envelope_ver(proof_id)`
- `is_supported_envelope_version(version)`

## Verification

```bash
cd contracts
cargo test -p harpocrates-registry test_metadata_envelope -- --nocapture
```
