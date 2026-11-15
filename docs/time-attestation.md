# Time Attestation & Offline Timestamp-Chain Validation

`backend/time_attestation.py` models the canonical `harpocrates-time-attestation/v1` envelope across claimed capture time, backend observed time, Stellar ledger anchors, and RFC 3161 TSA certificate chains.

## Offline timestamp-chain validation report

Call `build_offline_timestamp_chain_report(attestation, expected_evidence_digest=..., trust_store=..., offline_stellar_snapshots=..., now_unix_ms=...)` to evaluate every attestation dependency completely offline (`schema: harpocrates-offline-timestamp-chain-report/v1`):

- **Per-dependency bounded trust results:** Emits a `TimestampDependencyEntry` for `claimed_time`, `observed_time`, each `stellar_anchor[i]`, and each `rfc3161_anchor[i]` with bounded trust results (`verified_trusted`, `self_asserted_bounded`, `trust_material_unavailable`, `signature_or_chain_invalid`, `untrusted_anchor`).
- **Explicit separation of invalid signatures vs. unavailable trust material:**
  - `invalid_signature` (`hasInvalidSignatures` / `invalidSignatureDependencies`): Cryptographic certificate signature failures (`signature_invalid`), forged leaf signatures under a configured root, or invalid offline ledger anchor signatures.
  - `unavailable_trust_material` (`hasUnavailableTrustMaterial` / `unavailableTrustMaterialDependencies`): Missing RFC 3161 `certificateChain`, empty `TrustStore` (`missing_trust_roots`), absent `offline_stellar_snapshots` (`missing_offline_ledger_snapshot`), or optional crypto dependency unavailability.
- **Overall bounded assurance:** Summarizes the envelope as `verified_independent_anchor`, `bounded_unverified_material`, `self_asserted_only`, or `failed_validation` without elevating unverified or self-asserted timestamps to anchor trust.
