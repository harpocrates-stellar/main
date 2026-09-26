# feat(contracts): validate verifier circuit versions and bound delegated expiry

Closes #343
Closes #338

> This PR bundles two contracts changes that share the same trust boundary.
> They are described separately below and reviewed together because both touch
> proof admission in the Soroban registry.

---

## Part 1 — #343: validate verifier circuit versions across calls

### Summary

Every proof-verifying entry point now validates the proof's circuit version at
the trust boundary **before** the external verifier is invoked. The registry was
already framing silent-witness, revocation, aggregation, and selective-disclosure
proofs, but the version implied by each frame was never checked against what the
active verifier can actually answer.

### What changed

- **Per-call version gate.** `require_verified_proof` now takes the proof's
  circuit version and calls `require_supported_circuit_version` first. An
  unsupported version fails closed with the stable
  `RegistryError::UnsupportedCircuitVersion` (79) instead of reaching a verifier
  that cannot answer it.
- **Single source of truth.** The implicit versions are read off the existing
  codec/domain boundaries, not invented:
  | Circuit | Version |
  | --- | --- |
  | `silent_witness` v1 frame (160 B) | `CIRCUIT_VERSION_SILENT_WITNESS_V1` = 1 |
  | `silent_witness` v2 scoped frame (224 B) | `CIRCUIT_VERSION_SILENT_WITNESS_V2` = 2 |
  | `revocation_witness` frame (128 B) | `CIRCUIT_VERSION_REVOCATION_WITNESS` = 1 |
  | `silent_witness_aggregator` | `CIRCUIT_VERSION_AGGREGATION` = 1 |
  | `selective_disclosure` (version is in the frame) | `CIRCUIT_VERSION_SELECTIVE_DISCLOSURE` = `CURRENT_SELECTIVE_DISCLOSURE_VERSION` |
- **Verifier-declared window.** `set_verifier_circuit_versions(admin, min, max)`
  lets the admin declare which versions the active verifier can check. It is
  admin-only, bounded by the wasm's own framable range, and emits a
  version-only event (`verif`/`versions`). A window that is empty or outside the
  wasm range fails with `InvalidCircuitVersionRange` (80).
- **Read-only pre-flight.** `get_verifier_circuit_versions()` and
  `is_supported_circuit_version(version)` let callers check without a trial
  transaction.
- **Fail-closed reset.** `set_verifier` and both verifier-rotation transitions
  clear the window so an incoming verifier cannot inherit the outgoing
  verifier's claim.
- **SDK 27 repair (required to compile and test).** The workspace was bumped to
  `soroban-sdk 27` upstream but the contracts did not compile. This PR repairs
  the registry and its test suite for SDK 27: two-topic events, the `Vec`
  rename, `slice(Range)`, `BytesN::to_array`, `InvokeError` handling,
  per-invocation event capture, and regenerated committed snapshots. `classify_public_inputs`
  dispatches on schema (silent-witness 160 B vs revocation 128 B) with
  per-schema frame buffers.

### Behavior for hostile inputs

| Input | Result |
| --- | --- |
| Malformed / wrong-length frame | `InvalidPublicInputs` (10) or classifier `RejectCode::Length` (2) |
| Oversized proof blob | classifier `RejectCode::ProofOversize` (8) |
| Unsupported circuit version | `UnsupportedCircuitVersion` (79) |
| Verifier rejects or dependency fails | `InvalidProof` (7) |
| Rotation in overlap window | previous verifier accepted |
| Expired / revoked credential | `Expired` status / `RevokedCredentialRoot` (12) |

---

## Part 2 — #338: bound delegated issuer expiration

### Summary

A proof registered through `register_source_delegated` or
`register_seal_delegated` can no longer outlive the delegation that authorized
it. Delegated authority is already time-bounded
(`MAX_DELEGATION_DURATION_SECS`, 30 days) and checked live at registration; this
change closes the remaining gap where a delegate could mint an **eternal**
proof while holding only a short-lived grant.

### What changed

- `require_delegation` returns the live `DelegationRecord`.
- New `bounded_delegated_expiry` caps a delegated proof's `expires_at` at the
  delegation's `expires_at`; a non-zero proof TTL is the minimum of the two, and
  a zero (eternal) TTL becomes the delegation expiry.
- Direct `register_source` / `register_seal` are unchanged — a zero TTL still
  means "eternal".

---

## Trust boundary and privacy

- The version gate runs **before** any external call, so an unsupported version
  never leaves the contract.
- No witness values, public inputs, proofs, secrets, media, or private keys are
  logged. The only new event carries two integers (`verif`/`versions`).
- Failure responses are the pre-existing stable typed codes; one new code (79)
  is append-only and documented.
- Delegation expiry remains enforced at registration time; the new bound only
  shortens a derived artifact's lifetime.

## Migration and compatibility

- **Additive only.** `DataKey::VerifierCircuitVersions` is a new storage key;
  `RegistryError` codes are appended (79, 80). No existing key or code changes.
- **Backward compatible.** An unset window applies the full built-in range, so
  pre-#343 deployments, existing callers, and stored evidence validate exactly
  as before. Existing stored records are never rewritten.
- **Rollback.** Deploying a pre-#343 wasm ignores the new key and calls the
  verifier with no version gate; deploying a pre-#338 wasm restores eternal
  delegated proofs. Neither rollback corrupts stored evidence.

## Test plan

```
cd contracts
cargo test -p harpocrates-registry --lib     # 375 passed / 0 failed (15 new)
cargo build -p harpocrates-registry --target wasm32v1-none --release
```

New coverage in `src/test_verifier_versions.rs`:

- **Positive:** default window = full built-in range; exact `min == max` window
  accepted; widening the window restores acceptance; const consistency with the
  codec boundaries.
- **Negative / authorization:** non-admin cannot set the window (`Unauthorized`
  3); empty, below-range, and above-range windows rejected (`80`); a version
  outside the window rejected (`79`) *with a rejecting verifier behind it*,
  proving the gate precedes the external call.
- **Boundary:** version `0` and `MAX+1` unsupported via pre-flight; `min == max`
  boundary accepted; shorter proof TTL wins over the delegation.
- **Regression:** `set_verifier` resets the window; version-only event emitted;
  direct registration keeps `expires_at == 0`; delegated source and seal proofs
  bounded by the delegation.

## Notes for reviewers

- `rustfmt` and `clippy` components were not installed in this environment; the
  source is formatted to the existing style and the pre-existing warnings
  (unused consts, unread struct fields) are unchanged.
- The SDK 27 repair is mechanical but large; the meaningful review surface is
  `require_supported_circuit_version`, `set_verifier_circuit_versions`, the
  `require_verified_proof` call sites, and `bounded_delegated_expiry`.
