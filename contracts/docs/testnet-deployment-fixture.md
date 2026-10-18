# Deterministic Testnet Deployment Fixture

Issue #350 adds `test_deployment_fixture.rs` to the Soroban registry contract
test suite.  This document covers the trust-boundary, privacy, migration, and
rollback implications.

## Purpose

The fixture pins a reproducible, fully-initialized registry state that mirrors
a real Harpocrates testnet deployment without using live credentials, real
media, or production keys.  It gives CI a stable oracle against which every
future change to the registry can be validated end-to-end in a single
deterministic test run.

## What is covered

| Category | Tests |
|---|---|
| Happy-path deployment sequence | `init → set_verifier → add_issuer → add_credential_root` with all storage and event assertions |
| All three identity tiers | anonymous, anonymous_verified, source, seal |
| Negative authorization | non-admin caller on every privileged entry point |
| Budget boundary | single `register_anonymous_verified` inside a fixed CPU/mem ceiling |
| Encoding boundary | empty, truncated, dirty-padded, zero-nullifier public inputs; unknown schema id |
| Migration idempotency | `upgrade_storage` called twice; no event emitted, no state mutated |
| Rollback safety | issuer and credential root revoked; subsequent registrations fail with expected errors; read queries still work |
| Nullifier replay | duplicate nullifier rejected with `DuplicateNullifier (#6)` |
| Proof TTL | default is `DEFAULT_PROOF_TTL_SECS`; custom value stored and returned correctly |

## Trust-boundary notes

- The mock verifier accepts any 128-byte public-input blob with a non-empty
  proof.  It does **not** verify a real Noir proof.  Soundness of the ZK
  circuit remains the responsibility of the `zk/` layer.
- The `classify_public_inputs` entry point is exercised directly by the
  encoding-boundary tests, ensuring the contract's own codec rejects
  malformed frames before the mock verifier is ever invoked.
- Authorization gates are driven by a `stranger` address (generated fresh
  per test) rather than a known-bad key, so no real private key material
  appears in the test.

## Privacy notes

- No real keys, real proofs, real media, or production contract IDs appear
  anywhere in the fixture.
- Failure-path assertions check only error codes; they never print proof
  bytes, public inputs, witness values, credential roots, or nullifiers.
- All synthetic hashes are derived from a single fixed domain-tag byte and
  a slot index, reproducible from the source alone.
- The fixture obeys the same rule as the state-machine fuzzer: cancelled or
  rejected operations must not write registry records or emit success events.

## Migration notes

- This is a **test-only** addition.  No exported function signature, storage
  key, event schema, or WASM artifact is modified.
- The `upgrade_storage` idempotency test (`deployment_fixture_upgrade_storage_is_idempotent`)
  confirms that already-current deployments can safely run the migration
  entry point without side effects.
- When the storage schema is bumped to V2 in a future change, a corresponding
  fixture test should be added here to assert that old V1 records are
  readable after migration and that the upgrade event is emitted exactly once.

## Rollback notes

- Rolling back this change means reverting or removing
  `test_deployment_fixture.rs` and the `mod test_deployment_fixture;`
  declaration in `lib.rs`.  No on-chain repair, migration script, or storage
  cleanup is required.

## Reproduction

```bash
cd contracts
cargo test -p harpocrates-registry deployment_fixture -- --nocapture
```

To run the full contract test suite:

```bash
cd contracts
cargo test --workspace
```
