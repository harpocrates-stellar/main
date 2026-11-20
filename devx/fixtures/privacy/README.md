# Privacy Regression Fixtures

Synthetic test vectors for offline CI validation of Harpocrates privacy boundaries.
Fixtures are generated for tests only — they contain no real media, secrets,
witness values, private keys, or credentials.

Each JSON document is consumed by privacy regression tests in:
- `backend/test_privacy_regression.py`
- `cli/test/privacy-regression.test.ts`

## Schema

- `schemaVersion`: must be `1`
- `category`: one of `malformed`, `oversized`, `expired`, `revoked`, `unsupported`, `dependency-failure`
- `description`: human-readable description of the test case
- `input`: the test input (structure varies by category)
- `expect`: expected behavior assertion
  - `reject_code`: error code that must be returned
  - `must_not_log`: array of strings that must never appear in logs
  - `must_not_store`: array of field paths that must never reach storage

## Categories

### malformed
Inputs with invalid encoding, wrong types, or structural violations.

### oversized
Payloads exceeding size limits (envelope, field, or nesting depth).

### expired
Proofs, timestamps, or credentials past their validity window.

### revoked
Nullifiers, credentials, or attestations that have been revoked.

### unsupported
Protocol versions, tiers, or features not implemented or deprecated.

### dependency-failure
Simulated failures of external dependencies (TSA, RPC, indexer, etc.).

## Regeneration

Run the generator script to refresh fixtures:

```bash
python devx/fixtures/privacy/generate.py
```