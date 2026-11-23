# Proof Registration Intent Binding

## Overview

Proof registration binds each approved registration request to a deterministic **intent digest** derived from its canonical evidence statement before on-chain transaction verification runs. During reconciliation (`backend/registration_reconcile.py`), any confirmed transaction whose on-chain registered statement differs from (or omits) the approved intent is rejected fail-closed and never marked `confirmed`.

## Canonical Evidence Statement & Intent Digest

`backend/idempotency.py` defines the canonical evidence statement (`version = "harpocrates.registration_intent.v1"`):

- `video_hash`: 32-byte lowercase hex string
- `metadata_hash`: 32-byte lowercase hex string
- `proof_id`: 32-byte lowercase hex string
- `tier`: normalized lowercase tier (`silent`, `source`, or `seal`)
- `source_address`: Stellar StrKey address or `null`
- `contract_id`: Stellar contract StrKey or `null`

The intent digest is computed as:

```text
SHA-256("harpocrates:registration-intent:v1:" || canonical_json(statement))
```

where `canonical_json` uses sorted keys, compact separators (`(",", ":")`), and ASCII encoding.

**Privacy:** The canonical statement and persisted intent record contain only hashes, tier, and public Stellar identifiers — never raw media, metadata envelopes, witness values, credentials, or private keys.

## Persistence Before Verification

1. When `POST /api/proofs/register` receives a request with a `txHash`, it computes `intent_digest` and persists it via `persist_registration_intent(tx_hash, intent_digest)` in `idempotency_records` (`request_type = "registration_intent"`, `request_digest = normalized_tx_hash`) before enqueuing `verify_tx`.
2. Re-persisting the same `(tx_hash, intent_digest)` is idempotent. Attempting to bind the same `tx_hash` to a different `intent_digest` raises `IntentConflictError` (HTTP `409` on register; `status = "failed"`, `reason = "intent_digest_conflict"` during reconciliation without calling Horizon).
3. In `reconcile_registration(...)`, if `expected_statement` or `intent_digest` is provided (or previously persisted for `tx_hash`), the intent digest is persisted **before** `verify_transaction(...)` is called.

## Transaction Verification & Fail-Closed Rejection

`backend/tx_verification.py` extracts on-chain statement evidence from Horizon transaction responses via:

- `registered_statement` (mapping),
- `intent_digest` / `statement_digest` (32-byte hex), or
- Stellar `memo_type == "hash"` (base64-encoded 32-byte digest or 32-byte hex).

When an intent digest is bound to a registration:

| Condition | Result Status | Reason | `intentVerified` |
| --- | --- | --- | --- |
| Observed statement/digest matches approved intent | `confirmed` | `confirmed` | `true` |
| Observed statement/digest differs from approved intent | `failed` | `registered_statement_mismatch` | `false` |
| No statement/digest present on-chain | `failed` | `registered_statement_missing` | `false` |
| Observed statement is malformed | `failed` | `registered_statement_invalid` | `false` |
| Conflicting intent already persisted for `tx_hash` | `failed` | `intent_digest_conflict` | `false` |

Legacy reconciliation calls without a bound intent digest remain backward-compatible.
