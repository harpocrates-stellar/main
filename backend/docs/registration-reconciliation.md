# Registration confirmation reconciliation

## Purpose

`POST /api/proofs/register` accepts a Stellar `txHash` and stores the registration
row as `tx_status=pending`. Callers must not treat client-reported confirmation
as protocol truth. The registration reconciler queries Horizon (with failover),
applies a confirmation-depth policy, and updates `proof_events.tx_status` to one
of `confirmed`, `failed`, `missing`, or leaves the row `pending` for retry.

## Trust boundary

| Layer | Role |
| --- | --- |
| Client | May submit `txHash`; cannot assert finality |
| Backend reconciler | Canonical off-chain confirmation state for Neon rows |
| Horizon | Dependency for ledger inclusion / success bit |
| Soroban registry | Canonical on-chain proof record (unchanged) |

This path does **not** invent a second protocol truth: it only reconciles whether
the cited transaction is present and successful on Stellar before operators or
downstream verifiers trust the Neon `tx_status` field.

## Privacy

Logs and API responses include only:

- truncated `txHash` prefixes (8 hex chars) in logs
- status / reason codes, confirmation counts, ledger numbers

Never logged or returned: media, metadata envelopes, witness values, credentials,
API keys, or private keys.

## Registration reconciliation timeline

The reconciler records bounded observation and transition records for each
registration so an authorized requester can see how a registration's outcome
was determined over time.

Each registration timeline entry carries one of four outcome classifications:

| Outcome | Meaning |
| --- | --- |
| `submitted` | The transaction was accepted by the client and recorded as `pending`; no ledger observation yet |
| `confirmed` | Horizon reports the transaction as successful at or above `TX_MIN_CONFIRMATIONS` depth |
| `rejected` | Horizon reports the transaction as failed, or the transaction is absent after the retry window |
| `unknown` | Horizon could not be reached or returned an inconclusive response; the row remains `pending` |

Timeline records are bounded: at most 20 observation and transition records are
returned per registration, newest first. Records contain only outcome, status
code, ledger number, confirmation count, timestamp, and the truncated `txHash`
prefix. They never contain media, metadata envelopes, witness values,
credentials, or private keys.

Access to the timeline is limited to the authorized requester who owns the
registration. Requests from other identities receive HTTP 403.

## Interface

`POST /api/proofs/reconcile`

```json
{
  "txHash": "<optional 32-byte hex>",
  "limit": 50,
  "minConfirmations": 1,
  "force": false
}
```

- Omit `txHash` to batch-reconcile pending rows (max 50).
- `force=true` overwrites terminal statuses (repair / rollback aid).
- Horizon dependency failures return HTTP 503 for single-hash calls and are
  counted under `summary.error` for batch calls without writing durable state.
- Horizon failures during batch reconciliation are classified as `unknown` in the
  timeline and never promoted to `rejected`, so fail-closed verification is preserved.

`GET /api/proofs/{txHash}/timeline`

Returns the bounded timeline of observation and transition records for the
registration, each tagged with `submitted`, `confirmed`, `rejected`, or
`unknown`. Only the authorized owner of the registration may call this endpoint.

## Worker integration

- Registration enqueues a `verify_tx` job; the worker processes it via
  `process_verify_tx_job`.
- A background loop periodically runs `reconcile_pending_registrations`.

## Configuration

| Env | Default | Meaning |
| --- | --- | --- |
| `HORIZON_URLS` | testnet then pubnet Horizon | Comma-separated failover list |
| `TX_MIN_CONFIRMATIONS` | `1` | Required ledger depth for `confirmed` |

## Migration / rollback

- Additive only: no schema migration. Existing `tx_status` values remain valid.
- Rollback: stop calling `/api/proofs/reconcile` / disable the worker verify loop;
  pending rows simply remain `pending` until a future reconciler runs.
- Compatibility: callers of `/api/proofs/register` are unchanged; they still
  receive `created` events with `tx_status=pending` when a hash is supplied.
