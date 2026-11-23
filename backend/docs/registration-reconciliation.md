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
- Batch responses report `summary.selected` (rows chosen for this call),
  `summary.processed` (rows whose reconciliation outcome was applied or
  attempted to completion), `summary.deferred` (selected-eligible rows left
  for a later call, e.g. due to `limit` or a transient Horizon error), and
  `summary.error` (rows that failed reconciliation without writing durable state).
- Batch responses include `batch.complete` (`true` when the selected batch was
  fully processed with nothing deferred) and `backlog.complete` (`true` only when
  no pending rows remain eligible after this call). A complete batch does not
  imply a complete backlog: when `batch.complete=true` but `backlog.complete=false`,
  more pending rows exist and further calls are required.
- `force=true` overwrites terminal statuses (repair / rollback aid).
- Operator repair preview: `POST /api/proofs/reconcile/preview` accepts the same
  body as `/api/proofs/reconcile` and returns, for each selected row, the proposed
  `tx_status` update together with the chain evidence used to derive it (Horizon
  endpoint, transaction success bit, ledger number, confirmation count) and the
  expected row revision (`expectedRevision`) that a later apply must match. The
  preview performs no database writes. If a row's stored state contradicts the
  chain evidence (for example a row recorded as `confirmed` whose transaction is
  reported failed or absent), the preview marks that row `contradictory` with a
  reason code and proposes no update for it; contradictory rows never produce a
  write, even with `force=true`. Preview responses carry only status, reason codes,
  ledger numbers and truncated `txHash` prefixes, consistent with the privacy rules
  above.
- Horizon dependency failures return HTTP 503 for single-hash calls and are
  counted under `summary.error` for batch calls without writing durable state.
- Horizon failures during batch reconciliation are classified as `unknown` in the
  timeline and never promoted to `rejected`, so fail-closed verification is preserved.
- A provider outage (all Horizon endpoints unavailable / RPC unreachable) is an
  operational condition, not evidence invalidity. The pending registration intent
  is preserved (`tx_status` stays `pending`, no `failed` or `missing` is recorded)
  and the response carries a retryable operational code (`reason: "provider_unavailable"`,
  `retryable: true`) rather than a verdict on the transaction. Callers should retry
  with backoff; a `missing` status is only ever set when Horizon positively reports
  the transaction absent while reachable.

`GET /api/proofs/{txHash}/timeline`

Returns the bounded timeline of observation and transition records for the
registration, each tagged with `submitted`, `confirmed`, `rejected`, or
`unknown`. At most 20 records are returned, newest first. Only the authorized
owner of the registration may call this endpoint; other identities receive
HTTP 403.

## Worker integration

- Registration enqueues a `verify_tx` job; the worker processes it via
  `process_verify_tx_job`.
- A background loop periodically runs `reconcile_pending_registrations`.

## Configuration

| Env | Default | Meaning |
| --- | --- | --- |
| `HORIZON_URLS` | testnet then pubnet Horizon | Comma-separated failover list |
| `TX_MIN_CONFIRMATIONS` | `1` | Required ledger depth for `confirmed` |

A provider outage never downgrades a registration: unavailable RPC preserves the
pending intent and surfaces a retryable operational code, distinct from a
missing registration transaction.

## Migration / rollback

- Additive only: no schema migration. Existing `tx_status` values remain valid.
- Behavior change: provider outages now return the retryable operational code
  `provider_unavailable` with the pending intent preserved; previously a generic
  error. Existing `confirmed` / `failed` / `missing` semantics are unchanged.
- Rollback: stop calling `/api/proofs/reconcile` / disable the worker verify loop;
  pending rows simply remain `pending` until a future reconciler runs.
- Compatibility: callers of `/api/proofs/register` are unchanged; they still
  receive `created` events with `tx_status=pending` when a hash is supplied.