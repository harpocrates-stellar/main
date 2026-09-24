# Proof Generation Worker and Non-Worker Fallback

## Overview

Silent Witness proof generation (Noir witness execution + UltraHonk proving)
runs inside a dedicated Web Worker whenever possible. This keeps the UI
responsive during proving and allows in-flight proof generation to be
cancelled deterministically.

When the Web Worker API is unavailable (e.g. `Worker` is not constructible in
a given environment, or spawning fails), `ProofWorkerClient` falls back to
proving directly on the main thread with **explicit, configurable limits**
so a mis-set environment cannot turn the fallback into an unbounded main
thread hang or unbounded memory use.

Implementation:
- `src/workers/proofWorker.ts` — runs inside the worker, wraps `noirClient.ts`
- `src/workers/proofWorker.types.ts` — shared message/state/runtime types
- `src/workers/proofWorkerClient.ts` — main-thread client (`ProofWorkerClient`)
  and the non-worker fallback
- `src/noirClient.ts` — single source of truth for the actual proving logic

## Runtime selection

`ProofWorkerClient` is constructed with a runtime policy:

| Option | Default | Effect |
|---|---|---|
| `runtime: 'auto'` | **default** | Try to spawn the Web Worker; fall back to the main thread on failure. |
| `runtime: 'worker'` | | Never fall back. If the worker cannot be spawned, generation rejects with `WORKER_UNAVAILABLE`. |
| `runtime: 'main'` | | Always prove on the main thread. Never touches `Worker`. |
| `enableFallback: true` | **default** | Whether the non-worker fallback is allowed when `runtime` is `'auto'`/`'worker'`. |
| `timeoutMs` | `60_000` | Per-request timeout for both paths. |
| `maxSecretBytes` | `256` | Explicit limit on credential/nullifier secret byte length for the fallback path. |
| `prover` / `workerFactory` | | Test-only overrides; the default prover calls `noirClient.generateSilentWitnessProof`. |

The active mode is exposed via `client.mode` (`'worker' | 'main-thread' |
'unavailable'`) and each `generate()` result carries `mode` and
`fallbackReason` on the returned handle.

`fallbackReason` values:
- `worker_api_unavailable` — `Worker` is not defined.
- `worker_spawn_failed` — constructing/attaching the worker threw or the
  factory returned null.
- `worker_crashed` — an active worker crashed and a replacement could not be
  spawned, so the client permanently moves to the main thread.
- `runtime_forced_main` — constructed with `runtime: 'main'`.

## Threat assumptions

- `credentialSecret` and `nullifierSecret` are sensitive witness inputs and
  must never be logged, persisted, or included in any worker message other
  than the initial transfer.
- On the worker path, secrets are transferred as `ArrayBuffer`s via
  structured clone's transfer list (zero-copy; the buffer is detached from
  the sender). The worker zeroes the underlying bytes after use in a `finally`
  block, regardless of success or failure.
- On the fallback path, secrets never cross an IPC boundary at all — they stay
  inside `noirClient` on the main thread.
- The client assumes hostile/malformed input is possible (oversized secrets,
  non-hex video hashes) and validates before ever touching the worker, the
  WASM prover, or the network — see `INVALID_INPUT` and
  `FALLBACK_LIMIT_EXCEEDED` below.
- Fallback error messages are **stable and sanitized**: the raw exception
  (which could embed secret or witness data) is used only to classify the
  error code and is never surfaced to the UI. The worker path likewise
  forwards a stable message instead of the raw error text.
- A stuck or unresponsive worker (e.g. due to a WASM-level hang) is treated
  the same as a crash: it is terminated and replaced, never left running
  indefinitely.

## State machine

Each `ProofWorkerClient` instance dispatches at most one active proof
request at a time, on either runtime.

```
idle --generate()--> running --resolves/rejects--> idle
running --generate() again--> immediately rejected with BUSY (original request unaffected)
running --cancel()--> worker terminated + respawned (or fallback job rejected), request rejects CANCELLED
running --60s elapsed--> worker terminated + respawned (or fallback job rejected), request rejects TIMEOUT
running --worker crash (onerror/onmessageerror)--> worker terminated + respawned, all pending requests reject CRASHED
```

Cancellation and timeout terminate the worker outright rather than signalling
it cooperatively, because the underlying Noir/UltraHonk calls have no
cancellation hook and may block the worker's event loop for the duration of
proving. Terminating and spawning a fresh worker is the only way to guarantee
an in-flight proof stops promptly.

On the main-thread fallback, cancellation/timeout reject the caller's promise
but cannot interrupt the WASM prover already in flight; the fallback slot
stays busy until that prover settles, so a second request keeps receiving
`BUSY` rather than corrupting a shared WASM instance.

## Explicit fallback limits

The non-worker fallback enforces three bounds so a single request can never
drive unbounded main-thread work:

1. `timeoutMs` — hard wall-clock cap per fallback request (default 60s).
2. `maxSecretBytes` — credential/nullifier secrets are capped (default 256
   bytes); the same ceiling is enforced inside `noirClient` for every caller.
3. `maxConcurrency = 1` — only one main-thread proof runs at a time; a second
   concurrent request rejects with `BUSY`.

`noirClient.generateSilentWitnessProof` additionally bounds the scope
(`verifier_scope` must fit in a BN254 field element) and epoch (`u32`), and
rejects them with a stable error before any circuit/WASM work.

## Error codes

| Code | Meaning |
|---|---|
| `BUSY` | A proof is already running on this client; request rejected immediately without touching the worker. |
| `INVALID_INPUT` | `videoHash` is not 64 hex characters, a secret is empty, or a secret exceeds the maximum size (256 bytes). Rejected before any worker/network activity. |
| `FALLBACK_LIMIT_EXCEEDED` | The request passed structural validation but exceeds the explicit main-thread fallback limits (configured `maxSecretBytes`). Rejected with no worker/network activity. |
| `WORKER_UNAVAILABLE` | The worker cannot be spawned and the fallback is disabled (`enableFallback: false`, or `runtime: 'worker'`). |
| `CANCELLED` | `cancel()` was called for this request. |
| `TIMEOUT` | Proof generation exceeded the configured timeout (default 60s). |
| `CRASHED` | The worker fired `onerror`/`onmessageerror` unexpectedly. |
| `CIRCUIT_LOAD_FAILED` | Fetching or executing a compiled circuit artifact failed on the main-thread fallback. |
| `PROOF_GENERATION_FAILED` | Witness execution or proof generation threw (e.g. invalid field value). |

All messages surfaced to the caller are stable, human-readable, and free of
secret, witness, and proof material.

## Local verification

Run the worker/fallback automated tests:

```sh
cd frontend
npx vitest run src/workers/proofWorkerClient.test.ts
```

For a manual end-to-end check in a real browser (bypassing the rest of the
app), open the dev server in a browser tab, open DevTools console, and run:

```js
const mod = await import('/src/workers/proofWorkerClient.ts')
const client = new mod.ProofWorkerClient()
const { requestId, result, mode, fallbackReason } = client.generate(
  { videoHash: '0'.repeat(64), credentialSecret: '123456789', nullifierSecret: '987654321' },
  (stage) => console.log('progress:', stage),
)
console.log('mode:', mode, 'fallbackReason:', fallbackReason)
result.then(r => console.log('RESULT', r)).catch(e => console.log('ERROR', e.code, e.message))
```

Call `client.cancel(requestId)` while it's running to confirm cancellation.
To exercise the fallback explicitly, construct with `{ runtime: 'main' }` and
watch for `mode === 'main-thread'`.

## Operational signals

Progress callbacks report only the current stage name (`loading_circuits`,
`executing_helper`, `executing_main`, `generating_proof`) — never witness
values, secrets, or proof material. This is safe to log or surface in UI
without risk of leaking sensitive data.

## Compatibility

- `PROOF_RUNTIME_VERSION`-style changes: the worker and fallback produce
  byte-identical `SilentWitnessProof` payloads; the runtime that produced a
  proof is **not** part of the verifier-input codec or the proof bytes, so
  proofs from either path verify identically and conformance vectors are
  unaffected.
- Proof manifests already carry scope/epoch; they are not changed by this
  work.

## Rollout / rollback

`attachSilentWitnessProof` in `useEvidence.ts` now creates a
`ProofWorkerClient` per proof generation (default `runtime: 'auto'`), so
proving uses the worker when available and transparently falls back to the
main thread otherwise; a one-line notice is surfaced when the fallback is
active.

To roll back, revert `useEvidence.ts` to call
`generateSilentWitnessProof` from `noirClient.ts` directly on the main
thread. No data migration, persisted state, or artifact format changes are
involved.

Note: `noirClient.ts` now performs bounded input validation where it
previously did not; direct callers that relied on permissive behavior (e.g.
arbitrary `verifier_scope` / `epoch` values) must pass valid values.

## Known limitations

- Only one proof request is served per `ProofWorkerClient` instance at a
  time; concurrent requests are rejected with `BUSY` rather than queued.
- Cancellation and timeout on the worker path discard in-flight worker state
  entirely (via `terminate()`); there is no partial-result recovery.
- On the main-thread fallback, cancellation/timeout cannot stop the WASM
  prover already in flight; the slot remains busy (rejecting `BUSY`) until
  the underlying prover settles.
- The `@vitest/web-worker` test-environment mock does not fully replicate
  real browser `Worker.terminate()` semantics — an in-flight `fetch` inside a
  terminated worker may still resolve/reject in the mock after termination,
  surfacing as a benign "unhandled rejection" in test output. This has been
  observed not to affect real-browser behavior (verified manually).