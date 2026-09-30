# Proof Generation Worker and Non-Worker Fallback

## Overview

Silent Witness proof generation (Noir witness execution + UltraHonk proving)
runs inside a dedicated Web Worker instead of the main thread. This keeps the
UI responsive during proving and allows in-flight proof generation to be
cancelled deterministically and privacy-safely.

When the Web Worker API is unavailable (e.g. `Worker` is not constructible in
a given environment, or spawning fails), `ProofWorkerClient` falls back to
proving directly on the main thread with **explicit, configurable limits**
so a mis-set environment cannot turn the fallback into an unbounded main
thread hang or unbounded memory use.

Implementation:
- `src/workers/proofWorker.ts` — runs inside the worker, wraps `noirClient.ts`
- `src/workers/proofWorker.types.ts` — shared message/state/runtime types
- `src/workers/proofWorkerClient.ts` — main-thread client (`ProofWorkerClient`)
- `src/proofWorkerMemory.ts` — worker memory and artifact-size budget checks
- `src/hooks/useEvidence.ts` — Evidence Studio integration + Cancel button
- `src/workers/multiBrowserWorkerSupport.ts` — multi-browser capability floor for module-worker proving

## Threat assumptions

- `credentialSecret` and `nullifierSecret` are sensitive witness inputs and
  must never be logged, persisted, or included in any worker message other
  than the initial transfer.
- Secrets are transferred to the worker as `ArrayBuffer`s via structured
  clone's transfer list (zero-copy, and the buffer is detached from the
  sender). The worker zeroes the underlying bytes as soon as strings are
  materialised, and again in a `finally` block, including the BUSY reject
  path.
- The worker assumes hostile/malformed input is possible (oversized secrets,
  non-hex video hashes) and validates before ever touching the worker or the
  network — see `INVALID_INPUT` below.
- The worker budget is derived from existing canonical metadata:
  `zk/bench/bench.lock.json` supplies witness/proof/public-input ceilings, and
  `zk/browser.artifacts.manifest.json` supplies published browser ACIR byte
  ceilings. The runtime does not introduce a second circuit/proof truth.
- Browser ACIR is size-checked before JSON parsing when the response exposes a
  stream or content length. Witness, proof, and public-input byte counts are
  checked before crossing the next expensive proof boundary.
- A stuck or unresponsive worker (e.g. due to a WASM-level hang) is treated
  the same as a crash: it is terminated and replaced, never left running
  indefinitely.
- Cancel / timeout / destroy / unmount all settle with a stable `CANCELLED`
  (or `TIMEOUT` / `CRASHED`) code whose message never contains witness values,
  seeds, proof hex, or media identifiers beyond stage names.

## State machine

Each `ProofWorkerClient` instance dispatches at most one active proof
request at a time, on either runtime.

```
idle --generate()--> running --resolves/rejects--> idle
running --generate() again--> immediately rejected with BUSY (no worker post)
running --cancel() / AbortSignal--> CANCEL msg + terminate + respawn → CANCELLED
running --memory cap exceeded--> MEMORY_LIMIT_EXCEEDED
running --60s elapsed--> worker terminated + respawned → TIMEOUT
running --worker crash--> worker terminated + respawned → CRASHED
destroyed --generate()--> CANCELLED
```

Cancellation and timeout both terminate the worker after signalling CANCEL,
because the underlying Noir/UltraHonk calls have no interruption hook and may
block the worker event loop for the duration of proving. Terminating and
spawning a fresh worker is the only way to guarantee an in-flight proof stops
promptly. A generation counter drops any late messages from the terminated
worker so they cannot settle a newer request.

## Error codes

| Code | Meaning |
|---|---|
| `BUSY` | A proof is already running on this client; request rejected immediately without touching the worker. |
| `INVALID_INPUT` | `videoHash` is not 64 hex characters, a secret is empty, or a secret exceeds the maximum size (256 bytes). Rejected before any worker/network activity. |
| `UNSUPPORTED_ENVIRONMENT` | Multi-browser capability floor not met (Worker, WebAssembly, SubtleCrypto, BigInt, or ArrayBuffer missing). Rejected before secrets are transferred. |
| `CANCELLED` | `cancel()`, `AbortSignal`, `destroy()`, or unmount aborted this request. |
| `TIMEOUT` | Proof generation exceeded `PROOF_TIMEOUT_MS` (60s). |
| `CRASHED` | The worker fired `onerror`/`onmessageerror` unexpectedly. |
| `CIRCUIT_LOAD_FAILED` | Fetching a compiled circuit artifact failed. |
| `MEMORY_LIMIT_EXCEEDED` | A published ACIR, witness estimate, proof, public-input frame, or total worker runtime estimate exceeded the pinned proof-worker budget. |
| `PROOF_GENERATION_FAILED` | Witness execution or proof generation threw (e.g. invalid field value). |

## Input and dependency outcomes

| Condition | Worker behavior |
|---|---|
| Malformed input | `INVALID_INPUT`; rejected before any worker/network activity. |
| Oversized secret input | `INVALID_INPUT`; rejected before transfer. |
| Oversized artifact/witness/proof output | `MEMORY_LIMIT_EXCEEDED`; stable message `proof_worker_memory_exceeded`. |
| Unsupported input schema or scoped request against browser-v1 ACIR | `UNSUPPORTED_INPUT_SCHEMA`. |
| Browser capability missing | `UNSUPPORTED_ENVIRONMENT`; rejected before transfer. |
| Artifact fetch/parse dependency failure | `CIRCUIT_LOAD_FAILED`. |
| Prover dependency failure after valid inputs | `PROOF_GENERATION_FAILED`. |
| Expired or revoked evidence | Not decided by proof generation; verification/registry paths retain their existing `EXPIRED_EVIDENCE` and `REVOKED_EVIDENCE` handling. |

## Local verification

Run the worker/fallback automated tests:

```bash
cd frontend
npx vitest run src/proofWorkerMemory.test.ts src/workers/proofWorkerClient.test.ts
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
result.then(r => console.log('RESULT', r.proofBytes)).catch(e => console.log('ERROR', e.code, e.message))
```

Call `client.cancel(requestId)` while it's running to confirm cancellation.
In Evidence Studio, use **Cancel proving** while stage is `proving`.

## Operational signals

Progress callbacks report only the current stage name (`loading_circuits`,
`executing_helper`, `executing_main`, `generating_proof`) — never witness
values, secrets, or proof material. This is safe to log or surface in UI
without risk of leaking sensitive data.

## Compatibility / migration

- Proof / public-input encodings are unchanged (`noirClient.ts` remains the
  single proving implementation; the worker only wraps it).
- The memory cap is a browser-worker runtime guard only. It does not change
  Noir source, ACIR semantics, public-input frames, proof verification,
  contracts, or stored evidence.
- Call site moved from a direct `noirClient` import in the evidence flow to
  `ProofWorkerClient.generate()` inside `useEvidence.attachSilentWitnessProof`.
- No artifact, contract, or stored-evidence migration is required.
- Rollback: revert the worker budget module/client mapping and, if needed,
  revert `useEvidence.ts` to call `generateSilentWitnessProof` from
  `noirClient.ts` on the main thread and hide the Cancel button. No data repair
  or chain migration is required.

This change is additive at the call-site level: `useEvidence.ts`'s `runProver`
now calls `ProofWorkerClient.generate()` instead of calling
`generateSilentWitnessProof` from `noirClient.ts` directly on the UI thread.
`noirClient.ts` itself is unchanged and still the single source of truth for
the actual proving logic — the worker only wraps it. There is intentionally no
main-thread proving fallback: when the capability floor is not met,
`ProofWorkerClient` rejects with `UNSUPPORTED_ENVIRONMENT` before any
credential/nullifier secret is transferred (see `BROWSER_SUPPORT.md`).

To roll back, revert `useEvidence.ts`'s `attachSilentWitnessProof` to call
`generateSilentWitnessProof` from `noirClient.ts` directly on the main
thread. No data migration, persisted state, or artifact format changes are
involved — the change is confined to how/where the existing proving logic is
invoked.
## Trust boundary notes

| Boundary | Behaviour on cancel |
|---|---|
| Main thread | Pending promise rejects `CANCELLED`; AbortController cleared; no secrets retained (buffers already transferred/detached). |
| Worker | CANCEL acknowledged; secret `ArrayBuffer`s zeroed; ACIR/witness/proof memory bounded; worker then terminated so WASM heap is discarded. |
| UI | Stage returns to `ready` with a privacy-safe status message (no seeds/proof hex). |

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

## Multi-browser worker support

Browser proving is gated by the same support floor documented in
`frontend/BROWSER_SUPPORT.md` and pinned in `frontend/browser-support.mjs`
(Chrome 111+, Edge 111+, Firefox 114+, Safari 16.4+, iOS 16.4 best-effort).

`multiBrowserWorkerSupport.ts` maps that matrix onto the proof-worker boundary:

- Every matrix browser requires **module Web Workers** so witnesses never
  execute on the UI thread as a compatibility fallback.
- Desktop `supported` tiers are full proving surfaces; iOS/iPadOS remains
  `best-effort` because large UltraHonk proofs can exceed mobile memory.
- At generate-time, `ProofWorkerClient` calls `assessWorkerSupport()` and
  rejects with `UNSUPPORTED_ENVIRONMENT` when Worker, WebAssembly,
  SubtleCrypto, BigInt, or ArrayBuffer is missing — **before** any
  credential/nullifier secret is transferred.
- Assessment reasons name capability identifiers only; they never include
  media, witnesses, seeds, or private keys.

Compatibility / migration / rollback: this gate does not change Noir ACIR,
public inputs, contracts, or stored evidence. Rollback is a revert of the
support module + client check; no data migration is required.

Focused coverage lives in:

```bash
cd frontend
npx vitest run src/workers/multiBrowserWorkerSupport.test.ts src/proofWorkerMemory.test.ts src/workers/proofWorkerClient.test.ts
```

