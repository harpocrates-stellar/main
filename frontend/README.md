# Harpocrates Frontend

React Evidence Studio and Verification Portal.

## Run

```powershell
npm install
npm run dev
```

## Environment

Copy `.env.example` to `.env.local` and set:

```text
VITE_API_BASE=http://127.0.0.1:5050
VITE_HARPOCRATES_REGISTRY_ID=...
VITE_STELLAR_RPC_URL=https://soroban-testnet.stellar.org
VITE_STELLAR_READONLY_SOURCE=G...
```

## Stellar Client

The Stellar boundary is split into typed modules:

```text
src/stellarTypes.ts       shared registry types and branded hex strings
src/stellarEncoding.ts    hex and Soroban SCVal conversion helpers
src/harpocratesRegistry.ts typed HarpocratesRegistry calls
src/stellar.ts            public facade for app imports
```

## Browser support

The supported browser floor, required security capabilities, mobile limitations,
and fail-closed compatibility behavior are documented in
[`BROWSER_SUPPORT.md`](BROWSER_SUPPORT.md). The build consumes the same canonical
target list from `browser-support.mjs`. Verify the matrix with:

```powershell
npm run check:browser-support
```

## Build

```powershell
npm run build
```

The Vite config keeps the initial app bundle small and lazy-loads heavier
runtime code. Expected production chunks include:

```text
react
stellar
noir-runtime
noirClient
barretenberg
barretenberg-threads
```

## Test

Run the Vitest and React Testing Library suite:

```powershell
npm test
```

## Evidence Studio & Recovery

The Evidence Studio (`useEvidence` hook and `StudioView`) allows users to upload source videos, configure identity tiers, and record evidence notes:

- **Evidence Notes Preservation**: Original user-entered evidence notes (`evidenceNotes`) are maintained in memory across recoverable API failures (such as steganography service timeouts or temporary 5xx errors).
- **Stale Server Result Guard**: In-flight server requests cannot overwrite user edits made in the UI during or after a recoverable failure.
- **Reviewed File Identity**: The retry action (`retryEvidence`) is strictly tied to the reviewed file identity (matching file name, size, and last modified timestamp). If a user selects a different file, previous notes are safely reset for the new file context.

## Browser storage policy

All application-owned browser persistence must go through the wrappers in
`src/safeStorage.ts`. The allowlist contains only these public UI preferences:

- `currentView`: the active navigation view
- `selectedTier`: the active identity-tier selection
- `vaultRecoveryRehearsed`: flag indicating whether the one-time vault recovery rehearsal has completed

Credential or nullifier seeds, proof witnesses, generated proofs, raw private
inputs, and every other field are prohibited from both `localStorage` and
`sessionStorage`. Keep secret proof-generation data in memory only.

## Upload Admission & Queue State

Evidence Studio exposes backend upload admission and queue limits, mapping backend capacity reasons to actionable UI states:

- **Queue & Capacity Reasons**:
  - `queue_full` (HTTP 503): Service concurrency queue is saturated. Displays actionable wait time from `Retry-After` header and provides a single-click Retry button.
  - `identity_limit` (HTTP 429): Concurrent in-flight uploads for the active identity tier or address exceeded limits. Displays queue timeout and retry button.
  - `timeout` (HTTP 503): Request queued but timed out waiting for backend processing slot. Actionable retry state.
  - `rate_limited` (HTTP 429): Standard API rate limiting with retry-after hint.
- **Distinct from Invalid Evidence**:
  - Admission rejections (queue / capacity overloads) are treated as transient and retryable, rendering the `.admission-queue-banner`.
  - Invalid evidence rejections (e.g., 400 Bad Request, 413 Payload Too Large, 415 Unsupported Media Type, or payload integrity mismatches) are distinct failure states representing malformed inputs or integrity violations, rendering the `.invalid-evidence-banner` without falsely attributing capacity limits.

