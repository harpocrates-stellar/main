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

## Batch Verification & Preflight Report

The Batch Verification Workspace supports high-throughput verification of evidence files
and standalone JSON receipts with bounded browser memory and worker concurrency.

Before expensive verification operations (chunked hashing, steganography extraction,
ZK proving), the verifier performs a synchronous **batch preflight check**:
- **Duplicate inputs**: Identifies duplicate files in the input batch before computing hashes.
- **Total bytes**: Calculates aggregate byte counts across the batch upfront.
- **Unsupported formats**: Flags files that do not match supported video containers
  (`.mp4`, `.mov`, `.webm`, `.mkv`, `.avi` / `video/*`) or proof manifests (`.json` / `application/json`).
- **Oversized inputs**: Enforces per-file (`maxFileSizeBytes`) and total batch (`maxTotalSizeBytes`) bounds.

No hashing or proving begins on duplicate inputs or unsupported formats.
Preflight reports can be exported directly to JSON and CSV.

## Browser storage policy

All application-owned browser persistence must go through the wrappers in
`src/safeStorage.ts`. The allowlist contains only these public UI preferences:

- `currentView`: the active navigation view
- `selectedTier`: the active identity-tier selection

Credential or nullifier seeds, proof witnesses, generated proofs, raw private
inputs, and every other field are prohibited from both `localStorage` and
`sessionStorage`. Keep secret proof-generation data in memory only.
