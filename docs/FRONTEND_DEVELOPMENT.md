# Frontend Development & Testing

This document details the local equivalent commands used by the `Frontend CI` workflow. All commands must be run from within the `frontend/` directory.

## 1. Install Dependencies
Always use `npm ci` to ensure strict alignment with `package-lock.json`:
```bash
npm ci
```
## 2. Code Linting
Run static analysis to catch syntax and styling errors:
```bash
npm run lint
```
(If errors arise, try running npm run lint -- --fix to auto-correct styling issues).

## 3. Production Build
Verify the application compiles and bundles successfully for production:
```bash
npm run build
```
(This performs TypeScript type-checking and Vite compilation. It will fail if there are any TypeScript or bundling errors).

## 4. Batch Preflight Inspection Report
Before reading file buffers, computing SHA-256 chunks, parsing receipts, or calling verification endpoints, `inspectBatchPreflight` and `BatchVerifier.preflight` (`frontend/src/batchVerifier.ts`) evaluate `File` descriptor metadata synchronously:

- Reports `totalBytes`, `eligibleCount`, `eligibleBytes`, `duplicateInputs` (repeated descriptor identities), `unsupportedFormats` (non-video and non-JSON files), `oversizedFiles`, and `canProceed`.
- `BatchVerificationWorkspace` surfaces the preflight report immediately upon file selection, and `BatchVerifier.runBatch` completes preflight (and any `onPreflight` / `preflightOnly` gate) before starting any hashing or proving work.
