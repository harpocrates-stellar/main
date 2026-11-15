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

## 4. Stable Concurrent Batch Result Ordering
`BatchVerifier` (`frontend/src/batchVerifier.ts`), `BatchVerificationWorkspace`, and `frontend/src/batchExport.ts` anchor every selected file to its original `inputIndex` (`0..N-1`) and deterministic `inputIdentity` (`deriveSelectedInputIdentity`):

- Progress snapshots (`onProgress`), `getItems()`, `runBatch()`, retry updates, and JSON/CSV/receipt exports pass through `orderBatchItemsBySelection`, preserving the original selection order rather than asynchronous worker completion order.
- When concurrent workers hash identical files out of order, duplicate attribution is canonicalized so the earliest `inputIndex` retains primary verification status and later slots reference it via `duplicateOf`.
