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

## 4. Resumable Batch Verification Checkpoints
`frontend/src/batchVerifier.ts` and `frontend/src/batchExport.ts` support resumable batch verification checkpoints (`harpocrates-batch-checkpoint`, `version: 1`) via `createBatchCheckpoint`, `validateBatchCheckpoint`, `BatchVerifier.resumeBatch`, `exportBatchCheckpointJSON`, and `importBatchCheckpointJSON`:

- **Non-secret persistence only**: Checkpoints store ordered `inputFingerprints` (`inputIndex`, `sizeBytes`, `lastModified`, `mimeType`, and hashed `fingerprintId`) plus terminal `completedEntries`. Raw media bytes, `File` handles, directory paths, witness secrets, and wallet identifiers are never persisted.
- **Fail-closed context binding**: `validateBatchCheckpoint` and `BatchVerifier.resumeBatch` reject resumption (`BatchCheckpointError`) whenever selected files or their order change (`files_mismatch`), batch byte budgets change (`policy_mismatch`), or `apiBase`, `contractId`, or `networkPassphrase` differ (`network_mismatch`). Valid resumptions skip re-hashing and re-querying already-completed items.
