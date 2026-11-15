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

## 4. Deterministic Batch Comparison Export
`frontend/src/batchExport.ts` provides deterministic manifest diffing across versioned `harpocrates-batch-report` (`version: 1`) payloads via `compareBatchReports`, `exportBatchComparisonJSON`, and `exportBatchComparisonCSV`:

- Manifests are matched by canonical cryptographic statement identity (`deriveStatementIdentity` over `videoHash`, `metadataHash`, and `sourceHash`), independent of row order or local filename renames.
- Diff outputs deterministically separate `trustContextChanges` (`status`, `chainStatus`, or `tier` transitions for the same statement) from `added`, `removed`, and `unchanged` items, and fail closed (`BatchComparisonError`) on malformed JSON, mismatched protocol/version, or conflicting duplicate statements.
