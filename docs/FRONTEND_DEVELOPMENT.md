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

## 4. Duplicate Conflicting Statement Identifier Guard
Before serializing JSON, CSV, or receipt collections, `frontend/src/batchExport.ts` inspects canonical statement identifiers (`manifest.proofId` or `videoHash`) via `inspectBatchStatementConflicts`:

- Contradictory rows sharing a statement identifier with differing `status`, `videoHash`, `metadataHash`, `sourceHash`, `tier`, or `chainStatus` fail closed before serialization (`BatchExportConflictError`), reporting each conflicting `statementId`, differing fields, and participating inputs.
- Valid unique non-conflicting results are preserved in `inspection.validResults` (and `exportBatchJSON(results, { excludeConflicting: true })`), while benign byte-duplicate rows (`status: 'duplicate'`) pass without false conflict errors.
