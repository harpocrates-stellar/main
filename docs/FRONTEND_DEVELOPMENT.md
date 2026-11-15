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

## 4. Batch Completeness Summary & Unresolved-Check Accounting
`computeBatchCompleteness` in `frontend/src/batchVerifier.ts` (surfaced in `BatchSummary.completeness`, `exportBatchJSON`, and `BatchVerificationWorkspace`) reports four distinct item buckets plus unresolved-check accounting:

- **`verified`**: `confirmed` and `manifest-valid` items.
- **`failed`**: `revoked`, `manifest-invalid`, `malformed`, `oversized`, and `error` items.
- **`cancelled`**: aborted `cancelled` items.
- **`incomplete`**: non-terminal or partially resolved items (`pending`, `hashing`, `processing`, `unavailable`, `metadata-only`, `database-only`).
- **`unresolvedChecks`**: `cancelled + incomplete`. Interrupted or partially unresolved runs (`isInterrupted` or `unresolvedChecks > 0`) always report `isComplete: false`.
