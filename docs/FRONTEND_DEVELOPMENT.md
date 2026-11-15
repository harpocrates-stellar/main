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

## 4. Per-Item Batch Cancellation & Outcome Classification
`BatchVerifier` (`frontend/src/batchVerifier.ts`) maintains an isolated `AbortController` per batch item alongside the batch-wide controller:

- `verifier.cancelItem(itemId)` aborts a single queued (`pending`) or active (`hashing` / `processing`) item without interrupting sibling concurrent items; `verifier.skipItem(itemId)` skips a queued item prior to execution.
- `classifyBatchOutcome` (`outcomeCategory` on `BatchItemResult` and `CleanBatchReportItem`, plus `BatchSummary` counters) explicitly distinguishes **`verified`** (`confirmed`, `manifest-valid`), **`failed`** (`revoked`, `manifest-invalid`, `malformed`, `error`, `unavailable`), **`cancelled`** (`cancelled`), and **`skipped`** (`skipped`, `duplicate`, `oversized`).
