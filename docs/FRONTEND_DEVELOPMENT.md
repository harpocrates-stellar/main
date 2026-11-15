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

## 4. Evidence Notes & Recoverable API Retry Binding
`useEvidence` and `StudioView` preserve operator-entered `evidenceNotes` locally across recoverable API failures (`5xx`, `429`, and network timeouts):
- Local edits increment a monotonic revision counter so delayed or retried server responses never overwrite user-entered notes.
- `recoverableFailure` binds `retryRecoverableEvidence` to `computeReviewedFileIdentity(file)` (`name`, `size`, `lastModified`, `mimeType`, and deterministic fingerprint) and fails closed if the file identity changes before retry.