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

## 4. Interrupted Upload Recovery in Evidence Studio
`useEvidence` (`frontend/src/hooks/useEvidence.ts`) persists sanitized interrupted upload checkpoints via `CheckpointStorage` (never storing media bytes, host paths, or secret seeds) so `StudioView` (`frontend/src/views/StudioView.tsx`) keeps recovery choices visible across navigation:
- **Session classification**: `classifyInterruptedUploadSession` distinguishes `resumable` (within `UPLOAD_RECOVERY_TTL_MS`, 15 minutes), `expired`, and `unrecoverable` sessions.
- **Changed-source guard**: `resumeInterruptedUpload` verifies the candidate `File` fingerprint (`fileName`, `sizeBytes`, `lastModified`, and `mimeType`) before retrying and transitions to `unrecoverable` without automatic retry if the source file changed.
