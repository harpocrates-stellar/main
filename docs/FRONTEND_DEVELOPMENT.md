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

## 4. Batch Verification Export Privacy Profiles
Batch verification exports (`frontend/src/batchExport.ts` and `BatchVerificationWorkspace`) support two explicit `BatchExportPrivacyProfile` field sets defined in `BATCH_EXPORT_FIELD_SETS`:

- **`public` (`Public (redacted)`, UI default)**: Emits `itemRef`, `fileSizeBytes`, `status`, `videoHash`, `metadataHash`, `sourceHash`, `tier`, `chainStatus`, `message` (with raw filenames scrubbed), redacted `duplicateOf` references, and `durationMs`. Raw filenames (`fileName`), internal `failureReason`, and private `issuerNotes` are excluded from JSON, CSV, and receipt collection exports.
- **`owner-only` (`Owner-only (full)`, programmatic no-arg default for backward compatibility)**: Includes all `public` fields plus `fileName`, `failureReason`, and `issuerNotes` while continuing to strip in-memory `File` handles and media bytes.
