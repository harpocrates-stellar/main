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

## 4. Bounded Batch Archive Filenames & Output Paths
Batch verification exports (`frontend/src/batchExport.ts`) bound archive filenames via `MAX_ARCHIVE_STEM_LENGTH` (`48`) and `MAX_ARCHIVE_PATH_LENGTH` (`96`):

- `sanitizeArchiveStem` strips directory traversal segments (`..`, `/`, `\`), reserved characters, and Windows device stems (`CON`, `NUL`, etc.).
- `buildBatchArchiveEntries` and `exportBatchArchiveManifest` deterministically disambiguate duplicate or truncated-prefix stems (case-insensitively) using canonical digest suffixes while binding every exported entry back to its source item (`sourceItemId`, `sourceIndex`, `sourceFileName`, and `outputPath`).
