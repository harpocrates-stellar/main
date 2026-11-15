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

## 4. Separating Selected Evidence from Previously Verified Artifacts
When an operator selects a replacement video file in Evidence Studio (`frontend/src/hooks/useEvidence.ts` and `frontend/src/views/StudioView.tsx`), prior `proof`, `registration`, `processedVideoUrl`, Quick Verify status, `ChainProofPanel` badges, and `ProvenanceCard` records are cleared immediately before the replacement file finishes processing, while a polite `role="status"` region explains that previous verification badges were cleared because they belonged to an earlier artifact.
