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

## 4. Upload Admission & Queue State in Evidence Studio
Evidence Studio (`frontend/src/hooks/useEvidence.ts`, `frontend/src/views/StudioView.tsx`, and `frontend/src/services/apiError.ts`) maps upload pre-checks, queue telemetry (`X-Harpocrates-Admission-State`, `X-Harpocrates-Queue-Position`, `Retry-After`), and rejection codes into actionable `UploadAdmissionState` values:
- **Retryable queue & capacity rejections (`category: 'admission_rejected'`)**: `QUEUE_FULL`, `ADMISSION_DEFERRED`, `RATE_LIMITED`, `CAPACITY_EXCEEDED`, `STEGO_LIMIT_EXCEEDED`, and `DEPENDENCY_UNAVAILABLE` surface queue position / retry windows and expose `retryUploadAdmission()` for the existing file.
- **Invalid evidence errors (`category: 'invalid_evidence'`)**: `UNSUPPORTED_MEDIA_TYPE`, `PAYLOAD_TOO_LARGE`, `VALIDATION_ERROR`, local hashing failures, and corrupt steganography packages remain non-retryable and prompt selecting a valid replacement file.
