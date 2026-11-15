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

## 4. Export Privacy Summary in Evidence Studio
Before operators download embedded evidence videos or copy shareable verification links in `StudioView` (`frontend/src/views/StudioView.tsx`), `buildExportPrivacySummary` (`frontend/src/hooks/useEvidence.ts`) enumerates:
- **Included metadata classes** (`portable_manifest`, `integrity_digests`, `capture_timestamp`, tier credential class, and optional `ledger_settlement`).
- **Public identifiers** (`proofId`, `videoHash`, `metadataHash`, `sourceHash`, network passphrase, registry contract, and applicable nullifier/signer/transaction digests).
- **Differential sensitive-field acknowledgement**: baseline anonymous `silent` exports require no acknowledgement checkbox, while sensitive attribution or timing fields (`pseudonymous_wallet_attribution`, `institutional_issuer_attribution`, `claimed_capture_time_attestation`, `ledger_transaction_reference`) require explicit confirmation only when newly exposed.
