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

## 4. Verification Receipt Comparison View
The Verify portal (`frontend/src/views/VerifyView.tsx`) includes a **Compare two receipts** view (`frontend/src/components/ReceiptComparisonView.tsx` + `frontend/src/services/receiptComparison.ts`) for inspecting two verification receipts side by side:
- Highlights changed **Trust Observations** (`result`, `tier`, `signer.keyId`, `circuitVersion`, `verifierVersion`) and **Chain Observations** (`networkPassphrase`, `contractId`, `ledgerSequence`, `transactionHash`) with exact UTC ISO-8601 timestamps and elapsed time delta.
- Rejects receipts or URLs containing private evidence metadata or secret fields (`fileName`, `media`, `stego`, `witness`, `nullifier`, `seed`, `secret`, `credential`, etc.) fail-closed.
- Generates privacy-safe hash-routed comparison URLs (`#verify?compare=<base64url>`) containing only public receipt digests, timestamps, and chain identifiers.