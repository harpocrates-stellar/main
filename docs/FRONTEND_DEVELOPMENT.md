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

## 4. Guided Network Mismatch Recovery in Evidence Studio
When registration detects a wallet passphrase mismatch, `useEvidence` populates `networkRecovery` (`StudioNetworkRecoveryState`) and `StudioView` renders an accessible recovery banner:
- Displays both the required contract network and the current wallet network alongside the selected evidence intent (`tier` and digest summary).
- Blocks resuming registration until `revalidateNetworkRecovery` performs a fresh wallet network check and verifies that the selected file digests, identity tier, and wallet match the prepared evidence package (`resumeAfterNetworkRecovery`).