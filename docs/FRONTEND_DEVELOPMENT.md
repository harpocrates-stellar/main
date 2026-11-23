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

## 4. Studio Network Mismatch Recovery
When `useEvidence.registerProof` detects that Freighter's active network does not match `CONTRACT_NETWORK_PASSPHRASE` (or cannot be read), Evidence Studio enters a guided recovery state (`networkMismatchRecovery`):
- `StudioView` displays both the **Required network** and the **Current wallet network** (never raw passphrases, wallet addresses, or witness secrets) and keeps **Register proof** disabled.
- Calling **Re-validate & resume** (`revalidateNetworkMismatch`) performs a fresh wallet network check and verifies that the selected evidence intent (prepared proof package and active identity tier) is still valid and unchanged before clearing the mismatch and allowing registration to resume.
