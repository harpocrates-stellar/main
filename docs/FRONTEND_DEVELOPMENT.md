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

## 4. Evidence Studio Pre-Registration Review
Before submitting a prepared proof package to Stellar, `StudioView` and `useEvidence` (`frontend/src/hooks/useEvidence.ts`) require explicit confirmation of an **Evidence-processing review before registration** summary:
- Displays the **Selected Identity Tier** (`Silent Witness`, `Consistent Source`, or `Public Seal`), canonical 256-bit **Statement Digest** (`computeRegistrationStatementDigest` over tier, network passphrase, `proofId`, `videoHash`, `metadataHash`, and `sourceHash`), and **Target Network** (`formatNetworkLabel`) without exposing private witness seeds.
- `Register proof` stays disabled (and `registerProof` fails closed) until `confirmRegistrationReview()` confirms the active `reviewFingerprint`.
- Any change to the source `File` or proof parameters (`selectedTier`, `credentialSeed`, `nullifierSeed`, or prepared `ProofPackage`) recomputes `reviewFingerprint`, marks `isInvalidated: true`, and requires re-confirming the updated review before registration.
