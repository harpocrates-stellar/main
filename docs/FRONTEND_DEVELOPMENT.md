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

## 4. Read-Only Proof Preparation Preview
`buildProofPreparationPreview` (`useEvidence`) and `StudioView` provide a side-effect-free inspection panel before proof generation or transaction submission:
- Displays the active `policyVersion` (`harpocrates-proof-policy-v1`), `inputSchemaVersion` (`v1`), and canonical BN254 decimal / SHA-256 public inputs (`video_hash_hi`, `video_hash_lo`, `verifier_scope`, `epoch`, `metadata_hash`, `proof_id`).
- Conceals private witness values (`credential_secret`, `nullifier_secret`) behind `[CONCEALED WITNESS]` and never invokes the proof worker or Stellar submission endpoints.