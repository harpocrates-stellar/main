# Harpocrates Frontend

React Evidence Studio and Verification Portal.

## Run

```powershell
npm install
npm run dev
```

## Environment

Copy `.env.example` to `.env.local` and set:

```text
VITE_API_BASE=http://127.0.0.1:5050
VITE_HARPOCRATES_REGISTRY_ID=...
VITE_STELLAR_RPC_URL=https://soroban-testnet.stellar.org
VITE_STELLAR_READONLY_SOURCE=G...
```

## Stellar Client

The Stellar boundary is split into typed modules:

```text
src/stellarTypes.ts       shared registry types and branded hex strings
src/stellarEncoding.ts    hex and Soroban SCVal conversion helpers
src/harpocratesRegistry.ts typed HarpocratesRegistry calls
src/stellar.ts            public facade for app imports
```

## Browser support

The supported browser floor, required security capabilities, mobile limitations,
and fail-closed compatibility behavior are documented in
[`BROWSER_SUPPORT.md`](BROWSER_SUPPORT.md). The build consumes the same canonical
target list from `browser-support.mjs`. Verify the matrix with:

```powershell
npm run check:browser-support
```

## Build

```powershell
npm run build
```

The Vite config keeps the initial app bundle small and lazy-loads heavier
runtime code. Expected production chunks include:

```text
react
stellar
noir-runtime
noirClient
barretenberg
barretenberg-threads
```

## Test

Run the Vitest and React Testing Library suite:

```powershell
npm test
```

## Browser storage policy

All application-owned browser persistence must go through the wrappers in
`src/safeStorage.ts`. The allowlist contains only these public UI preferences:

- `currentView`: the active navigation view
- `selectedTier`: the active identity-tier selection

Credential or nullifier seeds, proof witnesses, generated proofs, raw private
inputs, and every other field are prohibited from both `localStorage` and
`sessionStorage`. Keep secret proof-generation data in memory only.

## Verification Portal Trust Reason Codes

`src/services/verificationFlow.ts` maps stable trust reason codes
(`TrustReasonCode`) to accessible, privacy-safe copy (`TRUST_REASON_COPY`,
`getTrustReasonCopy`, `resolveTrustReasonCode`, and `explainVerificationTrust`),
and `src/views/VerifyView.tsx` renders this explanation separately below the
underlying proof result so cryptographic proof validity is never obscured by
issuer registry standing:

| Reason Code | Meaning |
| :--- | :--- |
| `TRUSTED_ISSUER` | On-chain registry lists the issuer as active and the endorsement is current. |
| `UNKNOWN_ISSUER` | Issuer address is absent from the on-chain institutional allowlist. Explained as an issuer trust gap, distinct from an invalid signature; the underlying proof result remains visible. |
| `REVOKED_ISSUER` | Issuer is revoked in the on-chain registry; institutional endorsement is withdrawn. |
| `EXPIRED_ENDORSEMENT` | Issuer is active, but the proof record has passed its endorsement expiry window. |
| `INVALID_SIGNATURE` | Cryptographic signature or proof/metadata envelope binding failed (`INVALID_EVIDENCE` / `METADATA_ENVELOPE_MISMATCH`). Fail-closed: never downgraded to `UNKNOWN_ISSUER`. |
| `MALFORMED_ISSUER` | Issuer address on the chain record is malformed or oversized and cannot match a Stellar StrKey. |
| `ISSUER_LOOKUP_UNAVAILABLE` | Registry lookup failed. Fail-closed: neither an unknown issuer nor an invalid signature. |
| `NO_ISSUER_REQUIRED` | Identity tier (Tier 1 Silent Witness or Tier 2 Consistent Source) does not carry an institutional issuer. |
| `ISSUER_CHECK_PENDING` | Issuer lookup against the on-chain registry is still in flight. |
| `OFFLINE_NOT_CHECKED` | Offline local mode ran without querying the Stellar registry; no institutional trust decision was made. |

