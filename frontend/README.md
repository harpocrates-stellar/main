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

## Structured Verification Result Model

`src/services/verificationFlow.ts` (`evaluateStructuredVerificationResult`, `runVerificationFlow`, and `verifyUploadedVideo`) and `src/views/VerifyView.tsx` (`StructuredTrustDimensionsPanel`) evaluate four orthogonal trust dimensions independently:

- `contentIntegrity`: embedded Harpocrates metadata envelope and canonical digest consistency (`videoHash`, `metadataHash`)
- `chainRegistration`: Soroban `HarpocratesRegistry` commitment presence, revocation standing, and identity-tier binding
- `issuerTrust`: registry issuer standing for issuer-bearing tiers (`trusted`, `revoked`, `unknown`, `expired`, or `not-applicable` for anonymous / non-issuer tiers)
- `freshness`: proof expiry window, live observation staleness, and Stellar network passphrase alignment

Composition is strictly fail-closed and non-masking:

- Any `failed` dimension yields `overallVerdict: 'rejected'` (even when the remaining three dimensions are `verified`), suppresses shareable verification link generation, and surfaces both passing and failing dimension statuses side by side.
- Zero `failed` dimensions with one or more `unverified` dimensions (for example offline local checks or an unknown/incomplete issuer lookup) yields `overallVerdict: 'unconfirmed'`.
- `overallVerdict: 'verified'` requires every applicable dimension to be `verified` (`not-applicable` is permitted only for `issuerTrust` on anonymous or source-witness tiers without an institutional issuer).

## Browser storage policy

All application-owned browser persistence must go through the wrappers in
`src/safeStorage.ts`. The allowlist contains only these public UI preferences:

- `currentView`: the active navigation view
- `selectedTier`: the active identity-tier selection

Credential or nullifier seeds, proof witnesses, generated proofs, raw private
inputs, and every other field are prohibited from both `localStorage` and
`sessionStorage`. Keep secret proof-generation data in memory only.
