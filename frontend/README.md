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

### Storage Availability vs. Passphrase Diagnostics

`CredentialVault` (`src/credentialVault.ts`) and `src/safeStorage.ts` separate
browser storage errors from AES-GCM authentication failures:

- Blocked or unavailable storage throws `VaultAccessError` (or returns structured `VaultUnlockOutcome` from `unlockWithDiagnostics`) with `STORAGE_PERMISSION_DENIED`, `STORAGE_QUOTA_EXCEEDED`, or `STORAGE_UNAVAILABLE` plus explicit recovery guidance.
- Decryption tag failures set `code: 'INCORRECT_PASSPHRASE'` with passphrase-specific recovery guidance while `unlock()` continues returning `false` for backward compatibility.
- Storage read, write, or permission failures never call `removeItem` on `harpocrates:credential-vault`, preserving any stored encrypted envelope until storage permissions are restored.
