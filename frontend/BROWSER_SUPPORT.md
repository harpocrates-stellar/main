# Browser support

Harpocrates keeps private proof inputs in the browser, so browser compatibility
is a security boundary rather than only a rendering concern. This document
defines the frontend support floor and the behavior expected when a browser or
dependency cannot provide that boundary.

The canonical build targets live in [`browser-support.mjs`](browser-support.mjs)
and are consumed directly by `vite.config.ts`. They intentionally pin the
current Vite 8 **Baseline Widely Available** floor instead of inheriting a
moving default:

- `chrome111`
- `edge111`
- `firefox114`
- `safari16.4`
- `ios16.4`

## Support matrix

| Browser | Platform | Minimum | Tier | Notes |
| --- | --- | ---: | --- | --- |
| Chrome | desktop | 111+ | supported | Full Evidence Studio, verification, and browser proving are in scope. |
| Edge | desktop | 111+ | supported | Chromium-equivalent support floor. |
| Firefox | desktop | 114+ | supported | Full web feature set is expected; wallet-extension availability is separate. |
| Safari | macOS | 16.4+ | supported | Full web feature set is expected; wallet-extension availability is separate. |
| Safari | iOS/iPadOS | 16.4+ | best-effort | Build-compatible, but large in-browser proofs can exceed mobile memory limits and are not release-gated in CI. |

Versions below the matrix, Internet Explorer, embedded legacy WebViews, and
browsers with required APIs disabled are unsupported. A user may still reach
static UI in such an environment, but Harpocrates does not promise proof,
vault, or wallet flows there.

## Required browser capabilities

The compatibility floor is only meaningful while these application boundaries
remain available:

- secure-context Web Crypto (SubtleCrypto) for SHA-256, PBKDF2, AES-GCM, and
  ECDSA P-256 operations;
- WebAssembly for Noir/Barretenberg proof generation and verification;
- module Web Workers so proof work stays off the main UI thread;
- BigInt for exact cryptographic and Stellar integer handling;
- File/Blob/ArrayBuffer APIs for bounded local evidence processing; and
- localStorage for the explicitly permitted encrypted/checkpoint and public UI
  state described by the repository storage policies.

`navigator.clipboard` is an enhancement, not a proof or verification boundary.
Freighter is also a separate dependency: wallet-backed actions require a
Freighter-compatible browser/extension, while read-only verification does not.
Harpocrates never falls back to asking for a seed phrase or private key.

## Unsupported and dependency-failure behavior

Compatibility failures must fail closed at the feature boundary:

- **Web Crypto unavailable or rejected:** hashing, vault, receipt signing, or
  verification must return their normal bounded error. The application must not
  send a secret input to the backend as a compatibility fallback.
- **WebAssembly/Worker unavailable:** browser proving is unavailable. Witnesses
  and credential/nullifier seeds remain in memory and are not logged or
  uploaded merely to recover from the failure.
- **Storage unavailable/corrupt:** checkpoint or encrypted-vault restoration may
  fail or be cleared by existing validation. Raw witnesses, private keys, and
  media are never added to storage as a fallback.
- **Freighter unavailable/rejected:** wallet-backed actions fail through the
  existing connection path. Users are never asked to paste signing secrets.
- **Oversized/malformed evidence:** existing input limits and validation remain
  authoritative; browser support does not weaken those guards.

Error reports and compatibility diagnostics should contain capability names and
versions only. Do not include media bytes, proof witnesses, credential/nullifier
seeds, wallet private keys, or unbounded remote payloads.

## Compatibility, migration, threat model, and rollback

This matrix does **not** change the Harpocrates protocol, metadata format,
proof public inputs, contract interface, stored evidence, or cryptographic
domain. No data migration is required. Pinning the build target simply makes
the frontend's existing Vite 8 compatibility floor explicit so dependency
upgrades cannot silently move it.

The threat model is unchanged: private proof inputs stay client-side, and lack
of a browser capability is not permission to move those inputs across a trust
boundary. A future proposal to lower a minimum version must verify the required
capabilities and Noir/Barretenberg behavior on that browser before changing the
matrix.

Rollback is documentation/build-policy only: revert `browser-support.mjs`, the
`vite.config.ts` target reference, and this document together. Do not roll back
by adding insecure polyfills for Web Crypto, proof workers, or wallet signing.

## Reproducible check

From `frontend/`:

```bash
npm ci
npm run check:browser-support
npm test
npm run build
```

`check:browser-support` verifies that the documented matrix, canonical build
targets, required capability list, and Vite build configuration cannot drift
independently. It is safe to run in CI because it performs no network or browser
automation and uses no credentials.
