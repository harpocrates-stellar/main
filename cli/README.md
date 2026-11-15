# Headless verification CLI

From `cli/`, run `npm ci && npm run build`. The executable is `node dist/cli.js`.
It accepts the frontend's v2 proof manifest (and legacy v1), checks the
selected network and registry contract, looks up the manifest transaction and
video hash on Stellar RPC, and emits a machine-readable receipt with `--output
json`. It never needs a wallet or signing key. `--source-address` is optional:
when omitted, read-only Soroban simulation uses a local placeholder account
(sequence `0`) and needs no funded or existing account, so `verify` works
offline-friendly and in CI. When supplied, the explicit address is loaded from
RPC via `getAccount` as before.

```sh
node dist/cli.js --version
# or: node dist/cli.js version
```

```sh
node dist/cli.js verify --manifest proof.json \
  --contract-id C... --network 'Test SDF Network ; September 2015' \
  --source-address G... --output json
```

RPC lookups are bounded by a request timeout (default 15000 ms). Override it
with `--timeout <ms>`, which must be a positive integer:

```sh
node dist/cli.js verify --manifest proof.json \
  --contract-id C... --network 'Test DF Network ; September 2015' \
  --source-address G... --timeout 5000 --output json
```

To check the on-chain lifecycle status of a proof directly by its 32-byte proof ID:

```sh
node dist/cli.js status --proof-id <64-hex> \
  --contract-id C... --network 'Test SDF Network ; September 2015' \
  --rpc-url https://soroban-testnet.stellar.org --output json
```

`status` simulates `get_proof_status(proof_id)` against the registry and maps the result to a stable status string (`registered`, `revoked`, `expired`, or `unknown`) and exit code (`0` for `registered`, `1` for `expired`, `2` for `revoked`, `3` for `unknown`). Malformed or missing `--proof-id` values exit `2` immediately without making an RPC call.

To verify a signed verification receipt offline without hitting the RPC:

```sh
node dist/cli.js verify-receipt --receipt receipt.json --keys trusted_keys.json
```

To export C2PA authenticity assertions from a proof manifest (with an optional
verification receipt) for signing by your own C2PA tooling and key material:

```sh
node dist/cli.js c2pa --manifest proof.json [--receipt receipt.json] --output export.json
```

The export is an **unsigned** C2PA JSON manifest definition carrying standard
`c2pa.actions.v2` and `c2pa.hash.data` assertions plus namespaced
`hirpocrates.registry.v1` (canonical manifest fields bound by
`manifestHash`), `hirpocrates.verification.v1` (the receipt outcome verbatim,
only when `--receipt` is supplied, never a fabricated `valid`), and
`hirpocrates.export.v1` (`unsigned: true`). It contains only public manifest
and registry fields; it never carries media bytes, witness values, secrets,
proof bytes, or signing keys, and the exporter never signs. Out-of-band you
sign the result with your own C2PA signer. Missing `--manifest` exits 2;
malformed, unsupported, or unreadable input exits 8. The export is
deterministic, so the same manifest and receipt always produce the same bytes
(reproducible in CI via `devx/validate_c2pa_fixture.py`).

For reproducible, network-free manifest and status fixtures, run from `cli/`:

```sh
npm test -- --run test/manifest.test.ts test/normalize.test.ts test/status.test.ts
```

### Exit codes

Script authors and CI integrations can rely on the following exit codes to determine the outcome of a command.

| Code | Meaning | Emitted by |
| :--- | :--- | :--- |
| `0` | `valid` / `registered` / success (all required checks passed) | `verify` (single & `--batch`), `status`, `verify-receipt`, `verify-lineage` |
| `1` | `expired` | `verify` (single & `--batch`), `status`, `verify-lineage` |
| `2` | `revoked` / usage error (missing required flag) | `verify` (single & `--batch`), `status`, `verify-lineage`, `manifest`, `hash`, `c2pa` |
| `3` | `not_found` / `missing` / `unknown` | `verify` (single & `--batch`), `status`, `verify-lineage` |
| `4` | `network_mismatch` | `verify` (single & `--batch`) |
| `5` | `contract_mismatch` | `verify` (single & `--batch`) |
| `6` | `incomplete` / `pending` (skipped required checks such as `--offline`, empty batch, or unconfirmed tx) | `verify` (single & `--batch`) |
| `7` | `failed` transaction | `verify` (single & `--batch`) |
| `8` | `invalid` / `error` (malformed input, invalid receipt signature, statement/chain hash mismatch, cycle/disputed lineage) | `verify` (single & `--batch`), `status`, `verify-receipt`, `manifest`, `hash`, `c2pa`, `verify-lineage` |
| `9` | `unavailable` (RPC timeout or unreachable verification dependency) | `verify` (single & `--batch`), `status`, `verify-lineage` |

An offline verification (`--offline`) skips required on-chain verification checks and therefore exits `6` (`incomplete` / `pending`), **never** `0`: it checks local syntax and deployment binding only and cannot establish on-chain validity. Do not treat a nonzero exit or an offline receipt as verified evidence. `--tx-hash`, when supplied, must match the manifest. Invalid cryptographic or schema inputs exit `8` (`invalid`), while RPC request timeouts (`--timeout`) and unreachable verification endpoints exit `9` (`unavailable`). Batch verification (`verify --batch <manifest-list.json>`) applies the exact same exit-code table and exits `0` only when every item passes all required checks (empty batches exit `6`).

Harpocrates CLI environment variables:

- `HARPOCRATES_RPC_URL` -- default for `--rpc-url` in `verify`, `status`, and `manifest`.
- `HARPOCRATES_CONTRACT_ID` -- default for `--contract-id` in `verify`, `status`, and `manifest`.
- `HARPOCRATES_SOURCE_ADDRESS` -- default for `--source-address` in `verify` and `status`.

Explicit flags always take precedence over environment values. Contract-id
validation still applies to environment values.

The CLI accepts at most 1 MiB of manifest/metadata JSON. It rejects unknown
manifest fields and unsupported versions, and writes fixed, privacy-safe
error messages rather than raw RPC or file errors. Do not pass private
witnesses, seeds, credentials, media, or secrets in a manifest. The receipt
contains only public manifest and registry fields, but hashes and addresses
can still be sensitive in context; restrict receipt access accordingly.

Manifest v2 adds `verifierScope` and `epoch`, matching the frontend. V1 input
remains readable, without silently upgrading its version. Existing v1 receipt
shape and exit-code mapping remain unchanged. For rollback, deploy the prior
CLI build; no chain, metadata, or registry migration is required. The trust
boundary is the selected Stellar RPC and local clock (used to detect elapsed
record expiry); use a trusted RPC and synchronized host clock. The CLI
does not verify Noir proof bytes or replace the browser verifier.

## Single-file bundle

For air-gapped or audit use there's also a self-contained build. From `cli/`,
run `npm ci && npm run bundle`. That writes `dist/harpocrates.mjs` (all runtime
deps, including `@stellar/stellar-sdk`, inlined, with a `#!/usr/bin/env node`
shebang) and `dist/harpocrates.mjs.sha256` in `sha256sum` format. Copy both
files anywhere and run:

```sh
sha256sum -c harpocrates.mjs.sha256
node harpocrates.mjs help
```

No `node_modules` is needed. `@aztec/bb.js` is still loaded lazily and is not
bundled, so local proof verification needs it installed next to the bundle.
`npm run test:bundle` copies the bundle into an empty temp dir and runs `help`
as a smoke test. CI uploads both files as the `harpocrates-cli-bundle`
artifact. `npm run build` (tsc) output is unaffected.
