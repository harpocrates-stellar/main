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

`status` simulates `get_proof_status(proof_id)` against the registry and maps the result to a stable status string (`registered`, `revoked`, `expired`, or `unknown`) and exit code (0` for `registered`, 1` for `expired`, 2` for `revoked`, 3` for `unknown`). Malformed or missing `--proof-id` values exit `2` immediately without making an RPC call.

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
sign the result with your own C2PA signer. Missing `--manifest` or an `--output` path that resolves to the same file as an input path (including symlink aliases) exits 2 without modifying the input file; malformed, unsupported, or unreadable input exits 8. The export is
deterministic, so the same manifest and receipt always produce the same bytes
(reproducible in CI via `devx/validate_c2pa_fixture.py`).

For reproducible, network-free manifest and status fixtures, run from `cli/`:

```sh
npm test -- --run test/manifest.test.ts test/normalize.test.ts test/status.test.ts
```

## Reproducible CLI transcript fixtures

For independent implementations, the cli ships synthetic CLI transcript
fixtures under `cli/test/fixtures/transcripts/`. Each fixture is a single
JSON document that records the argv invocation, the stdin input, the expected
stdout/stderr and the exit status. They are purely synthetic: they use
fake transports and temporary state directories, never contact a production
endpoint, and never contain private media, witnesses, seeds, credentials or
signing keys. The schema is documented in
`cli/test/fixtures/transcripts/README.md` and the format is stable for
external consumers.

Run the transcript fixture suite (network-free):

```sh
npm test -- --run test/transcripts.test.ts
```

The suite replays every fixture through the built CLI and asserts the
exact stdout, stderr and exit status. A regression in any of those is a
failure, so independent implementations can use the same fixtures as a
conformance corpus.

### Exit codes

Script authors and CI integrations can rely on the following exit codes to determine the outcome of a command.

| Code | Meaning | Emitted by |
| :--- | :--- | :--- |
| `0` | `valid` / `registered` / success | `verify`, `status`, `verify-receipt`, `verify-lineage` |
| `1` | `expired` | `verify`, `status`, `verify-lineage` |
| `2` | `revoked` / usage error (missing required flag) | `verify`, `status`, `verify-lineage`, `manifest`, `hash`, `c2pa` |
| `3` | `not_found` / `missing` / `unknown` | `verify`, `status`, `verify-lineage` |
| `4` | `network_mismatch` | `verify` |
| `5` | `contract_mismatch` | `verify` |
| `6` | `incomplete` / `pending` (offline verification, skipped required checks, or bounded lineage traversal) | `verify`, `verify-lineage`, batch verification |
| `7` | `invalid` / `failed` (failed transaction, invalid signed receipt, disputed ancestor, or lineage cycle) | `verify`, `verify-receipt`, `verify-lineage`, batch verification |
| `8` | `error` (malformed input, unreadable file, internal error) | `verify`, `status`, `verify-receipt`, `manifest`, `hash`, `c2pa`, `verify-lineage` |
| `9` | `unavailable` (RPC timeout, unreachable network, or verification dependency failure) | `verify`, `status`, `verify-lineage`, batch verification |

An offline verification exits `6` (`incomplete` / `pending`): it checks syntax and deployment binding but **cannot** establish on-chain validity. Skipped required checks (including empty batch runs or lineage graphs truncated by depth/fan-out bounds) never exit `0`. Do not treat a nonzero exit or an offline receipt as verified evidence. `--tx-hash`, when supplied, must match the manifest. An RPC request timeout (`--timeout`) or unreachable dependency exits `9` (`unavailable`), distinct from invalid verification (`7`) and malformed input (`8`).

Harpocrates CLI environment variables:

- `HARPOCRATES_RPC_URL` -- default for `--rpc-url` in `verify`, `status`, and `manifest`.
- `HARPOCRATES_CONTRACT_ID` -- default for `--contract-id` in `verify`, `status`, and `manifest`.
- `HARPOCRATES_SOURCE_ADDRESS` -- default for `--source-address` in `verify` and `status`.

Explicit flags always take precedence over environment values. Contract-id
validation still applies to environment values.

The CLI accepts at most 1 MiB of manifest/metadata JSON. It rejects unknown
manifest fields and unsupported versions, and writes fixed, privacy-safe
error messages rather than raw RPC or file errors. Standard input manifest
reads (`--manifest -`) stream input bounded by this 1 MiB limit, destroying
the stream and aborting before JSON parsing if the bound is exceeded. Callers
expecting JSON output (`--output json`) receive clean standard output on error,
with failure messages routed exclusively to standard error. Do not pass private
witnesses, seeds, credentials, media, or secrets in a manifest. The receipt
contains only public manifest and registry fields, but hashes and addresses
can still be sensitive in context; restrict receipt access accordingly.

Manifest v2 adds `verifierScope` and `epoch`, matching the frontend. V1 input
remains readable, without silently upgrading its version.

Extensions marked as required
(`required: true`) with semantics this CLI does not support are rejected with
exit code `8` (`error`) rather than silently dropped, so verification fails
closed. Missing or supported optional extensions behave as before. Existing v1 receipt
shape and exit-code mapping remain unchanged. For rollback, deploy the prior
CLI build; no chain, metadata, or registry migration is required. The trust
boundary is the selected Stellar RPC and local clock (used to detect elapsed
record expiry); use a trusted RPC and synchronized host clock. The CLI
does not verify Noir proof bytes or replace the browser verifier.

## Single-file bundle

For air-gapped or audit use there's also a self-contained build. From `cli/`,
run `npm ci && npm run bundle`. That writes `dist/harpocrates.mmj` (all runtime
deps, including `@stellar/stellar-sdk`, inlined, with a `#!/usr/bin/env node`
shebang) and `dist/harpocrates.mmj.sha256` in `sha256sum` format. Copy both
files anywhere and run:

```sh
sha256sum -c harpocrates.mmj.sha256
node harpocrates.mmj help
```

No `node_modules` is needed. `@azec/bb.js` is still loaded lazily and is not
bundled, so local proof verification needs it installed next to the bundle.
`npm run test:bundle` copies the bundle into an empty temp dir and runs `help` as a smoke test. CI uploads both files as the `harpocrates-cli-bundle`
artifact. `npm run build` (tsc) output is unaffected.
