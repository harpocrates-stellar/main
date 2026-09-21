# C2PA authenticity assertion export

`devx/c2pa_export.py` converts a public Harpocrates proof manifest (the JSON
emitted by `harpocrates manifest`, see `cli/src/manifest.ts`) into a
deterministic, [C2PA](https://c2pa.org/) (Content Credentials) shaped manifest
whose **assertions** describe the evidence's authenticity.

This is interop/release tooling. It is not a signer and it is not a prover.

## Scope and trust boundary

- **Input**: a public proof manifest plus a public verification status. These
  are the same values already exposed by the CLI and the release gate.
- **Output**: a JSON C2PA manifest containing `c2pa.actions` and
  `org.harpocrates.*` assertions.
- **Not in the boundary**: media bytes, witnesses, nullifiers, per-session
  device keys, credentials, API keys, and private keys. The exporter never
  reads media and never touches a signing key.
- **No second protocol truth**: the exporter reuses the existing v1
  `harpocrates` manifest field set and only restates it. It does not mint a
  new proof, hash, or on-chain record.

`signature` is always `null`. Attaching a C2PA claim signature requires a
private key and therefore happens outside this repository.

## Usage

Export assertions:

```bash
python3 devx/c2pa_export.py \
  --manifest devx/fixtures/proof-manifest.sample.json \
  --result valid \
  --media-type video/mp4 \
  --title "Sample evidence" \
  --output /tmp/c2pa-export.json
```

Re-validate an existing export (assertion tamper detection):

```bash
python3 devx/c2pa_export.py --manifest /tmp/c2pa-export.json --verify
```

The output is canonical JSON (sorted keys, compact, ASCII only), so identical
inputs always produce byte-identical output. A committed golden fixture lives
at `devx/fixtures/c2pa-export.sample.v1.json` and is asserted by the test
suite.

## Assertions

| Label | Meaning |
| :--- | :--- |
| `c2pa.actions` | Standard action assertion. A `valid` export emits `c2pa.created` with the IPTC `digitalCapture` source type; `pending` omits the source type. |
| `org.harpocrates.evidence-binding` | SHA-256 bindings for `proofId`, `sourceHash`, `metadataHash`, and `videoHash` (hashes only). |
| `org.harpocrates.verification` | Public chain identity: `status`, `authenticity`, protocol/version, tier, network, contract ID, transaction reference, timestamp. |

`assertions_digest` is the canonical SHA-256 of the assertion array and lets
consumers detect post-export tampering without a signature.

## Failure behaviour

All failures are fail-closed, stable, and privacy-safe: callers receive an
error `code` and a fixed description. Input values are never echoed.

| Code | Trigger |
| :--- | :--- |
| `malformed` | Non-object input, missing/typed-wrong fields, bad 32-byte hex, non-ISO-8601 timestamp, non-string title, over-deep nesting, non-JSON input, tampered export. |
| `oversized` | Input or export exceeds 256 KiB, or the title exceeds 256 characters. |
| `unsupported` | Wrong protocol, version other than 1, unknown tier, unsupported media type, unknown verification status, or a prohibited sensitive field anywhere in the input. |
| `expired` | Verification status is `expired`; no authenticity assertion is emitted. |
| `revoked` | Verification status is `revoked`; no authenticity assertion is emitted. |
| `dependency_failure` | Verification status is `not_found`, `failed`, `error`, `network_mismatch`, or `contract_mismatch`. |

Any field name matching secret material (`seed`, `secret`, `private`,
`witness`, `nullifier`, `credential`, `password`, `passphrase`, `api_key`,
`mnemonic`, `device_key`, `signing_key`) is rejected with `unsupported` at any
depth. This is a hard leak stop: a proof package that mistakenly carries
secret material cannot be exported.

## Privacy guarantees

- Only public hashes, public chain identifiers, and public timestamps are
  emitted.
- No device identifiers, witness values, or raw evidence are included.
- Error output contains codes and fixed text only.
- The exporter is offline and performs no network calls.

## Compatibility and migration

- Input format: Harpocrates proof manifest `version: 1`. A manifest with any
  other version fails with `unsupported` instead of being silently coerced.
- Output format: `profile: harpocrates-c2pa-export/v1`, `export_version: 1`.
  Any consumer must gate on both before reading assertions.
- `org.harpocrates.*` labels are namespaced so they can never shadow a future
  standard `c2pa.*` label.
- Adding new optional assertion fields is additive; removing or renaming an
  assertion requires a new `export_version` and a migration note here.
- Existing metadata, proof, contract, and release interfaces are unchanged.

## Rollback

The feature is pure tooling with no stored state, migrations, or on-chain
writes:

1. Revert the commit that added `devx/c2pa_export.py` and its fixture.
2. Delete any exported JSON produced by the tool; it is not referenced by the
   backend, contracts, or release manifest.
3. No database, artifact, or contract state repair is required.

## Threat model notes

- **Tampering after export**: detected via `assertions_digest`; authenticity
  against a real key still requires an out-of-band C2PA signature.
- **Downgrade**: `expired`/`revoked` evidence never produces a positive
  assertion, so a stale verifier cannot be tricked into advertising revoked
  media as authentic.
- **Amplification**: size, title, depth, and media-type bounds are enforced
  before any output is produced.
- **Leakage**: the sensitive-field scan fails closed before values are read.

## Tests

```bash
python3 -m unittest discover -s devx -p 'test_*.py' -v
```

The suite covers positive, negative, boundary, privacy, tamper-detection,
deterministic-fixture, and CLI round-trip cases. The release-gate workflow
runs it automatically alongside `devx/release_guard.py`.

## Out of scope

- Signing C2PA claims (requires a private key).
- Reading, hashing, or embedding real media.
- Emitting CBOR or JPEG/PNG-embedded manifest stores. The JSON manifest is the
  interchange form that a C2PA writer would consume.
