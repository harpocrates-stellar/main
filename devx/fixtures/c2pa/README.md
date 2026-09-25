# C2PA authenticity assertion fixtures

Synthetic fixtures for offline CI validation of the C2PA authenticity
assertion exporter (`cli/src/c2pa.ts`, invoked as `harpocrates c2pa`).
Everything here is generated values — there are no real media files, no
credentials, no witness values, and no private keys.

- `manifest.json` — canonical Harpocrates proof manifest (v2), public
  synthetic fields only.
- `receipt.json` — verification receipt matching `manifest.json`
  (`result: valid`), again public synthetic fields only.
- `expected-export.json` — the deterministic C2PA manifest-definition export
  produced from the two inputs above by `devx/validate_c2pa_fixture.py`.

## Regenerate

```bash
cd cli && npm ci && npm run build
python3 devx/validate_c2pa_fixture.py --write
```

CI (`cli-ci.yml`) rebuilds the CLI, regenerates the fixture, and fails if the
output drifts from the committed `expected-export.json`.

## What the export contains

The export is an unsigned C2PA JSON manifest definition carrying standard
assertions:

- `c2pa.actions.v2` — `harpocrates.registered` action bound to the canonical
  manifest timestamp, tier, network, contract, transaction, and proof ID.
- `c2pa.hash.data` — SHA-256 content binding for the registered video hash.
- `harpocrates.registry.v1` — the canonical public registry/manifest fields
  plus a `manifestHash` that pins the exact serialised proof manifest
  (single protocol truth; no second metadata schema).
- `harpocrates.verification.v1` — the verification outcome verbatim when a
  receipt is supplied (including expired/revoked/pending states; a false
  `valid` status is never fabricated).
- `harpocrates.export.v1` — exporter identity, schema version, `unsigned: true`.

It never contains media bytes, witness values, credential secrets, proofs,
transaction blobs, or signing keys. Sign it with your own C2PA tooling and
key material.

## Schema

- `assertions[].label` — C2PA or `harpocrates.*` assertion label
- `assertions[].data` — public assertion payload
- `claim_generator` — `harpocrates-cli/c2pa`
- `format` — `application/json`