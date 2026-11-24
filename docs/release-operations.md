# Compatibility releases

Harpocrates publishes a release bundle, never an independently promoted
frontend, backend, circuit, verifier, or registry. The source of truth is
[`release/compatibility-manifest.json`](../release/compatibility-manifest.json).
It contains public identities and SHA-256 digests only; do not place media,
witnesses, credentials, proofs, signatures, transaction XDR, or deployment
secrets in it.

## Local verification

Run the release gate and its adversarial tests from the repository root:

```bash
python3 devx/release_guard.py
python3 -m unittest discover -s devx -p 'test_*.py' -v
```

The gate rejects unknown fields, malformed versions, mismatched circuit and
verifier proof systems, unbound network/interface versions, duplicate or
escaping artifact paths, modified artifacts, and attempts to publish a
non-active rollout. The workflow also runs each component's existing test and
build path. A digest mismatch is deliberate: rebuild and review all dependent
artifacts, then update one manifest in the same reviewed change.

For an `active` release, `release/verifier-binding.json` must also identify the
single verifier `.vk` artifact and repeat its SHA-256 digest in
`verification_key_sha256`.
The release gate rejects a missing, misnamed, or mismatched verifier-key
binding before publication.


## Cross-layer compatibility report

Operators and CI can publish a privacy-safe compatibility report derived from
the same canonical manifest:

```bash
python3 devx/compatibility_report.py --write --stable --check
python3 -m unittest discover -s devx -p 'test_compatibility_report.py' -v
```

The report lands at [`release/compatibility-report.json`](../release/compatibility-report.json).
It records per-layer version and interface checks plus cross-layer proof-system,
crypto-domain, metadata, and digest outcomes. Digest drift is reported as
`version_compatible_digest_drift` so version alignment remains visible while
artifact pins are refreshed. Use `--strict` when digests must match exactly.
The report never includes media, witnesses, credentials, proofs, or secrets.

## Cross-layer protocol compatibility

[`release/protocol-compatibility.json`](../release/protocol-compatibility.json)
binds the API, CLI, circuit, and contract schema versions to the release
baseline in `release/compatibility-manifest.json`. Each layer records the
identity that matters to its consumers:

| Layer | Recorded identity |
| :--- | :--- |
| `api` | Backend `api_version` and the SHA-256 of the generated OpenAPI schema |
| `cli` | CLI package version and the proof-manifest version it emits |
| `circuit` | Circuit version, input-schema version, and input-schema digest |
| `contract` | Registry interface version, compatibility-descriptor version, accepted verifier-input versions, and the circuit version the verifier expects |

```bash
python3 devx/protocol_compatibility.py --check
python3 -m unittest discover -s devx -p 'test_protocol_compatibility.py' -v
```

The check recomputes every layer from the checked-out tree and fails when a
recorded value drifts, when the baseline no longer matches the release manifest,
or when the layers disagree with each other (for example a circuit version
outside the contract's accepted window). It is offline and reads no
credentials, witnesses, proofs, or production endpoints, so a mixed-layer
combination is rejected before packaging or deployment. Regenerate the manifest
only as part of a reviewed baseline change:

```bash
python3 devx/protocol_compatibility.py --write
```

## Portable source paths

Portable releases must check out identically on case-insensitive filesystems
(macOS APFS/HFS+, Windows NTFS). The case-collision gate reads the git index and
reports every group of tracked paths that would collide after Unicode NFC
normalization and case folding:

```bash
python3 devx/check_case_collisions.py
python3 -m unittest discover -s devx -p 'test_check_case_collisions.py' -v
```

Output is deterministic on every host: groups are ordered by normalized key and
each group's paths are sorted. The command exits `1` when a collision exists, so
the release gate stops before packaging. Use `--paths-from` with a
NUL/newline-delimited file to check a synthetic list without a git checkout.

## Synthetic media fixtures

Generate synthetic video locally for API, interoperability, or packaging
workflows without supplying real media:

```bash
python3 devx/generate_synthetic_media.py --output /tmp/harpocrates-synthetic.mp4 --seed 17
```

The generator uses FFmpeg's synthetic `testsrc2` source, fixed metadata, and a
seeded noise filter. It accepts no media input, limits dimensions to 1280x1280,
duration to 10 seconds, and output to 64 MiB, and does not overwrite an existing
file unless `--force` is specified. Failures report stable categories without
printing FFmpeg output or media contents. The output is byte-reproducible for
identical arguments with the same pinned FFmpeg and encoder build; changing
that build can change encoded bytes. No canonical metadata, proof, or stored
evidence format is created or changed. Rolling back only requires removing the
DevX generator and its focused coverage; there is no migration or deployment
state to repair.

## C2PA Interoperability & Bounded Parser

External C2PA manifests entering Harpocrates boundaries are parsed using the bounded parser (`devx/c2pa_parser.py` and `devx/validate_c2pa_manifests.py`).

### Parser Bounds & Limits
* Maximum input payload: 256 KiB (`MAX_C2PA_PAYLOAD_BYTES = 256 * 1024`).
* Maximum nesting depth: 8 levels (`MAX_MANIFEST_DEPTH = 8`).
* Maximum assertions array length: 32 (`MAX_ASSERTIONS_COUNT = 32`).
* Maximum ingredients array length: 16 (`MAX_INGREDIENTS_COUNT = 16`).
* Maximum field string length: 256 chars (`MAX_FIELD_LENGTH = 256`).

### Input Classification & Failure Behaviors
* `valid`: Valid JSON and C2PA structure; extracted Harpocrates metadata (if present) is mapped to canonical metadata representation.
* `malformed`: JSON syntax error, invalid types, or invalid data structures (`ERR_MALFORMED`).
* `oversized`: Input exceeds size, depth, or collection bounds (`ERR_OVERSIZED`).
* `unsupported`: Unsupported spec version (`ERR_UNSUPPORTED_VERSION`).
* `expired`: Expired claim or certificate (`ERR_EXPIRED`).
* `revoked`: Revoked assertion status (`ERR_REVOKED`).
* `dependency_failure`: Parser or library execution failure (`ERR_DEPENDENCY_FAILURE`).

### Privacy & Trust Boundaries
* Imported C2PA manifests are untrusted external input and do NOT constitute verified Harpocrates proofs on their own.
* Sensitive fields (passwords, secrets, private keys, witness values, nullifiers, credentials, proof bytes, tokens) are strictly redacted to `[REDACTED]`.
* Raw media, private keys, witness values, or credentials are never logged or returned in error messages.
* No DB schema or protocol migration is required for C2PA manifest imports.

## Release state machine

`candidate -> staged -> active` is the forward path. `candidate` is valid for
local and CI verification but cannot be published. `staged` requires a durable
approval reference and a bounded `max_stage_percent`; production promotion
must first pass the conformance suite and health checks. `active` additionally
requires the deployment controller to run `python3 devx/release_guard.py
--require-active` against the exact checked-out bundle. `rollback` requires
`previous_release`, deploys that previously verified immutable bundle, and
never mutates its artifacts.

State transitions are idempotent by `release_id`: a controller records the
release ID, manifest SHA-256, target network, transition, and timestamp in its
durable deployment store with a unique `(network, release_id, transition)`
key. Concurrent requests must use a transaction/compare-and-set and return
the already-recorded transition. Timeouts or cancellation leave a transition
pending; reconciliation re-verifies the bundle and deployment before retrying.
No single process or in-memory lock is authoritative.

## Deployment and rollback constraints

The manifest network must equal the deployment target. Promote backend and
frontend only after the registry/verifier addresses and their built WASM/VK
digests are recorded by the deployment controller. Route a stage only to
instances reporting the exact public release ID and network. If any component
reports another tuple, stop traffic expansion and rollback to
`previous_release`; do not repair records by editing a released manifest.

The current repository tracks source and browser-verifier artifact hashes.
Production deployment must extend the manifest with the built registry WASM
and verifier VK/WASM hashes before activation. That prevents a compiler or
packaging change from silently reusing a source-only approval.

## Signals and troubleshooting

Emit only bounded, public fields: `release_id`, manifest digest, component
name, target network, state transition, result code, duration bucket, and
saturation bucket. Never log request bodies, metadata, media hashes if they
are sensitive in context, witnesses, proof bytes, credential roots, secrets,
signatures, or transaction payloads. Alert on digest mismatch, network
mismatch, failed readiness, repeated reconciliation, and rollout saturation.

If the gate says `digest mismatch`, restore the intended artifact or update
the digest only as part of a full compatible bundle. If it says `not active`,
the deployment controller must complete staging and record an approval; do not
bypass `--require-active`. If a frontend reaches a different backend release,
remove it from routing and redeploy the verified bundle rather than attempting
cross-version retries.

## Deprecation policy

V1 metadata, public inputs, API, and contract interface stay supported for at
least one active release train and one rollback window. Breaking changes need a
new protocol/cryptographic domain and a versioned migration in the manifest,
deterministic vectors shared by circuit/backend/frontend/contract, a parallel
read path, and an announced removal date. A release may not remove old readers
until every supported active and rollback bundle is outside that window.

## Software Bill of Materials (SBOM)

Every GitHub Release automatically triggers the `sbom-provenance.yml` workflow,
which runs in parallel with the Docker image build workflow.

### What is generated

| Artifact | Tool | Format |
| --- | --- | --- |
| `backend-sbom.cdx.json` | syft | CycloneDX JSON |
| `frontend-sbom.cdx.json` | syft | CycloneDX JSON |
| `contracts-sbom.cdx.json` | syft | CycloneDX JSON |
| `zk-sbom.cdx.json` | syft | CycloneDX JSON |
| `harpocrates-sbom.cdx.json` | syft | CycloneDX JSON (aggregate) |
| `*.cdx.json.sig` / `*.cdx.json.cert` | cosign | keyless Sigstore signatures |
| `harpocrates.intoto.jsonl` | slsa-github-generator | SLSA level-3 provenance |
| Docker image attestations | actions/attest-build-provenance | OCI image attestation |

All artifacts are attached to the GitHub Release and are also available as
workflow run artifacts for 90 days.

### Privacy constraints

SBOMs describe the *dependency graph* of each workspace. They must never
contain evidence payloads, media hashes in sensitive context, witness values,
credential roots, proof bytes, signing keys, or deployment secrets. The
`compatibility-manifest.json` is the authoritative source of public release
identity; do not duplicate or embed it inside an SBOM.

### Verifying a release SBOM locally

```bash
# Install cosign (https://docs.sigstore.dev/cosign/installation)
cosign version

# Verify a specific SBOM against its detached signature and certificate
cosign verify-blob \
  --certificate harpocrates-sbom.cdx.json.cert \
  --signature   harpocrates-sbom.cdx.json.sig  \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '.*' \
  harpocrates-sbom.cdx.json

# Inspect the SBOM
cat harpocrates-sbom.cdx.json | python3 -m json.tool | head -60
```

### Verifying Docker image provenance

```bash
# Replace <tag> with the release version, e.g. 1.0.0
gh attestation verify \
  oci://ghcr.io/<owner>/harpocrates-backend:<tag> \
  --repo <owner>/harpocrates
```

### Manual trigger (dry run)

To generate SBOMs for a branch without publishing a release:

```bash
gh workflow run sbom-provenance.yml \
  --field ref=main \
  --field upload_artifacts=true
```

### Rollback notes

If an SBOM artifact is found to contain incorrect or sensitive content after
publication, do not silently delete it from the release. Instead:
1. Remove the affected file from the GitHub Release.
2. Regenerate the corrected SBOM from the same tag using the manual trigger.
3. Re-attach and note the correction in the release changelog.

Do not invalidate or overwrite the `compatibility-manifest.json` as part of
an SBOM correction; those are independent artifacts with separate digests.
