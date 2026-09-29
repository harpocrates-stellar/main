# Harpocrates black-box conformance suite

Implementation-neutral fixtures plus a runner that checks Harpocrates protocol
behaviour **at public boundaries only**: bytes/JSON in, a stable machine code or
a byte-exact output out. Any implementation — TypeScript, Python, Rust, Go, a
deployed backend behind an HTTP shim — can be tested by writing a small
*adapter*. Nothing here imports repository code.

```
conformance/
  fixtures/v1/*.json      versioned, append-only, synthetic-only fixtures (one file per area)
  manifest.json           hash lock: SHA-256 of every fixture file and every case, + pinned external corpora
  reason-codes.json       every stable failure code and what it means
  runner/hpx_conformance.py   the runner (Python 3.9+, standard library only)
  adapters/reference_py/  strict reference adapter (stdlib only) - passes 100% incl. advisory
  adapters/ts/            drives the shipped cli/ and frontend/ TypeScript (repo-bound)
  adapters/skeleton/      ~40-line starting point for a new language
  tools/gen_fixtures.py   generator + drift/lock enforcement (needs `cryptography`, generator only)
  tools/bundle.py         byte-reproducible third-party bundle
  tests/test_suite.py     tests of the suite itself
```

## Quick start

```bash
# 1. Is the checked-in suite intact?
python conformance/runner/hpx_conformance.py check-lock
python conformance/runner/hpx_conformance.py lint

# 2. Run an implementation (any executable that speaks the adapter protocol)
python conformance/runner/hpx_conformance.py run \
  --adapter "python conformance/adapters/reference_py/adapter.py" --report out/ref.json

# Shipped TypeScript (after `npm ci` in cli/ and frontend/, and `npm i` in conformance/adapters/ts):
HPX_IMPL=cli      python conformance/runner/hpx_conformance.py run --allow-missing-ops \
  --adapter "npx --prefix conformance/adapters/ts tsx conformance/adapters/ts/adapter.ts" --report out/cli.json
HPX_IMPL=frontend ...same with HPX_IMPL=frontend...

# 3. Compatibility matrix from several reports
python conformance/runner/hpx_conformance.py matrix --reports out --out out/matrix.md

# 4. Suite self-tests
python -m unittest discover -s conformance/tests -v
```

Verdicts: `conformant` (every required case ran and passed) · `partial` (all implemented ops pass; some ops absent and
`--allow-missing-ops` given — exit 0, but the matrix shows exactly which areas were not exercised) · `incomplete` (ops absent
without the flag) · `non-conformant` · `aborted`.
Exit codes: `0` conformant/partial · `1` required case failed, or operations missing
without `--allow-missing-ops` · `2` harness/adapter error · `3` lock or lint failure.

A third party needs only the bundle (`python conformance/tools/bundle.py --out x.tgz`):
Python's standard library, the fixtures, and the two pinned `zk/vectors` corpora.

## Adapter protocol `hpx-conformance-adapter/1`

Line-delimited JSON on stdin/stdout. One request, one response, in order.

```
-> {"id":"hello","op":"hello","input":{}}
<- {"id":"hello","ok":true,"output":{"protocol":"hpx-conformance-adapter/1","ops":["hex32_normalize",...],
                                      "implementation":{"name":"acme","version":"1.2.3","language":"go"}}}
-> {"id":"se-hex32-neg-001-short#0","op":"hex32_normalize","input":{"value":"abcd"}}
<- {"id":"se-hex32-neg-001-short#0","ok":false,"code":"invalid_hex32"}
```

* `ok:true` → `output` must equal the case's `expect.output` **exactly** (canonical-JSON comparison).
* `ok:false` → `code` must equal `expect.code`; if the case has `expect.detail`, each listed key must match.
  `detail` may only ever carry a field **name** or a public network label — never input bytes.
* Ops you do not implement: answer `{"ok":false,"code":"unsupported_op"}`, or omit them from `hello.ops`.
  They are reported `not_implemented`; the run is `incomplete` unless `--allow-missing-ops`.
* Every request is sent twice (`--repeat 2`) and the answers must be identical (idempotence / determinism).
* Bounds enforced by the runner: 10 s per request (`--timeout`), 1 MiB per response line, at most 5 adapter restarts.
  A hung, crashing, malformed or id-mismatching adapter yields `error` for that case and never a pass.
* Adapter stderr is discarded by default.

### Operations

| Area (file) | Ops | Layer that can implement it |
|---|---|---|
| `canonical-json` | `canonicalize` | any (spec `hpx-cj/1` below) |
| `metadata-envelope` | `metadata_validate`, `metadata_hash`, `envelope_version_check`, `envelope_version_resolve`, `envelope_bind` | validate/hash: CLI/SDK, backend. envelope\_*: contract |
| `proof-manifest` | `manifest_create`, `manifest_parse` | CLI/SDK, frontend, backend |
| `receipt` | `receipt_verify`, `receipt_qr_encode`, `receipt_qr_decode` | CLI/SDK, frontend, backend |
| `stellar-encoding` | `hex32_normalize`, `hex_bytes_normalize`, `bytes_to_hex`, `strkey_decode`, `network_id`, `network_name`, `scval_bytes_xdr` | any |
| `network-guard` | `network_check` | frontend / wallet layer |
| `status-semantics` | `proof_status` | contract |
| `verification-result` | `verification_classify`, `result_exit_code` | CLI/SDK |
| `events` | `event_validate` | indexer / event decoder |
| `lineage` | `lineage_validate`, `lineage_manifest_create`, `lineage_manifest_parse` | contract / SDK |
| `error-abi` | `classify_error` | contract / SDK / backend |
| `public-inputs` *(existing corpus, by reference)* | `classify_public_inputs` | backend, frontend, contract |
| `malformed-hex` *(existing corpus, by reference)* | `decode_public_inputs_hex` | backend, frontend |

`zk/vectors/verifier_conformance_v1.json` and `malformed_public_inputs_v1.json` are **not copied**: the runner
reads them where they live and refuses to run if their SHA-256 differs from the pin in `manifest.json`.
There is one source of truth for the `hpx-vi/1` codec.

## Fixture format

```json
{ "format": "harpocrates.conformance", "suite_version": "1.0.0", "fixture_version": 1,
  "area": "network-guard", "synthetic": true,
  "cases": [ { "id": "ng-neg-010-mainnet-vs-testnet", "op": "network_check", "tier": "required",
               "description": "...", "input": {...},
               "expect": { "ok": false, "code": "network_mismatch", "detail": {"wallet_network":"Mainnet","contract_network":"Testnet"} } } ] }
```

Ids are `<area>-<pos|neg>-<nnn>-<slug>` and never change or get reused.

### Tiers: `required` vs `advisory`

* **required** — pins behaviour that is *deployed today* (or specified in `contracts/*.md` / `ERROR_ABI.md`). Gating.
* **advisory** — never gates; each carries `advisory_reason`:
  * `known_defect`: shipped code disagrees with the spec'd/expected result (each is a filed-worthy bug, see Findings).
  * `proposed_hardening`: a stricter rule that removes a real cross-language ambiguity (e.g. reject duplicate keys, reject floats).

  Advisory results still appear in the report and the matrix, so a defect fix or a hardening rollout flips a
  visible cell from `adv 0/4` to `adv 4/4`. **Promoting a case to `required` changes its tier and therefore its
  digest: it needs a suite version bump.**

### Canonical JSON `hpx-cj/1`

UTF-8; no insignificant whitespace; object keys sorted **recursively by UTF-16 code-unit order**; arrays keep order;
strings escaped as `JSON.stringify` does (`\" \\ \b \f \n \r \t`, other controls as lowercase `\u00xx`, everything else —
including U+2028/9 and all non-ASCII — literal); integers only, `|n| <= 2^53-1`. This is the recursive `canonicalize()` that
signed receipts already use. The *hash* of a metadata object or manifest is SHA-256 of that text.

## What the suite detects (verified by `tests/test_suite.py`)

Ten seeded cross-language bugs are each caught, by the expected case ids: code-point vs UTF-16 key order,
`ensure_ascii`, regex `$` accepting a trailing newline, string length in code points vs UTF-16 units, expiry compared as floats,
Python `strip()` vs JS `trim()`, expiry-before-revocation ordering, receipt size in characters vs bytes, u64 as a JSON number,
and a skipped privacy scan. The fixtures also pin **check order** (two layers that reject the same input for different
reasons are a divergence — operators branch on the code).

## Findings from the first run against the shipped code

`cli/` and `frontend/` are CONFORMANT on every required case they implement (277 and 239). The advisory tier records
real defects found while building the suite (none is exploitable on its own; each is a divergence risk):

| Case(s) | Defect | Where |
|---|---|---|
| `me-hash-010/011` | `canonicalMetadataHash` uses `JSON.stringify(m, Object.keys(m).sort())`: an array replacer also filters **nested** keys, so `extensions: {…}` hashes as `{}`. A backend that canonicalizes properly computes a different hash. | `cli/src/metadata.ts`, `cli/src/hashing.ts` |
| `pm-create-010`, `pm-pos-007/008` | Same replacer bug in `serializeManifest`: `selectiveDisclosure` serializes as `{}`. | `cli/src/manifest.ts`, `frontend/src/proofManifest.ts` |
| `se-b2h-adv-001/002` | `bytesToHex([256])` → `"100"`, `[-1]` → `"-1"` instead of rejecting. | `cli/src/hashing.ts`, `frontend/src/stellarEncoding.ts` |
| `ss-012/013` | Contract `get_proof_status` treats an unknown stored status as `Valid`, while the CLI classifier says `error` (unreachable today via entry points, but the layers disagree; fail-closed is the safer reading). | `contracts/.../lib.rs` |
| `me-neg-060..063`, `pm-neg-072/089/107`, `rc-adv-*` | Timestamps accept any `Date.parse`-able string (`"2026"`), versions/ledgers are unbounded, scope ≥ BN254 modulus, odd-length hex accepted. | `cli/src/*`, `frontend/src/verificationReceipt.ts` |

I did **not** change any shipped code: the issue is a test/publication task, and fixing these changes hashes of
already-issued manifests (see *Compatibility* below), which needs the migration analysis the issue requires.

## Trust and privacy boundaries

* **Fixtures are synthetic.** Every digest is `sha256("hpx-conformance/v1/" + label)`; strkeys are derived the same way;
  receipt signing keys are derived from public labels, signatures use RFC 6979 (deterministic), and **only public JWKs are
  written**. `lint` fails on secret-shaped values (Stellar secret seeds, PEM private keys, JWK `d`, cloud/API tokens) and
  on forbidden field names (`nullifier`, `witness`, `private_key`, …) anywhere outside the `events` privacy cases.
* **Reports carry no adapter output.** Only case ids, stable codes and SHA-256 prefixes of outputs. Adapter stderr is
  discarded. Pointing the runner at a *deployed* harness therefore cannot copy secrets into CI artifacts. (Tested.)
* **The runner trusts nothing from the adapter**: bounded time, bounded line size, id and shape checked, restarts capped.
* **The suite is not a security proof.** It pins structural and behavioural agreement. It does not prove that all layers
  accept the same *proofs* (that needs real proving artifacts: `docs/zk-reproducible-builds.md`), and a passing
  implementation can still be wrong on inputs the fixtures do not contain.

### Threat model (this change adds no cryptographic primitive)

| Threat | Mitigation |
|---|---|
| Corpus weakened by hand or by a "helpful" regeneration → every layer's assertions weaken silently | append-only lock (`manifest.json`), CI drift check, external corpora pinned by SHA-256, refuse-to-run on mismatch |
| Fixture leaks real evidence | synthetic derivation + `lint` + no raw outputs in reports |
| Malicious/buggy adapter hangs or floods the CI runner | timeouts, 1 MiB line cap, restart cap |
| A flaky adapter "passes" by luck | every request repeated and required identical |
| Test keys mistaken for real keys | labelled `conformance-key-*`, public halves only, derivation is documented and never used outside fixtures |
| Signature-scheme confusion (DER vs P1363) | dedicated negative case `rc-neg-003` |

## Versioning and "no silent regeneration"

* `fixtures/v1/` is **append-only**. `gen_fixtures.py` regenerates in memory and **refuses** if any existing case id
  changed or disappeared, unless `SUITE_VERSION` is bumped *and* `--allow-breaking` is passed — a breaking edit is always
  a visible version change in review.
* CI runs `gen_fixtures.py --check` (fixtures equal a fresh regeneration), `check-lock`, and `lint`.
* A new incompatible layout goes in `fixtures/v2/` next to `v1/`; `v1` is never rewritten.
* The lock was created once, before publication; from the first release on it is the baseline.

## Compatibility, migration, rollback

* **No schema, contract, circuit, or artifact changes.** Purely additive: new `conformance/` tree, new CI workflow,
  a pointer in `docs/zk-conformance-vectors.md`. No existing lint, type check, test, build, contract check or privacy
  guarantee is touched.
* **Migration:** none. **Rollback:** delete `conformance/` and `.github/workflows/conformance.yml`. Nothing persists,
  nothing is deployed, no state repair is needed.
* **If you fix a "known defect"** (e.g. make `canonicalMetadataHash` recurse) you change the hash of every manifest/
  metadata object that has nested members. Do it behind a new codec/version id, add the new vectors as *required*
  cases in a suite version bump, and publish a migration note in `MIGRATION_GUIDE.md` — do not "just fix it".

## Operating it

* **Add a case:** edit the matching `tools/fx/*.py`, run `python conformance/tools/gen_fixtures.py` (adds only),
  run the reference adapter, commit `fixtures/`, `manifest.json`, `reason-codes.json` together.
* **Add an implementation:** copy `adapters/skeleton`, implement ops, run with `--allow-missing-ops` while incomplete.
  A deployed harness is just an adapter that calls it (HTTP, CLI, RPC) and maps its answers to reason codes.
* **Contract layer:** `envelope_*`, `proof_status`, `lineage_validate`, `classify_error`, `classify_public_inputs` are
  contract behaviours. The existing Rust conformance test reads the same `zk/vectors` corpus; a Rust adapter (or a
  deployed-testnet harness) for the remaining contract ops is the natural next step and is **not** included here — the
  matrix shows those cells as `not implemented` rather than pretending.
* **Environment variables:** `HPX_IMPL=cli|frontend` (TS adapter), `HPX_ERROR_ABI` (reference adapter's ABI path).
* **CI:** `.github/workflows/conformance.yml` publishes per-implementation reports, `matrix.md`/`matrix.json`, and the
  bundle as artifacts, and fails on any required failure, drift, lock or lint violation.
