# Credential-free proof artifact release evidence bundle

A release decision needs to distinguish *evidence that a check ran* from *the
absence of that evidence*. The bundle produced by
`devx/proof_release_evidence.py` makes that distinction explicit: it collects
pinned/observed tool versions, committed artifact digests, and validation
outcomes, and it never promotes an unexecuted proving check to `pass`.

The builder is static. It does not run `nargo`/`bb`, read credentials, call an
RPC, fetch a URL, or open a witness. Inputs are bounded JSON documents from the
checkout plus an optional validation record produced by a pipeline that really
executed the checks.

## Build the bundle

```bash
python devx/proof_release_evidence.py --out zk/release/proof-evidence.json
python -m pytest devx/test_proof_release_evidence.py -q
```

Without a validation record the command still succeeds, but it reports the
proving checks as `missing_evidence` and `release_ready` is `false`. That is
the honest result for a checkout that has not executed proving locally.

With a record from an executed run, the same tool collects the outcomes:

```bash
python devx/proof_release_evidence.py --validation-record <record.json> --out zk/release/proof-evidence.json
python devx/proof_release_evidence.py --validation-record <record.json> --require-complete
```

Observed tool versions may also be supplied directly with
`--tool-version nargo=<version>` and `--tool-version barretenberg=<version>`.
A direct claim cannot override a record entry whose status is `skipped`,
`not_run`, or unknown: absence of execution evidence stays
`missing_evidence`.

## Bundle shape

The output is deterministic JSON (`harpocrates.proof-release-evidence`, version
`1`) sorted by key with no timestamps. It contains:

| Section | Contents |
| --- | --- |
| `tool_versions` | Pinned version from `zk/toolchain.lock.json`, observed version when evidenced, and per-tool status |
| `digests` | Repo-relative path, SHA-256, digest kind (`sha256`, `normalized`, `raw`), and source manifest |
| `validation_outcomes` | One `{id, status, source, detail}` entry per tool, digest source, and proving check |
| `summary` | Counts per status, total, and `release_ready` |

Digest sources are `zk/artifacts.manifest.json`,
`zk/browser.artifacts.manifest.json`, `zk/circuit.provenance.json`, and the
privacy-safe `zk/release/retention-manifest.json`. A missing source is
`missing_evidence`; a malformed source or wrong format identifier is a fatal
input error (exit `2`), never a pass.

## Validation record format

The record is a small JSON document that asserts only what a runner actually
observed:

```json
{
  "format": "harpocrates.proof-validation-record",
  "version": 1,
  "checks": [
    {"id": "toolchain.nargo_version", "status": "pass", "observed": "1.0.0-beta.9"},
    {"id": "toolchain.barretenberg_version", "status": "pass", "observed": "0.87.0"},
    {"id": "proof.generate", "status": "pass", "evidence": "synthetic-prove"},
    {"id": "proof.verify", "status": "pass", "evidence": "synthetic-verify"}
  ]
}
```

Recognised check ids are `toolchain.nargo_version`,
`toolchain.barretenberg_version`, `proof.generate`, and `proof.verify`. A
`pass` for `proof.generate` or `proof.verify` also requires a short evidence
label; a bare assertion without one is downgraded to `missing_evidence`.
`skipped`, `not_run`, `unknown`, and malformed statuses are all absence of
execution evidence. Sensitive field names and secret-like text are rejected
before any bundle is written.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Bundle built; no check failed (missing evidence is still reported) |
| `1` | A check failed, or `--require-complete` was set and evidence is missing |
| `2` | Missing, malformed, oversized, or sensitive input; nothing was written |

## Compatibility and rollback

This is additive: no existing manifest, CLI, circuit, contract, or stored
evidence changes. The bundle never writes into an input document. Remove the
CI step and upload, and stop producing the bundle, to roll back; no repository
state needs migration.
