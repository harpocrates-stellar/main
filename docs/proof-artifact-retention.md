# Proof artifact retention and privacy rules

CI retains proof artifacts so they can be inspected and compared across runs. Retention goes only through `devx/retain_proof_artifacts.py`, which fails closed.

## What is retained
Files with these suffixes, from the explicit source directories only: `.proof`, `.vk`, `.json`, `.sha256`, `.hex`.
A `retention-manifest.json` (schema `hpx-artifact-retention/1`) lists each file's relative path, size and SHA-256.

## What is never retained
- Real or test media (video, audio, images) and anything that is not allowlisted
- Private keys, seeds, secrets, mnemonics, `.env` files
- Witness values and prover inputs (`.gz`, `.wtns`, `Prover.toml`, JSON keys such as `witness`, `secret`, `seed`)
- Symlinks

A single violation aborts staging with exit code 2 and writes nothing. If staging fails, the upload step does not run.

## Failure codes (stable)
`DENIED_TYPE`, `DENIED_NAME`, `SECRET_CONTENT`, `FORBIDDEN_JSON_KEY`, `MALFORMED_JSON`, `OVERSIZED`, `TOTAL_TOO_LARGE`, `SYMLINK`, `MISSING_SOURCE`, `NOTHING_TO_RETAIN`, `OUT_NOT_EMPTY`.
Messages contain only the code, never file names or contents.

## Limits and retention period
- Per file: 5 MiB. Total: 25 MiB. Override with `--max-file-bytes` / `--max-total-bytes`.
- GitHub Actions retention: 14 days.

## Run locally
    python devx/retain_proof_artifacts.py --src <dir> --out retained-proof-artifacts
    python devx/retain_proof_artifacts.py --src <dir> --out /tmp/x --dry-run
    python -m unittest discover -s devx/tests -v

## Compatibility, migration and rollback
Additive CI change. No protocol, contract, circuit or stored-evidence changes, and no migration. Rollback: remove the two workflow steps (and optionally the script).