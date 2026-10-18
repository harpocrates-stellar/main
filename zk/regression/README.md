# Protocol proof regression suite

Pinned, synthetic regressions over Harpocrates' **public verifier-input boundary**.

## Trust boundary

- Inputs: conformance vectors under `zk/vectors/` (no real media, no production witnesses).
- Outputs: accept / stable reject codes only. Failures must not log secrets, seeds, or raw proofs.

## Compatibility

- Corpus format: `harpocrates.verifier-conformance` v1 (shared with
  `backend/test_conformance_vectors.py`, Rust `test_conformance.rs`, and the
  TypeScript conformance runner).
- Adding cases is additive; renumbering or changing accept→reject for an existing
  `id` is a breaking protocol change and needs a corpus version bump.

## Rollback

- Delete or revert this `zk/regression/` folder; the canonical corpus and existing
  layer runners remain the source of truth.

## Run

```bash
pytest zk/regression/test_protocol_proof_suite.py -q
```
