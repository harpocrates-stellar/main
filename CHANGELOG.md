# Changelog

## 1.0.0 — Unreleased

- Added `harpocrates c2pa` to export C2PA authenticity assertions from the
  canonical proof manifest (with an optional verification receipt) as an
  unsigned C2PA JSON manifest definition. Standard `c2pa.actions.v2` and
  `c2pa.hash.data` assertions plus namespaced `harpocrates.registry.v1`,
  `harpocrates.verification.v1`, and `harpocrates.export.v1`.
  Deterministic output, privacy-safe (never media, witnesses, secrets, proof
  bytes, or keys; never signs), schema version 1, 1 MiB input / 256 KiB
  output caps. Verified against a committed fixture by
  `devx/validate_c2pa_fixture.py` in the new CLI CI workflow (#384).

- Extended structured fuzzing of proof and public-input decoding: proof-hex
  mutators (odd nibble, non-hex, empty, length edges), exact proof-bound tables,
  silence checks, and regression corpus entries `fz-011`–`fz-013` (#369).

- Bound `revocation_witness` Merkle depth at `MAX_REVOCATION_WITNESS_DEPTH = 3` (8 leaves) across the Noir circuit, registry constants, verifier codec, and host tooling (#357).

- Added a CI end-to-end environment matrix (`devx/e2e_env_matrix.py`) that exercises public API boundaries across development/testing/production-like profiles with privacy-safe failure checks.

- Added an atomic compatibility manifest and release gate spanning frontend,
- Added a cross-layer compatibility report that publishes version, interface, and digest alignment across frontend, backend, circuit, verifier, and registry without embedding private material.
  backend, Noir circuit/verifier, and Soroban registry artifacts.
- Established the `harpocrates:silent-witness:v1` cryptographic domain and v1
  metadata, public-input, and registry interface bindings.
- Added staged rollout, rollback, artifact verification, and privacy-safe
  release signal requirements.
- Added the registry dispute and supersession state machine (`open_dispute`,
  `respond_dispute`, `resolve_dispute`, `dismiss_dispute`,
  `supersede_dispute`, `get_dispute`, `get_open_dispute_count`) with bounded
  open-dispute caps, reporter cooldowns, respond/resolve deadlines, cycle-safe
  supersession, privacy-safe typed events, and additive storage that needs no
  migration. See `contracts/DISPUTE.md`.
