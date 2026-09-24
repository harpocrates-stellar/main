# Changelog

## 1.0.0 — Unreleased

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

- Added revocation reason codes to the Soroban registry (`revoke_proof_with_reason`,
  `get_revocation_reason`) with bounded `0..=255` codes, an additive storage key
  that needs no migration, and a privacy-safe `reason_code` field on the
  `ProofRevoked` event (#327).

- Restored cross-layer verifier-input conformance: the silent-witness frame is
  now byte-identical across the Python, TypeScript, and Soroban codecs (160
  bytes / five fields including the `domain_tag` digest), the `domain_tag` is
  exempted from field-canonicity checks (it is a raw SHA-256 digest, not a
  field element), the fuzz regression corpus was migrated to the current frame
  layout (`fuzz_regressions_v1.json` version 2), and the contract test suite
  was repaired against soroban-sdk 27 so `cargo test --workspace`,
  `cargo fmt --check`, and the conformance/fuzz suites pass in CI.
