# Changelog

## 1.0.0 — Unreleased

- Added issuer trust-state badges to the verification portal and Evidence Studio. The frontend now reads `get_issuer` from the registry and resolves a record's issuer to one of nine stable states (`trusted`, `revoked`, `unknown`, `expired`, `unsupported`, `malformed`, `oversized`, `unavailable`, `checking`). Address shape is validated before any registry read, an unreadable registry is reported as `unavailable` rather than as `unknown`, and the badge surfaces only the issuer address already public on chain. See `frontend/src/provenance/issuerTrust.ts`.

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
