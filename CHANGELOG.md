# Changelog

## 1.0.0 — Unreleased

- Added `devx/c2pa_export.py`, a fail-closed devx/release tool that exports
  C2PA (Content Credentials) authenticity assertions from a public Harpocrates
  proof manifest. It is deterministic, privacy-safe (public hashes only),
  rejects secret-looking fields, refuses to assert authenticity for expired or
  revoked evidence, and never signs. See `docs/c2pa-export.md`.
- Added an atomic compatibility manifest and release gate spanning frontend,
  backend, Noir circuit/verifier, and Soroban registry artifacts.
- Established the `harpocrates:silent-witness:v1` cryptographic domain and v1
  metadata, public-input, and registry interface bindings.
- Added staged rollout, rollback, artifact verification, and privacy-safe
  release signal requirements.
