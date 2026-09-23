# Changelog

## Unreleased — Registry storage V2

- Split registry-admin and active-issuer authority into strictly disjoint roles
  with the stable `RoleConflict` (`#53`) authorization error.
- Added read-only `is_admin`, `is_issuer`, and `get_schema_version` queries.
- Added an idempotent storage V1-to-V2 migration that revokes only a conflicting
  admin issuer record while preserving all evidence and protocol boundaries.

## 1.0.0 — Unreleased

- Added an atomic compatibility manifest and release gate spanning frontend,
  backend, Noir circuit/verifier, and Soroban registry artifacts.
- Established the `harpocrates:silent-witness:v1` cryptographic domain and v1
  metadata, public-input, and registry interface bindings.
- Added staged rollout, rollback, artifact verification, and privacy-safe
  release signal requirements.
