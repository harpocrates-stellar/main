# Changelog

## 1.0.0 — Unreleased

- Added signed receipt digest commitment (#337): `commit_receipt_digest`
  anchors `sha256(canonical_json(signed_verification_receipt))` with a
  contract-bound P-256 attestation from an admin-managed allowlist
  (`add_receipt_signer`, `revoke_receipt_signer`, max 8 active keys), one
  immutable commitment per proof, idempotent retries, public
  `get_receipt_commitment` / `get_receipt_signer` reads, typed events, and
  additive storage. The receipt itself never touches the chain. See
  `contracts/RECEIPT_COMMITMENT.md`.
- External verifier verdicts are now enforced: registrations whose
  `verify_external_proof` call fails (or that pass an empty proof) revert with
  `InvalidProof` instead of proceeding silently.

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
