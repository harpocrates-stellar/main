# Changelog

## 1.0.0 — Unreleased

- Added a dependency pin and lockfile gate (`devx/check_dependency_pins.py`, wired into the release gate): pip requirements must be exactly pinned, npm lockfiles must match their manifests, cargo locks must resolve every workspace dependency, and the Noir toolchain lock must pin concrete compiler versions. See `docs/dependency-pins.md`. Closes #391.
- Domain-separated proof-cache keys in the backend verifier cache (#373): keys
  are SHA-256 digests over the versioned `harpocrates:verifier-cache:v1` domain
  tag plus length-prefixed fields, eliminating separator-ambiguity collisions
  and cross-domain key reuse; hex proof/public-input inputs are case- and
  whitespace-canonicalized. Bump the tag to invalidate all cached entries.
- Added on-chain **metadata envelope versioning** for the Soroban registry (`MetadataEnvelope`, `bind_metadata_envelope`, auto-V1 stamp on register, V1→V2 upgrade path) aligned with `backend/envelope.py`. See `contracts/METADATA_ENVELOPE.md`. Closes #317.

- Extended structured fuzzing of proof and public-input decoding: proof-hex
  mutators (odd nibble, non-hex, empty, length edges), exact proof-bound tables,
  silence checks, and regression corpus entries `fz-011`–`fz-013` (#369).

- Bound `revocation_witness` Merkle depth at `MAX_REVOCATION_WITNESS_DEPTH = 3` (8 leaves) across the Noir circuit, registry constants, verifier codec, and host tooling (#357).

- Closed an unpinned-circuit gap in the reproducible Noir build pipeline. The
  `selective_disclosure` circuit — fetched by the browser at
  `/noir/selective_disclosure.json` and accepted by the registry's
  `verify_selective_disclosure` — was not compiled or digested by
  `zk/noir/scripts/reproducible-build.sh` and was absent from
  `zk/toolchain.lock.json`, so it was a second, unpinned truth at a public
  boundary. It is now built, pinned, and publish-declared. Added
  `artifact_manifest.py check-coverage` (and
  `reproducible-build.sh --check-coverage`), which fails when a package under
  `zk/noir/` is not declared in the lock or a declared circuit has no package, so
  the condition cannot recur silently. The gate reads no artifacts, so bytecode,
  witnesses, and keys never reach a signal; findings carry circuit names and
  expected paths only and are deterministically ordered. Additive and inert for
  existing callers: a new subcommand, one lock limit (`max_circuits`), and new
  artifact declarations. Rollback is removing the CI step and the
  `coverage_gate` call. See `docs/zk-reproducible-builds.md` and OR-5 in
  `THREAT_MODEL.md`.

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
