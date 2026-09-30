# Changelog

## 1.0.0 — Unreleased

- Added a **circuit-versioned proof envelope** for the scoped silent witness
  proof (#368): `silent_witness/v2` / `hpx-vi/2` is the 224-byte scoped frame plus
  a trailing 32-byte `circuit_version` field element (8 × 32 = 256 bytes), and the
  Noir circuit asserts that value against `CURRENT_CIRCUIT_VERSION` in-circuit, so
  a proof names the circuit that produced it instead of leaving a verifier to
  infer the version from a byte count. The envelope is **required** on the
  registration path: `register_anonymous_verified` rejects the superseded bare
  224-byte frame with `RegistryError::CircuitVersionMismatch` (new ABI code 87 in
  `contracts/ERROR_ABI.md`) before the verifier is reached, so no proof can skip
  the version commitment by omitting the trailer. `hpx-vi/1` (160-byte
  `silent_witness/v1`, 128-byte revocation) is byte-for-byte unchanged, and
  `circuit_version` is never written to `ProofRecord`, so stored evidence is
  unaffected. Built the scoped ACIR with the pinned toolchain — 21 `nargo test`
  cases pass, including the version-downgrade rejection — and refreshed the source
  digests that cover it (`zk/circuit.provenance.json`,
  `release/compatibility-manifest.json`); the tracked published browser artifacts
  are a different, digest-pinned circuit shape and stay unchanged. Added a
  `verifier_conformance_v2.json` corpus and put `nargo test` for the silent
  witness circuits in CI. See `MIGRATION_GUIDE.md` and `THREAT_MODEL.md` (OR-5).
- Added bounded **issuer rotation grace windows** to the Soroban registry (#323).
  `rotate_issuer` retires an active issuer key in favour of a replacement and
  opens a bounded window (default `DEFAULT_ISSUER_ROTATION_GRACE_SECS`, capped by
  `MAX_ISSUER_ROTATION_GRACE_SECS`) during which the retired key's pre-rotation
  evidence stays verifiable, while the retired key itself — and its delegates —
  can no longer sign new seals. `is_issuer_verifiable` / `get_issuer_rotation`
  expose standing without panicking, and `finalize_issuer_rotation` settles a
  lapsed window and emits the grace-expiry event. `revoke_issuer`, its
  timelocked twin, and `add_issuer` all clear a rotation record. Additive on
  chain: `DataKey::IssuerRotation` is a new key and `IssuerRecord` keeps its
  existing serialization, so stored evidence and compatible callers are
  unaffected. New ABI codes 83–86 in `contracts/ERROR_ABI.md`; see
  `MIGRATION_GUIDE.md` and `THREAT_MODEL.md` (T3).
- Added a privacy-safe redaction preview in Evidence Studio that discloses truncated public fingerprints while withholding seeds, witness proofs, private keys, and media URLs (`frontend/src/redactionPreview.ts`).
- chore(devx): retain proof artifacts in CI through a privacy-checked allowlist (#398)
- Added the `redacted_ancestry` Noir circuit and helper (#356): proves a redacted
  derivative descends from a committed parent evidence object without revealing
  the unredacted parent hash, the redaction mask preimage, or credential secrets.
  Binds the canonical lineage `redact` identifier and the `1..=4` depth bound,
  with synthetic vectors and schema guards. See `docs/zk-redacted-ancestry-spec.md`.
- External verifier verdicts are now enforced: registrations whose
  `verify_external_proof` call fails (or that pass an empty proof) revert with
  `InvalidProof` instead of proceeding silently.
- Scoped `POST /api/proofs/register` auth to proof ownership: owner-bound bearer keys (`REGISTER_SCOPED_KEYS`, digests only) may register only their own `sourceAddress` and cannot take over another owner's proof; the legacy `REGISTER_API_KEY` is unchanged. Auth now runs before idempotency replay, and the registration route no longer crashes without a `timeAttestation`. See `docs/registration-auth-scoping.md`.
- Made protocol-binding comparisons constant-time in the Python, browser, and Soroban verifier-input codecs and the `/metrics` token check. Reject codes, circuits, and artifacts are unchanged; see `docs/zk-conformance-vectors.md`.
- Enforced configured CORS origins server-side in the Flask backend: requests
  carrying an `Origin` outside `CORS_ORIGINS` are now rejected with a privacy-safe
  `403 FORBIDDEN_ORIGIN` envelope before route handlers execute, closing the gap
  where flask-cors only withheld `Access-Control-Allow-Origin` headers (#266).
  Requests without an `Origin` header and the `/health`, `/ready`, and `/metrics`
  paths are exempt; rejections are counted in admission-rejection metrics and the
  origin value is never logged.
- Published circuit artifact provenance (`zk/circuit.provenance.json`) with `write-provenance` / `verify-provenance` gates that bind lock-declared circuit sources without compiling ACIR (#376).
- Added issuer trust-state badges to the verification portal and Evidence Studio. The frontend now reads `get_issuer` from the registry and resolves a record's issuer to one of nine stable states (`trusted`, `revoked`, `unknown`, `expired`, `unsupported`, `malformed`, `oversized`, `unavailable`, `checking`). Address shape is validated before any registry read, an unreadable registry is reported as `unavailable` rather than as `unknown`, and the badge surfaces only the issuer address already public on chain. See `frontend/src/provenance/issuerTrust.ts`.
- Added fail-closed startup verification of applied migration checksums: `backend/migration.py` replays each recorded SHA-256 digest against its in-code definition and aborts startup with `MigrationChecksumError` on mismatch (id/digest-only reporting). `MIGRATION_CHECKSUM_ENFORCEMENT=warn` is the break-glass rollback. See `backend/README.md` and `THREAT_MODEL.md` (T10).
- Added a fail-closed contract Wasm size budget (`MAX_WASM_SIZE_BYTES = 128_000`,
  just under Soroban's 128 KiB upload cap, plus a minimum-size floor and 15%
  regression band) enforced in Contracts CI against `devx/wasm_size_budget.json`,
  with digest-recorded baselines and typed `WasmBudgetError` codes in
  `contracts/harpocrates-registry/src/wasm_budget.rs` (#346).
- Added independent on-chain timestamp claim anchoring (`anchor_timestamp_claim`,
  `get_timestamp_claim`, `has_independent_timestamp_anchor`) so registry proofs can
  bind off-chain time attestations to Stellar ledger time and optional RFC 3161
  commitments without storing tokens or secrets. See `contracts/TIMESTAMP_CLAIMS.md`.
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

- Bound aggregation proof count at `MAX_AGGREGATION_SIZE = 8` (`MIN_AGGREGATION_SIZE = 1`) across Noir circuits, Soroban registry constants, backend/frontend verifier input validators, conformance vectors, and host tooling with structured, privacy-safe rejection codes (#488).

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
  backend, Noir circuit/verifier, and Soroban registry artifacts.
- Added a cross-layer compatibility report that publishes version, interface, and digest alignment across frontend, backend, circuit, verifier, and registry without embedding private material.
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
- Added a non-worker fallback for browser proof generation with explicit
  limits (60s timeout, 256-byte secret cap, single concurrent request) and a
  bounded runtime for Web Worker-unavailable environments; proof payloads are
  unchanged and both runtimes verify identically.