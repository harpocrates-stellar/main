## Description

Closes #341

### feat(contracts): split admin and issuer roles

## Summary

This PR enforces strict separation between Harpocrates registry-administrator authority and active Tier 3 issuer authority at the Soroban contract boundary.

The previous registry already required the caller to sign as `admin` for protocol administration and as `issuer` for Tier 3 seals, but it still allowed the same address to hold both roles through `add_issuer`. That collapsed two distinct trust domains:

- the registry admin controls policy, verifier configuration, credential roots, proof lifecycle, and the issuer allowlist; and
- an active issuer attests to Tier 3 evidence under institutional authority.

The storage V2 contract now rejects that overlap with a stable, typed `RoleConflict` error (`RegistryError #53`). It preserves existing callers, proof records, indexes, verifier integrations, metadata layouts, and all non-conflicting issuer records.

## Behavior

### Strict role separation

- `add_issuer(admin, issuer, metadata_hash)` rejects an issuer equal to the active admin with `RoleConflict`.
- A pending-admin address cannot be granted issuer authority before the transfer completes.
- `propose_admin` rejects an active issuer as the pending admin.
- `accept_admin` re-checks the role boundary, including for pending proposals created by an older artifact.
- `register_seal` and `register_seal_delegated` defensively reject a stale active issuer record that aliases the admin.
- Admin transfer remains a two-step operation. After a successful transfer, the former admin may be granted issuer authority because it no longer holds the admin role.

### Public queries

The change is additive to the current contract interface:

```text
get_schema_version() -> u32
is_admin(address) -> bool
is_issuer(address) -> bool
```

The role queries are read-only, accept arbitrary public addresses, do not require authorization, and expose only effective public role state. They do not expose key material, proof material, witnesses, secrets, or media.

### Stable failure behavior

`RoleConflict` is appended as contract error code `53`, preserving every existing error number. It is returned without a variable-length payload and without media, metadata, witness, proof, credential, signature, or key data.

No role operation accepts variable-length encoded input, so malformed and oversized encoding behavior remains governed by the existing verifier/public-input boundary. Revoked and unknown issuers continue to return the existing `UnknownIssuer` path. Expired, paused, duplicate, unsupported-schema, and verifier dependency failures remain in their existing canonical order. This change does not introduce a second proof, metadata, verifier, identity-tier, or deployment truth.

## Typed events and privacy

The migration reuses existing typed events rather than defining a parallel event protocol:

- `IssuerRevoked` is emitted only when the current admin had an active conflicting issuer record; and
- `SchemaUpgraded { previous: 1, current: 2 }` records the storage migration.

`IssuerAdded`, `IssuerRevoked`, admin transfer, verifier, proof, nullifier, and schema event topic layouts remain unchanged. No new event includes media, raw proof bytes, public inputs, witnesses, credentials, signatures, or private keys. The new failure path emits no event because the transaction reverts atomically.

## Storage migration and compatibility

### Fresh deployments

`init(admin)` is unchanged. Fresh contracts initialize directly at storage schema V2.

### Existing deployments

The current admin calls the existing entry point once:

```text
upgrade_storage(admin)
```

The migration is idempotent and deliberately narrow:

1. Requires the current admin's authorization.
2. Reads the current admin.
3. If that address has an active `IssuerRecord`, sets only that record's `active` flag to `false`.
4. Writes schema version V2.
5. Emits the existing typed migration/revocation events.

It does not rewrite:

- `ProofRecord` values or proof status;
- video or nullifier replay indexes;
- verifier addresses or rotation state;
- credential roots or revocation roots;
- schemas, versions, or thresholds;
- issuer metadata hashes; or
- non-conflicting issuer records.

`DataKey::Admin`, `DataKey::Issuer`, and all evidence layouts are unchanged. Existing stored evidence and proof IDs remain valid and readable. The additive role queries and migration do not break compatible V1 callers, and all existing contract entry points retain their signatures.

## Trust-boundary implications

Before this change, a single compromised or operationally reused key could both administer protocol policy and create Tier 3 institutional seals. V2 makes that role confusion impossible at grant, transfer, and registration boundaries.

This does **not** make a compromised admin harmless: the admin can still revoke proofs, credential roots, or issuers, replace verifier configuration, pause registration, and transfer control. Role separation limits cross-domain authority; it is not a substitute for multisig administration, key isolation, timelocked policy changes, or monitoring. The threat model now records that residual risk explicitly.

## Privacy implications

- No private data is added to contract events or error responses.
- Role checks use only public Stellar addresses and existing on-chain role records.
- The migration preserves historical proof records rather than deleting or rewriting evidence.
- Tests and documentation use synthetic addresses and fixed synthetic bytes only.
- Operational guidance continues to prohibit logging media, witnesses, proofs, credentials, signatures, or keys.

## Rollout and rollback

Recommended rollout:

1. Build and record the role-separated registry Wasm in the same reviewed release bundle as its interface/deployment metadata.
2. Upgrade the existing registry code.
3. Call `upgrade_storage` as the current admin.
4. Confirm `get_schema_version() == 2`.
5. Confirm `is_admin(admin) == true` and `is_issuer(admin) == false`.
6. Use a separate issuer key for all Tier 3 grants and seals.
7. Resume issuer operations only after those checks pass.

Rollback to the previous immutable Wasm does not require evidence repair: all stored records and indexes remain compatible and readable. However, a pre-V2 artifact does not enforce the role split and can grant the admin issuer authority again. If that artifact is active, operators must not grant issuer authority until the V2 artifact is restored and the idempotent migration is confirmed.

## Tests

Added focused fixtures in `test_roles.rs` covering:

- fresh V2 initialization and read-only role queries;
- a separate issuer successfully registering Tier 3 evidence;
- negative admin-to-issuer assignment;
- negative issuer-to-admin proposal;
- negative issuer attempts to manage issuer roles;
- admin transfer, revoked-issuer transfer, and former-admin role conversion;
- V1-to-V2 migration for both conflicting and non-conflicting issuer records;
- preservation of stored evidence and issuer metadata;
- typed migration event count and idempotence;
- defense against a legacy admin/issuer conflict before migration; and
- bounded CPU/memory behavior for a rejected role assignment.

The existing state-machine oracle was updated for schema V2 and the new role-conflict transitions. Existing add-issuer, register-seal, migration, verifier, encoding, pause, delegation, and budget suites remain regression coverage for the surrounding behavior.

## Local verification

The current execution environment does not include the Rust/Soroban toolchain, so the following required checks could not be executed here:

```text
$ cargo test --lib test::registers_all_identity_tiers --no-fail-fast
bash: cargo: command not found
```

A toolchain-enabled CI runner must run at minimum:

```bash
cd contracts
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
stellar contract build
```

The repository's DevX suite was also run. Six release-guard tests passed, while
`test_current_manifest_verifies` failed because the checked-in compatibility
manifest already reports digest mismatches for frontend, backend, circuit, and
registry sources (including the intentionally changed registry source). Updating
those approvals is deliberately left for the reviewed artifact/release bundle
rather than blessing unrelated pre-existing changes in this issue.

The PR should not be merged until the focused, Wasm, lint, and reviewed artifact
manifest checks are green.

## Compatibility and artifact notes

- Contract package / release train: `1.0.0` (unchanged compatible interface).
- Storage schema: V1 -> V2.
- Contract interface: additive; existing function signatures unchanged.
- Proof/public-input/verifier domains: unchanged.
- Evidence and replay indexes: unchanged.
- Deployment artifact hash must be regenerated and reviewed; this PR does not publish a production hash or credential.
