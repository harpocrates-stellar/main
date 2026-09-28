# Scoped Nullifier Migration and Rollout Guide

**Version:** 2.0  
**Date:** 2026-07-26  
**Status:** Active

---

## 1. Overview

This guide covers the migration from the legacy (v1) nullifier derivation to the scoped nullifier v2 derivation.  It is intended for maintainers and operators of Harpocrates registry contracts and verifier contracts.

The PowerShell commands below are checked in CI with `stellar` and `cargo` replaced by local stubs. CI validates their syntax, script references, and argument shape; it never deploys a contract or uses real keys. Supply your own admin alias, contract IDs, and pinned verifier artifacts before running them against a network.

---

## 2. What Changed

### 2.1 New Features

- **Scoped nullifier derivation** — nullifiers are now bound to a verifier/purpose scope and a bounded epoch, reducing cross-context correlation.
- **Epoch management** — the registry admin can advance the epoch for each scope, enabling time-bound nullifier validity.
- **Domain separator versioning** — the `SCOPED_NULLIFIER_V1` domain separator prevents proof replay across protocol versions.
- **Backward-compatible public input parsing** — the contract automatically detects v1 (128-byte) vs v2 (192-byte) public inputs.

### 2.2 What Stayed the Same

- v1 proofs continue to work unchanged
- The `register_anonymous` stub path is unchanged
- The `register_source` and `register_seal` paths are unchanged
- The revocation witness circuit is unchanged
- The credential root derivation is unchanged
- The nullifier consumption model (global set) is unchanged

---

## 3. Migration Steps

### 3.1 Prerequisites

- Soroban CLI installed and configured
- Admin keypair for the existing registry contract
- New verifier contract compiled with v2 support (192-byte public inputs)

### 3.2 Step 1: Deploy the New Verifier Contract

Build a compatible UltraHonk verifier with the pinned toolchain described in [Verifier Integration](contracts/VERIFIER_INTEGRATION.md). Set `$VerifierWasm` to that verifier's WASM and `$VerifierVk` to its Soroban verification-key artifact. The registry WASM is **not** the verifier. Deploy the verifier with your configured `$Admin` alias:

<!-- ci-example: deploy-verifier -->
```powershell
stellar contract deploy `
  --wasm $VerifierWasm `
  --source $Admin `
  --network testnet `
  -- `
  --vk_bytes-file-path $VerifierVk
```

### 3.3 Step 2: Update the Registry Contract

If you are deploying a new registry contract, use the latest `lib.rs` which includes:

- `SCOPED_NULLIFIER_V1` domain separator constant
- `MAX_SCOPE_LENGTH = 64` byte limit
- `DataKey::ScopeEpoch` for per-scope epoch tracking
- `register_anonymous_verified` v2 parsing path (192-byte inputs)
- `set_scope_epoch` / `get_scope_epoch` admin entry points
- `StaleEpoch` error variant

If you are upgrading an existing registry contract, this is a **non-breaking upgrade** — the existing v1 path is preserved and the v2 path is additive.

### 3.4 Step 3: Set the Verifier on the Registry

<!-- ci-example: attach-verifier -->
```powershell
.\contracts\scripts\set-verifier.ps1 `
  -ContractId $RegistryContractId `
  -Admin $Admin `
  -Verifier $VerifierContractId
```

### 3.5 Step 4: Configure Scopes and Epochs

For each verifier/purpose combination, use `deriveVerifierScope` in `frontend/src/seedVault.ts` to obtain the **decimal** BN254 field element. Set `$ScopeFieldDecimal` to that value. The contract takes `BytesN<32>`, so encode it as a 32-byte big-endian hex string before invoking `set_scope_epoch`:

<!-- ci-example: set-scope-epoch -->
```powershell
$scopeNumber = [System.Numerics.BigInteger]::Parse($ScopeFieldDecimal)
$fieldModulus = [System.Numerics.BigInteger]::Parse('21888242871839275222246405745257275088548364400416034343698204186575808495617')
if ($scopeNumber -le 0 -or $scopeNumber -ge $fieldModulus) { throw 'Scope must be a nonzero BN254 field element.' }
$ScopeHex = [Convert]::ToHexString($scopeNumber.ToByteArray($true, $true)).PadLeft(64, '0')
stellar contract invoke `
  --id $RegistryContractId `
  --source $Admin `
  --network testnet `
  -- set_scope_epoch `
  --admin $Admin `
  --scope $ScopeHex `
  --epoch 0
```

### 3.6 Step 5: Verify the Migration

Run the contract test suite to verify that:

1. v1 proofs still work (backward compatibility)
2. v2 scoped proofs work with the new verifier
3. Epoch management works correctly
4. Replay protection is enforced

<!-- ci-example: contract-tests -->
```powershell
cd contracts
cargo test --lib
```

---

## 4. Rollout Strategy

### 4.1 Phase 1: Shadow Deployment

- Deploy the new registry contract alongside the existing one
- Run both contracts in parallel
- Log all v2 scoped registrations for monitoring
- Do not enforce scope/epoch requirements yet

### 4.2 Phase 2: Soft Enforcement

- Begin accepting v2 scoped proofs
- Set initial epochs to 0 for all scopes
- Monitor for replay attempts and epoch mismatches
- Verify that v1 and v2 proofs coexist without conflict

### 4.3 Phase 3: Epoch Enforcement

- Begin rotating epochs for active scopes on a schedule
- Reject stale proofs (epoch mismatch)
- Monitor for any legitimate proofs that fail due to epoch rotation

### 4.4 Phase 4: Legacy Deprecation

- After a sufficient observation period, deprecate the v1 path
- Remove `register_anonymous_verified` v1 support if desired
- Update documentation to require v2 scoped proofs

---

## 5. Rollback Plan

### 5.1 Rollback Scenarios

| Scenario | Rollback Action |
|----------|----------------|
| v2 proof verification fails | Switch verifier back to the v1 verifier contract |
| Epoch rotation causes legitimate failures | Admin may restore the previous epoch via `set_scope_epoch`; assess whether old proofs would become valid again |
| Scope configuration error | Admin may set the epoch to 0, but the storage entry remains and old proofs may become valid again |
| Contract bug in v2 path | Deploy a patched contract and redirect verifier |

### 5.2 Rollback Procedure

1. Switch the verifier back to the previous verifier contract:
   <!-- ci-example: rollback-verifier -->
   ```powershell
   .\contracts\scripts\set-verifier.ps1 `
     -ContractId $RegistryContractId `
     -Admin $Admin `
     -Verifier $OldVerifierContractId
   ```
2. If restoring an epoch is necessary, review the replay implications first. Use the same 64-character `$ScopeHex` derived above and a reviewed `$PreviousEpoch` value:
   <!-- ci-example: rollback-epoch -->
   ```powershell
   if ($ScopeHex -notmatch '^[0-9A-Fa-f]{64}$') { throw 'Scope must be exactly 32 bytes of hex.' }
   [UInt64]$epochValue = 0
   if (-not [UInt64]::TryParse([string]$PreviousEpoch, [ref]$epochValue)) { throw 'Epoch must be a u64 value.' }
   stellar contract invoke `
     --id $RegistryContractId `
     --source $Admin `
     --network testnet `
     -- set_scope_epoch `
     --admin $Admin `
     --scope $ScopeHex `
     --epoch $epochValue
   ```
3. Revert the active deployment interfaces safely using the rollout guard:
   ```powershell
   .\scripts\rollback.ps1 -ManifestFile .\release\compatibility-manifest.json
   ```
4. Verify that v1 proofs work again:
   ```powershell
   .\scripts\e2e-harpocrates.ps1
   ```

### 5.3 State Repair

The registry contract does not require any state repair on rollback because:

- v1 and v2 nullifiers are tracked in the same global set
- Nullifiers consumed by v2 proofs remain consumed (they are one-use tokens)
- The `Nullifier` set is append-only and does not need to be cleared

---

## 6. Monitoring and Observability

### 6.1 Key Metrics

| Metric | Description |
|--------|-------------|
| `v1_registrations_total` | Count of v1 (legacy) proof registrations |
| `v2_registrations_total` | Count of v2 (scoped) proof registrations |
| `stale_epoch_rejections_total` | Count of proofs rejected due to epoch mismatch |
| `duplicate_nullifier_rejections_total` | Count of replay attempts |
| `scope_epoch_rotations_total` | Count of epoch advancement operations |

### 6.2 Events to Monitor

- `ScopeEpochSet` — emitted when the admin advances a scope epoch
- `ProofRegistered` — emitted for all successful registrations
- `NonRevocationChecked` — emitted for non-revocation proof checks

### 6.3 Alerts

- **StaleEpoch spike** — a sudden increase in stale epoch rejections may indicate a misconfigured epoch rotation schedule
- **DuplicateNullifier spike** — may indicate a replay attack attempt
- **ScopeEpochSet without corresponding registrations** — may indicate an admin error

---

## 7. Security Considerations

### 7.1 Scope String Validation

Scope strings must be validated before derivation:

- Non-empty
- At most 64 bytes
- Lowercase ASCII alphanumeric with colons, hyphens, or underscores only
- No whitespace or uppercase characters

The contract enforces the 64-byte limit via `MAX_SCOPE_LENGTH`. The frontend enforces the canonical format via `deriveScopeField` in `seedVault.ts`.

### 7.2 Epoch Advancement

- Epochs can only be advanced by the registry admin
- The current contract permits an admin to set a lower epoch; it does not enforce monotonicity
- Lowering an epoch can make previously stale proofs valid again, although consumed nullifiers remain consumed. Treat an epoch rollback as a security-sensitive admin action

### 7.3 Cross-Network Isolation

Each registry contract deployment has its own independent nullifier set. A nullifier consumed on one network is not tracked on another. This is an inherent property of the Soroban contract boundary.

### 7.4 Cross-Verifier Isolation

The verifier contract address is stored on-chain and used to verify proofs. A proof produced for verifier A will not verify against verifier B (different proving keys). Changing the verifier on the registry does not invalidate previously consumed nullifiers.

---

## 8. References

- [Nullifier Derivation Spec](NULLIFIER_DERIVATION_SPEC.md)
- [Threat Model](THREAT_MODEL.md)
- [Noir Circuit Source](zk/noir/silent_witness/src/main.nr)
- [Contract Source](contracts/contracts/harpocrates-registry/src/lib.rs)
- [Frontend Scope Derivation](frontend/src/seedVault.ts)

## Revocation witness depth bound (#357)

The `revocation_witness` circuit is fixed at **depth 3** (8 Pedersen leaves).

| Constant | Value | Layers |
| --- | --- | --- |
| `MAX_REVOCATION_WITNESS_DEPTH` | 3 | Noir, registry, frontend/backend codec, `zk/tools/revocation_depth.py` |
| `MAX_REVOCATION_LEAVES` | 8 | same |

**Compatibility:** Public-input layout (`revocation_witness/v1`, 128 bytes) is
unchanged. Existing depth-3 proofs remain valid.

**Migration / rollback:** No storage migration. Raising the depth requires a
new circuit version and coordinated artifact republish; rolling back means
keeping the depth-3 verifier key. Host tooling must keep rejecting `depth > 3`
so oversized trees never reach the prover.

## Verifier circuit-version validation (#343)

Every proof-verifying entry point (`register_anonymous_verified`,
`register_batch_verified`, `check_non_revocation`, `verify_selective_disclosure`)
now validates the proof's circuit version at the trust boundary before invoking
the configured verifier.

| Item | Value |
| --- | --- |
| Built-in versions | silent-witness v1 = 1, silent-witness v2 (scoped) = 2, revocation-witness = 1, aggregation = 1, selective-disclosure = 1 |
| Default window | `MIN_SUPPORTED_CIRCUIT_VERSION..=MAX_SUPPORTED_CIRCUIT_VERSION` (1..=2) |
| Admin entry point | `set_verifier_circuit_versions(admin, min_version, max_version)` |
| Read entry points | `get_verifier_circuit_versions()`, `is_supported_circuit_version(version)` |
| Stable failure | `RegistryError::UnsupportedCircuitVersion` (81) for a proof outside the window; `InvalidCircuitVersionRange` (82) for a malformed window |

The window is **additive**: when unset, the full built-in range applies, so
pre-#343 deployments, existing callers, and stored evidence validate exactly as
before. `set_verifier` and both verifier-rotation transitions clear the window
so an incoming verifier cannot inherit the outgoing verifier's claim.

**Migration / rollback:** `DataKey::VerifierCircuitVersions` is a new,
additive storage key; no data migration is required. Deploying a pre-#343 wasm
ignores the key and reverts to calling the verifier with no version gate, which
only widens acceptance and never corrupts stored evidence.

## Bounded delegated issuer expiration (#338)

A proof registered through `register_source_delegated` or
`register_seal_delegated` is now bounded by the delegation that authorized it:
its `expires_at` is the delegation's `expires_at` (or the configured proof TTL,
whichever is sooner). Delegated authority can never mint an artifact that
outlives it.

- Direct `register_source` / `register_seal` are unchanged; a zero TTL still
  means "eternal" for non-delegated registrations.
- Existing stored records are untouched.
- **Rollback:** deploying a pre-#338 wasm restores the old behavior of an
  eternal delegated proof; the delegation expiry is still enforced at
  registration time, so no authority is extended retroactively.

## Issuer rotation grace windows (#323)

A Tier 3 issuer key can now rotate to a replacement instead of being revoked
outright, with a bounded window during which the evidence it already signed stays
verifiable.

| Item | Value |
| --- | --- |
| Admin entry point | `rotate_issuer(admin, previous_issuer, replacement_issuer, grace_secs)` |
| Read entry points | `get_issuer_rotation(issuer)`, `is_issuer_verifiable(issuer)` |
| Settlement entry point | `finalize_issuer_rotation(issuer)` — permissionless once the window lapses |
| Default window | `DEFAULT_ISSUER_ROTATION_GRACE_SECS` (90 days) when `grace_secs == 0` |
| Maximum window | `MAX_ISSUER_ROTATION_GRACE_SECS` (365 days) |
| Events | `IssuerRotated` (`issuer/rotate`), `IssuerRotationGraceExpired` (`issuer/grace`) |
| Stable failures | `InvalidIssuerRotationGrace` (83), `InvalidIssuerRotation` (84), `IssuerRotationNotFound` (85), `IssuerRotationGraceStillActive` (86); `UnknownIssuer` (8) for an absent or inactive key |

**Semantics.** Rotation retires the previous key immediately — it can no longer
sign new seals, directly or through a delegation — and keeps the evidence it
already signed verifiable until `grace_expires_at`. The window is lazy
(`now < grace_expires_at` against ledger time), so it lapses with no transaction;
`finalize_issuer_rotation` closes the record afterwards and emits the grace-expiry
event. `revoke_issuer`, the timelocked `RevokeIssuer` action, and `add_issuer` all
clear the rotation record, so revocation and re-onboarding always outrank a grace
window.

**Migration / rollback:** `DataKey::IssuerRotation(Address)` is a new, additive
storage key and the stored `IssuerRecord` keeps its existing
`{metadata_hash, active}` serialization, so records written by earlier wasm decode
unchanged, no data migration is required, and a deployment that never rotates
reads as "no rotation" with standing decided by `active` alone. Deploying a
pre-#323 wasm ignores the key: `register_seal` falls back to the `active` flag,
which only widens acceptance for a retired key — never for a revoked one, and
never for new evidence after an explicit `revoke_issuer`.

**Compatibility:** existing entry points are unchanged and `get_issuer` returns
the same `IssuerRecord` shape. `is_issuer_verifiable` and `get_issuer_rotation`
never panic, so callers can pre-flight an unknown, revoked, or unsupported issuer
without risking a reverted transaction.
