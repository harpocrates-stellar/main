# Harpocrates Soroban Contracts

This workspace contains the Stellar Soroban contracts for Harpocrates.

## Contracts

```text
contracts/harpocrates-registry
```

`HarpocratesRegistry` stores evidence records for all identity tiers:

- Tier 1 Silent Witness: anonymous Noir proof with nullifier protection.
- Tier 2 Consistent Source: Stellar account signed source.
- Tier 3 Public Seal: approved institutional issuer.

## Build

```powershell
cargo test
stellar contract build
```

The current registry exports:

```text
init
propose_admin
cancel_admin_transfer
accept_admin
add_credential_root
revoke_credential_root
get_credential_root
add_issuer
revoke_issuer
set_verifier
get_verifier
schedule_verifier_rotation
activate_verifier_rotation
rollback_verifier_rotation
get_verifier_state
register_anonymous
register_anonymous_verified
register_source
register_seal
revoke_proof
get_proof
get_by_video
has_nullifier
get_issuer
```

## Staged verifier rotation

The registry now supports a staged verifier transition so a new verifier can be introduced without an unsafe instant cutover:

1. The admin schedules a pending verifier with an activation ledger and rollback window.
2. Once the ledger reaches the activation threshold, the admin activates the pending verifier.
3. During the rollback window, the admin can revert to the previous verifier if the new verifier misbehaves or fails validation.

The rotation state is persisted and can be inspected via `get_verifier_state`.

### Operational flow

```powershell
./scripts/schedule-verifier-rotation.ps1 -ContractId YOUR_REGISTRY -Admin harpocrates-admin -Verifier YOUR_NEW_VERIFIER -ActivationLedger 1000 -OverlapWindow 100 -RollbackWindow 200
./scripts/activate-verifier-rotation.ps1 -ContractId YOUR_REGISTRY -Admin harpocrates-admin
./scripts/rollback-verifier-rotation.ps1 -ContractId YOUR_REGISTRY -Admin harpocrates-admin
```

### Rollback and troubleshooting

- Activation is rejected before the configured activation ledger.
- Rollback is rejected once the rollback window closes.
- If the pending verifier fails validation or causes operational issues, revert to the previous verifier within the rollback window.
- If you need to reconfigure the verifier after the rotation completes, call `set_verifier` again to reset the rotation state and install a fresh verifier.

## Admin Transfer

Admin control uses a two-step transfer:

1. The current admin calls `propose_admin`, which creates or replaces the pending
   admin proposal.
2. The pending admin calls `accept_admin` to complete the transfer.

The current admin may call `cancel_admin_transfer` before acceptance. Proposals,
cancellations, and acceptances emit `["admin", "propose"]`,
`["admin", "cancel"]`, and `["admin", "accept"]` lifecycle events.

### Storage compatibility

The existing `DataKey::Admin` value and all existing record layouts are
unchanged. `DataKey::PendingAdmin` is appended as a new, independent persistent
storage key, so upgrading an initialized contract preserves its current admin
and all existing registry data. An upgraded contract starts with no pending
admin proposal.

## Tier 1 Verifier

`register_anonymous` is the development/demo boundary.

`register_anonymous_verified` is the real Tier 1 entrypoint. It checks public
inputs, requires an active credential root, prevents nullifier reuse, then calls
the configured verifier contract:

```text
verify_proof(public_inputs, proof)
```

See `VERIFIER_INTEGRATION.md` for the UltraHonk verifier deployment plan.

Current Testnet verifier:

```text
CCP2EQPKT5XAYTOARX3LGHNMJ37A6W2WY3H54MRIHEZVTVAZZPUSGZQJ
```

## Events

The registry emits typed Soroban events with `#[contractevent]`:

```text
["proof", "reg", proof_id]        => video_hash, tier, status
["proof", "revoke", proof_id]     => status
["issuer", "add", issuer]         => metadata_hash
["issuer", "revoke", issuer]      => {}
["verif", "set", verifier]        => {}
["credroot", "add", root]         => metadata_hash, issued_at
["credroot", "revoke", root]      => {}
["admin", "propose", pending]     => current_admin
["admin", "cancel", pending]      => current_admin
["admin", "accept", new_admin]    => previous_admin
```

## Scripts

PowerShell helpers live in `scripts/`:

```text
add-issuer.ps1
add-credential-root.ps1
register-anonymous-verified.ps1
register-source.ps1
register-seal.ps1
revoke-credential-root.ps1
set-verifier.ps1
schedule-verifier-rotation.ps1
activate-verifier-rotation.ps1
rollback-verifier-rotation.ps1
```
