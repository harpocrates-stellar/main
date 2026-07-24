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
add_credential_root
revoke_credential_root
get_credential_root
add_issuer
revoke_issuer
set_verifier
get_verifier
register_anonymous
register_anonymous_verified
register_source
register_seal
revoke_proof
get_proof
get_by_video
has_nullifier
get_issuer
get_proof_status
get_proof_history
get_proof_history_count
verify_proof
expire_proof
correct_proof
```

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
["proof", "history", proof_id]    => action, timestamp, actor, reason_code
```

## Lifecycle History (#90)

Every proof carries an append-only history of lifecycle transitions. History
entries are privacy-safe: they contain only `proof_id`, `action`, `timestamp`,
`actor`, and `reason_code`. No `video_hash`, `metadata_hash`, `nullifier`, or
proof bytes are ever stored in history or emitted in history events.

### Actions

```text
Registered  = 1
Verified    = 2
Revoked     = 3
Expired     = 4
Corrected   = 5
TtlUpdated  = 6
```

### Bounds

- `MAX_HISTORY_ENTRIES_PER_PROOF = 256` caps total entries per proof.
- `MAX_HISTORY_LIMIT = 50` caps the maximum number of entries returned by a
  single `get_proof_history` call.

### Query

```text
get_proof_history(proof_id, offset, limit) -> Vec<ProofHistoryEntry>
get_proof_history_count(proof_id) -> u32
```

`offset` is zero-based. `limit` must be `<= MAX_HISTORY_LIMIT`. Entries are
returned in chronological order.

### State Transitions

| Function | Authorization | Effect |
|----------|---------------|--------|
| `verify_proof` | Admin | Records a verification event in history. |
| `expire_proof` | Admin | Sets `status = STATUS_EXPIRED` and records history. Rejects if already expired. |
| `correct_proof` | Admin | Updates `metadata_hash` and records history. Rejects if metadata is unchanged. |

All registration functions and `revoke_proof` automatically record history.

### Privacy Properties

- History entries contain no sensitive proof material.
- Reason codes are bounded `u32` values (`0..=255`); free-text reasons are not accepted.
- The `actor` field records the address that authorized the transition, or `None` for anonymous registrations.
- On-chain history events use the topic `["proof", "history", proof_id]` so indexers can filter without reading contract storage.

### Backward Compatibility

Proofs registered before this feature have zero history entries. `get_proof_history`
returns an empty vector for such proofs. The existing `ProofRecord` schema is unchanged.

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
```
