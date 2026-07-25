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

## Registry State-Machine Fuzzing

Issue #93 adds deterministic state-machine fuzzing for the registry contract in
`contracts/harpocrates-registry/src/test_state_machine.rs`. The harness drives
the real Soroban contract boundary with bounded authorized and adversarial
command streams, including duplicate proof/video/nullifier attempts, wrong
admins, revoked and unknown issuers, invalid and oversized public inputs,
missing verifier/revocation-root cases, replayed non-revocation nullifiers,
admin-transfer replacement/cancellation, TTL expiry, and client-side cancelled,
timed-out, or partial operations that must not reach contract storage.

The oracle is an explicit model of registry storage and status semantics. After
every generated command it checks:

- `Proof`, `Video`, `Nullifier`, `Issuer`, `CredentialRoot`, `Verifier`,
  `ProofTtl`, and `RevocationRoot` query results match the model.
- `get_proof_status` returns `Valid`, `Expired`, `Revoked`, or `NotFound`
  according to the modeled timestamp, TTL, and revocation state.
- rejected transitions return the expected `RegistryError`, emit no contract
  event, and leave storage unchanged.
- successful transitions emit only the existing typed lifecycle events, except
  `set_proof_ttl`, which intentionally has no event.
- each command remains inside a fixed fuzz budget ceiling so hostile inputs stay
  bounded in CI.

The CI corpus is the combination of curated adversarial sequences and fixed
generated seeds in `REGRESSION_SEEDS`; it runs as part of normal
`cargo test --workspace`, so no workflow or dependency upgrade is required.
Local expansion is opt-in:

```bash
cd contracts
HARPOCRATES_REGISTRY_FUZZ_RUNS=128 \
HARPOCRATES_REGISTRY_FUZZ_SEED=0x9300000000000001 \
cargo test -p harpocrates-registry registry_state_machine -- --nocapture
```

When a case fails, the runner shrinks the command stream by deletion and command
simplification, then prints the original seed, the failing step, the shrunk
command list, and the expected/actual error code. It never prints proof bytes,
public input bytes, witnesses, media, credentials, signatures, or raw metadata.
The model uses deterministic slot numbers and synthetic hashes only.

### Compatibility And Rollout

This fuzzing change is test-only. It does not alter exported contract
functions, storage keys, event schemas, proof/public-input formats, verifier
domains, script arguments, or deployed artifact compatibility. There is no
migration. Rollout is enabling the new tests in CI through the existing
contracts workflow. Rollback is removal or revert of the test module and this
documentation; no on-chain repair is needed.

### Signals And Privacy

Production observers continue to rely on existing typed events:

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
["revroot", "set", root]          => {}
["nonrev", "check", root]         => nullifier, revocation_root
```

Failures are observable as deterministic transaction reverts with typed
`RegistryError` codes, not as extra events. The fuzz runner treats failed,
cancelled, timed-out, and partial operations as privacy-sensitive and asserts
that they do not emit success signals or write registry records.

### Threat Assumptions And Limits

The harness assumes Soroban ledger execution is atomic and serializes
concurrent submissions. Concurrent behavior is modeled as interleaved retries
and collisions against the same global `Proof`, `Video`, and `Nullifier` keys.
Client-side timeouts/cancellations are modeled as commands that never submit a
transaction; submitted partial failures are modeled through contract calls that
fail after parsing or authorization gates. Real user evidence, production
secrets, live mainnet behavior, and cryptographic verifier soundness are out of
scope for this test module. Cryptographic vectors remain owned by the Noir and
verifier conformance fixtures.

### Troubleshooting

Use the printed seed and shrunk commands to reproduce a failure with
`HARPOCRATES_REGISTRY_FUZZ_SEED`. If the failure is a budget ceiling only,
compare against `src/test_budget.rs` before raising the fuzz ceiling. If a
contract error changes intentionally, update the model order to match the
contract's exact validation order and keep the fixed seed in the corpus.

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
set_proof_ttl
get_proof_ttl
register_anonymous
register_anonymous_verified
register_source
register_seal
revoke_proof
get_proof
get_by_video
has_nullifier
get_issuer
set_revocation_root
get_revocation_root
check_non_revocation
```

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
```
