# Harpocrates Soroban Deployment

## Current Testnet

```text
HarpocratesRegistry=CCKTQNMBLXZXMWVR2WG4HDDUI3QGJU5LV5NTLFPCB72UITWE5TEDK7BT
SilentWitnessUltraHonkVerifier=CCP2EQPKT5XAYTOARX3LGHNMJ37A6W2WY3H54MRIHEZVTVAZZPUSGZQJ
Admin=GDVRSXIO4SK2KSMUKJTQHMDDHBBFC7NGZZ6WLVOPKAG47GYPYAZCZR7G
Issuer=GAJ3GSKWOCTI2B3ZQRTB7TWYYIX734VJLNGOMSIQSAGRMIGX6SSVMIB4
RegistryWasmHash=a0e9bd49967bae7cb3608166b323514c8ef46832905f56b3c4a5aff41e105e68
```

## Test And Build

```powershell
cargo test
stellar contract build
```

## Deploy Registry

```powershell
stellar contract deploy `
  --wasm target\wasm32v1-none\release\harpocrates_registry.wasm `
  --source harpocrates-admin `
  --network testnet
```

Initialize:

```powershell
stellar contract invoke `
  --id YOUR_REGISTRY_CONTRACT_ID `
  --source harpocrates-admin `
  --network testnet `
  -- init `
  --admin harpocrates-admin
```

## Deploy Silent Witness Verifier

Build Noir artifacts with the pinned verifier-compatible toolchain:

```powershell
.\zk\noir\scripts\build-silent-witness-wsl.ps1
.\zk\noir\scripts\prepare-soroban-verifier-artifacts.ps1
```

Deploy the UltraHonk verifier:

```powershell
stellar contract deploy `
  --wasm C:\Users\enliven\AppData\Local\Temp\rs-soroban-ultrahonk\target\wasm32v1-none\release\rs_soroban_ultrahonk.wasm `
  --source harpocrates-admin `
  --network testnet `
  -- `
  --vk_bytes-file-path C:\Users\enliven\Documents\GitHub\harpocrates-stellar\zk\noir\silent_witness\target\vk_soroban
```

Attach it to the registry:

```powershell
.\scripts\set-verifier.ps1 `
  -ContractId YOUR_REGISTRY_CONTRACT_ID `
  -Admin harpocrates-admin `
  -Verifier YOUR_VERIFIER_CONTRACT_ID
```

## Upgrade Existing Registries To Storage V2

The role-separated registry artifact starts fresh deployments at storage V2 and adds
strict separation between registry-admin and active-issuer authority. Before
using an upgraded contract for issuer operations, the current admin must run
the existing idempotent migration entry point:

```powershell
stellar contract invoke `
  --id YOUR_REGISTRY_CONTRACT_ID `
  --source harpocrates-admin `
  --network testnet `
  -- `
  -- upgrade_storage `
  --admin harpocrates-admin
```

Then query `get_schema_version`; it must return `2`. If the current admin also
has an active legacy issuer record, migration emits `IssuerRevoked` for that
address and `SchemaUpgraded` with `previous=1, current=2`. No proof, nullifier,
credential-root, verifier, metadata, or media state is rewritten. Keep the
admin and issuer keypairs distinct and verify `is_admin`/`is_issuer` before
granting Tier 3 access.

Rollback may restore the previous immutable Wasm, and all stored evidence
remains readable. However, a pre-V2 artifact does not enforce role separation;
if it is active, do not grant issuer authority until the V2 artifact is restored
and `upgrade_storage` is confirmed idempotently complete.

## Register Tiers

Tier 1 requires an active credential root before registration:

```powershell
.\scripts\add-credential-root.ps1 `
  -ContractId YOUR_REGISTRY_CONTRACT_ID `
  -Admin harpocrates-admin `
  -CredentialRoot YOUR_NOIR_PUBLIC_CREDENTIAL_ROOT `
  -MetadataHash YOUR_CREDENTIAL_POLICY_HASH
```

Tier 1, real Noir verified:

```powershell
.\scripts\register-anonymous-verified.ps1 `
  -ContractId YOUR_REGISTRY_CONTRACT_ID `
  -Source harpocrates-admin `
  -VideoHash YOUR_32_BYTE_HEX `
  -MetadataHash YOUR_32_BYTE_HEX `
  -ProofId YOUR_32_BYTE_HEX `
  -PublicInputsPath ..\zk\noir\silent_witness\target\public_inputs `
  -ProofPath ..\zk\noir\silent_witness\target\proof
```

Revoke a Silent Witness credential root:

```powershell
.\scripts\revoke-credential-root.ps1 `
  -ContractId YOUR_REGISTRY_CONTRACT_ID `
  -Admin harpocrates-admin `
  -CredentialRoot YOUR_NOIR_PUBLIC_CREDENTIAL_ROOT
```

Tier 2:

```powershell
.\scripts\register-source.ps1 `
  -ContractId YOUR_REGISTRY_CONTRACT_ID `
  -Source harpocrates-admin `
  -VideoHash YOUR_32_BYTE_HEX `
  -MetadataHash YOUR_32_BYTE_HEX `
  -ProofId YOUR_32_BYTE_HEX
```

Tier 3:

```powershell
.\scripts\add-issuer.ps1 `
  -ContractId YOUR_REGISTRY_CONTRACT_ID `
  -Admin harpocrates-admin `
  -Issuer harpocrates-issuer `
  -MetadataHash YOUR_32_BYTE_HEX

.\scripts\register-seal.ps1 `
  -ContractId YOUR_REGISTRY_CONTRACT_ID `
  -Issuer harpocrates-issuer `
  -VideoHash YOUR_32_BYTE_HEX `
  -MetadataHash YOUR_32_BYTE_HEX `
  -ProofId YOUR_32_BYTE_HEX
```
