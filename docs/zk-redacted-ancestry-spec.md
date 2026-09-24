# Redacted Derivative Ancestry — Circuit Specification

**Status:** Active draft for `redacted_ancestry/v1`  
**Issue:** #356  
**Compatibility:** Additive. Does not alter `silent_witness/v1` or `revocation_witness/v1` frames.

## 1. Summary

`redacted_ancestry` lets a prover demonstrate that a **redacted** derivative
descends from a committed parent evidence object without revealing the
unredacted parent content, the redaction mask preimage, or credential secrets.

It reuses the lineage operation code `redact = 3` and the graph depth bound
`MAX_ANCESTRY_DEPTH = 4` already enforced by `backend/lineage.py` and the
Soroban lineage entrypoints.

## 2. Public / Private Inputs

| Input | Visibility | Notes |
| --- | --- | --- |
| `parent_hash_hi/lo` | private | Unredacted parent media hash halves |
| `parent_blinding` | private | Binding factor for parent commitment |
| `mask_commitment` | private | Commitment to redaction mask |
| `redaction_seed` | private | Blinding / seed for redaction params |
| `credential_secret` / `nullifier_secret` | private | Identity binders |
| `parent_commitment` | public | Pedersen commitment to parent hash |
| `derivative_digest` | public | Digest of redacted derivative |
| `parameters_digest` | public | Digest of redaction parameters |
| `operation_type` | public | Must equal `3` (redact) |
| `ancestry_root` | public | Statement commitment |
| `nullifier` | public | One-use binder |
| `depth` | public | `1..=4` |
| `domain_tag` | public | Protocol/version/network tag |

## 3. Statement

```
parent_commitment = pedersen([DOMAIN_PARENT_COMMIT, hi, lo, blinding])
parameters_digest  = pedersen([DOMAIN_REDACT_PARAMS, mask, seed])
derivative_digest = pedersen([DOMAIN_DERIVATIVE, hi, lo, parameters_digest, seed])
ancestry_root     = pedersen([DOMAIN_ANCESTRY, parent, derivative, params, OP_REDACT, depth, CIRCUIT_VERSION])
nullifier         = pedersen([DOMAIN_NULLIFIER, cred, null_sec, ancestry_root])
domain_tag        = pedersen([PROTOCOL, VERSION, NETWORK])  // shared with silent_witness
```

Additionally: `operation_type == OP_REDACT`, `depth ∈ [1,4]`, no direct cycle
(`parent_commitment != derivative_digest`), and required fields are non-zero.

## 4. Threat Model & Privacy

**Hidden:** parent hash halves, blinding, mask commitment opening, redaction
seed, credential/nullifier secrets.

**Revealed:** parent commitment, derivative digest, parameters digest,
operation type, ancestry root, nullifier, depth, domain tag.

**Guarantees:** an adversary without the parent opening cannot forge a valid
parent commitment; swapping hash halves or tampering digests fails closed with
stable assert messages that never echo witness bytes.

## 5. Failure Modes

Malformed / unsupported / oversized / cyclic inputs fail with stable messages
(`operation must be redact`, `ancestry depth exceeds limit`,
`ancestry cycle detected`, `* mismatch`, `* must be non-zero`). No real media,
secrets, or witness values are logged by the circuit or fixture corpus.

## 6. Migration / Rollback

- **Migration:** additive circuit package under `zk/noir/redacted_ancestry` (+ helper).
  Existing silent-witness / revocation artifacts and on-chain frames are unchanged.
- **Rollback:** remove the packages from the tree / CIRCUITS list; no stored
  evidence format migration is required.
- **Version:** `CIRCUIT_VERSION = 1` is folded into `ancestry_root`.

## 7. Test Expectations

Focused positive, negative, boundary, and regression coverage lives in
`zk/noir/redacted_ancestry/src/main.nr` (`nargo test`). Synthetic vectors are
listed in `zk/noir/fixtures/redacted_ancestry_vectors.json`. Python schema
guards run via `python -m pytest zk/tools -q` without the Noir toolchain.
