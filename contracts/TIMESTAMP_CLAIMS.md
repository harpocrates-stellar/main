# Independent Timestamp Claims (#339)

**Version:** 1.0  
**Status:** Active  
**Scope:** `HarpocratesRegistry` (`contracts/contracts/harpocrates-registry`)

On-chain anchoring for off-chain time attestations (`harpocrates-time-attestation/v1`).
The contract stores **commitments and ledger metadata only** — never RFC 3161
token bytes, media, witness values, or private keys.

## Trust hierarchy

| Level | Constant | Meaning |
| --- | --- | --- |
| 0 | `TIMESTAMP_ASSURANCE_NONE` | No usable sources |
| 1 | `TIMESTAMP_ASSURANCE_CLAIMED` | Claimed time only (not used alone on-chain) |
| 2 | `TIMESTAMP_ASSURANCE_OBSERVED` | Reserved for observed-without-independent |
| 3 | `TIMESTAMP_ASSURANCE_INDEPENDENT` | Stellar ledger and/or RFC 3161 commitment |

Anchoring always sets `TIMESTAMP_SOURCE_STELLAR` from `env.ledger()`, so a
successful `anchor_timestamp_claim` yields assurance level 3.

## Source bitflags

| Bit | Constant | Meaning |
| --- | --- | --- |
| `0x01` | `TIMESTAMP_SOURCE_CLAIMED` | Optional claimed capture time present |
| `0x02` | `TIMESTAMP_SOURCE_STELLAR` | Ledger timestamp + sequence recorded |
| `0x04` | `TIMESTAMP_SOURCE_RFC3161` | 32-byte RFC 3161 token commitment present |

## Public interface

```text
anchor_timestamp_claim(actor, proof_id, attestation_digest, claimed_time, rfc3161_commitment) -> TimestampClaim
get_timestamp_claim(proof_id) -> Option<TimestampClaim>
has_independent_timestamp_anchor(proof_id) -> bool
```

### Authorization

`actor` must authenticate and be the registry admin, the proof `source`, or the
proof `issuer`. Otherwise `UnauthorizedTimestampActor` (75).

### Validation

* Proof must exist → else `TimestampClaimNotFound` (73)
* `attestation_digest` must be non-zero → else `InvalidTimestampClaim` (72)
* If `claimed_time > 0`, it must be ≤ ledger time + `MAX_TIMESTAMP_FUTURE_DRIFT_SECS` (300) → else (72)
* Absence of claimed time (`0`) and absence of RFC 3161 commitment (`[0;32]`) are valid
* Re-anchor allowed only as an assurance upgrade or when newly adding RFC 3161 → else `TimestampClaimAlreadyAnchored` (74)

## Storage / migration

Additive `DataKey::TimestampClaim(proof_id)`. No schema version bump; missing
keys mean “no claim” and existing proofs remain valid. Rollback: ignore the
new key; readers treat absence as unanchored.

## Privacy

Events and storage expose proof id, attestation digest, source flags,
assurance, ledger time/sequence, and optional RFC 3161 commitment hash only.
