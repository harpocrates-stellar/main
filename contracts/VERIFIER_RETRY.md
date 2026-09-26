# Verifier Failure Retry Semantics

**Version:** 1.0 (`hpx-vr/1`)  
**Status:** Active  
**Scope:** `HarpocratesRegistry` external verifier invoke path (`verify_external_proof`)  
**Issue:** #326

## Goal

Define stable, privacy-preserving retry semantics for verifier-path failures so
clients, operators, and the registry share one protocol truth.

## Failure classes

| Class | Meaning | Client retry? | In-tx retry? |
| --- | --- | --- | --- |
| `malformed` | Codec / framing failure (length, padding, non-canonical, domain, undersize) | No | No |
| `oversized` | Proof blob above `MAX_PROOF_BYTES` | No | No |
| `expired` | Credential / proof TTL expired | No | No |
| `revoked` | Credential root revoked | No | No |
| `unsupported` | Unknown / inactive schema or domain | No | No |
| `permanent_reject` | Verifier aborted or returned a contract error | No | No |
| `dependency_failure` | Verifier missing / misconfigured / host edge | Yes (after remediation) | Yes, up to cap |
| `retry_exhausted` | In-tx dependency retries consumed | Yes (after remediation) | No |

Constants:

| Name | Value |
| --- | --- |
| `RETRY_SEMANTICS_ID` | `hpx-vr/1` |
| `MAX_VERIFIER_INVOKE_ATTEMPTS` | `3` |

## On-chain behavior

`verify_external_proof`:

1. Invokes `verify_proof(public_inputs, proof)` on the configured verifier.
2. On success, returns normally (no event, no storage write).
3. On permanent reject (`InvokeError::Abort` or contract error), panics with
   `InvalidProof` (`7`). The same proof material must not be retried.
4. On classified dependency failure, retries in-transaction while
   `attempt < MAX_VERIFIER_INVOKE_ATTEMPTS`, then panics with
   `VerifierRetryExhausted` (`69`).
5. Never logs or emits proof bytes, public-input witnesses, media, or keys.

New append-only errors:

| Code | Name |
| --- | --- |
| `68` | `VerifierDependencyFailure` |
| `69` | `VerifierRetryExhausted` |

## Public helpers

```text
get_verifier_retry_policy() -> (semantics_id_hash_prefix, max_attempts)
is_registry_error_retryable(code: u32) -> bool
classify_registry_error_class(code: u32) -> u32
```

These are read-only and safe to call while domains are paused.

## Migration / rollback

- Additive: no storage keys, no schema version bump, no rewrite of proof /
  nullifier / video records.
- Rolling back to a pre-#326 wasm drops the helpers and the in-tx retry loop;
  existing error codes `1..67` keep their meaning.
- Compatible callers that only handle `InvalidProof` continue to work for the
  permanent-reject path.

## Threat notes

- Retrying a `permanent_reject` cannot turn an invalid proof into a valid one
  and only wastes budget; clients must fail closed.
- Dependency retries are bounded so a hostile verifier cannot force unbounded
  in-tx re-entry.
- Failure telemetry must stay free of sensitive payloads (see threat model T4/T5).
