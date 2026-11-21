# Registration auth scoped to proof ownership

`POST /api/proofs/register` accepts two kinds of bearer credential. Ownership is
the Stellar `sourceAddress` the registry already records; no second identity
scheme is introduced.

| Credential | Configured by | May register |
| --- | --- | --- |
| Legacy unscoped key | `REGISTER_API_KEY` | any `sourceAddress` (unchanged) |
| Owner-scoped key | `REGISTER_SCOPED_KEYS` | only proofs whose `sourceAddress` is its owner |

`REGISTER_SCOPED_KEYS` is `<G-address>:<sha256-hex>` entries, comma separated.
Only the SHA-256 **digest** of each token is configured, so a leaked
environment does not yield a usable credential. `REGISTER_API_KEY_EXPIRES`
expires every registration credential. With nothing configured the endpoint is
open, as before.

## Rules a scoped key is held to

1. `sourceAddress` must be present, valid, and equal to the key's owner (`403
   FORBIDDEN`, field `sourceAddress`; malformed addresses are `400`).
2. A proof already registered by a different address cannot be re-registered
   (`403 FORBIDDEN`, field `proofId`). The earliest register event with an
   address is authoritative. The owner is never named in the response.
3. If the ownership lookup fails the request is refused (`503
   DEPENDENCY_UNAVAILABLE`) and nothing is written. It never fails open.

Unchanged responses: `401` with `Authorization header with Bearer token is
required`, `Invalid API key`, or `API key has expired`; `413` for oversize
bodies.

## Trust boundary

Auth and the owner check run **before** `@idempotent`. Replays are keyed on the
request body alone, so running auth after them would let a cached success be
served to a caller who may not register it. Regression tests cover both an
unauthenticated caller and a different owner replaying an identical body.

## Reconciliation checkpoint

`registration_reconcile.py` keeps the last trusted ledger out of the request
path. Its checkpoint records the Stellar network name/passphrase and a
fingerprint of the current deployment configuration. Checkpoints from another
network or deployment are refused on load and on write, and a lower ledger is
rejected, so a restored or stale state directory cannot roll confirmed
registration state backwards.

The checkpoint is local durable state under
`HARPOCRATES_REGISTRATION_RECONCILE_DIR`, separate from the idempotency records
in `idempotency_records`. No request field, credential, or proof material is
written to it.

## Privacy

Failures carry a stable code and a field *name*. Tokens, digests, addresses and
database errors are never logged or returned; auth rejections log a reason
(`missing`, `invalid`, `expired`, `scope_mismatch`, `owner_conflict`) and the
request id only. Malformed `REGISTER_SCOPED_KEYS` fails startup naming the entry
position, not its contents. Credentials are compared in constant time and every
configured credential is checked on every request.

## Migration and compatibility

Additive. Existing `REGISTER_API_KEY` deployments and unauthenticated dev setups
behave as before, and stored `proof_events` rows are untouched (no schema
change). To adopt: generate a token per owner, configure its digest, hand the
token to that owner, then retire the shared legacy key. The legacy key stays
unscoped by design; scoping only constrains the new credentials.

## Rollback

Unset `REGISTER_SCOPED_KEYS` (and redeploy). Scoped tokens then stop working;
the legacy key and stored evidence are unaffected. No data migration.

## Limits

Scoped keys prove *who is calling*, not that the caller controls the private key
of `sourceAddress`; that would need a signed challenge, which is a protocol
change and out of scope here. The ownership check reads `proof_events`, so a
proof with no recorded address is claimable by the first scoped owner to
register it.
