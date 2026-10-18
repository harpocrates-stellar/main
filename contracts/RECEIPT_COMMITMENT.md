# Receipt Digest Commitment (#337)

The registry anchors an off-chain **signed verification receipt** by storing
only its digest. The receipt itself — its JSON, its signature, the media it
describes — never touches the chain. A receipt-signing key attests to the
digest on-chain with a P-256 signature over a domain-separated preimage that
binds the registry deployment, the proof, and the digest together.

```text
receipt_digest = sha256(canonical_json(signed_verification_receipt))
```

## Canonical JSON

Both `cli/src/signed-receipt.ts` and `frontend/src/verificationReceipt.ts`
produce the digest over the same canonicalization: UTF-8 JSON with object keys
sorted lexicographically, no insignificant whitespace, arrays preserved in
order. The contract never sees this JSON — it only stores and verifies the
32-byte digest.

## Attestation preimage

Before signing, the receipt-signing key signs the digest of a fixed
129-byte preimage (`RECEIPT_ATTEST_PREIMAGE_LEN`), not the digest alone:

| Range        | Contents                                                   |
|--------------|------------------------------------------------------------|
| `[0..29)`    | `RECEIPT_ATTEST_DOMAIN` = `"harpocrates:receipt-digest:v1"` |
| `[29..65)`   | ScAddress XDR of the calling contract — 4-byte big-endian discriminant `1` \|\| 32-byte contract id |
| `[65..97)`   | `proof_id`                                                  |
| `[97..129)`  | `receipt_digest`                                            |

The attestation digest is `sha256(preimage)`; the host verifies the signature
against it with `secp256r1_verify` (`verify_prehash` semantics — the 32 bytes
are the message hash, not re-hashed). Binding the contract address means an
attestation minted for one deployment cannot be replayed against another
registry that happens to store the same signer key, and binding `proof_id`
and `receipt_digest` stops a valid signature from being redirected to a
different proof or a different digest.

> Note: `Address::to_xdr` serializes an `Address` as an ScVal (40 bytes =
> 4-byte ScVal type tag + the ScAddress arm). The preimage takes the last 36
> bytes — the ScAddress arm only. `test_receipt::receipt_attestation_preimage_binds_scaddress_xdr`
> pins this layout.

A bad signature traps at the host crypto boundary (`Error(Crypto,
InvalidInput)` on a direct call; `Error(Context, InvalidAction)` through a
`try_` invocation): the call reverts deterministically and writes nothing.
The one-commitment slot is not consumed by a failed attempt.

## Entry points

| Function | Auth | Notes |
|----------|------|-------|
| `add_receipt_signer(admin, public_key)` | admin only | At most `MAX_RECEIPT_SIGNERS` (8) active keys. Re-adding an active key is a silent no-op; re-adding a revoked key reactivates it (consuming a freed slot). |
| `revoke_receipt_signer(admin, public_key)` | admin only | Revocation is recorded, not deleted; frees one slot; idempotent without a second event. |
| `commit_receipt_digest(caller, proof_id, receipt_digest, public_key, signature)` | admin, or the proof's own tier-2 source / tier-3 issuer; tier 1 is admin-only | One immutable commitment per proof. |
| `get_receipt_commitment(proof_id)` | public | Returns `None` when nothing was committed. |
| `get_receipt_signer(public_key)` | public | Distinguishes never-registered (`None`), active, and revoked. |

### Commit guards (in order)

1. `caller.require_auth()`.
2. Proof exists (`ReceiptProofNotFound`).
3. Caller is the admin or the proof's own tier-2 source / tier-3 issuer;
   tier 1 carries no on-chain identity and is admin-only (`Unauthorized`).
4. At most one digest per proof: an identical retry returns the stored record
   with no event; a different digest is rejected (`ReceiptAlreadyCommitted`).
5. Proof status is `Valid` (`ReceiptProofUnavailable` when expired or
   revoked). Because idempotency is checked first, retrying the *stored*
   digest after revocation still returns the record — commitments are
   historical anchors, not validity assertions — while a *new* digest on a
   revoked proof fails with `ReceiptAlreadyCommitted`.
6. Non-zero digest (`InvalidReceiptDigest`).
7. Registered (`ReceiptSignerUnknown`) and active (`ReceiptSignerRevoked`)
   receipt signer.
8. P-256 attestation verifies (host crypto boundary; no state written).

## Errors

| Code | Name | Meaning |
|------|------|---------|
| `#3`  | `Unauthorized` | Non-admin signer management, or a non-subject commit caller |
| `#68` | `ReceiptProofNotFound` | No such `proof_id` |
| `#69` | `ReceiptProofUnavailable` | Proof expired or revoked |
| `#70` | `ReceiptAlreadyCommitted` | A different digest is already committed for this proof |
| `#71` | `InvalidReceiptDigest` | All-zero digest |
| `#72` | `ReceiptSignerUnknown` | Public key not on the allowlist |
| `#73` | `ReceiptSignerRevoked` | Allowlist key was revoked |
| `#74` | `ReceiptSignersSaturated` | 8 active keys already |

## Events

| Event | Topics | Data fields |
|-------|--------|-------------|
| `ReceiptDigestCommitted` | `["receipt", "commit", proof_id]` | `receipt_digest`, `tier`, `public_key`, `committed_at` |
| `ReceiptSignerAdded` | `["signer", "add", public_key]` | `added_at` |
| `ReceiptSignerRevocation` | `["signer", "revoke", public_key]` | `revoked_at` |

Events expose only the digest and bounded metadata — never receipt contents.

## Pause interaction

Receipt signer management and receipt commits are deliberately **not** gated
by any registration pause domain: pause exists to stop new evidence entering
the registry during an incident, while anchoring and auditing existing
proofs must keep working. See `contracts/EMERGENCY_PAUSE.md`.

## Storage and compatibility

Additive persistent keys only — `ReceiptCommitment(proof_id)`,
`ReceiptSigner(public_key)`, `ReceiptSignerCount` — with typed events. No
existing key, event, or entry-point signature changes, so
`contract_interface_version` stays `1` and no migration is required; older
wasm simply ignores the new keys.

## Test vectors

`src/test_receipt.rs` pins the whole contract against offline-generated
P-256 vectors for a fixed contract id
(`CCWLMGB2F6O6VG7BQHKDUUL4R2WOAZ62TGOMU2TESZOKGBO6PMLTANC3` /
`acb6183a…b1730`, registered via `env.register_at`). The signatures were
produced with raw-prehash ECDSA (IEEE-P1363, low-S) so they match the host's
`verify_prehash`; no private key is committed — the keypair was discarded
after signing. Cross-contract, cross-proof, cross-digest, wrong-key, and
tampered-signature vectors prove each binding independently.
