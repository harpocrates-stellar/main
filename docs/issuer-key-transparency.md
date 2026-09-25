# Issuer Key Transparency & Rotation History

## Overview

Harpocrates publishes an independently auditable **issuer key transparency directory** so institutional (Tier 3 / Public Seal) issuer identity and key history can be verified without trusting a single operator view. Private organization details are never required in public artifacts — only opaque identity hashes, key hashes, and policy hashes appear.

This document covers onboarding, compromise response, checkpoint signing, and recovery.

## Trust boundaries

| Artifact | Public | Private (never published) |
| --- | --- | --- |
| `organizationIdentityHash` | Yes | Raw legal / contact identity |
| Active key `publicKeyHash` + `keyId` | Yes | Private signing keys |
| `policyHash` | Yes | Full policy prose if sensitive |
| Append-only lifecycle events | Yes | Human reason text (use `reasonHash`) |
| Signed directory checkpoints | Yes | Operator credentials |

## Canonical issuer manifest

Each issuer publishes a versioned manifest (`protocol: harpocrates-issuer-key-transparency`, `version: 1`) containing:

- Organization identity hash
- Issuer Stellar address
- Active keys (algorithm, validity window, status)
- Policy hash
- Predecessor / successor manifest links for rotation history
- Detached `signatureHash` (signature over the unsigned canonical body)

Canonical encoding is deterministic JSON (`sort_keys`, compact separators). Digest = SHA-256 of the unsigned body.

## Append-only lifecycle events

Event types: `activation`, `rotation`, `compromise`, `retirement`, `checkpoint`.

Each event carries a monotonic `sequence`, `previousEventHash` chain link, and opaque hashes only. Directory rebuild from the authoritative event log is deterministic: the same ordered events always yield the same key statuses and Merkle-style `treeHeadHash`.

## Directory checkpoints

A checkpoint binds:

- `treeHeadHash` — head of the event hash chain
- `eventCount`
- `manifestHash` — current published manifest
- `organizationIdentityHash`
- Optional `signatureHash` from the checkpoint signer

Clients detect **split views** (diverging heads at the same count), **rollback** (shrinking `eventCount` after a higher head was observed), **stale checkpoints**, **broken rotation links**, **conflicting manifests**, and **compromised keys**.

## Caching & freshness (fail-closed)

| Mode | Max age | Behavior |
| --- | --- | --- |
| Standard | 24h (`DEFAULT_FRESHNESS_SECONDS`) | Reject stale cache on verify |
| High-assurance seals | 1h (`HIGH_ASSURANCE_FRESHNESS_SECONDS`) | **Fail-closed** — refuse seal acceptance if checkpoint is stale |

Use `require_fresh_checkpoint(..., high_assurance=True)` before accepting high-assurance Public Seal evidence.

## Historical signatures after rotation

Key rotation sets `validUntil` on the predecessor. Signatures whose timestamp falls inside the key’s validity window remain valid after rotation. Compromised keys similarly retain validity for pre-compromise timestamps; verifiers must surface compromise status for post-compromise risk decisions.

## Operational procedures

### Onboarding an issuer

1. Derive `organizationIdentityHash` from the institution’s certified identity package (offline); do not upload raw PII to the directory.
2. Activate the first signing key (`activation` event, sequence 0).
3. Publish the initial signed manifest (no predecessor).
4. Sign and distribute a directory checkpoint.
5. Configure clients with the checkpoint signer’s public key and freshness policy.

### Compromise response

1. Emit a `compromise` event for the affected `keyId` with an opaque `reasonHash`.
2. Activate a replacement key (`activation` or `rotation` from a still-trusted predecessor if available).
3. Publish a new manifest linking `predecessorManifestHash`.
4. Sign a fresh checkpoint and push to all mirrors.
5. Revoke the issuer on-chain via `revoke_issuer` if institutional standing is withdrawn.
6. Notify relying parties; historical pre-compromise seals remain cryptographically valid but should be risk-flagged.

### Checkpoint signing

1. Rebuild the directory from the authoritative event log.
2. Confirm `treeHeadHash` and `manifestHash` match local state.
3. Canonicalize the unsigned checkpoint; sign; set `signatureHash`.
4. Publish to primary + at least one independent mirror.
5. Clients gossip-compare checkpoints to detect equivocation.

### Recovery

1. If a mirror serves a divergent head, prefer the view that extends a previously observed checkpoint without rollback.
2. Re-fetch the full event log from the authoritative source and `rebuild_directory`.
3. If the signer key is lost, rotate the checkpoint signer out-of-band and publish a recovery checkpoint attested by admin + remaining mirrors (document the ceremony in the change log).
4. Roll back application feature flags without rewriting the append-only log; never delete events.

## Privacy guarantees

- No email, legal name, phone, address, or employee identifiers in manifests, events, or checkpoints.
- Reason text for compromise/retirement stays off-directory; only `reasonHash` is published.
- Observability metrics should log event counts and freshness age — never raw organization payloads.

## Compatibility

- Module: `backend/issuer_key_transparency.py`
- Tests: `backend/test_issuer_key_transparency.py`
- On-chain issuer allowlist (`add_issuer` / `revoke_issuer`) remains the standing authority; this directory adds auditable key history beside it, not a parallel allowlist.
- Schema version is explicit (`version: 1`); future versions require migration notes in this document.

## Threat model notes

Adversaries may attempt split-view presentation, checkpoint rollback, stale cache reuse for high-assurance seals, broken rotation chains, conflicting manifests at one head, or continued use of compromised keys. The test suite encodes these failure paths; operators should alert on any consistency error returned by `verify_checkpoint_consistency` / `detect_rollback`.
