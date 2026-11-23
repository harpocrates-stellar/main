# Verification Receipt Comparison Report

`ackend/verification_receipt.py` provides `compare_verification_receipts(baseline, candidate)` and `format_receipt_comparison_report(report)` to compare two verification runs and explain what changed between them.

## Purpose

When the same evidence is verified at different times, under different verifiers, or after on-chain/revocation state changes, operators and auditors need to distinguish:

1. **Evidence changes** (`evidenceChanges`) — differences in `receiptId`, `videoHash`, `metadataHash`, `proofId`, `tier`, `circuitVersion`, or `timeAttestation.evidenceDigest`.
2. **Trust observations** (`trustChanges`) — differences in `result` (`verified` vs `unverified`), optional `trust` observation mappings, `timeAttestation` presence, RFC 3161 TSA anchor trust/status, or `timeAttestation` backdating risk.
3. **Revocation observations** (`revocationChanges`) — differences in optional `revocation` observation mappings (such as `status`, `revocationRoot`, or `revokedAt`).
4. **Chain observations** (`chainChanges`) — differences in `networkPassphrase`, `contractId`, `ledgerSequence`, `transactionHash`, or `timeAttestation.stellarAnchors`.
5. **Presentation-only differences** (`presentationChanges`) — differences in `verifiedAt`, `verifierVersion`, non-canonical hex casing (when canonical lowercase digests match), or envelope metadata (`protocol`, `version`, `signature`, `signedAt`, `format`).

## Fail-Closed Validation

```compare_verification_receipts(baseline, candidate)
```

Both `baseline` and `candidate` receipts are validated fail-closed against the canonical unsigned `VerificationReceiptInput` contract before comparison:

- Missing or invalid 32-byte hex digests (`proofId`, `videoHash`, `metadataHash`, `transactionHash`), invalid identity tiers (`silent`, `source`, `seal`), invalid `result` values, or negative `ledgerSequence` values raise `ValueError`.
- Malformed optional `trust`, `revocation`, or `timeAttestation` sections raise `ValueError`.
- Existing `build_verification_receipt()` behavior and unsigned receipt shape are unchanged.

## Conflicting Evidence and Derivative Identifiers

In addition to the per-receipt validation above, comparison is fail-closed with respect to conflicting evidence and derivative identifiers:

- **Conflicting evidence** — when two receipts identify the same canonical evidence but disagree on the derived evidence digests (for example the same `proofId` with different `videoHash` or `metadataHash`, or the same `timeAttestation.evidenceDigest` with different evidence digests), the comparison raises `ValueError` instead of reporting a routine evidence change.
- **Derivative identifiers** — a canonical parent-child statement binding is validated before any unsigned receipt input is returned. Derivative identifiers (such as a `receiptId` derived from the canonical statement) must be consistent with the parent statement they are derived from. A mismatch raises `ValueError`.
- Signing and envelope versioning remain owned by the frontend; the backend only validates and returns canonical unsigned receipt input.

## Example

```python
from verification_receipt import (
    compare_verification_receipts,
    format_receipt_comparison_report,
)

report = compare_verification_receipts(baseline_receipt, candidate_receipt)
print(format_receipt_comparison_report(report))
```
