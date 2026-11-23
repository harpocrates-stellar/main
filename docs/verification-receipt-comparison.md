# Verification Receipt Comparison Report

`backend/verification_receipt.py` provides `compare_verification_receipts(baseline, candidate)` and `format_receipt_comparison_report(report)` to compare two verification runs and explain what changed between them.

## Purpose

When the same evidence is verified at different times, under different verifiers, or after on-chain/revocation state changes, operators and auditors need to distinguish:

1. **Evidence changes** (`evidenceChanges`) — differences in `videoHash`, `metadataHash`, `proofId`, `tier`, `circuitVersion`, or `timeAttestation.evidenceDigest`.
2. **Trust observations** (`trustChanges`) — differences in `result` (`verified` vs `unverified`), optional `trust` observation mappings, `timeAttestation` presence, RFC 3161 TSA anchor trust/status, or `timeAttestation` backdating risk.
3. **Revocation observations** (`revocationChanges`) — differences in optional `revocation` observation mappings (such as `status`, `revocationRoot`, or `revokedAt`).
4. **Chain observations** (`chainChanges`) — differences in `networkPassphrase`, `contractId`, `ledgerSequence`, `transactionHash`, or `timeAttestation.stellarAnchors`.
5. **Presentation-only differences** (`presentationChanges`) — differences in `verifiedAt`, `verifierVersion`, non-canonical hex casing (when canonical lowercase digests match), or envelope metadata (`protocol`, `version`, `signature`, `signedAt`, `format`).

## Fail-Closed Validation

Both `baseline` and `candidate` receipts are validated fail-closed against the canonical unsigned `VerificationReceiptInput` contract before comparison:

- Missing or invalid 32-byte hex digests (`proofId`, `videoHash`, `metadataHash`, `transactionHash`), invalid identity tiers (`silent`, `source`, `seal`), invalid `result` values, or negative `ledgerSequence` values raise `ValueError`.
- Malformed optional `trust`, `revocation`, or `timeAttestation` sections raise `ValueError`.
- Existing `build_verification_receipt()` behavior and unsigned receipt shape are unchanged.

## Example

```python
from verification_receipt import (
    compare_verification_receipts,
    format_receipt_comparison_report,
)

report = compare_verification_receipts(baseline_receipt, candidate_receipt)
print(format_receipt_comparison_report(report))
```
