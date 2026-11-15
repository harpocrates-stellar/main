# Verification Receipt Comparison Reports

`backend/verification_receipt.py` provides `compare_verification_receipts(first_receipt, second_receipt, first_observation=..., second_observation=...)` (`schema: harpocrates-receipt-comparison-report/v1`) to explain how two verification runs agree or diverge.

## Difference categories

Each detected difference is classified into one of five categories:

- **`evidence_change`:** Underlying canonical digests or identity tier changed (`proofId`, `videoHash`, `metadataHash`, `tier`). Sets `sameEvidence: false` and `overallStatus: "different_evidence"`.
- **`trust_or_revocation_change`:** Verification verdict (`result`), revocation status (`revocationStatus`), issuer/signer trust posture (`trustStatus`), RFC 3161 TSA status (`tsaVerificationStatus`), or `signer.keyId` changed across runs.
- **`chain_observation_change`:** On-chain anchoring or network context changed (`ledgerSequence`, `transactionHash`, `networkPassphrase`, `contractId`, `stellarAnchorCount`).
- **`verifier_environment_change`:** `circuitVersion` or `verifierVersion` changed across runs.
- **`presentation_only`:** Non-substantive differences such as `verifiedAt` re-verification timestamps, ISO-8601 `Z` vs `+00:00` formatting, uppercase vs lowercase hex casing for an identical 32-byte digest, or fresh ECDSA signature bytes over an otherwise unchanged statement (`hasSubstantiveChanges: false`, `overallStatus: "presentation_only_differences"`).
