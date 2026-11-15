# Verification Receipt Metadata & Extensions

`backend/verification_receipt.py` builds and validates the canonical unsigned verification-receipt input consumed by Harpocrates receipt signers and verifiers.

## Critical and optional receipt metadata extensions

`build_verification_receipt`, `validate_receipt_extensions`, `serialize_receipt_metadata`, and `parse_receipt_metadata` support bounded receipt extension metadata while failing closed on unknown required semantics:

- **Supported critical extensions (`SUPPORTED_CRITICAL_RECEIPT_EXTENSIONS`):**
  - `timeAttestationDigest`: 64-character hex SHA-256 digest of the associated `TimeAttestation` envelope.
  - `revocationEpochBinding`: Object containing non-negative integer `epoch` and 64-character hex `rootHash`.
- **Fail-closed rejection of unknown critical semantics:** Any unrecognized name in `criticalExtensions` (or any inline extension entry declaring `"critical": true` outside `SUPPORTED_CRITICAL_RECEIPT_EXTENSIONS`), missing critical extension payload, malformed critical payload, or unknown top-level receipt field raises `ValueError`.
- **Optional extension preservation:** Compatible non-critical entries in `extensions` (up to `MAX_RECEIPT_EXTENSIONS = 16` keys and `MAX_EXTENSIONS_JSON_BYTES = 2048` bytes, free of private witness/secret/nonce keys) are preserved verbatim across `serialize_receipt_metadata` and `parse_receipt_metadata` round trips. Legacy contexts without `extensions` or `criticalExtensions` omit both keys so existing callers see no envelope change.
