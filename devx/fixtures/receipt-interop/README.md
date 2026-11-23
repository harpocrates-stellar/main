# Verification Receipt Interoperability Fixtures

Deterministic, synthetic test vectors shared between the Python backend (`backend/verification_receipt.py`) and the TypeScript CLI (`cli/src/signed-receipt.ts`) for the `harpocrates-verification-receipt` v1 protocol.

## Contents

- `vectors.json` — Contains:
  - `keys`: Synthetic test-only ECDSA P-256 public JWKs (`kty: "EC"`, `crv: "P-256"`, `x`, `y`). No private keys or real media digests are stored.
  - `keyValidity`: Validity window (`notBefore`, `notAfter`) for the test signing key.
  - `verificationNow`: Deterministic ISO-8601 timestamp used as `now` during verification checks.
  - `validVectors`: Valid signed receipts covering both `verified` (with `ledgerSequence` and `transactionHash`) and `unverified` (with `null` ledger fields) statements, along with their expected `unsignedInput`, `canonicalPayload`, `serializedReceipt`, and `qrPayload`.
  - `mutatedStatements`: Mutated copies of a valid signed receipt (tampered result, digests, tier, network passphrase, ledger sequence, signature bytes, unknown signer key, unsupported protocol/version) that both implementations must explicitly reject.

## Canonical Encoding & Signature Contract

- **Canonical JSON**: Recursive sorted object keys, no insignificant whitespace (`separators=(",", ":")`), UTF-8 encoded.
- **Signature**: `ECDSA_P256_SHA256` over the UTF-8 bytes of the canonicalized unsigned payload (all fields except `signature`), encoded as raw 64-byte IEEE P1363 (`r || s`, 32 bytes each, big-endian) in unpadded base64url.
- **QR Payload**: Unpadded base64url encoding of the UTF-8 bytes of the canonicalized signed receipt (`MAX_RECEIPT_BYTES = 8192`, `MAX_QR_PAYLOAD_BYTES = 4096`).

## Verification

- Backend:
  ```bash
  cd backend
  python -m pytest test_verification_receipt.py
  ```
- CLI:
  ```bash
  cd cli
  npm test -- test/signed-receipt.test.ts
  ```
