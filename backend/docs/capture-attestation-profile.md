# Harpocrates Capture-Device Attestation Profile

**Version:** 1.0.0-draft
**Status:** Proposed
**Date:** 2026-07-26

## 1. Overview

This document defines a platform-neutral profile for binding optional
capture-session attestation to evidence without exposing a stable device
identifier. The profile is designed to be layered on top of the existing
Harpocrates metadata envelope and proof-manifest conventions.

## 2. Design Principles

1. **Privacy-first:** No raw device serial, advertising ID, account
   identity, or location is ever required.
2. **Per-session identifiers:** Scoped to a single capture session or
   relying-party interaction. Not linkable across sessions.
3. **Graceful degradation:** Unknown platforms and unavailable attestation
   remain interoperable. The absence of attestation is explicit rather
   than silently ignored.
4. **Deterministic verification:** All encodings are canonical and
   versioned so verifiers can reproduce byte-identical digests.
5. **No parallel truth sources:** Attestation data flows through the
   existing metadata manifest, proof, and Soroban contract boundaries.

## 3. Trust Levels

| Level | Name | Description |
|-------|------|-------------|
| 0 | `unattested` | No device attestation was performed. |
| 1 | `software_attested` | Application-level assertion only (e.g., signed by the app). |
| 2 | `hardware_backed` | Hardware-backed key attestation (Android KeyStore, iOS Secure Enclave, TPM). |
| 3 | `rooted_or_emulated` | Platform indicates rooting, jailbreaking, or emulation. |
| 4 | `unverifiable` | Attestation was attempted but could not be verified. |

## 4. Canonical Attestation Object

### 4.1 Schema

```json
{
  "attestation": {
    "version": 1,
    "profile": "harpocrates-capture-attestation/v1",
    "trustLevel": 2,
    "captureNonce": "32-byte-hex",
    "appIdentity": {
      "packageName": "com.example.camera",
      "versionCode": "42",
      "buildFingerprint": "optional-platform-build-fingerprint",
      "signingDigest": "sha256-hex-of-signing-cert"
    },
    "secureTime": {
      "unixMs": 1721971200000,
      "source": "hardware_clock",
      "driftMs": 150
    },
    "cameraPipeline": {
      "sensorOrientation": 90,
      "hasWatermark": false,
      "claimedIntegrity": "raw_sensor"
    },
    "deviceCommitment": "32-byte-hex",
    "privacyScope": "per_session",
    "evidenceDigestBinding": "32-byte-hex",
    "platformClaims": {},
    "criticalFields": ["secureTime"],
    "criticalExtensions": ["harpocrates.evidence-binding/v1"],
    "optionalMetadata": {"captureMode": "still_burst"}
  }
}
```

### 4.2 Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | integer | Yes | Schema version (1). |
| `profile` | string | Yes | Fixed value `harpocrates-capture-attestation/v1`. |
| `trustLevel` | integer | Yes | 0–4 per the trust-level table above. |
| `captureNonce` | hex32 | Yes | Server-provided random nonce, single-use per capture. |
| `appIdentity` | object | Yes | Application and build identity claims. |
| `appIdentity.packageName` | string | Yes | Reverse-domain app identifier. |
| `appIdentity.versionCode` | string | Yes | App version/build code. |
| `appIdentity.buildFingerprint` | string | No | Platform build fingerprint (optional). |
| `appIdentity.signingDigest` | hex32 | No | SHA-256 of the app signing certificate. |
| `secureTime` | object | No | Independently verifiable time evidence. |
| `secureTime.unixMs` | integer | Yes | Unix timestamp in milliseconds. |
| `secureTime.source` | string | Yes | `hardware_clock`, `ntp_synchronized`, `platform_clock`. |
| `secureTime.driftMs` | integer | Yes | Estimated drift from ground truth in ms. |
| `cameraPipeline` | object | No | Claims about the camera capture pipeline. |
| `cameraPipeline.sensorOrientation` | integer | No | EXIF orientation value (1-8). |
| `cameraPipeline.hasWatermark` | boolean | No | Whether a visible watermark was applied. |
| `cameraPipeline.claimedIntegrity` | string | No | `raw_sensor`, `processed`, `screen_capture`, `unknown`. |
| `deviceCommitment` | hex32 | Yes | HMAC-SHA256(nonce, perSessionDeviceKey). |
| `privacyScope` | string | Yes | `per_session`, `per_relying_party`, `per_device_group`. |
| `evidenceDigestBinding` | hex32 | Yes | SHA-256 of the evidence payload this attestation describes. |
| `platformClaims` | object | No | Platform-specific transparent claims (e.g. SafetyNet/Play Integrity raw JWTs). An entry must not set `critical` or `required` to a non-false value. |
| `criticalFields` | array of strings | No | Known field names this profile requires the verifier to understand. A declared field must be present and non-empty. |
| `criticalExtensions` | array of strings | No | Extension identifiers whose semantics are required. Only `harpocrates.evidence-binding/v1` and `harpocrates.per-session-commitment/v1` are understood by V1. |
| `optionalMetadata` | object | No | Allowlisted display metadata (string values length-bounded). Preserved and reported as unverified; it never raises the trust level. |

### 4.3 Canonical Encoding

The attestation object is serialised using the same canonical JSON
convention used throughout Harpocrates:

```
JSON.stringify(attestation, sortedKeys, noWhitespace).encode('utf-8')
```

The canonical hash is then:

```
SHA-256(canonical_bytes)
```

### 4.4 Profile Version and Critical Declarations

Decoders fail closed when they cannot understand what a profile requires:

- `version` must be the integer `1`; booleans and non-integer values are
  rejected rather than coerced. `profile` must equal
  `harpocrates-capture-attestation/v<version>`.
- Unknown top-level fields, and unknown fields inside `appIdentity`,
  `secureTime`, and `cameraPipeline`, are rejected. Known optional fields remain
  compatible and round-trip unchanged.
- Every name in `criticalFields` must be a known attestation field, and the
  declared field must be present and non-empty. Unknown required fields raise
  `AttestationProfileValidationError` (a `ValueError` subclass).
- Every identifier in `criticalExtensions` must be understood by this verifier.
  An unsupported identifier raises `AttestationProfileValidationError` instead
  of being ignored.
- `platformClaims` may carry platform evidence, but an entry that sets
  `critical` or `required` to any non-false value is rejected. Only
  `criticalFields` and `criticalExtensions` can declare verifier requirements.
- `optionalMetadata` accepts only known scalar fields (`attestationBackend`,
  `captureMode`, `lensProfile`, `osPatchLevel`, `sensorModelClass`). String
  values are length-bounded; booleans and integers are preserved. It is
  preserved for display and policy input, but
  `inspect_attestation_profile_metadata` reports both
  `optionalMetadataVerified: false` and `broadTrustAssumed: false`.

## 5. Integration Points

### 5.1 Verification Assurance Response

`POST /api/capture-attestation/verify` retains its existing `valid`,
`attestation_hash`, and `checks` fields and adds an `assurance` object with the
stable schema identifier `harpocrates-capture-assurance/v1`:

```json
{
  "schema": "harpocrates-capture-assurance/v1",
  "deviceClaims": {
    "status": "reported",
    "trustLevel": { "code": 2, "label": "hardware_backed" },
    "claimedIntegrity": "raw_sensor"
  },
  "issuerCertification": {
    "status": "not_evaluated",
    "reasonCode": "issuer_transparency_not_checked"
  },
  "captureVerification": {
    "verifiedProperties": ["attested_digest_matches_request"],
    "failedProperties": [],
    "notEvaluatedProperties": [
      "device_commitment_matches_supplied_key",
      "evidence_content_digest",
      "secure_time",
      "camera_pipeline_integrity",
      "platform_claims"
    ]
  }
}
```

`deviceClaims` values, including `trustLevel` and `claimedIntegrity`, are
device-reported claims and do not establish issuer certification. The endpoint
sets issuer certification to `not_evaluated`; it does not query the issuer
directory. `captureVerification` lists only checks actually performed as
verified or failed. `attested_digest_matches_request` compares two supplied
digest values; the endpoint does not hash the evidence bytes, so
`evidence_content_digest` remains not evaluated. Secure-time,
camera-pipeline-integrity, and platform claims also remain not evaluated. A
caller-supplied device key can verify the per-session commitment but does not
elevate a device claim to institutional trust. The `assurance` object is
additive; the v1 attestation encoding and existing response fields remain
unchanged.

### 5.2 Metadata Envelope

The attestation object is included as an **optional** `attestation` field
in the Harpocrates metadata envelope embedded in video files:

```json
{
  "protocol": "harpocrates",
  "version": 1,
  "tier": "source",
  "sourceHash": "...",
  "proofId": "...",
  "timestamp": "2026-07-24T12:00:00.000Z",
  "attestation": {
    "version": 1,
    "profile": "harpocrates-capture-attestation/v1",
    "trustLevel": 2,
    ...
  }
}
```

The canonical metadata hash (used for on-chain registration) covers
the entire metadata including the attestation sub-object, so tampering
with attestation data is detectable on-chain.

### 5.3 Proof Manifest

The attestation status is reflected in the proof manifest as an
informational field:

```json
{
  "contractId": "...",
  "metadataHash": "...",
  "network": "...",
  "proofId": "...",
  "protocol": "harpocrates",
  "sourceHash": "...",
  "tier": "...",
  "timestamp": "...",
  "transactionRef": "...",
  "version": 1,
  "videoHash": "...",
  "attestationTrustLevel": 2
}
```

### 5.4 CLI and SDK

The `@harpocrates/cli` package includes attestation validation utilities
that verify the attestation binding against the evidence digest.

### 5.5 Soroban Contract

No on-chain changes are required. The attestation is fully verified
off-chain and its integrity is covered by the metadata hash that is
already stored in the contract's proof records.

## 6. Threat Model

### 6.1 Adversarial Capabilities

| Threat | Mitigation |
|--------|------------|
| Replay attack (reuse attestation for different evidence) | `evidenceDigestBinding` ties attestation to a specific piece of evidence. |
| Cloned attestation (copy from another device) | `captureNonce` is single-use, server-provided. |
| Stale nonce (reuse old nonce) | Server enforces nonce expiry; `secureTime` provides freshness evidence. |
| Cross-scope correlation | `privacyScope` limits linkability; per-session keys prevent long-term tracking. |
| Downgrade attack (strip attestation) | Absence of attestation results in `unattested` level; verifier policy decides acceptance. |
| Wrong evidence digest | `evidenceDigestBinding` must match the SHA-256 of the actual evidence. |
| Unknown platform | Handled gracefully; `trustLevel: 4` (`unverifiable`). |

### 6.2 Platform Trust Assumptions

- **Hardware-backed (Level 2):** Trusts the device's hardware key store
  and the platform's attestation API (Android KeyStore, iOS Secure Enclave).
- **Software-attested (Level 1):** Trusts the application's signing key
  and the integrity of the app binary.
- **Unattested (Level 0):** No trust assumptions. The verifier must
  evaluate evidence on its own merits.

## 7. Test Vectors

Reference implementations and test vectors are maintained in:

- `backend/test_capture_attestation.py` — Python reference implementation.
- `backend/test_attestation_profile_validation.py` — profile version and
  critical-declaration rejection cases.
- `cli/test/capture-attestation.test.ts` — Node.js test vectors.

## 8. Migration and Compatibility

- **Versioning:** The `profile` string includes a `/v1` suffix. Future
  versions will use `/v2`, etc.
- **Backward compatibility:** V1 verifiers MUST reject unknown profile
  versions and unknown required fields. Unknown top-level or nested fields are
  rejected too, so introducing a new optional field requires updating the
  verifier allow-list in the same release.
- **Critical declarations:** A profile that requires an unknown field or
  extension must be rejected, never downgraded to an unattested result silently.
- **Schema changes:** Require bumping the `version` number in the
  attestation object.

## 9. Out of Scope

- Live production deployment of attestation capture.
- Mobile app implementation (this is a protocol specification).
- Real credentials or sensitive media.
- Integration with specific hardware attestation SDKs.
