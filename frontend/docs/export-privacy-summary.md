# Pre-Export Privacy Summary

Before downloading an embedded evidence artifact from Evidence Studio, the **Export privacy summary** panel lists the metadata classes and public identifiers included in the exported package and gates export when newly exposed sensitive fields require explicit acknowledgement.

## Included Metadata Classes

Every valid evidence package includes:

- **Container & file metadata** (`container_file`): Sanitized output filename and embedded MP4 container metadata.
- **Cryptographic digests** (`cryptographic_digests`): SHA-256 commitments (`sourceHash`, `videoHash`, `metadataHash`, `proofId`).
- **Packaging timestamp** (`packaging_timestamp`): Local packaging timestamp.
- **Identity tier metadata** (`identity_tier`): Selected identity tier (`silent`, `source`, or `seal`).

Optional metadata classes appear only when present on the package:

- **Silent Witness proof metadata** (`silent_witness_proof`): Zero-knowledge nullifier and credential root when a Silent Witness proof is attached.
- **Time attestation metadata** (`time_attestation`): External time attestation anchor metadata when attached.

## Public Identifiers & Sensitive-Field Acknowledgement

- Baseline `silent` tier exports (without attached Silent Witness proof or time attestation) expose no sensitive identity fields and are immediately ready to export with no extra acknowledgement step.
- Explicit acknowledgement is required **only** for newly exposed sensitive fields:
  - `publicIdentity`: Exposed on `source` (Consistent Source) and `seal` (Public Seal) tiers, linking the artifact to a Stellar account.
  - `silentWitness.nullifier` and `silentWitness.credentialRoot`: Exposed when a Silent Witness proof is attached.
  - `timeAttestation`: Exposed when external time attestation metadata is attached.
- Once a sensitive field key is acknowledged in the current Studio session (`useEvidence().acknowledgedSensitiveFields`), it does not re-prompt unless a different, newly exposed sensitive field is introduced.

## Fail-Closed Boundaries & Privacy Guarantees

`buildExportPrivacySummary` (`frontend/src/exportPrivacySummary.ts`) is pure, deterministic, and fail-closed:

- Returns `MISSING_EVIDENCE`, `MALFORMED_EVIDENCE`, `UNSUPPORTED_TIER`, or `OVERSIZED_PAYLOAD` (over 64 KiB) with stable operator messages; any error blocks artifact export.
- Never includes credential seeds, nullifier seeds, private keys, raw witness proof bytes, or media object URLs.
- Never leaks the connected wallet address into `silent` tier public identifiers.
