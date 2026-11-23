### Security
- Capture attestations now fail closed on unknown profile versions, unknown top-level or nested fields, unknown `criticalFields`, missing declared critical fields, unsupported `criticalExtensions`, and platform claims that declare themselves `critical` or `required`. Issuer manifests also reject boolean versions and non-empty `criticalExtensions` (#1092).

### Changed
- Known optional capture metadata is preserved through encode/decode, but is reported as unverified and never raises the attestation trust level (#1092).
