# RFC 3161 chain fixtures

Synthetic X.509 certificate chains for offline CI validation of TSA trust
paths. Certificates are generated for tests only — they are not production TSA
material and contain no private keys, media, witnesses, or credentials.

Each JSON document is consumed by `devx/validate_rfc3161_chains.py`.

## Schema

- `schemaVersion`: must be `1`
- `chain`: base64 DER certificates, leaf first
- `trustRoots`: base64 DER trusted roots
- `revokedSerials`: lowercase hex serials (offline CRL/OCSP stand-in)
- `atTime`: ISO-8601 evaluation time (typically RFC 3161 genTime)
- `expect`: optional assertion for the validator CLI
