# Time Attestation & TSA Incident Exports

`backend/time_attestation.py` models the canonical `harpocrates-time-attestation/v1` envelope combining claimed capture time, backend observed time, Stellar ledger anchors, and RFC 3161 TSA anchors.

## Redacting external TSA URLs in private incident exports

When exporting time-attestation diagnostics for incident triage, call `export_time_attestation_for_incident(attestation)` (or `redact_tsa_url(raw_url)` directly):

- **Credential & query sanitization:** Strips embedded HTTP userinfo (`user:password@...`), URL fragments, path-embedded bearer tokens, and sensitive or unrecognized query values (`api_key`, `token`, `secret`, `sig`, `authorization`, etc.) while retaining safe non-secret query metadata (`alg`, `hash`, `policy`, `profile`, `version`).
- **Safe provider identity:** Preserves `providerIdentity` (`scheme://host[:port]`) and the sanitized `tsaUrl` when the URL uses `http` or `https` with a valid hostname, or replaces malformed/non-HTTP URLs with `[redacted-invalid-tsa-url]` without echoing raw input.
- **Stable error categories:** Maps internal `verification_error` values through `classify_tsa_error_category` to a closed set (`none`, `unverified_no_chain`, `dependency_unavailable`, `malformed_certificate_or_chain`, `unsupported_algorithm`, `certificate_expired_or_not_yet_valid`, `certificate_revoked`, `untrusted_root`, `signature_invalid`, `malformed_tsa_url`, `verification_failed`), preventing raw exception strings or embedded credentials from leaking into incident bundles.
