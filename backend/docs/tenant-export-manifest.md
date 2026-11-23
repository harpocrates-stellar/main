# Verifiable Tenant Data Export Manifest

## Overview

`backend/analytics/export_manager.py` attaches a verifiable `TenantExportManifest` to every `ExportArtifact` created by `ExportManager.create_export`. The manifest cryptographically binds the exported record classes, the active redaction policy, the consent state/revision, and the serialized payload hash to a canonical SHA-256 digest while excluding sensitive evidence and credential material by construction.

## Bound Manifest Fields

`TenantExportManifest` (`manifest_version = "1.0.0"`) binds the following fields in canonical JSON (`sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=True`) with domain separator `harpocrates-tenant-export-manifest-v1:`:

| Field | Description |
| :--- | :--- |
| `artifact_id` | Server-generated export artifact identifier (`exp-v1:...`). |
| `consent_policy_revision` | Consent policy revision effective for exported records (or `null`). |
| `consent_state` | One of `never_collected`, `withdrawn`, or `granted`. |
| `entry_count` | Number of records serialized in the export payload. |
| `excluded_sensitive_classes` | Sorted list of sensitive classes excluded by construction. |
| `manifest_version` | Schema version (`"1.0.0"`). |
| `payload_sha256` | Full 64-hex SHA-256 digest of the UTF-8 serialized payload. |
| `record_classes` | Sorted, deduplicated list of exported non-sensitive record classes. |
| `redaction_policy_digest` | Canonical SHA-256 digest of the active redaction policy (`rpol-v1:...`). |
| `redaction_policy_version` | Active redaction policy version identifier (e.g. `harpocrates-redaction-v1`). |
| `tenant_tag` | Opaque tenant/account tag (omitted / `null` for unverified shadow exports). |

The resulting digest is formatted as `mft-v1:<64-lowercase-hex>`.

## Exclusion of Sensitive Evidence & Credentials by Construction

Before serialization and manifest construction:

1. `filter_entries_for_tenant_export` excludes any `LogEntry` whose record class, event name, label keys, or counter keys match sensitive evidence, ZK witness/proof, wallet signature, PII, or credential hints, or whose values match credential patterns (consent tokens `cst-v1:...`, `Bearer` tokens, PEM private key headers, or Stellar secret seeds).
2. `build_tenant_export_manifest` fails closed with `ValueError` if any sensitive record class is supplied.
3. `ConsentState.to_export_summary()` in `backend/analytics/consent.py` produces a credential-free consent summary that omits `consent_token` by construction.

## Fail-Closed Verification

Use `verify_tenant_export_manifest(manifest, serialized_payload, *, expected_redaction_policy_digest=None, expected_tenant_tag=None)` or `ExportManager.verify_artifact_manifest(artifact_id, serialized_payload, ...)` to verify an export:

- Recomputes the canonical `manifest_digest` and compares in constant time (`hmac.compare_digest`).
- Recomputes `payload_sha256` against `serialized_payload` in constant time.
- Verifies `record_classes` is canonical and contains zero sensitive classes.
- Verifies `excluded_sensitive_classes` includes all required sensitive classes.
- Optionally enforces expected `redaction_policy_digest` and `tenant_tag`.
- Scans uncompressed JSON payloads for leaked sensitive keys or credential markers and checks `entry_count`.
