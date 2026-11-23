# Analytics Deletion Preview

The analytics deletion preview provides a read-only, privacy-preserving estimate of records eligible for deletion for a single authorized tenant.

## Interface

- `ConsentManager.preview_tenant_consent_deletion(account_tag, now_epoch_seconds=None)` in `backend/analytics/consent.py`
- `ExportManager.preview_deletion(authorized_tenant, requested_tenant, consent_manager=None, entries=None, now_epoch_seconds=None, preview_policy=None)` in `backend/analytics/export_manager.py`

## Tenant Isolation

`preview_deletion` enforces fail-closed tenant authorization:

- Both `authorized_tenant` and `requested_tenant` must be non-empty strings.
- They are compared in constant time (`hmac.compare_digest`); any mismatch raises `TenantAuthorizationError`.
- Only consent states, export artifacts (`exported_by_tag`), and log entries explicitly tagged for the authorized tenant are counted. Cross-tenant and untagged records are excluded.

## Bounded Output and Privacy

Counts are aggregated by `(data_class, retention_policy)` and bounded by `DeletionPreviewPolicy`:

| Field | Default | Description |
| --- | --- | --- |
| `count_cap_per_bucket` | `1000` | Maximum reported `eligible_count` / `retained_count` per bucket (`eligible_capped` / `retained_capped` indicates capping). |
| `max_buckets` | `64` | Maximum number of `(data_class, retention_policy)` buckets returned (`buckets_truncated` indicates truncation). |
| `export_artifact_retention_seconds` | `2592000` (30d) | Retention window for export artifacts. |
| `log_entry_retention_seconds` | `2592000` (30d) | Default retention window for analytics log entries. |
| `withdrawn_retention_seconds` | `0.0` | Retention window for records with withdrawn consent. |
| `data_class_retention_seconds` | `{}` | Optional per-`data_class` retention window overrides. |

The returned `DeletionPreviewResult` always sets `dry_run=True` and never mutates underlying state or returns raw tenant identifiers, consent tokens, artifact IDs, entry IDs, or payloads.
