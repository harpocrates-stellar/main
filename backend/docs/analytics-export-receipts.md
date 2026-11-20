# Analytics export completion receipts

Every analytics export that `ExportManager.create_export` completes carries a
completion receipt on its artifact (`ExportArtifact.receipt`). The receipt is
returned by `POST /analytics/export` and `GET /analytics/export/<artifact_id>`
under `"receipt"`. A rejected export (`export_token_required`) creates no
artifact and no receipt.

```json
"receipt": {
  "receipt_version": "receipt-v1",
  "artifact_id": "exp-v1:3f9c0a1b2d4e5f60",
  "completed_at_epoch_seconds": 1795031828.41,
  "scope": {
    "entry_source": "explicit",
    "requested_max_entries": 120,
    "candidate_count": 120,
    "exported_count": 64,
    "max_entries": 64,
    "max_bytes": 4194304,
    "include_sampled_out_events": false,
    "export_token_verified": true,
    "compress": false,
    "rollout_phase": "shadow"
  },
  "policy_revision": "pol-v1:9b1e04c2a7d35f18",
  "consent_schema_version": "1.0.0",
  "redaction_version": "harpocrates-redaction-v1",
  "format_version": "1.0.0",
  "output_digest": "sha256:<64 hex characters>",
  "payload_bytes": 18234
}
```

| Field | Meaning |
| --- | --- |
| `scope.entry_source` | `explicit` (entries passed by the caller), `processor` (the log processor's buffer) or `none`. `POST /analytics/export` passes a snapshot of the processor buffer, so API exports report `explicit`. |
| `scope.requested_max_entries` | The `max_entries` the requester asked for (`POST /analytics/export` body), or `null` when none was given. The effective cap is `min(requested, max_entries)`. |
| `scope.candidate_count` / `scope.exported_count` | Entries considered before filtering, and entries actually exported. |
| `scope.max_entries`, `scope.max_bytes`, `scope.include_sampled_out_events` | Export policy limits and filter in force. |
| `scope.export_token_verified`, `scope.compress`, `scope.rollout_phase` | How this export was requested. An unverified export has an empty output, and its receipt says so (`exported_count: 0`). |
| `policy_revision` | `pol-v1:` + the first 16 hex characters of the SHA-256 of the export policy settings (canonical JSON). Equal settings give the same revision; any change gives a new one. |
| `consent_schema_version`, `redaction_version`, `format_version` | Versions of the consent schema, redaction rules and export format in force. |
| `output_digest` | `sha256:` + the full SHA-256 of the exported output exactly as returned (the compressed form when `compress` is true). `checksum_sha256_prefix16` stays as its first 16 characters. |
| `payload_bytes` | Size of that output in bytes. |

## What a receipt never contains

The receipt is built only from policy settings, request flags, counts,
versions and digests. No field of any exported event reaches it: no entry
ids, event names, message summaries, labels, counters, or account, session
or correlation tags. The output itself is referenced only by its fixed-size
SHA-256 digest.
