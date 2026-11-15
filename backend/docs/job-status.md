# Job status and progress

`GET /api/jobs/<id>` returns the state of a background job (`embed`, `extract`,
`silent_witness`, `verify_tx`).

```json
{
  "ok": true,
  "job": {
    "id": 12,
    "type": "embed",
    "status": "running",
    "result": null,
    "created_at": "2026-10-18T16:00:00+00:00",
    "heartbeat_at": "2026-10-18T16:00:30+00:00",
    "progress": { "phase": "embedding", "percent": 42.5 }
  }
}
```

## `progress`

| Value | Meaning |
| --- | --- |
| `null` | No progress reported yet (pending, or a job type that does not report). Never an error. |
| `{"phase": string, "percent": number}` | Current step and its completion, 0–100, one decimal. |
| `{"phase": string, "percent": null}` | Current step has no measurable fraction. |

Phases reported today:

- `embed`: `hashing_source` → `embedding` (frames written / total frames; `percent`
  is `null` when ffprobe reports no frame count) → `hashing_output` → `recording`.
- `silent_witness`: `generating_proof` (the proof runs as one external command, so
  only the phase name is reported).

Processors call `db.report_job_progress(job_id, phase, percent)` as often as they
like; the value is stored at most once per second per job
(`JOB_PROGRESS_MIN_INTERVAL_SECONDS`), and only while the job is `running`.
Heartbeats extend the lease only and never overwrite progress.

## Per-tenant fair scheduling and deadlines

Expensive video and proof jobs (`embed`, `extract`, `silent_witness`) are
scheduled fairly across tenants while preserving existing HTTP admission
controls (`AdmissionController`):

- **Per-tenant queue bound (`TENANT_VIDEO_MAX_QUEUED`, default `16`):** caps how
  many `pending` expensive video jobs a single tenant may queue simultaneously,
  raising `TenantQuotaExceededError` (`reason="tenant_queue_limit"`) when full.
- **Per-tenant concurrency bound (`TENANT_VIDEO_MAX_CONCURRENT`, default `2`):**
  caps how many `running` expensive video jobs a single tenant may hold at once
  so a noisy tenant cannot monopolize worker slots.
- **Deficit / least-recently-leased round-robin:** `db.lease_job` selects the
  eligible tenant with the fewest `running` video jobs and the oldest last-lease
  sequence, keeping FIFO order within each tenant and never starving lightweight
  reconciliation jobs (`verify_tx`).
- **Independent processing deadlines (`VIDEO_JOB_DEADLINE_SECONDS`, default
  `600.0`):** every expensive video job records its own `deadline_at` budget.
  Jobs whose deadline expires while queued or mid-flight fail non-retryably
  (`job processing deadline exceeded`) and release their tenant slot without
  affecting newer or sibling-tenant jobs.
- **Privacy-safe tenant bucketing:** raw client IPs, wallet addresses, or tenant
  labels are hashed into opaque internal `_tenant_key` buckets and stripped by
  `public_job_view`.

## What the response never contains

The job's request `payload` (filenames, metadata, proof secrets) and internal
underscore-prefixed fields (trace links, throttle state) are stripped by
`public_job_view` before the job is returned. Progress values are phase names
and numbers only and carry no payload data.
