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

## Intentional cancellation vs processing failure

- `POST /api/jobs/<id>/cancel` cancels either a `pending` or an in-flight
  `running` job and transitions it to `status: "cancelled"` with the stable
  privacy-safe result `{"code": "CANCELLED", "cancelled": true}`.
- Repeated `POST /api/jobs/<id>/cancel` or `GET /api/jobs/<id>` calls on a
  cancelled job return the same stable `cancelled` state and result; late worker
  completions or errors cannot overwrite a cancelled job.
- Intentional worker cancellation (`JobCancelledError` or requester cancellation)
  is excluded from automatic failure accounting (`failure_count` and
  `retry_count`, bounded by `JOB_MAX_RETRIES`, default `3`), whereas genuine
  transient processing failures increment `failure_count` / `retry_count` until
  retries are exhausted.

## What the response never contains

The job's request `payload` (filenames, metadata, proof secrets) and internal
underscore-prefixed fields (trace links, throttle state) are stripped by
`public_job_view` before the job is returned. Progress values are phase names
and numbers only and carry no payload data.
