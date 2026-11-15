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

## What the response never contains

The job's request `payload` (filenames, metadata, proof secrets) and internal
underscore-prefixed fields (trace links, throttle state) are stripped by
`public_job_view` before the job is returned. Progress values are phase names
and numbers only and carry no payload data.

## Bounded worker attempt history

Each job maintains a FIFO-bounded `attempt_history` list (default cap `10`,
configurable via `JOB_ATTEMPT_HISTORY_MAX_ENTRIES`, hard ceiling `100`), plus
`attempt_count` and `attempts_evicted`:

- **Lease metadata**: `attempt`, sanitized `worker_id`, `leased_at`,
  `lease_duration_seconds`, and `heartbeat_at`.
- **Progress metadata**: `last_progress` (`{"phase", "percent"}`) and bounded
  deduplicated `phases` (up to `16` stages per attempt).
- **Terminal reason metadata**: `status` (`running`, `completed`, `failed`,
  `requeued`, `cancelled`), `ended_at`, canonical `terminal_reason`
  (`completed`, `cancelled`, `grace_period_exceeded`, `stego_limit_exceeded`,
  `missing_input`, `validation_error`, `retryable_error`, `fatal_error`,
  `lease_expired`), and safe exception class `error_type`.
- **Privacy invariants**: Uploaded media bytes, local storage or upload paths,
  raw exception messages, and proof/witness secrets are strictly excluded from
  attempt history and `public_job_view`.
