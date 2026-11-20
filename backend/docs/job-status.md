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

## `attempts` (worker attempt history)

Every lease opens an attempt; the job keeps the newest
`JOB_ATTEMPT_HISTORY_LIMIT` (10) attempts, oldest dropped first. The field is
absent until the first lease.

```json
"attempts": [
  { "attempt": 1, "worker_id": "worker-4182", "leased_at": "2026-10-18T16:00:01+00:00",
    "ended_at": "2026-10-18T16:01:10+00:00", "outcome": "released",
    "reason": "shutdown_grace_exceeded", "progress": { "phase": "embedding", "percent": 63.0 } },
  { "attempt": 2, "worker_id": "worker-4190", "leased_at": "2026-10-18T16:01:12+00:00",
    "ended_at": null, "outcome": null, "reason": null, "progress": null }
]
```

| Field | Meaning |
| --- | --- |
| `attempt` | 1-based attempt number. It keeps counting past the limit, so dropped attempts show as a gap. |
| `worker_id` | Worker that held the lease. |
| `leased_at` / `ended_at` | ISO 8601 UTC; `ended_at` is `null` while the attempt runs. |
| `outcome` | `null` (running), `completed`, `failed` (fatal) or `released` (back to the queue for a retry). |
| `reason` | Machine code for a failure or release: the exception class name (`ValueError`) or `shutdown_grace_exceeded`. |
| `progress` | Last stored `{"phase", "percent"}` of that attempt, same rules as `progress` above. |

The history holds metadata only. It never contains the request payload,
uploaded media bytes, file paths, proof secrets or free-text error messages:
`reason` and `worker_id` are stored only when they are plain codes
(`[A-Za-z_][A-Za-z0-9_]*` and `[A-Za-z0-9_.-]+`, at most 64 characters) and
are otherwise recorded as `null`. `fail_job(..., reason=...)` takes that code;
the free-text `error` field is unchanged and never copied into the history.
