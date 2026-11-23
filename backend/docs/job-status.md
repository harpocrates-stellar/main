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
| `{"phase": string, "percent": number}` | Current step and its completion, 0-100, one decimal. |
| `{"phase": string, "percent": null}` | Current step has no measurable fraction. |

Phases reported today:

- `embed`: `hashing_source` -> `embedding` (frames written / total frames; `percent`
  is `null` when ffprobe reports no frame count) -> `hashing_output` -> `recording`.
- `silent_witness`: `generating_proof` (the proof runs as one external command, so
  only the phase name is reported).

Processors call `db.report_job_progress(job_id, phase, percent, stage_revision=...)`
as often as they like; the value is stored at most once per second per job
(`JOB_PROGRESS_MIN_INTERVAL_SECONDS`), and only while the job is `running`.
When `stage_revision` is provided, revisions are enforced monotonically so
delayed updates from an already-completed stage are rejected regardless of
wall-clock ordering. Terminal jobs (`completed`, `failed`, `cancelled`) never
transition back to `running` and ignore further progress updates.
Heartbeats extend the lease only and never overwrite progress.

## Cancellation vs. processing failure

Intentional cancellation (via `POST /api/jobs/<id>/cancel` or a worker raising
`worker.JobCancelledError`) is kept distinct from processing failures:

- `status` transitions to `"cancelled"` and `cancelled_at` is recorded.
- `result` preserves a stable object for the requester:
  `{"cancelled": true, "reason": "<reason>"}` (defaults to `"Job cancelled"`).
- `retry_count` is **not** incremented, and cancelled jobs are never re-queued
  for automatic failure retries.
- Failure fields (`error`, `failed_at`) are not set, and late `complete_job` or
  `fail_job` calls do not overwrite an already-cancelled job.

## Claim generations (stale-worker fencing)

Every lease and every retryable release (`fail_job(..., is_fatal=False)`, used
for example when the shutdown grace period expires) increments the job's
internal `_claim_generation`. The worker passes the generation it leased to
`complete_job`, `fail_job`, `report_job_progress` and `heartbeat_job`
(`generation=`); a write from an older generation is ignored, returns `False`
and logs `job_claim_stale`. This keeps a worker that lost its claim from
overwriting a newer result, progress or failure state. Calls without
`generation` behave as before. The field is internal and never part of the
response above.

## What the response never contains

The job's request `payload` (filenames, metadata, proof secrets) and internal
underscore-prefixed fields (trace links, throttle state) are stripped by
`public_job_view` before the job is returned. Progress values are phase names
and numbers only and carry no payload data.

## Failure diagnostics

When a job fails, the exception text and traceback frames are sanitized before
they reach the logger or the job-failure record:

- Private filesystem paths are replaced with `<path>`.
- Secret-shaped values (tokens, keys, passwords, `Bearer` credentials) are
  replaced with `<redacted>`.
- Each diagnostic string is capped at a fixed byte budget and truncated with a
  `…[truncated]` marker when it exceeds it.

Sanitized diagnostics are stored in the job's `result` error fields; the raw
exception is never persisted.

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
