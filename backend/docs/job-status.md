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

## Processing deadlines

Two separate limits, both off by default (`0`), so existing deployments keep
today's behaviour:

| Setting | Measured from | When exceeded |
| --- | --- | --- |
| `HARPOCRATES_JOB_QUEUE_TTL_SECONDS` | when the job entered the queue (enqueue, or a retryable release back to `pending`) | the `pending` job ends `failed` with `"failure_reason": "queue_expired"` and is never leased |
| `HARPOCRATES_JOB_EXECUTION_TIMEOUT_SECONDS` | the lease (time waiting in the queue does not count) | the `running` job ends `failed` with `"failure_reason": "execution_timeout"` and is not retried |

Both values are non-negative integers; anything else fails config loading.
A job closed by a deadline is final: a late result or error from the process
that overran it is dropped and logged as `job_deadline_final`.

```json
{ "id": 12, "status": "failed", "failure_reason": "execution_timeout",
  "error": "Execution timeout exceeded", "progress": { "phase": "embedding", "percent": 63.0 } }
```

### Artifact cleanup after a timeout

A Python worker thread cannot be killed, so a timed-out job's process may keep
writing for a while. Until it returns, the job is marked as having an active
writer and `sweep_job_files` keeps its files even past
`HARPOCRATES_JOB_FILE_TTL_SECONDS`. When the process returns, the worker
removes the partial output; the input follows the normal retention sweep.
