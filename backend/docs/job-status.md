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

## Durable claim generations and stale-worker fencing

- Every `db.lease_job` or `db.reclaim_job_lease` claim atomically increments a
  durable `claim_generation` counter (persisted in PostgreSQL `job_claim_fences`
  when `DATABASE_URL` is configured and in an atomic local fence ledger under
  `HARPOCRATES_STORAGE_DIR` / `HARPOCRATES_CLAIM_FENCE_PATH` otherwise).
- Workers stage output artifacts under generation-scoped temporary files
  (`job_<id>_output.gen_<n>.tmp`) and publish them via
  `db.commit_fenced_job_output`, which verifies `claim_generation` still matches
  the active claim before replacing the canonical output path.
- `complete_job`, `fail_job`, `report_job_progress`, and `heartbeat_job` require
  the active `claim_generation` and record `committed_generation` on completion,
  preventing a slow or replaced worker from overwriting a newer worker's result,
  progress, lease, or output file.

## What the response never contains

The job's request `payload` (filenames, metadata, proof secrets) and internal
underscore-prefixed fields (trace links, throttle state) are stripped by
`public_job_view` before the job is returned. Progress values are phase names
and numbers only and carry no payload data.
