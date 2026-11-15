from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import threading

import pytest

_BACKEND_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _BACKEND_DIR.parent
for _p in (str(_BACKEND_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import db
import worker


@pytest.fixture(autouse=True)
def _isolated_jobs_and_writers():
    saved_jobs = dict(db._JOBS)
    saved_writers = dict(db._ACTIVE_JOB_WRITERS)
    db._JOBS.clear()
    db._ACTIVE_JOB_WRITERS.clear()
    try:
        yield
    finally:
        db._JOBS.clear()
        db._JOBS.update(saved_jobs)
        db._ACTIVE_JOB_WRITERS.clear()
        db._ACTIVE_JOB_WRITERS.update(saved_writers)


def test_queue_expiry_and_execution_timeout_are_strictly_separated(tmp_path: Path) -> None:
    policy = db.ProcessingDeadlinePolicy(queue_ttl_seconds=60.0, execution_timeout_seconds=120.0)
    t0 = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)

    # Job 1 sits in queue past 60s without being leased -> expires as queue_expired and is never leased
    j_stale_queue = db.enqueue_job("embed", {"filename": "a.mp4"}, now=t0, policy=policy)
    f_stale_in = tmp_path / f"job_{j_stale_queue}_input"
    f_stale_in.write_bytes(b"queued-bytes")

    # Job 2 enqueued at t0 + 20s; leased at t0 + 70s (waited 50s < 60s queue_ttl)
    j_leased_in_time = db.enqueue_job("embed", {"filename": "b.mp4"}, now=t0 + timedelta(seconds=20), policy=policy)

    leased = db.lease_job(
        "worker-1",
        ["embed"],
        now=t0 + timedelta(seconds=70),
        policy=policy,
    )
    # Job 1 expired before leasing; Job 2 was leased with a full 120s execution budget!
    assert leased is not None
    assert leased["id"] == j_leased_in_time
    assert db.get_job(j_stale_queue)["status"] == "expired"
    assert db.get_job(j_stale_queue)["deadline_kind"] == db.DEADLINE_KIND_QUEUE_EXPIRED
    assert db.get_job(j_stale_queue)["error"] == "queue_deadline_exceeded"

    # At t0 + 150s (130s since Job 2 was created > 60s queue_ttl, but only 80s of active execution < 120s):
    # Job 2 MUST still be running — queue wait time does NOT eat into active execution timeout!
    sweep_mid = worker.enforce_processing_deadlines(
        storage_dir=tmp_path,
        now=t0 + timedelta(seconds=150),
        policy=policy,
    )
    assert sweep_mid.execution_timed_out_job_ids == ()
    assert db.get_job(j_leased_in_time)["status"] == "running"
    # Meanwhile Job 1 had no active writer, so its queued input artifact was cleaned up
    assert sweep_mid.cleaned_artifact_count == 1
    assert not f_stale_in.exists()
    assert db.get_job(j_stale_queue)["cleanup_status"] == "cleaned"

    # At t0 + 195s (125s of active execution >= 120s execution_timeout): Job 2 times out as execution_timeout!
    sweep_late = worker.enforce_processing_deadlines(
        storage_dir=tmp_path,
        now=t0 + timedelta(seconds=195),
        policy=policy,
    )
    assert sweep_late.execution_timed_out_job_ids == (j_leased_in_time,)
    timed_out_row = db.get_job(j_leased_in_time)
    assert timed_out_row["status"] == "failed"
    assert timed_out_row["deadline_kind"] == db.DEADLINE_KIND_EXECUTION_TIMEOUT
    assert timed_out_row["error"] == "execution_deadline_exceeded"


def test_execution_timeout_defers_artifact_cleanup_until_active_writer_stops(
    tmp_path: Path,
) -> None:
    policy = db.ProcessingDeadlinePolicy(queue_ttl_seconds=300.0, execution_timeout_seconds=30.0)
    t0 = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)

    job_id = db.enqueue_job("embed", {"filename": "clip.mp4"}, now=t0, policy=policy)
    db.lease_job("worker-writer", ["embed"], now=t0 + timedelta(seconds=5), policy=policy)

    in_path = tmp_path / f"job_{job_id}_input"
    out_path = tmp_path / f"job_{job_id}_output"
    part_path = tmp_path / f"job_{job_id}_output.part"
    in_path.write_bytes(b"source-video")
    out_path.write_bytes(b"partial-output")
    part_path.write_bytes(b"partial-chunk")

    writer_entered = threading.Event()
    release_writer = threading.Event()

    def background_writer() -> None:
        with db.active_job_writer(job_id, "ffmpeg-subproc"):
            writer_entered.set()
            release_writer.wait(timeout=5.0)
            # Simulate final flush right before process exit: files must still exist here!
            out_path.write_bytes(b"flushed-before-exit")

    writer_thread = threading.Thread(target=background_writer)
    writer_thread.start()
    assert writer_entered.wait(timeout=5.0)

    # Trigger execution timeout while writer_thread is STILL actively writing
    res_while_active = worker.enforce_processing_deadlines(
        storage_dir=tmp_path,
        now=t0 + timedelta(seconds=60),
        policy=policy,
    )
    assert res_while_active.execution_timed_out_job_ids == (job_id,)
    assert res_while_active.cleaned_artifact_count == 0
    assert res_while_active.deferred_cleanup_job_ids == (job_id,)
    assert db.get_job(job_id)["cleanup_status"] == "deferred_active_writer"

    # Artifacts MUST NOT be deleted while active writer is still running
    assert in_path.exists()
    assert out_path.exists()
    assert part_path.exists()

    # Late complete_job / fail_job from timed-out worker cannot overwrite deadline terminal status
    db.complete_job(job_id, {"late": True})
    assert db.get_job(job_id)["status"] == "failed"
    assert db.get_job(job_id)["deadline_kind"] == db.DEADLINE_KIND_EXECUTION_TIMEOUT

    # Now stop the active writer process/thread and re-run cleanup -> artifacts are safely removed!
    release_writer.set()
    writer_thread.join(timeout=5.0)
    assert not db.is_job_writer_active(job_id)

    res_after_stop = worker.enforce_processing_deadlines(
        storage_dir=tmp_path,
        now=t0 + timedelta(seconds=61),
        policy=policy,
    )
    assert res_after_stop.cleaned_artifact_count == 3
    assert res_after_stop.deferred_cleanup_job_ids == ()
    assert not in_path.exists()
    assert not out_path.exists()
    assert not part_path.exists()
    assert db.get_job(job_id)["cleanup_status"] == "cleaned"
    assert db.get_job(job_id)["purged"] is True


def test_liveness_probe_automatically_detects_stopped_writer_thread(tmp_path: Path) -> None:
    policy = db.ProcessingDeadlinePolicy(queue_ttl_seconds=60.0, execution_timeout_seconds=10.0)
    t0 = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("extract", {"filename": "x.mp4"}, now=t0, policy=policy)
    db.lease_job("worker-1", ["extract"], now=t0, policy=policy)

    artifact = tmp_path / f"job_{job_id}_input"
    artifact.write_bytes(b"bytes")

    alive_flag = {"running": True}
    db.register_job_writer(job_id, "probe-writer", is_alive=lambda: alive_flag["running"])
    assert db.is_job_writer_active(job_id) is True

    sweep1 = worker.enforce_processing_deadlines(
        storage_dir=tmp_path,
        now=t0 + timedelta(seconds=20),
        policy=policy,
    )
    assert sweep1.cleaned_artifact_count == 0
    assert artifact.exists()

    # Simulated crash: process dies without calling unregister_job_writer, liveness probe turns False
    alive_flag["running"] = False
    assert db.is_job_writer_active(job_id) is False

    sweep2 = worker.enforce_processing_deadlines(
        storage_dir=tmp_path,
        now=t0 + timedelta(seconds=21),
        policy=policy,
    )
    assert sweep2.cleaned_artifact_count == 1
    assert not artifact.exists()


def test_deadline_policy_validation_and_env_loading(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError):
        db.ProcessingDeadlinePolicy(queue_ttl_seconds=0, execution_timeout_seconds=10)
    with pytest.raises(ValueError):
        db.ProcessingDeadlinePolicy(queue_ttl_seconds=10, execution_timeout_seconds=-5)
    with pytest.raises(ValueError):
        db.ProcessingDeadlinePolicy(queue_ttl_seconds=True, execution_timeout_seconds=10)  # type: ignore[arg-type]

    monkeypatch.setenv("JOB_QUEUE_TTL_SECONDS", "120.5")
    monkeypatch.setenv("JOB_EXECUTION_TIMEOUT_SECONDS", "45.0")
    loaded = db.load_processing_deadline_policy()
    assert loaded.queue_ttl_seconds == 120.5
    assert loaded.execution_timeout_seconds == 45.0

    monkeypatch.setenv("JOB_QUEUE_TTL_SECONDS", "-1")
    with pytest.raises(RuntimeError, match="JOB_QUEUE_TTL_SECONDS must be positive"):
        db.load_processing_deadline_policy()
