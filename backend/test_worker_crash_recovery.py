from __future__ import annotations

from pathlib import Path
import sys
import threading
from unittest.mock import patch

import pytest

_BACKEND_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _BACKEND_DIR.parent
for _p in (str(_BACKEND_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import db
import worker


@pytest.fixture(autouse=True)
def _isolated_jobs():
    saved = dict(db._JOBS)
    db._JOBS.clear()
    try:
        yield
    finally:
        db._JOBS.clear()
        db._JOBS.update(saved)


@pytest.mark.parametrize(
    "stage",
    [
        worker.CRASH_STAGE_HASHING,
        worker.CRASH_STAGE_PROVING,
        worker.CRASH_STAGE_METADATA_WRITE,
    ],
)
def test_deterministic_crash_recovery_scenarios_across_stages(stage: str, tmp_path: Path) -> None:
    outcome = worker.run_deterministic_crash_recovery_scenario(
        stage,
        storage_dir=tmp_path / stage,
        lease_duration=20,
    )
    assert outcome.scenario_stage == stage
    assert outcome.crashed_worker_id == "worker-alpha"
    assert outcome.crashed_lease_epoch == 1
    assert outcome.recovering_worker_id == "worker-beta"
    assert outcome.recovered_lease_epoch == 2
    assert outcome.stale_commit_blocked is True
    assert outcome.stale_metadata_write_blocked is True
    assert outcome.stale_fail_blocked is True
    assert outcome.final_status == "completed"
    assert outcome.committed_worker_id == "worker-beta"
    assert outcome.committed_lease_epoch == 2

    if stage == worker.CRASH_STAGE_PROVING:
        assert outcome.metadata_commits == ()
    else:
        # Only recovering worker (epoch 2) committed metadata; crashed epoch 1 never committed
        assert outcome.metadata_commits == (2,)


def test_unknown_crash_stage_and_non_positive_lease_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported crash stage"):
        worker.run_deterministic_crash_recovery_scenario("invalid_stage")

    with pytest.raises(ValueError, match="lease_duration must be positive"):
        worker.run_deterministic_crash_recovery_scenario(worker.CRASH_STAGE_HASHING, lease_duration=0)

    with pytest.raises(ValueError, match="lease_duration must be positive"):
        db.lease_job("worker-1", ["embed"], lease_duration=0)


def test_stale_worker_resuming_mid_metadata_write_cannot_clobber_reassigned_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HARPOCRATES_STORAGE_DIR", str(tmp_path))

    job_id = db.enqueue_job(
        "embed",
        {
            "filename": "clip.mp4",
            "metadata": {"protocol": "harpocrates", "version": 1, "proofId": "22" * 32, "tier": "silent"},
        },
    )
    input_file = worker.get_job_input_path(job_id)
    output_file = worker.get_job_output_path(job_id)
    input_file.write_bytes(b"original-video-bytes")

    worker_a_paused = threading.Event()
    allow_worker_a_resume = threading.Event()
    worker_a_errors: list[BaseException] = []
    committed_events: list[tuple[str | None, int | None, str]] = []

    def fake_embed(src, dst, meta, progress_callback=None):
        Path(dst).write_bytes(Path(src).read_bytes() + f"|by={Path(dst).name}".encode("ascii"))

    def fake_sha256(path):
        import hashlib

        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def recording_insert_proof_event(**kwargs):
        cur = db.get_job(job_id) or {}
        committed_events.append((cur.get("worker_id"), cur.get("lease_epoch"), kwargs["video_hash"]))
        return {"id": len(committed_events)}

    monkeypatch.setattr(worker, "embed_metadata", fake_embed)
    monkeypatch.setattr(worker, "sha256_file", fake_sha256)
    monkeypatch.setattr(worker, "insert_proof_event", recording_insert_proof_event)

    # Clock starts at t=100; Worker A leases with 10s lease
    clock = {"now": 100.0}
    monkeypatch.setattr(db.time, "monotonic", lambda: clock["now"])

    leased_a = db.lease_job("worker-a", ["embed"], lease_duration=10)
    assert leased_a is not None
    assert leased_a["lease_epoch"] == 1

    def pause_worker_a_at_metadata_write(stage: str, current_job: dict) -> None:
        if stage == worker.CRASH_STAGE_METADATA_WRITE and current_job.get("worker_id") == "worker-a":
            worker_a_paused.set()
            assert allow_worker_a_resume.wait(timeout=5.0)

    def run_worker_a() -> None:
        try:
            worker.execute_leased_job(leased_a, stage_hook=pause_worker_a_at_metadata_write)
        except BaseException as exc:
            worker_a_errors.append(exc)

    thread_a = threading.Thread(target=run_worker_a)
    thread_a.start()
    assert worker_a_paused.wait(timeout=5.0)

    # Advance monotonic clock past Worker A's lease expiry; Worker B reclaims (epoch=2) and finishes!
    clock["now"] = 115.0
    leased_b = db.lease_job("worker-b", ["embed"], lease_duration=10)
    assert leased_b is not None
    assert leased_b["lease_epoch"] == 2
    assert leased_b["reassigned_count"] == 1

    res_b = worker.execute_leased_job(leased_b)
    expected_output_bytes = output_file.read_bytes()
    assert b"epoch_2" in expected_output_bytes

    # Now wake stale Worker A at metadata_write: it must fail closed with StaleWorkerLeaseError
    allow_worker_a_resume.set()
    thread_a.join(timeout=5.0)
    assert not thread_a.is_alive()

    assert len(worker_a_errors) == 1
    assert isinstance(worker_a_errors[0], db.StaleWorkerLeaseError)

    # Canonical output file, committed result, and metadata events reflect ONLY Worker B (epoch 2)
    assert output_file.read_bytes() == expected_output_bytes
    assert not list(tmp_path.glob("*.tmp"))
    final_job = db.get_job(job_id)
    assert final_job is not None
    assert final_job["status"] == "completed"
    assert final_job["worker_id"] == "worker-b"
    assert final_job["committed_lease_epoch"] == 2
    assert final_job["result"] == res_b
    assert committed_events == [("worker-b", 2, res_b["embedded_hash"])]


def test_stale_heartbeat_and_progress_cannot_extend_or_mutate_reassigned_job() -> None:
    job_id = db.enqueue_job("silent_witness", {"video_hash": "aa" * 32})
    leased_1 = db.lease_job("worker-1", ["silent_witness"], lease_duration=20, now=50.0)
    assert leased_1 is not None and leased_1["lease_epoch"] == 1

    # Valid heartbeat extends lease to 55 + 20 = 75
    assert db.heartbeat_job(job_id, lease_duration=20, worker_id="worker-1", lease_epoch=1, now=55.0) is True
    assert db.lease_job("worker-2", ["silent_witness"], lease_duration=20, now=70.0) is None

    # At t=76 lease_1 expired; worker-2 claims epoch=2
    leased_2 = db.lease_job("worker-2", ["silent_witness"], lease_duration=20, now=76.0)
    assert leased_2 is not None and leased_2["lease_epoch"] == 2

    # Stale worker-1 heartbeat, progress, fail, and complete are all rejected
    assert db.heartbeat_job(job_id, lease_duration=20, worker_id="worker-1", lease_epoch=1, now=77.0) is False
    assert (
        db.report_job_progress(
            job_id,
            "generating_proof",
            None,
            now=80.0,
            worker_id="worker-1",
            lease_epoch=1,
        )
        is False
    )
    assert db.fail_job(job_id, "stale err", is_fatal=True, worker_id="worker-1", lease_epoch=1, now=80.0) is False
    with pytest.raises(db.StaleWorkerLeaseError):
        db.complete_job(job_id, {"proof": "stale"}, worker_id="worker-1", lease_epoch=1, now=80.0)

    # Active worker-2 can report progress and complete cleanly
    assert (
        db.report_job_progress(
            job_id,
            "generating_proof",
            None,
            now=81.0,
            worker_id="worker-2",
            lease_epoch=2,
        )
        is True
    )
    # Direct db.insert_proof_event rejects stale worker-1 and accepts active worker-2 (stub mode returns None)
    with pytest.raises(db.StaleWorkerLeaseError):
        db.insert_proof_event(
            event_type="embed",
            video_hash="aa" * 32,
            job_id=job_id,
            worker_id="worker-1",
            lease_epoch=1,
        )

    assert db.complete_job(job_id, {"proof": "valid"}, worker_id="worker-2", lease_epoch=2, now=82.0) is True
    assert db.get_job(job_id)["result"] == {"proof": "valid"}
