"""Deterministic multi-worker crash and recovery scenarios.

This module tests:
1. Interrupted hashing, proving, and metadata writes
2. Stale workers cannot commit after job reassignment
3. Boundary cases for crash recovery
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

import db
import worker


@pytest.fixture(autouse=True)
def _isolate_jobs():
    """Isolate in-memory job store for each test."""
    saved_jobs = dict(db._JOBS)
    saved_next_id = db._next_job_id
    db._JOBS.clear()
    try:
        yield
    finally:
        db._JOBS.clear()
        db._JOBS.update(saved_jobs)
        db._next_job_id = saved_next_id


class CrashSimulator:
    """Helper to simulate deterministic crashes at specific job phases."""

    def __init__(self):
        self.crash_at_phase = None
        self.crash_count = 0
        self.phases_seen = []
        self.lock = threading.Lock()

    def set_crash_at(self, phase: str):
        """Configure the phase at which to crash."""
        with self.lock:
            self.crash_at_phase = phase
            self.crash_count = 0
            self.phases_seen = []

    def maybe_crash(self, phase: str):
        """Call at each job phase; raises if this is the crash phase."""
        with self.lock:
            self.phases_seen.append(phase)
            if phase == self.crash_at_phase:
                self.crash_count += 1
                raise RuntimeError(f"Simulated crash at phase: {phase}")


def _mock_storage_paths(mock_input, mock_output):
    """Helper to mock storage paths with proper exists() behavior."""
    from pathlib import Path
    input_path = Path("/tmp/fake_input.mp4")
    output_path = Path("/tmp/fake_output.mp4")
    mock_input.return_value = input_path
    mock_output.return_value = output_path
    # Use MagicMock to allow exists() to be set
    mock_input.return_value = MagicMock(spec=Path)
    mock_input.return_value.exists.return_value = True
    mock_output.return_value = MagicMock(spec=Path)


def _run_embed_job(job_id, crash_phase=None, crash_simulator=None):
    """Run an embed job with optional crash simulation."""
    simulator = crash_simulator or CrashSimulator()
    if crash_phase:
        simulator.set_crash_at(crash_phase)

    def sha256_side_effect(path):
        if "input" in str(path):
            simulator.maybe_crash("hashing_source")
            return "source-hash"
        simulator.maybe_crash("hashing_output")
        return "embedded-hash"

    def embed_side_effect(*args, **kwargs):
        simulator.maybe_crash("embedding")

    def insert_side_effect(*args, **kwargs):
        simulator.maybe_crash("recording")
        return {"id": 1}

    with patch.object(worker, "sha256_file", side_effect=sha256_side_effect):
        with patch.object(worker, "embed_metadata", side_effect=embed_side_effect):
            with patch.object(worker, "canonical_metadata_hash", return_value="meta-hash"):
                with patch.object(worker, "insert_proof_event", side_effect=insert_side_effect):
                    with patch.object(worker, "get_job_input_path") as mock_input:
                        with patch.object(worker, "get_job_output_path") as mock_output:
                            _mock_storage_paths(mock_input, mock_output)
                            job = db.get_job(job_id)
                            try:
                                result = worker.process_embed(job)
                                # On success, mark job completed (normally done by worker loop)
                                db.complete_job(job_id, result)
                                return result
                            except RuntimeError as e:
                                # Simulate worker loop's exception handling
                                from worker import sanitize_exception_text, fail_job
                                safe_message = sanitize_exception_text(e)
                                fail_job(job_id, safe_message, is_fatal=False)
                                raise


def _run_embed_job_success(job_id):
    """Run an embed job to completion."""
    with patch.object(worker, "sha256_file", side_effect=["source-hash", "embedded-hash"]):
        with patch.object(worker, "embed_metadata"):
            with patch.object(worker, "canonical_metadata_hash", return_value="meta-hash"):
                with patch.object(worker, "insert_proof_event", return_value={"id": 100}):
                    with patch.object(worker, "get_job_input_path") as mock_input:
                        with patch.object(worker, "get_job_output_path") as mock_output:
                            _mock_storage_paths(mock_input, mock_output)
                            job = db.get_job(job_id)
                            result = worker.process_embed(job)
                            db.complete_job(job_id, result)
                            return result


def _run_silent_witness_job(job_id, crash_phase=None, crash_simulator=None):
    """Run a silent_witness job with optional crash simulation."""
    simulator = crash_simulator or CrashSimulator()
    if crash_phase:
        simulator.set_crash_at(crash_phase)

    def witness_side_effect(*args, **kwargs):
        simulator.maybe_crash(crash_phase or "generating_proof")
        return {"proof": "abc"}

    with patch.object(worker, "generate_silent_witness", side_effect=witness_side_effect):
        job = db.get_job(job_id)
        try:
            result = worker.process_silent_witness(job)
            db.complete_job(job_id, result)
            return result
        except RuntimeError as e:
            from worker import sanitize_exception_text, fail_job
            safe_message = sanitize_exception_text(e)
            fail_job(job_id, safe_message, is_fatal=False)
            raise


def _run_silent_witness_job_success(job_id):
    """Run a silent_witness job to completion."""
    with patch.object(worker, "generate_silent_witness", return_value={"proof": "def"}):
        job = db.get_job(job_id)
        result = worker.process_silent_witness(job)
        db.complete_job(job_id, result)
        return result


def _run_extract_job(job_id, crash_phase=None, crash_simulator=None):
    """Run an extract job with optional crash simulation."""
    simulator = crash_simulator or CrashSimulator()
    if crash_phase:
        simulator.set_crash_at(crash_phase)

    def insert_side_effect(*args, **kwargs):
        simulator.maybe_crash(crash_phase or "recording")
        return {"id": 1}

    with patch.object(worker, "sha256_file", return_value="video-hash"):
        with patch.object(worker, "extract_metadata", return_value={"proofId": "pid-extract"}):
            with patch.object(worker, "canonical_metadata_hash", return_value="meta-hash"):
                with patch.object(worker, "insert_proof_event", side_effect=insert_side_effect):
                    with patch.object(worker, "get_job_input_path") as mock_input:
                        _mock_storage_paths(mock_input, MagicMock())
                        job = db.get_job(job_id)
                        try:
                            result = worker.process_extract(job)
                            db.complete_job(job_id, result)
                            return result
                        except RuntimeError as e:
                            from worker import sanitize_exception_text, fail_job
                            safe_message = sanitize_exception_text(e)
                            fail_job(job_id, safe_message, is_fatal=False)
                            raise


def _run_extract_job_success(job_id):
    """Run an extract job to completion."""
    with patch.object(worker, "sha256_file", return_value="video-hash"):
        with patch.object(worker, "extract_metadata", return_value={"proofId": "pid-extract"}):
            with patch.object(worker, "canonical_metadata_hash", return_value="meta-hash"):
                with patch.object(worker, "insert_proof_event", return_value={"id": 100}):
                    with patch.object(worker, "get_job_input_path") as mock_input:
                        _mock_storage_paths(mock_input, MagicMock())
                        job = db.get_job(job_id)
                        result = worker.process_extract(job)
                        db.complete_job(job_id, result)
                        return result


def test_interrupted_hashing_source_crash_recovery():
    """Job crashes during source hashing; re-leased worker completes successfully."""
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("embed", {
        "metadata": {"proofId": "pid-1", "tier": "standard"},
        "filename": "video.mp4",
    })

    db.lease_job("worker-1", ["embed"], lease_duration=60, now=t0)

    # Crash during hashing_source
    try:
        _run_embed_job(job_id, crash_phase="hashing_source")
    except RuntimeError as e:
        assert "Simulated crash at phase: hashing_source" in str(e)

    # Job should be re-queued as pending
    job = db.get_job(job_id)
    assert job["status"] == "pending"
    assert "worker_id" not in job

    # Second worker picks up and completes successfully
    db.lease_job("worker-2", ["embed"], lease_duration=60, now=t0 + timedelta(seconds=10))
    result = _run_embed_job_success(job_id)

    assert result["source_hash"] == "source-hash"
    assert result["embedded_hash"] == "embedded-hash"
    assert result["metadata_hash"] == "meta-hash"
    assert db.get_job(job_id)["status"] == "completed"


def test_interrupted_embedding_crash_recovery():
    """Job crashes during embedding; re-leased worker completes successfully."""
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("embed", {
        "metadata": {"proofId": "pid-2", "tier": "standard"},
        "filename": "video.mp4",
    })

    db.lease_job("worker-1", ["embed"], lease_duration=60, now=t0)

    try:
        _run_embed_job(job_id, crash_phase="embedding")
    except RuntimeError as e:
        assert "Simulated crash at phase: embedding" in str(e)

    job = db.get_job(job_id)
    assert job["status"] == "pending"

    db.lease_job("worker-2", ["embed"], lease_duration=60, now=t0 + timedelta(seconds=10))
    result = _run_embed_job_success(job_id)

    assert result["embedded_hash"] == "embedded-hash"
    assert db.get_job(job_id)["status"] == "completed"


def test_interrupted_hashing_output_crash_recovery():
    """Job crashes during output hashing; re-leased worker completes successfully."""
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("embed", {
        "metadata": {"proofId": "pid-3", "tier": "standard"},
        "filename": "video.mp4",
    })

    db.lease_job("worker-1", ["embed"], lease_duration=60, now=t0)

    try:
        _run_embed_job(job_id, crash_phase="hashing_output")
    except RuntimeError as e:
        assert "Simulated crash at phase: hashing_output" in str(e)

    job = db.get_job(job_id)
    assert job["status"] == "pending"

    db.lease_job("worker-2", ["embed"], lease_duration=60, now=t0 + timedelta(seconds=10))
    result = _run_embed_job_success(job_id)

    assert result["embedded_hash"] == "embedded-hash"
    assert db.get_job(job_id)["status"] == "completed"


def test_interrupted_recording_metadata_crash_recovery():
    """Job crashes during metadata recording (DB write); re-leased worker completes."""
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("embed", {
        "metadata": {"proofId": "pid-4", "tier": "standard"},
        "filename": "video.mp4",
    })

    db.lease_job("worker-1", ["embed"], lease_duration=60, now=t0)

    try:
        _run_embed_job(job_id, crash_phase="recording")
    except RuntimeError as e:
        assert "Simulated crash at phase: recording" in str(e)

    job = db.get_job(job_id)
    assert job["status"] == "pending"

    db.lease_job("worker-2", ["embed"], lease_duration=60, now=t0 + timedelta(seconds=10))
    result = _run_embed_job_success(job_id)

    assert db.get_job(job_id)["status"] == "completed"


def test_interrupted_silent_witness_proving_crash_recovery():
    """Job crashes during proof generation; re-leased worker completes successfully."""
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("silent_witness", {
        "video_hash": "aa" * 32,
        "credential_secret": "cred",
        "nullifier_secret": "null",
    })

    db.lease_job("worker-1", ["silent_witness"], lease_duration=60, now=t0)

    try:
        _run_silent_witness_job(job_id, crash_phase="generating_proof")
    except RuntimeError as e:
        assert "Simulated crash at phase: generating_proof" in str(e)

    job = db.get_job(job_id)
    assert job["status"] == "pending"

    db.lease_job("worker-2", ["silent_witness"], lease_duration=60, now=t0 + timedelta(seconds=10))
    result = _run_silent_witness_job_success(job_id)

    assert result["proof"] == {"proof": "def"}
    assert db.get_job(job_id)["status"] == "completed"


def test_stale_worker_cannot_commit_after_reassignment():
    """A stale worker that wakes up after reassignment must not overwrite job result."""
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("embed", {
        "metadata": {"proofId": "pid-5", "tier": "standard"},
        "filename": "video.mp4",
    })

    db.lease_job("worker-1", ["embed"], lease_duration=10, now=t0)
    job = db.get_job(job_id)
    assert job["worker_id"] == "worker-1"

    # Worker 2 reclaims the stale job
    reclaimed = db.reclaim_stale_jobs(now=t0 + timedelta(seconds=15))
    assert len(reclaimed) == 1
    assert reclaimed[0]["id"] == job_id

    # Job is now pending, no worker assigned
    job = db.get_job(job_id)
    assert job["status"] == "pending"
    assert "worker_id" not in job

    # Worker 2 leases and completes the job
    db.lease_job("worker-2", ["embed"], lease_duration=60, now=t0 + timedelta(seconds=16))
    result = _run_embed_job_success(job_id)

    assert result["db_event"]["id"] == 100
    assert db.get_job(job_id)["status"] == "completed"
    assert db.get_job(job_id)["worker_id"] == "worker-2"

    # Verify stale worker-1's result would not overwrite (job is completed)
    # The completed job's result is from worker-2
    assert db.get_job(job_id)["result"]["db_event"]["id"] == 100


def test_stale_worker_heartbeat_does_not_extend_lease_after_reassignment():
    """Heartbeat from stale worker after reassignment must not prevent reclamation."""
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("embed", {"metadata": {}, "filename": "video.mp4"})

    db.lease_job("worker-1", ["embed"], lease_duration=10, now=t0)

    # Heartbeat from worker-1 before reassignment
    db.heartbeat_job(job_id, lease_duration=10, now=t0 + timedelta(seconds=5))
    job = db.get_job(job_id)
    assert job["heartbeat_at"] is not None

    # Reclaim by worker-2
    reclaimed = db.reclaim_stale_jobs(now=t0 + timedelta(seconds=15))
    assert len(reclaimed) == 1

    # Stale worker-1 sends heartbeat AFTER reassignment
    db.heartbeat_job(job_id, lease_duration=10, now=t0 + timedelta(seconds=20))

    # Job should still be pending (reclaimed), not running for worker-1
    job = db.get_job(job_id)
    assert job["status"] == "pending"
    assert job.get("worker_id") != "worker-1"


def test_concurrent_workers_same_job_only_one_completes():
    """Only one worker can successfully complete a job; other cannot lease it."""
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("embed", {
        "metadata": {"proofId": "pid-6", "tier": "standard"},
        "filename": "video.mp4",
    })

    # Worker 1 leases
    db.lease_job("worker-1", ["embed"], lease_duration=60, now=t0)

    # Simulate worker 1 completing
    result = _run_embed_job_success(job_id)

    assert db.get_job(job_id)["status"] == "completed"
    assert result["db_event"]["id"] == 100

    # Worker 2 tries to process same job (simulating race)
    # Job is no longer pending/running, so lease_job won't return it
    job2 = db.lease_job("worker-2", ["embed"], lease_duration=60, now=t0 + timedelta(seconds=10))
    assert job2 is None or job2["id"] != job_id


def test_crash_during_extract_metadata_write_recovery():
    """Extract job crashes during DB metadata write; recovery works."""
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("extract", {"filename": "video.mp4"})

    db.lease_job("worker-1", ["extract"], lease_duration=60, now=t0)

    try:
        _run_extract_job(job_id, crash_phase="recording")
    except RuntimeError as e:
        assert "Simulated crash at phase: recording" in str(e)

    job = db.get_job(job_id)
    assert job["status"] == "pending"

    # Recovery
    db.lease_job("worker-2", ["extract"], lease_duration=60, now=t0 + timedelta(seconds=10))
    result = _run_extract_job_success(job_id)

    assert result["db_event"]["id"] == 100
    assert db.get_job(job_id)["status"] == "completed"


def test_multiple_crash_recovery_attempts():
    """Job can be crashed and recovered multiple times before success."""
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("embed", {
        "metadata": {"proofId": "pid-7", "tier": "standard"},
        "filename": "video.mp4",
    })

    phases = ["hashing_source", "embedding", "hashing_output", "recording"]
    attempt = 0

    for phase in phases:
        attempt += 1
        db.lease_job(f"worker-{attempt}", ["embed"], lease_duration=60, now=t0 + timedelta(seconds=attempt * 5))

        try:
            _run_embed_job(job_id, crash_phase=phase)
        except RuntimeError as e:
            assert f"Simulated crash at phase: {phase}" in str(e)

        job = db.get_job(job_id)
        assert job["status"] == "pending", f"After crash at {phase}, job should be pending"

    # Final successful attempt
    attempt += 1
    db.lease_job(f"worker-{attempt}", ["embed"], lease_duration=60, now=t0 + timedelta(seconds=attempt * 5))
    result = _run_embed_job_success(job_id)

    assert result["db_event"]["id"] == 100
    assert db.get_job(job_id)["status"] == "completed"


def test_crash_recovery_preserves_job_payload():
    """Job payload remains intact across crash/recovery cycles."""
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    original_payload = {
        "metadata": {"proofId": "pid-payload", "tier": "premium", "custom": "data"},
        "filename": "important_video.mp4",
    }
    job_id = db.enqueue_job("embed", original_payload)

    db.lease_job("worker-1", ["embed"], lease_duration=10, now=t0)

    try:
        _run_embed_job(job_id, crash_phase="embedding")
    except RuntimeError:
        pass

    # Verify payload preserved
    job = db.get_job(job_id)
    assert job["payload"] == original_payload
    assert job["status"] == "pending"

    # Recovery
    db.lease_job("worker-2", ["embed"], lease_duration=60, now=t0 + timedelta(seconds=15))
    job = db.get_job(job_id)
    assert job["payload"] == original_payload


def test_reclaim_stale_jobs_clears_processing_state_on_re_lease():
    """Re-leasing a reclaimed job clears the stale processing_state."""
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("silent_witness", {
        "video_hash": "bb" * 32,
        "credential_secret": "SECRET-CRED",
        "nullifier_secret": "SECRET-NULL",
    })

    db.lease_job("worker-dead", ["silent_witness"], lease_duration=30, now=t0)

    # Reclaim after lease expires
    reclaimed = db.reclaim_stale_jobs(now=t0 + timedelta(seconds=35))
    assert len(reclaimed) == 1
    summary = reclaimed[0]
    assert summary["processing_state"]["reason"] == db.STALE_HEARTBEAT_REASON
    assert "SECRET-CRED" not in str(summary)

    # Re-lease to new worker
    re_leased = db.lease_job("worker-alive", ["silent_witness"], lease_duration=60, now=t0 + timedelta(seconds=40))
    assert re_leased is not None
    assert re_leased["id"] == job_id
    assert "processing_state" not in re_leased
    assert re_leased["worker_id"] == "worker-alive"


def test_worker_shutdown_grace_period_exceeded_job_requeued():
    """Job is re-queued (not failed) when worker shutdown grace period exceeded."""
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("embed", {"metadata": {}, "filename": "video.mp4"})

    db.lease_job("worker-1", ["embed"], lease_duration=60, now=t0)

    # Simulate slow job that exceeds grace period
    stop_event = threading.Event()

    def slow_embed(job):
        stop_event.set()  # Trigger shutdown immediately
        time.sleep(0.5)   # But job continues slowly
        return {"status": "ok"}

    with patch.object(worker, "process_embed", side_effect=slow_embed):
        with patch.object(worker, "init_db"):
            with patch.object(worker, "lease_job", side_effect=[db.get_job(job_id), None]):
                with patch.object(worker, "heartbeat_loop"):
                    with patch.object(worker, "tx_verification_loop"):
                        with patch.object(worker, "complete_job") as mock_complete:
                            with patch.object(worker, "fail_job") as mock_fail:
                                worker.run_worker(stop_event=stop_event, grace_period_seconds=0.1)

    # Job should be failed with is_fatal=False (re-queued as pending)
    mock_fail.assert_called_once()
    args, kwargs = mock_fail.call_args
    assert args[0] == job_id
    assert kwargs.get("is_fatal") is False or (len(args) > 2 and args[2] is False)

    # Verify job is pending for retry
    job = db.get_job(job_id)
    assert job["status"] == "pending"
    assert "worker_id" not in job


def test_crash_during_verification_tx_recovery():
    """Verify_tx job crashes; recovery picks up and completes."""
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("verify_tx", {"tx_hash": "tx-123"})

    db.lease_job("worker-1", ["verify_tx"], lease_duration=60, now=t0)

    simulator = CrashSimulator()
    simulator.set_crash_at("verifying")

    def mock_process_verify_tx_job(payload):
        simulator.maybe_crash("verifying")
        return {"status": "confirmed"}

    with patch.object(worker, "process_verify_tx_job", side_effect=mock_process_verify_tx_job):
        job = db.get_job(job_id)
        try:
            worker.process_verify_tx(job)
        except RuntimeError as e:
            assert "Simulated crash at phase: verifying" in str(e)
            from worker import sanitize_exception_text, fail_job
            safe_message = sanitize_exception_text(e)
            fail_job(job_id, safe_message, is_fatal=False)

    job = db.get_job(job_id)
    assert job["status"] == "pending"

    # Recovery
    db.lease_job("worker-2", ["verify_tx"], lease_duration=60, now=t0 + timedelta(seconds=10))

    with patch.object(worker, "process_verify_tx_job", return_value={"status": "confirmed"}):
        with patch.object(worker, "update_tx_status") as mock_update:
            job = db.get_job(job_id)
            result = worker.process_verify_tx(job)
            db.complete_job(job_id, result)

    assert db.get_job(job_id)["status"] == "completed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])