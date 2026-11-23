import os
import sys
import threading
from unittest.mock import patch

import pytest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

# Stub missing baseline exports so worker imports cleanly in isolation.
import stego
if not hasattr(stego, "StegoLimitExceededError"):
    class _StegoLimitExceededError(Exception):
        pass
    stego.StegoLimitExceededError = _StegoLimitExceededError

import verifier_inputs
if not hasattr(verifier_inputs, "MAX_AGGREGATION_SIZE"):
    verifier_inputs.MAX_AGGREGATION_SIZE = 16
if not hasattr(verifier_inputs, "MIN_AGGREGATION_SIZE"):
    verifier_inputs.MIN_AGGREGATION_SIZE = 2
if not hasattr(verifier_inputs, "check_aggregation_batch_size"):
    verifier_inputs.check_aggregation_batch_size = lambda x: None

import tx_verification
if not hasattr(tx_verification, "normalize_tx_hash"):
    tx_verification.normalize_tx_hash = lambda x: str(x) if x else None
if not hasattr(tx_verification, "verify_transaction"):
    tx_verification.verify_transaction = lambda *args, **kwargs: None

import types

_installed_app_stub = False
if "app" not in sys.modules:
    _app_stub = types.ModuleType("app")
    _app_stub.safe_filename = lambda name: str(name)
    _app_stub.normalize_filename = lambda name: str(name)
    _app_stub.redact_metadata = lambda meta: meta
    sys.modules["app"] = _app_stub
    _installed_app_stub = True

import db
import worker

if _installed_app_stub:
    sys.modules.pop("app", None)


@pytest.fixture(autouse=True)
def _clean_jobs():
    db._JOBS.clear()
    db._next_job_id = 1
    yield
    db._JOBS.clear()


def test_worker_cancellation_skips_failure_retry_and_preserves_stable_result():
    job_id = db.enqueue_job("embed", {"filename": "sample.mp4", "metadata": {}})
    stop_event = threading.Event()

    def _cancel_in_processor(job):
        stop_event.set()
        raise worker.JobCancelledError("requester cancelled")

    with patch.object(worker, "init_db"), \
         patch.object(worker, "process_embed", side_effect=_cancel_in_processor), \
         patch.object(worker, "heartbeat_loop"), \
         patch.object(worker, "tx_verification_loop"), \
         patch.object(worker, "run_indexer_loop"), \
         patch.object(worker, "sweep_job_files"):
        worker.run_worker(stop_event=stop_event, grace_period_seconds=1.0)

    job = db.get_job(job_id)
    assert job is not None
    assert job["status"] == "cancelled"
    assert job["retry_count"] == 0
    assert job["result"] == {"cancelled": True, "reason": "requester cancelled"}
    assert "cancelled_at" in job
    assert "error" not in job
    assert "failed_at" not in job
    # Cancelled job is never re-leased for automatic retry.
    assert db.lease_job("worker-other", ["embed"]) is None


def test_running_job_cancelled_externally_is_not_overwritten_by_completion_or_error():
    job_id = db.enqueue_job("embed", {"filename": "sample.mp4", "metadata": {}})
    stop_event = threading.Event()

    def _complete_after_external_cancel(job):
        assert db.cancel_job(job["id"], reason="user aborted") is True
        stop_event.set()
        return {"embedded_hash": "abc"}

    with patch.object(worker, "init_db"), \
         patch.object(worker, "process_embed", side_effect=_complete_after_external_cancel), \
         patch.object(worker, "heartbeat_loop"), \
         patch.object(worker, "tx_verification_loop"), \
         patch.object(worker, "run_indexer_loop"), \
         patch.object(worker, "sweep_job_files"):
        worker.run_worker(stop_event=stop_event, grace_period_seconds=1.0)

    job = db.get_job(job_id)
    assert job["status"] == "cancelled"
    assert job["retry_count"] == 0
    assert job["result"] == {"cancelled": True, "reason": "user aborted"}
    assert "completed_at" not in job

    # Even if fail_job or complete_job is invoked late, cancelled state is preserved.
    db.fail_job(job_id, "late failure", is_fatal=False)
    db.complete_job(job_id, {"embedded_hash": "late"})
    assert job["status"] == "cancelled"
    assert job["retry_count"] == 0
    assert job["result"] == {"cancelled": True, "reason": "user aborted"}


def test_processing_failure_still_increments_retry_count_and_requeues():
    job_id = db.enqueue_job("embed", {"filename": "sample.mp4", "metadata": {}})
    stop_event = threading.Event()

    def _transient_failure(job):
        stop_event.set()
        raise RuntimeError("transient encoder error")

    with patch.object(worker, "init_db"), \
         patch.object(worker, "process_embed", side_effect=_transient_failure), \
         patch.object(worker, "heartbeat_loop"), \
         patch.object(worker, "tx_verification_loop"), \
         patch.object(worker, "run_indexer_loop"), \
         patch.object(worker, "sweep_job_files"):
        worker.run_worker(stop_event=stop_event, grace_period_seconds=1.0)

    job = db.get_job(job_id)
    assert job["status"] == "pending"
    assert job["retry_count"] == 1
    assert job["error"] == "transient encoder error"
    assert "failed_at" in job
    assert "cancelled_at" not in job


def test_cancel_boundary_terminal_and_idempotent_states():
    done_id = db.enqueue_job("extract", {"filename": "done.mp4"})
    db.complete_job(done_id, {"video_hash": "h1"})
    assert db.cancel_job(done_id) is False
    assert db.get_job(done_id)["status"] == "completed"

    failed_id = db.enqueue_job("extract", {"filename": "bad.mp4"})
    db.fail_job(failed_id, "bad input", is_fatal=True)
    assert db.cancel_job(failed_id) is False
    assert db.get_job(failed_id)["status"] == "failed"

    cancelled_id = db.enqueue_job("extract", {"filename": "cancel.mp4"})
    assert db.cancel_job(cancelled_id, reason="first reason") is True
    first_ts = db.get_job(cancelled_id)["cancelled_at"]
    assert db.mark_job_cancelled(cancelled_id, reason="second reason") is True
    assert db.get_job(cancelled_id)["cancelled_at"] == first_ts
    assert db.get_job(cancelled_id)["result"] == {"cancelled": True, "reason": "first reason"}
