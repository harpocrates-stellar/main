from __future__ import annotations

import threading
from concurrent.futures import CancelledError
from pathlib import Path
from unittest.mock import patch

import pytest

import app as app_module
import db
import worker


@pytest.fixture(autouse=True)
def _reset_jobs(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("JOB_MAX_RETRIES", raising=False)
    with db._JOBS_LOCK:
        db._JOBS.clear()
        db._next_job_id = 1
    yield
    with db._JOBS_LOCK:
        db._JOBS.clear()


def test_cancel_pending_job_skips_lease_and_preserves_zero_failure_counts() -> None:
    job_id = db.enqueue_job(
        "embed",
        {"filename": "private_source_clip.bin", "metadata": {"proofId": "p-1"}},
    )

    assert db.cancel_job(job_id) is True

    job = db.get_job(job_id)
    assert job is not None
    assert job["status"] == "cancelled"
    assert job["result"] == {"code": "CANCELLED", "cancelled": True}
    assert job["failure_count"] == 0
    assert job["retry_count"] == 0
    assert "error" not in job
    assert db.lease_job("worker-1", ["embed"]) is None


def test_late_worker_updates_cannot_clobber_stable_cancelled_result() -> None:
    job_id = db.enqueue_job("embed", {"filename": "clip.bin", "metadata": {}})
    leased = db.lease_job("worker-1", ["embed"])
    assert leased is not None and leased["id"] == job_id

    assert db.report_job_progress(job_id, "embedding", 25.0, now=10.0) is True
    assert db.cancel_job(job_id) is True

    # Late progress, heartbeat, completion, or failure from an in-flight worker
    # must be ignored and must keep failure/retry counts untouched.
    assert db.report_job_progress(job_id, "hashing_output", 90.0, now=20.0) is False
    db.heartbeat_job(job_id)
    assert db.complete_job(job_id, {"embedded_hash": "a" * 64}) is False
    assert db.fail_job(job_id, "ffmpeg exited 1", is_fatal=False) is False

    job = db.get_job(job_id)
    assert job is not None
    assert job["status"] == "cancelled"
    assert job["result"] == {"code": "CANCELLED", "cancelled": True}
    assert job["failure_count"] == 0
    assert job["retry_count"] == 0
    assert "error" not in job


def test_transient_processing_failures_retry_until_exhausted_unlike_cancellation() -> None:
    job_id = db.enqueue_job("embed", {"filename": "clip.bin", "metadata": {}}, max_retries=2)

    # Attempt 1 fails transiently -> re-queued as pending, retry_count=1
    assert db.lease_job("worker-1", ["embed"]) is not None
    assert db.fail_job(job_id, "transient timeout", is_fatal=False) is True
    job = db.get_job(job_id)
    assert job is not None
    assert job["status"] == "pending"
    assert job["failure_count"] == 1
    assert job["retry_count"] == 1

    # Attempt 2 fails transiently -> re-queued as pending, retry_count=2
    assert db.lease_job("worker-1", ["embed"]) is not None
    assert db.fail_job(job_id, "transient timeout", is_fatal=False) is True
    job = db.get_job(job_id)
    assert job is not None
    assert job["status"] == "pending"
    assert job["failure_count"] == 2
    assert job["retry_count"] == 2

    # Attempt 3 exhausts max_retries=2 -> terminal failed
    assert db.lease_job("worker-1", ["embed"]) is not None
    assert db.fail_job(job_id, "transient timeout", is_fatal=False) is True
    job = db.get_job(job_id)
    assert job is not None
    assert job["status"] == "failed"
    assert job["failure_count"] == 3
    assert job["retry_count"] == 2
    assert db.cancel_job(job_id) is False


def test_in_flight_embed_cancellation_cleans_temp_files_and_acknowledges_cleanly(
    tmp_path: Path,
) -> None:
    in_file = tmp_path / "job-in.bin"
    out_file = tmp_path / "job-out.bin"
    in_file.write_bytes(b"synthetic-frame-bytes")
    out_file.write_bytes(b"partial-output")

    job_id = db.enqueue_job(
        "embed",
        {"filename": " confidential_witness.bin ", "metadata": {"proofId": "p-9"}},
    )

    stop_event = threading.Event()

    def _fake_embed(input_path, output_path, metadata, progress_callback=None):
        assert progress_callback is not None
        progress_callback(1, 4)
        # Simulate requester cancelling while ffmpeg is mid-stream
        assert db.cancel_job(job_id) is True
        progress_callback(2, 4)

    with (
        patch.object(worker, "init_db"),
        patch.object(worker, "tx_verification_loop"),
        patch.object(worker, "run_indexer_loop"),
        patch.object(worker, "sweep_job_files"),
        patch.object(worker, "get_job_input_path", return_value=in_file),
        patch.object(worker, "get_job_output_path", return_value=out_file),
        patch.object(worker, "sha256_file", return_value="b" * 64),
        patch.object(worker, "embed_metadata", side_effect=_fake_embed),
        patch.object(
            worker,
            "acknowledge_job_cancellation",
            wraps=db.acknowledge_job_cancellation,
        ) as ack_spy,
        patch.object(worker, "fail_job", wraps=db.fail_job) as fail_spy,
    ):
        original_ack = db.acknowledge_job_cancellation

        def _ack_and_stop(jid):
            res = original_ack(jid)
            stop_event.set()
            return res

        ack_spy.side_effect = _ack_and_stop
        worker.run_worker(stop_event=stop_event, grace_period_seconds=2.0)

    assert ack_spy.call_count == 1
    assert fail_spy.call_count == 0
    assert not in_file.exists()
    assert not out_file.exists()

    stored = db.get_job(job_id)
    assert stored is not None
    assert stored["status"] == "cancelled"
    assert stored["result"] == {"code": "CANCELLED", "cancelled": True}
    assert stored["failure_count"] == 0
    assert stored["retry_count"] == 0


def test_worker_treats_concurrent_futures_cancelled_error_as_cancellation() -> None:
    assert worker.is_cancellation(db.JobCancelledError("cancelled")) is True
    assert worker.is_cancellation(CancelledError()) is True
    assert worker.is_cancellation(RuntimeError("boom")) is False
    assert worker.is_fatal("embed", db.JobCancelledError("cancelled")) is False
    assert worker.is_fatal("embed", ValueError("bad input")) is True


def test_http_cancel_and_status_preserve_stable_result_without_leaking_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "testing")
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5173")
    flask_app = app_module.create_app()
    client = flask_app.test_client()

    secret_marker = "98765432109876543210987654321"
    job_id = db.enqueue_job(
        "silent_witness",
        {
            "video_hash": "a" * 64,
            "credential_secret": secret_marker,
            "nullifier_secret": "123456789",
        },
    )
    db.lease_job("worker-http", ["silent_witness"])

    first = client.post(f"/api/jobs/{job_id}/cancel")
    assert first.status_code == 200
    body1 = first.get_json()
    assert body1["ok"] is True
    assert body1["job"]["status"] == "cancelled"
    assert body1["job"]["result"] == {"code": "CANCELLED", "cancelled": True}
    assert body1["job"]["failure_count"] == 0
    assert body1["job"]["retry_count"] == 0
    assert secret_marker not in first.get_data(as_text=True)

    # Idempotent repeat cancel returns identical cancelled result
    second = client.post(f"/api/jobs/{job_id}/cancel")
    assert second.status_code == 200
    assert second.get_json()["job"]["result"] == {"code": "CANCELLED", "cancelled": True}

    # Polling GET /api/jobs/<id> preserves the stable cancelled result
    polled = client.get(f"/api/jobs/{job_id}")
    assert polled.status_code == 200
    polled_job = polled.get_json()["job"]
    assert polled_job["status"] == "cancelled"
    assert polled_job["result"] == {"code": "CANCELLED", "cancelled": True}
    assert secret_marker not in polled.get_data(as_text=True)

    # Completed and unknown jobs reject cancellation with 400
    done_id = db.enqueue_job("verify_tx", {"tx_hash": "c" * 64})
    db.lease_job("worker-http", ["verify_tx"])
    db.complete_job(done_id, {"status": "confirmed"})
    completed_cancel = client.post(f"/api/jobs/{done_id}/cancel")
    assert completed_cancel.status_code == 400
    assert "error" in completed_cancel.get_json()

    missing_cancel = client.post("/api/jobs/987654321/cancel")
    assert missing_cancel.status_code == 400
    assert "error" in missing_cancel.get_json()
