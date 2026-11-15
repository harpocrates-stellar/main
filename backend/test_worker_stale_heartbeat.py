from __future__ import annotations

from datetime import datetime, timedelta, timezone
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

import app as app_module
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


def test_stale_worker_heartbeat_exposes_retryable_reason_and_unverified_status() -> None:
    t0 = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job(
        "silent_witness",
        {"video_hash": "aa" * 32, "credential_secret": "cred", "nullifier_secret": "null"},
    )
    leased = db.lease_job("worker-1", ["silent_witness"], lease_duration=120, now=t0)
    assert leased is not None

    # Fresh heartbeat at t0 + 30s -> active, not stale
    db.heartbeat_job(job_id, lease_duration=120, now=t0 + timedelta(seconds=30))
    fresh_status = db.inspect_job_heartbeat(job_id, now=t0 + timedelta(seconds=90))
    assert fresh_status is not None
    assert fresh_status.processing_state == "active"
    assert fresh_status.state_reason is None
    assert fresh_status.retryable is True
    assert fresh_status.verification_status == db.VERIFICATION_UNVERIFIED
    assert fresh_status.cryptographic_failure is False

    # Past 120s since last heartbeat (t0 + 160s => 130s silence) -> stale_heartbeat, retryable, unverified!
    stale_status = db.inspect_job_heartbeat(job_id, now=t0 + timedelta(seconds=160))
    assert stale_status is not None
    assert stale_status.processing_state == "stale_heartbeat"
    assert stale_status.state_reason == db.REASON_WORKER_HEARTBEAT_STALE
    assert stale_status.retryable is True
    assert stale_status.verification_status == db.VERIFICATION_UNVERIFIED
    assert stale_status.cryptographic_failure is False
    assert stale_status.heartbeat_age_seconds == 130.0

    # Sweep transitions stale job back to pending for retry while preserving retryable reason & unverified state
    transitioned = db.sweep_stale_worker_heartbeats(requeue=True, now=t0 + timedelta(seconds=160))
    assert len(transitioned) == 1
    stored = db.get_job(job_id)
    assert stored is not None
    assert stored["status"] == "pending"
    assert stored["processing_state"] == "stale_heartbeat"
    assert stored["state_reason"] == db.REASON_WORKER_HEARTBEAT_STALE
    assert stored["retryable"] is True
    assert stored["verification_status"] == db.VERIFICATION_UNVERIFIED
    assert stored["cryptographic_failure"] is False
    assert stored["stale_heartbeat_count"] == 1
    assert "worker_id" not in stored

    # Public API view exposes retryable stale-heartbeat state without leaking payload secrets
    flask_app = app_module.create_app()
    flask_app.config["TESTING"] = True
    resp = flask_app.test_client().get(f"/api/jobs/{job_id}")
    assert resp.status_code == 200
    pub_job = resp.get_json()["job"]
    assert pub_job["processing_state"] == "stale_heartbeat"
    assert pub_job["state_reason"] == "worker_heartbeat_stale"
    assert pub_job["retryable"] is True
    assert pub_job["verification_status"] == "unverified"
    assert pub_job["cryptographic_failure"] is False
    assert "payload" not in pub_job


def test_cryptographic_proof_invalidity_is_distinct_from_stale_heartbeat_and_validation_errors() -> None:
    stale_cls = worker.classify_worker_failure(
        "silent_witness",
        worker.StaleWorkerHeartbeatError("heartbeat timed out during witness generation"),
    )
    assert stale_cls.is_fatal is False
    assert stale_cls.retryable is True
    assert stale_cls.state_reason == db.REASON_WORKER_HEARTBEAT_STALE
    assert stale_cls.verification_status == db.VERIFICATION_UNVERIFIED
    assert stale_cls.cryptographic_failure is False
    assert worker.is_fatal("silent_witness", worker.StaleWorkerHeartbeatError("stale")) is False

    # Input validation ValueError is fatal, but still unverified (NOT cryptographic proof invalidity)
    val_cls = worker.classify_worker_failure("silent_witness", ValueError("malformed field encoding"))
    assert val_cls.is_fatal is True
    assert val_cls.retryable is False
    assert val_cls.state_reason == db.REASON_INPUT_VALIDATION_FAILED
    assert val_cls.verification_status == db.VERIFICATION_UNVERIFIED
    assert val_cls.cryptographic_failure is False

    # Explicit ProofCryptographicInvalidError is fatal AND cryptographic_failure=True
    crypto_cls = worker.classify_worker_failure(
        "silent_witness",
        worker.ProofCryptographicInvalidError("Noir verifier rejected proof"),
    )
    assert crypto_cls.is_fatal is True
    assert crypto_cls.retryable is False
    assert crypto_cls.state_reason == db.REASON_PROOF_INVALID
    assert crypto_cls.verification_status == db.VERIFICATION_INVALID
    assert crypto_cls.cryptographic_failure is True
    assert worker.is_fatal("silent_witness", worker.ProofCryptographicInvalidError("bad proof")) is True


def test_fail_job_rejects_misclassifying_stale_heartbeat_or_unverified_output_as_crypto_failure() -> None:
    job_id = db.enqueue_job("silent_witness", {"video_hash": "bb" * 32})
    db.lease_job("worker-1", ["silent_witness"])

    with pytest.raises(ValueError, match="stale worker heartbeat is retryable"):
        db.fail_job(
            job_id,
            "heartbeat lost",
            is_fatal=True,
            state_reason=db.REASON_WORKER_HEARTBEAT_STALE,
        )

    with pytest.raises(ValueError, match="stale worker heartbeat is retryable"):
        db.fail_job(
            job_id,
            "heartbeat lost",
            is_fatal=False,
            state_reason=db.REASON_WORKER_HEARTBEAT_STALE,
            cryptographic_failure=True,
        )

    with pytest.raises(ValueError, match="unverified output cannot be marked"):
        db.fail_job(
            job_id,
            "prover crashed before verification",
            is_fatal=False,
            verification_status=db.VERIFICATION_INVALID,
            cryptographic_failure=False,
        )

    with pytest.raises(ValueError, match="stale_after_seconds must be positive"):
        db.inspect_job_heartbeat(job_id, stale_after_seconds=0)


def test_run_worker_records_stale_heartbeat_and_crypto_failures_distinctly() -> None:
    stop_event = threading.Event()
    j_stale = db.enqueue_job("silent_witness", {"video_hash": "11" * 32})
    j_crypto = db.enqueue_job("silent_witness", {"video_hash": "22" * 32})

    queue = [j_stale, j_crypto]

    def fake_lease(*args, **kwargs):
        if not queue:
            stop_event.set()
            return None
        jid = queue.pop(0)
        db._JOBS[jid]["status"] = "running"
        return dict(db._JOBS[jid])

    def fake_witness(job):
        if job["id"] == j_stale:
            raise worker.StaleWorkerHeartbeatError("prover worker heartbeat lost")
        raise worker.ProofCryptographicInvalidError("cryptographic proof verification failed")

    with patch.object(worker, "init_db"), \
         patch.object(worker, "lease_job", side_effect=fake_lease), \
         patch.object(worker, "process_silent_witness", side_effect=fake_witness), \
         patch.object(worker, "heartbeat_loop"), \
         patch.object(worker, "tx_verification_loop"), \
         patch.object(worker, "run_indexer_loop"), \
         patch.object(worker, "sweep_job_files"):
        worker.run_worker(stop_event=stop_event, grace_period_seconds=1.0)

    stale_row = db.get_job(j_stale)
    assert stale_row is not None
    assert stale_row["status"] == "pending"
    assert stale_row["processing_state"] == "stale_heartbeat"
    assert stale_row["state_reason"] == "worker_heartbeat_stale"
    assert stale_row["retryable"] is True
    assert stale_row["verification_status"] == "unverified"
    assert stale_row["cryptographic_failure"] is False

    crypto_row = db.get_job(j_crypto)
    assert crypto_row is not None
    assert crypto_row["status"] == "failed"
    assert crypto_row["processing_state"] == "failed"
    assert crypto_row["state_reason"] == "proof_invalid"
    assert crypto_row["retryable"] is False
    assert crypto_row["verification_status"] == "invalid"
    assert crypto_row["cryptographic_failure"] is True
