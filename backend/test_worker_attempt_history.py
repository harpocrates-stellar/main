"""Tests for bounded privacy-safe worker attempt history (issue #1107)."""

from __future__ import annotations

import json
import pytest

import app as app_module
import db


@pytest.fixture(autouse=True)
def isolated_jobs(monkeypatch):
    monkeypatch.delenv("JOB_ATTEMPT_HISTORY_MAX_ENTRIES", raising=False)
    saved_jobs = dict(db._JOBS)
    saved_next = db._next_job_id
    db._JOBS.clear()
    db._next_job_id = 1
    try:
        yield
    finally:
        db._JOBS.clear()
        db._JOBS.update(saved_jobs)
        db._next_job_id = saved_next


def test_records_lease_progress_and_terminal_reason_across_retries():
    job_id = db.enqueue_job(
        "embed",
        {"filename": "synthetic.mp4", "metadata": {"proofId": "11" * 32}},
    )

    # Attempt 1: leased, heartbeated, reported progress, then failed transiently
    leased_1 = db.lease_job("worker-alpha", ["embed"], lease_duration=180)
    assert leased_1 is not None
    db.heartbeat_job(job_id, lease_duration=240)
    assert db.report_job_progress(job_id, "hashing_source", None, now=1.0) is True
    assert db.report_job_progress(job_id, "embedding", 35.0, now=2.5) is True
    db.fail_job(
        job_id,
        "Worker shutdown grace period exceeded",
        is_fatal=False,
        reason="grace_period_exceeded",
        error_type="TimeoutError",
    )

    # Attempt 2: leased by another worker, completed cleanly
    leased_2 = db.lease_job("worker-beta", ["embed"], lease_duration=300)
    assert leased_2 is not None
    assert db.report_job_progress(job_id, "hashing_source", None, now=5.0) is True
    assert db.report_job_progress(job_id, "embedding", 100.0, now=7.0) is True
    assert db.report_job_progress(job_id, "recording", None, now=9.0) is True
    db.complete_job(job_id, {"embedded_hash": "ab" * 32})

    job = db.get_job(job_id)
    assert job is not None
    assert job["attempt_count"] == 2
    assert job["attempts_evicted"] == 0

    history = db.get_job_attempt_history(job_id)
    assert len(history) == 2

    first = history[0]
    assert first["attempt"] == 1
    assert first["worker_id"] == "worker-alpha"
    assert first["status"] == "requeued"
    assert first["leased_at"] is not None
    assert first["heartbeat_at"] is not None
    assert first["lease_duration_seconds"] == 240
    assert first["last_progress"] == {"phase": "embedding", "percent": 35.0}
    assert first["phases"] == ["hashing_source", "embedding"]
    assert first["ended_at"] is not None
    assert first["terminal_reason"] == "grace_period_exceeded"
    assert first["error_type"] == "TimeoutError"

    second = history[1]
    assert second["attempt"] == 2
    assert second["worker_id"] == "worker-beta"
    assert second["status"] == "completed"
    assert second["lease_duration_seconds"] == 300
    assert second["last_progress"] == {"phase": "recording", "percent": None}
    assert second["phases"] == ["hashing_source", "embedding", "recording"]
    assert second["terminal_reason"] == "completed"
    assert second["error_type"] is None


def test_attempt_history_is_bounded_and_tracks_evictions(monkeypatch):
    monkeypatch.setenv("JOB_ATTEMPT_HISTORY_MAX_ENTRIES", "3")
    job_id = db.enqueue_job("verify_tx", {"tx_hash": "22" * 32})

    for idx in range(1, 7):
        leased = db.lease_job(f"worker-{idx}", ["verify_tx"], lease_duration=120)
        assert leased is not None
        if idx < 6:
            db.fail_job(job_id, "temporary upstream blip", is_fatal=False, error_type="ConnectionError")
        else:
            db.complete_job(job_id, {"status": "confirmed"})

    job = db.get_job(job_id)
    assert job is not None
    assert job["attempt_count"] == 6
    assert job["attempts_evicted"] == 3

    history = db.get_job_attempt_history(job_id)
    assert len(history) == 3
    assert [entry["attempt"] for entry in history] == [4, 5, 6]
    assert [entry["status"] for entry in history] == ["requeued", "requeued", "completed"]


def test_attempt_history_excludes_media_bytes_private_paths_and_proof_secrets():
    private_path = "/var/private/harpocrates_jobs/job_42_input_secret.mp4"
    win_private_path = r"C:\Users\alice\private\evidence_clip.mp4"
    credential_secret = "98765432109876543210987654321"
    nullifier_secret = "12345678901234567890123456789"
    media_bytes = b"\x00\x00\x00\x18ftypmp42SENSITIVE_MEDIA_BYTES"

    job_id = db.enqueue_job(
        "silent_witness",
        {
            "video_hash": "aa" * 32,
            "credential_secret": credential_secret,
            "nullifier_secret": nullifier_secret,
            "raw_media": media_bytes,
            "input_path": private_path,
        },
    )

    leased = db.lease_job(f"worker@{private_path}", ["silent_witness"])
    assert leased is not None
    assert leased["worker_id"] == "redacted-worker"

    assert db.report_job_progress(job_id, f"stage:{win_private_path}", 50.0, now=1.0) is True
    db.fail_job(
        job_id,
        f"Input video file missing at {private_path} / {win_private_path} "
        f"credential_secret={credential_secret} nullifier_secret={nullifier_secret}",
        is_fatal=True,
        error_type=f"RuntimeError({private_path})",
    )

    # Inject adversarial raw bytes on top-level job dict to verify public_job_view strips them
    db._JOBS[job_id]["unexpected_media_blob"] = media_bytes

    history = db.get_job_attempt_history(job_id)
    assert len(history) == 1
    entry = history[0]
    assert entry["worker_id"] == "redacted-worker"
    assert entry["last_progress"] == {"phase": "redacted_phase", "percent": 50.0}
    assert entry["terminal_reason"] == "missing_input"
    assert entry["error_type"] is None

    flask_app = app_module.create_app()
    flask_app.config["TESTING"] = True
    resp = flask_app.test_client().get(f"/api/jobs/{job_id}")
    assert resp.status_code == 200
    serialized = resp.get_data(as_text=True)
    parsed = json.loads(serialized)
    assert parsed["ok"] is True
    assert len(parsed["job"]["attempt_history"]) == 1

    for forbidden in (
        private_path,
        "job_42_input_secret",
        win_private_path,
        "evidence_clip",
        credential_secret,
        nullifier_secret,
        "SENSITIVE_MEDIA_BYTES",
        "credential_secret",
        "nullifier_secret",
    ):
        assert forbidden not in serialized
        assert forbidden not in json.dumps(history)


def test_cancelled_job_records_cancelled_attempt_entry():
    job_id = db.enqueue_job("embed", {"filename": "clip.mp4", "metadata": {}})
    assert db.cancel_job(job_id) is True

    history = db.get_job_attempt_history(job_id)
    assert len(history) == 1
    assert history[0]["status"] == "cancelled"
    assert history[0]["terminal_reason"] == "cancelled"
    assert history[0]["ended_at"] is not None


def test_invalid_attempt_history_env_bound_rejected(monkeypatch):
    for invalid in ("0", "-5", "abc"):
        monkeypatch.setenv("JOB_ATTEMPT_HISTORY_MAX_ENTRIES", invalid)
        with pytest.raises(ValueError, match="JOB_ATTEMPT_HISTORY_MAX_ENTRIES"):
            db.job_attempt_history_max_entries()

    monkeypatch.setenv("JOB_ATTEMPT_HISTORY_MAX_ENTRIES", "9999")
    assert db.job_attempt_history_max_entries() == db.JOB_ATTEMPT_HISTORY_HARD_CAP
