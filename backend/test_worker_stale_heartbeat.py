"""Focused tests for stale worker heartbeat reporting and reclamation.

Verifies that a stale worker heartbeat is exposed as a retryable
processing-state reason (``stale_worker_heartbeat``) independently of proof
validity, and never classifies unverified output as a cryptographic failure.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import db


@pytest.fixture(autouse=True)
def _isolate_jobs():
    saved_jobs = dict(db._JOBS)
    saved_next_id = db._next_job_id
    db._JOBS.clear()
    try:
        yield
    finally:
        db._JOBS.clear()
        db._JOBS.update(saved_jobs)
        db._next_job_id = saved_next_id


def test_fresh_lease_is_not_stale():
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("silent_witness", {"video_hash": "aa" * 32})
    leased = db.lease_job("worker-1", ["silent_witness"], lease_duration=60, now=t0)
    assert leased is not None
    assert leased["id"] == job_id

    state = db.get_job_heartbeat_state(
        db.get_job(job_id),
        now=t0 + timedelta(seconds=59.999),
    )
    assert state["stale"] is False
    assert state["reason"] is None
    assert state["retryable"] is False
    assert state["category"] == db.PROCESSING_STATE_CATEGORY
    assert state["cryptographic_failure"] is False
    assert state["stale_after_seconds"] == 60.0


def test_stale_heartbeat_boundary_reports_retryable_processing_state():
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("silent_witness", {"video_hash": "bb" * 32})
    db.lease_job("worker-1", ["silent_witness"], lease_duration=60, now=t0)

    state = db.get_job_heartbeat_state(
        db.get_job(job_id),
        now=t0 + timedelta(seconds=60),
    )
    assert state["stale"] is True
    assert state["reason"] == db.STALE_HEARTBEAT_REASON
    assert state["retryable"] is True
    assert state["category"] == db.PROCESSING_STATE_CATEGORY
    assert state["cryptographic_failure"] is False
    assert state["heartbeat_age_seconds"] == 60.0


def test_heartbeat_refresh_prevents_staleness():
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    job_id = db.enqueue_job("embed", {"filename": "clip.mp4"})
    db.lease_job("worker-1", ["embed"], lease_duration=60, now=t0)

    db.heartbeat_job(job_id, lease_duration=60, now=t0 + timedelta(seconds=45))
    state = db.get_job_heartbeat_state(
        db.get_job(job_id),
        now=t0 + timedelta(seconds=90),
    )
    assert state["stale"] is False
    assert state["reason"] is None
    assert state["cryptographic_failure"] is False


def test_reclaim_stale_jobs_requeues_without_cryptographic_failure_and_redacts_payload():
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    stale_id = db.enqueue_job(
        "silent_witness",
        {
            "video_hash": "cc" * 32,
            "credential_secret": "TOP-SECRET-CRED",
            "nullifier_secret": "TOP-SECRET-NULL",
        },
    )
    fresh_id = db.enqueue_job("embed", {"filename": "fresh.mp4"})

    db.lease_job("worker-dead", ["silent_witness"], lease_duration=30, now=t0)
    db.lease_job("worker-alive", ["embed"], lease_duration=30, now=t0 + timedelta(seconds=20))

    reclaimed = db.reclaim_stale_jobs(now=t0 + timedelta(seconds=35))
    assert len(reclaimed) == 1
    summary = reclaimed[0]
    assert summary["id"] == stale_id
    assert summary["type"] == "silent_witness"
    assert summary["status"] == "pending"
    assert "payload" not in summary
    assert "TOP-SECRET-CRED" not in str(summary)

    ps = summary["processing_state"]
    assert ps["reason"] == db.STALE_HEARTBEAT_REASON
    assert ps["retryable"] is True
    assert ps["category"] == db.PROCESSING_STATE_CATEGORY
    assert ps["cryptographic_failure"] is False

    # Job record is retryable (pending), not failed, and unverified output is not a crypto error.
    stale_job = db.get_job(stale_id)
    assert stale_job["status"] == "pending"
    assert "worker_id" not in stale_job
    assert stale_job["result"] is None
    assert stale_job["processing_state"]["reason"] == db.STALE_HEARTBEAT_REASON
    assert stale_job["processing_state"]["cryptographic_failure"] is False

    # Fresh job remains running.
    assert db.get_job(fresh_id)["status"] == "running"

    # Re-leasing the reclaimed job clears the stale processing_state.
    re_leased = db.lease_job(
        "worker-2",
        ["silent_witness"],
        lease_duration=60,
        now=t0 + timedelta(seconds=40),
    )
    assert re_leased is not None
    assert re_leased["id"] == stale_id
    assert "processing_state" not in re_leased


def test_non_running_jobs_are_never_marked_stale():
    t0 = datetime(2026, 11, 20, 6, 0, 0, tzinfo=timezone.utc)
    pending_id = db.enqueue_job("embed", {})
    completed_id = db.enqueue_job("embed", {})
    db.lease_job("worker-1", ["embed"], lease_duration=10, now=t0)
    db.complete_job(pending_id, {"ok": True})

    state_pending = db.get_job_heartbeat_state(
        db.get_job(completed_id),
        now=t0 + timedelta(seconds=999),
    )
    state_completed = db.get_job_heartbeat_state(
        db.get_job(pending_id),
        now=t0 + timedelta(seconds=999),
    )
    assert state_pending["stale"] is False
    assert state_completed["stale"] is False
    assert db.reclaim_stale_jobs(now=t0 + timedelta(seconds=999)) == []


def test_invalid_positive_thresholds_raise_value_error():
    job_id = db.enqueue_job("embed", {})
    with pytest.raises(ValueError):
        db.lease_job("worker-1", ["embed"], lease_duration=0)
    db.lease_job("worker-1", ["embed"], lease_duration=30)
    with pytest.raises(ValueError):
        db.heartbeat_job(job_id, lease_duration=-5)
    with pytest.raises(ValueError):
        db.get_job_heartbeat_state(db.get_job(job_id), stale_after_seconds=0)
