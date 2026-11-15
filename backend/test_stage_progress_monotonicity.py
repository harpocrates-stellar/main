"""Tests for monotonic stage revisions and terminal-job progress fencing (issue #1108)."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

import db
import worker


@pytest.fixture(autouse=True)
def isolated_jobs():
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


def _lease_embed_job(payload: dict | None = None) -> dict:
    job_id = db.enqueue_job("embed", payload or {"filename": "clip.mp4", "metadata": {}})
    leased = db.lease_job("worker-test", ["embed"])
    assert leased is not None
    assert leased["id"] == job_id
    return leased


def test_monotonic_stage_revisions_reject_stale_revision_even_with_newer_clock():
    leased = _lease_embed_job()
    job_id = leased["id"]
    base_rev = leased["stage_revision"]

    assert db.report_job_progress(
        job_id, "hashing_source", None, now=10.0, revision=base_rev + 1
    ) is True
    assert db.report_job_progress(
        job_id, "embedding", 50.0, now=12.0, revision=base_rev + 5
    ) is True
    assert db.get_job(job_id)["stage_revision"] == base_rev + 5

    # Stale revision with a newer timestamp must be rejected rather than ordered by clock.
    assert db.report_job_progress(
        job_id, "embedding", 10.0, now=999.0, revision=base_rev + 3
    ) is False
    assert db.report_job_progress(
        job_id, "embedding", 20.0, now=1000.0, revision=base_rev + 5
    ) is False
    assert db.get_job(job_id)["progress"] == {"phase": "embedding", "percent": 50.0}
    assert db.get_job(job_id)["stage_revision"] == base_rev + 5


def test_monotonic_revision_accepts_advancing_stage_despite_skewed_clock():
    leased = _lease_embed_job()
    job_id = leased["id"]
    base_rev = leased["stage_revision"]

    assert db.report_job_progress(
        job_id, "hashing_source", None, now=500.0, revision=base_rev + 1
    ) is True
    # Clock skew moves backwards, but monotonic stage revision increases.
    assert db.report_job_progress(
        job_id, "embedding", 25.0, now=100.0, revision=base_rev + 2
    ) is True
    assert db.get_job(job_id)["progress"] == {"phase": "embedding", "percent": 25.0}
    assert db.get_job(job_id)["stage_revision"] == base_rev + 2


def test_rejects_progress_update_that_regresses_completed_pipeline_stage():
    leased = _lease_embed_job()
    job_id = leased["id"]
    base_rev = leased["stage_revision"]

    assert db.report_job_progress(
        job_id, "hashing_source", None, now=1.0, revision=base_rev + 1
    ) is True
    assert db.report_job_progress(
        job_id, "embedding", 80.0, now=3.0, revision=base_rev + 2
    ) is True
    assert db.report_job_progress(
        job_id, "hashing_output", None, now=5.0, revision=base_rev + 3
    ) is True

    # Even with a higher revision and later timestamp, returning to completed stages fails.
    assert db.report_job_progress(
        job_id, "hashing_source", None, now=10.0, revision=base_rev + 4
    ) is False
    assert db.report_job_progress(
        job_id, "embedding", 95.0, now=12.0, revision=base_rev + 5
    ) is False

    # Advancing forward to 'recording' still succeeds.
    assert db.report_job_progress(
        job_id, "recording", None, now=14.0, revision=base_rev + 6
    ) is True
    assert db.get_job(job_id)["progress"] == {"phase": "recording", "percent": None}


def test_complete_job_stage_blocks_same_stage_regression():
    leased = _lease_embed_job()
    job_id = leased["id"]

    assert db.report_job_progress(job_id, "embedding", 100.0, now=1.0) is True
    assert db.complete_job_stage(job_id, "embedding") is True

    # Stage was explicitly completed; further 'embedding' updates are rejected.
    assert db.report_job_progress(job_id, "embedding", 90.0, now=5.0) is False
    assert db.complete_job_stage(job_id, "embedding") is False

    # Later stage remains accepted.
    assert db.report_job_progress(job_id, "hashing_output", None, now=6.0) is True
    assert db.get_job(job_id)["progress"] == {"phase": "hashing_output", "percent": None}


def test_custom_stage_transition_marks_prior_stage_completed():
    job_id = db.enqueue_job("custom_pipeline", {})
    assert db.transition_job_to_running(job_id, worker_id="worker-custom") is True

    assert db.report_job_progress(job_id, "step_alpha", 50.0, now=1.0) is True
    assert db.report_job_progress(job_id, "step_beta", 10.0, now=3.0) is True
    assert db.report_job_progress(job_id, "step_alpha", 99.0, now=5.0) is False
    assert db.get_job(job_id)["progress"] == {"phase": "step_beta", "percent": 10.0}


@pytest.mark.parametrize("terminal_mode", ["completed", "failed", "cancelled"])
def test_terminal_job_never_returns_to_running_or_accepts_progress(terminal_mode: str):
    job_id = db.enqueue_job("embed", {"filename": "clip.mp4", "metadata": {}})
    if terminal_mode == "cancelled":
        assert db.cancel_job(job_id) is True
    else:
        leased = db.lease_job("worker-1", ["embed"])
        assert leased is not None
        assert db.report_job_progress(job_id, "embedding", 40.0, now=1.0) is True
        if terminal_mode == "completed":
            assert db.complete_job(job_id, {"embedded_hash": "aa" * 32}) is True
        else:
            assert db.fail_job(job_id, "invalid payload", is_fatal=True) is True

    snapshot_before = dict(db.get_job(job_id))
    assert snapshot_before["status"] == terminal_mode

    # None of these calls may return a terminal job to pending or running.
    assert db.transition_job_to_running(job_id, worker_id="worker-zombie") is False
    assert db.fail_job(job_id, "late transient retry", is_fatal=False) is False
    assert db.fail_job(job_id, "late fatal error", is_fatal=True) is False
    assert db.complete_job(job_id, {"embedded_hash": "bb" * 32}) is False
    assert db.lease_job("worker-2", ["embed"]) is None
    assert db.report_job_progress(job_id, "recording", None, now=50.0, revision=999) is False
    assert db.complete_job_stage(job_id, "recording", revision=1000) is False

    snapshot_after = db.get_job(job_id)
    assert snapshot_after["status"] == terminal_mode
    assert snapshot_after["stage_revision"] == snapshot_before["stage_revision"]
    assert snapshot_after.get("result") == snapshot_before.get("result")


def test_retryable_failure_allows_fresh_attempt_with_higher_revisions():
    leased_1 = _lease_embed_job()
    job_id = leased_1["id"]
    stale_rev = leased_1["stage_revision"]

    assert db.report_job_progress(job_id, "hashing_source", None, now=1.0) is True
    assert db.report_job_progress(job_id, "embedding", 30.0, now=3.0) is True
    # Non-fatal failure returns running -> pending for a genuine retry.
    assert db.fail_job(job_id, "temporary io glitch", is_fatal=False) is True
    assert db.get_job(job_id)["status"] == "pending"

    leased_2 = db.lease_job("worker-retry", ["embed"])
    assert leased_2 is not None
    assert leased_2["id"] == job_id
    assert leased_2["stage_revision"] > stale_rev

    # Zombie callback from attempt 1 carrying stale revision is rejected.
    assert db.report_job_progress(
        job_id, "hashing_output", None, now=10.0, revision=stale_rev + 1
    ) is False

    # Fresh attempt can start cleanly from 'hashing_source' with new revisions.
    assert db.report_job_progress(
        job_id,
        "hashing_source",
        None,
        now=12.0,
        revision=leased_2["stage_revision"] + 1,
    ) is True
    assert db.get_job(job_id)["progress"] == {"phase": "hashing_source", "percent": None}


def test_invalid_revision_raises_value_error():
    leased = _lease_embed_job()
    job_id = leased["id"]
    for bad_rev in (0, -1, True, False, "2", 1.5):
        with pytest.raises(ValueError, match="progress revision"):
            db.report_job_progress(job_id, "hashing_source", revision=bad_rev)  # type: ignore[arg-type]


def test_worker_process_embed_emits_strictly_increasing_revisions_and_exposes_public_view():
    import app as app_module

    leased = _lease_embed_job(
        {"metadata": {"proofId": "aa" * 32, "tier": "silent"}, "filename": "clip.mp4"}
    )
    job_id = leased["id"]
    seen_revisions: list[int] = []
    accepted_revisions: list[int] = []
    original_report = db.report_job_progress
    fake_now = [0.0]

    def next_monotonic() -> float:
        fake_now[0] += 1.5
        return fake_now[0]

    def spy_report(jid, phase, percent=None, **kwargs):
        rev = kwargs.get("revision")
        assert isinstance(rev, int)
        seen_revisions.append(rev)
        ok = original_report(jid, phase, percent, **kwargs)
        if ok:
            accepted_revisions.append(rev)
        return ok

    def fake_embed(source, output, metadata, progress_callback=None):
        Path(output).write_bytes(b"synthetic-out")
        if progress_callback:
            progress_callback(1, 2)
            progress_callback(2, 2)

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "in.bin"
        out = Path(tmp) / "out.bin"
        src.write_bytes(b"synthetic-in")
        with patch.object(worker, "get_job_input_path", return_value=src), \
             patch.object(worker, "get_job_output_path", return_value=out), \
             patch.object(worker, "sha256_file", return_value="ab" * 32), \
             patch.object(worker, "embed_metadata", side_effect=fake_embed), \
             patch.object(worker, "insert_proof_event", return_value={"id": 1}), \
             patch.object(worker, "report_job_progress", side_effect=spy_report), \
             patch.object(db.time, "monotonic", side_effect=next_monotonic):
            res = worker.process_embed(leased)
            assert db.complete_job(job_id, res) is True

    assert seen_revisions == sorted(seen_revisions)
    assert len(set(seen_revisions)) == len(seen_revisions)
    assert seen_revisions[0] > leased["stage_revision"]
    assert accepted_revisions == seen_revisions

    flask_app = app_module.create_app()
    flask_app.config["TESTING"] = True
    resp = flask_app.test_client().get(f"/api/jobs/{job_id}")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    assert body["job"]["status"] == "completed"
    assert body["job"]["stage_revision"] > accepted_revisions[-1]
    assert not any(k.startswith("_") for k in body["job"])
