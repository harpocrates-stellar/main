from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import patch

import pytest

import app as app_module
import db
import worker
from admission import AdmissionController, enqueue_admitted_job


@pytest.fixture(autouse=True)
def _reset_scheduler_state(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("TENANT_VIDEO_MAX_CONCURRENT", raising=False)
    monkeypatch.delenv("TENANT_VIDEO_MAX_QUEUED", raising=False)
    monkeypatch.delenv("VIDEO_JOB_DEADLINE_SECONDS", raising=False)
    with db._JOBS_LOCK:
        db._JOBS.clear()
        db._next_job_id = 1
        db._lease_seq = 0
        db._tenant_last_leased_seq.clear()
    yield
    with db._JOBS_LOCK:
        db._JOBS.clear()
        db._tenant_last_leased_seq.clear()


def test_round_robin_fair_scheduling_prevents_noisy_tenant_starvation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Allow up to 4 concurrent per tenant so only fairness ordering governs selection
    monkeypatch.setenv("TENANT_VIDEO_MAX_CONCURRENT", "4")

    a_ids = [
        db.enqueue_job("embed", {"filename": f"a-{i}.bin", "metadata": {}}, tenant_id="tenant-alpha")
        for i in range(4)
    ]
    b_id = db.enqueue_job("extract", {"filename": "b-0.bin"}, tenant_id="tenant-bravo")
    c_id = db.enqueue_job(
        "silent_witness",
        {"video_hash": "a" * 64, "credential_secret": "1", "nullifier_secret": "2"},
        tenant_id="tenant-charlie",
    )

    leased_order: list[int] = []
    for idx in range(6):
        leased = db.lease_job(f"worker-{idx}", ["embed", "extract", "silent_witness"])
        assert leased is not None
        leased_order.append(leased["id"])
        db.complete_job(leased["id"], {"ok": True})

    # Without fair scheduling, tenant-bravo and tenant-charlie would wait behind all 4 alpha jobs.
    # With deficit/LRU round-robin, alpha's first job runs, then bravo and charlie run before alpha's backlog.
    assert leased_order[:3] == [a_ids[0], b_id, c_id]
    assert leased_order[3:] == a_ids[1:]


def test_per_tenant_concurrent_limit_caps_running_video_jobs_and_allows_other_tenants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TENANT_VIDEO_MAX_CONCURRENT", "2")

    a1 = db.enqueue_job("embed", {"filename": "a1.bin", "metadata": {}}, tenant_id="noisy")
    a2 = db.enqueue_job("embed", {"filename": "a2.bin", "metadata": {}}, tenant_id="noisy")
    a3 = db.enqueue_job("embed", {"filename": "a3.bin", "metadata": {}}, tenant_id="noisy")

    j1 = db.lease_job("w1", ["embed"])
    j2 = db.lease_job("w2", ["embed"])
    assert j1 is not None and j1["id"] == a1
    assert j2 is not None and j2["id"] == a2

    # Third worker cannot lease a3 because tenant "noisy" hit TENANT_VIDEO_MAX_CONCURRENT=2
    assert db.lease_job("w3", ["embed"]) is None

    # Another tenant and lightweight control jobs remain immediately schedulable
    b1 = db.enqueue_job("embed", {"filename": "b1.bin", "metadata": {}}, tenant_id="quiet")
    ctrl = db.enqueue_job("verify_tx", {"tx_hash": "b" * 64}, tenant_id="noisy")

    leased_b = db.lease_job("w3", ["embed"])
    assert leased_b is not None and leased_b["id"] == b1

    leased_ctrl = db.lease_job("w4", ["embed", "verify_tx"])
    assert leased_ctrl is not None and leased_ctrl["id"] == ctrl

    # Completing a1 releases a running slot for tenant "noisy", making a3 eligible
    db.complete_job(a1, {"ok": True})
    leased_a3 = db.lease_job("w1", ["embed"])
    assert leased_a3 is not None and leased_a3["id"] == a3


def test_per_tenant_queued_limit_bounds_backlog_per_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TENANT_VIDEO_MAX_QUEUED", "2")

    q1 = db.enqueue_job("embed", {"filename": "1.bin", "metadata": {}}, tenant_id="bursty")
    q2 = db.enqueue_job("extract", {"filename": "2.bin"}, tenant_id="bursty")
    assert q1 != q2

    with pytest.raises(db.TenantQuotaExceededError) as exc_info:
        db.enqueue_job("embed", {"filename": "3.bin", "metadata": {}}, tenant_id="bursty")
    assert exc_info.value.reason == "tenant_queue_limit"
    assert exc_info.value.limit == 2
    assert "bursty" not in str(exc_info.value)

    # Other tenants and non-video jobs are unaffected
    other = db.enqueue_job("embed", {"filename": "ok.bin", "metadata": {}}, tenant_id="calm")
    tx_job = db.enqueue_job("verify_tx", {"tx_hash": "c" * 64}, tenant_id="bursty")
    assert other > 0 and tx_job > 0


def test_independent_processing_deadlines_expire_stale_jobs_without_blocking_healthy_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TENANT_VIDEO_MAX_QUEUED", "2")

    short_dead = db.enqueue_job(
        "embed",
        {"filename": "short.bin", "metadata": {}},
        tenant_id="tenant-x",
        deadline_seconds=5.0,
        now=100.0,
    )
    long_live = db.enqueue_job(
        "embed",
        {"filename": "long.bin", "metadata": {}},
        tenant_id="tenant-x",
        deadline_seconds=60.0,
        now=100.0,
    )

    # At t=106.0, short_dead has expired; enqueueing a new job for tenant-x succeeds
    # because expiring short_dead frees the queued slot, while long_live stays pending!
    replacement = db.enqueue_job(
        "embed",
        {"filename": "fresh.bin", "metadata": {}},
        tenant_id="tenant-x",
        deadline_seconds=60.0,
        now=106.0,
    )

    expired_job = db.get_job(short_dead)
    assert expired_job is not None
    assert expired_job["status"] == "failed"
    assert expired_job["error"] == "job processing deadline exceeded"

    leased_first = db.lease_job("w1", ["embed"], now=106.0)
    assert leased_first is not None and leased_first["id"] == long_live
    leased_second = db.lease_job("w2", ["embed"], now=106.0)
    assert leased_second is not None and leased_second["id"] == replacement


def test_in_flight_deadline_expiration_cleans_temp_files_and_fails_non_retryably(
    tmp_path: Path,
) -> None:
    in_file = tmp_path / "deadline-in.bin"
    out_file = tmp_path / "deadline-out.bin"
    in_file.write_bytes(b"synthetic-frames")
    out_file.write_bytes(b"partial")

    job_id = db.enqueue_job(
        "embed",
        {"filename": "clip.bin", "metadata": {}},
        tenant_id="tenant-timeout",
        deadline_seconds=10.0,
        now=50.0,
    )
    stop_event = threading.Event()

    def _slow_embed(input_path, output_path, metadata, progress_callback=None):
        assert progress_callback is not None
        # Force deadline expiration mid-stream before the next frame callback
        with db._JOBS_LOCK:
            db._JOBS[job_id]["_deadline_dt"] = db.datetime.now(db.timezone.utc) - db.timedelta(seconds=1)
        progress_callback(1, 3)

    with (
        patch.object(worker, "init_db"),
        patch.object(worker, "tx_verification_loop"),
        patch.object(worker, "run_indexer_loop"),
        patch.object(worker, "sweep_job_files"),
        patch.object(worker, "get_job_input_path", return_value=in_file),
        patch.object(worker, "get_job_output_path", return_value=out_file),
        patch.object(worker, "sha256_file", return_value="d" * 64),
        patch.object(worker, "embed_metadata", side_effect=_slow_embed),
        patch.object(worker, "fail_job", wraps=db.fail_job) as fail_spy,
    ):
        orig_fail = db.fail_job

        def _fail_and_stop(jid, err, *, is_fatal=False):
            orig_fail(jid, err, is_fatal=is_fatal)
            stop_event.set()

        fail_spy.side_effect = _fail_and_stop
        worker.run_worker(stop_event=stop_event, grace_period_seconds=2.0)

    assert not in_file.exists()
    assert not out_file.exists()
    stored = db.get_job(job_id)
    assert stored is not None
    assert stored["status"] == "failed"
    assert "deadline exceeded" in stored["error"]


def test_existing_admission_controls_and_privacy_invariants_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TENANT_VIDEO_MAX_QUEUED", "2")
    monkeypatch.setenv("APP_ENV", "testing")
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5173")

    controller = AdmissionController(
        max_concurrent=4,
        max_queue=0,
        max_per_identity=1,
        timeout_seconds=0.05,
    )
    raw_identity = "203.0.113.42"

    # Hold the identity's single admission slot to verify AdmissionController rejects first
    ok_hold, _ = controller.acquire(raw_identity)
    assert ok_hold is True
    admitted, reason, jid = enqueue_admitted_job(
        controller,
        raw_identity,
        "embed",
        {"filename": "secret_name.bin", "metadata": {}},
    )
    assert (admitted, reason, jid) == (False, "identity_limit", None)
    controller.release(raw_identity)

    # Once released, AdmissionController admits up to TENANT_VIDEO_MAX_QUEUED=2
    ok1, r1, jid1 = enqueue_admitted_job(
        controller,
        raw_identity,
        "embed",
        {"filename": "secret_1.bin", "metadata": {}},
    )
    ok2, r2, jid2 = enqueue_admitted_job(
        controller,
        raw_identity,
        "embed",
        {"filename": "secret_2.bin", "metadata": {}},
    )
    ok3, r3, jid3 = enqueue_admitted_job(
        controller,
        raw_identity,
        "embed",
        {"filename": "secret_3.bin", "metadata": {}},
    )
    assert ok1 is True and r1 == "ok" and jid1 is not None
    assert ok2 is True and r2 == "ok" and jid2 is not None
    assert (ok3, r3, jid3) == (False, "tenant_queue_limit", None)

    snapshot = db.get_tenant_scheduler_snapshot()
    assert raw_identity not in str(snapshot)
    hashed_key = db.normalize_tenant_key(raw_identity)
    assert snapshot["tenants"][hashed_key] == {"queued": 2, "running": 0}

    flask_app = app_module.create_app()
    resp = flask_app.test_client().get(f"/api/jobs/{jid1}")
    assert resp.status_code == 200
    raw_text = resp.get_data(as_text=True)
    assert raw_identity not in raw_text
    assert "_tenant_key" not in raw_text
    assert "secret_1.bin" not in raw_text
