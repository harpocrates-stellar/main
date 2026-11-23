import sys
import threading
import time
import types
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

import admission
import db


def _import_worker():
    try:
        import worker as worker_mod
        return worker_mod
    except (SyntaxError, ImportError):
        stub_config = types.ModuleType("config")
        stub_config.load_config = lambda: types.SimpleNamespace(redacted_summary=lambda: {})
        stub_app = types.ModuleType("app")
        stub_app.safe_filename = lambda name: name
        stub_app.normalize_filename = lambda name: name
        stub_app.redact_metadata = lambda meta: meta
        stub_reconcile = types.ModuleType("registration_reconcile")
        stub_reconcile.process_verify_tx_job = lambda payload: {}
        stub_reconcile.reconcile_pending_registrations = lambda **kwargs: {"summary": {}}
        stub_reconcile.default_min_confirmations = lambda: 1
        sys.modules["config"] = stub_config
        sys.modules["app"] = stub_app
        sys.modules["registration_reconcile"] = stub_reconcile
        import worker as worker_mod
        return worker_mod


worker = _import_worker()


@pytest.fixture(autouse=True)
def _reset_job_queue():
    db._JOBS.clear()
    db._next_job_id = 1
    db._TENANT_LAST_LEASED_SEQ.clear()
    db._lease_seq = 0
    yield
    db._JOBS.clear()
    db._next_job_id = 1
    db._TENANT_LAST_LEASED_SEQ.clear()
    db._lease_seq = 0


def test_per_tenant_queue_bound_enforced_for_video_jobs_only():
    # Tenant A can enqueue up to the per-tenant queued limit across embed/extract
    j1 = db.enqueue_job("embed", {"filename": "a1.mp4"}, tenant_id="tenant-a", max_queued_per_tenant=2)
    j2 = db.enqueue_job("extract", {"filename": "a2.mp4"}, tenant_id="tenant-a", max_queued_per_tenant=2)
    assert j1 != j2

    with pytest.raises(db.TenantQueueLimitExceededError) as exc_info:
        db.enqueue_job("embed", {"filename": "a3.mp4"}, tenant_id="tenant-a", max_queued_per_tenant=2)

    assert exc_info.value.tenant_id == "tenant-a"
    assert exc_info.value.limit == 2
    assert exc_info.value.queued_count == 2
    assert exc_info.value.job_type == "embed"

    # Another tenant is completely unaffected by tenant-a's queue saturation
    b1 = db.enqueue_job("embed", {"filename": "b1.mp4"}, tenant_id="tenant-b", max_queued_per_tenant=2)
    assert db.get_job(b1)["tenant_id"] == "tenant-b"

    # Non-video jobs for tenant-a are not blocked by the video queue bound
    tx_id = db.enqueue_job("verify_tx", {"tx_hash": "tx-1"}, tenant_id="tenant-a", max_queued_per_tenant=2)
    assert db.get_job(tx_id)["status"] == "pending"

    counts = db.get_tenant_video_job_counts()
    assert counts["tenant-a"] == {"pending": 2, "running": 0}
    assert counts["tenant-b"] == {"pending": 1, "running": 0}


def test_per_tenant_concurrent_bound_and_slot_release():
    t0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    a1 = db.enqueue_job("embed", {"filename": "a1.mp4"}, tenant_id="tenant-a")
    a2 = db.enqueue_job("extract", {"filename": "a2.mp4"}, tenant_id="tenant-a")
    b1 = db.enqueue_job("embed", {"filename": "b1.mp4"}, tenant_id="tenant-b")

    # Concurrency bound = 1 per tenant
    leased_1 = db.lease_job("w1", ["embed", "extract"], now=t0, max_concurrent_per_tenant=1)
    assert leased_1["id"] == a1
    assert leased_1["tenant_id"] == "tenant-a"

    # Next lease skips tenant-a (already at 1 running) and serves tenant-b
    leased_2 = db.lease_job("w2", ["embed", "extract"], now=t0, max_concurrent_per_tenant=1)
    assert leased_2["id"] == b1
    assert leased_2["tenant_id"] == "tenant-b"

    # Both tenants are at concurrency cap -> no video job can be leased
    leased_3 = db.lease_job("w3", ["embed", "extract"], now=t0, max_concurrent_per_tenant=1)
    assert leased_3 is None

    # Completing a1 frees tenant-a's concurrency slot so a2 can be leased
    db.complete_job(a1, {"ok": True})
    leased_4 = db.lease_job("w3", ["embed", "extract"], now=t0, max_concurrent_per_tenant=1)
    assert leased_4["id"] == a2
    assert leased_4["tenant_id"] == "tenant-a"


def test_fair_round_robin_prevents_tenant_starvation_sequential_and_concurrent():
    t0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    # Tenant A floods the queue first with 3 jobs, then Tenant B enqueues 2 jobs
    a1 = db.enqueue_job("embed", {"filename": "a1.mp4"}, tenant_id="tenant-a")
    a2 = db.enqueue_job("embed", {"filename": "a2.mp4"}, tenant_id="tenant-a")
    a3 = db.enqueue_job("embed", {"filename": "a3.mp4"}, tenant_id="tenant-a")
    b1 = db.enqueue_job("embed", {"filename": "b1.mp4"}, tenant_id="tenant-b")
    b2 = db.enqueue_job("embed", {"filename": "b2.mp4"}, tenant_id="tenant-b")

    # Even on a single worker (completing each job before leasing the next),
    # fair scheduling alternates between tenants instead of draining all of tenant-a first.
    order = []
    for i in range(5):
        job = db.lease_job("w1", ["embed"], now=t0 + timedelta(seconds=i), max_concurrent_per_tenant=2)
        assert job is not None
        order.append((job["tenant_id"], job["id"]))
        db.complete_job(job["id"], {"ok": True})

    assert order == [
        ("tenant-a", a1),
        ("tenant-b", b1),
        ("tenant-a", a2),
        ("tenant-b", b2),
        ("tenant-a", a3),
    ]


def test_independent_pending_deadline_expires_without_blocking_other_tenants():
    t0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    expired_id = db.enqueue_job(
        "embed",
        {"filename": "expired.mp4"},
        tenant_id="tenant-a",
        deadline_seconds=10,
        now=t0,
    )
    valid_id = db.enqueue_job(
        "embed",
        {"filename": "valid.mp4"},
        tenant_id="tenant-b",
        deadline_seconds=120,
        now=t0,
    )

    # At t0 + 15s, tenant-a's job has exceeded its independent deadline;
    # tenant-b's job is still valid and is leased immediately.
    leased = db.lease_job(
        "w1",
        ["embed"],
        now=t0 + timedelta(seconds=15),
        max_concurrent_per_tenant=1,
    )
    assert leased is not None
    assert leased["id"] == valid_id
    assert leased["tenant_id"] == "tenant-b"

    expired_job = db.get_job(expired_id)
    assert expired_job["status"] == "failed"
    assert expired_job["processing_state"]["reason"] == db.DEADLINE_EXCEEDED_REASON
    assert expired_job["processing_state"]["cryptographic_failure"] is False


def test_worker_respects_independent_running_job_deadline():
    stop_event = threading.Event()
    now = datetime.now(timezone.utc)
    slow_id = db.enqueue_job(
        "embed",
        {"filename": "slow.mp4"},
        tenant_id="tenant-a",
        deadline_at=now + timedelta(milliseconds=150),
        now=now,
    )

    def slow_embed(_job):
        time.sleep(0.5)
        return {"ok": True}

    def stop_after_deadline():
        time.sleep(0.35)
        stop_event.set()

    stopper = threading.Thread(target=stop_after_deadline, daemon=True)
    stopper.start()

    with patch.object(worker, "init_db"), \
         patch.object(worker, "process_embed", side_effect=slow_embed), \
         patch.object(worker, "heartbeat_loop"), \
         patch.object(worker, "tx_verification_loop"), \
         patch.object(worker, "run_indexer_loop"):
        worker.run_worker(
            stop_event=stop_event,
            grace_period_seconds=2.0,
            max_concurrent_video_jobs_per_tenant=1,
        )

    stopper.join(timeout=1.0)
    job = db.get_job(slow_id)
    assert job["status"] == "failed"
    assert "deadline" in job["error"].lower()


def test_existing_admission_controls_and_default_tenant_compatibility():
    # Omitting tenant_id defaults cleanly to "default"
    job_id = db.enqueue_job("embed", {"filename": "legacy.mp4"})
    assert db.get_job(job_id)["tenant_id"] == db.DEFAULT_TENANT_ID

    # Existing AdmissionController remains independent and functional
    controller = admission.AdmissionController(
        max_concurrent=1,
        max_queue=0,
        max_per_identity=1,
        timeout_seconds=0.1,
    )
    ok, reason = controller.acquire("client-1")
    assert ok is True and reason == "ok"
    ok2, reason2 = controller.acquire("client-1")
    assert ok2 is False and reason2 == "identity_limit"
    controller.release("client-1")


def test_boundary_and_invalid_inputs_fail_closed():
    with pytest.raises(ValueError, match="tenant_id"):
        db.enqueue_job("embed", {}, tenant_id="   ")

    with pytest.raises(ValueError, match="max_queued_per_tenant"):
        db.enqueue_job("embed", {}, tenant_id="tenant-a", max_queued_per_tenant=0)

    with pytest.raises(ValueError, match="deadline_seconds"):
        db.enqueue_job("embed", {}, tenant_id="tenant-a", deadline_seconds=0)

    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError, match="at most one"):
        db.enqueue_job("embed", {}, tenant_id="tenant-a", deadline_at=now, deadline_seconds=10)

    with pytest.raises(ValueError, match="max_concurrent_per_tenant"):
        db.lease_job("w1", ["embed"], max_concurrent_per_tenant=0)
