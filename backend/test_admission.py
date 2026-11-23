import time
import threading
from unittest.mock import patch, MagicMock

from flask import Flask, jsonify

from admission import AdmissionController, require_capacity, _get_client_identity


def test_admission_controller_capacity_limits():
    # max_concurrent = 2
    # max_queue = 1
    # max_per_identity = 3
    controller = AdmissionController(
        max_concurrent=2,
        max_queue=1,
        max_per_identity=3,
        timeout_seconds=0.1
    )

    # 1. Acquire up to concurrency limit
    ok1, reason1 = controller.acquire("client1")
    assert ok1 is True

    ok2, reason2 = controller.acquire("client2")
    assert ok2 is True

    # 2. Acquire when full but queue has space
    def acquire_delayed():
        # This will wait in the queue and then timeout
        return controller.acquire("client3")

    thread = threading.Thread(target=acquire_delayed)
    thread.start()
    
    # Let it get in the queue
    time.sleep(0.05)
    
    # 3. Queue is now full (1/1). The next acquire should fail immediately
    ok4, reason4 = controller.acquire("client4")
    assert ok4 is False
    assert reason4 == "queue_full"

    thread.join()

    # 4. Release slots
    controller.release("client1")
    controller.release("client2")

    # Now it should be possible to acquire again
    ok5, reason5 = controller.acquire("client5")
    assert ok5 is True


def test_admission_controller_identity_limit():
    controller = AdmissionController(
        max_concurrent=10,
        max_queue=10,
        max_per_identity=2,
        timeout_seconds=0.1
    )

    # Acquire up to identity limit
    ok1, _ = controller.acquire("user_A")
    assert ok1 is True
    ok2, _ = controller.acquire("user_A")
    assert ok2 is True

    # Third time fails for this user
    ok3, reason = controller.acquire("user_A")
    assert ok3 is False
    assert reason == "identity_limit"

    # But another user can acquire
    ok4, _ = controller.acquire("user_B")
    assert ok4 is True


def test_admission_controller_decorator():
    app = Flask(__name__)

    controller = AdmissionController(
        max_concurrent=1,
        max_queue=0,
        max_per_identity=1,
        timeout_seconds=0.1
    )

    @app.route("/test", methods=["GET"])
    @require_capacity(controller)
    def test_route():
        time.sleep(0.2)
        return jsonify({"ok": True})

    client = app.test_client()

    # Mock IP address to simulate same client
    environ = {"REMOTE_ADDR": "1.2.3.4"}

    # Test concurrent requests via threads (since test_client blocks)
    results = []

    def make_request():
        res = client.get("/test", environ_base=environ)
        results.append((res.status_code, res.json))

    t1 = threading.Thread(target=make_request)
    t2 = threading.Thread(target=make_request)

    t1.start()
    time.sleep(0.05) # ensure t1 acquires first
    t2.start()

    t1.join()
    t2.join()

    # One should succeed (200), one should fail (429 or 503)
    status_codes = [r[0] for r in results]
    assert 200 in status_codes
    assert 429 in status_codes or 503 in status_codes

    # Ensure it's correctly mapped (429 if identity_limit, 503 if queue_full)
    for code, data in results:
        if code != 200:
            assert "error" in data
            assert data["reason"] in ["identity_limit", "queue_full"]


# ── Storage budget tests ────────────────────────────────────────────────────────

def test_storage_budget_unlimited_by_default():
    """When no budget is configured, storage reservation always succeeds."""
    controller = AdmissionController(
        max_concurrent=10,
        max_queue=10,
        max_per_identity=5,
        timeout_seconds=0.1,
        # max_temp_storage_per_identity not set = unlimited
    )

    ok, reason = controller.reserve_storage("client1", 1_000_000)
    assert ok is True
    assert reason == "ok"

    # Multiple reservations for same identity should succeed
    ok2, reason2 = controller.reserve_storage("client1", 5_000_000)
    assert ok2 is True

    # Release should work
    controller.release_storage("client1", 1_000_000)
    controller.release_storage("client1", 5_000_000)

    # Reserved storage should be zero after full release
    assert controller.get_reserved_storage("client1") == 0


def test_storage_budget_enforced_per_identity():
    """Storage budget is enforced per identity."""
    budget = 10_000_000  # 10 MB per identity
    controller = AdmissionController(
        max_concurrent=10,
        max_queue=10,
        max_per_identity=5,
        timeout_seconds=0.1,
        max_temp_storage_per_identity=budget,
    )

    # First reservation succeeds
    ok1, reason1 = controller.reserve_storage("client1", 6_000_000)
    assert ok1 is True
    assert reason1 == "ok"

    # Second reservation for same identity succeeds if within budget
    ok2, reason2 = controller.reserve_storage("client1", 3_000_000)
    assert ok2 is True

    # Total reserved: 9 MB, 1 MB remaining
    assert controller.get_reserved_storage("client1") == 9_000_000

    # Third reservation exceeds budget
    ok3, reason3 = controller.reserve_storage("client1", 2_000_000)
    assert ok3 is False
    assert reason3 == "storage_budget_exceeded"

    # Different identity has separate budget
    ok4, reason4 = controller.reserve_storage("client2", budget)
    assert ok4 is True
    assert controller.get_reserved_storage("client2") == budget


def test_storage_budget_release():
    """Released storage becomes available for new reservations."""
    budget = 10_000_000
    controller = AdmissionController(
        max_concurrent=10,
        max_queue=10,
        max_per_identity=5,
        timeout_seconds=0.1,
        max_temp_storage_per_identity=budget,
    )

    # Reserve full budget
    ok1, _ = controller.reserve_storage("client1", budget)
    assert ok1 is True

    # Release half
    controller.release_storage("client1", 5_000_000)
    assert controller.get_reserved_storage("client1") == 5_000_000

    # Can now reserve up to remaining budget
    ok2, _ = controller.reserve_storage("client1", 5_000_000)
    assert ok2 is True

    # Release more than reserved (should clamp to zero)
    controller.release_storage("client1", 10_000_000)
    assert controller.get_reserved_storage("client1") == 0

    # Can reserve full budget again
    ok3, _ = controller.reserve_storage("client1", budget)
    assert ok3 is True


def test_storage_budget_zero_budget():
    """Zero budget means no storage allowed."""
    controller = AdmissionController(
        max_concurrent=10,
        max_queue=10,
        max_per_identity=5,
        timeout_seconds=0.1,
        max_temp_storage_per_identity=0,
    )

    ok, reason = controller.reserve_storage("client1", 1)
    assert ok is False
    assert reason == "storage_budget_exceeded"


def test_storage_budget_invalid_size():
    """Negative size is rejected."""
    controller = AdmissionController(
        max_concurrent=10,
        max_queue=10,
        max_per_identity=5,
        timeout_seconds=0.1,
        max_temp_storage_per_identity=10_000_000,
    )

    ok, reason = controller.reserve_storage("client1", -1)
    assert ok is False
    assert reason == "invalid_size"

    # Negative release is no-op
    controller.release_storage("client1", -100)
    assert controller.get_reserved_storage("client1") == 0


def test_storage_budget_concurrent_identities():
    """Multiple identities can reserve up to their individual budgets."""
    budget = 5_000_000
    controller = AdmissionController(
        max_concurrent=10,
        max_queue=10,
        max_per_identity=5,
        timeout_seconds=0.1,
        max_temp_storage_per_identity=budget,
    )

    identities = [f"client{i}" for i in range(10)]
    
    # All identities can reserve their full budget
    for identity in identities:
        ok, _ = controller.reserve_storage(identity, budget)
        assert ok is True
        assert controller.get_reserved_storage(identity) == budget

    # Total reserved across all identities: 10 * 5MB = 50MB
    # (There's no global limit, only per-identity)
    for identity in identities:
        controller.release_storage(identity, budget)
        assert controller.get_reserved_storage(identity) == 0
