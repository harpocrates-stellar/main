import os
import pytest
import time
from datetime import datetime, timedelta, timezone
from db import init_db, insert_proof_event, set_legal_hold, purge_expired_events, get_connection
from config import load_config, _parse_retention_classes
from retention import init_retention_worker, stop_retention_worker, _worker

@pytest.fixture(autouse=True)
def setup_db(monkeypatch):
    db_url = os.environ.get("TEST_DATABASE_URL") or "postgresql://postgres:password@localhost:5432/postgres"
    monkeypatch.setenv("DATABASE_URL", db_url)
    try:
        init_db()
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("truncate table proof_events cascade;")
                cursor.execute("truncate table deletion_receipts cascade;")
            conn.commit()
    except Exception as e:
        pytest.skip(f"Database connection failed: {e}")
    
    yield
    
    stop_retention_worker()

@pytest.mark.integration
def test_purge_expired_events():
    # Insert an event that is expired
    expired_time = datetime.now(timezone.utc) - timedelta(days=1)
    ev1 = insert_proof_event(event_type="test", video_hash="1"*64, proof_id="a"*64, expires_at=expired_time)
    
    # Insert an event that is not expired
    future_time = datetime.now(timezone.utc) + timedelta(days=1)
    ev2 = insert_proof_event(event_type="test", video_hash="2"*64, proof_id="b"*64, expires_at=future_time)
    
    # Insert an event that is expired but on legal hold
    ev3 = insert_proof_event(event_type="test", video_hash="3"*64, proof_id="c"*64, expires_at=expired_time)
    set_legal_hold("c"*64, True)
    
    # Insert an event with no expiration
    ev4 = insert_proof_event(event_type="test", video_hash="4"*64, proof_id="d"*64)
    
    receipts = purge_expired_events()
    
    assert len(receipts) == 1
    assert receipts[0]["proof_id"] == "a"*64
    
    # Verify remaining in DB
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select proof_id from proof_events order by id")
            remaining = [r["proof_id"] for r in cursor.fetchall()]
    assert remaining == ["b"*64, "c"*64, "d"*64]

    # Verify receipt is in table
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select proof_id from deletion_receipts")
            in_receipts = [r["proof_id"] for r in cursor.fetchall()]
    assert in_receipts == ["a"*64]

@pytest.mark.integration
def test_retention_worker(monkeypatch):
    monkeypatch.setenv("RETENTION_INTERVAL_SECONDS", "1")
    
    expired_time = datetime.now(timezone.utc) - timedelta(days=1)
    insert_proof_event(event_type="test", video_hash="5"*64, proof_id="e"*64, expires_at=expired_time)
    
    init_retention_worker()
    time.sleep(2)  # Wait for worker to run at least once
    
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select count(*) as c from deletion_receipts")
            count = cursor.fetchone()["c"]
    assert count == 1


# ---------------------------------------------------------------------------
# Retention class parsing (#276)
# ---------------------------------------------------------------------------


def test_retention_classes_default_when_unset() -> None:
    classes = _parse_retention_classes(None)
    assert classes["default"] == 30
    # A negative lifetime means "never purge"; app.py maps it to a null expires_at.
    assert classes["forever"] < 0
    assert _parse_retention_classes("   ") == classes


def test_retention_classes_override_always_keeps_default() -> None:
    classes = _parse_retention_classes("short:1,long:400")
    assert classes == {"short": 1, "long": 400, "default": 30}


def test_retention_classes_reject_malformed_values() -> None:
    with pytest.raises(RuntimeError):
        _parse_retention_classes("short=1")
    with pytest.raises(RuntimeError):
        _parse_retention_classes("short:not-a-number")


# ---------------------------------------------------------------------------
# Deletion metric (#276)
# ---------------------------------------------------------------------------


def test_deleted_events_metric_is_exposed() -> None:
    """Purge activity is observable without becoming a second index of deletions."""
    from metrics import collector

    collector.reset()
    collector.record_deleted_event()
    collector.record_deleted_event()

    rendered = collector.generate_prometheus_metrics()
    assert "harpocrates_deleted_events_total 2" in rendered
    # Label-free by design: no proof/media identifiers leak into the metric.
    assert "proof_id" not in rendered

    collector.reset()
    assert "harpocrates_deleted_events_total 0" in collector.generate_prometheus_metrics()


# ---------------------------------------------------------------------------
# Bounded draining (#276)
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_purge_expired_events_drains_in_bounded_batches() -> None:
    """A backlog larger than ``batch_size`` drains deterministically, oldest first."""
    expired_time = datetime.now(timezone.utc) - timedelta(days=1)
    for index in range(5):
        insert_proof_event(
            event_type="test",
            video_hash=str(index) * 64,
            proof_id=str(index) * 64,
            expires_at=expired_time,
        )

    # Each call is capped and ordered, so a sweep can be resumed after a restart.
    first = purge_expired_events(batch_size=2)
    assert [r["proof_id"] for r in first] == ["0" * 64, "1" * 64]

    second = purge_expired_events(batch_size=2)
    assert [r["proof_id"] for r in second] == ["2" * 64, "3" * 64]

    # A short batch signals the drain is complete.
    final = purge_expired_events(batch_size=2)
    assert [r["proof_id"] for r in final] == ["4" * 64]
    assert purge_expired_events(batch_size=2) == []

    # Every purged event left a receipt that names the proof it removed.
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select proof_id from deletion_receipts order by id")
            receipt_ids = [r["proof_id"] for r in cursor.fetchall()]
    assert receipt_ids == [str(i) * 64 for i in range(5)]
