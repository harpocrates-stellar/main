import os
import pytest
import time
from datetime import datetime, timedelta, timezone
from db import init_db, insert_proof_event, set_legal_hold, purge_expired_events, get_connection
from config import load_config
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

from unittest.mock import MagicMock, patch
from retention import RetentionWorker, RETENTION_BATCH_SIZE


def test_retention_worker_default_batch_size():
    worker = RetentionWorker()
    assert worker.batch_size == RETENTION_BATCH_SIZE
    assert worker.batch_size == 100


def test_retention_worker_custom_batch_size():
    custom_batch = 250
    worker = RetentionWorker(interval_seconds=60, batch_size=custom_batch)
    assert worker.batch_size == custom_batch

    # Mock purge_expired_events: first call returns 250 receipts,
    # second call returns fewer (50), verifying worker loops then breaks.
    batch_1 = [{"proof_id": f"p1_{i}"} for i in range(custom_batch)]
    batch_2 = [{"proof_id": f"p2_{i}"} for i in range(50)]

    with patch("retention.purge_expired_events", side_effect=[batch_1, batch_2]) as mock_purge, \
         patch("retention.metrics_collector") as mock_metrics:
        worker._purge()

        assert mock_purge.call_count == 2
        mock_purge.assert_called_with(batch_size=custom_batch)
        assert mock_metrics.record_deleted_event.call_count == custom_batch + 50


def test_config_retention_batch_size_default(monkeypatch):
    monkeypatch.delenv("HARPOCRATES_RETENTION_BATCH_SIZE", raising=False)
    config = load_config()
    assert config.retention_batch_size == 100


@pytest.mark.parametrize(
    "env_val, expected",
    [
        ("250", 250),
        ("1", 1),
        ("5000", 5000),
        ("10000", 5000),
        ("0", 1),
        ("-10", 1),
        ("   ", 100),
    ],
)
def test_config_retention_batch_size_clamping(monkeypatch, env_val, expected):
    monkeypatch.setenv("HARPOCRATES_RETENTION_BATCH_SIZE", env_val)
    config = load_config()
    assert config.retention_batch_size == expected


def test_init_retention_worker_configured_batch_size(monkeypatch):
    monkeypatch.setenv("RETENTION_WORKER_ENABLED", "true")
    monkeypatch.setenv("HARPOCRATES_RETENTION_BATCH_SIZE", "500")

    with patch.object(RetentionWorker, "start"):
        init_retention_worker()
        from retention import _worker
        assert _worker is not None
        assert _worker.batch_size == 500
    stop_retention_worker()
