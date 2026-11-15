from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import db
import storage
import worker


@pytest.fixture(autouse=True)
def _isolated_job_fences(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("HARPOCRATES_STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.delenv("HARPOCRATES_CLAIM_FENCE_PATH", raising=False)
    with db._JOBS_LOCK:
        db._JOBS.clear()
        db._next_job_id = 1
        db.reset_claim_fences()
    yield
    with db._JOBS_LOCK:
        db._JOBS.clear()
        db.reset_claim_fences()


def test_lease_expiry_takeover_increments_generation_and_fences_replaced_worker() -> None:
    job_id = db.enqueue_job("embed", {"filename": "clip.bin", "metadata": {}})

    claim1 = db.lease_job("worker-a", ["embed"], lease_duration=10, now=100.0)
    assert claim1 is not None
    assert claim1["id"] == job_id
    assert claim1["claim_generation"] == 1

    # Before lease expires, another worker cannot steal the running job
    assert db.lease_job("worker-b", ["embed"], lease_duration=10, now=105.0) is None

    # After lease expires at t=111.0, worker-b reclaims the job at generation 2
    claim2 = db.lease_job("worker-b", ["embed"], lease_duration=10, now=111.0)
    assert claim2 is not None
    assert claim2["id"] == job_id
    assert claim2["claim_generation"] == 2

    # Replaced worker-a (gen=1) cannot heartbeat, report progress, fail, or complete
    assert db.heartbeat_job(job_id, lease_duration=300, claim_generation=1, now=112.0) is False
    assert db.report_job_progress(job_id, "embedding", 50.0, now=112.0, claim_generation=1) is False
    assert db.fail_job(job_id, "stale worker crash", is_fatal=True, claim_generation=1) is False
    assert db.complete_job(job_id, {"embedded_hash": "1" * 64}, claim_generation=1) is False
    assert db.complete_job(job_id, {"embedded_hash": "0" * 64}) is False

    # Current worker-b (gen=2) reports progress and commits cleanly
    assert db.report_job_progress(job_id, "recording", 95.0, now=113.0, claim_generation=2) is True
    assert db.complete_job(job_id, {"embedded_hash": "2" * 64}, claim_generation=2) is True

    # Late completion or failure from replaced worker-a AFTER worker-b completed is still rejected
    assert db.complete_job(job_id, {"embedded_hash": "1" * 64}, claim_generation=1) is False
    assert db.fail_job(job_id, "late timeout", is_fatal=False, claim_generation=1) is False

    final = db.get_job(job_id)
    assert final is not None
    assert final["status"] == "completed"
    assert final["result"] == {"embedded_hash": "2" * 64}
    assert final["committed_generation"] == 2


def test_replaced_embed_worker_cannot_overwrite_newer_output_file_or_record_event() -> None:
    job_id = db.enqueue_job(
        "embed",
        {"filename": "evidence.bin", "metadata": {"proofId": "a" * 64, "tier": "silent"}},
    )
    input_path = storage.get_job_input_path(job_id)
    output_path = storage.get_job_output_path(job_id)
    input_path.write_bytes(b"canonical-input-bytes")

    claim1 = db.lease_job("worker-old", ["embed"], lease_duration=5, now=10.0)
    assert claim1 is not None and claim1["claim_generation"] == 1

    def _stale_embed_race(src: Path, dst: Path, metadata: dict, progress_callback=None):
        # Write stale output into worker-old's staged path (.gen_1.tmp)
        Path(dst).write_bytes(b"stale-generation-1-output")
        # Before worker-old finishes, worker-new reclaims the job (gen=2) and commits!
        claim2 = db.reclaim_job_lease(job_id, "worker-new", lease_duration=300, now=20.0)
        assert claim2 is not None and claim2["claim_generation"] == 2
        staged2 = storage.get_staged_job_output_path(job_id, 2)
        staged2.write_bytes(b"fresh-generation-2-output")
        db.commit_fenced_job_output(job_id, 2, staged2, output_path)
        assert db.complete_job(
            job_id,
            {"embedded_hash": "2" * 64, "winner": "worker-new"},
            claim_generation=2,
        ) is True

    with (
        patch.object(worker, "embed_metadata", side_effect=_stale_embed_race),
        patch.object(worker, "insert_proof_event") as event_spy,
    ):
        with pytest.raises(db.StaleClaimGenerationError) as exc_info:
            worker.process_embed(claim1)

    assert exc_info.value.attempted_generation == 1
    assert exc_info.value.current_generation == 2
    assert event_spy.call_count == 0
    # Canonical output preserves worker-new's bytes, and worker-old's staged temp file is removed
    assert output_path.read_bytes() == b"fresh-generation-2-output"
    assert not storage.get_staged_job_output_path(job_id, 1).exists()

    stored = db.get_job(job_id)
    assert stored is not None
    assert stored["status"] == "completed"
    assert stored["result"] == {"embedded_hash": "2" * 64, "winner": "worker-new"}


def test_run_worker_ignores_superseded_generation_without_calling_fail_job() -> None:
    job_id = db.enqueue_job(
        "silent_witness",
        {"video_hash": "b" * 64, "credential_secret": "11", "nullifier_secret": "22"},
    )
    stop_event = threading.Event()

    def _superseded_witness(v_hash: str, cred: str, null_sec: str):
        # Replacement worker claims generation 2 and completes while worker 1 runs
        reclaimed = db.reclaim_job_lease(job_id, "worker-replacement")
        assert reclaimed is not None and reclaimed["claim_generation"] == 2
        assert db.complete_job(job_id, {"proof": "gen2-proof"}, claim_generation=2) is True
        stop_event.set()
        return {"proof": "stale-gen1-proof"}

    with (
        patch.object(worker, "init_db"),
        patch.object(worker, "tx_verification_loop"),
        patch.object(worker, "run_indexer_loop"),
        patch.object(worker, "sweep_job_files"),
        patch.object(worker, "generate_silent_witness", side_effect=_superseded_witness),
        patch.object(worker, "fail_job", wraps=db.fail_job) as fail_spy,
    ):
        worker.run_worker(stop_event=stop_event, grace_period_seconds=2.0)

    assert fail_spy.call_count == 0
    stored = db.get_job(job_id)
    assert stored is not None
    assert stored["status"] == "completed"
    assert stored["result"] == {"proof": "gen2-proof"}
    assert stored["committed_generation"] == 2


def test_durable_file_fence_survives_in_memory_reset_and_never_reuses_old_generation() -> None:
    job_id = db.enqueue_job("verify_tx", {"tx_hash": "c" * 64})
    c1 = db.lease_job("worker-1", ["verify_tx"])
    assert c1 is not None and c1["claim_generation"] == 1
    c2 = db.reclaim_job_lease(job_id, "worker-2")
    assert c2 is not None and c2["claim_generation"] == 2

    # Simulate process restart clearing in-memory dicts while storage dir ledger persists
    with db._JOBS_LOCK:
        db._DURABLE_GENERATIONS.clear()
        db._JOBS[job_id]["claim_generation"] = 0
        db._JOBS[job_id]["status"] = "pending"

    assert db.get_durable_claim_generation(job_id) == 2
    c3 = db.lease_job("worker-3", ["verify_tx"])
    assert c3 is not None
    assert c3["claim_generation"] == 3

    # Stale generations 1 and 2 remain fenced out after restart
    assert db.complete_job(job_id, {"status": "stale"}, claim_generation=2) is False
    assert db.complete_job(job_id, {"status": "confirmed"}, claim_generation=3) is True

    # Sweeping job files preserves the dot-prefixed durable fence ledger
    ledger_path = storage.get_claim_fence_ledger_path()
    assert ledger_path.exists()
    storage.sweep_job_files(ttl_seconds=0)
    assert ledger_path.exists()


def test_postgres_durable_claim_fences_enforce_conditional_sql_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://test:test@localhost:5432/harpocrates")

    mock_cursor = MagicMock()
    # 1st fetchone: advance_durable_claim_generation -> gen 4
    # 2nd fetchone: stale complete_job(gen=3) -> None (0 rows matched WHERE claim_generation = 3)
    # 3rd fetchone: valid complete_job(gen=4) -> {"claim_generation": 4}
    mock_cursor.fetchone.side_effect = [
        {"claim_generation": 4},
        None,
        {"claim_generation": 4},
    ]
    mock_conn = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    with patch.object(db, "get_connection") as patched_conn:
        patched_conn.return_value.__enter__.return_value = mock_conn

        job_id = db.enqueue_job("verify_tx", {"tx_hash": "d" * 64})
        leased = db.lease_job("worker-pg", ["verify_tx"])
        assert leased is not None and leased["claim_generation"] == 4

        # Force local active_gen check to hit DB fence path for stale vs current commit
        assert db._commit_durable_fence_status(job_id, 3, "completed") is False
        assert db.complete_job(job_id, {"status": "confirmed"}, claim_generation=4) is True
