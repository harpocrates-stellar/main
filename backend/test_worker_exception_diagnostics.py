from __future__ import annotations

import logging
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


def test_sanitize_diagnostic_text_redacts_secrets_dsns_and_private_paths() -> None:
    stellar_seed = "S" + ("A" * 55)
    pem_block = (
        "-----BEGIN " + "PRIVATE KEY-----\n"
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQ\n"
        "-----END " + "PRIVATE KEY-----"
    )
    dsn = "postgres" + "ql://admin:s3cr3tPass@neon-internal.example:5432/harpocrates_prod"
    jwt_tok = "eyJhbGciOiJIUzI1NiJ9." + ("a" * 16) + "." + ("b" * 16)
    bearer_tok = "Bearer " + "sup3r_s3cr3t_api_tok3n_999"
    win_media_path = r"C:\Users\Alice\PrivateUploads\evidence_clip.mp4"
    posix_media_path = "/var/harpocrates/uploads/tenant_secret/raw_video.mov"
    posix_py_path = "/opt/harpocrates/backend/worker.py"
    witness_hex = "deadbeef" * 8

    raw_error = (
        f"Prover failed on {win_media_path} and {posix_media_path} via {posix_py_path}: "
        f"seed={stellar_seed} db={dsn} auth={bearer_tok} jwt={jwt_tok} "
        f"credential_secret=my_raw_cred_val witness_hash={witness_hex} key={pem_block}"
    )

    sanitized = db.sanitize_diagnostic_text(raw_error, max_bytes=1024)
    assert stellar_seed not in sanitized
    assert "s3cr3tPass" not in sanitized
    assert "neon-internal.example" not in sanitized
    assert jwt_tok not in sanitized
    assert "sup3r_s3cr3t_api_tok3n_999" not in sanitized
    assert "Alice" not in sanitized
    assert "evidence_clip.mp4" not in sanitized
    assert "tenant_secret" not in sanitized
    assert "raw_video.mov" not in sanitized
    assert "my_raw_cred_val" not in sanitized
    assert witness_hex not in sanitized
    assert "BEGIN PRIVATE" not in sanitized
    assert "<file:worker.py>" in sanitized
    assert "\n" not in sanitized


def test_sanitize_diagnostic_text_enforces_strict_utf8_byte_cap() -> None:
    # Multi-byte UTF-8 characters (3 bytes each) must never split mid-codepoint or exceed max_bytes
    huge = "error—" + ("é" * 500) + ("Ω" * 500)
    capped = db.sanitize_diagnostic_text(huge, max_bytes=128)
    encoded = capped.encode("utf-8")
    assert len(encoded) <= 128
    assert capped.endswith("...[truncated]")


def test_sanitize_traceback_frames_bounds_depth_bytes_and_omits_source_lines() -> None:
    stellar_seed = "S" + ("B" * 55)

    def recurse(depth: int) -> None:
        if depth <= 0:
            raise ValueError(f"invalid witness input for /home/operator/secret_dir/clip.mp4 seed={stellar_seed}")
        recurse(depth - 1)

    try:
        recurse(14)
    except ValueError as captured:
        err = captured
    else:  # pragma: no cover
        pytest.fail("expected ValueError")

    diag = worker.format_bounded_worker_diagnostic(
        err,
        max_error_bytes=160,
        max_traceback_bytes=420,
        max_frames=5,
    )
    assert diag.error_type == "ValueError"
    assert len(diag.error_message.encode("utf-8")) <= 160
    assert len(diag.traceback_summary.encode("utf-8")) <= 420
    assert diag.truncated is True
    assert stellar_seed not in diag.error_message
    assert stellar_seed not in diag.traceback_summary
    assert "/home/operator" not in diag.error_message
    assert "/home/operator" not in diag.traceback_summary
    assert "clip.mp4" not in diag.error_message
    assert "clip.mp4" not in diag.traceback_summary
    # Source line containing variable name `stellar_seed` must NOT appear in frame output
    assert "stellar_seed" not in diag.traceback_summary
    assert "<file:test_worker_exception_diagnostics.py>" in diag.traceback_summary
    assert "outer frames omitted" in diag.traceback_summary


def test_fail_job_and_run_worker_persist_and_log_only_sanitized_bounded_diagnostics(
    caplog: pytest.LogCaptureFixture,
) -> None:
    stop_event = threading.Event()
    job_id = db.enqueue_job("embed", {"filename": "clip.mp4", "metadata": {}})
    stellar_seed = "S" + ("Z" * 55)
    private_upload = "/tmp/private_quarantine/secret_evidence.mp4"
    oversized_tail = "X" * 2000

    leased = {"id": job_id, "type": "embed", "payload": {}}
    calls = {"n": 0}

    def lease_once(*args, **kwargs):
        if calls["n"] == 0:
            calls["n"] += 1
            db._JOBS[job_id]["status"] = "running"
            return leased
        stop_event.set()
        return None

    def exploding_embed(_job):
        raise ValueError(
            f"failed processing {private_upload} with credential_secret=raw_secret_123 "
            f"seed={stellar_seed} {oversized_tail}"
        )

    with caplog.at_level(logging.ERROR, logger="harpocrates.worker"), \
         patch.object(worker, "init_db"), \
         patch.object(worker, "lease_job", side_effect=lease_once), \
         patch.object(worker, "process_embed", side_effect=exploding_embed), \
         patch.object(worker, "heartbeat_loop"), \
         patch.object(worker, "tx_verification_loop"), \
         patch.object(worker, "run_indexer_loop"):
        worker.run_worker(stop_event=stop_event, grace_period_seconds=1.0)

    stored_job = db.get_job(job_id)
    assert stored_job is not None
    assert stored_job["status"] == "failed"
    persisted_err = stored_job["error"]
    assert len(persisted_err.encode("utf-8")) <= db.MAX_JOB_ERROR_DIAGNOSTIC_BYTES
    assert stellar_seed not in persisted_err
    assert "raw_secret_123" not in persisted_err
    assert "private_quarantine" not in persisted_err
    assert "secret_evidence.mp4" not in persisted_err

    logged_text = "\n".join(rec.getMessage() for rec in caplog.records)
    assert f"Failed job {job_id}" in logged_text
    assert stellar_seed not in logged_text
    assert "raw_secret_123" not in logged_text
    assert "private_quarantine" not in logged_text
    assert "secret_evidence.mp4" not in logged_text
    for rec in caplog.records:
        assert len(rec.getMessage().encode("utf-8")) <= worker.MAX_TRACEBACK_DIAGNOSTIC_BYTES + 128


def test_db_metrics_failure_log_redacts_connection_dsn(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dsn = "postgres" + "ql://app_user:top_secret_pw@db.internal:5432/prod_db"
    monkeypatch.setenv("DATABASE_URL", dsn)

    def failing_conn():
        raise RuntimeError(f"connection failed for {dsn}")

    monkeypatch.setattr(db, "get_connection", failing_conn)
    with caplog.at_level(logging.WARNING, logger=db.logger.name):
        metrics = db.get_job_queue_metrics()

    assert metrics == {"counts": {}, "oldest_queued_seconds": {}}
    logged = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "top_secret_pw" not in logged
    assert "db.internal" not in logged
    assert "[REDACTED:dsn]" in logged


def test_invalid_byte_or_frame_bounds_rejected() -> None:
    with pytest.raises(ValueError):
        db.sanitize_diagnostic_text("err", max_bytes=0)
    with pytest.raises(ValueError):
        worker.sanitize_traceback_frames(RuntimeError("err"), max_frames=0)
    with pytest.raises(ValueError):
        worker.sanitize_traceback_frames(RuntimeError("err"), max_bytes=0)
    with pytest.raises(ValueError):
        worker.format_bounded_worker_diagnostic(RuntimeError("err"), max_error_bytes=0)
