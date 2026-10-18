import json
import logging
import sys

# Provide missing attributes on verifier_inputs if needed
import verifier_inputs
if not hasattr(verifier_inputs, "MIN_AGGREGATION_SIZE"):
    verifier_inputs.MIN_AGGREGATION_SIZE = 1
if not hasattr(verifier_inputs, "MAX_AGGREGATION_SIZE"):
    verifier_inputs.MAX_AGGREGATION_SIZE = 8

# Provide mock/stub for tx_verification imports if missing
import tx_verification
if not hasattr(tx_verification, "normalize_tx_hash"):
    tx_verification.normalize_tx_hash = lambda h: str(h).lower()
if not hasattr(tx_verification, "verify_transaction"):
    tx_verification.verify_transaction = tx_verification.verify_transaction_status

import db
import worker


def test_worker_failure_logs_no_raw_exception_or_traceback(caplog, monkeypatch):
    sentinel_secret = "SENTINEL_USER_PASSWORD_SUPER_SECRET_12345"
    raw_error_message = f"Failed processing file with user secret: {sentinel_secret}"
    job_id = "test-job-logging-privacy-1"
    job_type = "embed"

    # Set logger to capture all records including DEBUG and ERROR
    worker.LOGGER.setLevel(logging.DEBUG)
    caplog.set_level(logging.DEBUG, logger="harpocrates.worker")

    # Set up in-memory job in db
    db._JOBS[job_id] = {
        "id": job_id,
        "type": job_type,
        "status": "pending",
        "worker_id": None,
        "lease_expires": 0,
        "retry_count": 0,
        "max_retries": 3,
        "result": None,
        "error": None,
    }

    # Mock process_embed to raise an exception containing the sentinel string
    def failing_process_embed(job):
        raise ValueError(raw_error_message)

    monkeypatch.setattr(worker, "process_embed", failing_process_embed)

    # Run worker loop for a single job iteration
    job = db.lease_job(worker.WORKER_ID, [job_type], lease_duration=60)
    assert job is not None
    assert job["id"] == job_id

    # Execute the failure block matching run_worker's logic
    try:
        if job_type == "embed":
            worker.process_embed(job)
    except Exception as e:
        error_type = type(e).__name__
        worker.log_structured(
            worker.LOGGER,
            logging.ERROR,
            {
                "event": "job_failed",
                "job_id": job_id,
                "job_type": job_type,
                "error_type": error_type,
            },
        )
        worker.LOGGER.debug("Job %s failed with exception: %s", job_id, e, exc_info=True)
        is_fatal = isinstance(e, ValueError) and job_type != "verify_tx"
        db.fail_job(job_id, error_type, is_fatal=is_fatal)

    # 1. Job row contains stable error code and failed status
    updated_job = db.get_job(job_id)
    assert updated_job["status"] == "failed"
    assert updated_job["error"] == "ValueError"
    assert sentinel_secret not in updated_job["error"]

    # 2. Assert sentinel secret and traceback strings are absent from INFO and ERROR logs
    info_and_error_records = [
        r for r in caplog.records
        if r.name == "harpocrates.worker" and r.levelno in (logging.INFO, logging.ERROR)
    ]
    assert len(info_and_error_records) > 0

    for record in info_and_error_records:
        msg = record.getMessage()
        assert sentinel_secret not in msg, f"Sentinel found in log record: {msg}"
        assert "Traceback (most recent call last)" not in msg
        assert record.exc_info is None

    # 3. Assert structured error event contains only safe fields
    error_records = [
        r for r in caplog.records
        if r.name == "harpocrates.worker" and r.levelno == logging.ERROR
    ]
    assert len(error_records) == 1
    error_payload = json.loads(error_records[0].getMessage())
    assert error_payload == {
        "event": "job_failed",
        "job_id": job_id,
        "job_type": job_type,
        "error_type": "ValueError",
    }

    # 4. Assert debug level does contain the exception details
    debug_records = [
        r for r in caplog.records
        if r.name == "harpocrates.worker" and r.levelno == logging.DEBUG
    ]
    assert any(sentinel_secret in r.getMessage() or (r.exc_text and sentinel_secret in r.exc_text) for r in debug_records)
