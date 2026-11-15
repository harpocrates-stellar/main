import logging
import time
import os
from logging_utils import log_structured
import threading
import traceback
from pathlib import Path

from db import (
    StaleClaimGenerationError,
    commit_fenced_job_output,
    is_current_claim_generation,
    lease_job,
    heartbeat_job,
    report_job_progress,
    require_current_claim_generation,
    complete_job,
    fail_job,
    insert_proof_event,
    init_db,
    database_url,
    get_connection,
    update_tx_status,
)
from envelope import canonical_metadata_hash
from stego import StegoLimitExceededError, embed_metadata, extract_metadata, sha256_file
from noir import generate_silent_witness
from app import normalize_filename, redact_metadata
from config import load_config

from storage import get_job_input_path, get_job_output_path, sweep_job_files
from tx_verification import verify_transaction_status
try:
    from registration_reconcile import (
        default_min_confirmations,
        process_verify_tx_job,
        reconcile_pending_registrations,
    )
except ImportError:
    default_min_confirmations = None
    process_verify_tx_job = None
    reconcile_pending_registrations = None
from tracing import traced_job
from chain_indexer import run_indexer_loop

LOGGER = logging.getLogger("harpocrates.worker")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)

WORKER_ID = f"worker-{os.getpid()}"

def _active_claim_generation(job: dict) -> int | None:
    gen = job.get("claim_generation")
    if isinstance(gen, int) and gen > 0:
        return gen
    return None


def _report_progress_fenced(
    job_id: int,
    phase: str,
    percent: float | None = None,
    *,
    claim_generation: int | None = None,
) -> bool:
    if claim_generation is not None:
        return report_job_progress(
            job_id,
            phase,
            percent,
            claim_generation=claim_generation,
        )
    return report_job_progress(job_id, phase, percent)


@traced_job("job.media.embed")
def process_embed(job: dict, storage: object | None = None) -> dict:
    claim_generation = _active_claim_generation(job)
    if storage is not None or "payload" not in job:
        raw_id = job.get("id", job.get("job_id", "unknown"))
        input_path = job["input_path"]
        message_path = job["message_path"]
        output_path = job["output_path"]
        message = Path(message_path).read_text()
        if claim_generation is not None:
            require_current_claim_generation(raw_id, claim_generation)
            staged_path = Path(f"{output_path}.gen_{claim_generation}.tmp")
            try:
                meta = embed_metadata(input_path, message, str(staged_path))
                commit_fenced_job_output(raw_id, claim_generation, staged_path, output_path)
            except StaleClaimGenerationError:
                staged_path.unlink(missing_ok=True)
                raise
        else:
            meta = embed_metadata(input_path, message, output_path)
        return {"output_path": output_path, "message": message, **(meta if isinstance(meta, dict) else {})}
    payload = job["payload"]
    job_id = job["id"]
    metadata = payload["metadata"]
    filename = payload["filename"]

    input_path = get_job_input_path(job_id)
    output_path = get_job_output_path(job_id)
    target_output_path = (
        Path(f"{output_path}.gen_{claim_generation}.tmp")
        if claim_generation is not None
        else output_path
    )

    if not input_path.exists():
        raise RuntimeError(f"Input video file missing for job {job_id}")

    require_current_claim_generation(job_id, claim_generation)
    _report_progress_fenced(
        job_id,
        "hashing_source",
        claim_generation=claim_generation,
    )
    source_hash = sha256_file(input_path)

    def on_frame(frames_done: int, frames_total: int | None) -> None:
        require_current_claim_generation(job_id, claim_generation)
        percent = (frames_done / frames_total * 100.0) if frames_total else None
        _report_progress_fenced(
            job_id,
            "embedding",
            percent,
            claim_generation=claim_generation,
        )

    try:
        embed_metadata(input_path, target_output_path, metadata, progress_callback=on_frame)
        require_current_claim_generation(job_id, claim_generation)
        _report_progress_fenced(
            job_id,
            "hashing_output",
            claim_generation=claim_generation,
        )
        embedded_hash = sha256_file(target_output_path)
        metadata_hash = canonical_metadata_hash(metadata)
        if claim_generation is not None:
            commit_fenced_job_output(
                job_id,
                claim_generation,
                target_output_path,
                output_path,
            )
    except StaleClaimGenerationError:
        if target_output_path != output_path:
            target_output_path.unlink(missing_ok=True)
        raise

    _report_progress_fenced(
        job_id,
        "recording",
        claim_generation=claim_generation,
    )
    db_event = insert_proof_event(
        event_type="embed",
        file_name=normalize_filename(filename),
        video_hash=embedded_hash,
        metadata_hash=metadata_hash,
        proof_id=metadata.get("proofId"),
        tier=metadata.get("tier"),
        embedded_hash=embedded_hash,
        metadata=redact_metadata(metadata),
    )

    if is_current_claim_generation(job_id, claim_generation):
        input_path.unlink(missing_ok=True)

    return {
        "source_hash": source_hash,
        "embedded_hash": embedded_hash,
        "metadata_hash": metadata_hash,
        "db_event": db_event
    }

@traced_job("job.media.extract")
def process_extract(job: dict, storage: object | None = None) -> dict:
    claim_generation = _active_claim_generation(job)
    if storage is not None or "payload" not in job:
        raw_id = job.get("id", job.get("job_id", "unknown"))
        input_path = job["input_path"]
        output_path = job["output_path"]
        if claim_generation is not None:
            require_current_claim_generation(raw_id, claim_generation)
            staged_path = Path(f"{output_path}.gen_{claim_generation}.tmp")
            try:
                res = extract_metadata(input_path, str(staged_path))
                commit_fenced_job_output(raw_id, claim_generation, staged_path, output_path)
            except StaleClaimGenerationError:
                staged_path.unlink(missing_ok=True)
                raise
        else:
            res = extract_metadata(input_path, output_path)
        return {"output_path": output_path, **(res if isinstance(res, dict) else {})}
    payload = job["payload"]
    job_id = job["id"]
    filename = payload["filename"]

    input_path = get_job_input_path(job_id)

    if not input_path.exists():
        raise RuntimeError(f"Input video file missing for job {job_id}")

    require_current_claim_generation(job_id, claim_generation)
    metadata = extract_metadata(input_path)
    video_hash = sha256_file(input_path)
    metadata_hash = canonical_metadata_hash(metadata) if metadata else None
    require_current_claim_generation(job_id, claim_generation)

    db_event = insert_proof_event(
        event_type="extract",
        file_name=normalize_filename(filename),
        video_hash=video_hash,
        metadata_hash=metadata_hash,
        proof_id=metadata.get("proofId") if metadata else None,
        tier=metadata.get("tier") if metadata else None,
        metadata=redact_metadata(metadata),
    )

    if is_current_claim_generation(job_id, claim_generation):
        input_path.unlink(missing_ok=True)

    return {
        "video_hash": video_hash,
        "metadata_hash": metadata_hash,
        "metadata": metadata,
        "db_event": db_event
    }

@traced_job("job.proof.noir")
def process_silent_witness(job: dict, storage: object | None = None) -> dict:
    claim_generation = _active_claim_generation(job)
    if storage is not None or "payload" not in job:
        raw_id = job.get("id", job.get("job_id", "unknown"))
        input_path = job["input_path"]
        output_path = job["output_path"]
        if claim_generation is not None:
            require_current_claim_generation(raw_id, claim_generation)
            staged_path = Path(f"{output_path}.gen_{claim_generation}.tmp")
            try:
                res = generate_silent_witness(input_path, str(staged_path))
                commit_fenced_job_output(raw_id, claim_generation, staged_path, output_path)
            except StaleClaimGenerationError:
                staged_path.unlink(missing_ok=True)
                raise
        else:
            res = generate_silent_witness(input_path, output_path)
        return {"output_path": output_path, **(res if isinstance(res, dict) else {})}
    payload = job["payload"]
    job_id = job["id"]

    video_hash = payload["video_hash"]
    credential_secret = payload["credential_secret"]
    nullifier_secret = payload["nullifier_secret"]

    # Phase names only: proof generation runs as one external command and
    # reports no measurable fraction, so percent stays None.
    require_current_claim_generation(job_id, claim_generation)
    _report_progress_fenced(
        job_id,
        "generating_proof",
        claim_generation=claim_generation,
    )
    proof = generate_silent_witness(
        video_hash,
        credential_secret,
        nullifier_secret,
    )
    require_current_claim_generation(job_id, claim_generation)

    return {"proof": proof}

def process_verify_tx(job: dict, storage: object | None = None) -> dict:
    """Reconcile a single registration tx enqueued at proof registration time."""
    claim_generation = _active_claim_generation(job)
    if storage is not None or ("input_path" in job and "payload" not in job):
        import json
        raw_id = job.get("id", job.get("job_id", "unknown"))
        data = json.loads(Path(job["input_path"]).read_text())
        status = verify_transaction_status(data["tx_id"])
        output_path = job["output_path"]
        if claim_generation is not None:
            require_current_claim_generation(raw_id, claim_generation)
            staged_path = Path(f"{output_path}.gen_{claim_generation}.tmp")
            staged_path.write_text(json.dumps(status))
            commit_fenced_job_output(raw_id, claim_generation, staged_path, output_path)
        else:
            Path(output_path).write_text(json.dumps(status))
        return {"output_path": output_path, **(status if isinstance(status, dict) else {"status": status})}
    raw_id = job.get("id", "unknown")
    require_current_claim_generation(raw_id, claim_generation)
    res = process_verify_tx_job(job.get("payload") or {})
    require_current_claim_generation(raw_id, claim_generation)
    return res


def is_fatal(job_type: str, err: BaseException) -> bool:
    """Classify whether a job failure is non-retryable."""
    return isinstance(err, ValueError) and job_type != "verify_tx"

def heartbeat_loop(
    job_id: int,
    stop_event: threading.Event,
    claim_generation: int | None = None,
):
    while not stop_event.is_set():
        if claim_generation is not None:
            if not heartbeat_job(
                job_id,
                lease_duration=300,
                claim_generation=claim_generation,
            ):
                break
        else:
            heartbeat_job(job_id, lease_duration=300)
        stop_event.wait(60)

def tx_verification_loop(stop_event: threading.Event):
    """
    Periodically reconcile pending registration confirmations against Horizon.

    Prefer the batch reconciler (confirmation depth + privacy-safe signals). Fall
    back to the legacy per-row Horizon probe when the DB helpers are unavailable.
    """
    LOGGER.info("Starting transaction verification / registration reconcile loop")
    while not stop_event.is_set():
        try:
            if not database_url():
                stop_event.wait(10)
                continue

            try:
                report = reconcile_pending_registrations(
                    limit=50,
                    min_confirmations=default_min_confirmations(),
                )
                summary = report.get("summary") or {}
                LOGGER.info(
                    "registration_reconcile_batch scanned=%s updated=%s confirmed=%s failed=%s missing=%s pending=%s error=%s",
                    summary.get("scanned"),
                    summary.get("updated"),
                    summary.get("confirmed"),
                    summary.get("failed"),
                    summary.get("missing"),
                    summary.get("pending"),
                    summary.get("error"),
                )
            except Exception:
                # Legacy fallback path keeps older deployments moving.
                with get_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT id, tx_hash
                            FROM proof_events
                            WHERE tx_hash IS NOT NULL AND tx_status = 'pending'
                            LIMIT 50
                            """
                        )
                        rows = [dict(row) for row in cur.fetchall()]

                for row in rows:
                    if stop_event.is_set():
                        break

                    tx_hash = row["tx_hash"]
                    LOGGER.info("Verifying transaction %s", str(tx_hash)[:8])
                    status = verify_transaction_status(tx_hash)

                    if status in ("confirmed", "failed", "missing"):
                        LOGGER.info(
                            "Transaction %s resolved to %s",
                            str(tx_hash)[:8],
                            status,
                        )
                        update_tx_status(tx_hash, status)

        except Exception as e:
            LOGGER.error("Error in tx verification loop: %s", type(e).__name__)

        stop_event.wait(15)


import signal
import sys

DEFAULT_WORKER_GRACE_PERIOD_SECONDS = 30.0


def _worker_grace_period_seconds() -> float:
    raw = os.getenv("WORKER_GRACE_PERIOD_SECONDS")
    if raw is None or not raw.strip():
        return DEFAULT_WORKER_GRACE_PERIOD_SECONDS
    try:
        val = float(raw)
        return val if val > 0 else DEFAULT_WORKER_GRACE_PERIOD_SECONDS
    except ValueError:
        return DEFAULT_WORKER_GRACE_PERIOD_SECONDS


def run_worker(
    stop_event: threading.Event | None = None,
    grace_period_seconds: float | None = None,
):
    init_db()
    config = load_config()
    LOGGER.info("Worker started with config summary")
    log_structured(LOGGER, logging.INFO, {"event": "worker_start", "config": config.redacted_summary()})
    LOGGER.info(f"Starting worker {WORKER_ID}")

    if stop_event is None:
        stop_event = threading.Event()

    if grace_period_seconds is None:
        grace_period_seconds = _worker_grace_period_seconds()

    def _signal_handler(signum, frame):
        LOGGER.info(f"Received signal {signum}, initiating graceful shutdown")
        stop_event.set()

    try:
        signal.signal(signal.SIGTERM, _signal_handler)
    except (ValueError, AttributeError):
        pass

    try:
        signal.signal(signal.SIGINT, _signal_handler)
    except (ValueError, AttributeError):
        pass

    verification_thread = threading.Thread(target=tx_verification_loop, args=(stop_event,))
    verification_thread.daemon = True
    verification_thread.start()

    indexer_thread = threading.Thread(target=run_indexer_loop, args=(stop_event,))
    indexer_thread.daemon = True
    indexer_thread.start()

    last_sweep_time = 0.0
    while not stop_event.is_set():
        try:
            now_time = time.time()
            if now_time - last_sweep_time >= 300:
                last_sweep_time = now_time
                try:
                    sweep_job_files()
                except Exception as e:
                    LOGGER.error("Job file sweep failed: %s", type(e).__name__)

            job = lease_job(
                WORKER_ID,
                ["embed", "extract", "silent_witness", "verify_tx"],
                lease_duration=300,
            )
            if not job:
                stop_event.wait(2)
                continue

            job_id = job["id"]
            job_type = job["type"]
            claim_generation = _active_claim_generation(job)
            LOGGER.info(f"Leased job {job_id} of type {job_type} (gen={claim_generation})")

            hb_stop_event = threading.Event()
            hb_args = (
                (job_id, hb_stop_event, claim_generation)
                if claim_generation is not None
                else (job_id, hb_stop_event)
            )
            hb_thread = threading.Thread(target=heartbeat_loop, args=hb_args)
            hb_thread.start()

            def _execute_job():
                try:
                    require_current_claim_generation(job_id, claim_generation)
                    if job_type == "embed":
                        res = process_embed(job)
                    elif job_type == "extract":
                        res = process_extract(job)
                    elif job_type == "silent_witness":
                        res = process_silent_witness(job)
                    elif job_type == "verify_tx":
                        res = process_verify_tx(job)
                    else:
                        raise ValueError(f"Unknown job type {job_type}")
                    if claim_generation is not None:
                        committed = complete_job(
                            job_id,
                            res,
                            claim_generation=claim_generation,
                        )
                    else:
                        complete_job(job_id, res)
                        committed = True
                    if committed is False:
                        LOGGER.warning(
                            "Superseded worker skipped result commit for job %s (gen=%s)",
                            job_id,
                            claim_generation,
                        )
                    else:
                        LOGGER.info(f"Completed job {job_id}")
                except StaleClaimGenerationError:
                    LOGGER.warning(
                        "Superseded worker dropped stale output for job %s (gen=%s)",
                        job_id,
                        claim_generation,
                    )
                except Exception as err:
                    LOGGER.error(f"Failed job {job_id}: {type(err).__name__}")
                    fatal = is_fatal(job_type, err)
                    if job_type == "verify_tx" and isinstance(err, ValueError):
                        fatal = True
                    if claim_generation is not None:
                        fail_job(
                            job_id,
                            str(err),
                            is_fatal=fatal,
                            claim_generation=claim_generation,
                        )
                    else:
                        fail_job(job_id, str(err), is_fatal=fatal)
                finally:
                    hb_stop_event.set()
                    hb_thread.join()

            work_thread = threading.Thread(target=_execute_job)
            work_thread.daemon = True
            work_thread.start()

            while work_thread.is_alive():
                work_thread.join(timeout=0.1)
                if stop_event.is_set() and work_thread.is_alive():
                    # Stop event received while processing job: give it until grace period expires
                    work_thread.join(timeout=grace_period_seconds)
                    if work_thread.is_alive():
                        LOGGER.warning(
                            f"Job {job_id} did not finish within grace period of {grace_period_seconds}s; releasing job"
                        )
                        hb_stop_event.set()
                        if claim_generation is not None:
                            fail_job(
                                job_id,
                                "Worker shutdown grace period exceeded",
                                is_fatal=False,
                                claim_generation=claim_generation,
                            )
                        else:
                            fail_job(job_id, "Worker shutdown grace period exceeded", is_fatal=False)
                    break

        except Exception as e:
            LOGGER.error(f"Worker loop error: {e}")
            stop_event.wait(5)

    LOGGER.info("Worker stop event set, waiting for tx verification loop to terminate")
    verification_thread.join(timeout=5.0)
    LOGGER.info("Worker stopped cleanly")


if __name__ == "__main__":
    run_worker()
    sys.exit(0)

