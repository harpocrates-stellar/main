from __future__ import annotations

from dataclasses import dataclass
import logging
import time
import os
from logging_utils import log_structured
import threading
import traceback
from pathlib import Path
from typing import Any, Callable

from db import (
    StaleWorkerLeaseError,
    assert_active_job_lease,
    enqueue_job,
    get_job,
    lease_job,
    heartbeat_job,
    reclaim_expired_job_leases,
    report_job_progress,
    complete_job,
    fail_job,
    insert_proof_event,
    init_db,
    database_url,
    get_connection,
    update_tx_status,
    verify_active_job_lease,
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

CRASH_STAGE_HASHING = "hashing"
CRASH_STAGE_PROVING = "proving"
CRASH_STAGE_METADATA_WRITE = "metadata_write"
SUPPORTED_CRASH_STAGES = frozenset(
    {
        CRASH_STAGE_HASHING,
        CRASH_STAGE_PROVING,
        CRASH_STAGE_METADATA_WRITE,
    }
)

StageHook = Callable[[str, dict[str, Any]], None]


class SimulatedWorkerCrash(RuntimeError):
    """Deterministic fault injected at a specific worker execution stage."""

    def __init__(self, stage: str, worker_id: str | None = None, lease_epoch: int | None = None) -> None:
        super().__init__(f"simulated worker crash at stage={stage} worker={worker_id} epoch={lease_epoch}")
        self.stage = stage
        self.worker_id = worker_id
        self.lease_epoch = lease_epoch


def _fence_job_if_leased(job: dict[str, Any]) -> tuple[str | None, int | None]:
    worker_id = job.get("worker_id")
    lease_epoch = job.get("lease_epoch")
    if lease_epoch is not None:
        assert_active_job_lease(job["id"], worker_id=worker_id, lease_epoch=lease_epoch)
    return worker_id, lease_epoch


def _run_stage_checkpoint(
    job: dict[str, Any],
    stage: str,
    stage_hook: StageHook | None = None,
) -> tuple[str | None, int | None]:
    worker_id, lease_epoch = _fence_job_if_leased(job)
    if stage_hook is not None:
        stage_hook(stage, job)
    return _fence_job_if_leased(job)


def _report_progress_fenced(
    job: dict[str, Any],
    phase: str,
    percent: float | None = None,
) -> bool:
    lease_epoch = job.get("lease_epoch")
    worker_id = job.get("worker_id")
    if lease_epoch is not None:
        return report_job_progress(
            job["id"],
            phase,
            percent,
            worker_id=worker_id,
            lease_epoch=lease_epoch,
        )
    return report_job_progress(job["id"], phase, percent)


@traced_job("job.media.embed")
def process_embed(
    job: dict,
    storage: object | None = None,
    *,
    stage_hook: StageHook | None = None,
) -> dict:
    if storage is not None or "payload" not in job:
        input_path = job["input_path"]
        message_path = job["message_path"]
        output_path = job["output_path"]
        message = Path(message_path).read_text()
        meta = embed_metadata(input_path, message, output_path)
        return {"output_path": output_path, "message": message, **(meta if isinstance(meta, dict) else {})}
    payload = job["payload"]
    job_id = job["id"]
    metadata = payload["metadata"]
    filename = payload["filename"]
    worker_id = job.get("worker_id")
    lease_epoch = job.get("lease_epoch")

    input_path = get_job_input_path(job_id)
    output_path = get_job_output_path(job_id)

    if not input_path.exists():
        raise RuntimeError(f"Input video file missing for job {job_id}")

    _report_progress_fenced(job, "hashing_source")
    _run_stage_checkpoint(job, CRASH_STAGE_HASHING, stage_hook)
    source_hash = sha256_file(input_path)
    _fence_job_if_leased(job)

    def on_frame(frames_done: int, frames_total: int | None) -> None:
        percent = (frames_done / frames_total * 100.0) if frames_total else None
        _report_progress_fenced(job, "embedding", percent)

    staged_output = (
        output_path.with_name(f"{output_path.name}.epoch_{lease_epoch}.tmp")
        if lease_epoch is not None
        else output_path
    )
    try:
        embed_metadata(input_path, staged_output, metadata, progress_callback=on_frame)

        _report_progress_fenced(job, "hashing_output")
        _fence_job_if_leased(job)
        embedded_hash = sha256_file(staged_output)
        metadata_hash = canonical_metadata_hash(metadata)

        _report_progress_fenced(job, "recording")
        _run_stage_checkpoint(job, CRASH_STAGE_METADATA_WRITE, stage_hook)

        if lease_epoch is not None and staged_output != output_path and staged_output.exists():
            os.replace(staged_output, output_path)

        insert_kwargs: dict[str, Any] = {
            "event_type": "embed",
            "file_name": normalize_filename(filename),
            "video_hash": embedded_hash,
            "metadata_hash": metadata_hash,
            "proof_id": metadata.get("proofId"),
            "tier": metadata.get("tier"),
            "embedded_hash": embedded_hash,
            "metadata": redact_metadata(metadata),
        }
        if lease_epoch is not None:
            assert_active_job_lease(job_id, worker_id=worker_id, lease_epoch=lease_epoch)
        db_event = insert_proof_event(**insert_kwargs)
    except BaseException:
        if lease_epoch is not None and staged_output != output_path:
            staged_output.unlink(missing_ok=True)
        raise

    if lease_epoch is None:
        input_path.unlink(missing_ok=True)

    return {
        "source_hash": source_hash,
        "embedded_hash": embedded_hash,
        "metadata_hash": metadata_hash,
        "db_event": db_event,
    }


@traced_job("job.media.extract")
def process_extract(
    job: dict,
    storage: object | None = None,
    *,
    stage_hook: StageHook | None = None,
) -> dict:
    if storage is not None or "payload" not in job:
        input_path = job["input_path"]
        output_path = job["output_path"]
        res = extract_metadata(input_path, output_path)
        return {"output_path": output_path, **(res if isinstance(res, dict) else {})}
    payload = job["payload"]
    job_id = job["id"]
    filename = payload["filename"]
    worker_id = job.get("worker_id")
    lease_epoch = job.get("lease_epoch")

    input_path = get_job_input_path(job_id)

    if not input_path.exists():
        raise RuntimeError(f"Input video file missing for job {job_id}")

    metadata = extract_metadata(input_path)
    _run_stage_checkpoint(job, CRASH_STAGE_HASHING, stage_hook)
    video_hash = sha256_file(input_path)
    metadata_hash = canonical_metadata_hash(metadata) if metadata else None

    _run_stage_checkpoint(job, CRASH_STAGE_METADATA_WRITE, stage_hook)
    if lease_epoch is not None:
        assert_active_job_lease(job_id, worker_id=worker_id, lease_epoch=lease_epoch)
    db_event = insert_proof_event(
        event_type="extract",
        file_name=normalize_filename(filename),
        video_hash=video_hash,
        metadata_hash=metadata_hash,
        proof_id=metadata.get("proofId") if metadata else None,
        tier=metadata.get("tier") if metadata else None,
        metadata=redact_metadata(metadata),
    )

    if lease_epoch is None:
        input_path.unlink(missing_ok=True)

    return {
        "video_hash": video_hash,
        "metadata_hash": metadata_hash,
        "metadata": metadata,
        "db_event": db_event,
    }


@traced_job("job.proof.noir")
def process_silent_witness(
    job: dict,
    storage: object | None = None,
    *,
    stage_hook: StageHook | None = None,
) -> dict:
    if storage is not None or "payload" not in job:
        input_path = job["input_path"]
        output_path = job["output_path"]
        res = generate_silent_witness(input_path, output_path)
        return {"output_path": output_path, **(res if isinstance(res, dict) else {})}
    payload = job["payload"]

    video_hash = payload["video_hash"]
    credential_secret = payload["credential_secret"]
    nullifier_secret = payload["nullifier_secret"]

    # Phase names only: proof generation runs as one external command and
    # reports no measurable fraction, so percent stays None.
    _report_progress_fenced(job, "generating_proof")
    _run_stage_checkpoint(job, CRASH_STAGE_PROVING, stage_hook)
    proof = generate_silent_witness(
        video_hash,
        credential_secret,
        nullifier_secret,
    )
    _fence_job_if_leased(job)

    return {"proof": proof}

def process_verify_tx(job: dict, storage: object | None = None) -> dict:
    """Reconcile a single registration tx enqueued at proof registration time."""
    if storage is not None or ("input_path" in job and "payload" not in job):
        import json
        data = json.loads(Path(job["input_path"]).read_text())
        status = verify_transaction_status(data["tx_id"])
        output_path = job["output_path"]
        Path(output_path).write_text(json.dumps(status))
        return {"output_path": output_path, **(status if isinstance(status, dict) else {"status": status})}
    return process_verify_tx_job(job.get("payload") or {})


def is_fatal(job_type: str, err: BaseException) -> bool:
    """Classify whether a job failure is non-retryable."""
    return isinstance(err, ValueError) and job_type != "verify_tx"

def heartbeat_loop(
    job_id: int | str,
    stop_event: threading.Event,
    *,
    worker_id: str | None = None,
    lease_epoch: int | None = None,
):
    while not stop_event.is_set():
        if lease_epoch is not None:
            alive = heartbeat_job(
                job_id,
                lease_duration=300,
                worker_id=worker_id,
                lease_epoch=lease_epoch,
            )
            if not alive:
                break
        else:
            heartbeat_job(job_id, lease_duration=300)
        stop_event.wait(60)


def execute_leased_job(
    job: dict[str, Any],
    *,
    stage_hook: StageHook | None = None,
) -> dict[str, Any]:
    """Execute a leased job and commit completion under its fencing epoch."""
    job_id = job["id"]
    job_type = job["type"]
    worker_id = job.get("worker_id")
    lease_epoch = job.get("lease_epoch")

    if job_type == "embed":
        res = process_embed(job, stage_hook=stage_hook)
    elif job_type == "extract":
        res = process_extract(job, stage_hook=stage_hook)
    elif job_type == "silent_witness":
        res = process_silent_witness(job, stage_hook=stage_hook)
    elif job_type == "verify_tx":
        _fence_job_if_leased(job)
        res = process_verify_tx(job)
    else:
        raise ValueError(f"Unknown job type {job_type}")

    if lease_epoch is not None:
        complete_job(job_id, res, worker_id=worker_id, lease_epoch=lease_epoch)
        if job_type in ("embed", "extract"):
            get_job_input_path(job_id).unlink(missing_ok=True)
    else:
        complete_job(job_id, res)
    return res


@dataclass(frozen=True)
class WorkerCrashRecoveryOutcome:
    scenario_stage: str
    job_id: int
    crashed_worker_id: str
    crashed_lease_epoch: int
    recovering_worker_id: str
    recovered_lease_epoch: int
    stale_commit_blocked: bool
    stale_metadata_write_blocked: bool
    stale_fail_blocked: bool
    final_status: str
    committed_worker_id: str | None
    committed_lease_epoch: int | None
    metadata_commits: tuple[int, ...]


def run_deterministic_crash_recovery_scenario(
    stage: str,
    *,
    storage_dir: Path | str | None = None,
    lease_duration: int = 30,
) -> WorkerCrashRecoveryOutcome:
    """Deterministically simulate multi-worker crash, reassignment, and stale-worker fencing.

    Supported stages:
      - ``hashing``: Worker A crashes during input hashing; Worker B reclaims and
        completes; stale Worker A cannot overwrite progress, metadata, or result.
      - ``proving``: Worker A stalls/crashes during Noir proof generation; Worker B
        reclaims and commits proof; stale Worker A cannot commit its late proof.
      - ``metadata_write``: Worker A crashes right before proof-event persistence;
        Worker B reclaims, writes canonical output + single metadata event, and
        commits; stale Worker A is fenced out of both metadata write and completion.
    """
    if stage not in SUPPORTED_CRASH_STAGES:
        raise ValueError(f"unsupported crash stage: {stage!r}")
    if lease_duration <= 0:
        raise ValueError("lease_duration must be positive")

    import hashlib as _hashlib
    import tempfile as _tempfile
    from contextlib import ExitStack
    from unittest.mock import patch as _patch

    worker_a = "worker-alpha"
    worker_b = "worker-beta"
    t0 = 1_000.0
    metadata_epochs_committed: list[int] = []

    with ExitStack() as stack:
        if storage_dir is None:
            tmp_dir = Path(stack.enter_context(_tempfile.TemporaryDirectory(prefix="harpocrates-crash-sim-")))
        else:
            tmp_dir = Path(storage_dir)
            tmp_dir.mkdir(parents=True, exist_ok=True)

        stack.enter_context(_patch.dict(os.environ, {"HARPOCRATES_STORAGE_DIR": str(tmp_dir)}))

        def _deterministic_embed(src: Path | str, dst: Path | str, meta: dict, progress_callback=None) -> None:
            raw = Path(src).read_bytes()
            if progress_callback is not None:
                progress_callback(1, 1)
            Path(dst).write_bytes(raw + b"|embedded:" + str(meta.get("proofId", "")).encode("ascii"))

        def _deterministic_sha256(path: Path | str) -> str:
            return _hashlib.sha256(Path(path).read_bytes()).hexdigest()

        def _fenced_insert_proof_event(**kwargs: Any) -> dict[str, Any]:
            if kwargs.get("job_id") is not None and (
                kwargs.get("worker_id") is not None or kwargs.get("lease_epoch") is not None
            ):
                assert_active_job_lease(
                    kwargs["job_id"],
                    worker_id=kwargs.get("worker_id"),
                    lease_epoch=kwargs.get("lease_epoch"),
                    now=t_reclaim + 2.0,
                )
            active_job = get_job(job_id) or {}
            epoch_now = int(active_job.get("lease_epoch") or 0)
            metadata_epochs_committed.append(epoch_now)
            return {"id": len(metadata_epochs_committed), "lease_epoch": epoch_now, "event_type": kwargs.get("event_type")}

        def _deterministic_witness(video_hash: str, cred_secret: str, null_secret: str) -> dict[str, str]:
            digest = _hashlib.sha256(f"{video_hash}:{len(cred_secret)}:{len(null_secret)}".encode("ascii")).hexdigest()
            return {"proof_digest": digest}

        stack.enter_context(_patch.object(sys.modules[__name__], "embed_metadata", side_effect=_deterministic_embed))
        stack.enter_context(_patch.object(sys.modules[__name__], "sha256_file", side_effect=_deterministic_sha256))
        stack.enter_context(_patch.object(sys.modules[__name__], "insert_proof_event", side_effect=_fenced_insert_proof_event))
        stack.enter_context(_patch.object(sys.modules[__name__], "generate_silent_witness", side_effect=_deterministic_witness))

        if stage == CRASH_STAGE_PROVING:
            job_id = enqueue_job(
                "silent_witness",
                {
                    "video_hash": "aa" * 32,
                    "credential_secret": "synthetic-cred-ref",
                    "nullifier_secret": "synthetic-null-ref",
                },
            )
        else:
            job_id = enqueue_job(
                "embed",
                {
                    "filename": "synthetic_clip.mp4",
                    "metadata": {
                        "protocol": "harpocrates",
                        "version": 1,
                        "tier": "silent",
                        "proofId": "11" * 32,
                    },
                },
            )
            get_job_input_path(job_id).write_bytes(b"synthetic-frame-bytes")

        # 1. Worker A leases job under epoch 1 and crashes deterministically at target stage.
        leased_a = lease_job(worker_a, ["embed", "extract", "silent_witness"], lease_duration=lease_duration, now=t0)
        assert leased_a is not None
        epoch_a = int(leased_a["lease_epoch"])

        def _crash_on_stage(current_stage: str, current_job: dict[str, Any]) -> None:
            if current_stage == stage and current_job.get("worker_id") == worker_a:
                raise SimulatedWorkerCrash(stage, worker_id=worker_a, lease_epoch=epoch_a)

        with _patch("db.time.monotonic", return_value=t0 + 1.0):
            try:
                execute_leased_job(leased_a, stage_hook=_crash_on_stage)
            except SimulatedWorkerCrash:
                pass

        # 2. Lease expires after unclean crash; Worker B reclaims job under epoch 2 and completes cleanly.
        t_reclaim = t0 + float(lease_duration) + 1.0
        leased_b = lease_job(worker_b, ["embed", "extract", "silent_witness"], lease_duration=lease_duration, now=t_reclaim)
        assert leased_b is not None
        epoch_b = int(leased_b["lease_epoch"])

        with _patch("db.time.monotonic", return_value=t_reclaim + 1.0):
            execute_leased_job(leased_b)

        # 3. Zombie / late Worker A wakes up holding stale epoch_a and tries to mutate metadata, completion, and failure state.
        stale_metadata_write_blocked = False
        try:
            insert_proof_event(
                event_type="embed",
                video_hash="ff" * 32,
                job_id=job_id,
                worker_id=worker_a,
                lease_epoch=epoch_a,
            )
        except StaleWorkerLeaseError:
            stale_metadata_write_blocked = True

        stale_commit_blocked = False
        try:
            complete_job(
                job_id,
                {"corrupted_by": worker_a},
                worker_id=worker_a,
                lease_epoch=epoch_a,
                now=t_reclaim + 2.0,
            )
        except StaleWorkerLeaseError:
            stale_commit_blocked = True

        stale_fail_ok = fail_job(
            job_id,
            "late crash cleanup from stale worker",
            is_fatal=True,
            worker_id=worker_a,
            lease_epoch=epoch_a,
            now=t_reclaim + 2.0,
        )
        stale_fail_blocked = not stale_fail_ok

        final_job = get_job(job_id) or {}
        return WorkerCrashRecoveryOutcome(
            scenario_stage=stage,
            job_id=job_id,
            crashed_worker_id=worker_a,
            crashed_lease_epoch=epoch_a,
            recovering_worker_id=worker_b,
            recovered_lease_epoch=epoch_b,
            stale_commit_blocked=stale_commit_blocked,
            stale_metadata_write_blocked=stale_metadata_write_blocked,
            stale_fail_blocked=stale_fail_blocked,
            final_status=str(final_job.get("status")),
            committed_worker_id=final_job.get("worker_id"),
            committed_lease_epoch=final_job.get("committed_lease_epoch"),
            metadata_commits=tuple(metadata_epochs_committed),
        )

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
            lease_epoch = job.get("lease_epoch")
            lease_worker_id = job.get("worker_id")
            LOGGER.info(f"Leased job {job_id} of type {job_type}")

            hb_stop_event = threading.Event()
            hb_kwargs = (
                {"worker_id": lease_worker_id, "lease_epoch": lease_epoch}
                if lease_epoch is not None
                else {}
            )
            hb_thread = threading.Thread(
                target=heartbeat_loop,
                args=(job_id, hb_stop_event),
                kwargs=hb_kwargs,
            )
            hb_thread.start()

            def _execute_job():
                try:
                    if job_type == "embed":
                        res = process_embed(job)
                    elif job_type == "extract":
                        res = process_extract(job)
                    elif job_type == "silent_witness":
                        res = process_silent_witness(job)
                    elif job_type == "verify_tx":
                        _fence_job_if_leased(job)
                        res = process_verify_tx(job)
                    else:
                        raise ValueError(f"Unknown job type {job_type}")
                    if lease_epoch is not None:
                        complete_job(job_id, res, worker_id=lease_worker_id, lease_epoch=lease_epoch)
                        if job_type in ("embed", "extract"):
                            get_job_input_path(job_id).unlink(missing_ok=True)
                    else:
                        complete_job(job_id, res)
                    LOGGER.info(f"Completed job {job_id}")
                except StaleWorkerLeaseError:
                    LOGGER.warning(
                        "Discarding stale execution for job %s (epoch=%s)",
                        job_id,
                        lease_epoch,
                    )
                except Exception as err:
                    LOGGER.error(f"Failed job {job_id}: {err}")
                    LOGGER.error(traceback.format_exc())
                    fatal = isinstance(err, ValueError) and job_type != "verify_tx"
                    if job_type == "verify_tx":
                        fatal = isinstance(err, ValueError)
                    if lease_epoch is not None:
                        fail_job(
                            job_id,
                            str(err),
                            is_fatal=fatal,
                            worker_id=lease_worker_id,
                            lease_epoch=lease_epoch,
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
                        if lease_epoch is not None:
                            fail_job(
                                job_id,
                                "Worker shutdown grace period exceeded",
                                is_fatal=False,
                                worker_id=lease_worker_id,
                                lease_epoch=lease_epoch,
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

