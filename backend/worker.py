from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import logging
import re
import time
import os
from logging_utils import log_structured
import threading
import traceback
from pathlib import Path
from typing import Any, Sequence

from db import (
    lease_job,
    heartbeat_job,
    report_job_progress,
    requeue_abandoned_job,
    snapshot_jobs_read_only,
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

@traced_job("job.media.embed")
def process_embed(job: dict, storage: object | None = None) -> dict:
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
    
    input_path = get_job_input_path(job_id)
    output_path = get_job_output_path(job_id)
    
    if not input_path.exists():
        raise RuntimeError(f"Input video file missing for job {job_id}")
        
    report_job_progress(job_id, "hashing_source")
    source_hash = sha256_file(input_path)

    def on_frame(frames_done: int, frames_total: int | None) -> None:
        percent = (frames_done / frames_total * 100.0) if frames_total else None
        report_job_progress(job_id, "embedding", percent)

    embed_metadata(input_path, output_path, metadata, progress_callback=on_frame)

    report_job_progress(job_id, "hashing_output")
    embedded_hash = sha256_file(output_path)
    metadata_hash = canonical_metadata_hash(metadata)

    report_job_progress(job_id, "recording")
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
    
    input_path.unlink(missing_ok=True)
    
    return {
        "source_hash": source_hash,
        "embedded_hash": embedded_hash,
        "metadata_hash": metadata_hash,
        "db_event": db_event
    }

@traced_job("job.media.extract")
def process_extract(job: dict, storage: object | None = None) -> dict:
    if storage is not None or "payload" not in job:
        input_path = job["input_path"]
        output_path = job["output_path"]
        res = extract_metadata(input_path, output_path)
        return {"output_path": output_path, **(res if isinstance(res, dict) else {})}
    payload = job["payload"]
    job_id = job["id"]
    filename = payload["filename"]
    
    input_path = get_job_input_path(job_id)
    
    if not input_path.exists():
        raise RuntimeError(f"Input video file missing for job {job_id}")
        
    metadata = extract_metadata(input_path)
    video_hash = sha256_file(input_path)
    metadata_hash = canonical_metadata_hash(metadata) if metadata else None
    
    db_event = insert_proof_event(
        event_type="extract",
        file_name=normalize_filename(filename),
        video_hash=video_hash,
        metadata_hash=metadata_hash,
        proof_id=metadata.get("proofId") if metadata else None,
        tier=metadata.get("tier") if metadata else None,
        metadata=redact_metadata(metadata),
    )
    
    input_path.unlink(missing_ok=True)
    
    return {
        "video_hash": video_hash,
        "metadata_hash": metadata_hash,
        "metadata": metadata,
        "db_event": db_event
    }

@traced_job("job.proof.noir")
def process_silent_witness(job: dict, storage: object | None = None) -> dict:
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
    report_job_progress(job["id"], "generating_proof")
    proof = generate_silent_witness(
        video_hash,
        credential_secret,
        nullifier_secret,
    )
    
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


UNCERTAINTY_LOW = "low_safe_to_recover"
UNCERTAINTY_ACTIVE_WRITER = "uncertain_possible_active_writer"
UNCERTAINTY_EXTERNAL_SIDE_EFFECT = "uncertain_external_side_effect"
UNCERTAINTY_ORPHANED_ARTIFACT = "uncertain_orphaned_without_job"

DEFAULT_MAX_RECOVERY_FINDINGS = 100
DEFAULT_MAX_RECOVERY_ACTIONS = 25
MAX_RECOVERY_ACTIONS_HARD_LIMIT = 100

_JOB_ARTIFACT_RE = re.compile(r"^job_([A-Za-z0-9_-]+)_(input|output)(.*)$")


class RecoverySelectionError(ValueError):
    """Raised when recovery action selection is unbounded, invalid, or unapproved for uncertain items."""


@dataclass(frozen=True)
class AbandonedLeaseFinding:
    action_id: str
    job_id: int | str
    job_type: str
    worker_id: str | None
    last_phase: str | None
    silence_seconds: float | None
    recommended_action: str
    uncertainty: str
    uncertainty_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "job_id": self.job_id,
            "job_type": self.job_type,
            "worker_id": self.worker_id,
            "last_phase": self.last_phase,
            "silence_seconds": self.silence_seconds,
            "recommended_action": self.recommended_action,
            "uncertainty": self.uncertainty,
            "uncertainty_reason": self.uncertainty_reason,
        }


@dataclass(frozen=True)
class PartialArtifactFinding:
    action_id: str
    job_id: int | str | None
    artifact_role: str
    size_bytes: int
    age_seconds: float
    recommended_action: str
    uncertainty: str
    uncertainty_reason: str
    _entry_name: str = field(repr=False)

    def to_dict(self) -> dict[str, Any]:
        # Omit _entry_name so user-supplied or unexpected filenames never leak in recovery reports.
        return {
            "action_id": self.action_id,
            "job_id": self.job_id,
            "artifact_role": self.artifact_role,
            "size_bytes": self.size_bytes,
            "age_seconds": self.age_seconds,
            "recommended_action": self.recommended_action,
            "uncertainty": self.uncertainty,
            "uncertainty_reason": self.uncertainty_reason,
        }


@dataclass(frozen=True)
class WorkerRecoveryPlan:
    plan_id: str
    generated_at: str
    read_only: bool
    truncated: bool
    lease_timeout_seconds: float
    abandoned_leases: tuple[AbandonedLeaseFinding, ...]
    partial_artifacts: tuple[PartialArtifactFinding, ...]
    _storage_root: Path | None = field(default=None, repr=False)

    def action_ids(self) -> frozenset[str]:
        lease_ids = {f.action_id for f in self.abandoned_leases}
        art_ids = {f.action_id for f in self.partial_artifacts}
        return frozenset(lease_ids | art_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "generated_at": self.generated_at,
            "read_only": self.read_only,
            "truncated": self.truncated,
            "lease_timeout_seconds": self.lease_timeout_seconds,
            "abandoned_leases": [f.to_dict() for f in self.abandoned_leases],
            "partial_artifacts": [f.to_dict() for f in self.partial_artifacts],
        }


@dataclass(frozen=True)
class RecoveryExecutionReport:
    plan_id: str
    applied_action_ids: tuple[str, ...]
    skipped_action_ids: tuple[str, ...]
    requeued_jobs: int
    removed_artifacts: int


def _parse_iso_utc(raw: Any) -> datetime | None:
    if isinstance(raw, datetime):
        return raw if raw.tzinfo is not None else raw.replace(tzinfo=timezone.utc)
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(float(raw), tz=timezone.utc)
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
            return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _coerce_now_dt(now: datetime | float | int | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, datetime):
        return now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    return datetime.fromtimestamp(float(now), tz=timezone.utc)


def _artifact_action_id(entry_name: str) -> str:
    digest = hashlib.sha256(f"harpocrates:recovery-artifact:v1|{entry_name}".encode("utf-8")).hexdigest()[:16]
    return f"remove_artifact:{digest}"


def build_worker_recovery_plan(
    *,
    storage_dir: Path | str | None = None,
    now: datetime | float | int | None = None,
    lease_timeout_seconds: float = 300.0,
    active_write_grace_seconds: float = 60.0,
    max_findings: int = DEFAULT_MAX_RECOVERY_FINDINGS,
) -> WorkerRecoveryPlan:
    """Inspect jobs and job-storage directory in strictly read-only mode after an unclean shutdown.

    Identifies abandoned ``running`` leases and partial/orphaned artifacts with
    explicit uncertainty classifications, never mutating DB state or filesystem
    directories/files.
    """
    if lease_timeout_seconds <= 0:
        raise ValueError("lease_timeout_seconds must be positive")
    if active_write_grace_seconds < 0:
        raise ValueError("active_write_grace_seconds must be non-negative")
    if max_findings <= 0:
        raise ValueError("max_findings must be positive")

    now_dt = _coerce_now_dt(now)
    target_dir = (
        Path(storage_dir)
        if storage_dir is not None
        else Path(os.getenv("HARPOCRATES_STORAGE_DIR", "/tmp/harpocrates_jobs"))
    )

    jobs_snapshot = snapshot_jobs_read_only()
    abandoned_leases: list[AbandonedLeaseFinding] = []
    abandoned_job_ids: set[int | str] = set()
    truncated = False

    # 1. Inspect running leases without mutating job state
    for jid in sorted(jobs_snapshot.keys(), key=lambda x: str(x)):
        job = jobs_snapshot[jid]
        if job.get("status") != "running":
            continue

        last_ts = (
            _parse_iso_utc(job.get("heartbeat_at"))
            or _parse_iso_utc(job.get("leased_at"))
            or _parse_iso_utc(job.get("created_at"))
        )
        effective_timeout = float(job.get("lease_duration") or lease_timeout_seconds)
        effective_timeout = min(effective_timeout, float(lease_timeout_seconds))

        silence_sec: float | None = None
        if last_ts is not None:
            silence_sec = round(max(0.0, (now_dt - last_ts).total_seconds()), 3)
            if silence_sec < effective_timeout:
                # Active healthy lease; not abandoned
                continue

        abandoned_job_ids.add(jid)
        if len(abandoned_leases) >= max_findings:
            truncated = True
            continue

        progress = job.get("progress")
        phase = progress.get("phase") if isinstance(progress, dict) else None
        job_type = str(job.get("type", "unknown"))

        if job_type == "verify_tx" or phase == "recording":
            uncertainty = UNCERTAINTY_EXTERNAL_SIDE_EFFECT
            reason = "interrupted during external metadata/chain reconciliation; verify idempotency before requeue"
            rec_action = "inspect_before_requeue"
        elif silence_sec is None:
            uncertainty = UNCERTAINTY_ACTIVE_WRITER
            reason = "missing heartbeat and lease timestamps; cannot rule out concurrent active worker"
            rec_action = "inspect_before_requeue"
        else:
            uncertainty = UNCERTAINTY_LOW
            reason = "heartbeat silence exceeded lease timeout in pre-commit stage"
            rec_action = "requeue_job"

        abandoned_leases.append(
            AbandonedLeaseFinding(
                action_id=f"requeue_lease:{jid}",
                job_id=jid,
                job_type=job_type,
                worker_id=job.get("worker_id"),
                last_phase=phase,
                silence_seconds=silence_sec,
                recommended_action=rec_action,
                uncertainty=uncertainty,
                uncertainty_reason=reason,
            )
        )

    # 2. Inspect storage artifacts in strictly read-only mode (no mkdir/chmod/unlink)
    partial_artifacts: list[PartialArtifactFinding] = []
    remaining_budget = max(0, max_findings - len(abandoned_leases))

    if target_dir.exists() and target_dir.is_dir():
        entries = sorted(target_dir.iterdir(), key=lambda p: p.name)
        for entry in entries:
            try:
                st = entry.lstat()
            except OSError:
                continue
            # Never follow symlinks; only inspect regular files
            if entry.is_symlink() or not entry.is_file():
                continue

            mtime_dt = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
            age_sec = round(max(0.0, (now_dt - mtime_dt).total_seconds()), 3)
            size_bytes = int(st.st_size)

            m = _JOB_ARTIFACT_RE.match(entry.name)
            matched_job_id: int | str | None = None
            role = "unknown_orphan"
            suffix = ""
            if m:
                raw_id, kind, suffix = m.group(1), m.group(2), m.group(3)
                matched_job_id = int(raw_id) if raw_id.isdigit() else raw_id
                if suffix and any(tok in suffix.lower() for tok in (".tmp", ".part", "epoch_")):
                    role = "partial_temp"
                else:
                    role = kind  # "input" or "output"
            elif entry.name.lower().endswith((".tmp", ".part")):
                role = "partial_temp"

            job = jobs_snapshot.get(matched_job_id) if matched_job_id is not None else None

            # Determine whether this file is a normal expected file or a partial/abandoned artifact
            is_candidate = False
            uncertainty = UNCERTAINTY_LOW
            reason = ""
            rec_action = "delete_partial_artifact"

            if job is None:
                is_candidate = True
                if age_sec < active_write_grace_seconds:
                    uncertainty = UNCERTAINTY_ACTIVE_WRITER
                    reason = "unreferenced artifact modified within active-write grace window"
                    rec_action = "retain_until_verified"
                else:
                    uncertainty = UNCERTAINTY_ORPHANED_ARTIFACT
                    reason = "artifact has no matching job record in job store"
                    rec_action = "delete_partial_artifact"
            else:
                j_status = job.get("status")
                if j_status == "pending":
                    # Pending job's normal input must be kept; any pre-existing output/temp or 0-byte input is partial
                    if role in ("output", "partial_temp"):
                        is_candidate = True
                        uncertainty = (
                            UNCERTAINTY_ACTIVE_WRITER
                            if age_sec < active_write_grace_seconds
                            else UNCERTAINTY_LOW
                        )
                        reason = "stale partial output present for pending job"
                    elif role == "input" and size_bytes == 0:
                        is_candidate = True
                        uncertainty = UNCERTAINTY_ORPHANED_ARTIFACT
                        reason = "zero-byte input artifact for pending job"
                        rec_action = "retain_until_verified"
                elif j_status == "running":
                    if matched_job_id in abandoned_job_ids:
                        if role in ("output", "partial_temp"):
                            is_candidate = True
                            if age_sec < active_write_grace_seconds:
                                uncertainty = UNCERTAINTY_ACTIVE_WRITER
                                reason = "partial output modified recently; writer may still be flushing"
                                rec_action = "retain_until_verified"
                            else:
                                uncertainty = UNCERTAINTY_LOW
                                reason = "incomplete output artifact left by abandoned worker lease"
                                rec_action = "delete_partial_artifact"
                        elif role == "input" and size_bytes == 0:
                            is_candidate = True
                            uncertainty = UNCERTAINTY_ORPHANED_ARTIFACT
                            reason = "zero-byte input file on abandoned lease"
                            rec_action = "retain_until_verified"
                    # Healthy running job artifacts are left untouched
                elif j_status == "completed":
                    if role == "partial_temp":
                        is_candidate = True
                        uncertainty = (
                            UNCERTAINTY_ACTIVE_WRITER
                            if age_sec < active_write_grace_seconds
                            else UNCERTAINTY_LOW
                        )
                        reason = "leftover temporary staging file after job completion"
                elif j_status in ("failed", "cancelled", "abandoned"):
                    if role in ("output", "partial_temp"):
                        is_candidate = True
                        uncertainty = (
                            UNCERTAINTY_ACTIVE_WRITER
                            if age_sec < active_write_grace_seconds
                            else UNCERTAINTY_LOW
                        )
                        reason = f"partial {role} artifact from {j_status} job"

            if not is_candidate:
                continue

            if len(partial_artifacts) >= remaining_budget:
                truncated = True
                continue

            partial_artifacts.append(
                PartialArtifactFinding(
                    action_id=_artifact_action_id(entry.name),
                    job_id=matched_job_id,
                    artifact_role=role,
                    size_bytes=size_bytes,
                    age_seconds=age_sec,
                    recommended_action=rec_action,
                    uncertainty=uncertainty,
                    uncertainty_reason=reason,
                    _entry_name=entry.name,
                )
            )

    plan_seed = "|".join(
        [now_dt.isoformat()]
        + [f.action_id for f in abandoned_leases]
        + [f.action_id for f in partial_artifacts]
    )
    plan_id = "wrp-v1:" + hashlib.sha256(plan_seed.encode("utf-8")).hexdigest()[:16]

    return WorkerRecoveryPlan(
        plan_id=plan_id,
        generated_at=now_dt.isoformat(),
        read_only=True,
        truncated=truncated,
        lease_timeout_seconds=float(lease_timeout_seconds),
        abandoned_leases=tuple(abandoned_leases),
        partial_artifacts=tuple(partial_artifacts),
        _storage_root=target_dir,
    )


def apply_selected_recovery_actions(
    plan: WorkerRecoveryPlan,
    selected_action_ids: Sequence[str],
    *,
    storage_dir: Path | str | None = None,
    max_actions: int = DEFAULT_MAX_RECOVERY_ACTIONS,
    allow_uncertain: bool = False,
) -> RecoveryExecutionReport:
    """Execute an explicit, bounded subset of actions from a read-only recovery plan."""
    if not isinstance(plan, WorkerRecoveryPlan):
        raise RecoverySelectionError("plan must be a WorkerRecoveryPlan")
    if isinstance(max_actions, bool) or not isinstance(max_actions, int) or max_actions <= 0:
        raise RecoverySelectionError("max_actions must be a positive integer")
    if max_actions > MAX_RECOVERY_ACTIONS_HARD_LIMIT:
        raise RecoverySelectionError(
            f"max_actions cannot exceed hard limit of {MAX_RECOVERY_ACTIONS_HARD_LIMIT}"
        )
    if (
        not isinstance(selected_action_ids, Sequence)
        or isinstance(selected_action_ids, (str, bytes))
        or len(selected_action_ids) == 0
    ):
        raise RecoverySelectionError("selected_action_ids must be a non-empty sequence of action IDs")
    if len(selected_action_ids) > max_actions:
        raise RecoverySelectionError(
            f"selected action count ({len(selected_action_ids)}) exceeds max_actions ({max_actions})"
        )

    lease_by_id = {f.action_id: f for f in plan.abandoned_leases}
    art_by_id = {f.action_id: f for f in plan.partial_artifacts}

    seen: set[str] = set()
    validated_ids: list[str] = []
    for raw_id in selected_action_ids:
        if not isinstance(raw_id, str) or not raw_id.strip():
            raise RecoverySelectionError("action_id must be a non-empty string")
        aid = raw_id.strip()
        if aid in ("*", "all", "ALL"):
            raise RecoverySelectionError("wildcard recovery selection is forbidden; select explicit action IDs")
        if aid in seen:
            raise RecoverySelectionError(f"duplicate action_id selected: {aid}")
        seen.add(aid)
        finding: AbandonedLeaseFinding | PartialArtifactFinding | None = lease_by_id.get(aid) or art_by_id.get(aid)
        if finding is None:
            raise RecoverySelectionError(f"unknown action_id not present in recovery plan: {aid}")
        if finding.uncertainty != UNCERTAINTY_LOW and not allow_uncertain:
            raise RecoverySelectionError(
                f"action {aid} carries uncertainty={finding.uncertainty!r}; "
                "pass allow_uncertain=True only after manual verification"
            )
        validated_ids.append(aid)

    root_dir = (
        Path(storage_dir)
        if storage_dir is not None
        else (plan._storage_root or Path(os.getenv("HARPOCRATES_STORAGE_DIR", "/tmp/harpocrates_jobs")))
    )

    applied: list[str] = []
    skipped: list[str] = []
    requeued_count = 0
    removed_count = 0

    for aid in validated_ids:
        if aid in lease_by_id:
            lf = lease_by_id[aid]
            if requeue_abandoned_job(lf.job_id):
                requeued_count += 1
                applied.append(aid)
            else:
                skipped.append(aid)
        else:
            af = art_by_id[aid]
            if not root_dir.exists() or root_dir.is_symlink():
                skipped.append(aid)
                continue
            resolved_root = root_dir.resolve()
            candidate = root_dir / af._entry_name
            if candidate.is_symlink():
                skipped.append(aid)
                continue
            try:
                resolved_candidate = candidate.resolve()
                resolved_candidate.relative_to(resolved_root)
            except (OSError, ValueError):
                skipped.append(aid)
                continue
            if candidate.exists() and candidate.is_file():
                try:
                    candidate.unlink()
                    removed_count += 1
                    applied.append(aid)
                except OSError:
                    skipped.append(aid)
            else:
                skipped.append(aid)

    return RecoveryExecutionReport(
        plan_id=plan.plan_id,
        applied_action_ids=tuple(applied),
        skipped_action_ids=tuple(skipped),
        requeued_jobs=requeued_count,
        removed_artifacts=removed_count,
    )


def is_fatal(job_type: str, err: BaseException) -> bool:
    """Classify whether a job failure is non-retryable."""
    return isinstance(err, ValueError) and job_type != "verify_tx"

def heartbeat_loop(job_id: int, stop_event: threading.Event):
    while not stop_event.is_set():
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
            LOGGER.info(f"Leased job {job_id} of type {job_type}")

            hb_stop_event = threading.Event()
            hb_thread = threading.Thread(target=heartbeat_loop, args=(job_id, hb_stop_event))
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
                        res = process_verify_tx(job)
                    else:
                        raise ValueError(f"Unknown job type {job_type}")
                    complete_job(job_id, res)
                    LOGGER.info(f"Completed job {job_id}")
                except Exception as err:
                    LOGGER.error(f"Failed job {job_id}: {err}")
                    LOGGER.error(traceback.format_exc())
                    is_fatal = isinstance(err, ValueError) and job_type != "verify_tx"
                    if job_type == "verify_tx":
                        is_fatal = isinstance(err, ValueError)
                    fail_job(job_id, str(err), is_fatal=is_fatal)
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

