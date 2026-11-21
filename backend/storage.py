import hashlib
import json
import logging
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

default_storage_dir = "/tmp/harpocrates_jobs"

RECEIPT_FILENAME = "deletion_receipts.jsonl"
RECEIPT_PHASE_SELECTED = "selected"
RECEIPT_PHASE_COMPLETED = "completed"


def _log_warning(message: str) -> None:
    try:
        import logging

        logging.getLogger(__name__).warning(message)
    except Exception:
        pass


def _get_owner_uid(path: Path) -> int | None:
    try:
        return path.stat().st_uid
    except OSError:
        return None


def get_storage_dir() -> Path:
    storage_dir = Path(os.getenv("HARPOCRATES_STORAGE_DIR", default_storage_dir))

    posix = os.name == "posix"
    if posix:
        storage_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            owner_uid = _get_owner_uid(storage_dir)
            if owner_uid == os.getuid():
                current_mode = stat.S_IMODE(storage_dir.stat().st_mode)
                if current_mode != 0o700:
                    os.chmod(storage_dir, 0o700)
            elif owner_uid is not None:
                _log_warning(
                    "Storage directory is owned by another user; "
                    "unable to tighten permissions."
                )
        except OSError:
            pass
    else:
        storage_dir.mkdir(parents=True, exist_ok=True)

    return storage_dir


def get_job_input_path(job_id: int | str) -> Path:
    return get_storage_dir() / f"job_{job_id}_input"


def get_job_output_path(job_id: int | str) -> Path:
    return get_storage_dir() / f"job_{job_id}_output"


def _parse_timestamp(val: Any) -> datetime:
    if isinstance(val, datetime):
        return val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
    if isinstance(val, (int, float)):
        return datetime.fromtimestamp(val, tz=timezone.utc)
    if isinstance(val, str):
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _receipt_digest(file_name: str) -> str:
    # Only a one-way digest of the file name is stored: no plaintext paths,
    # media contents or key material ever enter the receipt log.
    return hashlib.sha256(file_name.encode("utf-8")).hexdigest()


def _append_receipt(
    target_dir: Path,
    record: dict[str, Any],
) -> None:
    receipt_path = target_dir / RECEIPT_FILENAME
    line = _canonical_json(record) + "\n"
    fd = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def record_deletion_selection(
    target_dir: Path,
    selected: list[Path],
    receipt_id: str,
    now: datetime,
) -> dict[str, Any]:
    """Phase one: durably record the approved selection before any unlink."""
    record = {
        "receipt_id": receipt_id,
        "phase": RECEIPT_PHASE_SELECTED,
        "recorded_at": now.isoformat(),
        "selected_digests": sorted(_receipt_digest(p.name) for p in selected),
        "selected_count": len(selected),
    }
    _append_receipt(target_dir, record)
    return record


def record_deletion_completion(
    target_dir: Path,
    selection: dict[str, Any],
    completed: list[Path],
    failed: list[Path],
    now: datetime,
) -> dict[str, Any]:
    """Phase two: record which selected actions actually completed."""
    completed_digests = sorted(_receipt_digest(p.name) for p in completed)
    failed_digests = sorted(_receipt_digest(p.name) for p in failed)
    record = {
        "receipt_id": selection["receipt_id"],
        "phase": RECEIPT_PHASE_COMPLETED,
        "recorded_at": now.isoformat(),
        "selection_sha256": hashlib.sha256(
            _canonical_json(
                {
                    "receipt_id": selection["receipt_id"],
                    "selected_digests": selection["selected_digests"],
                }
            ).encode("utf-8")
        ).hexdigest(),
        "completed_digests": completed_digests,
        "failed_digests": failed_digests,
        "completed_count": len(completed_digests),
        "failed_count": len(failed_digests),
    }
    _append_receipt(target_dir, record)
    return record


def sweep_job_files(
    storage_dir: Path | str | None = None,
    ttl_seconds: int | float | None = None,
    now: datetime | None = None,
) -> int:
    """Sweep and remove expired terminal job files and orphaned files from storage.

    Deletes files for jobs in terminal states older than TTL, and orphaned files
    with no job row older than TTL.
    Never removes files for running or pending jobs.
    Logs counts only, never file names derived from user input.

    Each sweep writes a two-phase deletion receipt: the approved selection is
    recorded before any unlink, and the completed/failed outcome after. Receipts
    hold only SHA-256 digests of file names and counts, never media or keys.

    Returns the count of deleted files.
    """
    if storage_dir is None:
        target_dir = get_storage_dir()
    else:
        target_dir = Path(storage_dir)

    if not target_dir.exists():
        return 0

    if ttl_seconds is None:
        try:
            from config import load_config

            ttl_seconds = load_config().job_file_ttl_seconds
        except Exception:
            ttl_seconds = 86_400

    if now is None:
        now_dt = datetime.now(timezone.utc)
    elif isinstance(now, datetime):
        now_dt = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    elif isinstance(now, (int, float)):
        now_dt = datetime.fromtimestamp(now, tz=timezone.utc)
    else:
        now_dt = datetime.now(timezone.utc)

    terminal_states = {"completed", "failed", "cancelled", "abandoned"}

    # Phase one: select without deleting.
    selected: list[Path] = []
    for entry in sorted(target_dir.iterdir()):
        if not entry.is_file():
            continue

        # Extract job_id from filename pattern: job_<id>_input, job_<id>_output, etc.
        job_id: int | str | None = None
        match = re.match(r"^job_([^_]+)(?:_(?:input|output).*)?$", entry.name)
        if match:
            raw_id = match.group(1)
            job_id = int(raw_id) if raw_id.isdigit() else raw_id

        job = None
        if job_id is not None:
            try:
                from db import get_job

                job = get_job(job_id)
            except Exception:
                job = None

        file_stat = entry.stat()
        file_mtime = datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc)

        if job is None:
            # Orphaned file with no job row
            file_age = (now_dt - file_mtime).total_seconds()
            if file_age >= ttl_seconds:
                selected.append(entry)
        else:
            status = job.get("status")
            if status in terminal_states:
                # Determine job completion / terminal timestamp
                ts_val = (
                    job.get("completed_at")
                    or job.get("failed_at")
                    or job.get("cancelled_at")
                    or job.get("finished_at")
                    or job.get("ended_at")
                    or job.get("updated_at")
                    or job.get("created_at")
                )
                if ts_val is not None:
                    job_dt = _parse_timestamp(ts_val)
                else:
                    job_dt = file_mtime

                job_age = (now_dt - job_dt).total_seconds()
                if job_age >= ttl_seconds:
                    selected.append(entry)
            # If status not in terminal_states (e.g., 'running' or 'pending'), do not remove.

    if not selected:
        return 0

    receipt_id = hashlib.sha256(
        f"{now_dt.isoformat()}|{len(selected)}|{os.getpid()}".encode("utf-8")
    ).hexdigest()[:32]

    # Receipt is durable before the first unlink; if it cannot be written, fail closed.
    selection = record_deletion_selection(target_dir, selected, receipt_id, now_dt)

    # Phase two: perform the approved actions and record the outcome.
    completed: list[Path] = []
    failed: list[Path] = []
    for entry in selected:
        try:
            entry.unlink(missing_ok=True)
            completed.append(entry)
        except OSError:
            failed.append(entry)

    record_deletion_completion(target_dir, selection, completed, failed, now_dt)

    purged_count = len(completed)
    if purged_count > 0:
        LOGGER.info("Purged %d stale job files", purged_count)

    return purged_count


purge_stale_job_files = sweep_job_files
