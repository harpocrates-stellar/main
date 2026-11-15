import errno
import logging
import os
import re
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

default_storage_dir = "/tmp/harpocrates_jobs"


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
    purged_count = 0

    for entry in list(target_dir.iterdir()):
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
                try:
                    entry.unlink(missing_ok=True)
                    purged_count += 1
                except OSError:
                    pass
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
                    try:
                        entry.unlink(missing_ok=True)
                        purged_count += 1
                        job["purged"] = True
                    except OSError:
                        pass
            # If status not in terminal_states (e.g., 'running' or 'pending'), do not remove.

    if purged_count > 0:
        LOGGER.info("Purged %d stale job files", purged_count)

    return purged_count


purge_stale_job_files = sweep_job_files


STORAGE_QUOTA_EXHAUSTED = "STORAGE_QUOTA_EXHAUSTED"
EVIDENCE_CORRUPTED = "EVIDENCE_CORRUPTED"
STORAGE_IO_UNAVAILABLE = "STORAGE_IO_UNAVAILABLE"

_WINDOWS_DISK_FULL_WINERRORS = frozenset({39, 112, 1816})


class EvidenceStorageOperationalError(RuntimeError):
    """Privacy-safe operational storage error carrying a stable reason code."""

    reason_code: str = STORAGE_IO_UNAVAILABLE
    retryable: bool = True
    quarantine_eligible: bool = False
    http_status: int = 503

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.reason_code)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": False,
            "reasonCode": self.reason_code,
            "retryable": self.retryable,
            "quarantined": False,
        }


class StorageQuotaExhaustedError(EvidenceStorageOperationalError):
    """Raised when disk free space or configured storage quota is exhausted."""

    reason_code = STORAGE_QUOTA_EXHAUSTED
    retryable = True
    quarantine_eligible = False
    http_status = 507


class EvidenceCorruptionError(EvidenceStorageOperationalError):
    """Raised when ciphertext authentication or canonical digest verification fails."""

    reason_code = EVIDENCE_CORRUPTED
    retryable = False
    quarantine_eligible = True
    http_status = 422


class StorageIOUnavailableError(EvidenceStorageOperationalError):
    """Raised on non-corruption, non-quota storage I/O failures."""

    reason_code = STORAGE_IO_UNAVAILABLE
    retryable = True
    quarantine_eligible = False
    http_status = 503


def is_quota_or_capacity_error(exc: BaseException) -> bool:
    """Return True when *exc* represents disk-full or storage quota exhaustion."""
    if isinstance(exc, StorageQuotaExhaustedError):
        return True
    if not isinstance(exc, OSError):
        return False
    quota_errnos = {errno.ENOSPC}
    edquot = getattr(errno, "EDQUOT", None)
    if edquot is not None:
        quota_errnos.add(edquot)
    if exc.errno in quota_errnos:
        return True
    winerror = getattr(exc, "winerror", None)
    if winerror in _WINDOWS_DISK_FULL_WINERRORS:
        return True
    return False


def classify_storage_exception(exc: BaseException) -> EvidenceStorageOperationalError:
    """Map low-level storage or crypto exceptions into stable operational reason codes."""
    if isinstance(exc, EvidenceStorageOperationalError):
        return exc
    if type(exc).__name__ == "InvalidToken":
        return EvidenceCorruptionError("evidence failed cryptographic authentication")
    if is_quota_or_capacity_error(exc):
        return StorageQuotaExhaustedError("storage capacity or quota exhausted")
    if isinstance(exc, OSError):
        return StorageIOUnavailableError("storage I/O unavailable")
    return StorageIOUnavailableError("unexpected storage operational failure")


def _positive_env_bytes(name: str) -> int | None:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return None
    try:
        parsed = int(raw.strip())
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if parsed <= 0:
        raise RuntimeError(f"{name} must be positive")
    return parsed


def directory_used_bytes(target_dir: Path) -> int:
    if not target_dir.exists():
        return 0
    total = 0
    for root, _dirs, files in os.walk(target_dir):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                continue
    return total


def check_storage_capacity(
    target_dir: Path | str,
    required_bytes: int,
    *,
    quota_bytes: int | None = None,
    min_free_bytes: int | None = None,
) -> None:
    """Verify configured quota and filesystem free capacity before writing bytes."""
    if required_bytes < 0:
        raise ValueError("required_bytes must be non-negative")
    directory = Path(target_dir)
    directory.mkdir(parents=True, exist_ok=True)

    effective_quota = (
        quota_bytes
        if quota_bytes is not None
        else _positive_env_bytes("HARPOCRATES_STORAGE_QUOTA_BYTES")
    )
    if effective_quota is not None:
        used = directory_used_bytes(directory)
        if used + required_bytes > effective_quota:
            raise StorageQuotaExhaustedError("configured storage byte quota exceeded")

    effective_min_free = (
        min_free_bytes
        if min_free_bytes is not None
        else (_positive_env_bytes("HARPOCRATES_STORAGE_MIN_FREE_BYTES") or 0)
    )
    try:
        usage = shutil.disk_usage(directory)
    except OSError as exc:
        raise classify_storage_exception(exc) from exc
    if usage.free < required_bytes + effective_min_free:
        raise StorageQuotaExhaustedError("insufficient filesystem free capacity")


def atomic_write_blob_bytes(
    target_path: Path | str,
    payload: bytes,
    *,
    quota_bytes: int | None = None,
    min_free_bytes: int | None = None,
) -> int:
    """Write blob bytes atomically while preserving existing files on quota exhaustion."""
    dest = Path(target_path)
    parent = dest.parent
    check_storage_capacity(
        parent,
        len(payload),
        quota_bytes=quota_bytes,
        min_free_bytes=min_free_bytes,
    )
    fd: int | None = None
    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=str(parent), prefix=".blob_", suffix=".tmp")
        handle = os.fdopen(fd, "wb")
        fd = None
        with handle:
            handle.write(payload)
            handle.flush()
        if os.name == "posix":
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
        os.replace(tmp_path, dest)
        tmp_path = None
        return len(payload)
    except BaseException as exc:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        if isinstance(exc, (OSError, EvidenceStorageOperationalError)):
            raise classify_storage_exception(exc) from exc
        raise
