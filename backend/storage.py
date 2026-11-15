from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import stat
import tempfile
import threading
from typing import Any, Mapping

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


INTEGRITY_CURSOR_DOMAIN = "harpocrates:integrity-cursor:v1:"
INTEGRITY_AUDIT_REF_DOMAIN = "harpocrates:integrity-audit-ref:v1:"
INTEGRITY_VERIFY_BATCH_DEFAULT = 50
INTEGRITY_VERIFY_BATCH_MAX = 500


def compute_integrity_cursor_digest(identifier: str) -> str:
    """Compute a non-reversible cursor digest for resumable integrity checkpoints."""
    return hashlib.sha256(
        (INTEGRITY_CURSOR_DOMAIN + identifier.strip()).encode("utf-8")
    ).hexdigest()


def compute_integrity_audit_ref(identifier: str) -> str:
    """Compute a non-secret 32-byte hex audit reference for an inspected blob."""
    return hashlib.sha256(
        (INTEGRITY_AUDIT_REF_DOMAIN + identifier.strip()).encode("utf-8")
    ).hexdigest()


def clamp_integrity_batch_size(batch_size: object = None) -> int:
    """Validate and clamp integrity verification batch size into ``1..500``."""
    if batch_size is None:
        raw_env = os.getenv("EVIDENCE_INTEGRITY_BATCH_SIZE")
        if raw_env is None or not raw_env.strip():
            return INTEGRITY_VERIFY_BATCH_DEFAULT
        batch_size = raw_env.strip()
    if isinstance(batch_size, bool):
        raise ValueError("batch_size must be a positive integer")
    try:
        parsed = int(batch_size)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError("batch_size must be a positive integer") from exc
    if parsed < 1:
        raise ValueError("batch_size must be a positive integer")
    return min(parsed, INTEGRITY_VERIFY_BATCH_MAX)


@dataclass(frozen=True)
class IntegrityVerificationCheckpoint:
    """Non-secret resumable progress checkpoint for evidence integrity scans."""

    cursor_offset: int = 0
    cursor_digest: str | None = None
    scanned_count: int = 0
    verified_count: int = 0
    corrupted_count: int = 0
    unverifiable_legacy_count: int = 0
    completed: bool = False
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "cursorOffset": self.cursor_offset,
            "cursorDigest": self.cursor_digest,
            "scannedCount": self.scanned_count,
            "verifiedCount": self.verified_count,
            "corruptedCount": self.corrupted_count,
            "unverifiableLegacyCount": self.unverifiable_legacy_count,
            "completed": self.completed,
            "updatedAt": self.updated_at,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> IntegrityVerificationCheckpoint:
        cursor_offset = int(raw.get("cursorOffset", 0))
        if cursor_offset < 0:
            raise ValueError("cursorOffset must be non-negative")
        cursor_digest_raw = raw.get("cursorDigest")
        cursor_digest: str | None = None
        if cursor_digest_raw is not None:
            cleaned = str(cursor_digest_raw).strip().lower()
            if len(cleaned) != 64 or not all(c in "0123456789abcdef" for c in cleaned):
                raise ValueError("cursorDigest must be a 32-byte hex string")
            cursor_digest = cleaned
        return cls(
            cursor_offset=cursor_offset,
            cursor_digest=cursor_digest,
            scanned_count=max(0, int(raw.get("scannedCount", 0))),
            verified_count=max(0, int(raw.get("verifiedCount", 0))),
            corrupted_count=max(0, int(raw.get("corruptedCount", 0))),
            unverifiable_legacy_count=max(0, int(raw.get("unverifiableLegacyCount", 0))),
            completed=bool(raw.get("completed", False)),
            updated_at=str(raw.get("updatedAt") or ""),
        )


def _checkpoint_env_path(explicit_path: Path | str | None = None) -> Path | None:
    if explicit_path is not None:
        return Path(explicit_path)
    raw = os.getenv("EVIDENCE_INTEGRITY_CHECKPOINT_PATH")
    if raw and raw.strip():
        return Path(raw.strip())
    return None


class IntegrityCheckpointStore:
    """Thread-safe store persisting strictly non-secret integrity verification progress."""

    def __init__(self, *, checkpoint_path: Path | str | None = None) -> None:
        self._lock = threading.Lock()
        self._explicit_path = Path(checkpoint_path) if checkpoint_path is not None else None
        self._checkpoint: IntegrityVerificationCheckpoint | None = None
        self._loaded_path: Path | None = None

    def _effective_path(self) -> Path | None:
        return _checkpoint_env_path(self._explicit_path)

    def load(self) -> IntegrityVerificationCheckpoint:
        with self._lock:
            path = self._effective_path()
            if path is not None and self._loaded_path != path:
                self._loaded_path = path
                if path.exists():
                    raw = json.loads(path.read_text(encoding="utf-8"))
                    if not isinstance(raw, Mapping):
                        raise ValueError("invalid integrity checkpoint payload")
                    self._checkpoint = IntegrityVerificationCheckpoint.from_dict(raw)
            if self._checkpoint is None:
                self._checkpoint = IntegrityVerificationCheckpoint()
            return self._checkpoint

    def save(self, checkpoint: IntegrityVerificationCheckpoint) -> IntegrityVerificationCheckpoint:
        with self._lock:
            self._checkpoint = checkpoint
            path = self._effective_path()
            if path is not None:
                self._loaded_path = path
                path.parent.mkdir(parents=True, exist_ok=True)
                encoded = json.dumps(
                    checkpoint.to_dict(),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                fd: int | None = None
                tmp_name: str | None = None
                try:
                    fd, tmp_name = tempfile.mkstemp(
                        dir=str(path.parent), prefix=".integrity_ckpt_", suffix=".tmp"
                    )
                    handle = os.fdopen(fd, "wb")
                    fd = None
                    with handle:
                        handle.write(encoded)
                        handle.flush()
                    if os.name == "posix":
                        try:
                            os.chmod(tmp_name, 0o600)
                        except OSError:
                            pass
                    os.replace(tmp_name, path)
                    tmp_name = None
                except BaseException:
                    if fd is not None:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                    if tmp_name is not None:
                        try:
                            os.unlink(tmp_name)
                        except OSError:
                            pass
                    raise
            return checkpoint

    def reset(self) -> IntegrityVerificationCheckpoint:
        fresh = IntegrityVerificationCheckpoint(
            updated_at=datetime.now(timezone.utc).isoformat()
        )
        return self.save(fresh)


_DEFAULT_INTEGRITY_CHECKPOINT_STORE = IntegrityCheckpointStore()


def get_default_integrity_checkpoint_store() -> IntegrityCheckpointStore:
    return _DEFAULT_INTEGRITY_CHECKPOINT_STORE
