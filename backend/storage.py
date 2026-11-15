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
ENVELOPE_METADATA_SCHEMA = "hpx-evidence-envelope/1"
ENVELOPE_SIDECAR_SUFFIX = ".envelope.json"
_CONTENT_HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")


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


def get_envelope_metadata_path(artifact_path: Path | str) -> Path:
    """Return the sidecar metadata path associated with an encrypted artifact."""
    base = Path(artifact_path)
    return base.with_name(f"{base.name}{ENVELOPE_SIDECAR_SUFFIX}")


def write_envelope_metadata(
    artifact_path: Path | str,
    *,
    envelope_version: str,
    content_hash: str | None = None,
    size_bytes: int | None = None,
) -> Path:
    """Persist privacy-safe encryption envelope version metadata next to an artifact."""
    from evidence_storage import (
        LEGACY_ENVELOPE_VERSION,
        SUPPORTED_ENVELOPE_VERSIONS,
        UnsupportedEnvelopeError,
    )

    if not isinstance(envelope_version, str) or envelope_version not in SUPPORTED_ENVELOPE_VERSIONS:
        raise UnsupportedEnvelopeError(
            f"Unsupported encryption envelope version: {envelope_version}"
        )
    if content_hash is not None and not _CONTENT_HASH_RE.fullmatch(content_hash):
        raise ValueError("content_hash must be a 64-character hex SHA-256 digest.")
    if size_bytes is not None and (not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes < 0):
        raise ValueError("size_bytes must be a non-negative integer.")

    record: dict[str, Any] = {
        "schema": ENVELOPE_METADATA_SCHEMA,
        "envelope_version": envelope_version,
        "is_legacy_envelope": envelope_version == LEGACY_ENVELOPE_VERSION,
    }
    if content_hash is not None:
        record["content_hash"] = content_hash.lower()
    if size_bytes is not None:
        record["size_bytes"] = size_bytes

    sidecar_path = get_envelope_metadata_path(artifact_path)
    sidecar_path.parent.mkdir(parents=True, exist_ok=True)
    sidecar_path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    return sidecar_path


def read_envelope_metadata(artifact_path: Path | str) -> dict[str, Any] | None:
    """Read and fail-closed validate persisted envelope metadata for an artifact."""
    from evidence_storage import (
        LEGACY_ENVELOPE_VERSION,
        MalformedEnvelopeError,
        SUPPORTED_ENVELOPE_VERSIONS,
        UnsupportedEnvelopeError,
    )

    sidecar_path = get_envelope_metadata_path(artifact_path)
    if not sidecar_path.exists():
        return None

    try:
        payload = json.loads(sidecar_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise MalformedEnvelopeError("Malformed stored envelope metadata JSON.") from exc

    if not isinstance(payload, dict) or payload.get("schema") != ENVELOPE_METADATA_SCHEMA:
        raise MalformedEnvelopeError("Invalid stored envelope metadata schema.")

    version = payload.get("envelope_version")
    if not isinstance(version, str):
        raise MalformedEnvelopeError("Missing envelope_version in stored metadata.")
    if version not in SUPPORTED_ENVELOPE_VERSIONS:
        raise UnsupportedEnvelopeError(
            f"Unsupported encryption envelope version: {version}"
        )

    result: dict[str, Any] = {
        "schema": ENVELOPE_METADATA_SCHEMA,
        "envelope_version": version,
        "is_legacy_envelope": version == LEGACY_ENVELOPE_VERSION,
    }
    if "content_hash" in payload:
        content_hash = payload["content_hash"]
        if not isinstance(content_hash, str) or not _CONTENT_HASH_RE.fullmatch(content_hash):
            raise MalformedEnvelopeError("Invalid content_hash in stored envelope metadata.")
        result["content_hash"] = content_hash.lower()
    if "size_bytes" in payload:
        size_bytes = payload["size_bytes"]
        if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes < 0:
            raise MalformedEnvelopeError("Invalid size_bytes in stored envelope metadata.")
        result["size_bytes"] = size_bytes

    return result


purge_stale_job_files = sweep_job_files
