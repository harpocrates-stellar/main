"""Bounded-chunk streaming upload helpers with concurrent SHA-256 hashing.

Trust boundary
--------------
Upload bytes cross the public HTTP boundary into temporary disk under a
hard size limit.  Hashing happens while bytes are copied so callers never
need a second full-file read.  Failure messages are stable and never echo
payload bytes, filenames beyond what Flask already accepted, or secrets.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator, Optional, Tuple, Union

from flask import g
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import RequestEntityTooLarge

# ---------------------------------------------------------------------------
# Bounded chunk sizing
# ---------------------------------------------------------------------------

DEFAULT_CHUNK_BYTES = 65_536  # 64 KiB
MIN_CHUNK_BYTES = 4_096  # 4 KiB
MAX_CHUNK_BYTES = 1_048_576  # 1 MiB


def clamp_chunk_bytes(value: int | None, *, enforce_min: bool = False) -> int:
    """Return a positive chunk size capped at ``MAX_CHUNK_BYTES``.

    When *enforce_min* is true (config/env path), values below ``MIN_CHUNK_BYTES``
    are raised to the minimum so operators cannot accidentally configure tiny
    reads. Explicit API callers may pass smaller sizes for tests.
    """
    if value is None:
        return DEFAULT_CHUNK_BYTES
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return DEFAULT_CHUNK_BYTES
    if parsed <= 0:
        return DEFAULT_CHUNK_BYTES
    if enforce_min and parsed < MIN_CHUNK_BYTES:
        return MIN_CHUNK_BYTES
    if parsed > MAX_CHUNK_BYTES:
        return MAX_CHUNK_BYTES
    return parsed


def _upload_config():
    try:
        return getattr(g, "upload_config", None)
    except RuntimeError:
        return None


def resolve_chunk_bytes(explicit: int | None = None) -> int:
    """Resolve chunk size from an explicit value, Flask ``g``, or the default."""
    if explicit is not None:
        return clamp_chunk_bytes(explicit, enforce_min=False)
    config = _upload_config()
    if config is not None:
        return clamp_chunk_bytes(
            getattr(config, "upload_chunk_bytes", None), enforce_min=True
        )
    return DEFAULT_CHUNK_BYTES


def resolve_max_bytes(explicit: int | None = None) -> int:
    """Resolve the hard upload size limit (0 = unlimited, not recommended)."""
    if explicit is not None:
        return max(0, int(explicit))
    config = _upload_config()
    if config is not None:
        for attr in ("upload_max_bytes", "max_video_bytes"):
            value = getattr(config, attr, None)
            if value is not None:
                return max(0, int(value))
    return 0


def resolve_temp_dir(explicit: str | Path | None = None) -> Optional[str]:
    if explicit is not None:
        return str(explicit)
    config = _upload_config()
    if config is not None:
        value = getattr(config, "upload_temp_dir", None)
        if value:
            return str(value)
    return None


def hash_stream_to_path(
    source: BinaryIO,
    destination: Union[str, Path],
    *,
    chunk_size: int | None = None,
    max_size: int | None = None,
    temp_dir: str | Path | None = None,
) -> Tuple[str, int]:
    """Copy *source* to *destination* in bounded chunks while hashing SHA-256.

    Returns ``(hex_digest, bytes_written)``.
    Raises ``RequestEntityTooLarge`` when *max_size* is exceeded mid-stream.
    Temporary files are cleaned up on failure; destination is not left partial
    unless an OS error occurs after the final rename.
    """
    bounded = resolve_chunk_bytes(chunk_size)
    limit = resolve_max_bytes(max_size)
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)

    hasher = hashlib.sha256()
    bytes_written = 0
    tmp_path: Optional[Path] = None

    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix="harpocrates-stream-",
            dir=resolve_temp_dir(temp_dir),
        )
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "wb") as tmp_file:
            while True:
                chunk = source.read(bounded)
                if not chunk:
                    break
                if limit > 0 and bytes_written + len(chunk) > limit:
                    raise RequestEntityTooLarge("Upload exceeds size limit")
                tmp_file.write(chunk)
                hasher.update(chunk)
                bytes_written += len(chunk)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())

        # Atomic-ish replace into the final destination.
        shutil.move(str(tmp_path), str(dest))
        tmp_path = None
        return hasher.hexdigest(), bytes_written
    except Exception:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        if dest.exists():
            # Do not leave a partial final artifact after a size abort.
            try:
                dest.unlink()
            except OSError:
                pass
        raise


def hash_paths_concat(
    paths: Iterable[Union[str, Path]],
    destination: Union[str, Path],
    *,
    chunk_size: int | None = None,
    max_size: int | None = None,
) -> Tuple[str, int]:
    """Concatenate *paths* into *destination* with bounded-chunk SHA-256 hashing."""
    bounded = resolve_chunk_bytes(chunk_size)
    limit = resolve_max_bytes(max_size)
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)

    hasher = hashlib.sha256()
    bytes_written = 0
    tmp_path: Optional[Path] = None

    try:
        fd, tmp_name = tempfile.mkstemp(prefix="harpocrates-concat-")
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "wb") as out:
            for path in paths:
                with Path(path).open("rb") as handle:
                    while True:
                        chunk = handle.read(bounded)
                        if not chunk:
                            break
                        if limit > 0 and bytes_written + len(chunk) > limit:
                            raise RequestEntityTooLarge("Upload exceeds size limit")
                        out.write(chunk)
                        hasher.update(chunk)
                        bytes_written += len(chunk)
            out.flush()
            os.fsync(out.fileno())
        shutil.move(str(tmp_path), str(dest))
        tmp_path = None
        return hasher.hexdigest(), bytes_written
    except Exception:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        if dest.exists():
            try:
                dest.unlink()
            except OSError:
                pass
        raise


def sha256_path_bounded(
    path: Union[str, Path],
    *,
    chunk_size: int | None = None,
) -> str:
    """SHA-256 a file using bounded chunk reads (no full-file buffering)."""
    bounded = resolve_chunk_bytes(chunk_size)
    hasher = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(bounded)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


class StreamingFileStorage(FileStorage):
    """FileStorage that streams to disk in bounded chunks while hashing."""

    def __init__(
        self,
        stream: BinaryIO,
        filename: Optional[str] = None,
        content_type: Optional[str] = None,
        max_size: int = 0,
        chunk_size: int | None = None,
        temp_dir: str | Path | None = None,
    ):
        super().__init__(stream, filename, content_type=content_type)
        self._max_size = max_size
        self._chunk_size = resolve_chunk_bytes(chunk_size)
        self._temp_dir = resolve_temp_dir(temp_dir)
        self._materialized_path: Optional[Path] = None
        self._bytes_written = 0
        self._hash_computed = False
        self._digest: Optional[str] = None

    @property
    def chunk_size(self) -> int:
        return self._chunk_size

    @property
    def bytes_written(self) -> int:
        return self._bytes_written

    @property
    def computed_hash(self) -> Optional[str]:
        """Hex SHA-256 digest once the stream has been fully consumed."""
        return self._digest if self._hash_computed else None

    
    def save(self, dst, buffer_size: int = 16384) -> None:  # noqa: ARG002
        """Stream the upload to *dst* with bounded chunks and concurrent hashing.

        ``buffer_size`` is accepted for FileStorage API compatibility but the
        configured bounded chunk size always wins.
        """
        destination = Path(dst)
        if self._hash_computed and self._materialized_path and self._materialized_path.exists():
            shutil.copyfile(self._materialized_path, destination)
            return

        digest, written = hash_stream_to_path(
            self.stream,
            destination,
            chunk_size=self._chunk_size,
            max_size=self._max_size,
            temp_dir=self._temp_dir,
        )
        self._bytes_written = written
        self._digest = digest
        self._hash_computed = True
        self._materialized_path = destination

    def close(self) -> None:
        try:
            super().close()
        finally:
            # Only remove temp artifacts we own (not caller destinations).
            pass


def create_streaming_file_storage(field_storage: FileStorage) -> StreamingFileStorage:
    """Wrap a Werkzeug ``FileStorage`` with bounded-chunk streaming hashing."""
    config = _upload_config()
    max_size = resolve_max_bytes(
        getattr(config, "upload_max_bytes", None)
        if config is not None
        else None
    )
    if max_size == 0 and config is not None:
        max_size = int(getattr(config, "max_video_bytes", 0) or 0)
    chunk_size = resolve_chunk_bytes(
        getattr(config, "upload_chunk_bytes", None) if config is not None else None
    )
    temp_dir = resolve_temp_dir(
        getattr(config, "upload_temp_dir", None) if config is not None else None
    )
    return StreamingFileStorage(
        stream=field_storage.stream,
        filename=field_storage.filename,
        content_type=field_storage.content_type,
        max_size=max_size,
        chunk_size=chunk_size,
        temp_dir=temp_dir,
    )


# ---------------------------------------------------------------------------
# Upload session expiry & operator retention preview
# ---------------------------------------------------------------------------

SESSION_DIR_PREFIX = "harpocrates-session-"
SESSION_META_FILENAME = ".session.json"
DEFAULT_UPLOAD_SESSION_TTL_SECONDS = 3_600.0
MIN_UPLOAD_SESSION_TTL_SECONDS = 60.0
MAX_UPLOAD_SESSION_TTL_SECONDS = 604_800.0
MAX_PREVIEW_EXPIRED_SESSIONS = 200
MAX_SESSION_SCAN_ENTRIES = 5_000

_PROCESS_ACTIVE_SESSIONS_LOCK = threading.Lock()
_PROCESS_ACTIVE_SESSIONS: dict[str, int] = {}


def _to_epoch_seconds(now: float | int | datetime | None = None) -> float:
    if now is None:
        return time.time()
    if isinstance(now, datetime):
        dt = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    return float(now)


def resolve_session_ttl_seconds(explicit: float | int | None = None) -> float:
    """Resolve upload-session TTL in seconds (`UPLOAD_SESSION_TTL_SECONDS`)."""
    if explicit is not None:
        val = float(explicit)
        if val <= 0:
            raise ValueError("ttl_seconds must be positive.")
        return val

    raw_env = os.getenv("UPLOAD_SESSION_TTL_SECONDS")
    if raw_env is not None and raw_env.strip():
        parsed = float(raw_env)
        if parsed <= 0:
            raise ValueError("UPLOAD_SESSION_TTL_SECONDS must be positive.")
        return max(
            MIN_UPLOAD_SESSION_TTL_SECONDS,
            min(parsed, MAX_UPLOAD_SESSION_TTL_SECONDS),
        )
    return DEFAULT_UPLOAD_SESSION_TTL_SECONDS


@contextmanager
def active_upload_session_worker(
    session_id: str,
    *,
    controller: Any = None,
) -> Iterator[None]:
    """Mark `session_id` referenced by an active worker so sweeps never delete its chunks."""
    with _PROCESS_ACTIVE_SESSIONS_LOCK:
        _PROCESS_ACTIVE_SESSIONS[session_id] = _PROCESS_ACTIVE_SESSIONS.get(session_id, 0) + 1
    if controller is not None and hasattr(controller, "acquire_session_worker"):
        controller.acquire_session_worker(session_id)
    try:
        yield
    finally:
        if controller is not None and hasattr(controller, "release_session_worker"):
            controller.release_session_worker(session_id)
        with _PROCESS_ACTIVE_SESSIONS_LOCK:
            remaining = _PROCESS_ACTIVE_SESSIONS.get(session_id, 0) - 1
            if remaining <= 0:
                _PROCESS_ACTIVE_SESSIONS.pop(session_id, None)
            else:
                _PROCESS_ACTIVE_SESSIONS[session_id] = remaining


def is_upload_session_active(session_id: str, *, controller: Any = None) -> bool:
    """Return True when any in-flight chunk writer or commit worker holds `session_id`."""
    with _PROCESS_ACTIVE_SESSIONS_LOCK:
        if _PROCESS_ACTIVE_SESSIONS.get(session_id, 0) > 0:
            return True
    if controller is not None and hasattr(controller, "is_session_active"):
        if controller.is_session_active(session_id):
            return True
    return False


def register_upload_session(
    session_id: str,
    session_dir: Union[str, Path],
    *,
    ttl_seconds: float | int | None = None,
    now: float | int | datetime | None = None,
) -> dict[str, Any]:
    """Write initial session expiry metadata inside `session_dir`."""
    now_ts = _to_epoch_seconds(now)
    ttl = resolve_session_ttl_seconds(ttl_seconds)
    directory = Path(session_dir)
    directory.mkdir(parents=True, exist_ok=True)
    meta = {
        "session_id": session_id,
        "created_at": now_ts,
        "updated_at": now_ts,
        "ttl_seconds": ttl,
        "expires_at": now_ts + ttl,
    }
    meta_path = directory / SESSION_META_FILENAME
    meta_path.write_text(json.dumps(meta, sort_keys=True), encoding="utf-8")
    return meta


def touch_upload_session(
    session_dir: Union[str, Path],
    *,
    ttl_seconds: float | int | None = None,
    now: float | int | datetime | None = None,
) -> dict[str, Any] | None:
    """Refresh `updated_at` / `expires_at` on an active upload session."""
    directory = Path(session_dir)
    if not directory.exists():
        return None
    now_ts = _to_epoch_seconds(now)
    meta_path = directory / SESSION_META_FILENAME
    meta: dict[str, Any] = {}
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            meta = {}
    ttl = resolve_session_ttl_seconds(
        ttl_seconds if ttl_seconds is not None else meta.get("ttl_seconds")
    )
    created_at = float(meta.get("created_at", now_ts))
    updated = {
        "session_id": str(meta.get("session_id") or directory.name.removeprefix(SESSION_DIR_PREFIX)),
        "created_at": created_at,
        "updated_at": now_ts,
        "ttl_seconds": ttl,
        "expires_at": now_ts + ttl,
    }
    meta_path.write_text(json.dumps(updated, sort_keys=True), encoding="utf-8")
    return updated


def is_upload_session_expired(
    session_dir: Union[str, Path],
    *,
    ttl_seconds: float | int | None = None,
    now: float | int | datetime | None = None,
    controller: Any = None,
) -> bool:
    """Return True when `session_dir` is past its TTL and has no active worker."""
    directory = Path(session_dir)
    if not directory.exists():
        return False
    session_id = directory.name.removeprefix(SESSION_DIR_PREFIX)
    if is_upload_session_active(session_id, controller=controller):
        return False

    now_ts = _to_epoch_seconds(now)
    meta_path = directory / SESSION_META_FILENAME
    last_updated: float | None = None
    effective_ttl: float | None = None
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if isinstance(meta, dict):
                if "updated_at" in meta:
                    last_updated = float(meta["updated_at"])
                if ttl_seconds is None and "ttl_seconds" in meta:
                    effective_ttl = float(meta["ttl_seconds"])
        except (OSError, ValueError, TypeError):
            last_updated = None

    ttl = resolve_session_ttl_seconds(ttl_seconds if ttl_seconds is not None else effective_ttl)
    if last_updated is None:
        last_updated = directory.stat().st_mtime
    return (now_ts - last_updated) >= ttl


def _inspect_session_directory(
    directory: Path,
    *,
    now_ts: float,
    default_ttl: float,
    override_ttl: bool,
    controller: Any,
) -> dict[str, Any]:
    session_id = directory.name.removeprefix(SESSION_DIR_PREFIX)
    meta_path = directory / SESSION_META_FILENAME
    last_updated: float | None = None
    session_ttl = default_ttl

    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if isinstance(meta, dict):
                if meta.get("session_id"):
                    session_id = str(meta["session_id"])
                if "updated_at" in meta:
                    last_updated = float(meta["updated_at"])
                if not override_ttl and "ttl_seconds" in meta:
                    session_ttl = float(meta["ttl_seconds"])
        except (OSError, ValueError, TypeError):
            last_updated = None

    chunk_count = 0
    total_bytes = 0
    newest_mtime = directory.stat().st_mtime
    for child in list(directory.iterdir()):
        if not child.is_file() or child.is_symlink():
            continue
        stat_res = child.stat()
        newest_mtime = max(newest_mtime, stat_res.st_mtime)
        if child.name != SESSION_META_FILENAME:
            total_bytes += int(stat_res.st_size)
        if child.name.startswith("chunk-"):
            chunk_count += 1

    if last_updated is None:
        last_updated = newest_mtime

    age_seconds = round(max(0.0, now_ts - last_updated), 3)
    active_worker = is_upload_session_active(session_id, controller=controller)
    past_ttl = age_seconds >= session_ttl

    return {
        "session_id": session_id,
        "age_seconds": age_seconds,
        "ttl_seconds": session_ttl,
        "chunk_count": chunk_count,
        "reclaimable_bytes": total_bytes,
        "past_ttl": past_ttl,
        "active_worker": active_worker,
        "eligible_for_cleanup": bool(past_ttl and not active_worker),
    }


def preview_expired_upload_sessions(
    *,
    base_dir: Union[str, Path, None] = None,
    ttl_seconds: float | int | None = None,
    now: float | int | datetime | None = None,
    controller: Any = None,
    max_sessions: int = 100,
) -> dict[str, Any]:
    """Return a read-only operator preview of expired upload sessions and reclaimable bytes."""
    if isinstance(max_sessions, bool) or not isinstance(max_sessions, int) or max_sessions < 1:
        raise ValueError("max_sessions must be a positive integer.")
    bounded_max = min(max_sessions, MAX_PREVIEW_EXPIRED_SESSIONS)
    default_ttl = resolve_session_ttl_seconds(ttl_seconds)
    now_ts = _to_epoch_seconds(now)
    root = Path(base_dir) if base_dir is not None else Path(resolve_temp_dir() or tempfile.gettempdir())

    expired_items: list[dict[str, Any]] = []
    reclaimable_bytes = 0
    protected_active_count = 0
    protected_active_bytes = 0
    within_ttl_count = 0
    scanned = 0
    scan_capped = False

    if root.exists() and root.is_dir():
        for entry in sorted(root.iterdir(), key=lambda p: p.name):
            if not entry.name.startswith(SESSION_DIR_PREFIX):
                continue
            if entry.is_symlink() or not entry.is_dir():
                continue
            if scanned >= MAX_SESSION_SCAN_ENTRIES:
                scan_capped = True
                break
            scanned += 1
            info = _inspect_session_directory(
                entry,
                now_ts=now_ts,
                default_ttl=default_ttl,
                override_ttl=(ttl_seconds is not None),
                controller=controller,
            )
            if info["active_worker"]:
                protected_active_count += 1
                protected_active_bytes += info["reclaimable_bytes"]
            elif info["eligible_for_cleanup"]:
                reclaimable_bytes += info["reclaimable_bytes"]
                expired_items.append(
                    {
                        "session_id": info["session_id"],
                        "age_seconds": info["age_seconds"],
                        "ttl_seconds": info["ttl_seconds"],
                        "chunk_count": info["chunk_count"],
                        "reclaimable_bytes": info["reclaimable_bytes"],
                    }
                )
            else:
                within_ttl_count += 1

    expired_items.sort(key=lambda item: (-item["age_seconds"], item["session_id"]))
    return {
        "evaluated_at": datetime.fromtimestamp(now_ts, tz=timezone.utc).isoformat(),
        "ttl_seconds": default_ttl,
        "counts": {
            "sessions_scanned": scanned,
            "expired_reclaimable": len(expired_items),
            "protected_by_active_workers": protected_active_count,
            "within_ttl": within_ttl_count,
        },
        "storage": {
            "reclaimable_bytes": reclaimable_bytes,
            "protected_active_bytes": protected_active_bytes,
            "unit": "bytes",
        },
        "expired_sessions": expired_items[:bounded_max],
        "truncated": len(expired_items) > bounded_max or scan_capped,
    }


def sweep_expired_upload_sessions(
    *,
    base_dir: Union[str, Path, None] = None,
    ttl_seconds: float | int | None = None,
    now: float | int | datetime | None = None,
    controller: Any = None,
    dry_run: bool = False,
    max_delete: int = 100,
) -> dict[str, Any]:
    """Delete expired upload sessions while strictly preserving active-worker chunks."""
    if isinstance(max_delete, bool) or not isinstance(max_delete, int) or max_delete < 1:
        raise ValueError("max_delete must be a positive integer.")
    preview = preview_expired_upload_sessions(
        base_dir=base_dir,
        ttl_seconds=ttl_seconds,
        now=now,
        controller=controller,
        max_sessions=min(max_delete, MAX_PREVIEW_EXPIRED_SESSIONS),
    )
    if dry_run:
        return {
            **preview,
            "dry_run": True,
            "deleted_sessions": 0,
            "reclaimed_bytes": 0,
        }

    root = Path(base_dir) if base_dir is not None else Path(resolve_temp_dir() or tempfile.gettempdir())
    deleted_sessions = 0
    reclaimed_bytes = 0
    skipped_newly_active = 0

    for item in preview["expired_sessions"][:max_delete]:
        session_id = item["session_id"]
        # Re-check worker lease immediately before touching any chunk file!
        if is_upload_session_active(session_id, controller=controller):
            skipped_newly_active += 1
            continue
        session_dir = root / f"{SESSION_DIR_PREFIX}{session_id}"
        if not session_dir.exists() or session_dir.is_symlink():
            continue
        try:
            shutil.rmtree(session_dir)
            deleted_sessions += 1
            reclaimed_bytes += int(item["reclaimable_bytes"])
        except OSError:
            continue

    return {
        **preview,
        "dry_run": False,
        "deleted_sessions": deleted_sessions,
        "reclaimed_bytes": reclaimed_bytes,
        "skipped_newly_active_workers": skipped_newly_active,
    }
