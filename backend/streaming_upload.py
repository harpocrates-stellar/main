"""Bounded-chunk streaming upload helpers with concurrent SHA-256 hashing.

Trust boundary
--------------
Upload bytes cross the public HTTP boundary into temporary disk under a
hard size limit.  Hashing happens while bytes are copied so callers never
need a second full-file read.  Failure messages are stable and never echo
payload bytes, filenames beyond what Flask already accepted, or secrets.
"""

from __future__ import annotations

import json
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Optional, Tuple, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import g
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import ClientDisconnected, RequestEntityTooLarge

UPLOAD_TERMINATED_PREMATURELY = "UPLOAD_TERMINATED_PREMATURELY"
_DISCONNECT_EXCEPTIONS = (ClientDisconnected, ConnectionError, EOFError)

# ---------------------------------------------------------------------------
# Bounded chunk sizing
# ---------------------------------------------------------------------------

DEFAULT_CHUNK_BYTES = 65_536  # 64 KiB
MIN_CHUNK_BYTES = 4_096  # 4 KiB
MAX_CHUNK_BYTES = 1_048_576  # 1 MiB


def _sanitize_progress_error(exc: Exception) -> str:
    """Return a stable, path-free error message for client progress responses."""
    if isinstance(exc, RequestEntityTooLarge):
        return "Upload exceeds size limit"
    return "Upload hashing failed"


class UploadHashingProgress:
    """Thread-safe bounded byte counter and completion state for upload hashing.

    This object intentionally excludes all server filesystem locations
    (temporary paths, destination paths, and raw OS error strings) so
    snapshots can be safely returned in client responses.
    """

    def __init__(self, max_bytes: int = 0) -> None:
        self._lock = threading.Lock()
        self._max_bytes = max(0, int(max_bytes))
        self._bytes_hashed = 0
        self._chunks_processed = 0
        self._completed = False
        self._failed = False
        self._digest: Optional[str] = None
        self._error: Optional[str] = None

    @property
    def bytes_hashed(self) -> int:
        with self._lock:
            return self._bytes_hashed

    @property
    def max_bytes(self) -> int:
        with self._lock:
            return self._max_bytes

    @property
    def chunks_processed(self) -> int:
        with self._lock:
            return self._chunks_processed

    @property
    def completed(self) -> bool:
        with self._lock:
            return self._completed

    @property
    def failed(self) -> bool:
        with self._lock:
            return self._failed

    @property
    def digest(self) -> Optional[str]:
        with self._lock:
            return self._digest

    @property
    def error(self) -> Optional[str]:
        with self._lock:
            return self._error

    def record_chunk(self, chunk_bytes: int) -> Dict[str, Any]:
        """Record a hashed chunk, clamping ``bytes_hashed`` to ``max_bytes`` if set."""
        with self._lock:
            next_bytes = self._bytes_hashed + max(0, int(chunk_bytes))
            if self._max_bytes > 0 and next_bytes > self._max_bytes:
                next_bytes = self._max_bytes
            self._bytes_hashed = next_bytes
            self._chunks_processed += 1
            return self._snapshot_locked()

    def mark_completed(self, digest: str) -> Dict[str, Any]:
        """Mark hashing as completed with the final hex digest."""
        with self._lock:
            self._completed = True
            self._failed = False
            self._digest = digest
            self._error = None
            return self._snapshot_locked()

    def mark_failed(self, exc: Exception) -> Dict[str, Any]:
        """Mark hashing as failed with a sanitized, path-free error message."""
        with self._lock:
            self._completed = False
            self._failed = True
            self._digest = None
            self._error = _sanitize_progress_error(exc)
            return self._snapshot_locked()

    def _snapshot_locked(self) -> Dict[str, Any]:
        return {
            "bytes_hashed": self._bytes_hashed,
            "max_bytes": self._max_bytes,
            "chunks_processed": self._chunks_processed,
            "completed": self._completed,
            "failed": self._failed,
            "digest": self._digest,
            "error": self._error,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable snapshot without any filesystem paths."""
        with self._lock:
            return self._snapshot_locked()


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


def resolve_max_bytes(explicit: int | None = None) -> int | None:
    """Resolve the hard upload size limit in bytes (None = unlimited)."""
    if explicit is not None:
        return max(0, int(explicit))
    config = _upload_config()
    if config is not None:
        for attr in ("upload_max_bytes", "max_video_bytes"):
            value = getattr(config, attr, None)
            if value is not None:
                return max(0, int(value))
    return None


def resolve_temp_dir(explicit: str | Path | None = None) -> Optional[str]:
    if explicit is not None:
        return str(explicit)
    config = _upload_config()
    if config is not None:
        value = getattr(config, "upload_temp_dir", None)
        if value:
            return str(value)
    return None


class UploadState(str, Enum):
    QUEUED = "queued"
    RECEIVING = "receiving"
    COMMITTING = "committing"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    FAILED = "failed"


class UploadCancelledError(RuntimeError):
    def __init__(self, message: str = "Upload cancelled"):
        super().__init__(message)
        self.code = "UPLOAD_CANCELLED"
        self.status_code = 409


@dataclass
class UploadSession:
    id: str
    session_dir: Path
    state: UploadState = UploadState.QUEUED
    cancel_event: threading.Event = field(default_factory=threading.Event)
    admission_ticket_id: Optional[str] = None
    queued_admission_ticket_id: Optional[str] = None
    cleanup_done: bool = False
    _active_writers: int = field(default=0, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    @property
    def active_writers(self) -> int:
        with self._lock:
            return self._active_writers

    def attach_admission(self, ticket_id: Optional[str]) -> None:
        with self._lock:
            self.admission_ticket_id = ticket_id

    def attach_queued_admission(self, ticket_id: Optional[str]) -> None:
        with self._lock:
            self.queued_admission_ticket_id = ticket_id
            self.admission_ticket_id = ticket_id

    def mark_receiving(self) -> None:
        with self._lock:
            if self.state is UploadState.QUEUED:
                self.state = UploadState.RECEIVING

    def mark_committing(self) -> None:
        with self._lock:
            if self.state in (UploadState.QUEUED, UploadState.RECEIVING):
                self.state = UploadState.COMMITTING

    def complete(self) -> None:
        with self._lock:
            self.state = UploadState.COMPLETED

    def fail(self) -> None:
        with self._lock:
            if self.state is not UploadState.CANCELLED:
                self.state = UploadState.FAILED

    @contextmanager
    def writer(self) -> Iterator["UploadSession"]:
        self.check_cancelled()
        with self._lock:
            if self.state is UploadState.CANCELLED:
                raise UploadCancelledError()
            self._active_writers += 1
            self.mark_receiving()
        try:
            yield self
        finally:
            cleanup = False
            with self._lock:
                self._active_writers -= 1
                if self._active_writers == 0 and self.state is UploadState.CANCELLED:
                    cleanup = True
            if cleanup:
                self._cleanup()

    def cancel(self) -> bool:
        cleanup = False
        with self._lock:
            if self.state not in (
                UploadState.QUEUED,
                UploadState.RECEIVING,
                UploadState.COMMITTING,
            ):
                return False
            self.state = UploadState.CANCELLED
            self.cancel_event.set()
            cleanup = self._active_writers == 0
        if cleanup:
            self._cleanup()
        return True

    def check_cancelled(self) -> None:
        if self.cancel_event.is_set() or self.state is UploadState.CANCELLED:
            raise UploadCancelledError()

    def _cleanup(self) -> None:
        with self._lock:
            if self.cleanup_done:
                return
            self.cleanup_done = True
        shutil.rmtree(self.session_dir, ignore_errors=True)


class UploadSessionRegistry:
    def __init__(self) -> None:
        self._sessions: dict[str, UploadSession] = {}
        self._lock = threading.Lock()

    def create(self, session_id: str, session_dir: Union[str, Path]) -> UploadSession:
        session = UploadSession(id=session_id, session_dir=Path(session_dir))
        with self._lock:
            self._sessions[session_id] = session
        return session

    def get(self, session_id: str) -> Optional[UploadSession]:
        with self._lock:
            return self._sessions.get(session_id)

    def cancel(self, session_id: str, admission_controller=None) -> Optional[bool]:
        session = self.get(session_id)
        if session is None:
            return None
        cancelled = session.cancel()
        if cancelled and admission_controller is not None:
            ticket_ids = [
                session.admission_ticket_id,
                session.queued_admission_ticket_id,
            ]
            for ticket_id in dict.fromkeys(ticket_ids):
                if ticket_id is None:
                    continue
                ticket = admission_controller.get_ticket(ticket_id)
                admission_controller.cancel(ticket_id)
                if ticket is not None and ticket.queued:
                    admission_controller.release_ticket(ticket_id)
        return cancelled

    def remove(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)


def hash_stream_to_path(
    source: BinaryIO,
    destination: Union[str, Path],
    *,
    chunk_size: int | None = None,
    max_size: int | None = None,
    temp_dir: str | Path | None = None,
    cancellation: UploadSession | None = None,
) -> Tuple[str, int]:
    """Copy *source* to *destination* in bounded chunks while hashing SHA-256.

    Returns ``(hex_digest, bytes_written)``.
    Raises ``RequestEntityTooLarge`` when *max_size* is exceeded mid-stream.
    Temporary files are cleaned up on failure; destination is not left partial
    unless an OS error occurs after the final rename.
    """
    bounded = resolve_chunk_bytes(chunk_size)
    limit = resolve_max_bytes(max_size)
    expected = max(0, int(expected_size)) if expected_size is not None else None
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tracker = progress or (
        UploadHashingProgress(max_bytes=limit) if progress_callback is not None else None
    )

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
                if cancellation is not None:
                    cancellation.check_cancelled()
                chunk = source.read(bounded)
                if not chunk:
                    break
                if limit is not None and bytes_written + len(chunk) > limit:
                    raise RequestEntityTooLarge("Upload exceeds size limit")
                tmp_file.write(chunk)
                hasher.update(chunk)
                bytes_written += len(chunk)
            if expected is not None and bytes_written < expected:
                raise PrematureUploadTerminationError(
                    bytes_received=bytes_written,
                    expected_bytes=expected,
                )
            tmp_file.flush()
            os.fsync(tmp_file.fileno())

        # Atomic-ish replace into the final destination.
        shutil.move(str(tmp_path), str(dest))
        tmp_path = None
        digest = hasher.hexdigest()
        if tracker is not None:
            snapshot = tracker.mark_completed(digest)
            if progress_callback is not None:
                progress_callback(snapshot)
        return digest, bytes_written
    except Exception as exc:
        if tracker is not None:
            snapshot = tracker.mark_failed(exc)
            if progress_callback is not None:
                progress_callback(snapshot)
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
    cancellation: UploadSession | None = None,
) -> Tuple[str, int]:
    """Concatenate *paths* into *destination* with bounded-chunk SHA-256 hashing."""
    bounded = resolve_chunk_bytes(chunk_size)
    limit = resolve_max_bytes(max_size)
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tracker = progress or (
        UploadHashingProgress(max_bytes=limit) if progress_callback is not None else None
    )

    hasher = hashlib.sha256()
    bytes_written = 0
    tmp_path: Optional[Path] = None

    try:
        fd, tmp_name = tempfile.mkstemp(prefix="harpocrates-concat-")
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "wb") as out:
            for path in paths:
                if cancellation is not None:
                    cancellation.check_cancelled()
                with Path(path).open("rb") as handle:
                    while True:
                        if cancellation is not None:
                            cancellation.check_cancelled()
                        chunk = handle.read(bounded)
                        if not chunk:
                            break
                        if limit is not None and bytes_written + len(chunk) > limit:
                            raise RequestEntityTooLarge("Upload exceeds size limit")
                        out.write(chunk)
                        hasher.update(chunk)
                        bytes_written += len(chunk)
                        if tracker is not None:
                            snapshot = tracker.record_chunk(len(chunk))
                            if progress_callback is not None:
                                progress_callback(snapshot)
            out.flush()
            os.fsync(out.fileno())
        shutil.move(str(tmp_path), str(dest))
        tmp_path = None
        digest = hasher.hexdigest()
        if tracker is not None:
            snapshot = tracker.mark_completed(digest)
            if progress_callback is not None:
                progress_callback(snapshot)
        return digest, bytes_written
    except Exception as exc:
        if tracker is not None:
            snapshot = tracker.mark_failed(exc)
            if progress_callback is not None:
                progress_callback(snapshot)
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
        max_size: int | None = None,
        chunk_size: int | None = None,
        temp_dir: str | Path | None = None,
        cancellation: UploadSession | None = None,
    ):
        super().__init__(stream, filename, content_type=content_type)
        self._max_size = max_size
        self._chunk_size = resolve_chunk_bytes(chunk_size)
        self._temp_dir = resolve_temp_dir(temp_dir)
        self._expected_size = expected_size
        self._materialized_path: Optional[Path] = None
        self._cancellation = cancellation
        self._bytes_written = 0
        self._hash_computed = False
        self._digest: Optional[str] = None
        self._progress = UploadHashingProgress(max_bytes=max_size)

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

    @property
    def progress(self) -> UploadHashingProgress:
        """Bounded upload hashing progress tracker (path-free)."""
        return self._progress

    def progress_snapshot(self) -> Dict[str, Any]:
        """Return a JSON-serializable progress snapshot without filesystem paths."""
        return self._progress.to_dict()

    
    def save(
        self,
        dst,
        buffer_size: int = 16384,  # noqa: ARG002
        *,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
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
            cancellation=self._cancellation,
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


def create_streaming_file_storage(
    field_storage: FileStorage,
    cancellation: UploadSession | None = None,
) -> StreamingFileStorage:
    """Wrap a Werkzeug ``FileStorage`` with bounded-chunk streaming hashing."""
    config = _upload_config()
    max_size = resolve_max_bytes()
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
        cancellation=cancellation,
    )


# ---------------------------------------------------------------------------
# Upload session lifecycle & operator retention preview
# ---------------------------------------------------------------------------

SESSION_PREFIX = "harpocrates-session-"
DEFAULT_SESSION_TTL_SECONDS = 3600  # 1 hour
DEFAULT_RETENTION_PREVIEW_LIMIT = 500  # bounded scan ceiling


@dataclass(frozen=True)
class SessionRetentionPreview:
    """Operator preview of expired upload sessions and bounded reclaimable storage."""

    expired_sessions: list[dict[str, Any]]
    expired_count: int
    reclaimable_bytes: int
    active_skipped_count: int
    active_skipped_bytes: int
    total_scanned: int
    ttl_seconds: float
    limit: int


def resolve_session_ttl(explicit: int | float | None = None) -> float:
    """Resolve upload session TTL in seconds from explicit, Flask g, config, or default."""
    if explicit is not None:
        try:
            val = float(explicit)
            if val >= 0:
                return val
        except (TypeError, ValueError):
            pass
    config = _upload_config()
    if config is not None:
        val = getattr(config, "upload_session_ttl_seconds", None)
        if val is not None:
            try:
                parsed = float(val)
                if parsed >= 0:
                    return parsed
            except (TypeError, ValueError):
                pass
    try:
        from config import load_config

        cfg = load_config()
        val = getattr(cfg, "upload_session_ttl_seconds", None)
        if val is not None:
            return max(0.0, float(val))
    except Exception:
        pass
    raw = os.getenv("UPLOAD_SESSION_TTL_SECONDS") or os.getenv("HARPOCRATES_UPLOAD_SESSION_TTL_SECONDS")
    if raw is not None:
        try:
            parsed = float(raw)
            if parsed >= 0:
                return parsed
        except (TypeError, ValueError):
            pass
    return float(DEFAULT_SESSION_TTL_SECONDS)


def get_session_dir(
    session_id: str,
    temp_dir: str | Path | None = None,
) -> Path:
    """Return the filesystem directory path for an upload session."""
    base = resolve_temp_dir(temp_dir) or tempfile.gettempdir()
    return Path(base) / f"{SESSION_PREFIX}{session_id}"


def init_session_dir(
    session_id: str,
    temp_dir: str | Path | None = None,
) -> Path:
    """Create a session directory and record creation metadata."""
    session_dir = get_session_dir(session_id, temp_dir=temp_dir)
    session_dir.mkdir(parents=True, exist_ok=True)
    meta_path = session_dir / ".session_meta"
    now_ts = time.time()
    if not meta_path.exists():
        try:
            meta_path.write_text(
                json.dumps({
                    "session_id": session_id,
                    "created_at": now_ts,
                    "updated_at": now_ts,
                }),
                encoding="utf-8",
            )
        except OSError:
            pass
    return session_dir


def touch_session(session_dir: Path | str) -> None:
    """Update session activity timestamp on chunk upload or touch."""
    s_dir = Path(session_dir)
    meta_path = s_dir / ".session_meta"
    now_ts = time.time()
    try:
        if meta_path.exists():
            data = json.loads(meta_path.read_text(encoding="utf-8"))
            data["updated_at"] = now_ts
            meta_path.write_text(json.dumps(data), encoding="utf-8")
        else:
            session_id = s_dir.name
            if session_id.startswith(SESSION_PREFIX):
                session_id = session_id[len(SESSION_PREFIX):]
            meta_path.write_text(
                json.dumps({
                    "session_id": session_id,
                    "created_at": now_ts,
                    "updated_at": now_ts,
                }),
                encoding="utf-8",
            )
        os.utime(str(s_dir), (now_ts, now_ts))
    except (OSError, json.JSONDecodeError):
        pass


def get_session_info(
    session_dir: Path | str,
    now: float | None = None,
) -> dict[str, Any]:
    """Inspect an upload session directory and compute its age, chunk count, and bytes.

    Bounded calculation: sums file stat sizes without buffering file contents.
    """
    s_dir = Path(session_dir)
    if now is None:
        now = time.time()
    session_id = s_dir.name
    if session_id.startswith(SESSION_PREFIX):
        session_id = session_id[len(SESSION_PREFIX):]

    meta_path = s_dir / ".session_meta"
    created_at: float | None = None
    updated_at: float | None = None
    if meta_path.exists():
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
            created_at = float(data.get("created_at", 0))
            updated_at = float(data.get("updated_at", created_at))
        except Exception:
            pass

    try:
        stat = s_dir.stat()
        file_ts = stat.st_mtime
        if created_at is None or created_at <= 0:
            created_at = min(file_ts, stat.st_ctime) if stat.st_ctime > 0 else file_ts
        if updated_at is None or updated_at <= 0:
            updated_at = file_ts
    except OSError:
        if created_at is None:
            created_at = now
        if updated_at is None:
            updated_at = now

    chunk_count = 0
    reclaimable_bytes = 0
    try:
        for entry in s_dir.iterdir():
            try:
                if entry.is_file():
                    reclaimable_bytes += entry.stat().st_size
                    if entry.name.startswith("chunk-"):
                        chunk_count += 1
            except OSError:
                pass
    except OSError:
        pass

    age_seconds = max(0.0, now - created_at)
    idle_seconds = max(0.0, now - updated_at)

    return {
        "session_id": session_id,
        "path": str(s_dir),
        "created_at": created_at,
        "updated_at": updated_at,
        "age_seconds": round(age_seconds, 2),
        "idle_seconds": round(idle_seconds, 2),
        "chunk_count": chunk_count,
        "reclaimable_bytes": reclaimable_bytes,
    }


def is_session_expired(
    session_dir: Path | str,
    ttl_seconds: float | None = None,
    now: float | None = None,
) -> bool:
    """Return whether an upload session has exceeded its TTL."""
    ttl = resolve_session_ttl(ttl_seconds)
    if ttl <= 0:
        return False
    info = get_session_info(session_dir, now=now)
    return info["age_seconds"] >= ttl


def _extract_active_sessions(
    active_sessions: Iterable[str] | Any | None,
) -> set[str]:
    """Extract set of active session IDs from an AdmissionController, set, or iterable."""
    if active_sessions is None:
        return set()
    if hasattr(active_sessions, "get_active_sessions"):
        return active_sessions.get_active_sessions()
    if isinstance(active_sessions, (set, list, tuple)):
        return set(active_sessions)
    return set()


def preview_upload_session_retention(
    *,
    temp_dir: str | Path | None = None,
    ttl_seconds: int | float | None = None,
    now: datetime | float | None = None,
    active_sessions: Iterable[str] | Any | None = None,
    limit: int | None = DEFAULT_RETENTION_PREVIEW_LIMIT,
) -> SessionRetentionPreview:
    """List expired sessions and bounded reclaimable storage.

    Avoids deleting or marking chunks referenced by active workers as reclaimable.
    Scans are bounded by *limit* to prevent unbounded memory allocation.
    """
    if now is None:
        now_ts = time.time()
    elif hasattr(now, "timestamp"):
        now_ts = now.timestamp()
    else:
        now_ts = float(now)

    ttl = resolve_session_ttl(ttl_seconds)
    clamped_limit = max(1, min(limit or DEFAULT_RETENTION_PREVIEW_LIMIT, 5000))
    active_set = _extract_active_sessions(active_sessions)

    base = Path(resolve_temp_dir(temp_dir) or tempfile.gettempdir())
    expired_sessions: list[dict[str, Any]] = []
    reclaimable_bytes = 0
    active_skipped_count = 0
    active_skipped_bytes = 0
    total_scanned = 0

    if base.exists():
        session_dirs = []
        try:
            for entry in base.iterdir():
                if entry.is_dir() and entry.name.startswith(SESSION_PREFIX):
                    session_dirs.append(entry)
        except OSError:
            pass

        # Sort by directory name for deterministic evaluation
        session_dirs.sort(key=lambda d: d.name)

        for s_dir in session_dirs:
            if total_scanned >= clamped_limit:
                break
            total_scanned += 1

            info = get_session_info(s_dir, now=now_ts)
            session_id = info["session_id"]
            is_expired = (ttl > 0 and info["age_seconds"] >= ttl)

            if is_expired:
                # Avoid deleting chunks referenced by active workers
                if session_id in active_set:
                    active_skipped_count += 1
                    active_skipped_bytes += info["reclaimable_bytes"]
                else:
                    expired_sessions.append(info)
                    reclaimable_bytes += info["reclaimable_bytes"]

    return SessionRetentionPreview(
        expired_sessions=expired_sessions,
        expired_count=len(expired_sessions),
        reclaimable_bytes=reclaimable_bytes,
        active_skipped_count=active_skipped_count,
        active_skipped_bytes=active_skipped_bytes,
        total_scanned=total_scanned,
        ttl_seconds=ttl,
        limit=clamped_limit,
    )


def purge_expired_upload_sessions(
    *,
    temp_dir: str | Path | None = None,
    ttl_seconds: int | float | None = None,
    now: datetime | float | None = None,
    active_sessions: Iterable[str] | Any | None = None,
    limit: int | None = DEFAULT_RETENTION_PREVIEW_LIMIT,
    dry_run: bool = False,
) -> tuple[int, int, int]:
    """Purge expired upload sessions and return (purged_count, reclaimed_bytes, active_skipped_count).

    Chunks referenced by active workers are NEVER deleted.
    """
    preview = preview_upload_session_retention(
        temp_dir=temp_dir,
        ttl_seconds=ttl_seconds,
        now=now,
        active_sessions=active_sessions,
        limit=limit,
    )

    if dry_run:
        return preview.expired_count, preview.reclaimable_bytes, preview.active_skipped_count

    purged_count = 0
    reclaimed_bytes = 0

    for sess in preview.expired_sessions:
        session_id = sess["session_id"]
        # Double check if session became active concurrently before deleting
        if active_sessions is not None:
            if hasattr(active_sessions, "is_session_active") and active_sessions.is_session_active(session_id):
                continue
            if isinstance(active_sessions, (set, list, tuple)) and session_id in active_sessions:
                continue

        s_path = Path(sess["path"])
        try:
            shutil.rmtree(s_path, ignore_errors=True)
            purged_count += 1
            reclaimed_bytes += sess["reclaimable_bytes"]
        except OSError:
            pass

    return purged_count, reclaimed_bytes, preview.active_skipped_count
