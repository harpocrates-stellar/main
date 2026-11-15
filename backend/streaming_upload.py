"""Bounded-chunk streaming upload helpers with concurrent SHA-256 hashing.

Trust boundary
--------------
Upload bytes cross the public HTTP boundary into temporary disk under a
hard size limit.  Hashing happens while bytes are copied so callers never
need a second full-file read.  Failure messages are stable and never echo
payload bytes, filenames beyond what Flask already accepted, or secrets.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import os
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Any, BinaryIO, Callable, Dict, Iterable, Optional, Tuple, Union

from flask import g
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import RequestEntityTooLarge

# ---------------------------------------------------------------------------
# Bounded chunk sizing
# ---------------------------------------------------------------------------

DEFAULT_CHUNK_BYTES = 65_536  # 64 KiB
MIN_CHUNK_BYTES = 4_096  # 4 KiB
MAX_CHUNK_BYTES = 1_048_576  # 1 MiB
MAX_PROGRESS_SESSIONS = 1_024
MAX_PROGRESS_COUNTER_BYTES = 1_099_511_627_776  # 1 TiB hard counter ceiling

PROGRESS_STATE_PENDING = "pending"
PROGRESS_STATE_HASHING = "hashing"
PROGRESS_STATE_COMPLETED = "completed"
PROGRESS_STATE_FAILED = "failed"


def _clamp_counter(value: int | None, *, ceiling: int = MAX_PROGRESS_COUNTER_BYTES) -> int:
    if value is None:
        return 0
    parsed = int(value)
    if parsed < 0:
        return 0
    bound = max(0, int(ceiling)) if ceiling is not None else MAX_PROGRESS_COUNTER_BYTES
    return min(parsed, bound)


@dataclass(frozen=True)
class UploadProgressSnapshot:
    """Privacy-safe upload hashing progress snapshot (never carries filesystem paths)."""

    session_id: str
    state: str
    bytes_hashed: int
    expected_bytes: Optional[int]
    chunks_hashed: int
    completed: bool

    def to_public_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "ok": True,
            "sessionId": self.session_id,
            "state": self.state,
            "bytesHashed": self.bytes_hashed,
            "chunksHashed": self.chunks_hashed,
            "completed": self.completed,
        }
        if self.expected_bytes is not None:
            payload["expectedBytes"] = self.expected_bytes
        else:
            payload["expectedBytes"] = None
        return payload


class UploadProgressTracker:
    """Bounded thread-safe tracker of per-session upload hashing counters."""

    def __init__(
        self,
        *,
        max_sessions: int = MAX_PROGRESS_SESSIONS,
        max_counter_bytes: int = MAX_PROGRESS_COUNTER_BYTES,
    ) -> None:
        self.max_sessions = max(1, int(max_sessions))
        self.max_counter_bytes = max(1, int(max_counter_bytes))
        self._lock = threading.Lock()
        self._entries: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()

    def _ensure_entry_unlocked(
        self,
        session_id: str,
        *,
        expected_bytes: Optional[int] = None,
    ) -> Dict[str, Any]:
        entry = self._entries.get(session_id)
        if entry is not None:
            self._entries.move_to_end(session_id)
            if expected_bytes is not None and entry["expected_bytes"] is None:
                entry["expected_bytes"] = _clamp_counter(
                    expected_bytes, ceiling=self.max_counter_bytes
                )
            return entry

        while len(self._entries) >= self.max_sessions:
            self._entries.popitem(last=False)

        clamped_expected = (
            _clamp_counter(expected_bytes, ceiling=self.max_counter_bytes)
            if expected_bytes is not None
            else None
        )
        entry = {
            "session_id": session_id,
            "state": PROGRESS_STATE_PENDING,
            "committed_bytes": 0,
            "in_flight_bytes": 0,
            "expected_bytes": clamped_expected,
            "chunks_hashed": 0,
            "completed": False,
        }
        self._entries[session_id] = entry
        return entry

    def start_session(
        self,
        session_id: str,
        *,
        expected_bytes: Optional[int] = None,
    ) -> UploadProgressSnapshot:
        with self._lock:
            entry = self._ensure_entry_unlocked(
                session_id,
                expected_bytes=expected_bytes,
            )
            return self._snapshot_unlocked(entry)

    def make_stream_reporter(
        self,
        session_id: str,
        *,
        ceiling_bytes: Optional[int] = None,
        reset_base: bool = False,
        finalize_session: bool = False,
    ) -> Callable[[int, str], None]:
        """Return a callback ``(stream_bytes_hashed, phase)`` for bounded stream updates."""
        bound = (
            min(self.max_counter_bytes, max(0, int(ceiling_bytes)))
            if ceiling_bytes and ceiling_bytes > 0
            else self.max_counter_bytes
        )

        def _report(stream_bytes: int, phase: str) -> None:
            clamped_stream = _clamp_counter(stream_bytes, ceiling=bound)
            with self._lock:
                entry = self._ensure_entry_unlocked(session_id)
                if reset_base and phase == "start":
                    entry["committed_bytes"] = 0
                if phase in ("start", "chunk"):
                    entry["state"] = PROGRESS_STATE_HASHING
                    entry["completed"] = False
                    entry["in_flight_bytes"] = clamped_stream
                elif phase == "done":
                    entry["in_flight_bytes"] = 0
                    entry["committed_bytes"] = _clamp_counter(
                        entry["committed_bytes"] + clamped_stream,
                        ceiling=bound,
                    )
                    if finalize_session:
                        entry["state"] = PROGRESS_STATE_COMPLETED
                        entry["completed"] = True
                    else:
                        entry["chunks_hashed"] += 1
                        entry["state"] = PROGRESS_STATE_PENDING
                elif phase == "failed":
                    entry["state"] = PROGRESS_STATE_FAILED
                    entry["completed"] = False
                    entry["in_flight_bytes"] = clamped_stream

        return _report

    def _snapshot_unlocked(self, entry: Dict[str, Any]) -> UploadProgressSnapshot:
        total = _clamp_counter(
            int(entry["committed_bytes"]) + int(entry["in_flight_bytes"]),
            ceiling=self.max_counter_bytes,
        )
        return UploadProgressSnapshot(
            session_id=str(entry["session_id"]),
            state=str(entry["state"]),
            bytes_hashed=total,
            expected_bytes=entry["expected_bytes"],
            chunks_hashed=max(0, int(entry["chunks_hashed"])),
            completed=bool(entry["completed"]),
        )

    def get(self, session_id: str) -> Optional[UploadProgressSnapshot]:
        with self._lock:
            entry = self._entries.get(session_id)
            if entry is None:
                return None
            return self._snapshot_unlocked(entry)


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
    progress_callback: Optional[Callable[[int, str], None]] = None,
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
        if progress_callback is not None:
            progress_callback(0, "start")
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
                if progress_callback is not None:
                    progress_callback(bytes_written, "chunk")
            tmp_file.flush()
            os.fsync(tmp_file.fileno())

        # Atomic-ish replace into the final destination.
        shutil.move(str(tmp_path), str(dest))
        tmp_path = None
        if progress_callback is not None:
            progress_callback(bytes_written, "done")
        return hasher.hexdigest(), bytes_written
    except Exception:
        if progress_callback is not None:
            progress_callback(bytes_written, "failed")
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
    progress_callback: Optional[Callable[[int, str], None]] = None,
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
        if progress_callback is not None:
            progress_callback(0, "start")
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
                        if progress_callback is not None:
                            progress_callback(bytes_written, "chunk")
            out.flush()
            os.fsync(out.fileno())
        shutil.move(str(tmp_path), str(dest))
        tmp_path = None
        if progress_callback is not None:
            progress_callback(bytes_written, "done")
        return hasher.hexdigest(), bytes_written
    except Exception:
        if progress_callback is not None:
            progress_callback(bytes_written, "failed")
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
        progress_callback: Optional[Callable[[int, str], None]] = None,
    ):
        super().__init__(stream, filename, content_type=content_type)
        self._max_size = max_size
        self._chunk_size = resolve_chunk_bytes(chunk_size)
        self._temp_dir = resolve_temp_dir(temp_dir)
        self._progress_callback = progress_callback
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
            progress_callback=self._progress_callback,
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
    *,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> StreamingFileStorage:
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
        progress_callback=progress_callback,
    )
