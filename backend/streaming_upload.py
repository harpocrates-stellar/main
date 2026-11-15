"""Bounded-chunk streaming upload helpers with concurrent SHA-256 hashing.

Trust boundary
--------------
Upload bytes cross the public HTTP boundary into temporary disk under a
hard size limit.  Hashing happens while bytes are copied so callers never
need a second full-file read.  Failure messages are stable and never echo
payload bytes, filenames beyond what Flask already accepted, or secrets.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import BinaryIO, Iterable, Optional, Tuple, Union

from flask import g
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import ClientDisconnected, RequestEntityTooLarge

UPLOAD_PREMATURE_TERMINATION = "UPLOAD_PREMATURE_TERMINATION"


class PrematureUploadTerminationError(Exception):
    """Raised when an upload stream disconnects or ends short of its declared byte count."""

    def __init__(
        self,
        *,
        reason: str = "stream_disconnected",
        expected_bytes: Optional[int] = None,
        observed_bytes: int = 0,
    ) -> None:
        self.code = UPLOAD_PREMATURE_TERMINATION
        self.reason = reason
        self.expected_bytes = (
            max(0, int(expected_bytes)) if expected_bytes is not None else None
        )
        self.observed_bytes = max(0, int(observed_bytes))
        super().__init__("upload stream terminated before completion")


def parse_expected_upload_bytes(raw: int | str | None) -> Optional[int]:
    """Parse an optional declared byte count for truncation detection."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ValueError("expected upload bytes must be a non-negative integer")
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return None
        parsed = int(stripped)
    else:
        parsed = int(raw)
    if parsed < 0:
        raise ValueError("expected upload bytes must be non-negative")
    return parsed

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
    expected_bytes: int | str | None = None,
    temp_dir: str | Path | None = None,
) -> Tuple[str, int]:
    """Copy *source* to *destination* in bounded chunks while hashing SHA-256.

    Returns ``(hex_digest, bytes_written)``.
    Raises ``RequestEntityTooLarge`` when *max_size* is exceeded mid-stream.
    Raises ``PrematureUploadTerminationError`` when *source* disconnects or ends
    short of *expected_bytes*, while treating a clean zero-byte stream (with
    ``expected_bytes`` absent or ``0``) as valid.
    Temporary files are cleaned up on failure; destination is not left partial.
    """
    bounded = resolve_chunk_bytes(chunk_size)
    limit = resolve_max_bytes(max_size)
    declared_expected = parse_expected_upload_bytes(expected_bytes)
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
                try:
                    chunk = source.read(bounded)
                except (ConnectionError, EOFError, ClientDisconnected, OSError) as exc:
                    raise PrematureUploadTerminationError(
                        reason="stream_disconnected",
                        expected_bytes=declared_expected,
                        observed_bytes=bytes_written,
                    ) from exc
                if not chunk:
                    break
                if limit > 0 and bytes_written + len(chunk) > limit:
                    raise RequestEntityTooLarge("Upload exceeds size limit")
                tmp_file.write(chunk)
                hasher.update(chunk)
                bytes_written += len(chunk)

            if declared_expected is not None and bytes_written < declared_expected:
                raise PrematureUploadTerminationError(
                    reason="short_read",
                    expected_bytes=declared_expected,
                    observed_bytes=bytes_written,
                )

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
            # Do not leave a partial final artifact after a size or disconnect abort.
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
    expected_bytes: int | str | None = None,
) -> Tuple[str, int]:
    """Concatenate *paths* into *destination* with bounded-chunk SHA-256 hashing."""
    bounded = resolve_chunk_bytes(chunk_size)
    limit = resolve_max_bytes(max_size)
    declared_expected = parse_expected_upload_bytes(expected_bytes)
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
            if declared_expected is not None and bytes_written < declared_expected:
                raise PrematureUploadTerminationError(
                    reason="short_read",
                    expected_bytes=declared_expected,
                    observed_bytes=bytes_written,
                )
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
        expected_bytes: int | str | None = None,
        temp_dir: str | Path | None = None,
    ):
        super().__init__(stream, filename, content_type=content_type)
        self._max_size = max_size
        self._chunk_size = resolve_chunk_bytes(chunk_size)
        self._expected_bytes = parse_expected_upload_bytes(expected_bytes)
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
            expected_bytes=self._expected_bytes,
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


class ObservedUploadStream:
    """Zero-buffering WSGI input wrapper tracking bytes read and premature EOF."""

    def __init__(self, wrapped: BinaryIO, declared_length: int | None) -> None:
        self._wrapped = wrapped
        self.declared_length = (
            int(declared_length)
            if declared_length is not None and int(declared_length) >= 0
            else None
        )
        self.bytes_read = 0
        self.disconnected = False

    def read(self, size: int = -1) -> bytes:
        try:
            chunk = self._wrapped.read(size)
        except (ClientDisconnected, ConnectionError, EOFError, OSError):
            self.disconnected = True
            raise
        if chunk:
            self.bytes_read += len(chunk)
        elif (
            self.declared_length is not None
            and self.declared_length > 0
            and size != 0
            and self.bytes_read < self.declared_length
        ):
            self.disconnected = True
        return chunk

    def readline(self, size: int = -1) -> bytes:
        readline_fn = getattr(self._wrapped, "readline", None)
        if readline_fn is None:
            return self.read(size)
        try:
            line = readline_fn(size) if size >= 0 else readline_fn()
        except (ClientDisconnected, ConnectionError, EOFError, OSError):
            self.disconnected = True
            raise
        if line:
            self.bytes_read += len(line)
        elif (
            self.declared_length is not None
            and self.declared_length > 0
            and size != 0
            and self.bytes_read < self.declared_length
        ):
            self.disconnected = True
        return line

    def __iter__(self):
        while True:
            line = self.readline()
            if not line:
                break
            yield line

    def __getattr__(self, name: str):
        return getattr(self._wrapped, name)


def ensure_multipart_stream_complete(
    environ: dict | None,
    *,
    stream: BinaryIO | None = None,
    observed_stream: ObservedUploadStream | None = None,
    content_length: int | None,
    mimetype: str | None,
) -> None:
    """Detect when Werkzeug's silent multipart parser aborted on a truncated body."""
    if observed_stream is not None and observed_stream.disconnected:
        raise PrematureUploadTerminationError(
            reason="incomplete_multipart",
            expected_bytes=observed_stream.declared_length,
            observed_bytes=observed_stream.bytes_read,
        )
    if not content_length or content_length <= 0:
        return
    if (mimetype or "").lower() != "multipart/form-data":
        return
    candidate = stream if stream is not None else (environ.get("wsgi.input") if environ else None)
    if candidate is None:
        return
    pos = getattr(candidate, "_pos", None)
    if pos is None and callable(getattr(candidate, "tell", None)):
        try:
            pos = candidate.tell()
        except (OSError, ValueError):
            pos = None
    limit = getattr(candidate, "limit", content_length)
    if pos is not None and pos < limit:
        try:
            probe = candidate.read(1)
        except (ClientDisconnected, ConnectionError, EOFError, OSError) as exc:
            raise PrematureUploadTerminationError(
                reason="incomplete_multipart",
                expected_bytes=int(limit),
                observed_bytes=int(pos),
            ) from exc
        if not probe:
            raise PrematureUploadTerminationError(
                reason="incomplete_multipart",
                expected_bytes=int(limit),
                observed_bytes=int(pos),
            )


def create_streaming_file_storage(
    field_storage: FileStorage,
    *,
    expected_bytes: int | str | None = None,
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
        expected_bytes=expected_bytes,
        temp_dir=temp_dir,
    )
