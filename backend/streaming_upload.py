"""Bounded-chunk streaming upload helpers with concurrent SHA-256 hashing.

Trust boundary
--------------
Upload bytes cross the public HTTP boundary into temporary disk under a
hard size limit.  Hashing happens while bytes are copied so callers never
need a second full-file read.  Failure messages are stable and never echo
payload bytes, filenames beyond what Flask already accepted, or secrets.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterable, Mapping, Optional, Tuple, Union

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


def hash_stream_to_path(
    source: BinaryIO,
    destination: Union[str, Path],
    *,
    chunk_size: int | None = None,
    max_size: int | None = None,
    temp_dir: str | Path | None = None,
    expected_size: int | None = None,
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
                try:
                    chunk = source.read(bounded)
                except _DISCONNECT_EXCEPTIONS as exc:
                    raise PrematureUploadTerminationError(
                        bytes_received=bytes_written,
                        expected_bytes=expected,
                    ) from exc
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
    progress: Optional[UploadHashingProgress] = None,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
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
                with Path(path).open("rb") as handle:
                    while True:
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
        expected_size: int | None = None,
    ):
        super().__init__(stream, filename, content_type=content_type)
        self._max_size = max_size
        self._chunk_size = resolve_chunk_bytes(chunk_size)
        self._temp_dir = resolve_temp_dir(temp_dir)
        self._expected_size = expected_size
        self._materialized_path: Optional[Path] = None
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
            expected_size=self._expected_size,
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
    )


# ---------------------------------------------------------------------------
# Resumable encrypted upload sessions with explicit ownership
# ---------------------------------------------------------------------------

DEFAULT_MAX_SESSION_CHUNKS = 10_000
_SESSION_ID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_MAX_OWNER_LEN = 256
_MAX_TOKEN_LEN = 256
_NONCE_BYTES = 12
_DEK_BYTES = 32


class UploadSessionError(Exception):
    """Base error for resumable upload sessions with stable, privacy-safe codes."""

    def __init__(self, message: str, *, code: str = "UPLOAD_SESSION_ERROR", status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class SessionNotFoundError(UploadSessionError):
    def __init__(self, message: str = "upload session not found"):
        super().__init__(message, code="SESSION_NOT_FOUND", status_code=404)


class SessionAuthError(UploadSessionError):
    def __init__(self, message: str = "upload session authentication failed", *, code: str = "SESSION_UNAUTHORIZED", status_code: int = 401):
        super().__init__(message, code=code, status_code=status_code)


class SessionStateError(UploadSessionError):
    def __init__(self, message: str = "upload session is not in a valid state", *, code: str = "SESSION_INVALID_STATE", status_code: int = 400):
        super().__init__(message, code=code, status_code=status_code)


class ContentHashMismatchError(UploadSessionError):
    def __init__(self, message: str = "content hash verification failed"):
        super().__init__(message, code="CONTENT_HASH_MISMATCH", status_code=422)


class PrematureUploadTerminationError(UploadSessionError):
    """Raised when an upload stream disconnects or ends before completion."""

    def __init__(
        self,
        message: str = "upload terminated prematurely before completion",
        *,
        bytes_received: int = 0,
        expected_bytes: int | None = None,
    ):
        super().__init__(
            message,
            code=UPLOAD_TERMINATED_PREMATURELY,
            status_code=400,
        )
        self.bytes_received = bytes_received
        self.expected_bytes = expected_bytes


def _normalize_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().lower()
    if not _SHA256_HEX_RE.match(cleaned):
        raise UploadSessionError("expected_sha256 must be a 64-character hex digest", code="INVALID_SHA256", status_code=400)
    return cleaned


def _normalize_owner(owner: str | None) -> str | None:
    if owner is None:
        return None
    cleaned = owner.strip()
    if not cleaned:
        return None
    if len(cleaned) > _MAX_OWNER_LEN:
        raise UploadSessionError("owner identifier exceeds maximum length", code="INVALID_OWNER", status_code=400)
    return cleaned


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(tmp_path), str(path))
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def _derive_master_key(explicit_key: bytes | None = None) -> bytes:
    if explicit_key is not None:
        if len(explicit_key) == _DEK_BYTES:
            return explicit_key
        return hashlib.sha256(explicit_key).digest()
    env_key = os.getenv("UPLOAD_SESSION_MASTER_KEY") or os.getenv("MASTER_ENCRYPTION_KEY")
    if env_key and env_key.strip():
        return hashlib.sha256(env_key.strip().encode("utf-8")).digest()
    return os.urandom(_DEK_BYTES)


@dataclass(frozen=True)
class ChunkProgress:
    """Persisted metadata for one encrypted chunk in a resumable upload session."""

    index: int
    bytes_written: int
    sha256: str
    nonce_b64: str
    ciphertext_bytes: int

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "bytes_written": self.bytes_written,
            "sha256": self.sha256,
            "nonce_b64": self.nonce_b64,
            "ciphertext_bytes": self.ciphertext_bytes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ChunkProgress":
        return cls(
            index=int(data["index"]),
            bytes_written=int(data["bytes_written"]),
            sha256=str(data["sha256"]),
            nonce_b64=str(data["nonce_b64"]),
            ciphertext_bytes=int(data["ciphertext_bytes"]),
        )


@dataclass
class UploadSession:
    """Persisted state for a resumable, encrypted upload session."""

    session_id: str
    owner: Optional[str]
    owner_tier: Optional[str]
    token_digest: Optional[str]
    wrapped_dek_b64: str
    dek_nonce_b64: str
    expected_sha256: Optional[str]
    expected_size: Optional[int]
    max_size: Optional[int]
    chunk_size: int
    max_chunks: int
    state: str = "open"
    chunks: Dict[int, ChunkProgress] = field(default_factory=dict)
    total_bytes: int = 0
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)

    def received_chunk_indices(self) -> list[int]:
        return sorted(self.chunks.keys())

    def next_chunk_index(self) -> int:
        idx = 0
        while idx in self.chunks:
            idx += 1
        return idx

    def to_manifest(self) -> dict:
        return {
            "version": 1,
            "session_id": self.session_id,
            "owner": self.owner,
            "owner_tier": self.owner_tier,
            "token_digest": self.token_digest,
            "wrapped_dek_b64": self.wrapped_dek_b64,
            "dek_nonce_b64": self.dek_nonce_b64,
            "expected_sha256": self.expected_sha256,
            "expected_size": self.expected_size,
            "max_size": self.max_size,
            "chunk_size": self.chunk_size,
            "max_chunks": self.max_chunks,
            "state": self.state,
            "total_bytes": self.total_bytes,
            "chunks": {str(k): v.to_dict() for k, v in sorted(self.chunks.items())},
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_manifest(cls, data: dict) -> "UploadSession":
        chunks_raw = data.get("chunks") or {}
        chunks = {int(k): ChunkProgress.from_dict(v) for k, v in chunks_raw.items()}
        return cls(
            session_id=str(data["session_id"]),
            owner=data.get("owner"),
            owner_tier=data.get("owner_tier"),
            token_digest=data.get("token_digest"),
            wrapped_dek_b64=str(data["wrapped_dek_b64"]),
            dek_nonce_b64=str(data["dek_nonce_b64"]),
            expected_sha256=data.get("expected_sha256"),
            expected_size=data.get("expected_size"),
            max_size=data.get("max_size"),
            chunk_size=int(data["chunk_size"]),
            max_chunks=int(data.get("max_chunks", DEFAULT_MAX_SESSION_CHUNKS)),
            state=str(data.get("state", "open")),
            chunks=chunks,
            total_bytes=int(data.get("total_bytes", sum(c.bytes_written for c in chunks.values()))),
            created_at=str(data.get("created_at", "")),
            updated_at=str(data.get("updated_at", "")),
        )


class ResumableUploadSessionStore:
    """Manages resumable, AES-256-GCM encrypted upload sessions with explicit ownership.

    Each session stores an atomic ``manifest.json`` and encrypted ``chunk-<n>.enc``
    files under ``base_dir / harpocrates-session-<session_id>``.  Chunk ciphertexts
    are authenticated with AAD binding ``(session_id, owner, chunk_index)`` so
    chunks cannot be replayed across sessions, owners, or indices.
    """

    def __init__(
        self,
        base_dir: Union[str, Path],
        *,
        master_key: bytes | None = None,
        default_chunk_size: int | None = None,
        default_max_size: int | None = None,
        max_chunks: int = DEFAULT_MAX_SESSION_CHUNKS,
    ):
        self._base_dir = Path(base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._master_key = _derive_master_key(master_key)
        self._default_chunk_size = resolve_chunk_bytes(default_chunk_size)
        self._default_max_size = default_max_size
        self._max_chunks = max(1, int(max_chunks))

    def _session_dir(self, session_id: str) -> Path:
        if not isinstance(session_id, str) or not _SESSION_ID_RE.match(session_id):
            raise SessionNotFoundError()
        return self._base_dir / f"harpocrates-session-{session_id}"

    def _manifest_path(self, session_id: str) -> Path:
        return self._session_dir(session_id) / "manifest.json"

    def _chunk_path(self, session_id: str, chunk_index: int) -> Path:
        return self._session_dir(session_id) / f"chunk-{chunk_index}.enc"

    def _dek_aad(self, session_id: str, owner: Optional[str]) -> bytes:
        return f"dek:{session_id}:{owner or ''}".encode("utf-8")

    def _chunk_aad(self, session_id: str, owner: Optional[str], chunk_index: int) -> bytes:
        return f"chunk:{session_id}:{owner or ''}:{chunk_index}".encode("utf-8")

    def _wrap_dek(self, dek: bytes, session_id: str, owner: Optional[str]) -> Tuple[str, str]:
        nonce = os.urandom(_NONCE_BYTES)
        wrapped = AESGCM(self._master_key).encrypt(nonce, dek, self._dek_aad(session_id, owner))
        return base64.b64encode(wrapped).decode("ascii"), base64.b64encode(nonce).decode("ascii")

    def _unwrap_dek(self, session: UploadSession) -> bytes:
        try:
            wrapped = base64.b64decode(session.wrapped_dek_b64)
            nonce = base64.b64decode(session.dek_nonce_b64)
            return AESGCM(self._master_key).decrypt(
                nonce, wrapped, self._dek_aad(session.session_id, session.owner)
            )
        except (ValueError, InvalidTag) as exc:
            raise SessionStateError("failed to decrypt session key", code="SESSION_CORRUPT", status_code=500) from exc

    def _save_manifest(self, session: UploadSession) -> None:
        session.updated_at = _utc_now_iso()
        encoded = json.dumps(session.to_manifest(), separators=(",", ":"), sort_keys=True).encode("utf-8")
        _atomic_write_bytes(self._manifest_path(session.session_id), encoded)

    def _load_manifest(self, session_id: str) -> UploadSession:
        manifest_path = self._manifest_path(session_id)
        if not manifest_path.exists():
            raise SessionNotFoundError()
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            return UploadSession.from_manifest(raw)
        except (OSError, ValueError, KeyError) as exc:
            raise SessionStateError("upload session manifest is corrupt", code="SESSION_CORRUPT", status_code=500) from exc

    def create_session(
        self,
        *,
        owner: str | None = None,
        owner_tier: str | None = None,
        expected_sha256: str | None = None,
        expected_size: int | None = None,
        max_size: int | None = None,
        chunk_size: int | None = None,
    ) -> Tuple[UploadSession, Optional[str]]:
        """Create a new encrypted upload session and persist its manifest.

        When *owner* is provided, a random session bearer token is generated and
        returned once; only its SHA-256 digest is persisted.
        """
        norm_owner = _normalize_owner(owner)
        norm_sha256 = _normalize_sha256(expected_sha256)
        effective_max = self._default_max_size if max_size is None else max(0, int(max_size))
        if expected_size is not None:
            parsed_expected = int(expected_size)
            if parsed_expected < 0:
                raise UploadSessionError("expected_size must be non-negative", code="INVALID_EXPECTED_SIZE", status_code=400)
            if effective_max is not None and parsed_expected > effective_max:
                raise RequestEntityTooLarge("Upload exceeds size limit")
        else:
            parsed_expected = None

        session_id = str(uuid.uuid4())
        session_dir = self._session_dir(session_id)
        session_dir.mkdir(parents=True, exist_ok=True)

        dek = os.urandom(_DEK_BYTES)
        wrapped_dek_b64, dek_nonce_b64 = self._wrap_dek(dek, session_id, norm_owner)

        session_token: Optional[str] = None
        token_digest: Optional[str] = None
        if norm_owner is not None:
            session_token = secrets.token_urlsafe(32)
            token_digest = _token_digest(session_token)

        session = UploadSession(
            session_id=session_id,
            owner=norm_owner,
            owner_tier=owner_tier.strip() if isinstance(owner_tier, str) and owner_tier.strip() else None,
            token_digest=token_digest,
            wrapped_dek_b64=wrapped_dek_b64,
            dek_nonce_b64=dek_nonce_b64,
            expected_sha256=norm_sha256,
            expected_size=parsed_expected,
            max_size=effective_max,
            chunk_size=resolve_chunk_bytes(chunk_size) if chunk_size is not None else self._default_chunk_size,
            max_chunks=self._max_chunks,
        )
        self._save_manifest(session)
        return session, session_token

    def authenticate_session(
        self,
        session_id: str,
        *,
        session_token: str | None = None,
        owner: str | None = None,
    ) -> UploadSession:
        """Load *session_id* and enforce explicit ownership & bearer token auth."""
        session = self._load_manifest(session_id)
        if session.owner is not None or session.token_digest is not None:
            if not session_token or len(session_token) > _MAX_TOKEN_LEN:
                raise SessionAuthError("session authentication token is required", code="SESSION_UNAUTHORIZED", status_code=401)
            presented_digest = _token_digest(session_token)
            if not session.token_digest or not hmac.compare_digest(presented_digest, session.token_digest):
                raise SessionAuthError("invalid session authentication token", code="SESSION_UNAUTHORIZED", status_code=401)
            if owner is not None:
                norm_owner = _normalize_owner(owner)
                if norm_owner is None or session.owner is None or not hmac.compare_digest(norm_owner, session.owner):
                    raise SessionAuthError("session owner mismatch", code="SESSION_OWNER_MISMATCH", status_code=403)
        return session

    def get_progress(
        self,
        session_id: str,
        *,
        session_token: str | None = None,
        owner: str | None = None,
    ) -> dict:
        """Return persisted resumable progress for an authenticated session."""
        session = self.authenticate_session(session_id, session_token=session_token, owner=owner)
        return {
            "sessionId": session.session_id,
            "owner": session.owner,
            "ownerTier": session.owner_tier,
            "state": session.state,
            "encrypted": True,
            "receivedChunks": session.received_chunk_indices(),
            "nextChunkIndex": session.next_chunk_index(),
            "totalBytes": session.total_bytes,
            "expectedSha256": session.expected_sha256,
            "expectedSize": session.expected_size,
        }

    def write_chunk(
        self,
        session_id: str,
        chunk_index: int,
        source: BinaryIO,
        *,
        session_token: str | None = None,
        owner: str | None = None,
        chunk_sha256: str | None = None,
        expected_size: int | None = None,
    ) -> Tuple[ChunkProgress, int]:
        """Read, hash, encrypt, and atomically persist a single bounded chunk.

        Returns ``(ChunkProgress, updated_session_total_bytes)``.
        """
        session = self.authenticate_session(session_id, session_token=session_token, owner=owner)
        if session.state != "open":
            raise SessionStateError("upload session is not open", code="SESSION_CLOSED", status_code=409)
        if chunk_index < 0 or chunk_index >= session.max_chunks:
            raise UploadSessionError("chunk_index is out of bounds", code="INVALID_CHUNK_INDEX", status_code=400)

        expected_chunk_hash = _normalize_sha256(chunk_sha256)
        expected = max(0, int(expected_size)) if expected_size is not None else None
        previous_bytes = session.chunks[chunk_index].bytes_written if chunk_index in session.chunks else 0
        other_bytes = session.total_bytes - previous_bytes

        bounded = session.chunk_size
        hasher = hashlib.sha256()
        buffer = bytearray()
        bytes_read = 0

        while True:
            try:
                piece = source.read(bounded)
            except _DISCONNECT_EXCEPTIONS as exc:
                raise PrematureUploadTerminationError(
                    bytes_received=bytes_read,
                    expected_bytes=expected,
                ) from exc
            if not piece:
                break
            bytes_read += len(piece)
            if session.max_size is not None and (other_bytes + bytes_read) > session.max_size:
                raise RequestEntityTooLarge("Upload exceeds size limit")
            hasher.update(piece)
            buffer.extend(piece)

        if expected is not None and bytes_read < expected:
            raise PrematureUploadTerminationError(
                bytes_received=bytes_read,
                expected_bytes=expected,
            )

        computed_hash = hasher.hexdigest()
        if expected_chunk_hash is not None and not hmac.compare_digest(computed_hash, expected_chunk_hash):
            raise ContentHashMismatchError("chunk hash verification failed")

        dek = self._unwrap_dek(session)
        nonce = os.urandom(_NONCE_BYTES)
        aad = self._chunk_aad(session.session_id, session.owner, chunk_index)
        ciphertext = AESGCM(dek).encrypt(nonce, bytes(buffer), aad)

        _atomic_write_bytes(self._chunk_path(session.session_id, chunk_index), ciphertext)

        progress = ChunkProgress(
            index=chunk_index,
            bytes_written=bytes_read,
            sha256=computed_hash,
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            ciphertext_bytes=len(ciphertext),
        )
        session.chunks[chunk_index] = progress
        session.total_bytes = other_bytes + bytes_read
        self._save_manifest(session)
        return progress, session.total_bytes

    def assemble_and_verify(
        self,
        session_id: str,
        destination: Union[str, Path],
        *,
        session_token: str | None = None,
        owner: str | None = None,
        expected_sha256: str | None = None,
    ) -> Tuple[UploadSession, str, int]:
        """Decrypt all contiguous chunks to *destination* and verify final content hash.

        Fails closed on missing chunks, tampering/AAD mismatch, size mismatch, or
        final SHA-256 mismatch, leaving no partial file at *destination*.
        """
        session = self.authenticate_session(session_id, session_token=session_token, owner=owner)
        if session.state != "open":
            raise SessionStateError("upload session is not open", code="SESSION_CLOSED", status_code=409)
        if not session.chunks:
            raise SessionStateError("session has no chunks", code="SESSION_EMPTY", status_code=400)

        indices = session.received_chunk_indices()
        if indices != list(range(len(indices))):
            raise SessionStateError("session is missing one or more chunks", code="SESSION_INCOMPLETE", status_code=400)

        commit_expected_hash = _normalize_sha256(expected_sha256)
        if session.expected_sha256 and commit_expected_hash:
            if not hmac.compare_digest(session.expected_sha256, commit_expected_hash):
                raise ContentHashMismatchError("commit hash does not match session expected hash")
        effective_expected_hash = commit_expected_hash or session.expected_sha256

        dek = self._unwrap_dek(session)
        aesgcm = AESGCM(dek)
        dest = Path(destination)
        dest.parent.mkdir(parents=True, exist_ok=True)

        final_hasher = hashlib.sha256()
        total_written = 0
        tmp_path: Optional[Path] = None

        try:
            fd, tmp_name = tempfile.mkstemp(prefix="harpocrates-assemble-", dir=str(dest.parent))
            tmp_path = Path(tmp_name)
            with os.fdopen(fd, "wb") as out:
                for idx in indices:
                    chunk_meta = session.chunks[idx]
                    chunk_file = self._chunk_path(session.session_id, idx)
                    if not chunk_file.exists():
                        raise SessionStateError("persisted chunk file is missing", code="SESSION_INCOMPLETE", status_code=400)
                    ciphertext = chunk_file.read_bytes()
                    nonce = base64.b64decode(chunk_meta.nonce_b64)
                    aad = self._chunk_aad(session.session_id, session.owner, idx)
                    try:
                        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
                    except InvalidTag as exc:
                        raise ContentHashMismatchError("chunk integrity verification failed") from exc

                    chunk_digest = hashlib.sha256(plaintext).hexdigest()
                    if not hmac.compare_digest(chunk_digest, chunk_meta.sha256):
                        raise ContentHashMismatchError("chunk digest mismatch during assembly")

                    if session.max_size is not None and (total_written + len(plaintext)) > session.max_size:
                        raise RequestEntityTooLarge("Upload exceeds size limit")

                    out.write(plaintext)
                    final_hasher.update(plaintext)
                    total_written += len(plaintext)
                out.flush()
                os.fsync(out.fileno())

            final_digest = final_hasher.hexdigest()
            if session.expected_size is not None and total_written != session.expected_size:
                raise ContentHashMismatchError("assembled size does not match expected size")
            if effective_expected_hash is not None and not hmac.compare_digest(final_digest, effective_expected_hash):
                raise ContentHashMismatchError("final content hash does not match expected digest")

            shutil.move(str(tmp_path), str(dest))
            tmp_path = None
            return session, final_digest, total_written
        except Exception:
            if tmp_path is not None and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            if dest.exists():
                try:
                    dest.unlink()
                except OSError:
                    pass
            raise

    def cleanup_session(self, session_id: str) -> None:
        """Remove a session directory and all encrypted chunk files."""
        try:
            session_dir = self._session_dir(session_id)
        except SessionNotFoundError:
            return
        shutil.rmtree(session_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Offline upload integrity reporting for failed sessions
# ---------------------------------------------------------------------------

INTEGRITY_REPORT_SCHEMA_VERSION = 1

DIGEST_STATUS_MATCHED = "matched"
DIGEST_STATUS_MISMATCH = "mismatch"
DIGEST_STATUS_UNVERIFIED = "unverified"
DIGEST_STATUS_UNAVAILABLE = "unavailable"

BYTE_COUNT_STATUS_MATCHED = "matched"
BYTE_COUNT_STATUS_UNDERFLOW = "underflow"
BYTE_COUNT_STATUS_OVERFLOW = "overflow"
BYTE_COUNT_STATUS_UNKNOWN = "unknown"

_SAFE_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_CHUNK_FILE_RE = re.compile(r"^chunk-(\d+)$")


def _normalize_digest(digest: Optional[str]) -> Optional[str]:
    if digest is None:
        return None
    normalized = digest.strip().lower()
    return normalized or None


def _sanitize_session_id(session_id: Optional[str]) -> Optional[str]:
    """Return *session_id* only if it is an opaque identifier, never a path."""
    if session_id is None:
        return None
    candidate = session_id.strip()
    if not candidate or ".." in candidate or not _SAFE_SESSION_ID_RE.match(candidate):
        return None
    return candidate


def _classify_digest_status(
    expected_digest: Optional[str],
    observed_digest: Optional[str],
) -> str:
    if observed_digest is None:
        return DIGEST_STATUS_UNAVAILABLE
    if expected_digest is None:
        return DIGEST_STATUS_UNVERIFIED
    if observed_digest == expected_digest:
        return DIGEST_STATUS_MATCHED
    return DIGEST_STATUS_MISMATCH


def _classify_byte_count_status(
    expected_bytes: Optional[int],
    observed_bytes: int,
) -> str:
    if expected_bytes is None:
        return BYTE_COUNT_STATUS_UNKNOWN
    if observed_bytes == expected_bytes:
        return BYTE_COUNT_STATUS_MATCHED
    if observed_bytes < expected_bytes:
        return BYTE_COUNT_STATUS_UNDERFLOW
    return BYTE_COUNT_STATUS_OVERFLOW


@dataclass(frozen=True)
class ChunkIntegritySummary:
    """Privacy-safe integrity summary for a single indexed upload chunk.

    Contains only numeric indices, byte counts, and SHA-256 digest metadata —
    never uploaded media bytes or private filenames.
    """

    chunk_index: int
    observed_bytes: int
    observed_digest: Optional[str]
    expected_bytes: Optional[int] = None
    expected_digest: Optional[str] = None
    byte_count_status: str = BYTE_COUNT_STATUS_UNKNOWN
    digest_status: str = DIGEST_STATUS_UNVERIFIED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chunk_index": self.chunk_index,
            "expected_bytes": self.expected_bytes,
            "observed_bytes": self.observed_bytes,
            "byte_count_status": self.byte_count_status,
            "expected_digest": self.expected_digest,
            "observed_digest": self.observed_digest,
            "digest_status": self.digest_status,
        }


@dataclass(frozen=True)
class UploadIntegrityReport:
    """Offline integrity report for a failed (or inspected) upload session.

    Excludes uploaded media bytes, filesystem paths, and private filenames.
    """

    schema_version: int
    session_id: Optional[str]
    status: str
    failure_reason: Optional[str]
    expected_bytes: Optional[int]
    observed_bytes: int
    byte_count_status: str
    expected_digest: Optional[str]
    observed_digest: Optional[str]
    digest_status: str
    chunk_count: int
    missing_chunk_indices: Tuple[int, ...]
    chunks: Tuple[ChunkIntegritySummary, ...]
    generated_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "status": self.status,
            "failure_reason": self.failure_reason,
            "expected_bytes": self.expected_bytes,
            "observed_bytes": self.observed_bytes,
            "byte_count_status": self.byte_count_status,
            "expected_digest": self.expected_digest,
            "observed_digest": self.observed_digest,
            "digest_status": self.digest_status,
            "chunk_count": self.chunk_count,
            "missing_chunk_indices": list(self.missing_chunk_indices),
            "chunks": [chunk.to_dict() for chunk in self.chunks],
            "generated_at": self.generated_at,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)


def build_upload_integrity_report(
    *,
    session_id: Optional[str] = None,
    expected_bytes: Optional[int] = None,
    observed_bytes: int = 0,
    expected_digest: Optional[str] = None,
    observed_digest: Optional[str] = None,
    failure_reason: Optional[str] = None,
    chunks: Iterable[ChunkIntegritySummary] = (),
    missing_chunk_indices: Iterable[int] = (),
    max_bytes: Optional[int] = None,
) -> UploadIntegrityReport:
    """Construct a privacy-safe ``UploadIntegrityReport`` from session metrics."""
    norm_expected_digest = _normalize_digest(expected_digest)
    norm_observed_digest = _normalize_digest(observed_digest)
    byte_status = _classify_byte_count_status(expected_bytes, observed_bytes)
    digest_status = _classify_digest_status(norm_expected_digest, norm_observed_digest)

    chunk_tuple = tuple(chunks)
    missing_tuple = tuple(sorted(set(missing_chunk_indices)))

    inferred_reason = failure_reason
    if inferred_reason is None:
        if max_bytes is not None and max_bytes > 0 and observed_bytes > max_bytes:
            inferred_reason = "size_limit_exceeded"
        elif missing_tuple:
            inferred_reason = "chunk_gap"
        elif byte_status in (BYTE_COUNT_STATUS_UNDERFLOW, BYTE_COUNT_STATUS_OVERFLOW):
            inferred_reason = "byte_count_mismatch"
        elif digest_status == DIGEST_STATUS_MISMATCH:
            inferred_reason = "digest_mismatch"

    status = "failed" if inferred_reason is not None else "verified"

    return UploadIntegrityReport(
        schema_version=INTEGRITY_REPORT_SCHEMA_VERSION,
        session_id=_sanitize_session_id(session_id),
        status=status,
        failure_reason=inferred_reason,
        expected_bytes=expected_bytes,
        observed_bytes=observed_bytes,
        byte_count_status=byte_status,
        expected_digest=norm_expected_digest,
        observed_digest=norm_observed_digest,
        digest_status=digest_status,
        chunk_count=len(chunk_tuple),
        missing_chunk_indices=missing_tuple,
        chunks=chunk_tuple,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def inspect_failed_upload_session(
    session_dir: Union[str, Path],
    *,
    session_id: Optional[str] = None,
    expected_bytes: Optional[int] = None,
    expected_digest: Optional[str] = None,
    expected_chunks: Optional[int] = None,
    chunk_expectations: Optional[
        Mapping[int, Tuple[Optional[int], Optional[str]]]
    ] = None,
    failure_reason: Optional[str] = None,
    chunk_size: int | None = None,
    max_size: int | None = None,
) -> UploadIntegrityReport:
    """Inspect a session directory offline and produce an ``UploadIntegrityReport``.

    Reads only ``chunk-<N>`` files in bounded chunks while computing SHA-256
    digests. Any other files in *session_dir* are ignored and their names are
    never recorded. Uploaded media bytes and filesystem paths are excluded from
    the returned report.
    """
    directory = Path(session_dir)
    if not directory.exists() or not directory.is_dir():
        return build_upload_integrity_report(
            session_id=session_id,
            expected_bytes=expected_bytes,
            observed_bytes=0,
            expected_digest=expected_digest,
            observed_digest=None,
            failure_reason=failure_reason or "missing_session",
            max_bytes=max_size,
        )

    indexed_files: list[Tuple[int, Path]] = []
    for entry in directory.iterdir():
        if not entry.is_file():
            continue
        match = _CHUNK_FILE_RE.match(entry.name)
        if match is not None:
            indexed_files.append((int(match.group(1)), entry))

    indexed_files.sort(key=lambda item: item[0])

    if not indexed_files:
        missing_indices: list[int] = (
            list(range(expected_chunks)) if expected_chunks and expected_chunks > 0 else []
        )
        return build_upload_integrity_report(
            session_id=session_id,
            expected_bytes=expected_bytes,
            observed_bytes=0,
            expected_digest=expected_digest,
            observed_digest=None,
            failure_reason=failure_reason or "empty_session",
            missing_chunk_indices=missing_indices,
            max_bytes=max_size,
        )

    bounded = resolve_chunk_bytes(chunk_size)
    combined_hasher = hashlib.sha256()
    total_observed_bytes = 0
    chunk_summaries: list[ChunkIntegritySummary] = []

    present_indices = {idx for idx, _ in indexed_files}
    upper_bound = max(present_indices) + 1
    if expected_chunks is not None and expected_chunks > upper_bound:
        upper_bound = expected_chunks
    missing_indices = [i for i in range(upper_bound) if i not in present_indices]

    for idx, chunk_path in indexed_files:
        chunk_hasher = hashlib.sha256()
        chunk_bytes = 0
        with chunk_path.open("rb") as handle:
            while True:
                data = handle.read(bounded)
                if not data:
                    break
                chunk_hasher.update(data)
                combined_hasher.update(data)
                chunk_bytes += len(data)

        total_observed_bytes += chunk_bytes
        c_expected_bytes: Optional[int] = None
        c_expected_digest: Optional[str] = None
        if chunk_expectations and idx in chunk_expectations:
            c_expected_bytes, c_expected_digest = chunk_expectations[idx]
        c_norm_expected = _normalize_digest(c_expected_digest)
        c_observed_digest = chunk_hasher.hexdigest()

        chunk_summaries.append(
            ChunkIntegritySummary(
                chunk_index=idx,
                observed_bytes=chunk_bytes,
                observed_digest=c_observed_digest,
                expected_bytes=c_expected_bytes,
                expected_digest=c_norm_expected,
                byte_count_status=_classify_byte_count_status(
                    c_expected_bytes, chunk_bytes
                ),
                digest_status=_classify_digest_status(
                    c_norm_expected, c_observed_digest
                ),
            )
        )

    return build_upload_integrity_report(
        session_id=session_id,
        expected_bytes=expected_bytes,
        observed_bytes=total_observed_bytes,
        expected_digest=expected_digest,
        observed_digest=combined_hasher.hexdigest(),
        failure_reason=failure_reason,
        chunks=chunk_summaries,
        missing_chunk_indices=missing_indices,
        max_bytes=max_size,
    )


def write_upload_integrity_report(
    report: UploadIntegrityReport,
    destination: Union[str, Path],
) -> Path:
    """Persist an ``UploadIntegrityReport`` as canonical JSON to *destination*."""
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(report.to_json() + "\n", encoding="utf-8")
    return dest
