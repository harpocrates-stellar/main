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
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Optional, Tuple, Union

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
    env_value = os.getenv("UPLOAD_TEMP_DIR")
    if env_value and env_value.strip():
        return env_value.strip()
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
# Offline upload integrity report for failed sessions
# ---------------------------------------------------------------------------

FAILED_UPLOAD_INTEGRITY_SCHEMA = "hpx-failed-upload-integrity-report/1"
SESSION_DIR_PREFIX = "harpocrates-session-"
SESSION_META_FILENAME = ".session_meta.json"
SESSION_FAILURE_FILENAME = ".failure_record.json"

DIGEST_STATUS_MATCHED = "matched"
DIGEST_STATUS_MISMATCH = "mismatch"
DIGEST_STATUS_UNVERIFIED = "unverified"
DIGEST_STATUS_EMPTY = "empty"

_SAFE_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_REASON_RE = re.compile(r"^[a-z0-9_]{1,64}$")


def _utc_iso(dt: datetime | None = None) -> str:
    current = dt.astimezone(timezone.utc) if dt is not None else datetime.now(timezone.utc)
    return current.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sanitize_session_id(session_id: str) -> str:
    candidate = str(session_id or "").strip()
    if not _SAFE_SESSION_ID_RE.fullmatch(candidate):
        raise ValueError("session_id must be a safe opaque identifier")
    return candidate


def resolve_session_root(explicit: str | Path | None = None) -> Path:
    resolved = resolve_temp_dir(explicit)
    return Path(resolved) if resolved else Path(tempfile.gettempdir())


def resolve_session_dir(
    session_id: str,
    *,
    session_root: str | Path | None = None,
) -> Path:
    safe_id = sanitize_session_id(session_id)
    return resolve_session_root(session_root) / f"{SESSION_DIR_PREFIX}{safe_id}"


def normalize_expected_sha256(raw: str | None) -> Optional[str]:
    if raw is None:
        return None
    cleaned = str(raw).strip().lower()
    if not cleaned:
        return None
    if cleaned.startswith("sha256:"):
        cleaned = cleaned[len("sha256:") :]
    if not _HEX64_RE.fullmatch(cleaned):
        raise ValueError("expected_sha256 must be a 64-character hexadecimal SHA-256 digest")
    return cleaned


def normalize_expected_bytes(raw: int | str | None) -> Optional[int]:
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ValueError("expected_bytes must be a non-negative integer")
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return None
        parsed = int(stripped)
    else:
        parsed = int(raw)
    if parsed < 0:
        raise ValueError("expected_bytes must be non-negative")
    return parsed


def init_upload_session_metadata(
    session_dir: str | Path,
    *,
    session_id: str,
    expected_bytes: int | str | None = None,
    expected_sha256: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Persist privacy-safe session expectations without filenames or media bytes."""
    safe_id = sanitize_session_id(session_id)
    norm_bytes = normalize_expected_bytes(expected_bytes)
    norm_sha = normalize_expected_sha256(expected_sha256)
    target_dir = Path(session_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "session_id": safe_id,
        "expected_bytes": norm_bytes,
        "expected_sha256": norm_sha,
        "created_at": _utc_iso(now),
    }
    meta_path = target_dir / SESSION_META_FILENAME
    meta_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return payload


def _load_session_metadata(session_dir: Path) -> dict[str, Any]:
    meta_path = session_dir / SESSION_META_FILENAME
    if not meta_path.is_file():
        return {}
    try:
        loaded = json.loads(meta_path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}
    except (OSError, ValueError):
        return {}


def compute_session_observed_state(
    session_dir: str | Path,
    *,
    chunk_size: int | None = None,
) -> tuple[int, int, Optional[str]]:
    """Compute ``(observed_bytes, chunk_count, sha256_or_none)`` using bounded reads."""
    directory = Path(session_dir)
    if not directory.is_dir():
        return 0, 0, None

    chunk_files: list[tuple[int, Path]] = []
    for entry in directory.iterdir():
        if not entry.is_file() or not entry.name.startswith("chunk-"):
            continue
        suffix = entry.name[len("chunk-") :]
        if suffix.isdigit():
            chunk_files.append((int(suffix), entry))
    chunk_files.sort(key=lambda item: item[0])
    if not chunk_files:
        return 0, 0, None

    bounded = resolve_chunk_bytes(chunk_size)
    hasher = hashlib.sha256()
    observed_bytes = 0
    for _idx, chunk_path in chunk_files:
        with chunk_path.open("rb") as handle:
            while True:
                block = handle.read(bounded)
                if not block:
                    break
                hasher.update(block)
                observed_bytes += len(block)
    return observed_bytes, len(chunk_files), hasher.hexdigest()


def evaluate_digest_status(
    *,
    observed_bytes: int,
    observed_sha256: Optional[str],
    expected_sha256: Optional[str],
) -> str:
    norm_expected = normalize_expected_sha256(expected_sha256)
    if norm_expected is not None:
        effective_observed = (
            observed_sha256.lower()
            if observed_sha256
            else (hashlib.sha256(b"").hexdigest() if observed_bytes == 0 else None)
        )
        if effective_observed is None:
            return DIGEST_STATUS_UNVERIFIED
        if effective_observed == norm_expected:
            return DIGEST_STATUS_MATCHED
        return DIGEST_STATUS_MISMATCH
    if observed_bytes == 0 and observed_sha256 is None:
        return DIGEST_STATUS_EMPTY
    return DIGEST_STATUS_UNVERIFIED


@dataclass(frozen=True)
class FailedUploadSessionRecord:
    """Privacy-safe integrity record for a failed upload session."""

    session_id: str
    failure_reason: str
    expected_bytes: Optional[int]
    observed_bytes: int
    byte_delta: Optional[int]
    chunk_count: int
    digest_status: str
    recorded_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "failure_reason": self.failure_reason,
            "expected_bytes": self.expected_bytes,
            "observed_bytes": self.observed_bytes,
            "byte_delta": self.byte_delta,
            "chunk_count": self.chunk_count,
            "digest_status": self.digest_status,
            "recorded_at": self.recorded_at,
        }


def record_failed_upload_session(
    session_dir: str | Path,
    *,
    session_id: str | None = None,
    failure_reason: str,
    expected_bytes: int | str | None = None,
    expected_sha256: str | None = None,
    observed_bytes_override: int | None = None,
    observed_sha256_override: str | None = None,
    now: datetime | None = None,
) -> FailedUploadSessionRecord:
    """Record a failed session's byte counts and digest status on disk without media or filenames."""
    directory = Path(session_dir)
    meta = _load_session_metadata(directory)
    derived_id = session_id or meta.get("session_id")
    if not derived_id and directory.name.startswith(SESSION_DIR_PREFIX):
        derived_id = directory.name[len(SESSION_DIR_PREFIX) :]
    safe_id = sanitize_session_id(str(derived_id or "unknown-session"))

    clean_reason = str(failure_reason or "upload_failed").strip().lower()
    if not _SAFE_REASON_RE.fullmatch(clean_reason):
        clean_reason = "upload_failed"

    eff_expected_bytes = (
        normalize_expected_bytes(expected_bytes)
        if expected_bytes is not None
        else normalize_expected_bytes(meta.get("expected_bytes"))
    )
    eff_expected_sha = (
        normalize_expected_sha256(expected_sha256)
        if expected_sha256 is not None
        else normalize_expected_sha256(meta.get("expected_sha256"))
    )

    disk_bytes, chunk_count, disk_sha = compute_session_observed_state(directory)
    observed_bytes = (
        max(0, int(observed_bytes_override))
        if observed_bytes_override is not None
        else disk_bytes
    )
    observed_sha = (
        observed_sha256_override
        if observed_sha256_override is not None
        else disk_sha
    )
    digest_status = evaluate_digest_status(
        observed_bytes=observed_bytes,
        observed_sha256=observed_sha,
        expected_sha256=eff_expected_sha,
    )
    byte_delta = (
        observed_bytes - eff_expected_bytes
        if eff_expected_bytes is not None
        else None
    )

    record = FailedUploadSessionRecord(
        session_id=safe_id,
        failure_reason=clean_reason,
        expected_bytes=eff_expected_bytes,
        observed_bytes=observed_bytes,
        byte_delta=byte_delta,
        chunk_count=chunk_count,
        digest_status=digest_status,
        recorded_at=_utc_iso(now),
    )
    if directory.is_dir():
        failure_path = directory / SESSION_FAILURE_FILENAME
        failure_path.write_text(
            json.dumps(record.to_dict(), sort_keys=True),
            encoding="utf-8",
        )
    return record


def build_failed_session_integrity_report(
    session_root: str | Path | None = None,
    *,
    include_unmarked_incomplete: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build an offline integrity report across failed upload sessions.

    Scans ``harpocrates-session-*`` directories under *session_root* without
    requiring a database or running server, excluding all uploaded media bytes,
    private filenames, and server filesystem paths.
    """
    root = resolve_session_root(session_root)
    records: list[FailedUploadSessionRecord] = []

    if root.is_dir():
        for entry in sorted(root.iterdir(), key=lambda item: item.name):
            if not entry.is_dir() or not entry.name.startswith(SESSION_DIR_PREFIX):
                continue
            raw_id = entry.name[len(SESSION_DIR_PREFIX) :]
            try:
                safe_id = sanitize_session_id(raw_id)
            except ValueError:
                continue

            failure_path = entry / SESSION_FAILURE_FILENAME
            if failure_path.is_file():
                try:
                    data = json.loads(failure_path.read_text(encoding="utf-8"))
                    exp_b = normalize_expected_bytes(data.get("expected_bytes"))
                    obs_b = max(0, int(data.get("observed_bytes", 0)))
                    status = str(data.get("digest_status", DIGEST_STATUS_UNVERIFIED))
                    if status not in {
                        DIGEST_STATUS_MATCHED,
                        DIGEST_STATUS_MISMATCH,
                        DIGEST_STATUS_UNVERIFIED,
                        DIGEST_STATUS_EMPTY,
                    }:
                        status = DIGEST_STATUS_UNVERIFIED
                    reason = str(data.get("failure_reason", "upload_failed"))
                    if not _SAFE_REASON_RE.fullmatch(reason):
                        reason = "upload_failed"
                    records.append(
                        FailedUploadSessionRecord(
                            session_id=safe_id,
                            failure_reason=reason,
                            expected_bytes=exp_b,
                            observed_bytes=obs_b,
                            byte_delta=(obs_b - exp_b) if exp_b is not None else None,
                            chunk_count=max(0, int(data.get("chunk_count", 0))),
                            digest_status=status,
                            recorded_at=str(data.get("recorded_at") or _utc_iso(now)),
                        )
                    )
                    continue
                except (OSError, ValueError, TypeError):
                    pass

            if include_unmarked_incomplete:
                records.append(
                    record_failed_upload_session(
                        entry,
                        session_id=safe_id,
                        failure_reason="incomplete_session",
                        now=now,
                    )
                )

    records.sort(key=lambda r: (r.recorded_at, r.session_id))
    by_digest_status = {
        DIGEST_STATUS_MATCHED: 0,
        DIGEST_STATUS_MISMATCH: 0,
        DIGEST_STATUS_UNVERIFIED: 0,
        DIGEST_STATUS_EMPTY: 0,
    }
    by_failure_reason: dict[str, int] = {}
    total_expected_bytes = 0
    total_observed_bytes = 0

    for rec in records:
        by_digest_status[rec.digest_status] = (
            by_digest_status.get(rec.digest_status, 0) + 1
        )
        by_failure_reason[rec.failure_reason] = (
            by_failure_reason.get(rec.failure_reason, 0) + 1
        )
        if rec.expected_bytes is not None:
            total_expected_bytes += rec.expected_bytes
        total_observed_bytes += rec.observed_bytes

    return {
        "schema": FAILED_UPLOAD_INTEGRITY_SCHEMA,
        "generated_at": _utc_iso(now),
        "total_failed_sessions": len(records),
        "total_expected_bytes": total_expected_bytes,
        "total_observed_bytes": total_observed_bytes,
        "by_digest_status": by_digest_status,
        "by_failure_reason": by_failure_reason,
        "sessions": [rec.to_dict() for rec in records],
    }
