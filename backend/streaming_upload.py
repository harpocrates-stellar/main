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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Mapping, MutableMapping, Optional, Tuple, Union

from flask import g
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import RequestEntityTooLarge

# ---------------------------------------------------------------------------
# Bounded chunk sizing & normalized byte-unit upload limits
# ---------------------------------------------------------------------------

DEFAULT_CHUNK_BYTES = 65_536  # 64 KiB
MIN_CHUNK_BYTES = 4_096  # 4 KiB
MAX_CHUNK_BYTES = 1_048_576  # 1 MiB

UPLOAD_LIMIT_UNIT = "bytes"
LIMIT_POLICY_UNLIMITED = "unlimited"
LIMIT_POLICY_ZERO_ALLOWANCE = "zero_allowance"
LIMIT_POLICY_ENFORCED = "enforced"

HEADER_UPLOAD_LIMIT_UNIT = "X-Upload-Limit-Unit"
HEADER_UPLOAD_MAX_BYTES = "X-Upload-Max-Bytes"
HEADER_UPLOAD_CHUNK_BYTES = "X-Upload-Chunk-Bytes"
HEADER_UPLOAD_LIMIT_POLICY = "X-Upload-Limit-Policy"

_UNLIMITED_TOKENS = frozenset({"none", "unlimited"})


@dataclass(frozen=True)
class UploadLimitSpec:
    """Normalized upload limit specification expressed exclusively in bytes.

    ``limit_bytes`` distinguishes three states unambiguously:
    - ``None``: absent limit (``policy == "unlimited"``)
    - ``0``: explicit zero-byte allowance (``policy == "zero_allowance"``)
    - ``> 0``: positive byte ceiling (``policy == "enforced"``)
    """

    limit_bytes: Optional[int]
    chunk_bytes: int = DEFAULT_CHUNK_BYTES
    unit: str = UPLOAD_LIMIT_UNIT

    def __post_init__(self) -> None:
        if self.unit != UPLOAD_LIMIT_UNIT:
            raise ValueError(f"upload limit unit must be {UPLOAD_LIMIT_UNIT!r}")
        if self.limit_bytes is not None and int(self.limit_bytes) < 0:
            raise ValueError("limit_bytes must be non-negative or None")

    @property
    def is_unlimited(self) -> bool:
        return self.limit_bytes is None

    @property
    def is_zero_allowance(self) -> bool:
        return self.limit_bytes == 0

    @property
    def policy(self) -> str:
        if self.limit_bytes is None:
            return LIMIT_POLICY_UNLIMITED
        if self.limit_bytes == 0:
            return LIMIT_POLICY_ZERO_ALLOWANCE
        return LIMIT_POLICY_ENFORCED

    def allows_bytes(self, byte_count: int) -> bool:
        count = int(byte_count)
        if count < 0:
            raise ValueError("byte_count must be non-negative")
        if self.limit_bytes is None:
            return True
        return count <= self.limit_bytes

    def to_headers(self) -> dict[str, str]:
        headers = {
            HEADER_UPLOAD_LIMIT_UNIT: UPLOAD_LIMIT_UNIT,
            HEADER_UPLOAD_CHUNK_BYTES: str(self.chunk_bytes),
            HEADER_UPLOAD_LIMIT_POLICY: self.policy,
        }
        if self.limit_bytes is not None:
            headers[HEADER_UPLOAD_MAX_BYTES] = str(self.limit_bytes)
        return headers

    def to_rejection_fields(
        self,
        *,
        observed_bytes: Optional[int] = None,
    ) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "unit": UPLOAD_LIMIT_UNIT,
            "limit_bytes": self.limit_bytes,
            "limit_policy": self.policy,
            "chunk_bytes": self.chunk_bytes,
        }
        if observed_bytes is not None:
            fields["observed_bytes"] = max(0, int(observed_bytes))
        return fields


class UploadLimitExceededError(RequestEntityTooLarge):
    """Raised when an upload stream exceeds a configured byte limit."""

    def __init__(
        self,
        *,
        limit_bytes: int,
        observed_bytes: Optional[int] = None,
    ) -> None:
        normalized_limit = max(0, int(limit_bytes))
        self.limit_bytes = normalized_limit
        self.observed_bytes = (
            max(0, int(observed_bytes)) if observed_bytes is not None else None
        )
        self.unit = UPLOAD_LIMIT_UNIT
        self.limit_policy = (
            LIMIT_POLICY_ZERO_ALLOWANCE
            if normalized_limit == 0
            else LIMIT_POLICY_ENFORCED
        )
        super().__init__(
            f"Upload exceeds size limit ({normalized_limit} {UPLOAD_LIMIT_UNIT})"
        )


def parse_upload_limit_bytes(raw: object) -> tuple[Optional[int], bool]:
    """Parse a raw limit value into ``(limit_bytes, explicit_unlimited)``."""
    if raw is None:
        return None, False
    if isinstance(raw, bool):
        raise ValueError("upload limit bytes must be an integer or 'unlimited'")
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return None, False
        if stripped.lower() in _UNLIMITED_TOKENS:
            return None, True
        try:
            parsed = int(stripped)
        except ValueError as exc:
            raise ValueError(
                "upload limit bytes must be a non-negative integer or 'unlimited'"
            ) from exc
    else:
        try:
            parsed = int(raw)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "upload limit bytes must be a non-negative integer or 'unlimited'"
            ) from exc

    if parsed < 0:
        raise ValueError("upload limit bytes must be non-negative")
    return parsed, False


def apply_upload_limit_headers(
    headers: MutableMapping[str, str],
    spec: UploadLimitSpec,
) -> None:
    """Attach normalized byte-unit upload limit headers to a response mapping."""
    if spec.is_unlimited and HEADER_UPLOAD_MAX_BYTES in headers:
        del headers[HEADER_UPLOAD_MAX_BYTES]
    for key, value in spec.to_headers().items():
        headers[key] = value


def build_upload_limit_rejection_body(
    spec: UploadLimitSpec,
    *,
    message: str = "upload exceeds size limit",
    code: str = "PAYLOAD_TOO_LARGE",
    request_id: Optional[str] = None,
    observed_bytes: Optional[int] = None,
) -> dict[str, Any]:
    """Build a normalized byte-unit 413 error payload without echoing media data."""
    unit_fields = spec.to_rejection_fields(observed_bytes=observed_bytes)
    error_payload: dict[str, Any] = {
        "code": code,
        "message": message,
        **unit_fields,
    }
    if request_id is not None:
        error_payload["request_id"] = request_id
    body: dict[str, Any] = {
        "ok": False,
        "error": error_payload,
        **unit_fields,
    }
    if request_id is not None:
        body["request_id"] = request_id
    return body


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


def resolve_upload_limit_bytes(
    explicit: int | str | None = None,
    *,
    config: object | None = None,
) -> Optional[int]:
    """Resolve the upload limit in bytes, distinguishing ``None`` (unlimited) from ``0`` (zero allowance)."""
    if explicit is not None:
        parsed, is_unlimited = parse_upload_limit_bytes(explicit)
        return None if is_unlimited else parsed

    cfg = config if config is not None else _upload_config()
    if cfg is not None:
        if getattr(cfg, "upload_limit_unlimited", False):
            return None
        raw_upload_max = getattr(cfg, "upload_max_bytes", None)
        if raw_upload_max is not None:
            parsed, is_unlimited = parse_upload_limit_bytes(raw_upload_max)
            return None if is_unlimited else parsed
        raw_video_max = getattr(cfg, "max_video_bytes", None)
        if raw_video_max is not None:
            parsed, is_unlimited = parse_upload_limit_bytes(raw_video_max)
            return None if is_unlimited else parsed
    return None


def resolve_upload_limit_spec(
    explicit_max_bytes: int | str | None = None,
    *,
    explicit_chunk_bytes: int | None = None,
    config: object | None = None,
) -> UploadLimitSpec:
    """Resolve the complete normalized ``UploadLimitSpec`` in byte units."""
    cfg = config if config is not None else _upload_config()
    limit_bytes = resolve_upload_limit_bytes(explicit_max_bytes, config=cfg)
    if explicit_chunk_bytes is not None:
        chunk_bytes = clamp_chunk_bytes(explicit_chunk_bytes, enforce_min=False)
    elif cfg is not None:
        chunk_bytes = clamp_chunk_bytes(
            getattr(cfg, "upload_chunk_bytes", None), enforce_min=True
        )
    else:
        chunk_bytes = DEFAULT_CHUNK_BYTES
    return UploadLimitSpec(limit_bytes=limit_bytes, chunk_bytes=chunk_bytes)


def resolve_max_bytes(explicit: int | None = None) -> int:
    """Legacy integer limit helper retained for compatibility; prefer ``resolve_upload_limit_bytes``."""
    resolved = resolve_upload_limit_bytes(explicit)
    return 0 if resolved is None else resolved


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
    max_size: int | str | None = None,
    temp_dir: str | Path | None = None,
) -> Tuple[str, int]:
    """Copy *source* to *destination* in bounded chunks while hashing SHA-256.

    Returns ``(hex_digest, bytes_written)``.
    Raises ``UploadLimitExceededError`` (a ``RequestEntityTooLarge`` subclass)
    when *max_size* is exceeded mid-stream, including when *max_size* is ``0``
    and one or more bytes arrive. When *max_size* is ``None`` and no config
    ceiling is active, no byte ceiling is enforced.
    """
    spec = resolve_upload_limit_spec(max_size, explicit_chunk_bytes=chunk_size)
    bounded = spec.chunk_bytes
    limit = spec.limit_bytes
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
                next_total = bytes_written + len(chunk)
                if limit is not None and next_total > limit:
                    raise UploadLimitExceededError(
                        limit_bytes=limit,
                        observed_bytes=next_total,
                    )
                tmp_file.write(chunk)
                hasher.update(chunk)
                bytes_written = next_total
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
    max_size: int | str | None = None,
) -> Tuple[str, int]:
    """Concatenate *paths* into *destination* with bounded-chunk SHA-256 hashing."""
    spec = resolve_upload_limit_spec(max_size, explicit_chunk_bytes=chunk_size)
    bounded = spec.chunk_bytes
    limit = spec.limit_bytes
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
                        next_total = bytes_written + len(chunk)
                        if limit is not None and next_total > limit:
                            raise UploadLimitExceededError(
                                limit_bytes=limit,
                                observed_bytes=next_total,
                            )
                        out.write(chunk)
                        hasher.update(chunk)
                        bytes_written = next_total
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
        max_size: int | str | None = None,
        chunk_size: int | None = None,
        temp_dir: str | Path | None = None,
    ):
        super().__init__(stream, filename, content_type=content_type)
        self._limit_spec = resolve_upload_limit_spec(
            max_size, explicit_chunk_bytes=chunk_size
        )
        self._max_size: int | str | None = (
            LIMIT_POLICY_UNLIMITED
            if self._limit_spec.is_unlimited
            else self._limit_spec.limit_bytes
        )
        self._chunk_size = self._limit_spec.chunk_bytes
        self._temp_dir = resolve_temp_dir(temp_dir)
        self._materialized_path: Optional[Path] = None
        self._bytes_written = 0
        self._hash_computed = False
        self._digest: Optional[str] = None

    @property
    def limit_spec(self) -> UploadLimitSpec:
        return self._limit_spec

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
    spec = resolve_upload_limit_spec(config=config)
    temp_dir = resolve_temp_dir(
        getattr(config, "upload_temp_dir", None) if config is not None else None
    )
    return StreamingFileStorage(
        stream=field_storage.stream,
        filename=field_storage.filename,
        content_type=field_storage.content_type,
        max_size=LIMIT_POLICY_UNLIMITED if spec.is_unlimited else spec.limit_bytes,
        chunk_size=spec.chunk_bytes,
        temp_dir=temp_dir,
    )
