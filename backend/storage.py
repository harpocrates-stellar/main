import errno
import logging
import os
import re
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from evidence_storage import assert_safe_destination


@dataclass(frozen=True)
class StorageConfig:
    """Runtime configuration for the local blob store."""

    storage_path: Path
    """Root directory for evidence blobs."""

    protected_paths: frozenset[Path]
    """Canonical paths that blob destinations must not alias."""


def load_storage_config() -> StorageConfig | None:
    """Return a :class:`StorageConfig` built from environment variables.

    Returns ``None`` when ``EVIDENCE_STORAGE_PATH`` is not set, which
    disables local blob storage without raising an error.

    Raises
    ------
    RuntimeError
        When ``EVIDENCE_STORAGE_PATH`` is set but resolves to a path
        that conflicts with a protected file or directory.
    """
    raw = os.getenv("EVIDENCE_STORAGE_PATH", "").strip()
    if not raw:
        return None

    storage_path = Path(raw)
    protected = _collect_protected_paths(storage_path)

    # The storage root itself must not alias any protected path.
    resolved_root = storage_path.resolve()
    for protected_path in protected:
        if _paths_alias(resolved_root, protected_path):
            raise RuntimeError(
                f"EVIDENCE_STORAGE_PATH '{storage_path}' conflicts with "
                f"protected path '{protected_path}'"
            )

    return StorageConfig(
        storage_path=storage_path,
        protected_paths=protected,
    )


class BlobStore:
    """Write and retrieve encrypted evidence blobs under a root directory.

    Parameters
    ----------
    config:
        Storage configuration; obtain via :func:`load_storage_config`.
    """

    def __init__(self, config: StorageConfig) -> None:
        self._config = config

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def write(self, relative_name: str, data: bytes) -> Path:
        """Persist *data* at *relative_name* inside the storage root.

        Parameters
        ----------
        relative_name:
            A simple filename (or a single-level sub-path).  It must not
            contain path traversal sequences.
        data:
            Raw bytes to write; the caller is responsible for encrypting
            the blob before passing it here.

        Returns
        -------
        Path
            The absolute path of the written file.

        Raises
        ------
        ValueError
            When *relative_name* would escape the storage root or alias a
            protected path.
        RuntimeError
            When an I/O error prevents the write.
        """
        destination = self._resolve_destination(relative_name)
        assert_safe_destination(destination, self._config.protected_paths)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        return destination

    def read(self, relative_name: str) -> bytes:
        """Return the raw bytes stored at *relative_name*.

        Raises
        ------
        ValueError
            When *relative_name* would escape the storage root or alias a
            protected path.
        FileNotFoundError
            When no blob exists for the given name.
        """
        destination = self._resolve_destination(relative_name)
        assert_safe_destination(destination, self._config.protected_paths)
        return destination.read_bytes()

    def delete(self, relative_name: str) -> bool:
        """Remove the blob at *relative_name*.

        Returns ``True`` if the file was deleted, ``False`` if it did not
        exist.  Raises :class:`ValueError` on path-safety violations.
        """
        destination = self._resolve_destination(relative_name)
        assert_safe_destination(destination, self._config.protected_paths)
        try:
            destination.unlink()
            return True
        except FileNotFoundError:
            return False

    def collect_unreferenced(self, referenced_names: set[str]) -> list[Path]:
        """Return paths of blobs not in *referenced_names* (for GC).

        Only files directly inside the storage root are considered; the
        caller decides whether to delete them.
        """
        storage_root = self._config.storage_path.resolve()
        if not storage_root.is_dir():
            return []

        unreferenced: list[Path] = []
        for entry in storage_root.iterdir():
            if entry.is_file() and entry.name not in referenced_names:
                unreferenced.append(entry)
        return unreferenced

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _resolve_destination(self, relative_name: str) -> Path:
        """Resolve *relative_name* relative to the storage root.

        Raises :class:`ValueError` when the resolved path escapes the root.
        """
        if not relative_name or not relative_name.strip():
            raise ValueError("evidence blob name must not be empty")

        # Reject obvious traversal markers before resolving.
        candidate = Path(relative_name)
        if candidate.is_absolute():
            raise ValueError(
                f"evidence blob name must be relative, got: {relative_name!r}"
            )

        storage_root = self._config.storage_path.resolve()
        destination = (storage_root / candidate).resolve()

        # Ensure the destination stays inside the storage root.
        try:
            destination.relative_to(storage_root)
        except ValueError:
            raise ValueError(
                f"evidence blob name '{relative_name}' escapes the storage root"
            )

        return destination


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
