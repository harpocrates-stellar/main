"""Local blob store for encrypted evidence files.

Evidence is written to a configurable directory (``EVIDENCE_STORAGE_PATH``).
Before any write the destination path is validated by
:func:`evidence_storage.assert_safe_destination` so that it can never
alias the metadata database file, encryption-key material, or the
application's own source tree.

Environment variables
---------------------
EVIDENCE_STORAGE_PATH
    Absolute path to the directory that receives evidence blobs.
    Required when local storage is enabled.  The directory is created on
    first use if it does not already exist.
EVIDENCE_STORAGE_KEY_FILE
    Optional path to a file that holds the symmetric encryption key.
    When set it is added to the protected-paths set so that evidence
    blobs can never overwrite it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
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


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _collect_protected_paths(storage_path: Path) -> frozenset[Path]:
    """Build the set of canonical paths that destinations must not alias.

    Always protects:

    * The application source directory (the directory containing this
      file, resolved to its real path).
    * The key file named by ``EVIDENCE_STORAGE_KEY_FILE``, if set.
    * The database file named by ``DATABASE_URL`` when it uses the
      ``sqlite:///`` scheme (the PostgreSQL URL used in production does
      not map to a local path).

    Parameters
    ----------
    storage_path:
        The configured storage root; included so callers can pass it
        through ``assert_safe_destination`` for the root-conflict check.
    """
    protected: set[Path] = set()

    # --- application source tree ---
    source_root = Path(__file__).resolve().parent
    protected.add(source_root)

    # --- optional encryption-key file ---
    key_file_raw = os.getenv("EVIDENCE_STORAGE_KEY_FILE", "").strip()
    if key_file_raw:
        protected.add(Path(key_file_raw).resolve())

    # --- SQLite metadata database (if DATABASE_URL points to a file) ---
    db_url = os.getenv("DATABASE_URL", "").strip()
    if db_url.startswith("sqlite:///"):
        db_file_path = db_url[len("sqlite:///"):]
        if db_file_path:
            protected.add(Path(db_file_path).resolve())

    return frozenset(protected)


def _paths_alias(resolved_a: Path, resolved_b: Path) -> bool:
    """Return ``True`` when *a* is equal to or a child of *b*, or vice-versa."""
    if resolved_a == resolved_b:
        return True
    try:
        resolved_a.relative_to(resolved_b)
        return True
    except ValueError:
        pass
    try:
        resolved_b.relative_to(resolved_a)
        return True
    except ValueError:
        pass
    return False


# --- restored from history ---
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

