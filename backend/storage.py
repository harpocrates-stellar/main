from collections.abc import Iterable
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any
from urllib.parse import unquote, urlparse

LOGGER = logging.getLogger(__name__)

default_storage_dir = "/tmp/harpocrates_jobs"


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
    validate_storage_dir(storage_dir)

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


def _validate_safe_job_id(job_id: int | str) -> str:
    raw = str(job_id)
    if not raw or "/" in raw or "\\" in raw or ".." in raw or "\x00" in raw:
        raise StoragePathAliasError("job_id contains disallowed path traversal characters")
    return raw


def get_job_input_path(job_id: int | str) -> Path:
    safe_id = _validate_safe_job_id(job_id)
    base = get_storage_dir()
    candidate = base / f"job_{safe_id}_input"
    validate_storage_destination(candidate, allowed_root=base)
    return candidate


def get_job_output_path(job_id: int | str) -> Path:
    safe_id = _validate_safe_job_id(job_id)
    base = get_storage_dir()
    candidate = base / f"job_{safe_id}_output"
    validate_storage_destination(candidate, allowed_root=base)
    return candidate


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


PROTECTED_PATH_ALIAS = "PROTECTED_PATH_ALIAS"

_PROTECTED_DB_SUFFIXES = (
    ".db",
    ".sqlite",
    ".sqlite3",
    ".db-wal",
    ".db-shm",
    ".db-journal",
    ".sqlite-wal",
    ".sqlite-shm",
    ".sqlite3-wal",
    ".sqlite3-shm",
)
_PROTECTED_KEY_SUFFIXES = (
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    ".kdbx",
    ".age",
)
_PROTECTED_EXACT_NAMES = frozenset(
    {
        ".env",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "master.key",
        "metadata.db",
    }
)
_PROTECTED_FILE_ENV_VARS = (
    "HARPOCRATES_METADATA_DB_PATH",
    "METADATA_DB_PATH",
    "ANALYTICS_DURABLE_PATH",
    "MASTER_ENCRYPTION_KEY_FILE",
    "HARPOCRATES_KEY_FILE",
    "SSL_KEY_FILE",
    "TLS_KEY_FILE",
)
_PROTECTED_DIR_ENV_VARS = (
    "HARPOCRATES_KEYSTORE_DIR",
    "KEYSTORE_DIR",
)


class StoragePathAliasError(ValueError):
    """Raised when a storage destination aliases a metadata database or key file."""

    reason_code = PROTECTED_PATH_ALIAS

    def __init__(self, message: str = "storage destination aliases a protected metadata database or key path") -> None:
        super().__init__(message)


def _sqlite_paths_from_database_url() -> list[Path]:
    raw_url = os.getenv("DATABASE_URL", "").strip()
    if not raw_url.lower().startswith("sqlite:"):
        return []
    parsed = urlparse(raw_url)
    raw_path = unquote(parsed.path or "")
    if not raw_path or raw_path == "/:memory:" or ":memory:" in raw_url:
        return []
    # Handle Windows sqlite:///C:/path/to/meta.db where urlparse yields /C:/path...
    if os.name == "nt" and len(raw_path) >= 3 and raw_path[0] == "/" and raw_path[2] == ":":
        raw_path = raw_path[1:]
    base = Path(raw_path)
    return [
        base,
        Path(f"{base}-wal"),
        Path(f"{base}-shm"),
        Path(f"{base}-journal"),
    ]


def _configured_protected_targets(
    extra_protected: Iterable[Path | str] = (),
) -> tuple[list[Path], list[Path]]:
    protected_files: list[Path] = []
    protected_dirs: list[Path] = []

    for env_name in _PROTECTED_FILE_ENV_VARS:
        val = os.getenv(env_name)
        if val and val.strip():
            p = Path(val.strip())
            protected_files.append(p)
            if p.suffix.lower() in {".db", ".sqlite", ".sqlite3"}:
                protected_files.extend(
                    [Path(f"{p}-wal"), Path(f"{p}-shm"), Path(f"{p}-journal")]
                )

    protected_files.extend(_sqlite_paths_from_database_url())

    for env_name in _PROTECTED_DIR_ENV_VARS:
        val = os.getenv(env_name)
        if val and val.strip():
            protected_dirs.append(Path(val.strip()))

    for extra in extra_protected:
        p = Path(extra)
        if p.exists() and p.is_dir():
            protected_dirs.append(p)
        else:
            protected_files.append(p)

    return protected_files, protected_dirs


def _norm_resolved(path: Path) -> str:
    resolved = path.expanduser().resolve(strict=False)
    return os.path.normcase(str(resolved))


def _paths_alias_same_inode(candidate: Path, target: Path) -> bool:
    try:
        if candidate.exists() and target.exists():
            return os.path.samefile(candidate, target)
    except OSError:
        return False
    return False


def _is_same_or_subpath(child_norm: str, parent_norm: str) -> bool:
    if child_norm == parent_norm:
        return True
    sep = os.path.normcase(os.sep)
    prefix = parent_norm if parent_norm.endswith(sep) else parent_norm + sep
    return child_norm.startswith(prefix)


def _has_protected_name_or_suffix(path: Path) -> bool:
    name_lower = path.name.lower()
    if name_lower in _PROTECTED_EXACT_NAMES or name_lower.startswith(".env."):
        return True
    if any(name_lower.endswith(sfx) for sfx in _PROTECTED_DB_SUFFIXES):
        return True
    if any(name_lower.endswith(sfx) for sfx in _PROTECTED_KEY_SUFFIXES):
        return True
    return False


def validate_storage_dir(
    storage_dir: Path | str,
    *,
    protected_paths: Iterable[Path | str] = (),
) -> Path:
    """Validate that a storage directory does not alias a metadata DB or key location."""
    if not isinstance(storage_dir, (Path, str)) or not str(storage_dir).strip():
        raise StoragePathAliasError("storage directory must be a non-empty path")
    raw_dir = Path(storage_dir)
    if _has_protected_name_or_suffix(raw_dir):
        raise StoragePathAliasError()
    resolved_dir = raw_dir.expanduser().resolve(strict=False)
    if _has_protected_name_or_suffix(resolved_dir):
        raise StoragePathAliasError()
    if raw_dir.exists() and raw_dir.is_file():
        raise StoragePathAliasError()

    dir_norm = _norm_resolved(raw_dir)
    protected_files, protected_dirs = _configured_protected_targets(protected_paths)

    for pf in protected_files:
        pf_norm = _norm_resolved(pf)
        if dir_norm == pf_norm or _paths_alias_same_inode(raw_dir, pf):
            raise StoragePathAliasError()

    for pd in protected_dirs:
        pd_norm = _norm_resolved(pd)
        if (
            _is_same_or_subpath(dir_norm, pd_norm)
            or _is_same_or_subpath(pd_norm, dir_norm)
            or _paths_alias_same_inode(raw_dir, pd)
        ):
            raise StoragePathAliasError()

    return resolved_dir


def validate_storage_destination(
    destination: Path | str,
    *,
    allowed_root: Path | str | None = None,
    protected_paths: Iterable[Path | str] = (),
) -> Path:
    """Validate a resolved evidence output destination before opening or writing."""
    if not isinstance(destination, (Path, str)) or not str(destination).strip():
        raise StoragePathAliasError("storage destination must be a non-empty path")
    if "\x00" in str(destination):
        raise StoragePathAliasError("storage destination contains invalid null byte")

    raw_dest = Path(destination)
    # Check both raw lexical basename (before symlink resolution) and resolved target
    if _has_protected_name_or_suffix(raw_dest):
        raise StoragePathAliasError()

    resolved_dest = raw_dest.expanduser().resolve(strict=False)
    if _has_protected_name_or_suffix(resolved_dest):
        raise StoragePathAliasError()

    if resolved_dest.exists() and resolved_dest.is_dir():
        raise StoragePathAliasError("storage destination cannot be an existing directory")

    dest_norm = os.path.normcase(str(resolved_dest))

    if allowed_root is not None:
        root_norm = _norm_resolved(Path(allowed_root))
        sep = os.path.normcase(os.sep)
        root_prefix = root_norm if root_norm.endswith(sep) else root_norm + sep
        if not dest_norm.startswith(root_prefix):
            raise StoragePathAliasError("storage destination escapes allowed storage directory")

    protected_files, protected_dirs = _configured_protected_targets(protected_paths)
    for pf in protected_files:
        pf_norm = _norm_resolved(pf)
        if (
            _is_same_or_subpath(dest_norm, pf_norm)
            or _paths_alias_same_inode(raw_dest, pf)
            or _paths_alias_same_inode(resolved_dest, pf)
        ):
            raise StoragePathAliasError()

    for pd in protected_dirs:
        pd_norm = _norm_resolved(pd)
        if (
            _is_same_or_subpath(dest_norm, pd_norm)
            or _paths_alias_same_inode(raw_dest, pd)
            or _paths_alias_same_inode(resolved_dest, pd)
        ):
            raise StoragePathAliasError()

    return resolved_dest


def write_evidence_blob(
    destination: Path | str,
    payload: bytes,
    *,
    allowed_root: Path | str | None = None,
    protected_paths: Iterable[Path | str] = (),
) -> Path:
    """Validate destination pre-write and atomically persist encrypted evidence bytes."""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")
    raw_dest = Path(destination)
    if raw_dest.is_symlink():
        raise StoragePathAliasError("refusing to write evidence through a symbolic link")

    resolved_dest = validate_storage_destination(
        raw_dest,
        allowed_root=allowed_root,
        protected_paths=protected_paths,
    )
    parent = resolved_dest.parent
    validate_storage_dir(parent, protected_paths=protected_paths)
    parent.mkdir(parents=True, exist_ok=True)

    fd: int | None = None
    tmp_name: str | None = None
    try:
        fd, tmp_name = tempfile.mkstemp(dir=str(parent), prefix=".evidence_", suffix=".tmp")
        handle = os.fdopen(fd, "wb")
        fd = None
        with handle:
            handle.write(bytes(payload))
            handle.flush()
        if os.name == "posix":
            try:
                os.chmod(tmp_name, 0o600)
            except OSError:
                pass
        os.replace(tmp_name, resolved_dest)
        tmp_name = None
        return resolved_dest
    except BaseException:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        raise
