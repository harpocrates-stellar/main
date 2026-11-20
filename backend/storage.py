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
