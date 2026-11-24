"""Tests for evidence_storage.assert_safe_destination and storage.BlobStore.

All tests use temporary directories as the storage root so no real
application state is touched.  No production credentials or database
connections are required.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from evidence_storage import assert_safe_destination
from blob_store import BlobStore, StorageConfig, _collect_protected_paths, _paths_alias, load_storage_config


# ---------------------------------------------------------------------------
# assert_safe_destination — core path-alias checks
# ---------------------------------------------------------------------------


class TestAssertSafeDestination:
    """Unit tests for the low-level alias-rejection function."""

    def _protected(self, *paths: Path) -> frozenset[Path]:
        return frozenset(p.resolve() for p in paths)

    def test_safe_path_is_accepted(self, tmp_path: Path) -> None:
        """A destination outside any protected path raises nothing."""
        safe = tmp_path / "evidence" / "abc123.bin"
        protected = self._protected(tmp_path / "keys" / "secret.pem")
        assert_safe_destination(safe, protected)  # must not raise

    def test_exact_match_is_rejected(self, tmp_path: Path) -> None:
        """A destination identical to a protected file is rejected."""
        key_file = tmp_path / "keys" / "secret.pem"
        with pytest.raises(ValueError, match="aliases protected path"):
            assert_safe_destination(key_file, self._protected(key_file))

    def test_destination_inside_protected_directory_is_rejected(self, tmp_path: Path) -> None:
        """A destination that is a child of a protected directory is rejected."""
        source_tree = tmp_path / "app"
        destination = source_tree / "config.py"
        with pytest.raises(ValueError, match="inside a protected directory"):
            assert_safe_destination(destination, self._protected(source_tree))

    def test_destination_that_is_parent_of_protected_file_is_rejected(self, tmp_path: Path) -> None:
        """A destination that *contains* a protected file is rejected.

        Writing to a directory that holds the metadata DB would replace
        the directory entry — that must not be allowed.
        """
        db_dir = tmp_path / "data"
        db_file = db_dir / "metadata.db"
        # destination == db_dir (the directory that holds the DB file)
        with pytest.raises(ValueError, match="parent of a protected path"):
            assert_safe_destination(db_dir, self._protected(db_file))

    def test_symlink_to_protected_file_is_rejected(self, tmp_path: Path) -> None:
        """A symlink whose target resolves to a protected file is rejected."""
        real_key = tmp_path / "real_keys" / "secret.pem"
        real_key.parent.mkdir(parents=True)
        real_key.write_bytes(b"key material")

        link = tmp_path / "evidence" / "link_to_key"
        link.parent.mkdir(parents=True)
        link.symlink_to(real_key)

        with pytest.raises(ValueError, match="aliases protected path"):
            assert_safe_destination(link, frozenset({real_key.resolve()}))

    def test_symlink_to_protected_directory_is_rejected(self, tmp_path: Path) -> None:
        """A symlink whose target resolves to a protected directory is rejected."""
        source_tree = tmp_path / "app"
        source_tree.mkdir()

        link = tmp_path / "evidence" / "sneaky_link"
        link.parent.mkdir(parents=True)
        link.symlink_to(source_tree)

        with pytest.raises(ValueError, match="aliases protected path"):
            assert_safe_destination(link, frozenset({source_tree.resolve()}))

    def test_dotdot_traversal_to_protected_file_is_rejected(self, tmp_path: Path) -> None:
        """Path-traversal via ``..`` components is resolved and rejected."""
        key_file = (tmp_path / "keys" / "secret.pem").resolve()
        traversal = tmp_path / "evidence" / ".." / "keys" / "secret.pem"

        with pytest.raises(ValueError, match="aliases protected path"):
            assert_safe_destination(traversal, frozenset({key_file}))

    def test_empty_protected_set_always_accepts(self, tmp_path: Path) -> None:
        """With no protected paths every destination is acceptable."""
        destination = tmp_path / "output" / "blob.bin"
        assert_safe_destination(destination, frozenset())  # must not raise

    def test_multiple_protected_paths_any_match_rejects(self, tmp_path: Path) -> None:
        """When multiple protected paths are given, a match against any one rejects."""
        key_a = tmp_path / "keyA.pem"
        key_b = tmp_path / "keyB.pem"
        protected = frozenset({key_a.resolve(), key_b.resolve()})

        with pytest.raises(ValueError):
            assert_safe_destination(key_b, protected)

    def test_path_in_different_unprotected_subtree_is_accepted(self, tmp_path: Path) -> None:
        """A path in a different subtree from the protected paths is fine."""
        protected_dir = tmp_path / "protected"
        safe_dir = tmp_path / "safe"
        destination = safe_dir / "output.bin"

        # The directories don't even need to exist on disk for path checks.
        assert_safe_destination(destination, frozenset({protected_dir.resolve()}))


# ---------------------------------------------------------------------------
# BlobStore — write / read / delete / escape prevention
# ---------------------------------------------------------------------------


class TestBlobStore:
    """Integration-style tests for BlobStore using a real temp directory."""

    def _make_store(self, tmp_path: Path, extra_protected: frozenset[Path] | None = None) -> BlobStore:
        storage_root = tmp_path / "blobs"
        storage_root.mkdir()
        protected = frozenset({(tmp_path / "protected_key.pem").resolve()})
        if extra_protected:
            protected = protected | extra_protected
        config = StorageConfig(storage_path=storage_root, protected_paths=protected)
        return BlobStore(config)

    # --- write ---

    def test_write_creates_file_with_correct_content(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.write("abc123.bin", b"encrypted evidence")
        dest = tmp_path / "blobs" / "abc123.bin"
        assert dest.exists()
        assert dest.read_bytes() == b"encrypted evidence"

    def test_write_returns_absolute_path(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        result = store.write("output.bin", b"data")
        assert result.is_absolute()
        assert result == (tmp_path / "blobs" / "output.bin").resolve()

    def test_write_creates_subdirectory_as_needed(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.write("2026/11/abc.bin", b"blob")
        assert (tmp_path / "blobs" / "2026" / "11" / "abc.bin").exists()

    def test_write_rejects_empty_name(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        with pytest.raises(ValueError, match="must not be empty"):
            store.write("", b"data")

    def test_write_rejects_absolute_name(self, tmp_path: Path) -> None:
        """An absolute-style name is either caught early (Unix) or by the
        escape check (Windows, where '/etc/passwd' is relative-to-cwd)."""
        store = self._make_store(tmp_path)
        with pytest.raises(ValueError):
            store.write("/etc/passwd", b"data")

    def test_write_rejects_traversal_escaping_root(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        with pytest.raises(ValueError, match="escapes the storage root"):
            store.write("../../etc/passwd", b"data")

    def test_write_rejects_destination_aliasing_protected_key(self, tmp_path: Path) -> None:
        """A symlink inside the blob root that resolves to a protected key file is rejected.

        Depending on where the symlink target resolves, the rejection may come
        from the root-escape check (target is outside the blob root) or from
        assert_safe_destination (target is inside the blob root but aliases a
        protected file).  Either way, a ValueError is raised.
        """
        key_file = tmp_path / "protected_key.pem"
        store = self._make_store(tmp_path)
        link_name = "link_to_key.bin"
        link_path = tmp_path / "blobs" / link_name
        key_file.write_bytes(b"private key")
        link_path.symlink_to(key_file)

        with pytest.raises(ValueError):
            store.write(link_name, b"evil blob")

    def test_write_rejects_destination_inside_protected_directory(self, tmp_path: Path) -> None:
        """A symlink inside the blob root that points into a protected dir is rejected.

        The symlink resolves outside the blob root so the escape check fires;
        if it were somehow inside, assert_safe_destination would catch it.
        Either way a ValueError is raised before any write occurs.
        """
        protected_dir = tmp_path / "app_source"
        protected_dir.mkdir()
        store = self._make_store(tmp_path, extra_protected=frozenset({protected_dir.resolve()}))

        link = tmp_path / "blobs" / "sneaky"
        link.symlink_to(protected_dir)

        with pytest.raises(ValueError):
            store.write("sneaky/config.py", b"overwrite source")

    # --- read ---

    def test_read_returns_stored_bytes(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.write("file.bin", b"content")
        assert store.read("file.bin") == b"content"

    def test_read_raises_file_not_found_for_missing_blob(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        with pytest.raises(FileNotFoundError):
            store.read("nonexistent.bin")

    def test_read_rejects_traversal(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        with pytest.raises(ValueError, match="escapes the storage root"):
            store.read("../outside.bin")

    # --- delete ---

    def test_delete_removes_existing_file(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.write("del.bin", b"x")
        removed = store.delete("del.bin")
        assert removed is True
        assert not (tmp_path / "blobs" / "del.bin").exists()

    def test_delete_returns_false_for_nonexistent_file(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        assert store.delete("ghost.bin") is False

    def test_delete_rejects_traversal(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        with pytest.raises(ValueError, match="escapes the storage root"):
            store.delete("../../etc/important")

    # --- collect_unreferenced ---

    def test_collect_unreferenced_returns_untracked_files(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.write("a.bin", b"a")
        store.write("b.bin", b"b")
        store.write("c.bin", b"c")
        unreferenced = store.collect_unreferenced({"a.bin", "c.bin"})
        names = {p.name for p in unreferenced}
        assert names == {"b.bin"}

    def test_collect_unreferenced_returns_empty_when_all_referenced(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.write("a.bin", b"a")
        assert store.collect_unreferenced({"a.bin"}) == []

    def test_collect_unreferenced_returns_empty_for_missing_root(self, tmp_path: Path) -> None:
        empty_root = tmp_path / "nonexistent_blobs"
        config = StorageConfig(storage_path=empty_root, protected_paths=frozenset())
        store = BlobStore(config)
        assert store.collect_unreferenced(set()) == []


# ---------------------------------------------------------------------------
# _collect_protected_paths — environment variable handling
# ---------------------------------------------------------------------------


class TestCollectProtectedPaths:
    """Verify that environment variables correctly influence the protected set."""

    def test_always_includes_source_root(self, tmp_path: Path) -> None:
        """The application source directory is always protected."""
        import blob_store as storage_module

        with patch.dict(os.environ, {}, clear=False):
            protected = _collect_protected_paths(tmp_path)

        source_root = Path(storage_module.__file__).resolve().parent
        assert source_root in protected

    def test_includes_key_file_when_configured(self, tmp_path: Path) -> None:
        key_file = str(tmp_path / "app.key")
        with patch.dict(os.environ, {"EVIDENCE_STORAGE_KEY_FILE": key_file}):
            protected = _collect_protected_paths(tmp_path)
        assert Path(key_file).resolve() in protected

    def test_excludes_key_file_when_not_configured(self, tmp_path: Path) -> None:
        env = {k: v for k, v in os.environ.items() if k != "EVIDENCE_STORAGE_KEY_FILE"}
        with patch.dict(os.environ, env, clear=True):
            protected = _collect_protected_paths(tmp_path)
        # None of the protected paths should look like a key file from env
        assert all("app.key" not in str(p) for p in protected)

    def test_includes_sqlite_database_file(self, tmp_path: Path) -> None:
        db_path = str(tmp_path / "metadata.db")
        db_url = f"sqlite:///{db_path}"
        with patch.dict(os.environ, {"DATABASE_URL": db_url}):
            protected = _collect_protected_paths(tmp_path)
        assert Path(db_path).resolve() in protected

    def test_ignores_postgresql_database_url(self, tmp_path: Path) -> None:
        pg_url = "postgresql://user:pass@host/db?sslmode=require"
        with patch.dict(os.environ, {"DATABASE_URL": pg_url}):
            protected = _collect_protected_paths(tmp_path)
        # No entry in the protected set should contain "postgresql" as a path
        assert all("postgresql" not in str(p) for p in protected)


# ---------------------------------------------------------------------------
# load_storage_config — full config construction
# ---------------------------------------------------------------------------


class TestLoadStorageConfig:
    """Test the top-level config loader, including storage-root conflict detection."""

    def test_returns_none_when_path_not_set(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "EVIDENCE_STORAGE_PATH"}
        with patch.dict(os.environ, env, clear=True):
            assert load_storage_config() is None

    def test_returns_config_for_valid_path(self, tmp_path: Path) -> None:
        storage_dir = str(tmp_path / "evidence")
        with patch.dict(os.environ, {"EVIDENCE_STORAGE_PATH": storage_dir}, clear=False):
            config = load_storage_config()
        assert config is not None
        assert config.storage_path == Path(storage_dir)

    def test_raises_when_storage_path_aliases_source_root(self) -> None:
        """Configuring EVIDENCE_STORAGE_PATH to the app source dir is rejected at load time."""
        import blob_store as storage_module

        source_root = str(Path(storage_module.__file__).resolve().parent)
        with patch.dict(os.environ, {"EVIDENCE_STORAGE_PATH": source_root}, clear=False):
            with pytest.raises(RuntimeError, match="conflicts with protected path"):
                load_storage_config()

    def test_raises_when_storage_path_aliases_sqlite_db(self, tmp_path: Path) -> None:
        """EVIDENCE_STORAGE_PATH must not alias the SQLite metadata database."""
        db_path = tmp_path / "metadata.db"
        db_path.write_bytes(b"")
        env = {
            "EVIDENCE_STORAGE_PATH": str(db_path),
            "DATABASE_URL": f"sqlite:///{db_path}",
        }
        with patch.dict(os.environ, env, clear=False):
            with pytest.raises(RuntimeError, match="conflicts with protected path"):
                load_storage_config()

    def test_raises_when_storage_path_aliases_key_file(self, tmp_path: Path) -> None:
        """EVIDENCE_STORAGE_PATH must not alias the encryption key file."""
        key_file = tmp_path / "secret.pem"
        key_file.write_bytes(b"key")
        env = {
            "EVIDENCE_STORAGE_PATH": str(key_file),
            "EVIDENCE_STORAGE_KEY_FILE": str(key_file),
        }
        with patch.dict(os.environ, env, clear=False):
            with pytest.raises(RuntimeError, match="conflicts with protected path"):
                load_storage_config()


# ---------------------------------------------------------------------------
# _paths_alias helper
# ---------------------------------------------------------------------------


class TestPathsAlias:
    """Unit tests for the _paths_alias helper used in storage root validation."""

    def test_identical_paths_alias(self, tmp_path: Path) -> None:
        p = tmp_path / "file.txt"
        assert _paths_alias(p, p) is True

    def test_child_aliases_parent_directory(self, tmp_path: Path) -> None:
        parent = tmp_path / "dir"
        child = parent / "file.txt"
        assert _paths_alias(child, parent) is True

    def test_parent_aliases_child(self, tmp_path: Path) -> None:
        parent = tmp_path / "dir"
        child = parent / "file.txt"
        assert _paths_alias(parent, child) is True

    def test_sibling_paths_do_not_alias(self, tmp_path: Path) -> None:
        a = tmp_path / "dir_a" / "file.txt"
        b = tmp_path / "dir_b" / "file.txt"
        assert _paths_alias(a, b) is False
