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

_BACKEND_DIR = str(Path(__file__).resolve().parent)
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import evidence_storage
from metrics import collector as metrics_collector


class FakeRow(dict):
    """Row mapping returned by FakeCursor.fetchone()."""


class FakeCursor:
    """In-memory fake cursor capturing SQL statements, parameters, and state."""

    def __init__(self, connection: "FakeConnection") -> None:
        self.connection = connection
        self.executed: list[tuple[str, tuple]] = []
        self._last_row: FakeRow | None = None
        self._results: list[FakeRow] = []
        self._idx: int = 0

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        return None

    def execute(self, sql: str, params: tuple = ()) -> None:
        self.executed.append((sql, params))
        normalized = " ".join(sql.lower().split())

        if normalized.startswith("insert into blobs"):
            if len(params) == 5:
                content_hash, encrypted_dek, size_bytes, storage_path, envelope_version = params
            else:
                content_hash, encrypted_dek, size_bytes, storage_path = params
                envelope_version = None
            # ON CONFLICT (content_hash) DO NOTHING
            with self.connection.lock:
                if content_hash not in self.connection.blobs:
                    self.connection.blobs[content_hash] = {
                        "content_hash": content_hash,
                        "encrypted_dek": encrypted_dek,
                        "size_bytes": size_bytes,
                        "storage_path": storage_path,
                        "envelope_version": envelope_version,
                        "created_at": time.time(),
                    }
            self._last_row = None

        elif normalized.startswith("insert into tenant_blob_refs"):
            tenant_id, content_hash = params
            key = (tenant_id, content_hash)
            # ON CONFLICT (tenant_id, content_hash) DO UPDATE SET ref_count = ref_count + 1
            with self.connection.lock:
                if key in self.connection.tenant_refs:
                    self.connection.tenant_refs[key]["ref_count"] += 1
                else:
                    self.connection.tenant_refs[key] = {
                        "tenant_id": tenant_id,
                        "content_hash": content_hash,
                        "ref_count": 1,
                    }
            self._last_row = None

        elif normalized.startswith("select encrypted_dek, storage_path, envelope_version from blobs"):
            (content_hash,) = params
            with self.connection.lock:
                blob = self.connection.blobs.get(content_hash)
                if blob is None:
                    self._last_row = None
                else:
                    self._last_row = FakeRow(
                        encrypted_dek=blob["encrypted_dek"],
                        storage_path=blob["storage_path"],
                        envelope_version=blob.get("envelope_version"),
                    )

        elif "select ref_count from tenant_blob_refs" in normalized:
            tenant_id, content_hash = params[0], params[1]
            key = (tenant_id, content_hash)
            with self.connection.lock:
                if key in self.connection.tenant_refs:
                    self._last_row = FakeRow(ref_count=self.connection.tenant_refs[key]["ref_count"])
                else:
                    self._last_row = None

        elif "update tenant_blob_refs" in normalized:
            tenant_id, content_hash = params[0], params[1]
            key = (tenant_id, content_hash)
            with self.connection.lock:
                if key in self.connection.tenant_refs:
                    self.connection.tenant_refs[key]["ref_count"] -= 1

        elif "delete from tenant_blob_refs" in normalized:
            tenant_id, content_hash = params[0], params[1]
            key = (tenant_id, content_hash)
            with self.connection.lock:
                self.connection.tenant_refs.pop(key, None)

        elif "select content_hash, storage_path from blobs" in normalized and "where not exists" in normalized:
            limit = params[0]
            with self.connection.lock:
                unreferenced = []
                for h, b in sorted(self.connection.blobs.items(), key=lambda item: item[1].get("created_at", 0)):
                    has_ref = any(
                        ref["content_hash"] == h and ref["ref_count"] > 0
                        for ref in self.connection.tenant_refs.values()
                    )
                    if not has_ref:
                        unreferenced.append(b)
                        if len(unreferenced) >= limit:
                            break

            for b in unreferenced:
                row_lock = self.connection.get_row_lock(b["content_hash"])
                row_lock.acquire()
                self.connection.held_locks.append(row_lock)

            if self.connection.before_collector_delete_hook:
                self.connection.before_collector_delete_hook()

            self._results = [
                FakeRow(content_hash=b["content_hash"], storage_path=b["storage_path"])
                for b in unreferenced
            ]
            self._idx = 0

        elif "delete from blobs where content_hash = %s" in normalized:
            content_hash = params[0]
            with self.connection.lock:
                self.connection.blobs.pop(content_hash, None)
                to_delete = [k for k, v in self.connection.tenant_refs.items() if v["content_hash"] == content_hash]
                for k in to_delete:
                    del self.connection.tenant_refs[k]

        elif "from tenant_blob_refs r join blobs b" in normalized:
            (tenant_id,) = params
            with self.connection.lock:
                matched = []
                for (ref_tenant, content_hash), ref in self.connection.tenant_refs.items():
                    if ref_tenant != tenant_id or ref["ref_count"] <= 0:
                        continue
                    blob = self.connection.blobs.get(content_hash)
                    if blob is None:
                        continue
                    shared = any(
                        other_tenant != tenant_id
                        and other_hash == content_hash
                        and other_ref["ref_count"] > 0
                        for (other_tenant, other_hash), other_ref in self.connection.tenant_refs.items()
                    )
                    matched.append(
                        FakeRow(
                            content_hash=content_hash,
                            ref_count=ref["ref_count"],
                            size_bytes=blob["size_bytes"],
                            created_at=blob["created_at"],
                            shared_with_other_tenants=shared,
                        )
                    )
                matched.sort(key=lambda r: (r["created_at"], r["content_hash"]))
            self._results = matched
            self._idx = 0

    def fetchone(self) -> FakeRow | None:
        if self._results and self._idx < len(self._results):
            row = self._results[self._idx]
            self._idx += 1
            return row
        return self._last_row

    def fetchall(self) -> list[FakeRow]:
        res = self._results[self._idx:]
        self._idx = len(self._results)
        return res


class FakeConnection:
    """In-memory fake Postgres connection supporting cursor context managers."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.blobs: dict[str, dict] = {}
        self.tenant_refs: dict[tuple[str, str], dict] = {}
        self.cursors: list[FakeCursor] = []
        self.commits: int = 0
        self.row_locks: dict[str, threading.Lock] = {}
        self.row_locks_guard = threading.Lock()
        self.held_locks: list[threading.Lock] = []
        self.before_collector_delete_hook = None

    def get_row_lock(self, content_hash: str) -> threading.Lock:
        with self.row_locks_guard:
            if content_hash not in self.row_locks:
                self.row_locks[content_hash] = threading.Lock()
            return self.row_locks[content_hash]

    @property
    def executed(self) -> list[tuple[str, tuple]]:
        return [call for cur in self.cursors for call in cur.executed]

    def cursor(self) -> FakeCursor:
        cur = FakeCursor(self)
        self.cursors.append(cur)
        return cur

    def commit(self) -> None:
        self.commits += 1
        for lock in self.held_locks:
            lock.release()
        self.held_locks.clear()

    def rollback(self) -> None:
        for lock in self.held_locks:
            lock.release()
        self.held_locks.clear()

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()


@pytest.fixture
def fake_db(monkeypatch: pytest.MonkeyPatch) -> FakeConnection:
    """Fixture providing a fake db.get_connection context manager and connection."""
    conn = FakeConnection()

    @contextmanager
    def _fake_get_connection():
        yield conn

    monkeypatch.setattr(evidence_storage.db, "get_connection", _fake_get_connection)
    metrics_collector.reset()
    yield conn
    metrics_collector.reset()


@pytest.fixture
def master_key(monkeypatch: pytest.MonkeyPatch) -> str:
    """Fixture configuring a deterministic valid Fernet MASTER_ENCRYPTION_KEY."""
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("MASTER_ENCRYPTION_KEY", key)
    return key


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

    assert fake_db.commits == 1
    assert len(fake_db.executed) == 1
    sql, params = fake_db.executed[0]
    normalized_sql = " ".join(sql.lower().split())
    assert "insert into blobs (content_hash, encrypted_dek, size_bytes, storage_path, envelope_version)" in normalized_sql
    assert "values (%s, %s, %s, %s, %s)" in normalized_sql
    assert "on conflict (content_hash) do nothing" in normalized_sql
    assert params == (
        content_hash,
        encrypted_dek.decode(),
        size_bytes,
        storage_path,
        evidence_storage.DEFAULT_ENVELOPE_VERSION,
    )

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

    assert fake_db.commits == 2
    assert len(fake_db.executed) == 2
    assert fake_db.executed[0][1] == (
        content_hash,
        first_dek.decode(),
        1024,
        "/blobs/first",
        evidence_storage.DEFAULT_ENVELOPE_VERSION,
    )
    assert fake_db.executed[1][1] == (
        content_hash,
        second_dek.decode(),
        9999,
        "/blobs/second",
        evidence_storage.DEFAULT_ENVELOPE_VERSION,
    )

    # Duplicate content_hash preserves the original blob entry (DO NOTHING)
    info = evidence_storage.get_blob_info(content_hash)
    assert info == {
        "encrypted_dek": first_dek.decode(),
        "storage_path": "/blobs/first",
        "envelope_version": evidence_storage.DEFAULT_ENVELOPE_VERSION,
    }

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

    assert evidence_storage.get_blob_info(unknown_hash) is None
    sql, params = fake_db.executed[-1]
    assert "select encrypted_dek, storage_path, envelope_version from blobs where content_hash = %s" in " ".join(
        sql.lower().split()
    )
    assert params == (unknown_hash,)

    def test_read_returns_stored_bytes(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.write("file.bin", b"content")
        assert store.read("file.bin") == b"content"

    assert result == {
        "encrypted_dek": encrypted_dek.decode(),
        "storage_path": storage_path,
        "envelope_version": evidence_storage.DEFAULT_ENVELOPE_VERSION,
    }
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# _collect_protected_paths — environment variable handling
# ---------------------------------------------------------------------------


class TestCollectProtectedPaths:
    """Verify that environment variables correctly influence the protected set."""

    def test_always_includes_source_root(self, tmp_path: Path) -> None:
        """The application source directory is always protected."""
        import storage as storage_module

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
        import storage as storage_module

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


def test_preview_tenant_retention_rejects_invalid_inputs(fake_db: FakeConnection) -> None:
    with pytest.raises(ValueError, match="tenant_id must be a non-empty string"):
        evidence_storage.preview_tenant_retention("")

    with pytest.raises(ValueError, match="tenant_id must be a non-empty string"):
        evidence_storage.preview_tenant_retention("   ")

    with pytest.raises(ValueError, match="ttl_seconds must be a non-negative number"):
        evidence_storage.preview_tenant_retention("tenant_a", ttl_seconds=-1)

    with pytest.raises(ValueError, match="ttl_seconds must be a non-negative number"):
        evidence_storage.preview_tenant_retention("tenant_a", ttl_seconds=True)


class EvidenceStorageUnittestSuite(unittest.TestCase):
    """Unittest-compatible test case so `python -m unittest discover` also exercises the suite."""

    def setUp(self) -> None:
        self.conn = FakeConnection()

        @contextmanager
        def _fake_get_connection():
            yield self.conn

        self._conn_patch = patch.object(
            evidence_storage.db, "get_connection", _fake_get_connection
        )
        self._conn_patch.start()
        self.master_key = Fernet.generate_key().decode("ascii")
        self._env_patch = patch.dict(
            os.environ, {"MASTER_ENCRYPTION_KEY": self.master_key}, clear=False
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        self._conn_patch.stop()

    def test_end_to_end_blob_lifecycle_without_postgres(self) -> None:
        dek, encrypted_dek = evidence_storage.generate_dek()
        encryptor = evidence_storage.get_encryptor(dek)
        ciphertext = encryptor.encrypt(b"evidence-bytes")

        content_hash = "e" * 64
        self.assertIsNone(evidence_storage.get_blob_info(content_hash))

        evidence_storage.record_blob(content_hash, encrypted_dek, len(ciphertext), "/blobs/ee")
        evidence_storage.record_blob(content_hash, b"ignored-duplicate", 0, "/blobs/other")
        evidence_storage.record_tenant_ref("tenant-1", content_hash)
        evidence_storage.record_tenant_ref("tenant-1", content_hash)

        blob_info = evidence_storage.get_blob_info(content_hash)
        self.assertEqual(
            blob_info,
            {
                "encrypted_dek": encrypted_dek.decode(),
                "storage_path": "/blobs/ee",
                "envelope_version": evidence_storage.DEFAULT_ENVELOPE_VERSION,
            },
        )
        unwrapped_dek = evidence_storage.decrypt_dek(
            blob_info["encrypted_dek"].encode("ascii")
        )
        self.assertEqual(unwrapped_dek, dek)
        self.assertEqual(
            evidence_storage.decrypt_blob_ciphertext(
                unwrapped_dek,
                ciphertext,
                envelope_version=blob_info["envelope_version"],
            ),
            b"evidence-bytes",
        )


# ---------------------------------------------------------------------------
# Encryption envelope version tests
# ---------------------------------------------------------------------------


def test_classify_envelope_version_distinguishes_supported_legacy_and_unsupported() -> None:
    assert (
        evidence_storage.classify_envelope_version(evidence_storage.ENVELOPE_VERSION_FERNET_V1)
        == evidence_storage.ENVELOPE_CLASS_SUPPORTED
    )
    assert (
        evidence_storage.classify_envelope_version("  fernet-v1  ")
        == evidence_storage.ENVELOPE_CLASS_SUPPORTED
    )

    # Known legacy formats (including pre-versioning NULL metadata)
    assert evidence_storage.classify_envelope_version(None) == evidence_storage.ENVELOPE_CLASS_LEGACY
    assert evidence_storage.classify_envelope_version("legacy-v0") == evidence_storage.ENVELOPE_CLASS_LEGACY
    assert evidence_storage.classify_envelope_version("fernet-v0") == evidence_storage.ENVELOPE_CLASS_LEGACY

    # Unsupported formats
    for bad in ("", "   ", "aes-gcm-v2", "fernet-v99", "unknown", 1, True, b"fernet-v1"):
        assert (
            evidence_storage.classify_envelope_version(bad)
            == evidence_storage.ENVELOPE_CLASS_UNSUPPORTED
        )


def test_record_blob_rejects_legacy_and_unsupported_envelope_versions(
    fake_db: FakeConnection,
) -> None:
    content_hash = "f" * 64
    encrypted_dek = b"gAAAAABk-fake-dek"

    with pytest.raises(evidence_storage.LegacyEnvelopeVersionError):
        evidence_storage.record_blob(
            content_hash, encrypted_dek, 128, "/blobs/legacy", envelope_version="legacy-v0"
        )

    with pytest.raises(evidence_storage.UnsupportedEnvelopeVersionError):
        evidence_storage.record_blob(
            content_hash, encrypted_dek, 128, "/blobs/unknown", envelope_version="aes-gcm-v2"
        )

    with pytest.raises(evidence_storage.UnsupportedEnvelopeVersionError):
        evidence_storage.record_blob(
            content_hash, encrypted_dek, 128, "/blobs/empty", envelope_version="   "
        )

    assert fake_db.commits == 0
    assert fake_db.executed == []


def test_decrypt_blob_ciphertext_never_guesses_algorithm_from_malformed_ciphertext() -> None:
    dek = Fernet.generate_key()
    plaintext = b"synthetic-evidence-envelope-test"
    valid_ciphertext = evidence_storage.get_encryptor(dek).encrypt(plaintext)

    # Supported explicit version decrypts cleanly
    assert (
        evidence_storage.decrypt_blob_ciphertext(
            dek, valid_ciphertext, envelope_version=evidence_storage.ENVELOPE_VERSION_FERNET_V1
        )
        == plaintext
    )

    # Pre-versioning legacy row (None) remains compatible with Fernet
    assert (
        evidence_storage.decrypt_blob_ciphertext(dek, valid_ciphertext, envelope_version=None)
        == plaintext
    )

    # Malformed ciphertext fails closed with InvalidToken (never guesses another algorithm)
    for malformed in (b"", b"not-fernet", b"\x00\x01\x02aes-gcm-like-header", valid_ciphertext[:-4]):
        with pytest.raises(InvalidToken):
            evidence_storage.decrypt_blob_ciphertext(
                dek, malformed, envelope_version=evidence_storage.ENVELOPE_VERSION_FERNET_V1
            )

    # Known legacy version raises LegacyEnvelopeVersionError without attempting decryption
    with pytest.raises(evidence_storage.LegacyEnvelopeVersionError):
        evidence_storage.decrypt_blob_ciphertext(dek, valid_ciphertext, envelope_version="legacy-v0")

    # Unsupported version raises UnsupportedEnvelopeVersionError even if ciphertext is valid Fernet
    with pytest.raises(evidence_storage.UnsupportedEnvelopeVersionError):
        evidence_storage.decrypt_blob_ciphertext(dek, valid_ciphertext, envelope_version="aes-gcm-v2")


def test_verify_blob_integrity_distinguishes_legacy_and_unsupported_envelope_versions(
    tmp_path: Path,
    master_key: str,
) -> None:
    dek, encrypted_dek = evidence_storage.generate_dek()
    plaintext = b"synthetic-envelope-verify"
    ciphertext = evidence_storage.get_encryptor(dek).encrypt(plaintext)
    blob_path = tmp_path / "envelope.bin"
    blob_path.write_bytes(ciphertext)
    import hashlib

    base_record = {
        "content_hash": hashlib.sha256(plaintext).hexdigest(),
        "encrypted_dek": encrypted_dek.decode("utf-8"),
        "size_bytes": len(ciphertext),
        "storage_path": str(blob_path),
    }

    # Explicit supported version verifies
    res_supported = evidence_storage.verify_blob_integrity(
        dict(base_record, envelope_version=evidence_storage.ENVELOPE_VERSION_FERNET_V1)
    )
    assert res_supported["status"] == evidence_storage.STATUS_VERIFIED
    assert res_supported["reason"] == "ok"

    # Pre-versioning legacy row (envelope_version=None) remains compatible
    res_unversioned = evidence_storage.verify_blob_integrity(dict(base_record, envelope_version=None))
    assert res_unversioned["status"] == evidence_storage.STATUS_VERIFIED
    assert res_unversioned["reason"] == "ok"

    # Known legacy envelope version -> unverifiable_legacy (distinct from unsupported)
    res_legacy = evidence_storage.verify_blob_integrity(
        dict(base_record, envelope_version="legacy-v0")
    )
    assert res_legacy["status"] == evidence_storage.STATUS_UNVERIFIABLE_LEGACY
    assert res_legacy["reason"] == "legacy_envelope_version"

    # Unsupported envelope version -> failed (never guesses algorithm even on valid ciphertext)
    res_unsupported = evidence_storage.verify_blob_integrity(
        dict(base_record, envelope_version="aes-gcm-v2")
    )
    assert res_unsupported["status"] == evidence_storage.STATUS_FAILED
    assert res_unsupported["reason"] == "unsupported_envelope_version"


if __name__ == "__main__":
    unittest.main()
