"""Unit tests for backend/evidence_storage.py without a live Postgres database."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet, InvalidToken
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
            content_hash, encrypted_dek, size_bytes, storage_path = params
            # ON CONFLICT (content_hash) DO NOTHING
            with self.connection.lock:
                if content_hash not in self.connection.blobs:
                    self.connection.blobs[content_hash] = {
                        "content_hash": content_hash,
                        "encrypted_dek": encrypted_dek,
                        "size_bytes": size_bytes,
                        "storage_path": storage_path,
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

        elif normalized.startswith("select encrypted_dek, storage_path from blobs"):
            (content_hash,) = params
            with self.connection.lock:
                blob = self.connection.blobs.get(content_hash)
                if blob is None:
                    self._last_row = None
                else:
                    self._last_row = FakeRow(
                        encrypted_dek=blob["encrypted_dek"],
                        storage_path=blob["storage_path"],
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
# Key wrapping & encryption tests (generate_dek, decrypt_dek, get_encryptor)
# ---------------------------------------------------------------------------


def test_generate_and_decrypt_dek_roundtrip(master_key: str) -> None:
    dek, encrypted_dek = evidence_storage.generate_dek()

    assert isinstance(dek, bytes)
    assert isinstance(encrypted_dek, bytes)
    assert dek != encrypted_dek

    recovered = evidence_storage.decrypt_dek(encrypted_dek)
    assert recovered == dek
    assert Fernet(master_key.encode("ascii")).decrypt(encrypted_dek) == dek


def test_generate_dek_without_master_key_env_uses_ephemeral_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MASTER_ENCRYPTION_KEY", raising=False)

    dek, encrypted_dek = evidence_storage.generate_dek()
    assert isinstance(dek, bytes)
    assert isinstance(encrypted_dek, bytes)
    assert dek != encrypted_dek


def test_decrypt_dek_rejects_missing_master_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MASTER_ENCRYPTION_KEY", raising=False)
    with pytest.raises(ValueError, match="MASTER_ENCRYPTION_KEY is not set"):
        evidence_storage.decrypt_dek(b"some-encrypted-bytes")


def test_decrypt_dek_rejects_wrong_key_or_corrupt_ciphertext(
    master_key: str,
) -> None:
    other_key = Fernet.generate_key()
    wrong_ciphertext = Fernet(other_key).encrypt(b"my-dek-value")

    with pytest.raises(InvalidToken):
        evidence_storage.decrypt_dek(wrong_ciphertext)

    with pytest.raises(InvalidToken):
        evidence_storage.decrypt_dek(b"completely-corrupted-token")


def test_get_encryptor_encrypt_and_decrypt_roundtrip() -> None:
    dek = Fernet.generate_key()
    encryptor = evidence_storage.get_encryptor(dek)

    plaintext = b"top-secret-evidence-payload"
    token = encryptor.encrypt(plaintext)
    assert token != plaintext
    assert encryptor.decrypt(token) == plaintext


# ---------------------------------------------------------------------------
# DB persistence & idempotency tests (record_blob, record_tenant_ref, get_blob_info)
# ---------------------------------------------------------------------------


def test_record_blob_executes_parameterized_insert_and_commits(
    fake_db: FakeConnection,
) -> None:
    content_hash = "a" * 64
    encrypted_dek = b"gAAAAABk-fake-encrypted-dek"
    size_bytes = 4096
    storage_path = "/var/lib/harpocrates/blobs/aa/aaaa"

    evidence_storage.record_blob(content_hash, encrypted_dek, size_bytes, storage_path)

    assert fake_db.commits == 1
    assert len(fake_db.executed) == 1
    sql, params = fake_db.executed[0]
    normalized_sql = " ".join(sql.lower().split())
    assert "insert into blobs (content_hash, encrypted_dek, size_bytes, storage_path)" in normalized_sql
    assert "values (%s, %s, %s, %s)" in normalized_sql
    assert "on conflict (content_hash) do nothing" in normalized_sql
    assert params == (
        content_hash,
        encrypted_dek.decode(),
        size_bytes,
        storage_path,
    )


def test_record_blob_idempotent_on_duplicate_content_hash(
    fake_db: FakeConnection,
) -> None:
    content_hash = "b" * 64
    first_dek = b"gAAAAABk-first-dek"
    second_dek = b"gAAAAABk-second-dek"

    evidence_storage.record_blob(content_hash, first_dek, 1024, "/blobs/first")
    evidence_storage.record_blob(content_hash, second_dek, 9999, "/blobs/second")

    assert fake_db.commits == 2
