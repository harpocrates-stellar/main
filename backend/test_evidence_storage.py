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

        elif "select content_hash, size_bytes, storage_path from blobs" in normalized:
            with self.connection.lock:
                self._results = [
                    FakeRow(
                        content_hash=b["content_hash"],
                        size_bytes=b["size_bytes"],
                        storage_path=b["storage_path"],
                    )
                    for _, b in sorted(self.connection.blobs.items(), key=lambda item: item[0])
                ]
            self._idx = 0

        elif "select tenant_id, content_hash, ref_count from tenant_blob_refs" in normalized:
            with self.connection.lock:
                rows = [
                    FakeRow(
                        tenant_id=ref["tenant_id"],
                        content_hash=ref["content_hash"],
                        ref_count=ref["ref_count"],
                    )
                    for ref in self.connection.tenant_refs.values()
                    if ref["ref_count"] > 0
                ]
                rows.sort(key=lambda r: (r["tenant_id"], r["content_hash"]))
                self._results = rows
            self._idx = 0
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


def test_record_blob_idempotent_on_duplicate_content_hash(
    fake_db: FakeConnection,
) -> None:
    content_hash = "b" * 64
    first_dek = b"gAAAAABk-first-dek"
    second_dek = b"gAAAAABk-second-dek"

    evidence_storage.record_blob(content_hash, first_dek, 1024, "/blobs/first")
    evidence_storage.record_blob(content_hash, second_dek, 9999, "/blobs/second")

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


def test_record_tenant_ref_sql_parameters_and_idempotent_ref_count(
    fake_db: FakeConnection,
) -> None:
    tenant_id = "tenant-alpha"
    content_hash = "c" * 64

    evidence_storage.record_tenant_ref(tenant_id, content_hash)
    evidence_storage.record_tenant_ref(tenant_id, content_hash)

    assert fake_db.commits == 2
    assert len(fake_db.executed) == 2

    for sql, params in fake_db.executed:
        normalized_sql = " ".join(sql.lower().split())
        assert "insert into tenant_blob_refs (tenant_id, content_hash, ref_count)" in normalized_sql
        assert "values (%s, %s, 1)" in normalized_sql
        assert "on conflict (tenant_id, content_hash) do update" in normalized_sql
        assert "set ref_count = tenant_blob_refs.ref_count + 1" in normalized_sql
        assert params == (tenant_id, content_hash)

    assert fake_db.tenant_refs[(tenant_id, content_hash)]["ref_count"] == 2


def test_get_blob_info_returns_none_for_unknown_and_dict_for_known(
    fake_db: FakeConnection,
) -> None:
    unknown_hash = "0" * 64
    known_hash = "d" * 64
    encrypted_dek = b"gAAAAABk-known-dek"
    storage_path = "/blobs/dd/dddd"

    assert evidence_storage.get_blob_info(unknown_hash) is None
    sql, params = fake_db.executed[-1]
    assert "select encrypted_dek, storage_path, envelope_version from blobs where content_hash = %s" in " ".join(
        sql.lower().split()
    )
    assert params == (unknown_hash,)

    evidence_storage.record_blob(known_hash, encrypted_dek, 512, storage_path)
    result = evidence_storage.get_blob_info(known_hash)

    assert result == {
        "encrypted_dek": encrypted_dek.decode(),
        "storage_path": storage_path,
        "envelope_version": evidence_storage.DEFAULT_ENVELOPE_VERSION,
    }
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Reference removal, garbage collection, and concurrency tests
# ---------------------------------------------------------------------------


def test_remove_tenant_ref_decrements_and_deletes(fake_db: FakeConnection, tmp_path: Path):
    evidence_storage.record_blob("hash_1", b"dek", 10, str(tmp_path / "b1"))

    # Add reference twice
    evidence_storage.record_tenant_ref("tenant_a", "hash_1")
    evidence_storage.record_tenant_ref("tenant_a", "hash_1")
    assert fake_db.tenant_refs[("tenant_a", "hash_1")]["ref_count"] == 2

    # First remove decrements ref_count to 1
    assert evidence_storage.remove_tenant_ref("tenant_a", "hash_1") is True
    assert fake_db.tenant_refs[("tenant_a", "hash_1")]["ref_count"] == 1

    # Second remove deletes the reference row
    assert evidence_storage.remove_tenant_ref("tenant_a", "hash_1") is True
    assert ("tenant_a", "hash_1") not in fake_db.tenant_refs

    # Third remove returns False since reference no longer exists
    assert evidence_storage.remove_tenant_ref("tenant_a", "hash_1") is False


def test_blobs_with_remaining_references_are_never_deleted(fake_db: FakeConnection, tmp_path: Path):
    b1_file = tmp_path / "b1.enc"
    b1_file.write_bytes(b"content1")
    evidence_storage.record_blob("hash_1", b"dek1", 8, str(b1_file))

    # Two tenants reference the same blob
    evidence_storage.record_tenant_ref("tenant_a", "hash_1")
    evidence_storage.record_tenant_ref("tenant_b", "hash_1")

    # Tenant A removes reference
    assert evidence_storage.remove_tenant_ref("tenant_a", "hash_1") is True

    # Garbage collector should NOT delete hash_1 because Tenant B still references it
    collected = evidence_storage.collect_unreferenced_blobs(limit=10)
    assert collected == 0
    assert b1_file.exists()
    assert evidence_storage.get_blob_info("hash_1") is not None

    # Tenant B removes reference
    assert evidence_storage.remove_tenant_ref("tenant_b", "hash_1") is True

    # Now hash_1 has zero references, so it should be collected
    collected = evidence_storage.collect_unreferenced_blobs(limit=10)
    assert collected == 1
    assert not b1_file.exists()
    assert evidence_storage.get_blob_info("hash_1") is None


def test_file_deletion_failure_retried_on_next_run(fake_db: FakeConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    b_file = tmp_path / "failing.enc"
    b_file.write_bytes(b"content")
    evidence_storage.record_blob("hash_fail", b"dek", 7, str(b_file))

    should_fail = True
    orig_unlink = os.unlink

    def fake_unlink(path):
        if should_fail and str(path) == str(b_file):
            raise PermissionError("Simulated file lock")
        return orig_unlink(path)

    monkeypatch.setattr(os, "unlink", fake_unlink)

    # First run: unlink fails
    collected = evidence_storage.collect_unreferenced_blobs(limit=10)
    assert collected == 0
    # The blob file and the DB row must be kept intact
    assert b_file.exists()
    assert evidence_storage.get_blob_info("hash_fail") is not None

    # Verify metrics were not incremented
    metrics = metrics_collector.generate_prometheus_metrics()
    assert "harpocrates_retention_deleted_blobs_total 0" in metrics

    # Second run: unlink succeeds
    should_fail = False
    collected = evidence_storage.collect_unreferenced_blobs(limit=10)
    assert collected == 1
    assert not b_file.exists()
    assert evidence_storage.get_blob_info("hash_fail") is None

    # Metrics incremented
    metrics = metrics_collector.generate_prometheus_metrics()
    assert "harpocrates_retention_deleted_blobs_total 1" in metrics
    # Ensure no hashes are leaked in metrics
    assert "hash_fail" not in metrics


def test_concurrent_add_and_collect_race(fake_db: FakeConnection, tmp_path: Path):
    """Simulate race: collector selects unreferenced blob, while concurrent tenant adds reference.

    Row locking ensures the tenant's transaction cannot conflict with unreferenced collection.
    """
    b_file = tmp_path / "race.enc"
    b_file.write_bytes(b"race-data")
    evidence_storage.record_blob("hash_race", b"dek", 9, str(b_file))

    race_barrier = threading.Barrier(2)
    tenant_result = {"status": None}

    def tenant_thread():
        # Wait until collector has selected and locked the candidate row
        race_barrier.wait()
        try:
            # Attempt to record tenant ref while collector transaction is active
            evidence_storage.record_tenant_ref("tenant_race", "hash_race")
            tenant_result["status"] = "success"
        except Exception as e:
            tenant_result["status"] = type(e).__name__

    def collector_hook():
        race_barrier.wait()
        time.sleep(0.05)

    fake_db.before_collector_delete_hook = collector_hook

    t = threading.Thread(target=tenant_thread)
    t.start()

    collected = evidence_storage.collect_unreferenced_blobs(limit=10)
    t.join()

    # Collector successfully deleted the unreferenced blob
    assert collected == 1
    assert not b_file.exists()
    assert evidence_storage.get_blob_info("hash_race") is None


def test_concurrent_add_first_prevents_collection(fake_db: FakeConnection, tmp_path: Path):
    """If tenant adds reference right before collection, the blob is never deleted."""
    b_file = tmp_path / "safe.enc"
    b_file.write_bytes(b"safe-data")
    evidence_storage.record_blob("hash_safe", b"dek", 9, str(b_file))

    # Add reference
    evidence_storage.record_tenant_ref("tenant_safe", "hash_safe")

    # Collector runs
    collected = evidence_storage.collect_unreferenced_blobs(limit=10)
    assert collected == 0
    assert b_file.exists()
    assert evidence_storage.get_blob_info("hash_safe") is not None


def test_collect_unreferenced_blobs_batch_limit(fake_db: FakeConnection, tmp_path: Path):
    # Create 5 unreferenced blobs
    for i in range(5):
        f = tmp_path / f"batch_{i}.enc"
        f.write_bytes(b"x")
        evidence_storage.record_blob(f"hash_{i}", b"dek", 1, str(f))

    # Collect with limit=2
    collected = evidence_storage.collect_unreferenced_blobs(limit=2)
    assert collected == 2
    assert len(fake_db.blobs) == 3

    # Collect next batch with limit=2
    collected = evidence_storage.collect_unreferenced_blobs(limit=2)
    assert collected == 2
    assert len(fake_db.blobs) == 1

    # Collect remaining with limit=2
    collected = evidence_storage.collect_unreferenced_blobs(limit=2)
    assert collected == 1
    assert len(fake_db.blobs) == 0


def test_metrics_do_not_expose_hashes(fake_db: FakeConnection, tmp_path: Path):
    sensitive_hash = "super_secret_evidence_hash_12345"
    f = tmp_path / "secret.enc"
    f.write_bytes(b"data")
    evidence_storage.record_blob(sensitive_hash, b"dek", 4, str(f))

    evidence_storage.collect_unreferenced_blobs(limit=10)

    metrics = metrics_collector.generate_prometheus_metrics()
    assert sensitive_hash not in metrics
    assert "super_secret" not in metrics
    assert "harpocrates_retention_deleted_blobs_total 1" in metrics


# ---------------------------------------------------------------------------
# Per-tenant retention preview tests
# ---------------------------------------------------------------------------


def test_preview_tenant_retention_counts_ages_and_eligibility(
    fake_db: FakeConnection, tmp_path: Path
) -> None:
    now_ts = 1_700_000_000.0

    # Exclusive old blob (eligible when ttl=3600)
    evidence_storage.record_blob("hash_a_old", b"dek1", 1000, str(tmp_path / "a_old.enc"))
    fake_db.blobs["hash_a_old"]["created_at"] = now_ts - 7200.0
    evidence_storage.record_tenant_ref("tenant_a", "hash_a_old")
    evidence_storage.record_tenant_ref("tenant_a", "hash_a_old")

    # Exclusive recent blob (within retention window when ttl=3600)
    evidence_storage.record_blob("hash_a_new", b"dek2", 500, str(tmp_path / "a_new.enc"))
    fake_db.blobs["hash_a_new"]["created_at"] = now_ts - 600.0
    evidence_storage.record_tenant_ref("tenant_a", "hash_a_new")

    # Shared old blob (ineligible because tenant_b also references it)
    evidence_storage.record_blob("hash_shared", b"dek3", 250, str(tmp_path / "shared.enc"))
    fake_db.blobs["hash_shared"]["created_at"] = now_ts - 10800.0
    evidence_storage.record_tenant_ref("tenant_a", "hash_shared")
    evidence_storage.record_tenant_ref("tenant_b", "hash_shared")

    # Tenant B's private blob (must never appear in tenant_a's preview)
    evidence_storage.record_blob(
        "hash_b_secret", b"dek4", 9999, str(tmp_path / "tenant_b_private_path.enc")
    )
    fake_db.blobs["hash_b_secret"]["created_at"] = now_ts - 20000.0
    evidence_storage.record_tenant_ref("tenant_b", "hash_b_secret")

    preview = evidence_storage.preview_tenant_retention(
        "tenant_a", now=now_ts, ttl_seconds=3600
    )

    assert preview["tenant_id"] == "tenant_a"
    assert preview["ttl_seconds"] == 3600
    assert preview["blob_count"] == 3
    assert preview["total_ref_count"] == 4
    assert preview["total_size_bytes"] == 1750
    assert preview["eligible_for_deletion_count"] == 1
    assert preview["retained_count"] == 2
    assert preview["shared_blob_count"] == 1
    assert preview["oldest_age_seconds"] == pytest.approx(10800.0)
    assert preview["newest_age_seconds"] == pytest.approx(600.0)
    assert preview["average_age_seconds"] == pytest.approx((10800.0 + 7200.0 + 600.0) / 3)

    by_hash = {item["content_hash"]: item for item in preview["blobs"]}
    assert set(by_hash.keys()) == {"hash_a_old", "hash_a_new", "hash_shared"}

    assert by_hash["hash_a_old"]["ref_count"] == 2
    assert by_hash["hash_a_old"]["age_seconds"] == pytest.approx(7200.0)
    assert by_hash["hash_a_old"]["deletion_eligible"] is True
    assert by_hash["hash_a_old"]["deletion_ineligible_reason"] is None

    assert by_hash["hash_a_new"]["ref_count"] == 1
    assert by_hash["hash_a_new"]["age_seconds"] == pytest.approx(600.0)
    assert by_hash["hash_a_new"]["deletion_eligible"] is False
    assert by_hash["hash_a_new"]["deletion_ineligible_reason"] == "within_retention_window"

    assert by_hash["hash_shared"]["ref_count"] == 1
    assert by_hash["hash_shared"]["age_seconds"] == pytest.approx(10800.0)
    assert by_hash["hash_shared"]["deletion_eligible"] is False
    assert by_hash["hash_shared"]["deletion_ineligible_reason"] == "shared_with_other_tenants"

    # Read-only: DB state untouched
    assert len(fake_db.blobs) == 4
    assert fake_db.tenant_refs[("tenant_a", "hash_a_old")]["ref_count"] == 2


def test_preview_tenant_retention_keeps_other_tenants_and_storage_paths_private(
    fake_db: FakeConnection, tmp_path: Path
) -> None:
    now_ts = 1_700_000_000.0
    path_a = str(tmp_path / "secret_dir_a" / "blob_a.enc")
    path_b = str(tmp_path / "secret_dir_b" / "blob_b.enc")
    hash_b = "b_private_hash_987654321"

    evidence_storage.record_blob("hash_a_only", b"dek_a", 128, path_a)
    fake_db.blobs["hash_a_only"]["created_at"] = now_ts - 100.0
    evidence_storage.record_tenant_ref("tenant_a", "hash_a_only")

    evidence_storage.record_blob(hash_b, b"dek_b", 256, path_b)
    fake_db.blobs[hash_b]["created_at"] = now_ts - 500.0
    evidence_storage.record_tenant_ref("tenant_b", hash_b)

    preview = evidence_storage.preview_tenant_retention("tenant_a", now=now_ts)
    serialized = str(preview)

    assert hash_b not in serialized
    assert "tenant_b" not in serialized
    assert path_a not in serialized
    assert path_b not in serialized
    assert "storage_path" not in serialized
    assert "encrypted_dek" not in serialized

    # Verify the SQL query itself does not select storage_path or encrypted_dek
    sql, params = fake_db.executed[-1]
    normalized_sql = " ".join(sql.lower().split())
    assert "storage_path" not in normalized_sql
    assert "encrypted_dek" not in normalized_sql
    assert params == ("tenant_a",)


def test_preview_tenant_retention_empty_and_boundary_cases(fake_db: FakeConnection) -> None:
    now_ts = 1_700_000_000.0

    # Empty tenant
    empty = evidence_storage.preview_tenant_retention("tenant_empty", now=now_ts, ttl_seconds=60)
    assert empty["blob_count"] == 0
    assert empty["total_ref_count"] == 0
    assert empty["total_size_bytes"] == 0
    assert empty["eligible_for_deletion_count"] == 0
    assert empty["retained_count"] == 0
    assert empty["shared_blob_count"] == 0
    assert empty["oldest_age_seconds"] is None
    assert empty["newest_age_seconds"] is None
    assert empty["average_age_seconds"] is None
    assert empty["blobs"] == []

    # Exact TTL boundary: age == ttl_seconds is eligible
    evidence_storage.record_blob("hash_boundary", b"dek", 64, "/blobs/boundary")
    fake_db.blobs["hash_boundary"]["created_at"] = now_ts - 60.0
    evidence_storage.record_tenant_ref("tenant_bound", "hash_boundary")

    boundary = evidence_storage.preview_tenant_retention(
        "tenant_bound", now=now_ts, ttl_seconds=60
    )
    assert boundary["eligible_for_deletion_count"] == 1
    assert boundary["blobs"][0]["deletion_eligible"] is True
    assert boundary["blobs"][0]["deletion_ineligible_reason"] is None


def test_preview_tenant_retention_rejects_invalid_inputs(fake_db: FakeConnection) -> None:
    with pytest.raises(ValueError, match="tenant_id must be a non-empty string"):
        evidence_storage.preview_tenant_retention("")

    with pytest.raises(ValueError, match="tenant_id must be a non-empty string"):
        evidence_storage.preview_tenant_retention("   ")

    with pytest.raises(ValueError, match="ttl_seconds must be a non-negative number"):
        evidence_storage.preview_tenant_retention("tenant_a", ttl_seconds=-1)

    with pytest.raises(ValueError, match="ttl_seconds must be a non-negative number"):
        evidence_storage.preview_tenant_retention("tenant_a", ttl_seconds=True)


# ---------------------------------------------------------------------------
# Evidence storage consistency report tests
# ---------------------------------------------------------------------------


def test_consistency_report_clean_state(fake_db: FakeConnection, tmp_path: Path) -> None:
    now_ts = 1_700_000_000.0
    blob_dir = tmp_path / "aa"
    blob_dir.mkdir()
    blob_file = blob_dir / "blob_1.enc"
    blob_file.write_bytes(b"encrypted-payload-1")

    evidence_storage.record_blob("hash_1", b"dek_1", len(b"encrypted-payload-1"), str(blob_file))
    evidence_storage.record_tenant_ref("tenant_a", "hash_1")
    evidence_storage.record_tenant_ref("tenant_b", "hash_1")

    report = evidence_storage.generate_consistency_report(storage_dir=tmp_path, now=now_ts)

    assert report["consistent"] is True
    assert report["storage_dir"] == str(tmp_path.resolve())
    assert report["summary"] == {
        "total_blobs": 1,
        "total_tenant_refs": 2,
        "total_physical_files": 1,
        "missing_files_count": 0,
        "orphaned_blobs_count": 0,
        "orphaned_tenant_refs_count": 0,
        "orphaned_files_count": 0,
        "size_mismatches_count": 0,
    }
    assert report["missing_files"] == []
    assert report["orphaned_blobs"] == []
    assert report["orphaned_tenant_refs"] == []
    assert report["orphaned_files"] == []
    assert report["size_mismatches"] == []


def test_consistency_report_detects_missing_and_orphaned_records_without_modifying(
    fake_db: FakeConnection, tmp_path: Path
) -> None:
    now_ts = 1_700_000_000.0

    # 1. Healthy blob
    healthy_file = tmp_path / "healthy.enc"
    healthy_file.write_bytes(b"12345")
    evidence_storage.record_blob("hash_healthy", b"dek_h", 5, str(healthy_file))
    evidence_storage.record_tenant_ref("tenant_a", "hash_healthy")

    # 2. Missing physical file
    missing_path = tmp_path / "missing.enc"
    evidence_storage.record_blob("hash_missing_file", b"dek_m", 10, str(missing_path))
    evidence_storage.record_tenant_ref("tenant_a", "hash_missing_file")

    # 3. Empty storage_path
    evidence_storage.record_blob("hash_empty_path", b"dek_e", 10, "")
    evidence_storage.record_tenant_ref("tenant_a", "hash_empty_path")

    # 4. storage_path points to a directory
    dir_path = tmp_path / "not_a_file_dir"
    dir_path.mkdir()
    evidence_storage.record_blob("hash_dir_path", b"dek_d", 10, str(dir_path))
    evidence_storage.record_tenant_ref("tenant_a", "hash_dir_path")

    # 5. Orphaned blob (no active tenant refs; include a zero ref_count row to verify it is ignored)
    orphan_blob_file = tmp_path / "orphan_blob.enc"
    orphan_blob_file.write_bytes(b"orphan")
    evidence_storage.record_blob("hash_orphan_blob", b"dek_o", 6, str(orphan_blob_file))
    fake_db.tenant_refs[("tenant_zero", "hash_orphan_blob")] = {
        "tenant_id": "tenant_zero",
        "content_hash": "hash_orphan_blob",
        "ref_count": 0,
    }

    # 6. Orphaned tenant reference (missing blob metadata)
    evidence_storage.record_tenant_ref("tenant_dangling", "hash_no_blob")

    # 7. Orphaned physical file (no blob metadata)
    orphan_disk_file = tmp_path / "untracked.enc"
    orphan_disk_file.write_bytes(b"stray-bytes")

    # 8. Size mismatch
    mismatch_file = tmp_path / "mismatch.enc"
    mismatch_file.write_bytes(b"actual-12345")
    evidence_storage.record_blob("hash_size_mismatch", b"dek_s", 999, str(mismatch_file))
    evidence_storage.record_tenant_ref("tenant_a", "hash_size_mismatch")

    blobs_before = dict(fake_db.blobs)
    refs_before = dict(fake_db.tenant_refs)
    files_before = sorted(p for p in tmp_path.rglob("*") if p.is_file())

    report = evidence_storage.generate_consistency_report(storage_dir=tmp_path, now=now_ts)

    assert report["consistent"] is False
    assert report["summary"] == {
        "total_blobs": 6,
        "total_tenant_refs": 6,
        "total_physical_files": 4,
        "missing_files_count": 3,
        "orphaned_blobs_count": 1,
        "orphaned_tenant_refs_count": 1,
        "orphaned_files_count": 1,
        "size_mismatches_count": 1,
    }

    missing_by_hash = {item["content_hash"]: item for item in report["missing_files"]}
    assert set(missing_by_hash.keys()) == {"hash_dir_path", "hash_empty_path", "hash_missing_file"}
    assert missing_by_hash["hash_missing_file"]["reason"] == "file_not_found"
    assert missing_by_hash["hash_empty_path"]["reason"] == "missing_storage_path"
    assert missing_by_hash["hash_dir_path"]["reason"] == "not_a_file"

    assert report["orphaned_blobs"] == [
        {"content_hash": "hash_orphan_blob", "size_bytes": 6, "file_exists": True}
    ]
    assert report["orphaned_tenant_refs"] == [
        {"tenant_id": "tenant_dangling", "content_hash": "hash_no_blob", "ref_count": 1}
    ]
    assert report["orphaned_files"] == [
        {"path": str(orphan_disk_file.resolve()), "size_bytes": len(b"stray-bytes")}
    ]
    assert report["size_mismatches"] == [
        {
            "content_hash": "hash_size_mismatch",
            "expected_size_bytes": 999,
            "actual_size_bytes": len(b"actual-12345"),
        }
    ]

    # Privacy: encrypted_dek must never be queried or returned
    serialized = str(report)
    assert "encrypted_dek" not in serialized
    assert "dek_h" not in serialized
    for sql, _ in fake_db.executed[-2:]:
        assert "encrypted_dek" not in sql.lower()

    # Read-only: DB state and physical files must be completely unmodified
    assert fake_db.blobs == blobs_before
    assert fake_db.tenant_refs == refs_before
    assert sorted(p for p in tmp_path.rglob("*") if p.is_file()) == files_before
    assert orphan_disk_file.exists()
    assert orphan_blob_file.exists()


def test_consistency_report_empty_and_nonexistent_storage_dir(
    fake_db: FakeConnection, tmp_path: Path
) -> None:
    nonexistent = tmp_path / "does_not_exist_yet"
    assert not nonexistent.exists()

    empty_report = evidence_storage.generate_consistency_report(storage_dir=nonexistent)
    assert empty_report["consistent"] is True
    assert empty_report["summary"]["total_blobs"] == 0
    assert empty_report["summary"]["total_physical_files"] == 0
    # Read-only: must not create missing storage directory
    assert not nonexistent.exists()

    # When a blob points into a non-existent directory, it is reported as missing
    evidence_storage.record_blob("hash_missing", b"dek", 4, str(nonexistent / "blob.enc"))
    evidence_storage.record_tenant_ref("tenant_a", "hash_missing")

    report = evidence_storage.generate_consistency_report(storage_dir=nonexistent)
    assert report["consistent"] is False
    assert report["summary"]["missing_files_count"] == 1
    assert report["missing_files"][0]["content_hash"] == "hash_missing"
    assert report["missing_files"][0]["reason"] == "file_not_found"
    assert not nonexistent.exists()


def test_consistency_report_uses_env_storage_dir_when_omitted(
    fake_db: FakeConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HARPOCRATES_STORAGE_DIR", str(tmp_path))
    orphan_file = tmp_path / "stray.enc"
    orphan_file.write_bytes(b"abc")

    report = evidence_storage.generate_consistency_report()
    assert report["consistent"] is False
    assert report["storage_dir"] == str(tmp_path.resolve())
    assert report["summary"]["orphaned_files_count"] == 1
    assert report["orphaned_files"][0]["path"] == str(orphan_file.resolve())


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


if __name__ == "__main__":
    unittest.main()
