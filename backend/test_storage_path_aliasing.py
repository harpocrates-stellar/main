"""Focused tests rejecting storage paths aliasing metadata databases or key files (#1050)."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path

from cryptography.fernet import Fernet
import pytest

import evidence_storage
from evidence_storage import (
    PROTECTED_PATH_ALIAS,
    StoragePathAliasError,
    record_blob,
    store_encrypted_evidence_at,
)
import storage
from storage import (
    get_job_input_path,
    get_job_output_path,
    get_storage_dir,
    validate_storage_destination,
    write_evidence_blob,
)
from test_evidence_storage import FakeConnection


@pytest.fixture
def fake_db(monkeypatch: pytest.MonkeyPatch) -> FakeConnection:
    conn = FakeConnection()

    @contextmanager
    def _fake_conn():
        yield conn

    monkeypatch.setattr(evidence_storage.db, "get_connection", _fake_conn)
    return conn


@pytest.fixture
def master_key(monkeypatch: pytest.MonkeyPatch) -> str:
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("MASTER_ENCRYPTION_KEY", key)
    return key


def test_rejects_metadata_db_paths_and_preserves_existing_db_intact(
    fake_db: FakeConnection,
    master_key: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    meta_dir = tmp_path / "meta"
    blob_dir = tmp_path / "blobs"
    meta_dir.mkdir()
    blob_dir.mkdir()

    # Configured metadata database with non-standard extension + WAL sidecar + standard .sqlite3
    custom_db = meta_dir / "state_ledger.dat"
    custom_db_bytes = b"SQLITE_CANARY_METADATA_LEDGER_INTACT_V1"
    custom_db.write_bytes(custom_db_bytes)

    sqlite_file = meta_dir / "app_metadata.sqlite3"
    sqlite_bytes = b"SQLITE_PRIMARY_DB_CANARY_BYTES"
    sqlite_file.write_bytes(sqlite_bytes)
    wal_file = Path(f"{sqlite_file}-wal")
    wal_bytes = b"SQLITE_WAL_CANARY_BYTES"
    wal_file.write_bytes(wal_bytes)

    monkeypatch.setenv("HARPOCRATES_METADATA_DB_PATH", str(custom_db))
    sqlite_uri_path = sqlite_file.as_posix()
    if not sqlite_uri_path.startswith("/"):
        sqlite_uri_path = "/" + sqlite_uri_path
    monkeypatch.setenv("DATABASE_URL", f"sqlite://{sqlite_uri_path}")

    # Relative traversal from blob_dir onto custom_db, sqlite_file, wal_file, and generic .db
    traversal_custom = blob_dir / ".." / "meta" / "state_ledger.dat"
    traversal_sqlite = blob_dir / ".." / "meta" / "app_metadata.sqlite3"
    traversal_wal = blob_dir / ".." / "meta" / "app_metadata.sqlite3-wal"
    direct_db_ext = blob_dir / "shadow_copy.db"

    for bad_target in (traversal_custom, traversal_sqlite, traversal_wal, direct_db_ext):
        with pytest.raises(StoragePathAliasError) as exc_info:
            store_encrypted_evidence_at(b"new-evidence", bad_target)
        assert exc_info.value.reason_code == PROTECTED_PATH_ALIAS

        with pytest.raises(StoragePathAliasError):
            record_blob("aa" * 32, b"wrapped-dek", 12, str(bad_target))

    # Existing database files and WAL sidecar remain byte-for-byte intact and no DB rows recorded
    assert custom_db.read_bytes() == custom_db_bytes
    assert sqlite_file.read_bytes() == sqlite_bytes
    assert wal_file.read_bytes() == wal_bytes
    assert not direct_db_ext.exists()
    assert len(fake_db.blobs) == 0


def test_rejects_key_files_hardlinks_symlinks_and_keystore_dirs_keeping_keys_intact(
    fake_db: FakeConnection,
    master_key: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    keystore_dir = tmp_path / "keystore"
    blob_dir = tmp_path / "blobs"
    keystore_dir.mkdir()
    blob_dir.mkdir()

    # Configured key file with arbitrary extension + standard .key / .pem / .env files
    configured_key = tmp_path / "wrapping_secret.bin"
    configured_key_bytes = b"KEK_CANARY_DO_NOT_TOUCH_BYTES"
    configured_key.write_bytes(configured_key_bytes)

    tls_key = tmp_path / "service_signing.key"
    tls_key_bytes = b"SIGNING_KEY_CANARY_BYTES"
    tls_key.write_bytes(tls_key_bytes)

    env_file = tmp_path / ".env"
    env_bytes = b"APP_CONFIG_CANARY=1\n"
    env_file.write_bytes(env_bytes)

    keystore_member = keystore_dir / "slot_01.raw"
    keystore_bytes = b"KEYSTORE_SLOT_CANARY"
    keystore_member.write_bytes(keystore_bytes)

    monkeypatch.setenv("MASTER_ENCRYPTION_KEY_FILE", str(configured_key))
    monkeypatch.setenv("HARPOCRATES_KEYSTORE_DIR", str(keystore_dir))

    # Create a hardlink inside blob_dir aliasing configured_key (same inode!)
    hardlink_alias = blob_dir / "innocent_looking_blob.enc"
    os.link(configured_key, hardlink_alias)

    for bad_dest in (
        configured_key,
        tls_key,
        env_file,
        blob_dir / ".env.production",
        blob_dir / "cert_bundle.pem",
        keystore_member,
        keystore_dir / "new_blob.enc",
        hardlink_alias,
    ):
        with pytest.raises(StoragePathAliasError):
            write_evidence_blob(bad_dest, b"attempted-overwrite")

    # Also test symlink alias if current OS user is permitted to create symlinks
    symlink_alias = blob_dir / "symlink_to_key.enc"
    symlink_created = False
    try:
        symlink_alias.symlink_to(configured_key)
        symlink_created = True
    except OSError:
        symlink_created = False

    if symlink_created:
        with pytest.raises(StoragePathAliasError):
            store_encrypted_evidence_at(b"via-symlink", symlink_alias)

    # Every existing key and secret file remains byte-for-byte intact!
    assert configured_key.read_bytes() == configured_key_bytes
    assert tls_key.read_bytes() == tls_key_bytes
    assert env_file.read_bytes() == env_bytes
    assert keystore_member.read_bytes() == keystore_bytes
    assert len(fake_db.blobs) == 0


def test_storage_dir_and_job_paths_reject_aliasing_and_allow_valid_blobs(
    fake_db: FakeConnection,
    master_key: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    key_file = tmp_path / "operator.key"
    key_file.write_bytes(b"KEY_CANARY")

    # HARPOCRATES_STORAGE_DIR pointing at a key file or .db path is rejected
    monkeypatch.setenv("HARPOCRATES_STORAGE_DIR", str(key_file))
    with pytest.raises(StoragePathAliasError):
        get_storage_dir()
    assert key_file.read_bytes() == b"KEY_CANARY"

    # Valid storage directory accepts clean job IDs and rejects path-traversal job IDs
    valid_jobs = tmp_path / "valid_jobs"
    monkeypatch.setenv("HARPOCRATES_STORAGE_DIR", str(valid_jobs))
    assert get_job_input_path(42) == valid_jobs / "job_42_input"
    assert get_job_output_path(42) == valid_jobs / "job_42_output"

    with pytest.raises(StoragePathAliasError):
        get_job_output_path("../../escape")

    # Valid encrypted evidence destination writes and records cleanly
    clean_dest = valid_jobs / "evidence_01.enc"
    result = store_encrypted_evidence_at(
        b"authentic-evidence-payload",
        clean_dest,
        allowed_root=valid_jobs,
    )
    assert clean_dest.is_file()
    assert result["ciphertextBytes"] == clean_dest.stat().st_size
    assert evidence_storage.get_blob_info(result["contentHash"]) is not None
