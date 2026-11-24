"""Focused tests distinguishing storage quota exhaustion from evidence corruption (#1052)."""

from __future__ import annotations

from contextlib import contextmanager
import errno
import os
from pathlib import Path
from unittest import mock

from cryptography.fernet import Fernet
import pytest

import evidence_storage
from evidence_storage import (
    EVIDENCE_CORRUPTED,
    STORAGE_IO_UNAVAILABLE,
    STORAGE_QUOTA_EXHAUSTED,
    EvidenceCorruptionError,
    StorageIOUnavailableError,
    StorageQuotaExhaustedError,
    is_blob_quarantined,
    quarantine_corrupted_blob,
    reset_corrupted_quarantine,
    store_encrypted_blob,
    verify_or_stage_encrypted_blob,
)
from storage import atomic_write_blob_bytes, classify_storage_exception
from test_evidence_storage import FakeConnection


@pytest.fixture(autouse=True)
def _clean_quarantine(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("HARPOCRATES_STORAGE_QUOTA_BYTES", raising=False)
    monkeypatch.delenv("HARPOCRATES_STORAGE_MIN_FREE_BYTES", raising=False)
    reset_corrupted_quarantine()
    yield
    reset_corrupted_quarantine()


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


def test_quota_exhaustion_on_write_returns_stable_code_without_quarantining(
    fake_db: FakeConnection,
    master_key: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    blob_dir = tmp_path / "blobs"
    monkeypatch.setenv("HARPOCRATES_STORAGE_QUOTA_BYTES", "32")

    payload = b"synthetic-evidence-payload-exceeding-tiny-quota"
    out = store_encrypted_blob(payload, storage_dir=blob_dir)

    assert out == {
        "ok": False,
        "reasonCode": STORAGE_QUOTA_EXHAUSTED,
        "retryable": True,
        "quarantined": False,
    }
    import hashlib

    digest = hashlib.sha256(payload).hexdigest()
    assert is_blob_quarantined(digest) is False
    assert evidence_storage.get_blob_info(digest) is None
    assert list(blob_dir.glob("*")) == []


def test_disk_enospc_during_staging_never_quarantines_valid_evidence_and_recovers(
    fake_db: FakeConnection,
    master_key: str,
    tmp_path: Path,
):
    blob_dir = tmp_path / "blobs"
    stage_dir = tmp_path / "stage"
    stage_dir.mkdir(parents=True)

    payload = b"valid-authenticated-evidence-bytes-1052"
    stored = store_encrypted_blob(payload, storage_dir=blob_dir)
    assert stored["ok"] is True
    content_hash = stored["contentHash"]

    stage_target = stage_dir / "staged_output"

    # Simulate ENOSPC (No space left on device) when staging valid decrypted evidence
    with mock.patch(
        "storage.os.fdopen",
        side_effect=OSError(errno.ENOSPC, "No space left on device"),
    ):
        failed_stage = verify_or_stage_encrypted_blob(
            content_hash,
            stage_path=stage_target,
        )

    assert failed_stage == {
        "ok": False,
        "reasonCode": STORAGE_QUOTA_EXHAUSTED,
        "retryable": True,
        "quarantined": False,
    }
    # Valid evidence MUST NOT be quarantined and no partial stage file may remain
    assert is_blob_quarantined(content_hash) is False
    assert not stage_target.exists()
    assert list(stage_dir.glob("*.tmp")) == []

    # Once disk capacity recovers, the exact same evidence verifies and stages cleanly!
    recovered = verify_or_stage_encrypted_blob(
        content_hash,
        stage_path=stage_target,
    )
    assert recovered["ok"] is True
    assert recovered["reasonCode"] == "OK"
    assert recovered["quarantined"] is False
    assert stage_target.read_bytes() == payload


def test_genuine_ciphertext_and_digest_corruption_return_evidence_corrupted_and_quarantine(
    fake_db: FakeConnection,
    master_key: str,
    tmp_path: Path,
):
    blob_dir = tmp_path / "blobs"
    payload = b"integrity-checked-evidence-1052"
    stored = store_encrypted_blob(payload, storage_dir=blob_dir)
    content_hash = stored["contentHash"]

    info = evidence_storage.get_blob_info(content_hash)
    assert info is not None
    blob_path = Path(info["storage_path"])

    # Corrupt the ciphertext bytes on disk so Fernet HMAC authentication fails
    blob_path.write_bytes(b"corrupted-ciphertext-not-valid-fernet")

    corrupt_res = verify_or_stage_encrypted_blob(content_hash)
    assert corrupt_res == {
        "ok": False,
        "reasonCode": EVIDENCE_CORRUPTED,
        "retryable": False,
        "quarantined": True,
    }
    assert is_blob_quarantined(content_hash) is True

    # Subsequent calls short-circuit on quarantine with EVIDENCE_CORRUPTED
    repeat_res = verify_or_stage_encrypted_blob(content_hash)
    assert repeat_res["reasonCode"] == EVIDENCE_CORRUPTED
    assert repeat_res["quarantined"] is True


def test_digest_mismatch_with_valid_encryption_is_classified_as_corruption(
    fake_db: FakeConnection,
    master_key: str,
    tmp_path: Path,
):
    blob_dir = tmp_path / "blobs"
    stored = store_encrypted_blob(b"original-bytes", storage_dir=blob_dir)
    content_hash = stored["contentHash"]

    mismatch_res = verify_or_stage_encrypted_blob(
        content_hash,
        expected_plaintext_hash="ff" * 32,
    )
    assert mismatch_res == {
        "ok": False,
        "reasonCode": EVIDENCE_CORRUPTED,
        "retryable": False,
        "quarantined": True,
    }
    assert is_blob_quarantined(content_hash) is True


def test_quarantine_guard_rejects_quota_and_io_errors_and_preserves_existing_file(
    tmp_path: Path,
):
    with pytest.raises(ValueError, match="EVIDENCE_CORRUPTED"):
        quarantine_corrupted_blob("aa" * 32, error=StorageQuotaExhaustedError())
    with pytest.raises(ValueError, match="EVIDENCE_CORRUPTED"):
        quarantine_corrupted_blob("aa" * 32, error=StorageIOUnavailableError())

    # Classification covers POSIX ENOSPC, EDQUOT, generic OSError, and InvalidToken
    enospc = classify_storage_exception(OSError(errno.ENOSPC, "disk full /secret/path"))
    assert isinstance(enospc, StorageQuotaExhaustedError)
    assert enospc.reason_code == STORAGE_QUOTA_EXHAUSTED
    assert "/secret/path" not in str(enospc.to_dict())

    generic_io = classify_storage_exception(OSError(errno.EACCES, "permission denied"))
    assert generic_io.reason_code == STORAGE_IO_UNAVAILABLE
    assert generic_io.quarantine_eligible is False

    # Atomic write failure leaves existing valid file intact
    existing = tmp_path / "existing_valid.enc"
    existing.write_bytes(b"intact-ciphertext")
    with pytest.raises(StorageQuotaExhaustedError):
        atomic_write_blob_bytes(existing, b"x" * 2048, quota_bytes=64)
    assert existing.read_bytes() == b"intact-ciphertext"
