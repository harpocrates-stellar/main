"""Focused tests for two-phase retained evidence deletion receipts (#1053)."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import time

from cryptography.fernet import Fernet
import pytest

import evidence_storage
import storage
from storage import (
    DeletionReceiptLedger,
    compute_deletion_audit_ref,
    reset_deletion_receipts,
    sweep_job_files,
    verify_deletion_receipt,
)
from test_evidence_storage import FakeConnection


@pytest.fixture(autouse=True)
def _clean_receipt_state(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DELETION_RECEIPT_LOG_PATH", raising=False)
    reset_deletion_receipts()
    yield
    reset_deletion_receipts()


@pytest.fixture
def fake_db(monkeypatch: pytest.MonkeyPatch) -> FakeConnection:
    conn = FakeConnection()

    @contextmanager
    def _fake_conn():
        yield conn

    monkeypatch.setattr(evidence_storage.db, "get_connection", _fake_conn)
    return conn


def test_two_phase_deletion_receipt_records_selection_before_delete_and_verifies_chain(
    fake_db: FakeConnection,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    master_key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("MASTER_ENCRYPTION_KEY", master_key)
    dek, encrypted_dek = evidence_storage.generate_dek()
    sensitive_media = b"PRIVATE_SYNTHETIC_MEDIA_PAYLOAD_DO_NOT_RETAIN"
    ciphertext = evidence_storage.get_encryptor(dek).encrypt(sensitive_media)

    content_hash = "ab" * 32
    blob_file = tmp_path / "retained_evidence_blob.enc"
    blob_file.write_bytes(ciphertext)
    evidence_storage.record_blob(content_hash, encrypted_dek, len(ciphertext), str(blob_file))

    log_file = tmp_path / "receipts" / "deletion_ledger.json"
    ledger = DeletionReceiptLedger(log_path=log_file)
    observed_phases_at_unlink: list[str] = []
    orig_unlink = os.unlink

    def spy_unlink(path):
        if Path(path) == blob_file:
            # Phase 1 approval MUST already exist before storage unlink executes!
            current = ledger.list_receipts()
            assert len(current) == 1
            assert current[0]["phase"] == "selection_approved"
            assert current[0]["actions"]["selectionApproved"] is True
            assert current[0]["actions"]["fileDeleted"] is False
            assert current[0]["actions"]["metadataDeleted"] is False
            assert current[0]["completionDigest"] is None
            observed_phases_at_unlink.append(current[0]["phase"])
        return orig_unlink(path)

    monkeypatch.setattr(os, "unlink", spy_unlink)

    collected, receipts = evidence_storage.collect_unreferenced_blobs_with_receipts(
        limit=10,
        receipt_ledger=ledger,
        reason="retention_expired",
    )

    assert collected == 1
    assert observed_phases_at_unlink == ["selection_approved"]
    assert not blob_file.exists()
    assert evidence_storage.get_blob_info(content_hash) is None

    assert len(receipts) == 1
    rec = receipts[0]
    assert rec["phase"] == "completed"
    assert rec["reason"] == "retention_expired"
    assert rec["actions"] == {
        "selectionApproved": True,
        "requiresMetadataDelete": True,
        "fileDeleted": True,
        "metadataDeleted": True,
    }
    assert rec["auditRef"] == compute_deletion_audit_ref(content_hash)
    assert verify_deletion_receipt(rec, expected_identifier=content_hash) is True
    assert verify_deletion_receipt(rec, expected_identifier="cd" * 32) is False

    # Privacy guarantee: neither receipt dict nor persisted file contains media, paths, raw hashes, or keys
    persisted_text = log_file.read_text(encoding="utf-8")
    for forbidden in (
        content_hash,
        str(blob_file),
        "retained_evidence_blob.enc",
        dek.decode("ascii"),
        encrypted_dek.decode("ascii"),
        master_key,
        sensitive_media.decode("ascii"),
    ):
        assert forbidden not in persisted_text
        assert forbidden not in str(rec)

    # Reload ledger from durable file and confirm cryptographic receipt verification passes
    reloaded_ledger = DeletionReceiptLedger(log_path=log_file)
    reloaded = reloaded_ledger.get_receipt(rec["receiptId"])
    assert reloaded is not None
    assert verify_deletion_receipt(reloaded, expected_identifier=content_hash) is True


def test_storage_unlink_failure_keeps_receipt_uncompleted_and_succeeds_on_retry(
    fake_db: FakeConnection,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    content_hash = "cc" * 32
    blob_file = tmp_path / "locked_evidence.enc"
    blob_file.write_bytes(b"ciphertext-bytes")
    evidence_storage.record_blob(content_hash, b"wrapped-dek-token", 16, str(blob_file))

    fail_unlink = True
    orig_unlink = os.unlink

    def flaky_unlink(path):
        if fail_unlink and Path(path) == blob_file:
            raise PermissionError("simulated lock containing /secret/path")
        return orig_unlink(path)

    monkeypatch.setattr(os, "unlink", flaky_unlink)

    collected_1, receipts_1 = evidence_storage.collect_unreferenced_blobs_with_receipts(limit=10)
    assert collected_1 == 0
    assert blob_file.exists()
    assert evidence_storage.get_blob_info(content_hash) is not None

    assert len(receipts_1) == 1
    failed_rec = receipts_1[0]
    assert failed_rec["phase"] == "storage_failed"
    assert failed_rec["completedAt"] is None
    assert failed_rec["completionDigest"] is None
    assert failed_rec["actions"]["selectionApproved"] is True
    assert failed_rec["actions"]["fileDeleted"] is False
    assert failed_rec["actions"]["metadataDeleted"] is False
    assert failed_rec["lastErrorCode"] == "PermissionError"
    assert "/secret/path" not in str(failed_rec)
    assert verify_deletion_receipt(failed_rec, expected_identifier=content_hash) is True

    # Retry once storage lock clears -> new two-phase receipt completes cleanly
    fail_unlink = False
    collected_2, receipts_2 = evidence_storage.collect_unreferenced_blobs_with_receipts(limit=10)
    assert collected_2 == 1
    assert not blob_file.exists()
    assert len(receipts_2) == 1
    assert receipts_2[0]["phase"] == "completed"
    assert verify_deletion_receipt(receipts_2[0], expected_identifier=content_hash) is True

    by_hash = evidence_storage.list_deletion_receipts(content_hash=content_hash)
    assert [r["phase"] for r in by_hash] == ["completed", "storage_failed"]


def test_tampered_receipt_and_incomplete_completion_are_rejected():
    ledger = DeletionReceiptLedger(max_entries=4)
    phase1 = ledger.approve_selection(identifier="ef" * 32, reason="tenant_purge")

    # Cannot complete when file_deleted=False or metadata_deleted=False while required
    with pytest.raises(ValueError, match="file_deleted"):
        ledger.complete_deletion(phase1.receipt_id, file_deleted=False, metadata_deleted=True)
    with pytest.raises(ValueError, match="metadata deletion"):
        ledger.complete_deletion(phase1.receipt_id, file_deleted=True, metadata_deleted=False)

    completed = ledger.complete_deletion(
        phase1.receipt_id,
        file_deleted=True,
        metadata_deleted=True,
    )
    tampered = completed.to_dict()
    tampered["actions"]["metadataDeleted"] = False
    assert verify_deletion_receipt(tampered) is False

    # Bounded capacity evicts oldest receipts deterministically
    for idx in range(6):
        r = ledger.approve_selection(identifier=f"item-{idx}", reason="unreferenced_blob_gc")
        ledger.complete_deletion(r.receipt_id, file_deleted=True, metadata_deleted=True)
    assert len(ledger.list_receipts(limit=100)) == 4


def test_sweep_job_files_emits_two_phase_receipts_without_retaining_filenames(tmp_path: Path):
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    stale_artifact = jobs_dir / "job_901_output"
    stale_artifact.write_bytes(b"ephemeral-job-payload")
    old_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).timestamp()
    os.utime(stale_artifact, (old_ts, old_ts))

    ledger = DeletionReceiptLedger()
    purged = sweep_job_files(
        storage_dir=jobs_dir,
        ttl_seconds=3600,
        now=datetime.now(timezone.utc),
        receipt_ledger=ledger,
    )
    assert purged == 1
    assert not stale_artifact.exists()

    receipts = ledger.list_receipts()
    assert len(receipts) == 1
    assert receipts[0]["phase"] == "completed"
    assert receipts[0]["reason"] == "expired_job_artifact"
    assert receipts[0]["actions"]["fileDeleted"] is True
    assert receipts[0]["actions"]["requiresMetadataDelete"] is False
    assert "job_901_output" not in str(receipts[0])
    assert verify_deletion_receipt(receipts[0], expected_identifier="job-file:job_901_output") is True
