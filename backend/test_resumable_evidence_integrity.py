"""Focused tests for resumable evidence integrity verification (#1051)."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import logging
from pathlib import Path

from cryptography.fernet import Fernet
import pytest

import evidence_storage
from evidence_storage import (
    STATUS_CORRUPTED,
    STATUS_UNVERIFIABLE_LEGACY,
    STATUS_VERIFIED,
    inspect_blob_integrity,
    verify_evidence_integrity_batch,
)
from storage import (
    INTEGRITY_VERIFY_BATCH_MAX,
    IntegrityCheckpointStore,
    clamp_integrity_batch_size,
    get_default_integrity_checkpoint_store,
)
from test_evidence_storage import FakeConnection, FakeCursor, FakeRow


class PaginatedFakeCursor(FakeCursor):
    """Extends FakeCursor with ordered paginated SELECT support for integrity scans."""

    def execute(self, sql: str, params: tuple = ()) -> None:
        normalized = " ".join(sql.lower().split())
        if (
            "select content_hash, encrypted_dek, size_bytes, storage_path from blobs"
            in normalized
            and "order by content_hash asc" in normalized
        ):
            limit, offset = int(params[0]), int(params[1])
            with self.connection.lock:
                ordered = sorted(
                    self.connection.blobs.values(),
                    key=lambda row: str(row["content_hash"]),
                )
                page = ordered[offset : offset + limit]
            self.executed.append((sql, params))
            self._results = [
                FakeRow(
                    content_hash=r["content_hash"],
                    encrypted_dek=r["encrypted_dek"],
                    size_bytes=r["size_bytes"],
                    storage_path=r["storage_path"],
                )
                for r in page
            ]
            self._idx = 0
            return
        super().execute(sql, params)


class PaginatedFakeConnection(FakeConnection):
    def cursor(self) -> PaginatedFakeCursor:
        cur = PaginatedFakeCursor(self)
        self.cursors.append(cur)
        return cur


@pytest.fixture(autouse=True)
def _clean_checkpoint_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("EVIDENCE_INTEGRITY_CHECKPOINT_PATH", raising=False)
    monkeypatch.delenv("EVIDENCE_INTEGRITY_BATCH_SIZE", raising=False)
    get_default_integrity_checkpoint_store().reset()
    yield
    get_default_integrity_checkpoint_store().reset()


@pytest.fixture
def fake_db(monkeypatch: pytest.MonkeyPatch) -> PaginatedFakeConnection:
    conn = PaginatedFakeConnection()

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


def _write_modern_blob(
    tmp_path: Path,
    name: str,
    plaintext: bytes,
) -> tuple[str, bytes, bytes, Path]:
    dek, encrypted_dek = evidence_storage.generate_dek()
    ciphertext = evidence_storage.get_encryptor(dek).encrypt(plaintext)
    digest = hashlib.sha256(plaintext).hexdigest()
    path = tmp_path / name
    path.write_bytes(ciphertext)
    evidence_storage.record_blob(digest, encrypted_dek, len(ciphertext), str(path))
    return digest, dek, encrypted_dek, path


def test_resumable_integrity_verification_across_bounded_batches_and_restarts(
    fake_db: PaginatedFakeConnection,
    master_key: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
):
    secret_media_1 = b"PRIVATE_EVIDENCE_STREAM_ONE_1051"
    secret_media_2 = b"PRIVATE_EVIDENCE_STREAM_TWO_1051"
    h1, dek1, enc_dek1, p1 = _write_modern_blob(tmp_path, "blob_valid_one.enc", secret_media_1)
    h2, dek2, enc_dek2, p2 = _write_modern_blob(tmp_path, "blob_valid_two.enc", secret_media_2)

    # Corrupted blob 1: tampered ciphertext bytes (matching size, invalid HMAC)
    h_tampered, _dek_t, _enc_t, p_tampered = _write_modern_blob(
        tmp_path, "blob_tampered.enc", b"tamper-target-bytes"
    )
    raw_ct = bytearray(p_tampered.read_bytes())
    raw_ct[-4] ^= 0x5A
    p_tampered.write_bytes(bytes(raw_ct))

    # Corrupted blob 2: recorded size mismatch
    h_sized, _dek_s, enc_s, p_sized = _write_modern_blob(
        tmp_path, "blob_truncated.enc", b"size-mismatch-target"
    )
    p_sized.write_bytes(p_sized.read_bytes()[:-5])

    # Unverifiable legacy blob: pre-envelope raw key marker, intact file & size
    legacy_path = tmp_path / "legacy_pre_v1_blob.enc"
    legacy_bytes = b"legacy-unauthenticated-ciphertext"
    legacy_path.write_bytes(legacy_bytes)
    legacy_id = "00" * 32
    evidence_storage.record_blob(legacy_id, b"legacy-raw-key-marker", len(legacy_bytes), str(legacy_path))

    ckpt_file = tmp_path / "state" / "integrity_checkpoint.json"
    caplog.set_level(logging.INFO)

    # Batch 1: scans 2 of 5 blobs and persists non-secret checkpoint
    r1 = verify_evidence_integrity_batch(batch_size=2, checkpoint_path=ckpt_file)
    assert r1["batchSize"] == 2
    assert r1["batchScanned"] == 2
    assert r1["checkpoint"]["scannedCount"] == 2
    assert r1["checkpoint"]["completed"] is False
    assert ckpt_file.exists()

    # Simulate process restart by instantiating a brand-new IntegrityCheckpointStore on ckpt_file
    restarted_store_2 = IntegrityCheckpointStore(checkpoint_path=ckpt_file)
    r2 = verify_evidence_integrity_batch(batch_size=2, checkpoint_store=restarted_store_2)
    assert r2["batchScanned"] == 2
    assert r2["checkpoint"]["scannedCount"] == 4
    assert r2["checkpoint"]["completed"] is False

    # Batch 3: scans final 1 blob (< batch_size=2) -> marks completed=True
    restarted_store_3 = IntegrityCheckpointStore(checkpoint_path=ckpt_file)
    r3 = verify_evidence_integrity_batch(batch_size=2, checkpoint_store=restarted_store_3)
    assert r3["batchScanned"] == 1
    assert r3["checkpoint"]["completed"] is True
    assert r3["checkpoint"]["scannedCount"] == 5
    assert r3["checkpoint"]["verifiedCount"] == 2
    assert r3["checkpoint"]["corruptedCount"] == 2
    assert r3["checkpoint"]["unverifiableLegacyCount"] == 1

    # Calling again once completed is an idempotent no-op unless reset=True
    r4 = verify_evidence_integrity_batch(batch_size=2, checkpoint_store=restarted_store_3)
    assert r4["batchScanned"] == 0
    assert r4["checkpoint"]["completed"] is True

    # Strict privacy check on persisted checkpoint file, responses, and logs
    ckpt_text = ckpt_file.read_text(encoding="utf-8")
    combined_outputs = "\n".join([ckpt_text, str(r1), str(r2), str(r3), caplog.text])
    for secret in (
        master_key,
        dek1.decode("ascii"),
        dek2.decode("ascii"),
        enc_dek1.decode("ascii"),
        enc_dek2.decode("ascii"),
        enc_s.decode("ascii"),
        secret_media_1.decode("ascii"),
        secret_media_2.decode("ascii"),
        str(p1),
        str(p2),
        str(legacy_path),
        "blob_valid_one.enc",
        h1,
        h2,
        h_tampered,
        h_sized,
    ):
        assert secret not in combined_outputs


def test_distinguishes_legacy_blobs_from_missing_or_truncated_legacy_files(
    master_key: str,
    tmp_path: Path,
):
    # Legacy blob with empty encrypted_dek and intact file -> unverifiable_legacy
    intact_file = tmp_path / "legacy_intact.enc"
    intact_file.write_bytes(b"1234567890")
    status, reason = inspect_blob_integrity(
        {
            "content_hash": "ab" * 32,
            "encrypted_dek": "",
            "size_bytes": 10,
            "storage_path": str(intact_file),
        }
    )
    assert (status, reason) == (STATUS_UNVERIFIABLE_LEGACY, "missing_envelope_key")

    # Modern Fernet AEAD blob with non-SHA256 legacy identifier -> unverifiable_legacy (AEAD valid!)
    dek, enc_dek = evidence_storage.generate_dek()
    ct = evidence_storage.get_encryptor(dek).encrypt(b"authenticated-legacy-id")
    legacy_id_file = tmp_path / "legacy_id_modern_ct.enc"
    legacy_id_file.write_bytes(ct)
    status_id, reason_id = inspect_blob_integrity(
        {
            "content_hash": "legacy-evidence-key-7",
            "encrypted_dek": enc_dek.decode("ascii"),
            "size_bytes": len(ct),
            "storage_path": str(legacy_id_file),
        }
    )
    assert (status_id, reason_id) == (
        STATUS_UNVERIFIABLE_LEGACY,
        "legacy_non_sha256_identifier",
    )

    # Legacy blob whose file was truncated or missing -> corrupted!
    status_trunc, reason_trunc = inspect_blob_integrity(
        {
            "content_hash": "ab" * 32,
            "encrypted_dek": "",
            "size_bytes": 999,
            "storage_path": str(intact_file),
        }
    )
    assert (status_trunc, reason_trunc) == (STATUS_CORRUPTED, "size_mismatch")

    status_missing, reason_missing = inspect_blob_integrity(
        {
            "content_hash": "ab" * 32,
            "encrypted_dek": "",
            "size_bytes": 10,
            "storage_path": str(tmp_path / "does_not_exist.enc"),
        }
    )
    assert (status_missing, reason_missing) == (
        STATUS_CORRUPTED,
        "missing_ciphertext_file",
    )


def test_batch_size_bounds_and_invalid_inputs():
    assert clamp_integrity_batch_size(None) == 50
    assert clamp_integrity_batch_size(1) == 1
    assert clamp_integrity_batch_size(99999) == INTEGRITY_VERIFY_BATCH_MAX
    for bad in (0, -5, "nope", False, True):
        with pytest.raises(ValueError, match="batch_size"):
            clamp_integrity_batch_size(bad)
