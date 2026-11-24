import hashlib
import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

import evidence_storage
import storage


def _make_encrypted_blob(
    tmp_path: Path,
    plaintext: bytes,
    *,
    filename: str,
    size_mode: str = "ciphertext",
) -> tuple[dict, bytes]:
    dek, encrypted_dek = evidence_storage.generate_dek()
    ciphertext = evidence_storage.get_encryptor(dek).encrypt(plaintext)
    blob_path = tmp_path / filename
    blob_path.write_bytes(ciphertext)
    content_hash = hashlib.sha256(plaintext).hexdigest()
    size_bytes = len(ciphertext) if size_mode == "ciphertext" else len(plaintext)
    record = {
        "content_hash": content_hash,
        "encrypted_dek": encrypted_dek.decode("utf-8"),
        "size_bytes": size_bytes,
        "storage_path": str(blob_path),
    }
    return record, dek


def _make_fake_fetcher(records: list[dict]):
    ordered = sorted(records, key=lambda item: item["content_hash"])

    def _fetch(after_content_hash: str | None, limit: int) -> list[dict]:
        if after_content_hash is None:
            return ordered[:limit]
        return [r for r in ordered if r["content_hash"] > after_content_hash][:limit]

    return _fetch


def test_storage_integrity_progress_path_and_traversal_guard(tmp_path, monkeypatch):
    monkeypatch.setenv("HARPOCRATES_STORAGE_DIR", str(tmp_path))
    path = storage.get_integrity_progress_path()
    assert path == tmp_path / "evidence_integrity_progress.json"

    with pytest.raises(ValueError):
        storage.get_integrity_progress_path("../escape.json")
    with pytest.raises(ValueError):
        storage.get_integrity_progress_path("nested/progress.json")


def test_clamp_verify_batch_size_bounds():
    assert evidence_storage.clamp_verify_batch_size(None) == evidence_storage.DEFAULT_VERIFY_BATCH_SIZE
    assert evidence_storage.clamp_verify_batch_size(10) == 10
    assert (
        evidence_storage.clamp_verify_batch_size(evidence_storage.MAX_VERIFY_BATCH_SIZE + 100)
        == evidence_storage.MAX_VERIFY_BATCH_SIZE
    )
    with pytest.raises(ValueError):
        evidence_storage.clamp_verify_batch_size(0)
    with pytest.raises(ValueError):
        evidence_storage.clamp_verify_batch_size(-5)
    with pytest.raises(ValueError):
        evidence_storage.clamp_verify_batch_size(True)


def test_verify_blob_integrity_valid_ciphertext_and_plaintext_size(tmp_path, monkeypatch):
    monkeypatch.setenv("MASTER_ENCRYPTION_KEY", Fernet.generate_key().decode("utf-8"))

    rec_ct, _ = _make_encrypted_blob(tmp_path, b"synthetic-evidence-1", filename="b1.bin", size_mode="ciphertext")
    rec_pt, _ = _make_encrypted_blob(tmp_path, b"synthetic-evidence-2", filename="b2.bin", size_mode="plaintext")

    assert evidence_storage.verify_blob_integrity(rec_ct) == {
        "content_hash": rec_ct["content_hash"],
        "status": evidence_storage.STATUS_VERIFIED,
        "reason": "ok",
    }
    assert evidence_storage.verify_blob_integrity(rec_pt) == {
        "content_hash": rec_pt["content_hash"],
        "status": evidence_storage.STATUS_VERIFIED,
        "reason": "ok",
    }


def test_verify_blob_integrity_distinguishes_legacy_and_failures(tmp_path, monkeypatch):
    current_master = Fernet.generate_key().decode("utf-8")
    old_master = Fernet.generate_key().decode("utf-8")
    monkeypatch.setenv("MASTER_ENCRYPTION_KEY", old_master)

    legacy_rotated_key_blob, _ = _make_encrypted_blob(tmp_path, b"legacy-rotated", filename="legacy_rot.bin")

    monkeypatch.setenv("MASTER_ENCRYPTION_KEY", current_master)

    # Unverifiable legacy cases
    assert evidence_storage.verify_blob_integrity(legacy_rotated_key_blob)["status"] == (
        evidence_storage.STATUS_UNVERIFIABLE_LEGACY
    )
    assert evidence_storage.verify_blob_integrity(legacy_rotated_key_blob)["reason"] == "unreadable_legacy_dek"

    missing_dek = dict(legacy_rotated_key_blob, encrypted_dek="")
    assert evidence_storage.verify_blob_integrity(missing_dek)["status"] == (
        evidence_storage.STATUS_UNVERIFIABLE_LEGACY
    )
    assert evidence_storage.verify_blob_integrity(missing_dek)["reason"] == "missing_encrypted_dek"

    legacy_prefix = dict(legacy_rotated_key_blob, encrypted_dek="legacy:v0:opaque")
    assert evidence_storage.verify_blob_integrity(legacy_prefix)["status"] == (
        evidence_storage.STATUS_UNVERIFIABLE_LEGACY
    )
    assert evidence_storage.verify_blob_integrity(legacy_prefix)["reason"] == "legacy_dek_format"

    legacy_hash = dict(legacy_rotated_key_blob, content_hash="legacy-md5-deadbeef")
    assert evidence_storage.verify_blob_integrity(legacy_hash)["status"] == (
        evidence_storage.STATUS_UNVERIFIABLE_LEGACY
    )
    assert evidence_storage.verify_blob_integrity(legacy_hash)["reason"] == "legacy_hash_format"

    missing_size = dict(legacy_rotated_key_blob, size_bytes=None)
    assert evidence_storage.verify_blob_integrity(missing_size)["status"] == (
        evidence_storage.STATUS_UNVERIFIABLE_LEGACY
    )
    assert evidence_storage.verify_blob_integrity(missing_size)["reason"] == "missing_size_metadata"

    # Failure cases
    tampered_blob, _ = _make_encrypted_blob(tmp_path, b"tamper-me", filename="tampered.bin")
    Path(tampered_blob["storage_path"]).write_bytes(b"not-a-valid-fernet-token")
    res_tampered = evidence_storage.verify_blob_integrity(tampered_blob)
    assert res_tampered["status"] == evidence_storage.STATUS_FAILED
    assert res_tampered["reason"] == "corrupt_ciphertext"

    missing_file_blob, _ = _make_encrypted_blob(tmp_path, b"gone", filename="gone.bin")
    Path(missing_file_blob["storage_path"]).unlink()
    res_missing = evidence_storage.verify_blob_integrity(missing_file_blob)
    assert res_missing["status"] == evidence_storage.STATUS_FAILED
    assert res_missing["reason"] == "missing_blob"

    wrong_hash_blob, _ = _make_encrypted_blob(tmp_path, b"real-payload", filename="wrong_hash.bin")
    wrong_hash_blob["content_hash"] = hashlib.sha256(b"other-payload").hexdigest()
    res_hash = evidence_storage.verify_blob_integrity(wrong_hash_blob)
    assert res_hash["status"] == evidence_storage.STATUS_FAILED
    assert res_hash["reason"] == "hash_mismatch"

    wrong_size_blob, _ = _make_encrypted_blob(tmp_path, b"sized-payload", filename="wrong_size.bin")
    wrong_size_blob["size_bytes"] = 999999
    res_size = evidence_storage.verify_blob_integrity(wrong_size_blob)
    assert res_size["status"] == evidence_storage.STATUS_FAILED
    assert res_size["reason"] == "size_mismatch"

    bad_meta_blob = dict(wrong_size_blob, size_bytes=-1)
    res_meta = evidence_storage.verify_blob_integrity(bad_meta_blob)
    assert res_meta["status"] == evidence_storage.STATUS_FAILED
    assert res_meta["reason"] == "invalid_metadata"


def test_resumable_bounded_batches_and_nonsecret_progress(tmp_path, monkeypatch):
    master_key = Fernet.generate_key().decode("utf-8")
    monkeypatch.setenv("MASTER_ENCRYPTION_KEY", master_key)
    monkeypatch.setenv("HARPOCRATES_STORAGE_DIR", str(tmp_path / "state"))

    secret_plaintext = b"SENSITIVE_SYNTHETIC_MARKER_NEVER_PERSIST"
    rec1, dek1 = _make_encrypted_blob(tmp_path, secret_plaintext + b"-1", filename="e1.bin")
    rec2, _ = _make_encrypted_blob(tmp_path, secret_plaintext + b"-2", filename="e2.bin")
    rec3, _ = _make_encrypted_blob(tmp_path, secret_plaintext + b"-3", filename="e3.bin")
    Path(rec3["storage_path"]).write_bytes(b"corrupted-bytes")

    legacy_rec = {
        "content_hash": hashlib.sha256(b"legacy-item").hexdigest(),
        "encrypted_dek": "legacy:v0:unverifiable",
        "size_bytes": 11,
        "storage_path": str(tmp_path / "legacy.bin"),
    }
    rec4, _ = _make_encrypted_blob(tmp_path, secret_plaintext + b"-4", filename="e4.bin")

    records = [rec1, rec2, rec3, legacy_rec, rec4]
    fetcher = _make_fake_fetcher(records)
    progress_path = storage.get_integrity_progress_path()

    # Batch 1: processes 2 of 5
    p1 = evidence_storage.verify_evidence_resumable(
        batch_size=2,
        max_batches=1,
        progress_path=progress_path,
        fetch_batch=fetcher,
    )
    assert p1["status"] == "in_progress"
    assert p1["batches_completed"] == 1
    assert p1["totals"]["checked"] == 2
    assert p1["cursor"] is not None

    # Resume to completion: processes remaining 3 across 2 more batches
    p2 = evidence_storage.verify_evidence_resumable(
        batch_size=2,
        progress_path=progress_path,
        fetch_batch=fetcher,
    )
    assert p2["run_id"] == p1["run_id"]
    assert p2["status"] == "completed"
    assert p2["batches_completed"] == 3
    assert p2["totals"] == {
        "checked": 5,
        "verified": 3,
        "failed": 1,
        "unverifiable_legacy": 1,
    }
    assert p2["failure_reasons"] == {"corrupt_ciphertext": 1}
    assert p2["legacy_reasons"] == {"legacy_dek_format": 1}

    # Verify persisted progress contains NO secrets or storage paths
    raw_progress = progress_path.read_text(encoding="utf-8")
    assert "SENSITIVE_SYNTHETIC_MARKER_NEVER_PERSIST" not in raw_progress
    assert master_key not in raw_progress
    assert dek1.decode("utf-8") not in raw_progress
    assert rec1["encrypted_dek"] not in raw_progress
    assert str(tmp_path) not in raw_progress
    assert "e1.bin" not in raw_progress

    # Starting again after completion begins a new run_id
    p3 = evidence_storage.verify_evidence_resumable(
        batch_size=5,
        progress_path=progress_path,
        fetch_batch=fetcher,
    )
    assert p3["run_id"] != p2["run_id"]
    assert p3["status"] == "completed"
    assert p3["totals"]["checked"] == 5


def test_load_integrity_progress_fails_closed_on_corrupt_file(tmp_path):
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not-json", encoding="utf-8")
    with pytest.raises(ValueError):
        evidence_storage.load_integrity_progress(bad_json)

    wrong_version = tmp_path / "wrong_version.json"
    wrong_version.write_text(json.dumps({"schema_version": 999}), encoding="utf-8")
    with pytest.raises(ValueError):
        evidence_storage.load_integrity_progress(wrong_version)
