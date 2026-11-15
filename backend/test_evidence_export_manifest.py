"""Tests for the read-only encrypted evidence export manifest (issue #1049)."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from cryptography.fernet import Fernet
import pytest

_BACKEND_DIR = str(Path(__file__).resolve().parent)
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import evidence_storage
import storage


class _ExportFakeCursor:
    def __init__(self, conn: "_ExportFakeConn") -> None:
        self.conn = conn
        self._rows: list[Any] = []

    def __enter__(self) -> "_ExportFakeCursor":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        return None

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        self.conn.executed.append((sql, params))
        normalized = " ".join(sql.lower().split())
        assert normalized.startswith("select ")
        assert "for update" not in normalized

        if "b.content_hash = any(%s)" in normalized:
            tenant_id, requested_hashes, limit = params[0], set(params[1]), int(params[2])
        else:
            tenant_id, requested_hashes, limit = params[0], None, int(params[1])

        matched: list[dict[str, Any]] = []
        for content_hash in sorted(self.conn.blobs):
            if requested_hashes is not None and content_hash not in requested_hashes:
                continue
            ref = self.conn.refs.get((tenant_id, content_hash))
            if not ref or ref["ref_count"] <= 0:
                continue
            blob = self.conn.blobs[content_hash]
            row = dict(blob)
            row["ref_count"] = ref["ref_count"]
            matched.append(row)
            if len(matched) >= limit:
                break
        self._rows = matched

    def fetchone(self) -> Any:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[Any]:
        return list(self._rows)


class _ExportFakeConn:
    def __init__(self) -> None:
        self.blobs: dict[str, dict[str, Any]] = {}
        self.refs: dict[tuple[str, str], dict[str, Any]] = {}
        self.executed: list[tuple[str, tuple[Any, ...]]] = []
        self.commits = 0
        self.rollbacks = 0

    def cursor(self) -> _ExportFakeCursor:
        return _ExportFakeCursor(self)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def add_blob(
        self,
        *,
        content_hash: str,
        encrypted_dek: str | bytes | None,
        size_bytes: int,
        storage_path: str,
        extra_metadata: dict[str, Any] | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "content_hash": content_hash,
            "encrypted_dek": (
                encrypted_dek.decode("utf-8")
                if isinstance(encrypted_dek, bytes)
                else encrypted_dek
            ),
            "size_bytes": size_bytes,
            "storage_path": storage_path,
        }
        if extra_metadata:
            record.update(extra_metadata)
        self.blobs[content_hash] = record

    def set_ref(self, tenant_id: str, content_hash: str, ref_count: int) -> None:
        self.refs[(tenant_id, content_hash)] = {
            "tenant_id": tenant_id,
            "content_hash": content_hash,
            "ref_count": ref_count,
        }


@pytest.fixture
def export_db(monkeypatch: pytest.MonkeyPatch) -> _ExportFakeConn:
    conn = _ExportFakeConn()

    @contextmanager
    def _get_conn():
        yield conn

    monkeypatch.setattr(evidence_storage.db, "get_connection", _get_conn)
    return conn


def _write_fernet_blob(
    directory: Path,
    name: str,
    plaintext: bytes,
    master_key_b64: str,
) -> tuple[str, bytes, bytes, Path]:
    master = Fernet(master_key_b64.encode("ascii"))
    dek = Fernet.generate_key()
    wrapped_dek = master.encrypt(dek)
    ciphertext = Fernet(dek).encrypt(plaintext)
    content_hash = hashlib.sha256(plaintext).hexdigest()
    blob_path = directory / name
    blob_path.write_bytes(ciphertext)
    return content_hash, dek, wrapped_dek, blob_path


def test_export_manifest_includes_digests_envelope_versions_and_authorized_refs(
    export_db: _ExportFakeConn,
    tmp_path: Path,
) -> None:
    master_key = Fernet.generate_key().decode("ascii")
    hash_a, _dek_a, wrapped_a, path_a = _write_fernet_blob(
        tmp_path, "evidence_alpha.enc", b"synthetic-evidence-alpha", master_key
    )
    hash_b, _dek_b, _wrapped_b, path_b = _write_fernet_blob(
        tmp_path, "evidence_beta.enc", b"synthetic-evidence-beta", master_key
    )
    legacy_path = tmp_path / "evidence_legacy.enc"
    legacy_ciphertext = b"v0:raw-legacy-ciphertext-frame"
    legacy_path.write_bytes(legacy_ciphertext)
    hash_c = hashlib.sha256(b"synthetic-evidence-gamma").hexdigest()

    export_db.add_blob(
        content_hash=hash_a,
        encrypted_dek=wrapped_a,
        size_bytes=path_a.stat().st_size,
        storage_path=str(path_a),
    )
    export_db.add_blob(
        content_hash=hash_b,
        encrypted_dek="legacy-keywrap:opaque-header",
        size_bytes=path_b.stat().st_size,
        storage_path=str(path_b),
    )
    export_db.add_blob(
        content_hash=hash_c,
        encrypted_dek="",
        size_bytes=len(legacy_ciphertext),
        storage_path=str(legacy_path),
    )

    export_db.set_ref("tenant-alpha", hash_a, 2)
    export_db.set_ref("tenant-alpha", hash_b, 1)
    export_db.set_ref("tenant-alpha", hash_c, 4)

    fixed_now = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
    manifest = evidence_storage.build_encrypted_evidence_export_manifest(
        "tenant-alpha",
        now=fixed_now,
    )

    assert manifest["ok"] is True
    assert manifest["readOnly"] is True
    assert manifest["schema"] == storage.EXPORT_MANIFEST_SCHEMA
    assert manifest["generatedAt"] == "2026-11-15T12:00:00Z"
    assert manifest["entryCount"] == 3
    assert storage.verify_export_manifest_digest(manifest) is True

    by_digest = {entry["contentDigest"]: entry for entry in manifest["entries"]}
    assert list(by_digest.keys()) == sorted([hash_a, hash_b, hash_c])

    expected_tenant_digest = storage.compute_tenant_export_ref_digest("tenant-alpha")
    assert manifest["tenantRefDigest"] == expected_tenant_digest

    entry_a = by_digest[hash_a]
    assert entry_a["ciphertextSha256"] == hashlib.sha256(path_a.read_bytes()).hexdigest()
    assert entry_a["ciphertextBytes"] == path_a.stat().st_size
    assert entry_a["envelopeVersion"] == "fernet-v1"
    assert isinstance(entry_a["wrappedKeyCommitment"], str)
    assert len(entry_a["wrappedKeyCommitment"]) == 64
    assert entry_a["authorizedReferences"] == [
        {"tenantRefDigest": expected_tenant_digest, "refCount": 2}
    ]

    entry_b = by_digest[hash_b]
    assert entry_b["envelopeVersion"] == "fernet-v1-legacy-keywrap"
    assert entry_b["authorizedReferences"] == [
        {"tenantRefDigest": expected_tenant_digest, "refCount": 1}
    ]

    entry_c = by_digest[hash_c]
    assert entry_c["envelopeVersion"] == "legacy-unversioned"
    assert entry_c["wrappedKeyCommitment"] is None
    assert entry_c["authorizedReferences"] == [
        {"tenantRefDigest": expected_tenant_digest, "refCount": 4}
    ]


def test_export_manifest_excludes_unwrapped_deks_wrapped_deks_paths_and_media_metadata(
    export_db: _ExportFakeConn,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    master_key = Fernet.generate_key().decode("ascii")
    plaintext = b"confidential-witness-payload-never-decrypted"
    content_hash, raw_dek, wrapped_dek, blob_path = _write_fernet_blob(
        tmp_path, "secret_dir_blob.enc", plaintext, master_key
    )

    # Ensure MASTER_ENCRYPTION_KEY is absent and decrypt_dek is never invoked.
    monkeypatch.delenv("MASTER_ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr(
        evidence_storage,
        "decrypt_dek",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("decrypt_dek must never be called during manifest export")
        ),
    )

    sensitive_metadata = {
        "original_filename": "whistleblower-interview-recording-raw",
        "gps_coordinates": "37.7749,-122.4194",
        "device_serial": "CAM-SN-99887766",
        "capture_timestamp": "2026-11-01T03:14:15Z",
        "exif_summary": "Make=AcmeCamera;Lens=35mm",
        "uploader_identity": "alice@example.org",
        "plaintext_dek": raw_dek.decode("ascii"),
    }
    export_db.add_blob(
        content_hash=content_hash,
        encrypted_dek=wrapped_dek,
        size_bytes=blob_path.stat().st_size,
        storage_path=str(blob_path),
        extra_metadata=sensitive_metadata,
    )
    export_db.set_ref("tenant-privacy-check", content_hash, 1)

    manifest = evidence_storage.build_encrypted_evidence_export_manifest(
        "tenant-privacy-check"
    )
    serialized = json.dumps(manifest, sort_keys=True)

    forbidden_fragments = [
        master_key,
        raw_dek.decode("ascii"),
        wrapped_dek.decode("ascii"),
        str(blob_path),
        "secret_dir_blob.enc",
        "tenant-privacy-check",
        plaintext.decode("ascii"),
        *sensitive_metadata.values(),
        *sensitive_metadata.keys(),
    ]
    for secret_fragment in forbidden_fragments:
        assert secret_fragment not in serialized

    entry = manifest["entries"][0]
    assert set(entry.keys()) == {
        "contentDigest",
        "ciphertextSha256",
        "ciphertextBytes",
        "envelopeVersion",
        "wrappedKeyCommitment",
        "authorizedReferences",
    }


def test_export_manifest_isolates_authorized_tenant_and_hides_cross_tenant_refs(
    export_db: _ExportFakeConn,
    tmp_path: Path,
) -> None:
    master_key = Fernet.generate_key().decode("ascii")
    hash_shared, _, wrapped_shared, path_shared = _write_fernet_blob(
        tmp_path, "shared.enc", b"shared-evidence", master_key
    )
    hash_foreign, _, wrapped_foreign, path_foreign = _write_fernet_blob(
        tmp_path, "foreign.enc", b"foreign-tenant-evidence", master_key
    )
    hash_released, _, wrapped_released, path_released = _write_fernet_blob(
        tmp_path, "released.enc", b"zero-ref-evidence", master_key
    )

    for h, w, p in (
        (hash_shared, wrapped_shared, path_shared),
        (hash_foreign, wrapped_foreign, path_foreign),
        (hash_released, wrapped_released, path_released),
    ):
        export_db.add_blob(
            content_hash=h,
            encrypted_dek=w,
            size_bytes=p.stat().st_size,
            storage_path=str(p),
        )

    export_db.set_ref("tenant-owner", hash_shared, 3)
    export_db.set_ref("tenant-neighbor", hash_shared, 7)
    export_db.set_ref("tenant-neighbor", hash_foreign, 2)
    export_db.set_ref("tenant-owner", hash_released, 0)

    manifest = evidence_storage.build_encrypted_evidence_export_manifest(
        "tenant-owner",
        content_hashes=[hash_shared, hash_foreign, hash_released],
    )

    assert manifest["entryCount"] == 1
    only_entry = manifest["entries"][0]
    assert only_entry["contentDigest"] == hash_shared
    neighbor_digest = storage.compute_tenant_export_ref_digest("tenant-neighbor")
    owner_digest = storage.compute_tenant_export_ref_digest("tenant-owner")
    assert only_entry["authorizedReferences"] == [
        {"tenantRefDigest": owner_digest, "refCount": 3}
    ]
    assert neighbor_digest not in json.dumps(manifest)


def test_export_manifest_is_strictly_read_only_for_db_and_filesystem(
    export_db: _ExportFakeConn,
    tmp_path: Path,
) -> None:
    master_key = Fernet.generate_key().decode("ascii")
    content_hash, _, wrapped_dek, blob_path = _write_fernet_blob(
        tmp_path, "immutable.enc", b"immutable-ciphertext-check", master_key
    )
    before_bytes = blob_path.read_bytes()
    before_mtime_ns = blob_path.stat().st_mtime_ns

    export_db.add_blob(
        content_hash=content_hash,
        encrypted_dek=wrapped_dek,
        size_bytes=len(before_bytes),
        storage_path=str(blob_path),
    )
    export_db.set_ref("tenant-ro", content_hash, 1)

    manifest = evidence_storage.build_encrypted_evidence_export_manifest("tenant-ro")
    assert manifest["entryCount"] == 1
    assert export_db.commits == 0
    assert export_db.rollbacks == 1
    assert blob_path.read_bytes() == before_bytes
    assert blob_path.stat().st_mtime_ns == before_mtime_ns

    guard = evidence_storage._ReadOnlyCursorGuard(export_db.cursor())
    for forbidden_sql in (
        "insert into blobs values ('x')",
        "update tenant_blob_refs set ref_count = 0",
        "delete from blobs",
        "drop table blobs",
        "select content_hash from blobs for update",
    ):
        with pytest.raises(RuntimeError, match="strictly read-only"):
            guard.execute(forbidden_sql)


def test_export_manifest_digest_tamper_detection(
    export_db: _ExportFakeConn,
    tmp_path: Path,
) -> None:
    master_key = Fernet.generate_key().decode("ascii")
    content_hash, _, wrapped_dek, blob_path = _write_fernet_blob(
        tmp_path, "tamper.enc", b"tamper-check-bytes", master_key
    )
    export_db.add_blob(
        content_hash=content_hash,
        encrypted_dek=wrapped_dek,
        size_bytes=blob_path.stat().st_size,
        storage_path=str(blob_path),
    )
    export_db.set_ref("tenant-tamper", content_hash, 2)

    manifest = evidence_storage.build_encrypted_evidence_export_manifest("tenant-tamper")
    assert storage.verify_export_manifest_digest(manifest) is True

    tampered_ref = json.loads(json.dumps(manifest))
    tampered_ref["entries"][0]["authorizedReferences"][0]["refCount"] = 99
    assert storage.verify_export_manifest_digest(tampered_ref) is False

    tampered_env = json.loads(json.dumps(manifest))
    tampered_env["entries"][0]["envelopeVersion"] = "legacy-v0"
    assert storage.verify_export_manifest_digest(tampered_env) is False

    tampered_ro = json.loads(json.dumps(manifest))
    tampered_ro["readOnly"] = False
    assert storage.verify_export_manifest_digest(tampered_ro) is False


def test_export_manifest_limits_empty_selection_and_missing_file_boundaries(
    export_db: _ExportFakeConn,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("EVIDENCE_EXPORT_MANIFEST_MAX_BLOBS", "2500")
    empty_manifest = evidence_storage.build_encrypted_evidence_export_manifest(
        "tenant-empty",
        content_hashes=[],
    )
    assert empty_manifest["entryCount"] == 0
    assert empty_manifest["limitApplied"] == storage.EXPORT_MAX_LIMIT_CAP
    assert storage.verify_export_manifest_digest(empty_manifest) is True

    with pytest.raises(ValueError, match="authorized_tenant_id"):
        evidence_storage.build_encrypted_evidence_export_manifest("   ")

    for bad_limit in (0, -5, True, "not-an-int"):
        with pytest.raises(ValueError, match="limit"):
            evidence_storage.build_encrypted_evidence_export_manifest(
                "tenant-empty", limit=bad_limit
            )

    with pytest.raises(ValueError, match="content_hashes"):
        evidence_storage.build_encrypted_evidence_export_manifest(
            "tenant-empty", content_hashes="not-a-sequence"
        )

    missing_secret_path = tmp_path / "private_subdir" / "vanished_blob.enc"
    export_db.add_blob(
        content_hash="f" * 64,
        encrypted_dek="gAAAAABk-missing-file",
        size_bytes=128,
        storage_path=str(missing_secret_path),
    )
    export_db.set_ref("tenant-missing", "f" * 64, 1)

    with pytest.raises(FileNotFoundError) as exc_info:
        evidence_storage.build_encrypted_evidence_export_manifest("tenant-missing")
    assert str(missing_secret_path) not in str(exc_info.value)
    assert "vanished_blob.enc" not in str(exc_info.value)

    empty_blob_path = tmp_path / "truncated_zero.enc"
    empty_blob_path.write_bytes(b"")
    export_db.add_blob(
        content_hash="e" * 64,
        encrypted_dek="gAAAAABk-empty-file",
        size_bytes=0,
        storage_path=str(empty_blob_path),
    )
    export_db.set_ref("tenant-truncated", "e" * 64, 1)
    with pytest.raises(ValueError, match="empty or truncated"):
        evidence_storage.build_encrypted_evidence_export_manifest("tenant-truncated")
