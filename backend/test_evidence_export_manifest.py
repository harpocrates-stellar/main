from datetime import datetime, timezone
import hashlib
import json
from unittest.mock import patch

import pytest

import evidence_storage


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
FIXED_TS = datetime(2026, 11, 21, 12, 0, 0, tzinfo=timezone.utc)


class _FakeCursor:
    def __init__(self, rows):
        self._rows = rows
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchall(self):
        return list(self._rows)


class _FakeConnection:
    def __init__(self, rows):
        self.cursor_obj = _FakeCursor(rows)
        self.committed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.committed = True


def test_build_manifest_includes_digests_envelope_versions_and_authorized_refs():
    rows = [
        {
            "content_hash": DIGEST_B.upper(),
            "size_bytes": 2048,
            "tenant_id": "tenant-b",
            "ref_count": 2,
        },
        {
            "content_hash": DIGEST_A,
            "size_bytes": 1024,
            "tenant_id": "tenant-a",
            "ref_count": 1,
            "envelope_version": "fernet-v1",
        },
        {
            "content_hash": DIGEST_A,
            "size_bytes": 1024,
            "tenant_id": "tenant-b",
            "ref_count": 3,
            "envelope_version": "fernet-v1",
        },
    ]

    manifest = evidence_storage.build_evidence_export_manifest(
        rows,
        authorized_tenants=["tenant-b", "tenant-a"],
        generated_at=FIXED_TS,
    )

    assert manifest["manifest_version"] == evidence_storage.EXPORT_MANIFEST_VERSION
    assert manifest["read_only"] is True
    assert manifest["generated_at"] == FIXED_TS.isoformat()
    assert manifest["authorized_tenants"] == ["tenant-a", "tenant-b"]
    assert manifest["entry_count"] == 2
    assert manifest["entries"] == [
        {
            "blob_digest": DIGEST_A,
            "envelope_version": "fernet-v1",
            "size_bytes": 1024,
            "authorized_references": [
                {"tenant_id": "tenant-a", "ref_count": 1},
                {"tenant_id": "tenant-b", "ref_count": 3},
            ],
        },
        {
            "blob_digest": DIGEST_B,
            "envelope_version": evidence_storage.DEFAULT_ENVELOPE_VERSION,
            "size_bytes": 2048,
            "authorized_references": [
                {"tenant_id": "tenant-b", "ref_count": 2},
            ],
        },
    ]

    payload_without_digest = {k: v for k, v in manifest.items() if k != "manifest_digest"}
    expected_digest = hashlib.sha256(
        evidence_storage.serialize_evidence_export_manifest(payload_without_digest).encode("utf-8")
    ).hexdigest()
    assert manifest["manifest_digest"] == expected_digest


def test_manifest_excludes_unwrapped_keys_and_sensitive_media_metadata():
    rows = [
        {
            "content_hash": DIGEST_A,
            "size_bytes": 512,
            "tenant_id": "tenant-a",
            "ref_count": 1,
            "dek": "UNWRAPPED-DEK-SECRET",
            "unwrapped_dek": "UNWRAPPED-DEK-SECRET-2",
            "encrypted_dek": "WRAPPED-DEK-VALUE",
            "storage_path": "/tmp/harpocrates_jobs/secret_video.mp4",
            "filename": "witness_interview.mp4",
            "media_metadata": {"gps": "37.7749,-122.4194", "camera": "synthetic-cam"},
            "exif": {"serial": "SYNTH-001"},
            "raw_bytes": "synthetic-raw-bytes",
        }
    ]

    manifest = evidence_storage.build_evidence_export_manifest(
        rows,
        authorized_tenants=["tenant-a"],
        generated_at=FIXED_TS,
    )
    serialized = evidence_storage.serialize_evidence_export_manifest(manifest)

    for forbidden in (
        "UNWRAPPED-DEK-SECRET",
        "WRAPPED-DEK-VALUE",
        "encrypted_dek",
        "storage_path",
        "secret_video.mp4",
        "witness_interview.mp4",
        "media_metadata",
        "37.7749",
        "SYNTH-001",
        "raw_bytes",
    ):
        assert forbidden not in serialized

    assert set(manifest["entries"][0].keys()) == {
        "blob_digest",
        "envelope_version",
        "size_bytes",
        "authorized_references",
    }


def test_manifest_filters_unauthorized_tenants_and_unreferenced_blobs():
    rows = [
        {
            "content_hash": DIGEST_A,
            "size_bytes": 512,
            "tenant_id": "tenant-other",
            "ref_count": 4,
        },
        {
            "content_hash": DIGEST_B,
            "size_bytes": 512,
            "tenant_id": "tenant-a",
            "ref_count": 0,
        },
    ]

    manifest = evidence_storage.build_evidence_export_manifest(
        rows,
        authorized_tenants=["tenant-a"],
        generated_at=FIXED_TS,
    )

    assert manifest["entry_count"] == 0
    assert manifest["entries"] == []
    assert len(manifest["manifest_digest"]) == 64


def test_export_evidence_manifest_is_read_only_and_never_unwraps_deks(monkeypatch):
    monkeypatch.delenv("MASTER_ENCRYPTION_KEY", raising=False)
    fake_conn = _FakeConnection(
        [
            {
                "content_hash": DIGEST_A,
                "size_bytes": 4096,
                "tenant_id": "tenant-a",
                "ref_count": 2,
            }
        ]
    )

    with patch.object(evidence_storage.db, "get_connection", return_value=fake_conn):
        with patch.object(evidence_storage, "decrypt_dek", side_effect=AssertionError("must not unwrap DEKs")):
            manifest = evidence_storage.export_evidence_manifest(
                authorized_tenants=["tenant-a"],
                generated_at=FIXED_TS,
            )

    assert fake_conn.committed is False
    assert len(fake_conn.cursor_obj.executed) == 1
    sql, params = fake_conn.cursor_obj.executed[0]
    sql_lower = sql.lower()
    assert "select" in sql_lower
    assert "encrypted_dek" not in sql_lower
    assert "storage_path" not in sql_lower
    assert params == (["tenant-a"],)
    assert manifest["entry_count"] == 1
    assert manifest["entries"][0]["blob_digest"] == DIGEST_A


@pytest.mark.parametrize(
    "bad_tenants",
    [
        [],
        "tenant-a",
        [""],
        ["   "],
        [123],
    ],
)
def test_manifest_rejects_invalid_authorized_tenants(bad_tenants):
    with pytest.raises(ValueError):
        evidence_storage.build_evidence_export_manifest([], authorized_tenants=bad_tenants)


def test_manifest_rejects_malformed_digest_and_invalid_fields():
    with pytest.raises(ValueError, match="blob digest"):
        evidence_storage.build_evidence_export_manifest(
            [{"content_hash": "not-a-hex-digest", "size_bytes": 10, "tenant_id": "t1", "ref_count": 1}],
            authorized_tenants=["t1"],
        )

    with pytest.raises(ValueError, match="envelope_version"):
        evidence_storage.build_evidence_export_manifest(
            [],
            authorized_tenants=["t1"],
            envelope_version="   ",
        )

    with pytest.raises(ValueError, match="size_bytes"):
        evidence_storage.build_evidence_export_manifest(
            [{"content_hash": DIGEST_A, "size_bytes": -1, "tenant_id": "t1", "ref_count": 1}],
            authorized_tenants=["t1"],
        )

    with pytest.raises(ValueError, match="generated_at"):
        evidence_storage.build_evidence_export_manifest(
            [],
            authorized_tenants=["t1"],
            generated_at=datetime(2026, 11, 21, 12, 0, 0),
        )


def test_manifest_rejects_conflicting_blob_metadata():
    rows = [
        {"content_hash": DIGEST_A, "size_bytes": 100, "tenant_id": "t1", "ref_count": 1},
        {"content_hash": DIGEST_A, "size_bytes": 200, "tenant_id": "t2", "ref_count": 1},
    ]
    with pytest.raises(ValueError, match="conflicting size_bytes"):
        evidence_storage.build_evidence_export_manifest(rows, authorized_tenants=["t1", "t2"])


def test_serialize_manifest_is_valid_canonical_json():
    manifest = evidence_storage.build_evidence_export_manifest(
        [{"content_hash": DIGEST_A, "size_bytes": 64, "tenant_id": "t1", "ref_count": 1}],
        authorized_tenants=["t1"],
        generated_at=FIXED_TS,
    )
    serialized = evidence_storage.serialize_evidence_export_manifest(manifest)
    assert json.loads(serialized) == manifest
    assert "\n" not in serialized
