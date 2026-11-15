"""Focused regression and privacy boundary tests for issue #1047:
add per-tenant evidence retention previews.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as app_module  # noqa: E402
import db as db_module  # noqa: E402
import evidence_storage  # noqa: E402
import storage  # noqa: E402
import strkey  # noqa: E402


class _FakeRetentionDB:
    def __init__(self) -> None:
        self.blobs: dict[str, dict[str, object]] = {}
        self.refs: dict[tuple[str, str], dict[str, object]] = {}
        self._rows: list[dict[str, object]] = []

    def add_blob(
        self,
        content_hash: str,
        *,
        size_bytes: int,
        storage_path: str,
        encrypted_dek: str = "synthetic-dek-placeholder",
        created_at: datetime,
    ) -> None:
        self.blobs[content_hash] = {
            "content_hash": content_hash,
            "encrypted_dek": encrypted_dek,
            "size_bytes": size_bytes,
            "storage_path": storage_path,
            "created_at": created_at,
        }

    def add_ref(
        self,
        tenant_id: str,
        content_hash: str,
        *,
        ref_count: int = 1,
        created_at: datetime,
    ) -> None:
        self.refs[(tenant_id, content_hash)] = {
            "tenant_id": tenant_id,
            "content_hash": content_hash,
            "ref_count": ref_count,
            "created_at": created_at,
            "updated_at": created_at,
        }

    @contextmanager
    def connection(self):
        yield self

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return None

    def execute(self, sql: str, params: tuple = ()) -> None:
        normalized = " ".join(sql.lower().split())
        if "from tenant_blob_refs t" in normalized:
            external_exclude_tenant, target_tenant = params
            matched: list[dict[str, object]] = []
            for (tenant_id, content_hash), ref in self.refs.items():
                if tenant_id != target_tenant or int(ref["ref_count"]) <= 0:
                    continue
                blob = self.blobs.get(content_hash, {})
                has_external = any(
                    other_tenant != external_exclude_tenant and int(other_ref["ref_count"]) > 0
                    for (other_tenant, other_hash), other_ref in self.refs.items()
                    if other_hash == content_hash
                )
                matched.append(
                    {
                        "content_hash": content_hash,
                        "ref_count": ref["ref_count"],
                        "created_at": ref["created_at"],
                        "updated_at": ref["updated_at"],
                        "size_bytes": blob.get("size_bytes", 0),
                        "blob_created_at": blob.get("created_at"),
                        "has_external_refs": has_external,
                    }
                )
            matched.sort(key=lambda r: (r["created_at"], r["content_hash"]))
            self._rows = matched

    def fetchall(self):
        return list(self._rows)


class TenantRetentionPreviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
        self.tenant_a = strkey.make_strkey(strkey._VERSION_BYTE_ED25519_PUBLIC, b"\x11" * 32)
        self.tenant_b = strkey.make_strkey(strkey._VERSION_BYTE_ED25519_PUBLIC, b"\x22" * 32)
        self.fake_db = _FakeRetentionDB()

        # 1) Sole expired blob owned by tenant A -> eligible_for_deletion
        self.hash_sole_expired = "1" * 64
        self.fake_db.add_blob(
            self.hash_sole_expired,
            size_bytes=4096,
            storage_path="/var/private/blobs/11/secret_path_1",
            created_at=self.now - timedelta(hours=48),
        )
        self.fake_db.add_ref(
            self.tenant_a,
            self.hash_sole_expired,
            ref_count=1,
            created_at=self.now - timedelta(hours=48),
        )

        # 2) Expired blob shared with tenant B -> shared_blob_retained
        self.hash_shared = "2" * 64
        self.fake_db.add_blob(
            self.hash_shared,
            size_bytes=8192,
            storage_path="/var/private/blobs/22/secret_path_2",
            created_at=self.now - timedelta(hours=36),
        )
        self.fake_db.add_ref(
            self.tenant_a,
            self.hash_shared,
            ref_count=1,
            created_at=self.now - timedelta(hours=30),
        )
        self.fake_db.add_ref(
            self.tenant_b,
            self.hash_shared,
            ref_count=2,
            created_at=self.now - timedelta(hours=10),
        )

        # 3) Expired blob with multiple references held by tenant A -> multiple_tenant_references
        self.hash_multi_ref = "3" * 64
        self.fake_db.add_blob(
            self.hash_multi_ref,
            size_bytes=2048,
            storage_path="/var/private/blobs/33/secret_path_3",
            created_at=self.now - timedelta(hours=26),
        )
        self.fake_db.add_ref(
            self.tenant_a,
            self.hash_multi_ref,
            ref_count=3,
            created_at=self.now - timedelta(hours=26),
        )

        # 4) Fresh blob within TTL held by tenant A -> within_retention_window
        self.hash_fresh = "4" * 64
        self.fake_db.add_blob(
            self.hash_fresh,
            size_bytes=1024,
            storage_path="/var/private/blobs/44/secret_path_4",
            created_at=self.now - timedelta(hours=2),
        )
        self.fake_db.add_ref(
            self.tenant_a,
            self.hash_fresh,
            ref_count=1,
            created_at=self.now - timedelta(hours=2),
        )

        # 5) Private blob owned EXCLUSIVELY by tenant B -> must NEVER leak to tenant A!
        self.hash_tenant_b_secret = "9" * 64
        self.fake_db.add_blob(
            self.hash_tenant_b_secret,
            size_bytes=65536,
            storage_path="/var/private/blobs/99/tenant_b_secret_file",
            created_at=self.now - timedelta(hours=72),
        )
        self.fake_db.add_ref(
            self.tenant_b,
            self.hash_tenant_b_secret,
            ref_count=1,
            created_at=self.now - timedelta(hours=72),
        )

        self._db_patch = patch.object(
            evidence_storage.db,
            "get_connection",
            self.fake_db.connection,
        )
        self._db_patch.start()

    def tearDown(self) -> None:
        self._db_patch.stop()

    def test_preview_reports_counts_ages_and_eligibility_without_leaking_other_tenants_or_paths(self) -> None:
        preview = evidence_storage.preview_tenant_retention(
            self.tenant_a,
            retention_ttl_seconds=86_400,
            now=self.now,
        )

        self.assertEqual(preview["tenant_id"], self.tenant_a)
        self.assertEqual(
            preview["counts"],
            {
                "total_blobs": 4,
                "total_references": 6,
                "expired_blobs": 3,
                "within_retention_window": 1,
                "eligible_for_deletion": 1,
                "retained_by_shared_reference": 1,
                "total_size_bytes": 4096 + 8192 + 2048 + 1024,
                "reclaimable_size_bytes": 4096,
            },
        )
        self.assertEqual(preview["ages"]["oldest_age_seconds"], 48 * 3600.0)
        self.assertEqual(preview["ages"]["newest_age_seconds"], 2 * 3600.0)
        self.assertFalse(preview["truncated"])

        by_hash = {item["content_hash"]: item for item in preview["items"]}
        self.assertNotIn(self.hash_tenant_b_secret, by_hash)
        self.assertEqual(by_hash[self.hash_sole_expired]["eligibility_status"], "eligible_for_deletion")
        self.assertTrue(by_hash[self.hash_sole_expired]["eligible_for_deletion"])
        self.assertEqual(by_hash[self.hash_shared]["eligibility_status"], "shared_blob_retained")
        self.assertFalse(by_hash[self.hash_shared]["eligible_for_deletion"])
        self.assertEqual(by_hash[self.hash_multi_ref]["eligibility_status"], "multiple_tenant_references")
        self.assertFalse(by_hash[self.hash_multi_ref]["eligible_for_deletion"])
        self.assertEqual(by_hash[self.hash_fresh]["eligibility_status"], "within_retention_window")
        self.assertFalse(by_hash[self.hash_fresh]["eligible_for_deletion"])

        serialized = json.dumps(preview)
        self.assertNotIn(self.hash_tenant_b_secret, serialized)
        self.assertNotIn(self.tenant_b, serialized)
        self.assertNotIn("storage_path", serialized)
        self.assertNotIn("secret_path", serialized)
        self.assertNotIn("encrypted_dek", serialized)

    def test_cross_tenant_or_missing_identity_and_invalid_bounds_fail_closed(self) -> None:
        with self.assertRaises(evidence_storage.TenantAccessDeniedError):
            evidence_storage.preview_tenant_retention("")

        with self.assertRaises(evidence_storage.TenantAccessDeniedError):
            evidence_storage.preview_tenant_retention(
                self.tenant_a,
                requested_tenant_id=self.tenant_b,
            )

        with self.assertRaises(ValueError):
            evidence_storage.preview_tenant_retention(self.tenant_a, retention_ttl_seconds=0)

        with self.assertRaises(ValueError):
            evidence_storage.preview_tenant_retention(self.tenant_a, max_items=0)

        truncated = evidence_storage.preview_tenant_retention(
            self.tenant_a,
            retention_ttl_seconds=86_400,
            now=self.now,
            max_items=2,
        )
        self.assertEqual(len(truncated["items"]), 2)
        self.assertTrue(truncated["truncated"])
        self.assertEqual(truncated["counts"]["total_blobs"], 4)

    def test_storage_preview_tenant_job_retention_is_readonly_and_path_private(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            file_a_expired = root / "job_101_input"
            file_a_expired.write_bytes(b"a" * 300)
            file_a_running = root / "job_102_input"
            file_a_running.write_bytes(b"b" * 150)
            file_b_expired = root / "job_201_input"
            file_b_expired.write_bytes(b"c" * 900)

            jobs = {
                101: {
                    "id": 101,
                    "tenant_id": self.tenant_a,
                    "status": "completed",
                    "completed_at": (self.now - timedelta(hours=30)).isoformat(),
                },
                102: {
                    "id": 102,
                    "tenant_id": self.tenant_a,
                    "status": "running",
                    "created_at": (self.now - timedelta(hours=40)).isoformat(),
                },
                201: {
                    "id": 201,
                    "tenant_id": self.tenant_b,
                    "status": "completed",
                    "completed_at": (self.now - timedelta(hours=50)).isoformat(),
                },
            }

            with patch.object(db_module, "get_job", side_effect=lambda jid: jobs.get(jid)):
                preview = storage.preview_tenant_job_retention(
                    self.tenant_a,
                    storage_dir=root,
                    ttl_seconds=86_400,
                    now=self.now,
                )

            self.assertEqual(
                preview["counts"],
                {
                    "total_files": 2,
                    "eligible_for_deletion": 1,
                    "within_retention_window": 0,
                    "active_protected": 1,
                    "total_size_bytes": 450,
                    "reclaimable_size_bytes": 300,
                },
            )
            # Read-only guarantee: all files still exist on disk!
            self.assertTrue(file_a_expired.exists())
            self.assertTrue(file_a_running.exists())
            self.assertTrue(file_b_expired.exists())

            dumped = json.dumps(preview)
            self.assertNotIn(str(root), dumped)
            self.assertNotIn("job_201", dumped)
            self.assertNotIn(self.tenant_b, dumped)

    def test_authenticated_http_endpoint_enforces_scoped_tenant_ownership(self) -> None:
        token_a = "scoped-secret-token-tenant-a"
        token_b = "scoped-secret-token-tenant-b"
        legacy_token = "legacy-unscoped-key"
        digest_a = hashlib.sha256(token_a.encode("utf-8")).hexdigest()
        digest_b = hashlib.sha256(token_b.encode("utf-8")).hexdigest()

        env = {
            "REGISTER_API_KEY": legacy_token,
            "REGISTER_SCOPED_KEYS": f"{self.tenant_a}:{digest_a},{self.tenant_b}:{digest_b}",
        }
        with patch.dict(os.environ, env, clear=False):
            flask_app = app_module.create_app()
            client = flask_app.test_client()

            unauth = client.get("/api/evidence/retention-preview")
            self.assertEqual(unauth.status_code, 401)

            unscoped = client.get(
                "/api/evidence/retention-preview",
                headers={"Authorization": f"Bearer {legacy_token}"},
            )
            self.assertEqual(unscoped.status_code, 403)

            forbidden = client.get(
                f"/api/evidence/retention-preview?tenantId={self.tenant_b}",
                headers={"Authorization": f"Bearer {token_a}"},
            )
            self.assertEqual(forbidden.status_code, 403)

            ok = client.get(
                "/api/evidence/retention-preview?ttlSeconds=86400",
                headers={"Authorization": f"Bearer {token_a}"},
            )
            self.assertEqual(ok.status_code, 200)
            body = ok.get_json()
            self.assertEqual(body["tenant_id"], self.tenant_a)
            self.assertEqual(body["counts"]["total_blobs"], 4)
            self.assertNotIn(self.hash_tenant_b_secret, json.dumps(body))
            self.assertNotIn("storage_path", json.dumps(body))

        with patch.dict(
            os.environ,
            {
                **env,
                "REGISTER_API_KEY_EXPIRES": "2020-01-01T00:00:00Z",
            },
            clear=False,
        ):
            expired_client = app_module.create_app().test_client()
            expired = expired_client.get(
                "/api/evidence/retention-preview",
                headers={"Authorization": f"Bearer {token_a}"},
            )
            self.assertEqual(expired.status_code, 401)


if __name__ == "__main__":
    unittest.main()
