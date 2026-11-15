"""Focused regression and read-only boundary tests for issue #1045:
expose an evidence storage consistency report.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import evidence_storage  # noqa: E402
import manage  # noqa: E402


class _ReadOnlyAuditDB:
    def __init__(self) -> None:
        self.blobs: list[dict[str, object]] = []
        self.refs: list[dict[str, object]] = []
        self.executed_sql: list[str] = []
        self._rows: list[dict[str, object]] = []

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
        self.executed_sql.append(normalized)
        for forbidden in ("insert ", "update ", "delete ", "drop ", "alter ", "truncate "):
            if forbidden in f" {normalized} ":
                raise AssertionError(f"Consistency report executed mutating SQL: {normalized}")

        if normalized.startswith("select content_hash, size_bytes, storage_path from blobs"):
            self._rows = list(self.blobs)
        elif normalized.startswith("select tenant_id, content_hash, ref_count from tenant_blob_refs"):
            self._rows = list(self.refs)

    def fetchall(self):
        return list(self._rows)


class EvidenceConsistencyReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fake_db = _ReadOnlyAuditDB()
        self._db_patch = patch.object(
            evidence_storage.db,
            "get_connection",
            self.fake_db.connection,
        )
        self._db_patch.start()

    def tearDown(self) -> None:
        self._db_patch.stop()

    def test_clean_consistent_store_reports_zero_anomalies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            blob_path = root / "aa" / "healthy.enc"
            blob_path.parent.mkdir(parents=True, exist_ok=True)
            blob_path.write_bytes(b"encrypted-healthy-bytes")

            content_hash = "a" * 64
            self.fake_db.blobs.append(
                {
                    "content_hash": content_hash,
                    "size_bytes": 23,
                    "storage_path": str(blob_path),
                }
            )
            self.fake_db.refs.append(
                {
                    "tenant_id": "tenant-healthy",
                    "content_hash": content_hash,
                    "ref_count": 2,
                }
            )

            report = evidence_storage.generate_consistency_report(
                storage_dir=root,
                now=datetime(2026, 11, 15, 18, 0, tzinfo=timezone.utc),
            )
            self.assertTrue(report["consistent"])
            self.assertEqual(report["schema"], evidence_storage.CONSISTENCY_REPORT_SCHEMA)
            self.assertEqual(
                report["counts"],
                {
                    "blobs_checked": 1,
                    "active_tenant_references_checked": 1,
                    "physical_files_scanned": 1,
                    "missing_physical_files": 0,
                    "referenced_missing_physical_files": 0,
                    "dangling_tenant_references": 0,
                    "stale_non_positive_references": 0,
                    "unreferenced_blob_records": 0,
                    "orphaned_physical_files": 0,
                    "orphaned_physical_bytes": 0,
                },
            )
            self.assertTrue(blob_path.exists())

    def test_detects_missing_orphaned_and_dangling_records_without_modifying_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)

            # 1) Healthy referenced blob + file
            healthy_file = root / "healthy.enc"
            healthy_bytes = b"synthetic-ciphertext-healthy"
            healthy_file.write_bytes(healthy_bytes)
            hash_healthy = "1" * 64

            # 2) Referenced blob whose physical file is missing!
            missing_file = root / "missing_referenced.enc"
            hash_missing_ref = "2" * 64

            # 3) Unreferenced DB blob whose physical file still exists on disk
            unref_file = root / "unreferenced.enc"
            unref_bytes = b"synthetic-ciphertext-unreferenced"
            unref_file.write_bytes(unref_bytes)
            hash_unref = "3" * 64

            # 4) Orphaned physical files on disk with NO blob metadata row
            orphan_1 = root / "orphan_a.enc"
            orphan_2 = root / "nested" / "orphan_b.enc"
            orphan_2.parent.mkdir(parents=True, exist_ok=True)
            orphan_1.write_bytes(b"o" * 120)
            orphan_2.write_bytes(b"p" * 80)

            # 5) Dangling tenant reference to non-existent blob + stale zero-ref row
            hash_dangling = "9" * 64

            self.fake_db.blobs.extend(
                [
                    {"content_hash": hash_healthy, "size_bytes": len(healthy_bytes), "storage_path": str(healthy_file)},
                    {"content_hash": hash_missing_ref, "size_bytes": 512, "storage_path": str(missing_file)},
                    {"content_hash": hash_unref, "size_bytes": len(unref_bytes), "storage_path": str(unref_file)},
                ]
            )
            self.fake_db.refs.extend(
                [
                    {"tenant_id": "tenant-secret-alpha", "content_hash": hash_healthy, "ref_count": 1},
                    {"tenant_id": "tenant-secret-bravo", "content_hash": hash_missing_ref, "ref_count": 3},
                    {"tenant_id": "tenant-secret-charlie", "content_hash": hash_dangling, "ref_count": 2},
                    {"tenant_id": "tenant-secret-delta", "content_hash": hash_healthy, "ref_count": 0},
                ]
            )

            report = evidence_storage.generate_consistency_report(
                storage_dir=root,
                max_samples=1,
            )

            self.assertFalse(report["consistent"])
            self.assertTrue(report["samples_truncated"])
            self.assertEqual(
                report["counts"],
                {
                    "blobs_checked": 3,
                    "active_tenant_references_checked": 3,
                    "physical_files_scanned": 4,
                    "missing_physical_files": 1,
                    "referenced_missing_physical_files": 1,
                    "dangling_tenant_references": 1,
                    "stale_non_positive_references": 1,
                    "unreferenced_blob_records": 1,
                    "orphaned_physical_files": 2,
                    "orphaned_physical_bytes": 200,
                },
            )
            self.assertEqual(len(report["anomalies"]["orphaned_physical_files"]), 1)

            # Strictly read-only: files and bytes untouched!
            self.assertEqual(healthy_file.read_bytes(), healthy_bytes)
            self.assertEqual(unref_file.read_bytes(), unref_bytes)
            self.assertTrue(orphan_1.exists())
            self.assertTrue(orphan_2.exists())

            # Strictly privacy-safe: no raw hashes, tenant IDs, or paths leaked!
            serialized = json.dumps(report)
            for secret_value in (
                hash_healthy,
                hash_missing_ref,
                hash_unref,
                hash_dangling,
                "tenant-secret-alpha",
                "tenant-secret-bravo",
                "tenant-secret-charlie",
                str(root),
                "orphan_a.enc",
            ):
                self.assertNotIn(secret_value, serialized)

    def test_missing_directory_and_manage_cli_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            non_existent_dir = Path(tmp_dir) / "does_not_exist"
            report = evidence_storage.generate_consistency_report(storage_dir=non_existent_dir)
            self.assertTrue(report["consistent"])
            self.assertFalse(report["storage_directory_present"])
            # Must not create missing directories during a read-only audit!
            self.assertFalse(non_existent_dir.exists())

            with self.assertRaises(ValueError):
                evidence_storage.generate_consistency_report(storage_dir=non_existent_dir, max_samples=0)

            buf = io.StringIO()
            with patch.dict(os.environ, {"DATABASE_URL": "postgresql://synthetic/test"}, clear=False):
                with patch.object(sys, "stdout", buf):
                    ok_code = manage.main(
                        ["--json", "evidence-consistency", "--storage-dir", str(non_existent_dir)]
                    )
            self.assertEqual(ok_code, manage.EXIT_OK)
            parsed_ok = json.loads(buf.getvalue().strip())
            self.assertTrue(parsed_ok["consistent"])

            # Add an anomaly and confirm manage.py exits with EXIT_PROBLEMS (1).
            self.fake_db.refs.append(
                {"tenant_id": "tenant-x", "content_hash": "f" * 64, "ref_count": 1}
            )
            buf_err = io.StringIO()
            with patch.dict(os.environ, {"DATABASE_URL": "postgresql://synthetic/test"}, clear=False):
                with patch.object(sys, "stdout", buf_err):
                    err_code = manage.main(
                        ["--json", "evidence-consistency", "--storage-dir", str(non_existent_dir)]
                    )
            self.assertEqual(err_code, manage.EXIT_PROBLEMS)
            parsed_err = json.loads(buf_err.getvalue().strip())
            self.assertFalse(parsed_err["consistent"])
            self.assertEqual(parsed_err["counts"]["dangling_tenant_references"], 1)


if __name__ == "__main__":
    unittest.main()
