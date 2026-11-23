"""Focused coverage for encrypted-blob collection safety."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_storage as evidence


CONTENT_HASH = "ab" * 32


class FakeCursor:
    def __init__(self, calls, blob_row, ref_row, fail_sql):
        self.calls = calls
        self.blob_row = blob_row
        self.ref_row = ref_row
        self.fail_sql = fail_sql
        self.row = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        normalized = " ".join(sql.split()).lower()
        self.calls.append(("execute", normalized))
        if self.fail_sql and self.fail_sql in normalized:
            raise RuntimeError("metadata store unavailable")
        if "from blobs" in normalized and "for update" in normalized:
            self.row = self.blob_row
        elif "from tenant_blob_refs" in normalized:
            self.row = self.ref_row
        else:
            self.row = None

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, calls, blob_row, ref_row, fail_sql, blob_path=None):
        self.calls = calls
        self.blob_path = blob_path
        self.blob_row = blob_row
        self.ref_row = ref_row
        self.fail_sql = fail_sql
        self.rollback_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self):
        return FakeCursor(self.calls, self.blob_row, self.ref_row, self.fail_sql)

    def commit(self):
        exists = self.blob_path.exists() if self.blob_path else None
        self.calls.append(("commit", exists))

    def rollback(self):
        self.rollback_calls += 1
        self.calls.append(("rollback", None))


class BlobCollectionTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.blob_path = self.root / "blob.enc"
        self.blob_path.write_bytes(b"encrypted-evidence")
        self._env = patch.dict(
            os.environ,
            {
                "DB_CONNECT_MAX_ATTEMPTS": "2",
                "DB_CONNECT_DEADLINE_SECONDS": "15",
                "DB_CONNECT_RETRY_BASE_SECONDS": "0.001",
            },
            clear=False,
        )
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    def _connection(self, *, blob_row=True, ref_row=None, fail_sql=None, calls=None):
        calls = calls if calls is not None else []
        return FakeConnection(
            calls=calls,
            blob_row={"storage_path": str(self.blob_path)} if blob_row else None,
            ref_row=ref_row,
            fail_sql=fail_sql,
            blob_path=self.blob_path,
        )

    def _collect(self, connection):
        with patch.object(evidence.db, "get_connection", return_value=connection):
            return evidence.collect_unreferenced_blob(CONTENT_HASH)

    def test_reference_check_failure_preserves_blob_and_reports_bounded_retry(self):
        calls = []
        connection = self._connection(fail_sql="from tenant_blob_refs", calls=calls)

        with self.assertRaises(evidence.StorageMetadataRetryableError) as raised:
            self._collect(connection)

        self.assertTrue(self.blob_path.exists())
        self.assertEqual(raised.exception.attempts, 2)
        self.assertGreaterEqual(connection.rollback_calls, 1)
        self.assertFalse(any("delete from blobs" in call[1] for call in calls if call[0] == "execute"))

    def test_metadata_delete_failure_preserves_blob(self):
        calls = []
        connection = self._connection(fail_sql="delete from blobs", calls=calls)

        with self.assertRaises(evidence.StorageMetadataRetryableError):
            self._collect(connection)

        self.assertTrue(self.blob_path.exists())
        self.assertFalse(any(call[0] == "commit" for call in calls))

    def test_referenced_blob_is_not_deleted(self):
        calls = []
        connection = self._connection(ref_row={"1": 1}, calls=calls)

        result = self._collect(connection)

        self.assertEqual(result.status, "referenced")
        self.assertTrue(self.blob_path.exists())
        self.assertFalse(any("delete from blobs" in call[1] for call in calls if call[0] == "execute"))

    def test_unreferenced_blob_is_deleted_after_committed_reference_check(self):
        calls = []
        connection = self._connection(calls=calls)

        result = self._collect(connection)

        self.assertEqual(result.status, "collected")
        self.assertFalse(self.blob_path.exists())
        sql_order = [call[1] for call in calls if call[0] == "execute"]
        ref_check_index = next(
            index for index, sql in enumerate(sql_order) if "from tenant_blob_refs" in sql
        )
        delete_index = next(
            index for index, sql in enumerate(sql_order) if "delete from blobs" in sql
        )
        self.assertLess(ref_check_index, delete_index)
        commits_before_delete = [
            call for call in calls if call[0] == "commit" and call[1] is True
        ]
        self.assertTrue(commits_before_delete)

    def test_missing_blob_is_reported_without_deletion(self):
        calls = []
        connection = self._connection(blob_row=False, calls=calls)

        result = self._collect(connection)

        self.assertEqual(result.status, "missing")
        self.assertTrue(self.blob_path.exists())
        self.assertFalse(any("delete from blobs" in call[1] for call in calls if call[0] == "execute"))


class TenantRefRetryTest(unittest.TestCase):
    def setUp(self):
        self._env = patch.dict(
            os.environ,
            {
                "DB_CONNECT_MAX_ATTEMPTS": "2",
                "DB_CONNECT_DEADLINE_SECONDS": "15",
                "DB_CONNECT_RETRY_BASE_SECONDS": "0.001",
            },
            clear=False,
        )
        self._env.start()
        self.addCleanup(self._env.stop)

    def test_failed_reference_metadata_update_is_retryable(self):
        calls = []
        connection = FakeConnection(
            calls=calls,
            blob_row={"storage_path": "/does/not/matter"},
            ref_row=None,
            fail_sql="insert into tenant_blob_refs",
        )
        with patch.object(evidence.db, "get_connection", return_value=connection):
            with self.assertRaises(evidence.StorageMetadataRetryableError) as raised:
                evidence.record_tenant_ref("tenant-1", CONTENT_HASH)

        self.assertEqual(raised.exception.attempts, 2)
        self.assertFalse(any(call[0] == "commit" for call in calls))

    def test_reference_metadata_update_commits_after_blob_lock(self):
        calls = []
        connection = FakeConnection(
            calls=calls,
            blob_row={"storage_path": "/does/not/matter"},
            ref_row=None,
            fail_sql=None,
        )
        with patch.object(evidence.db, "get_connection", return_value=connection):
            evidence.record_tenant_ref("tenant-1", CONTENT_HASH)

        sql_order = [call[1] for call in calls if call[0] == "execute"]
        self.assertIn("select 1 from blobs", sql_order[0])
        self.assertIn("insert into tenant_blob_refs", sql_order[1])
        self.assertTrue(any(call[0] == "commit" for call in calls))


if __name__ == "__main__":
    unittest.main()
