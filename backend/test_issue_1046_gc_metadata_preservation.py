"""Focused regression and failure-boundary tests for issue #1046:
preserve encrypted evidence when a garbage-collection metadata update fails.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parent))

import evidence_storage  # noqa: E402
from metrics import collector as metrics_collector  # noqa: E402
import storage  # noqa: E402


class _TransactionalGCDB:
    def __init__(self) -> None:
        self.committed_blobs: dict[str, str] = {}
        self.working_blobs: dict[str, str] | None = None
        self.live_refs: set[str] = set()
        self.fail_on_delete_call: int | None = None
        self.fail_on_commit: bool = False
        self.inject_ref_before_delete: set[str] = set()
        self.delete_calls = 0
        self.rowcount: int | None = None
        self._rows: list[dict[str, str]] = []

    def add_blob(self, content_hash: str, storage_path: str) -> None:
        self.committed_blobs[content_hash] = storage_path

    @contextmanager
    def connection(self):
        self.working_blobs = dict(self.committed_blobs)
        yield self

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return None

    def execute(self, sql: str, params: tuple = ()) -> None:
        normalized = " ".join(sql.lower().split())
        assert self.working_blobs is not None

        if "select content_hash, storage_path from blobs" in normalized:
            (limit,) = params
            candidates = [
                {"content_hash": h, "storage_path": p}
                for h, p in sorted(self.working_blobs.items())
                if h not in self.live_refs
            ]
            self._rows = candidates[:limit]
            self.rowcount = len(self._rows)
        elif "delete from blobs where content_hash = %s" in normalized:
            self.delete_calls += 1
            if self.fail_on_delete_call == self.delete_calls:
                raise RuntimeError("synthetic database metadata delete failure")
            (content_hash,) = params
            if content_hash in self.inject_ref_before_delete:
                self.live_refs.add(content_hash)
            if content_hash in self.live_refs:
                self.rowcount = 0
            elif content_hash in self.working_blobs:
                del self.working_blobs[content_hash]
                self.rowcount = 1
            else:
                self.rowcount = 0

    def fetchall(self):
        return list(self._rows)

    def commit(self) -> None:
        if self.fail_on_commit:
            raise RuntimeError("synthetic database commit failure")
        if self.working_blobs is not None:
            self.committed_blobs = dict(self.working_blobs)
            self.working_blobs = None

    def rollback(self) -> None:
        self.working_blobs = None


class GCMetadataPreservationTests(unittest.TestCase):
    def setUp(self) -> None:
        metrics_collector.reset()
        self.dek = Fernet.generate_key()
        self.cipher = Fernet(self.dek)
        self.fake_db = _TransactionalGCDB()
        self._db_patch = patch.object(
            evidence_storage.db,
            "get_connection",
            self.fake_db.connection,
        )
        self._db_patch.start()

    def tearDown(self) -> None:
        self._db_patch.stop()
        metrics_collector.reset()

    def test_mid_batch_metadata_delete_failure_preserves_all_encrypted_blobs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            blob_1 = root / "evidence_01.enc"
            blob_2 = root / "evidence_02.enc"
            ct_1 = self.cipher.encrypt(b"synthetic-evidence-alpha")
            ct_2 = self.cipher.encrypt(b"synthetic-evidence-bravo")
            blob_1.write_bytes(ct_1)
            blob_2.write_bytes(ct_2)

            hash_1 = "1" * 64
            hash_2 = "2" * 64
            self.fake_db.add_blob(hash_1, str(blob_1))
            self.fake_db.add_blob(hash_2, str(blob_2))
            self.fake_db.fail_on_delete_call = 2

            with self.assertRaises(storage.RetryableStorageError) as ctx:
                evidence_storage.collect_unreferenced_blobs(
                    limit=10,
                    retry_after_seconds=9999,
                )

            err = ctx.exception
            self.assertEqual(err.code, "GC_METADATA_UPDATE_FAILED")
            self.assertTrue(err.retryable)
            # Bounded retry_after_seconds clamped to MAX_RETRY_AFTER_SECONDS (300).
            self.assertEqual(err.retry_after_seconds, 300)
            self.assertEqual(err.preserved_count, 2)

            serialized_err = json.dumps(err.to_dict())
            self.assertNotIn(hash_1, serialized_err)
            self.assertNotIn(hash_2, serialized_err)
            self.assertNotIn(str(root), serialized_err)

            # Both encrypted files are preserved intact and decrypt cleanly!
            self.assertTrue(blob_1.exists())
            self.assertTrue(blob_2.exists())
            self.assertEqual(self.cipher.decrypt(blob_1.read_bytes()), b"synthetic-evidence-alpha")
            self.assertEqual(self.cipher.decrypt(blob_2.read_bytes()), b"synthetic-evidence-bravo")
            self.assertEqual(list(root.glob("*.gc-preserve-*")), [])
            self.assertEqual(set(self.fake_db.committed_blobs), {hash_1, hash_2})
            self.assertIn(
                "harpocrates_retention_deleted_blobs_total 0",
                metrics_collector.generate_prometheus_metrics(),
            )

            # Subsequent retry after DB recovery collects both blobs cleanly.
            self.fake_db.fail_on_delete_call = None
            collected = evidence_storage.collect_unreferenced_blobs(limit=10)
            self.assertEqual(collected, 2)
            self.assertFalse(blob_1.exists())
            self.assertFalse(blob_2.exists())
            self.assertEqual(self.fake_db.committed_blobs, {})

    def test_commit_failure_restores_ciphertext_and_returns_bounded_error_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            blob = root / "commit_fail.enc"
            ciphertext = self.cipher.encrypt(b"synthetic-commit-test")
            blob.write_bytes(ciphertext)
            content_hash = "3" * 64
            self.fake_db.add_blob(content_hash, str(blob))
            self.fake_db.fail_on_commit = True

            result = evidence_storage.run_garbage_collection_cycle(
                limit=5,
                retry_after_seconds=0,
            )
            self.assertFalse(result["ok"])
            self.assertEqual(result["collected"], 0)
            self.assertEqual(
                result["error"],
                {
                    "code": "GC_METADATA_UPDATE_FAILED",
                    "message": result["error"]["message"],
                    "retryable": True,
                    "retry_after_seconds": 1,
                    "preserved_count": 1,
                },
            )
            self.assertTrue(blob.exists())
            self.assertEqual(blob.read_bytes(), ciphertext)
            self.assertIn(content_hash, self.fake_db.committed_blobs)

    def test_guarded_reference_recheck_prevents_deleting_newly_referenced_blob(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            referenced_blob = root / "newly_referenced.enc"
            unreferenced_blob = root / "truly_unreferenced.enc"
            ct_ref = self.cipher.encrypt(b"keep-me-encrypted")
            ct_unref = self.cipher.encrypt(b"collect-me")
            referenced_blob.write_bytes(ct_ref)
            unreferenced_blob.write_bytes(ct_unref)

            hash_ref = "4" * 64
            hash_unref = "5" * 64
            self.fake_db.add_blob(hash_ref, str(referenced_blob))
            self.fake_db.add_blob(hash_unref, str(unreferenced_blob))
            self.fake_db.inject_ref_before_delete.add(hash_ref)

            # Also verify copy2 fallback when os.link is unavailable.
            with patch.object(os, "link", side_effect=OSError("hardlink unsupported")):
                result = evidence_storage.run_garbage_collection_cycle(limit=10)

            self.assertEqual(result, {"ok": True, "collected": 1, "error": None})
            self.assertTrue(referenced_blob.exists())
            self.assertEqual(self.cipher.decrypt(referenced_blob.read_bytes()), b"keep-me-encrypted")
            self.assertFalse(unreferenced_blob.exists())
            self.assertEqual(set(self.fake_db.committed_blobs), {hash_ref})


if __name__ == "__main__":
    unittest.main()
