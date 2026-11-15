"""Focused regression and failure-boundary tests for issue #1044:
add a staged evidence encryption-key rotation workflow.
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
import storage  # noqa: E402


class _KeyRotationDB:
    def __init__(self) -> None:
        self.committed_blobs: dict[str, dict[str, object]] = {}
        self.working_blobs: dict[str, dict[str, object]] | None = None
        self.update_count = 0
        self.rowcount: int | None = None
        self._rows: list[dict[str, object]] = []
        self._row: dict[str, object] | None = None

    def put_blob(self, content_hash: str, encrypted_dek: str, storage_path: str) -> None:
        self.committed_blobs[content_hash] = {
            "content_hash": content_hash,
            "encrypted_dek": encrypted_dek,
            "storage_path": storage_path,
        }

    @contextmanager
    def connection(self):
        self.working_blobs = {k: dict(v) for k, v in self.committed_blobs.items()}
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
        self._row = None

        if normalized.startswith("select content_hash, encrypted_dek, storage_path from blobs"):
            (limit,) = params
            ordered = [self.working_blobs[k] for k in sorted(self.working_blobs)]
            self._rows = [dict(r) for r in ordered[:limit]]
        elif normalized.startswith("select encrypted_dek, storage_path from blobs"):
            (content_hash,) = params
            blob = self.working_blobs.get(content_hash)
            if blob is not None:
                self._row = {
                    "encrypted_dek": blob["encrypted_dek"],
                    "storage_path": blob["storage_path"],
                }
        elif normalized.startswith("update blobs set encrypted_dek = %s"):
            new_dek, content_hash, expected_prev = params
            blob = self.working_blobs.get(content_hash)
            if blob is not None and blob["encrypted_dek"] == expected_prev:
                blob["encrypted_dek"] = new_dek
                self.rowcount = 1
                self.update_count += 1
            else:
                self.rowcount = 0

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._row

    def commit(self) -> None:
        if self.working_blobs is not None:
            self.committed_blobs = {k: dict(v) for k, v in self.working_blobs.items()}
            self.working_blobs = None

    def rollback(self) -> None:
        self.working_blobs = None


class StagedKeyRotationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.legacy_master = Fernet.generate_key().decode("ascii")
        self.v1_master = Fernet.generate_key().decode("ascii")
        self.v2_master = Fernet.generate_key().decode("ascii")
        self.fake_db = _KeyRotationDB()
        self._db_patch = patch.object(
            evidence_storage.db,
            "get_connection",
            self.fake_db.connection,
        )
        self._db_patch.start()

    def tearDown(self) -> None:
        self._db_patch.stop()

    def test_staged_rotation_verifies_ciphertext_commits_and_rolls_back_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            journals = root / "journals"

            # Blob 1: wrapped under unprefixed legacy master key
            dek_1 = Fernet.generate_key()
            legacy_wrapped = Fernet(self.legacy_master.encode("ascii")).encrypt(dek_1).decode("ascii")
            file_1 = root / "blob_1.enc"
            plain_1 = b"synthetic-evidence-payload-one"
            file_1.write_bytes(Fernet(dek_1).encrypt(plain_1))
            hash_1 = "1" * 64

            # Blob 2: wrapped under versioned kek-v1
            dek_2 = Fernet.generate_key()
            v1_wrapped = evidence_storage.wrap_dek_with_key_id(dek_2, self.v1_master, "kek-v1").decode("ascii")
            file_2 = root / "blob_2.enc"
            plain_2 = b"synthetic-evidence-payload-two"
            file_2.write_bytes(Fernet(dek_2).encrypt(plain_2))
            hash_2 = "2" * 64

            # Blob 3: already wrapped under kek-v2 -> must be skipped
            dek_3 = Fernet.generate_key()
            v2_wrapped = evidence_storage.wrap_dek_with_key_id(dek_3, self.v2_master, "kek-v2").decode("ascii")
            file_3 = root / "blob_3.enc"
            file_3.write_bytes(Fernet(dek_3).encrypt(b"already-v2"))
            hash_3 = "3" * 64

            self.fake_db.put_blob(hash_1, legacy_wrapped, str(file_1))
            self.fake_db.put_blob(hash_2, v1_wrapped, str(file_2))
            self.fake_db.put_blob(hash_3, v2_wrapped, str(file_3))

            staged = evidence_storage.stage_key_rotation(
                source_keys={"legacy": self.legacy_master, "kek-v1": self.v1_master},
                target_key_id="kek-v2",
                target_master_key=self.v2_master,
                journal_dir=journals,
                rotation_id="rot_20261115_01",
            )
            # Staging must perform ZERO DB updates while writing rollback evidence!
            self.assertEqual(self.fake_db.update_count, 0)
            self.assertEqual(staged["staged_count"], 2)
            self.assertEqual(staged["skipped_already_rotated"], 1)
            self.assertEqual(self.fake_db.committed_blobs[hash_1]["encrypted_dek"], legacy_wrapped)

            journal_raw = Path(staged["journal_path"]).read_text(encoding="utf-8")
            for forbidden in (
                dek_1.decode("ascii"),
                dek_2.decode("ascii"),
                self.legacy_master,
                self.v1_master,
                self.v2_master,
                plain_1.decode("ascii"),
                str(file_1),
            ):
                self.assertNotIn(forbidden, journal_raw)

            # Commit staged metadata updates
            committed = evidence_storage.commit_staged_key_rotation(staged, journal_dir=journals)
            self.assertEqual(committed["status"], "committed")
            self.assertEqual(committed["updated_count"], 2)

            new_dek_1 = str(self.fake_db.committed_blobs[hash_1]["encrypted_dek"])
            new_dek_2 = str(self.fake_db.committed_blobs[hash_2]["encrypted_dek"])
            self.assertTrue(new_dek_1.startswith("kid:kek-v2:"))
            self.assertTrue(new_dek_2.startswith("kid:kek-v2:"))

            # Decrypt using MASTER_ENCRYPTION_KEY_RING containing only kek-v2!
            with patch.dict(
                os.environ,
                {"MASTER_ENCRYPTION_KEY_RING": f"kek-v2={self.v2_master}"},
                clear=True,
            ):
                recovered_1 = evidence_storage.decrypt_dek(new_dek_1)
                recovered_2 = evidence_storage.decrypt_dek(new_dek_2)
            self.assertEqual(Fernet(recovered_1).decrypt(file_1.read_bytes()), plain_1)
            self.assertEqual(Fernet(recovered_2).decrypt(file_2.read_bytes()), plain_2)

            # Roll back using preserved rollback journal
            rolled_back = evidence_storage.rollback_key_rotation(
                staged["journal_path"],
                source_keys={"legacy": self.legacy_master, "kek-v1": self.v1_master},
                journal_dir=journals,
            )
            self.assertEqual(rolled_back["status"], "rolled_back")
            self.assertEqual(rolled_back["restored_count"], 2)
            self.assertEqual(self.fake_db.committed_blobs[hash_1]["encrypted_dek"], legacy_wrapped)
            self.assertEqual(self.fake_db.committed_blobs[hash_2]["encrypted_dek"], v1_wrapped)

            persisted = storage.read_key_rotation_journal(staged["journal_path"])
            self.assertEqual(persisted["status"], "rolled_back")

    def test_corrupted_or_missing_ciphertext_aborts_before_committing_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            journals = root / "journals"

            dek = Fernet.generate_key()
            wrapped = evidence_storage.wrap_dek_with_key_id(dek, self.v1_master, "kek-v1").decode("ascii")
            corrupted_file = root / "corrupted.enc"
            corrupted_file.write_bytes(b"corrupted-ciphertext-not-readable")
            content_hash = "c" * 64
            self.fake_db.put_blob(content_hash, wrapped, str(corrupted_file))

            with self.assertRaises(evidence_storage.KeyRotationVerificationError) as ctx:
                evidence_storage.rotate_evidence_keys(
                    source_keys={"kek-v1": self.v1_master},
                    target_key_id="kek-v2",
                    target_master_key=self.v2_master,
                    journal_dir=journals,
                )
            self.assertEqual(ctx.exception.reason_code, "CORRUPT_EVIDENCE_CIPHERTEXT")
            self.assertEqual(self.fake_db.update_count, 0)
            self.assertEqual(self.fake_db.committed_blobs[content_hash]["encrypted_dek"], wrapped)
            self.assertFalse(journals.exists())

            # Missing ciphertext file on disk also aborts fail-closed.
            corrupted_file.unlink()
            with self.assertRaises(evidence_storage.KeyRotationVerificationError) as missing_ctx:
                evidence_storage.stage_key_rotation(
                    source_keys={"kek-v1": self.v1_master},
                    target_key_id="kek-v2",
                    target_master_key=self.v2_master,
                    journal_dir=journals,
                )
            self.assertEqual(missing_ctx.exception.reason_code, "MISSING_CIPHERTEXT_FILE")
            self.assertEqual(self.fake_db.update_count, 0)

    def test_commit_detects_post_staging_ciphertext_drift_and_concurrent_dek_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            journals = root / "journals"

            dek_a = Fernet.generate_key()
            dek_b = Fernet.generate_key()
            wrapped_a = evidence_storage.wrap_dek_with_key_id(dek_a, self.v1_master, "kek-v1").decode("ascii")
            wrapped_b = evidence_storage.wrap_dek_with_key_id(dek_b, self.v1_master, "kek-v1").decode("ascii")

            file_a = root / "a.enc"
            file_b = root / "b.enc"
            file_a.write_bytes(Fernet(dek_a).encrypt(b"alpha"))
            file_b.write_bytes(Fernet(dek_b).encrypt(b"bravo"))

            hash_a = "a" * 64
            hash_b = "b" * 64
            self.fake_db.put_blob(hash_a, wrapped_a, str(file_a))
            self.fake_db.put_blob(hash_b, wrapped_b, str(file_b))

            staged = evidence_storage.stage_key_rotation(
                source_keys={"kek-v1": self.v1_master},
                target_key_id="kek-v2",
                target_master_key=self.v2_master,
                journal_dir=journals,
            )

            # Tamper with file_b on disk after staging -> commit must abort and roll back hash_a!
            original_b = file_b.read_bytes()
            file_b.write_bytes(original_b + b"tampered")
            with self.assertRaises(evidence_storage.KeyRotationVerificationError) as drift_ctx:
                evidence_storage.commit_staged_key_rotation(staged, journal_dir=journals)
            self.assertEqual(drift_ctx.exception.reason_code, "CIPHERTEXT_DIGEST_DRIFT")
            self.assertEqual(self.fake_db.committed_blobs[hash_a]["encrypted_dek"], wrapped_a)

            # Restore file_b, but simulate concurrent DEK rotation on hash_b -> commit aborts!
            file_b.write_bytes(original_b)
            other_wrapped = evidence_storage.wrap_dek_with_key_id(dek_b, self.v2_master, "kek-v9").decode("ascii")
            self.fake_db.committed_blobs[hash_b]["encrypted_dek"] = other_wrapped
            with self.assertRaises(evidence_storage.KeyRotationError) as race_ctx:
                evidence_storage.commit_staged_key_rotation(staged, journal_dir=journals)
            self.assertEqual(race_ctx.exception.reason_code, "CONCURRENT_DEK_MODIFICATION")
            self.assertEqual(self.fake_db.committed_blobs[hash_a]["encrypted_dek"], wrapped_a)

    def test_key_id_validation_and_unknown_key_id_rejection(self) -> None:
        dek = Fernet.generate_key()
        with self.assertRaises(evidence_storage.KeyRotationError):
            evidence_storage.wrap_dek_with_key_id(dek, self.v2_master, "legacy")
        with self.assertRaises(evidence_storage.KeyRotationError):
            evidence_storage.wrap_dek_with_key_id(dek, self.v2_master, "BAD KEY ID")

        wrapped = evidence_storage.wrap_dek_with_key_id(dek, self.v2_master, "kek-v2")
        with self.assertRaises(evidence_storage.KeyRotationError) as ctx:
            evidence_storage.decrypt_dek(wrapped, key_ring={"kek-v1": self.v1_master})
        self.assertEqual(ctx.exception.reason_code, "UNKNOWN_KEY_ID")


if __name__ == "__main__":
    unittest.main()
