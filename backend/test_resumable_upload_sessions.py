"""Focused tests for resumable encrypted upload sessions with explicit ownership.

All payloads are synthetic; no real sensitive media, secrets, or live
credentials are used.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.exceptions import RequestEntityTooLarge

from admission import AdmissionController, AdmissionRejectedError, admit_verified_work
from streaming_upload import (
    ContentHashMismatchError,
    ResumableUploadSessionStore,
    SessionAuthError,
    SessionNotFoundError,
    SessionStateError,
)


class TestResumableUploadSessionStore(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base_dir = Path(self._tmp.name)
        self.master_key = b"synthetic-test-master-key-32byte"
        self.store = ResumableUploadSessionStore(
            self.base_dir,
            master_key=self.master_key,
            default_chunk_size=16,
            default_max_size=1024,
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_encrypted_chunk_persistence_and_resume_across_store_restart(self):
        part0 = b"SYNTHETIC_HEADER_0000"
        part1 = b"SYNTHETIC_MIDDLE_1111"
        part2 = b"SYNTHETIC_FOOTER_2222"
        full_payload = part0 + part1 + part2
        expected_hash = hashlib.sha256(full_payload).hexdigest()

        session, token = self.store.create_session(
            owner="GOWNER1234567890",
            owner_tier="scoped",
            expected_sha256=expected_hash,
            expected_size=len(full_payload),
        )
        self.assertIsNotNone(token)
        self.assertEqual(session.owner, "GOWNER1234567890")

        # Manifest must never store the plaintext bearer token.
        manifest_text = (
            self.base_dir / f"harpocrates-session-{session.session_id}" / "manifest.json"
        ).read_text(encoding="utf-8")
        self.assertNotIn(token, manifest_text)

        # Upload chunks 0 and 1.
        p0, total0 = self.store.write_chunk(
            session.session_id,
            0,
            io.BytesIO(part0),
            session_token=token,
            owner="GOWNER1234567890",
        )
        self.assertEqual(p0.bytes_written, len(part0))
        self.assertEqual(total0, len(part0))

        p1, total1 = self.store.write_chunk(
            session.session_id,
            1,
            io.BytesIO(part1),
            session_token=token,
            owner="GOWNER1234567890",
        )
        self.assertEqual(p1.bytes_written, len(part1))
        self.assertEqual(total1, len(part0) + len(part1))

        # Encrypted chunk on disk must not contain plaintext bytes.
        chunk0_disk = (
            self.base_dir / f"harpocrates-session-{session.session_id}" / "chunk-0.enc"
        ).read_bytes()
        self.assertNotIn(part0, chunk0_disk)

        # Simulate process restart with a fresh store instance using the same master key.
        restarted_store = ResumableUploadSessionStore(
            self.base_dir,
            master_key=self.master_key,
            default_chunk_size=16,
            default_max_size=1024,
        )
        progress = restarted_store.get_progress(
            session.session_id,
            session_token=token,
            owner="GOWNER1234567890",
        )
        self.assertEqual(progress["receivedChunks"], [0, 1])
        self.assertEqual(progress["nextChunkIndex"], 2)
        self.assertEqual(progress["totalBytes"], len(part0) + len(part1))
        self.assertTrue(progress["encrypted"])

        # Re-upload chunk 1 (idempotent resume) and upload final chunk 2.
        _, total_reupload = restarted_store.write_chunk(
            session.session_id,
            1,
            io.BytesIO(part1),
            session_token=token,
            owner="GOWNER1234567890",
        )
        self.assertEqual(total_reupload, len(part0) + len(part1))

        restarted_store.write_chunk(
            session.session_id,
            2,
            io.BytesIO(part2),
            session_token=token,
            owner="GOWNER1234567890",
        )

        dest = self.base_dir / "assembled.bin"
        _, final_hash, written = restarted_store.assemble_and_verify(
            session.session_id,
            dest,
            session_token=token,
            owner="GOWNER1234567890",
        )
        self.assertEqual(final_hash, expected_hash)
        self.assertEqual(written, len(full_payload))
        self.assertEqual(dest.read_bytes(), full_payload)

    def test_auth_and_ownership_failures_fail_closed(self):
        session, token = self.store.create_session(owner="GOWNER_ALPHA")

        with self.assertRaises(SessionAuthError) as missing_ctx:
            self.store.get_progress(session.session_id)
        self.assertEqual(missing_ctx.exception.status_code, 401)

        with self.assertRaises(SessionAuthError) as bad_token_ctx:
            self.store.get_progress(session.session_id, session_token="wrong-token")
        self.assertEqual(bad_token_ctx.exception.status_code, 401)

        with self.assertRaises(SessionAuthError) as wrong_owner_ctx:
            self.store.get_progress(
                session.session_id,
                session_token=token,
                owner="GOWNER_BETA",
            )
        self.assertEqual(wrong_owner_ctx.exception.status_code, 403)
        self.assertEqual(wrong_owner_ctx.exception.code, "SESSION_OWNER_MISMATCH")

        with self.assertRaises(SessionNotFoundError):
            self.store.get_progress("../escape")

    def test_content_hash_mismatch_and_tampering_rejected_without_partial_output(self):
        payload = b"synthetic-evidence-payload"
        wrong_hash = hashlib.sha256(b"different-payload").hexdigest()
        session, token = self.store.create_session(
            owner="GOWNER_HASH",
            expected_sha256=wrong_hash,
        )
        self.store.write_chunk(
            session.session_id,
            0,
            io.BytesIO(payload),
            session_token=token,
            owner="GOWNER_HASH",
        )
        dest = self.base_dir / "should-not-exist.bin"
        with self.assertRaises(ContentHashMismatchError) as ctx:
            self.store.assemble_and_verify(
                session.session_id,
                dest,
                session_token=token,
                owner="GOWNER_HASH",
            )
        self.assertEqual(ctx.exception.status_code, 422)
        self.assertFalse(dest.exists())

    def test_tampered_ciphertext_fails_aead_verification(self):
        payload = b"synthetic-aead-check"
        session, token = self.store.create_session(
            owner="GOWNER_AEAD",
            expected_sha256=hashlib.sha256(payload).hexdigest(),
        )
        self.store.write_chunk(
            session.session_id,
            0,
            io.BytesIO(payload),
            session_token=token,
        )
        chunk_file = (
            self.base_dir / f"harpocrates-session-{session.session_id}" / "chunk-0.enc"
        )
        corrupted = bytearray(chunk_file.read_bytes())
        corrupted[0] ^= 0xFF
        chunk_file.write_bytes(bytes(corrupted))

        dest = self.base_dir / "tampered.bin"
        with self.assertRaises(ContentHashMismatchError):
            self.store.assemble_and_verify(session.session_id, dest, session_token=token)
        self.assertFalse(dest.exists())

    def test_missing_chunk_gap_and_size_limit_boundaries(self):
        session, token = self.store.create_session(owner="GOWNER_BOUND", max_size=32)
        self.store.write_chunk(session.session_id, 0, io.BytesIO(b"a" * 10), session_token=token)
        self.store.write_chunk(session.session_id, 2, io.BytesIO(b"c" * 10), session_token=token)

        with self.assertRaises(SessionStateError) as gap_ctx:
            self.store.assemble_and_verify(
                session.session_id,
                self.base_dir / "gap.bin",
                session_token=token,
            )
        self.assertEqual(gap_ctx.exception.code, "SESSION_INCOMPLETE")

        with self.assertRaises(RequestEntityTooLarge):
            self.store.write_chunk(
                session.session_id,
                1,
                io.BytesIO(b"b" * 20),
                session_token=token,
            )


class TestPreAdmissionVerification(unittest.TestCase):
    def test_admit_verified_work_enforces_backpressure_and_releases(self):
        controller = AdmissionController(
            max_concurrent=1,
            max_queue=0,
            max_per_identity=1,
            timeout_seconds=0.05,
        )
        with admit_verified_work(controller, "owner:GOWNER1", endpoint="/commit"):
            with self.assertRaises(AdmissionRejectedError) as ctx:
                with admit_verified_work(controller, "owner:GOWNER1", endpoint="/commit"):
                    pass
            self.assertEqual(ctx.exception.status_code, 429)
            self.assertEqual(ctx.exception.reason, "identity_limit")

        # Slot must be released after exiting the context manager.
        with admit_verified_work(controller, "owner:GOWNER1", endpoint="/commit"):
            pass

    def test_commit_verifies_hash_before_admitting_processing_work(self):
        with patch.dict(
            os.environ,
            {
                "RATELIMIT_ENABLED": "false",
                "DATABASE_URL": "",
                "NOIR_WORKER_ENABLED": "false",
            },
        ):
            import app as app_module

            flask_app = app_module.create_app()
            flask_app.config["TESTING"] = True
            client = flask_app.test_client()

            payload = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom"
            wrong_hash = hashlib.sha256(b"not-the-payload").hexdigest()

            create_res = client.post(
                "/api/stego/upload-session",
                json={
                    "owner": "GOWNER_PRE_ADMIT",
                    "expectedSha256": wrong_hash,
                },
            )
            self.assertEqual(create_res.status_code, 200)
            session_data = create_res.get_json()
            session_id = session_data["sessionId"]
            token = session_data["sessionToken"]
            headers = {
                "Authorization": f"Bearer {token}",
                "X-Upload-Owner": "GOWNER_PRE_ADMIT",
            }

            put_res = client.put(
                f"/api/stego/upload-session/{session_id}/chunk/0",
                data={"chunk": (io.BytesIO(payload), "chunk0.bin")},
                content_type="multipart/form-data",
                headers=headers,
            )
            self.assertEqual(put_res.status_code, 200)

            # Resume endpoint returns persisted progress.
            status_res = client.get(f"/api/stego/upload-session/{session_id}", headers=headers)
            self.assertEqual(status_res.status_code, 200)
            self.assertEqual(status_res.get_json()["receivedChunks"], [0])

            # Commit with mismatched hash MUST fail with 422 BEFORE AdmissionController.acquire is called.
            metadata = json.dumps({
                "proofId": "a" * 64,
                "tier": "public",
                "fileName": "synthetic.mp4",
                "timestamp": "2026-01-01T00:00:00Z",
            })
            with (
                patch.object(app_module, "validate_embed_metadata", return_value=None),
                patch.object(
                    AdmissionController, "acquire", wraps=AdmissionController.acquire
                ) as mock_acquire,
            ):
                commit_res = client.post(
                    f"/api/stego/upload-session/{session_id}/commit",
                    data={"metadata": metadata},
                    content_type="multipart/form-data",
                    headers=headers,
                )
                self.assertEqual(commit_res.status_code, 422)
                self.assertEqual(
                    commit_res.get_json()["error"]["code"], "CONTENT_HASH_MISMATCH"
                )
                mock_acquire.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
