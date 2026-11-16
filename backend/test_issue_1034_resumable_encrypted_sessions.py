from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as app_module  # noqa: E402
import strkey  # noqa: E402
from admission import AdmissionController  # noqa: E402
from streaming_upload import (  # noqa: E402
    ResumableEncryptedSessionStore,
    UploadContentHashMismatchError,
    UploadOwnershipError,
)


def _synthetic_g_address(seed: int) -> str:
    body = bytes([6 << 3]) + bytes([seed & 0xFF]) * 32
    crc = strkey._crc16_xmodem(body)
    return base64.b32encode(body + crc.to_bytes(2, "big")).decode("ascii")


OWNER_A = _synthetic_g_address(0x31)
OWNER_B = _synthetic_g_address(0x42)
TOKEN_A = "synthetic-owner-token-1034-a"
TOKEN_B = "synthetic-owner-token-1034-b"


class ResumableEncryptedSessionUnitTests(unittest.TestCase):
    def test_encrypts_chunks_enforces_max_chunks_and_detects_tampering(self) -> None:
        store = ResumableEncryptedSessionStore(max_chunks=2)
        sentinel = b"SYNTHETIC-PLAINTEXT-CHUNK-NEVER-ON-DISK-1034"
        full_hash = hashlib.sha256(sentinel + b"-tail").hexdigest()

        with tempfile.TemporaryDirectory() as tmp_root:
            s_dir = Path(tmp_root) / "session-enc"
            store.create_session(
                "s-enc",
                s_dir,
                owner=OWNER_A,
                expected_sha256=full_hash,
            )

            store.write_encrypted_chunk(
                "s-enc",
                s_dir,
                caller_owner=OWNER_A,
                chunk_index=0,
                source=io.BytesIO(sentinel),
                chunk_size=16,
            )
            # Plaintext bytes MUST NOT appear anywhere on disk inside s_dir!
            for disk_file in s_dir.iterdir():
                self.assertNotIn(sentinel, disk_file.read_bytes())

            # Wrong owner is rejected fail-closed on progress lookup and chunk write.
            with self.assertRaises(UploadOwnershipError):
                store.get_progress("s-enc", s_dir, caller_owner=OWNER_B)
            with self.assertRaises(UploadOwnershipError):
                store.write_encrypted_chunk(
                    "s-enc",
                    s_dir,
                    caller_owner=OWNER_B,
                    chunk_index=1,
                    source=io.BytesIO(b"-tail"),
                )

            # Chunk index >= max_chunks is rejected cleanly.
            with self.assertRaises(ValueError):
                store.write_encrypted_chunk(
                    "s-enc",
                    s_dir,
                    caller_owner=OWNER_A,
                    chunk_index=2,
                    source=io.BytesIO(b"overflow"),
                )

            store.write_encrypted_chunk(
                "s-enc",
                s_dir,
                caller_owner=OWNER_A,
                chunk_index=1,
                source=io.BytesIO(b"-tail"),
                chunk_size=16,
            )

            verified_digest, total_len = store.verify_assembled_sha256(
                "s-enc",
                s_dir,
                caller_owner=OWNER_A,
            )
            self.assertEqual(verified_digest, full_hash)
            self.assertEqual(total_len, len(sentinel) + 5)

            # Bit-flip tampering in chunk-1.enc fails HMAC integrity check BEFORE staging.
            enc1 = s_dir / "chunk-1.enc"
            raw_enc = bytearray(enc1.read_bytes())
            raw_enc[-5] ^= 0xFF
            enc1.write_bytes(bytes(raw_enc))
            with self.assertRaises(UploadContentHashMismatchError):
                store.verify_assembled_sha256("s-enc", s_dir, caller_owner=OWNER_A)

            store.destroy_session("s-enc", s_dir)
            self.assertFalse(s_dir.exists())


class ResumableEncryptedSessionRouteTests(unittest.TestCase):
    def _build_app(self):
        digest_a = hashlib.sha256(TOKEN_A.encode("utf-8")).hexdigest()
        digest_b = hashlib.sha256(TOKEN_B.encode("utf-8")).hexdigest()
        env = {
            "RATELIMIT_ENABLED": "false",
            "REGISTER_SCOPED_KEYS": f"{OWNER_A}:{digest_a},{OWNER_B}:{digest_b}",
        }
        with patch.dict(os.environ, env, clear=False):
            return app_module.create_app()

    def test_authenticated_resume_ownership_and_hash_verification_before_admission(self) -> None:
        flask_app = self._build_app()
        controller: AdmissionController = flask_app.extensions["admission_controller"]
        client = flask_app.test_client()

        chunk0 = b"\x00\x00\x00\x18ftypmp42SYNTHETIC-CHUNK-ZERO-1034"
        chunk1 = b"SYNTHETIC-CHUNK-ONE-1034-PAYLOAD"
        expected_hash = hashlib.sha256(chunk0 + chunk1).hexdigest()
        wrong_hash = "0" * 64

        # 1. Unauthenticated session creation is rejected with 401 when credentials exist.
        unauth = client.post("/api/stego/upload-session")
        self.assertEqual(unauth.status_code, 401)

        # 2. Scoped key cannot claim another owner's address (403).
        spoof = client.post(
            "/api/stego/upload-session",
            headers={
                "Authorization": f"Bearer {TOKEN_A}",
                "X-Upload-Owner": OWNER_B,
            },
        )
        self.assertEqual(spoof.status_code, 403)

        # 3. OWNER_A creates session, uploads chunk 0, then resumes via GET status.
        created = client.post(
            "/api/stego/upload-session",
            headers={"Authorization": f"Bearer {TOKEN_A}"},
            json={"expectedSha256": expected_hash},
        )
        self.assertEqual(created.status_code, 200)
        session_id = created.get_json()["sessionId"]
        session_dir = Path(tempfile.gettempdir()) / f"harpocrates-session-{session_id}"

        put0 = client.put(
            f"/api/stego/upload-session/{session_id}/chunk/0",
            headers={"Authorization": f"Bearer {TOKEN_A}"},
            data={"chunk": (io.BytesIO(chunk0), "part0")},
            content_type="multipart/form-data",
        )
        self.assertEqual(put0.status_code, 200)
        self.assertTrue((session_dir / "chunk-0.enc").exists())
        self.assertNotIn(b"SYNTHETIC-CHUNK-ZERO-1034", (session_dir / "chunk-0.enc").read_bytes())

        # 4. OWNER_B is denied resume status, chunk upload, and commit with 403 FORBIDDEN.
        self.assertEqual(
            client.get(
                f"/api/stego/upload-session/{session_id}",
                headers={"Authorization": f"Bearer {TOKEN_B}"},
            ).status_code,
            403,
        )
        self.assertEqual(
            client.put(
                f"/api/stego/upload-session/{session_id}/chunk/1",
                headers={"Authorization": f"Bearer {TOKEN_B}"},
                data={"chunk": (io.BytesIO(chunk1), "part1")},
                content_type="multipart/form-data",
            ).status_code,
            403,
        )

        # 5. OWNER_A queries resume endpoint, sees nextChunkIndex == 1, and uploads chunk 1.
        resume_resp = client.get(
            f"/api/stego/upload-session/{session_id}",
            headers={"Authorization": f"Bearer {TOKEN_A}"},
        )
        self.assertEqual(resume_resp.status_code, 200)
        resume_json = resume_resp.get_json()
        self.assertEqual(resume_json["owner"], OWNER_A)
        self.assertEqual(resume_json["receivedChunks"], [0])
        self.assertEqual(resume_json["nextChunkIndex"], 1)
        self.assertEqual(resume_json["totalBytes"], len(chunk0))

        put1 = client.put(
            f"/api/stego/upload-session/{session_id}/chunk/1",
            headers={"Authorization": f"Bearer {TOKEN_A}"},
            data={"chunk": (io.BytesIO(chunk1), "part1")},
            content_type="multipart/form-data",
        )
        self.assertEqual(put1.status_code, 200)

        valid_meta = {
            "version": 2,
            "proofId": "proof-1034",
            "tier": "verified",
            "timestamp": "2026-11-15T00:00:00Z",
        }

        # 6. Hash mismatch on commit MUST fail BEFORE acquiring admission capacity or calling embed_metadata!
        with (
            patch.object(controller, "acquire", wraps=controller.acquire) as spy_acquire,
            patch.object(app_module, "embed_metadata") as spy_embed,
            patch.object(app_module, "validate_embed_metadata", return_value=None),
        ):
            bad_commit = client.post(
                f"/api/stego/upload-session/{session_id}/commit",
                headers={
                    "Authorization": f"Bearer {TOKEN_A}",
                    "X-Upload-Content-SHA256": wrong_hash,
                },
                data={"metadata": json.dumps(valid_meta)},
                content_type="multipart/form-data",
            )
            self.assertEqual(bad_commit.status_code, 400)
            self.assertEqual(
                bad_commit.get_json()["error"]["code"],
                "UPLOAD_CONTENT_HASH_MISMATCH",
            )
            self.assertEqual(spy_acquire.call_count, 0)
            self.assertEqual(spy_embed.call_count, 0)

        # 7. Matching final SHA-256 verifies cleanly, acquires admission capacity, embeds, and wipes session.
        def _fake_embed(_src, dst, _meta):
            Path(dst).write_bytes(b"synthetic-embedded-mp4")

        with (
            patch.object(controller, "acquire", wraps=controller.acquire) as spy_acquire_ok,
            patch.object(app_module, "sniff_media_type_path", return_value="video/mp4"),
            patch.object(app_module, "embed_metadata", side_effect=_fake_embed) as spy_embed_ok,
            patch.object(app_module, "validate_embed_metadata", return_value=None),
            patch.object(app_module, "insert_proof_event", return_value={"id": 1}),
        ):
            good_commit = client.post(
                f"/api/stego/upload-session/{session_id}/commit",
                headers={
                    "Authorization": f"Bearer {TOKEN_A}",
                    "X-Upload-Content-SHA256": expected_hash,
                },
                data={"metadata": json.dumps(valid_meta)},
                content_type="multipart/form-data",
            )
            self.assertEqual(good_commit.status_code, 200)
            self.assertEqual(spy_acquire_ok.call_count, 1)
            self.assertEqual(spy_embed_ok.call_count, 1)
            self.assertEqual(
                good_commit.headers["X-Harpocrates-Source-Hash"],
                expected_hash,
            )
        self.assertFalse(session_dir.exists())


if __name__ == "__main__":
    unittest.main()
