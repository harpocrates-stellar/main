"""Focused tests for premature upload termination detection (issue #1040)."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as app_module  # noqa: E402
from streaming_upload import (  # noqa: E402
    UPLOAD_PREMATURE_TERMINATION,
    PrematureUploadTerminationError,
    StreamingFileStorage,
    hash_stream_to_path,
)

_METADATA = {
    "protocol": "harpocrates",
    "version": 1,
    "tier": "silent",
    "sourceHash": "11" * 32,
    "proofId": "22" * 32,
    "timestamp": "2026-06-18T00:00:00.000Z",
}


class _DisconnectStream:
    def __init__(self, chunks: list[bytes], exc: Exception) -> None:
        self._chunks = list(chunks)
        self._exc = exc

    def read(self, _size: int = -1) -> bytes:
        if self._chunks:
            return self._chunks.pop(0)
        raise self._exc


class PrematureUploadTerminationTest(unittest.TestCase):
    def test_differentiates_disconnected_or_short_input_from_valid_empty_stream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)

            # 1. Valid empty stream (both absent expected_bytes and explicit 0)
            empty_a = tmp_dir / "empty_a.bin"
            digest_a, written_a = hash_stream_to_path(io.BytesIO(b""), empty_a)
            self.assertEqual(written_a, 0)
            self.assertEqual(digest_a, hashlib.sha256(b"").hexdigest())
            self.assertTrue(empty_a.exists())

            empty_b = tmp_dir / "empty_b.bin"
            digest_b, written_b = hash_stream_to_path(
                io.BytesIO(b""), empty_b, expected_bytes=0
            )
            self.assertEqual(written_b, 0)
            self.assertEqual(digest_b, hashlib.sha256(b"").hexdigest())

            # 2. Disconnected at zero bytes is NOT treated as a valid empty stream
            disc_zero = tmp_dir / "disc_zero.bin"
            with self.assertRaises(PrematureUploadTerminationError) as z_ctx:
                hash_stream_to_path(
                    _DisconnectStream([], ConnectionResetError("peer reset")),
                    disc_zero,
                )
            self.assertEqual(z_ctx.exception.code, UPLOAD_PREMATURE_TERMINATION)
            self.assertEqual(z_ctx.exception.reason, "stream_disconnected")
            self.assertEqual(z_ctx.exception.observed_bytes, 0)
            self.assertFalse(disc_zero.exists())

            # 3. Disconnected mid-stream removes partial destination artifact
            disc_mid = tmp_dir / "disc_mid.bin"
            with self.assertRaises(PrematureUploadTerminationError) as m_ctx:
                hash_stream_to_path(
                    _DisconnectStream([b"frame-0", b"frame-1"], BrokenPipeError("broken")),
                    disc_mid,
                    chunk_size=16,
                )
            self.assertEqual(m_ctx.exception.code, UPLOAD_PREMATURE_TERMINATION)
            self.assertEqual(m_ctx.exception.observed_bytes, 14)
            self.assertFalse(disc_mid.exists())

            # 4. Clean EOF short of expected_bytes raises short_read and leaves no artifact
            short_dest = tmp_dir / "short.bin"
            storage = StreamingFileStorage(
                io.BytesIO(b"partial"),
                filename="clip.mp4",
                expected_bytes=64,
            )
            with self.assertRaises(PrematureUploadTerminationError) as s_ctx:
                storage.save(str(short_dest))
            self.assertEqual(s_ctx.exception.reason, "short_read")
            self.assertEqual(s_ctx.exception.expected_bytes, 64)
            self.assertEqual(s_ctx.exception.observed_bytes, 7)
            self.assertFalse(short_dest.exists())

    def test_http_premature_termination_returns_distinct_code_and_blocks_processing_jobs(self) -> None:
        env = {
            "APP_ENV": "testing",
            "DATABASE_URL": "",
            "NOIR_WORKER_ENABLED": "false",
            "RATELIMIT_ENABLED": "false",
        }
        with patch.dict(os.environ, env, clear=False):
            flask_app = app_module.create_app()
            client = flask_app.test_client()

            with (
                patch.object(app_module, "embed_metadata") as embed_mock,
                patch.object(app_module, "insert_proof_event") as db_mock,
            ):
                # 1. Truncated multipart body mid-upload (declared Content-Length > actual bytes)
                boundary = "----HarpocratesBoundary99"
                partial_multipart = (
                    f"--{boundary}\r\n"
                    'Content-Disposition: form-data; name="metadata"\r\n\r\n'
                    f"{json.dumps(_METADATA)}\r\n"
                    f"--{boundary}\r\n"
                    'Content-Disposition: form-data; name="video"; filename="clip.mp4"\r\n'
                    "Content-Type: video/mp4\r\n\r\n"
                    "PARTIAL_BYTES_ONLY"
                ).encode("utf-8")

                truncated_resp = client.open(
                    "/api/stego/embed",
                    method="POST",
                    headers={
                        "Content-Type": f"multipart/form-data; boundary={boundary}",
                        "Content-Length": str(len(partial_multipart) + 4096),
                    },
                    input_stream=io.BytesIO(partial_multipart),
                )
                self.assertEqual(truncated_resp.status_code, 400)
                t_body = truncated_resp.get_json()
                self.assertFalse(t_body["ok"])
                self.assertEqual(
                    t_body["error"]["code"], UPLOAD_PREMATURE_TERMINATION
                )
                embed_mock.assert_not_called()
                db_mock.assert_not_called()

                # 2. Declared X-Upload-Expected-Bytes larger than uploaded video part
                short_embed = client.post(
                    "/api/stego/embed",
                    headers={"X-Upload-Expected-Bytes": "2048"},
                    data={
                        "metadata": json.dumps(_METADATA),
                        "video": (io.BytesIO(b"\x00\x00\x00\x18ftypmp42"), "clip.mp4", "video/mp4"),
                    },
                    content_type="multipart/form-data",
                )
                self.assertEqual(short_embed.status_code, 400)
                self.assertEqual(
                    short_embed.get_json()["error"]["code"],
                    UPLOAD_PREMATURE_TERMINATION,
                )
                embed_mock.assert_not_called()
                db_mock.assert_not_called()

                # 3. Session chunk: valid empty chunk vs truncated chunk + commit guard
                sess = client.post("/api/stego/upload-session")
                self.assertEqual(sess.status_code, 200)
                session_id = sess.get_json()["sessionId"]
                session_dir = Path(tempfile.gettempdir()) / f"harpocrates-session-{session_id}"
                try:
                    valid_empty = client.put(
                        f"/api/stego/upload-session/{session_id}/chunk/0",
                        headers={"X-Upload-Expected-Bytes": "0"},
                        data={"chunk": (io.BytesIO(b""), "empty.bin")},
                        content_type="multipart/form-data",
                    )
                    self.assertEqual(valid_empty.status_code, 200)
                    self.assertEqual(valid_empty.get_json()["bytes"], 0)

                    short_chunk = client.put(
                        f"/api/stego/upload-session/{session_id}/chunk/1",
                        headers={"X-Upload-Expected-Bytes": "512"},
                        data={"chunk": (io.BytesIO(b"short"), "part.bin")},
                        content_type="multipart/form-data",
                    )
                    self.assertEqual(short_chunk.status_code, 400)
                    self.assertEqual(
                        short_chunk.get_json()["error"]["code"],
                        UPLOAD_PREMATURE_TERMINATION,
                    )
                    self.assertFalse((session_dir / "chunk-1").exists())

                    short_commit = client.post(
                        f"/api/stego/upload-session/{session_id}/commit",
                        headers={"X-Upload-Expected-Bytes": "128"},
                        data={"metadata": json.dumps(_METADATA)},
                        content_type="multipart/form-data",
                    )
                    self.assertEqual(short_commit.status_code, 400)
                    self.assertEqual(
                        short_commit.get_json()["error"]["code"],
                        UPLOAD_PREMATURE_TERMINATION,
                    )
                    embed_mock.assert_not_called()
                    db_mock.assert_not_called()
                finally:
                    shutil.rmtree(session_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
