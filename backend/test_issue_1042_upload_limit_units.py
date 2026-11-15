"""Focused tests for normalized upload limit headers and byte-unit error payloads (issue #1042)."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask, g, jsonify

sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as app_module  # noqa: E402
from admission import AdmissionController, require_capacity  # noqa: E402
from streaming_upload import (  # noqa: E402
    HEADER_UPLOAD_CHUNK_BYTES,
    HEADER_UPLOAD_LIMIT_POLICY,
    HEADER_UPLOAD_LIMIT_UNIT,
    HEADER_UPLOAD_MAX_BYTES,
    LIMIT_POLICY_ENFORCED,
    LIMIT_POLICY_UNLIMITED,
    LIMIT_POLICY_ZERO_ALLOWANCE,
    UPLOAD_LIMIT_UNIT,
    StreamingFileStorage,
    UploadLimitExceededError,
    hash_paths_concat,
    hash_stream_to_path,
    resolve_upload_limit_spec,
)


class UploadLimitUnitsTest(unittest.TestCase):
    def test_distinguishes_absent_limit_from_zero_byte_allowance_in_stream_and_concat(self) -> None:
        absent_spec = resolve_upload_limit_spec(None)
        self.assertIsNone(absent_spec.limit_bytes)
        self.assertTrue(absent_spec.is_unlimited)
        self.assertFalse(absent_spec.is_zero_allowance)
        self.assertEqual(absent_spec.policy, LIMIT_POLICY_UNLIMITED)
        absent_headers = absent_spec.to_headers()
        self.assertEqual(absent_headers[HEADER_UPLOAD_LIMIT_UNIT], UPLOAD_LIMIT_UNIT)
        self.assertEqual(absent_headers[HEADER_UPLOAD_LIMIT_POLICY], LIMIT_POLICY_UNLIMITED)
        self.assertNotIn(HEADER_UPLOAD_MAX_BYTES, absent_headers)

        zero_spec = resolve_upload_limit_spec(0)
        self.assertEqual(zero_spec.limit_bytes, 0)
        self.assertFalse(zero_spec.is_unlimited)
        self.assertTrue(zero_spec.is_zero_allowance)
        self.assertEqual(zero_spec.policy, LIMIT_POLICY_ZERO_ALLOWANCE)
        zero_headers = zero_spec.to_headers()
        self.assertEqual(zero_headers[HEADER_UPLOAD_LIMIT_UNIT], UPLOAD_LIMIT_UNIT)
        self.assertEqual(zero_headers[HEADER_UPLOAD_LIMIT_POLICY], LIMIT_POLICY_ZERO_ALLOWANCE)
        self.assertEqual(zero_headers[HEADER_UPLOAD_MAX_BYTES], "0")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            # Absent limit allows arbitrary non-empty payload
            unbounded_dest = tmp_dir / "unbounded.bin"
            digest, written = hash_stream_to_path(
                io.BytesIO(b"synthetic-bytes"), unbounded_dest, max_size=None
            )
            self.assertEqual(written, 15)
            self.assertEqual(digest, hashlib.sha256(b"synthetic-bytes").hexdigest())

            # Explicit 0-byte allowance accepts 0 bytes...
            empty_dest = tmp_dir / "zero-ok.bin"
            zero_digest, zero_written = hash_stream_to_path(
                io.BytesIO(b""), empty_dest, max_size=0
            )
            self.assertEqual(zero_written, 0)
            self.assertEqual(zero_digest, hashlib.sha256(b"").hexdigest())

            # ...and rejects even 1 byte with byte-unit metadata!
            one_byte_dest = tmp_dir / "zero-reject.bin"
            with self.assertRaises(UploadLimitExceededError) as ctx:
                hash_stream_to_path(io.BytesIO(b"x"), one_byte_dest, max_size=0)
            self.assertEqual(ctx.exception.limit_bytes, 0)
            self.assertEqual(ctx.exception.observed_bytes, 1)
            self.assertEqual(ctx.exception.unit, "bytes")
            self.assertEqual(ctx.exception.limit_policy, LIMIT_POLICY_ZERO_ALLOWANCE)
            self.assertFalse(one_byte_dest.exists())

            # Same distinction for StreamingFileStorage and hash_paths_concat
            storage = StreamingFileStorage(io.BytesIO(b"z"), filename="synthetic.mp4", max_size=0)
            with self.assertRaises(UploadLimitExceededError):
                storage.save(str(tmp_dir / "storage-reject.bin"))

            part = tmp_dir / "part-0"
            part.write_bytes(b"z")
            with self.assertRaises(UploadLimitExceededError) as concat_ctx:
                hash_paths_concat([part], tmp_dir / "concat-reject.bin", max_size=0)
            self.assertEqual(concat_ctx.exception.limit_bytes, 0)
            self.assertEqual(concat_ctx.exception.unit, "bytes")

    def test_declared_upload_limit_preserves_zero_and_unlimited_modes(self) -> None:
        zero_cfg = SimpleNamespace(
            upload_max_bytes=0,
            max_video_bytes=4096,
            max_content_length=10_000_000,
        )
        self.assertEqual(
            app_module.declared_upload_limit_bytes(zero_cfg),
            app_module.UPLOAD_MULTIPART_OVERHEAD_BYTES,
        )

        unlimited_cfg = SimpleNamespace(
            upload_limit_unlimited=True,
            upload_max_bytes=None,
            max_video_bytes=4096,
            max_content_length=0,
        )
        self.assertIsNone(app_module.declared_upload_limit_bytes(unlimited_cfg))

    def test_http_upload_headers_and_rejection_bodies_use_bytes_consistently(self) -> None:
        base_env = {
            "APP_ENV": "testing",
            "DATABASE_URL": "",
            "NOIR_WORKER_ENABLED": "false",
            "RATELIMIT_ENABLED": "false",
            "UPLOAD_CHUNK_BYTES": "8192",
        }

        # 1. Zero-byte allowance via UPLOAD_MAX_BYTES=0
        with patch.dict(os.environ, {**base_env, "UPLOAD_MAX_BYTES": "0"}, clear=False):
            flask_app = app_module.create_app()
            client = flask_app.test_client()
            created = client.post("/api/stego/upload-session")
            self.assertEqual(created.status_code, 200)
            self.assertEqual(created.headers[HEADER_UPLOAD_LIMIT_UNIT], "bytes")
            self.assertEqual(created.headers[HEADER_UPLOAD_LIMIT_POLICY], LIMIT_POLICY_ZERO_ALLOWANCE)
            self.assertEqual(created.headers[HEADER_UPLOAD_MAX_BYTES], "0")
            self.assertEqual(created.headers[HEADER_UPLOAD_CHUNK_BYTES], "8192")
            session_id = created.get_json()["sessionId"]

            # Empty chunk succeeds under zero-byte allowance
            ok_empty = client.put(
                f"/api/stego/upload-session/{session_id}/chunk/0",
                data={"chunk": (io.BytesIO(b""), "empty.bin")},
                content_type="multipart/form-data",
            )
            self.assertEqual(ok_empty.status_code, 200)
            self.assertEqual(ok_empty.get_json()["bytes"], 0)

            # Non-empty chunk rejected with 413 and normalized byte-unit fields
            sentinel = b"SYNTHETIC_SECRET_PAYLOAD_DO_NOT_ECHO"
            rejected = client.put(
                f"/api/stego/upload-session/{session_id}/chunk/1",
                data={"chunk": (io.BytesIO(sentinel), "private-name.mp4")},
                content_type="multipart/form-data",
            )
            self.assertEqual(rejected.status_code, 413)
            self.assertEqual(rejected.headers[HEADER_UPLOAD_LIMIT_UNIT], "bytes")
            self.assertEqual(rejected.headers[HEADER_UPLOAD_MAX_BYTES], "0")
            body = rejected.get_json()
            self.assertFalse(body["ok"])
            self.assertEqual(body["unit"], "bytes")
            self.assertEqual(body["limit_bytes"], 0)
            self.assertEqual(body["limit_policy"], LIMIT_POLICY_ZERO_ALLOWANCE)
            self.assertEqual(body["chunk_bytes"], 8192)
            self.assertEqual(body["error"]["code"], "PAYLOAD_TOO_LARGE")
            self.assertEqual(body["error"]["unit"], "bytes")
            self.assertEqual(body["error"]["limit_bytes"], 0)
            self.assertNotIn("SYNTHETIC_SECRET_PAYLOAD_DO_NOT_ECHO", rejected.get_data(as_text=True))
            self.assertNotIn("private-name.mp4", rejected.get_data(as_text=True))
            shutil.rmtree(
                Path(tempfile.gettempdir()) / f"harpocrates-session-{session_id}",
                ignore_errors=True,
            )

        # 2. Absent limit via UPLOAD_MAX_BYTES=unlimited omits X-Upload-Max-Bytes
        with patch.dict(os.environ, {**base_env, "UPLOAD_MAX_BYTES": "unlimited"}, clear=False):
            unlimited_app = app_module.create_app()
            unlimited_client = unlimited_app.test_client()
            resp = unlimited_client.post("/api/stego/upload-session")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.headers[HEADER_UPLOAD_LIMIT_UNIT], "bytes")
            self.assertEqual(resp.headers[HEADER_UPLOAD_LIMIT_POLICY], LIMIT_POLICY_UNLIMITED)
            self.assertNotIn(HEADER_UPLOAD_MAX_BYTES, resp.headers)
            shutil.rmtree(
                Path(tempfile.gettempdir()) / f"harpocrates-session-{resp.get_json()['sessionId']}",
                ignore_errors=True,
            )

        # 3. Enforced positive byte limit on admission rejection includes byte-unit fields
        mini_app = Flask(__name__)
        controller = AdmissionController(
            max_concurrent=1,
            max_queue=0,
            max_per_identity=0,
            timeout_seconds=0.1,
        )

        @mini_app.before_request
        def _set_cfg() -> None:
            g.upload_config = SimpleNamespace(
                upload_max_bytes=16_384,
                upload_chunk_bytes=4096,
                upload_limit_unlimited=False,
            )

        @mini_app.post("/upload")
        @require_capacity(controller)
        def _upload_route():
            return jsonify({"ok": True})

        adm_resp = mini_app.test_client().post("/upload")
        self.assertEqual(adm_resp.status_code, 429)
        self.assertEqual(adm_resp.headers[HEADER_UPLOAD_LIMIT_UNIT], "bytes")
        self.assertEqual(adm_resp.headers[HEADER_UPLOAD_MAX_BYTES], "16384")
        self.assertEqual(adm_resp.headers[HEADER_UPLOAD_LIMIT_POLICY], LIMIT_POLICY_ENFORCED)
        adm_body = adm_resp.get_json()
        self.assertEqual(adm_body["reason"], "identity_limit")
        self.assertEqual(adm_body["unit"], "bytes")
        self.assertEqual(adm_body["limit_bytes"], 16_384)


if __name__ == "__main__":
    unittest.main(verbosity=2)
