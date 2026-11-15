from __future__ import annotations

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
from streaming_upload import (  # noqa: E402
    DeclaredUploadSizeBinder,
    DeclaredUploadSizeMismatchError,
)


class DeclaredUploadSizeUnitTests(unittest.TestCase):
    def test_binder_persists_session_identity_and_rejects_changes(self) -> None:
        binder = DeclaredUploadSizeBinder()
        with tempfile.TemporaryDirectory() as tmp_dir:
            s_dir = Path(tmp_dir) / "session-a"
            s_dir.mkdir()
            binder.bind_session("session-a", s_dir, 512)
            self.assertEqual(binder.verify_for_chunk("session-a", s_dir, 512), 512)
            binder.record_chunk_accepted("session-a", s_dir)

            # Different declared size fails closed.
            with self.assertRaises(DeclaredUploadSizeMismatchError):
                binder.verify_for_chunk("session-a", s_dir, 1024)

            # Replayed metadata under a different session_id fails closed.
            with self.assertRaises(DeclaredUploadSizeMismatchError):
                binder.verify_for_chunk("session-b", s_dir, 512)

    def test_undeclared_first_chunk_rejects_late_declared_size(self) -> None:
        binder = DeclaredUploadSizeBinder()
        with tempfile.TemporaryDirectory() as tmp_dir:
            s_dir = Path(tmp_dir) / "session-u"
            s_dir.mkdir()
            binder.bind_session("session-u", s_dir, None)
            self.assertIsNone(binder.verify_for_chunk("session-u", s_dir, None))
            binder.record_chunk_accepted("session-u", s_dir)

            with self.assertRaises(DeclaredUploadSizeMismatchError):
                binder.verify_for_chunk("session-u", s_dir, 256)


class DeclaredUploadSizeRouteTests(unittest.TestCase):
    def _build_app(self):
        with patch.dict(
            os.environ,
            {"RATELIMIT_ENABLED": "false"},
            clear=False,
        ):
            return app_module.create_app()

    def test_conflicting_chunk_rejected_while_preserving_accepted_chunks(self) -> None:
        flask_app = self._build_app()
        client = flask_app.test_client()

        part0 = b"\x00\x00\x00\x18ftypmp42" + b"a" * 116  # 128 bytes
        part1 = b"b" * 128  # 128 bytes -> total 256 bytes

        create_resp = client.post(
            "/api/stego/upload-session",
            json={"declaredSize": 256},
        )
        self.assertEqual(create_resp.status_code, 200)
        session_id = create_resp.get_json()["sessionId"]
        session_dir = Path(tempfile.gettempdir()) / f"harpocrates-session-{session_id}"

        c0 = client.put(
            f"/api/stego/upload-session/{session_id}/chunk/0",
            headers={"X-Upload-Declared-Size": "256"},
            data={"chunk": (io.BytesIO(part0), "part0")},
            content_type="multipart/form-data",
        )
        self.assertEqual(c0.status_code, 200)
        chunk0_disk = session_dir / "chunk-0"
        self.assertEqual(chunk0_disk.read_bytes(), part0)

        # Conflicting request on chunk 1 AND conflicting overwrite attempt on chunk 0
        # MUST be rejected with 409 UPLOAD_DECLARED_SIZE_MISMATCH and preserve chunk-0!
        conflict_c1 = client.put(
            f"/api/stego/upload-session/{session_id}/chunk/1",
            headers={"X-Upload-Declared-Size": "512"},
            data={"chunk": (io.BytesIO(b"corrupt" * 20), "part1")},
            content_type="multipart/form-data",
        )
        self.assertEqual(conflict_c1.status_code, 409)
        self.assertEqual(
            conflict_c1.get_json()["error"]["code"],
            "UPLOAD_DECLARED_SIZE_MISMATCH",
        )
        self.assertFalse((session_dir / "chunk-1").exists())
        self.assertEqual(chunk0_disk.read_bytes(), part0)

        conflict_overwrite_c0 = client.put(
            f"/api/stego/upload-session/{session_id}/chunk/0",
            headers={"X-Upload-Declared-Size": "999"},
            data={"chunk": (io.BytesIO(b"overwrite-attempt"), "part0")},
            content_type="multipart/form-data",
        )
        self.assertEqual(conflict_overwrite_c0.status_code, 409)
        self.assertEqual(chunk0_disk.read_bytes(), part0)

        # Valid chunk 1 with matching declared size succeeds and commits cleanly.
        valid_c1 = client.put(
            f"/api/stego/upload-session/{session_id}/chunk/1",
            headers={"X-Upload-Declared-Size": "256"},
            data={"chunk": (io.BytesIO(part1), "part1")},
            content_type="multipart/form-data",
        )
        self.assertEqual(valid_c1.status_code, 200)

        def _fake_embed(_src, dst, _meta):
            Path(dst).write_bytes(b"synthetic-mp4")

        valid_meta = {
            "version": 2,
            "proofId": "proof-1036",
            "tier": "verified",
            "timestamp": "2026-11-15T00:00:00Z",
        }
        with (
            patch.object(app_module, "sniff_media_type_path", return_value="video/mp4"),
            patch.object(app_module, "embed_metadata", side_effect=_fake_embed),
            patch.object(app_module, "validate_embed_metadata", return_value=None),
            patch.object(app_module, "insert_proof_event", return_value={"id": 1}),
        ):
            commit_resp = client.post(
                f"/api/stego/upload-session/{session_id}/commit",
                headers={"X-Upload-Declared-Size": "256"},
                data={"metadata": json.dumps(valid_meta)},
                content_type="multipart/form-data",
            )
        self.assertEqual(commit_resp.status_code, 200)
        self.assertEqual(
            commit_resp.headers["X-Harpocrates-Source-Hash"],
            hashlib.sha256(part0 + part1).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
