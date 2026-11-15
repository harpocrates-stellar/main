from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.exceptions import RequestEntityTooLarge

sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as app_module  # noqa: E402
from streaming_upload import UploadProgressTracker, hash_stream_to_path  # noqa: E402


class UploadHashingProgressUnitTests(unittest.TestCase):
    def test_tracker_clamps_counters_evicts_oldest_and_omits_paths(self) -> None:
        tracker = UploadProgressTracker(max_sessions=2, max_counter_bytes=500)
        tracker.start_session("s1", expected_bytes=9999)
        snap1 = tracker.get("s1")
        self.assertIsNotNone(snap1)
        assert snap1 is not None
        self.assertEqual(snap1.expected_bytes, 500)
        self.assertEqual(snap1.state, "pending")
        self.assertFalse(snap1.completed)

        with tempfile.TemporaryDirectory() as tmp_dir:
            dest = Path(tmp_dir) / "secret-server-location.bin"
            observed_states: list[tuple[str, int, bool]] = []
            base_cb = tracker.make_stream_reporter("s1", ceiling_bytes=500, finalize_session=True)

            def _spy_cb(written: int, phase: str) -> None:
                base_cb(written, phase)
                cur = tracker.get("s1")
                assert cur is not None
                observed_states.append((cur.state, cur.bytes_hashed, cur.completed))
                serialized = json.dumps(cur.to_public_dict())
                self.assertNotIn(str(tmp_dir), serialized)
                self.assertNotIn("secret-server-location", serialized)
                self.assertNotIn("harpocrates-stream-", serialized)

            hash_stream_to_path(
                io.BytesIO(b"a" * 300),
                dest,
                chunk_size=100,
                temp_dir=tmp_dir,
                progress_callback=_spy_cb,
            )

        self.assertIn(("hashing", 100, False), observed_states)
        self.assertIn(("hashing", 200, False), observed_states)
        self.assertIn(("completed", 300, True), observed_states)

        # Bounded session map evicts oldest session once max_sessions is exceeded.
        tracker.start_session("s2")
        tracker.start_session("s3")
        self.assertIsNone(tracker.get("s1"))
        self.assertIsNotNone(tracker.get("s2"))
        self.assertIsNotNone(tracker.get("s3"))

    def test_oversized_stream_marks_failed_without_exposing_temp_path(self) -> None:
        tracker = UploadProgressTracker(max_counter_bytes=1024)
        with tempfile.TemporaryDirectory() as tmp_dir:
            dest = Path(tmp_dir) / "partial-output.bin"
            cb = tracker.make_stream_reporter("s-fail", ceiling_bytes=256)
            with self.assertRaises(RequestEntityTooLarge):
                hash_stream_to_path(
                    io.BytesIO(b"x" * 400),
                    dest,
                    chunk_size=128,
                    max_size=256,
                    temp_dir=tmp_dir,
                    progress_callback=cb,
                )
            snap = tracker.get("s-fail")
            assert snap is not None
            self.assertEqual(snap.state, "failed")
            self.assertFalse(snap.completed)
            self.assertEqual(snap.bytes_hashed, 256)
            body = json.dumps(snap.to_public_dict())
            self.assertNotIn(str(tmp_dir), body)
            self.assertNotIn("partial-output", body)


class UploadHashingProgressRouteTests(unittest.TestCase):
    def _build_app(self, extra_env: dict[str, str] | None = None):
        env = {
            "RATELIMIT_ENABLED": "false",
            "MAX_VIDEO_BYTES": "1024",
        }
        if extra_env:
            env.update(extra_env)
        with patch.dict(os.environ, env, clear=False):
            return app_module.create_app()

    def _assert_no_server_paths(self, raw_text: str) -> None:
        temp_root = tempfile.gettempdir()
        self.assertNotIn(temp_root, raw_text)
        self.assertNotIn(temp_root.replace("\\", "/"), raw_text)
        self.assertNotIn("harpocrates-session-", raw_text)
        self.assertNotIn("harpocrates-stream-", raw_text)
        self.assertNotIn("harpocrates-concat-", raw_text)
        self.assertNotIn("chunk-0", raw_text)
        self.assertNotIn("combined.video", raw_text)

    def test_session_progress_lifecycle_and_path_redaction(self) -> None:
        flask_app = self._build_app()
        client = flask_app.test_client()

        missing = client.get("/api/stego/upload-session/unknown-id/progress")
        self.assertEqual(missing.status_code, 404)
        self._assert_no_server_paths(missing.get_data(as_text=True))

        created = client.post(
            "/api/stego/upload-session",
            headers={"X-Upload-Declared-Size": "512"},
        )
        self.assertEqual(created.status_code, 200)
        session_id = created.get_json()["sessionId"]

        initial = client.get(f"/api/stego/upload-session/{session_id}/progress")
        self.assertEqual(initial.status_code, 200)
        p0 = initial.get_json()
        self.assertEqual(p0["state"], "pending")
        self.assertEqual(p0["bytesHashed"], 0)
        self.assertEqual(p0["expectedBytes"], 512)
        self.assertFalse(p0["completed"])
        self._assert_no_server_paths(initial.get_data(as_text=True))

        c0 = client.put(
            f"/api/stego/upload-session/{session_id}/chunk/0",
            data={"chunk": (io.BytesIO(b"\x00\x00\x00\x18ftypmp42" + b"p" * 244), "secret_dir/video.mp4")},
            content_type="multipart/form-data",
        )
        self.assertEqual(c0.status_code, 200)

        after_chunk = client.get(f"/api/stego/upload-session/{session_id}/progress")
        p1 = after_chunk.get_json()
        self.assertEqual(p1["bytesHashed"], 256)
        self.assertEqual(p1["chunksHashed"], 1)
        self.assertFalse(p1["completed"])
        self._assert_no_server_paths(after_chunk.get_data(as_text=True))

        # Oversized chunk transitions session progress to failed without leaking temp paths.
        oversized = client.put(
            f"/api/stego/upload-session/{session_id}/chunk/1",
            data={"chunk": (io.BytesIO(b"x" * 2048), "oversized.mp4")},
            content_type="multipart/form-data",
        )
        self.assertEqual(oversized.status_code, 413)
        failed_prog = client.get(f"/api/stego/upload-session/{session_id}/progress")
        self.assertEqual(failed_prog.get_json()["state"], "failed")
        self._assert_no_server_paths(failed_prog.get_data(as_text=True))

        # Commit valid chunk 0 transitions session progress to completed=True.
        def _fake_embed(_src, dst, _meta):
            Path(dst).write_bytes(b"synthetic-mp4")

        valid_meta = {
            "version": 2,
            "proofId": "proof-1038",
            "tier": "verified",
            "timestamp": "2026-11-15T00:00:00Z",
        }
        with (
            patch.object(app_module, "sniff_media_type_path", return_value="video/mp4"),
            patch.object(app_module, "embed_metadata", side_effect=_fake_embed),
            patch.object(app_module, "validate_embed_metadata", return_value=None),
            patch.object(app_module, "insert_proof_event", return_value={"id": 1}),
        ):
            committed = client.post(
                f"/api/stego/upload-session/{session_id}/commit",
                data={"metadata": json.dumps(valid_meta)},
                content_type="multipart/form-data",
            )
        self.assertEqual(committed.status_code, 200)

        done_prog = client.get(f"/api/stego/upload-session/{session_id}/progress")
        self.assertEqual(done_prog.status_code, 200)
        pf = done_prog.get_json()
        self.assertEqual(pf["state"], "completed")
        self.assertTrue(pf["completed"])
        self.assertEqual(pf["bytesHashed"], 256)
        self._assert_no_server_paths(done_prog.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
