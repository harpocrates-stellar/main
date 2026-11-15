"""Focused regression and active-worker safety tests for issue #1043:
add upload session expiry with an operator retention preview.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from admission import AdmissionController  # noqa: E402
import app as app_module  # noqa: E402
import streaming_upload  # noqa: E402


class UploadSessionExpiryPreviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = AdmissionController(
            max_concurrent=4,
            max_queue=4,
            max_per_identity=2,
            timeout_seconds=1.0,
        )
        self.base_time = 1_763_200_000.0

    def test_preview_lists_expired_sessions_bounded_storage_and_protects_active_workers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)

            # Session 1: expired and idle -> reclaimable (600 bytes across 2 chunks)
            s1_dir = root / "harpocrates-session-expired-1"
            streaming_upload.register_upload_session(
                "expired-1", s1_dir, ttl_seconds=600, now=self.base_time - 1800
            )
            (s1_dir / "chunk-0").write_bytes(b"a" * 250)
            (s1_dir / "chunk-1").write_bytes(b"b" * 350)

            # Session 2: expired on wall-clock, BUT referenced by an active worker!
            s2_dir = root / "harpocrates-session-active-worker"
            streaming_upload.register_upload_session(
                "active-worker", s2_dir, ttl_seconds=600, now=self.base_time - 2400
            )
            (s2_dir / "chunk-0").write_bytes(b"w" * 1024)

            # Session 3: fresh within TTL -> retained
            s3_dir = root / "harpocrates-session-fresh"
            streaming_upload.register_upload_session(
                "fresh", s3_dir, ttl_seconds=600, now=self.base_time - 120
            )
            (s3_dir / "chunk-0").write_bytes(b"f" * 512)

            with self.controller.session_worker_lease("active-worker"):
                preview = streaming_upload.preview_expired_upload_sessions(
                    base_dir=root,
                    ttl_seconds=600,
                    now=self.base_time,
                    controller=self.controller,
                )

                self.assertEqual(
                    preview["counts"],
                    {
                        "sessions_scanned": 3,
                        "expired_reclaimable": 1,
                        "protected_by_active_workers": 1,
                        "within_ttl": 1,
                    },
                )
                self.assertEqual(
                    preview["storage"],
                    {
                        "reclaimable_bytes": 600,
                        "protected_active_bytes": 1024,
                        "unit": "bytes",
                    },
                )
                self.assertEqual(len(preview["expired_sessions"]), 1)
                self.assertEqual(preview["expired_sessions"][0]["session_id"], "expired-1")
                self.assertEqual(preview["expired_sessions"][0]["chunk_count"], 2)
                self.assertEqual(preview["expired_sessions"][0]["reclaimable_bytes"], 600)

                serialized = json.dumps(preview)
                self.assertNotIn(str(root), serialized)
                self.assertNotIn("chunk-0", serialized)

                # Dry-run sweep deletes nothing.
                dry = streaming_upload.sweep_expired_upload_sessions(
                    base_dir=root,
                    ttl_seconds=600,
                    now=self.base_time,
                    controller=self.controller,
                    dry_run=True,
                )
                self.assertEqual(dry["deleted_sessions"], 0)
                self.assertTrue(s1_dir.exists())

                # Live sweep deletes expired-1 while strictly preserving active-worker chunks!
                swept = streaming_upload.sweep_expired_upload_sessions(
                    base_dir=root,
                    ttl_seconds=600,
                    now=self.base_time,
                    controller=self.controller,
                    dry_run=False,
                )
                self.assertEqual(swept["deleted_sessions"], 1)
                self.assertEqual(swept["reclaimed_bytes"], 600)
                self.assertFalse(s1_dir.exists())
                self.assertTrue((s2_dir / "chunk-0").exists())
                self.assertTrue((s3_dir / "chunk-0").exists())

            # Once active-worker lease is released, session becomes reclaimable.
            after_release = streaming_upload.sweep_expired_upload_sessions(
                base_dir=root,
                ttl_seconds=600,
                now=self.base_time,
                controller=self.controller,
            )
            self.assertEqual(after_release["deleted_sessions"], 1)
            self.assertEqual(after_release["reclaimed_bytes"], 1024)
            self.assertFalse(s2_dir.exists())
            self.assertTrue(s3_dir.exists())

    def test_race_between_preview_and_sweep_skips_newly_active_worker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            s_dir = root / "harpocrates-session-race-target"
            streaming_upload.register_upload_session(
                "race-target", s_dir, ttl_seconds=60, now=self.base_time - 300
            )
            (s_dir / "chunk-0").write_bytes(b"r" * 400)

            orig_preview = streaming_upload.preview_expired_upload_sessions

            def preview_then_activate(**kwargs):
                res = orig_preview(**kwargs)
                self.controller.acquire_session_worker("race-target")
                return res

            try:
                with patch.object(
                    streaming_upload,
                    "preview_expired_upload_sessions",
                    side_effect=preview_then_activate,
                ):
                    result = streaming_upload.sweep_expired_upload_sessions(
                        base_dir=root,
                        ttl_seconds=60,
                        now=self.base_time,
                        controller=self.controller,
                    )
                self.assertEqual(result["deleted_sessions"], 0)
                self.assertEqual(result["skipped_newly_active_workers"], 1)
                self.assertTrue((s_dir / "chunk-0").exists())
            finally:
                self.controller.release_session_worker("race-target")

    def test_http_session_expiry_and_operator_retention_preview_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch.object(tempfile, "gettempdir", return_value=tmp_dir), patch.dict(
                os.environ,
                {"METRICS_TOKEN": "synthetic-operator-token", "UPLOAD_SESSION_TTL_SECONDS": "120"},
                clear=False,
            ):
                flask_app = app_module.create_app()
                client = flask_app.test_client()

                created = client.post("/api/stego/upload-session")
                self.assertEqual(created.status_code, 200)
                body = created.get_json()
                session_id = body["sessionId"]
                self.assertEqual(body["ttlSeconds"], 120.0)
                self.assertIn("expiresAt", body)

                chunk_res = client.put(
                    f"/api/stego/upload-session/{session_id}/chunk/0",
                    data={"chunk": (io.BytesIO(b"synthetic-chunk"), "chunk0.bin")},
                    content_type="multipart/form-data",
                )
                self.assertEqual(chunk_res.status_code, 200)

                # Backdate session metadata so it appears expired.
                session_dir = Path(tmp_dir) / f"harpocrates-session-{session_id}"
                streaming_upload.touch_upload_session(session_dir, ttl_seconds=120, now=1_000.0)

                # Expired session rejects subsequent chunk uploads with 410 Gone.
                expired_put = client.put(
                    f"/api/stego/upload-session/{session_id}/chunk/1",
                    data={"chunk": (io.BytesIO(b"late-chunk"), "chunk1.bin")},
                    content_type="multipart/form-data",
                )
                self.assertEqual(expired_put.status_code, 410)

                # Operator preview requires METRICS_TOKEN when configured.
                unauth = client.get("/api/stego/upload-sessions/retention-preview")
                self.assertEqual(unauth.status_code, 401)

                auth_preview = client.get(
                    "/api/stego/upload-sessions/retention-preview",
                    headers={"Authorization": "Bearer synthetic-operator-token"},
                )
                self.assertEqual(auth_preview.status_code, 200)
                pdata = auth_preview.get_json()
                self.assertEqual(pdata["counts"]["expired_reclaimable"], 1)
                self.assertEqual(pdata["storage"]["reclaimable_bytes"], len(b"synthetic-chunk"))


if __name__ == "__main__":
    unittest.main()
