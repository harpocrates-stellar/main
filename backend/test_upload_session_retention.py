"""Focused automated coverage for upload session expiry, active worker safety,
and operator retention preview.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from admission import AdmissionController
from errors import GONE
from streaming_upload import (
    DEFAULT_SESSION_TTL_SECONDS,
    SESSION_PREFIX,
    SessionRetentionPreview,
    get_session_dir,
    get_session_info,
    init_session_dir,
    is_session_expired,
    preview_upload_session_retention,
    purge_expired_upload_sessions,
    resolve_session_ttl,
    touch_session,
)


class TestUploadSessionRetention(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="harpocrates-test-retention-")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_fake_session(
        self,
        session_id: str,
        *,
        age_seconds: float = 0.0,
        now: float | None = None,
        chunks: list[bytes] | None = None,
        with_metadata: bool = True,
    ) -> Path:
        s_dir = Path(self.temp_dir) / f"{SESSION_PREFIX}{session_id}"
        s_dir.mkdir(parents=True, exist_ok=True)
        base_now = now if now is not None else time.time()
        created_at = base_now - age_seconds
        updated_at = base_now - age_seconds

        if with_metadata:
            meta = s_dir / ".session_meta"
            meta.write_text(
                json.dumps({
                    "session_id": session_id,
                    "created_at": created_at,
                    "updated_at": updated_at,
                }),
                encoding="utf-8",
            )

        if chunks:
            for idx, content in enumerate(chunks):
                chunk_file = s_dir / f"chunk-{idx}"
                chunk_file.write_bytes(content)
                os.utime(str(chunk_file), (updated_at, updated_at))

        os.utime(str(s_dir), (updated_at, updated_at))
        return s_dir

    def test_session_creation_initializes_metadata(self):
        session_id = "test-session-init"
        s_dir = init_session_dir(session_id, temp_dir=self.temp_dir)
        self.assertTrue(s_dir.exists())
        meta_file = s_dir / ".session_meta"
        self.assertTrue(meta_file.exists())
        data = json.loads(meta_file.read_text(encoding="utf-8"))
        self.assertEqual(data["session_id"], session_id)
        self.assertAlmostEqual(data["created_at"], time.time(), delta=5.0)
        self.assertAlmostEqual(data["updated_at"], time.time(), delta=5.0)

    def test_session_is_expired_respects_ttl_and_boundaries(self):
        ttl = 3600.0
        now = 100000.0

        # Boundary 1: Fresh session (age 100s) -> not expired
        s1 = self._create_fake_session("s1", age_seconds=100.0, now=now)
        self.assertFalse(is_session_expired(s1, ttl_seconds=ttl, now=now))

        # Boundary 2: Exact boundary (age == TTL) -> expired
        s2 = self._create_fake_session("s2", age_seconds=3600.0, now=now)
        self.assertTrue(is_session_expired(s2, ttl_seconds=ttl, now=now))

        # Boundary 3: Just under TTL (age == TTL - 1s) -> not expired
        s3 = self._create_fake_session("s3", age_seconds=3599.0, now=now)
        self.assertFalse(is_session_expired(s3, ttl_seconds=ttl, now=now))

        # Boundary 4: Well expired (age == 7200s) -> expired
        s4 = self._create_fake_session("s4", age_seconds=7200.0, now=now)
        self.assertTrue(is_session_expired(s4, ttl_seconds=ttl, now=now))

    def test_touch_session_updates_activity(self):
        s_dir = self._create_fake_session("s-touch", age_seconds=500.0)
        old_info = get_session_info(s_dir)
        time.sleep(0.01)
        touch_session(s_dir)
        new_info = get_session_info(s_dir)
        self.assertGreater(new_info["updated_at"], old_info["updated_at"])

    def test_preview_lists_expired_sessions_and_bounded_reclaimable_storage(self):
        # Create 3 sessions:
        # s_expired_1: 2 chunks of 100 bytes = 200 bytes (+ meta size)
        chunk_100 = b"x" * 100
        s1 = self._create_fake_session(
            "sess-exp-1",
            age_seconds=5000.0,
            chunks=[chunk_100, chunk_100],
        )
        s1_bytes = get_session_info(s1)["reclaimable_bytes"]

        # s_expired_2: 1 chunk of 500 bytes
        chunk_500 = b"y" * 500
        s2 = self._create_fake_session(
            "sess-exp-2",
            age_seconds=4000.0,
            chunks=[chunk_500],
        )
        s2_bytes = get_session_info(s2)["reclaimable_bytes"]

        # s_fresh: fresh session (should not be listed or counted as expired)
        self._create_fake_session(
            "sess-fresh",
            age_seconds=10.0,
            chunks=[b"z" * 1000],
        )

        preview = preview_upload_session_retention(
            temp_dir=self.temp_dir,
            ttl_seconds=3600,
        )

        self.assertEqual(preview.expired_count, 2)
        self.assertEqual(preview.reclaimable_bytes, s1_bytes + s2_bytes)
        self.assertEqual(preview.active_skipped_count, 0)
        self.assertEqual(preview.active_skipped_bytes, 0)
        self.assertEqual(preview.total_scanned, 3)

        expired_ids = {s["session_id"] for s in preview.expired_sessions}
        self.assertEqual(expired_ids, {"sess-exp-1", "sess-exp-2"})

        # Check detail records
        s1_rec = next(s for s in preview.expired_sessions if s["session_id"] == "sess-exp-1")
        self.assertEqual(s1_rec["chunk_count"], 2)
        self.assertEqual(s1_rec["reclaimable_bytes"], s1_bytes)
        self.assertGreaterEqual(s1_rec["age_seconds"], 5000.0)

    def test_avoid_deleting_chunks_referenced_by_active_workers(self):
        """CRITICAL: Chunks referenced by active workers must NOT be deleted or marked reclaimable."""
        controller = AdmissionController(
            max_concurrent=5,
            max_queue=5,
            max_per_identity=5,
            timeout_seconds=1.0,
        )

        # 3 expired sessions:
        # 1. sess-idle: no active worker
        # 2. sess-active-controller: registered on AdmissionController
        # 3. sess-active-set: registered via active_sessions iterable
        c1 = b"chunk1" * 50
        c2 = b"chunk2" * 50
        s_idle = self._create_fake_session("sess-idle", age_seconds=5000.0, chunks=[c1])
        s_active1 = self._create_fake_session("sess-active-ctrl", age_seconds=5000.0, chunks=[c2])
        s_active2 = self._create_fake_session("sess-active-set", age_seconds=5000.0, chunks=[c1, c2])

        # Active worker claims sess-active-ctrl via AdmissionController
        controller.acquire_session("sess-active-ctrl")
        self.assertTrue(controller.is_session_active("sess-active-ctrl"))

        # Preview with controller:
        preview = preview_upload_session_retention(
            temp_dir=self.temp_dir,
            ttl_seconds=3600,
            active_sessions=controller,
        )

        # sess-idle is expired and reclaimable
        self.assertEqual(preview.expired_count, 2)  # sess-idle and sess-active-set
        expired_ids = {s["session_id"] for s in preview.expired_sessions}
        self.assertIn("sess-idle", expired_ids)
        self.assertIn("sess-active-set", expired_ids)
        self.assertNotIn("sess-active-ctrl", expired_ids)
        self.assertEqual(preview.active_skipped_count, 1)
        self.assertGreater(preview.active_skipped_bytes, 0)

        # Preview combining both active sessions
        preview_both = preview_upload_session_retention(
            temp_dir=self.temp_dir,
            ttl_seconds=3600,
            active_sessions={"sess-active-ctrl", "sess-active-set"},
        )
        self.assertEqual(preview_both.expired_count, 1)
        self.assertEqual(preview_both.expired_sessions[0]["session_id"], "sess-idle")
        self.assertEqual(preview_both.active_skipped_count, 2)

        # NOW PURGE: Purge must delete sess-idle, but PRESERVE chunks in active sessions!
        purged, reclaimed, skipped = purge_expired_upload_sessions(
            temp_dir=self.temp_dir,
            ttl_seconds=3600,
            active_sessions=controller,
        )

        self.assertEqual(purged, 2)  # sess-idle and sess-active-set were purged
        self.assertEqual(skipped, 1)  # sess-active-ctrl was skipped
        self.assertFalse(s_idle.exists())
        # The chunks in active session MUST still exist!
        self.assertTrue(s_active1.exists())
        self.assertTrue((s_active1 / "chunk-0").exists())
        self.assertEqual((s_active1 / "chunk-0").read_bytes(), c2)

        # Release session in controller
        controller.release_session("sess-active-ctrl")
        self.assertFalse(controller.is_session_active("sess-active-ctrl"))

        # Now that worker has finished, another purge will clean it up
        purged2, _, skipped2 = purge_expired_upload_sessions(
            temp_dir=self.temp_dir,
            ttl_seconds=3600,
            active_sessions=controller,
        )
        self.assertEqual(purged2, 1)
        self.assertEqual(skipped2, 0)
        self.assertFalse(s_active1.exists())

    def test_scan_limit_is_bounded(self):
        # Create 10 expired sessions
        for i in range(10):
            self._create_fake_session(f"sess-{i:02d}", age_seconds=5000.0, chunks=[b"data"])

        # Request a bounded limit of 4
        preview = preview_upload_session_retention(
            temp_dir=self.temp_dir,
            ttl_seconds=3600,
            limit=4,
        )
        self.assertEqual(preview.total_scanned, 4)
        self.assertEqual(len(preview.expired_sessions), 4)
        self.assertEqual(preview.limit, 4)

    def test_backward_compatibility_without_metadata_file(self):
        """Sessions created before this feature without .session_meta must still be recognized."""
        s_legacy = self._create_fake_session(
            "sess-legacy",
            age_seconds=6000.0,
            chunks=[b"legacy_chunk"],
            with_metadata=False,
        )
        self.assertFalse((s_legacy / ".session_meta").exists())
        info = get_session_info(s_legacy)
        self.assertEqual(info["session_id"], "sess-legacy")
        self.assertEqual(info["chunk_count"], 1)
        self.assertGreaterEqual(info["age_seconds"], 5000.0)

        preview = preview_upload_session_retention(
            temp_dir=self.temp_dir,
            ttl_seconds=3600,
        )
        self.assertEqual(preview.expired_count, 1)
        self.assertEqual(preview.expired_sessions[0]["session_id"], "sess-legacy")

    def test_corrupted_metadata_file_handled_gracefully(self):
        s_corrupted = self._create_fake_session("sess-corrupt", age_seconds=6000.0)
        meta = s_corrupted / ".session_meta"
        meta.write_text("NOT_VALID_JSON{{{", encoding="utf-8")

        info = get_session_info(s_corrupted)
        self.assertEqual(info["session_id"], "sess-corrupt")
        self.assertTrue(is_session_expired(s_corrupted, ttl_seconds=3600))


class TestUploadSessionApiExpiry(unittest.TestCase):
    def setUp(self):
        from app import create_app
        os.environ["UPLOAD_SESSION_TTL_SECONDS"] = "1"
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        os.environ.pop("UPLOAD_SESSION_TTL_SECONDS", None)

    def test_upload_chunk_on_expired_session_returns_410_gone(self):
        # Create session
        res = self.client.post("/api/stego/upload-session")
        self.assertEqual(res.status_code, 200)
        session_id = res.get_json()["sessionId"]

        # Wait for TTL to expire (1 second)
        time.sleep(1.1)

        # Try to upload chunk
        chunk_data = io.BytesIO(b"sample-chunk-data")
        chunk_res = self.client.put(
            f"/api/stego/upload-session/{session_id}/chunk/0",
            data={"chunk": (chunk_data, "chunk.bin")},
            content_type="multipart/form-data",
        )
        self.assertEqual(chunk_res.status_code, 410)
        body = chunk_res.get_json()
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"]["code"], GONE)
        self.assertIn("expired", body["error"]["message"])

    def test_commit_on_expired_session_returns_410_gone(self):
        # Create session
        res = self.client.post("/api/stego/upload-session")
        self.assertEqual(res.status_code, 200)
        session_id = res.get_json()["sessionId"]

        # Wait for TTL to expire (1 second)
        time.sleep(1.1)

        # Try to commit
        commit_res = self.client.post(
            f"/api/stego/upload-session/{session_id}/commit",
            data={"metadata": "{}"},
            content_type="multipart/form-data",
        )
        self.assertEqual(commit_res.status_code, 410)
        body = commit_res.get_json()
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"]["code"], GONE)
        self.assertIn("expired", body["error"]["message"])


if __name__ == "__main__":
    unittest.main()
