"""Tests for declared size consistency in upload sessions."""

import io
import json
import unittest
from unittest.mock import patch


class TestUploadSessionDeclaredSize(unittest.TestCase):
    def setUp(self):
        from app import create_app
        self.app = create_app()
        self.client = self.app.test_client()

    def _create_session(self):
        response = self.client.post("/api/stego/upload-session")
        self.assertEqual(response.status_code, 200)
        return response.get_json()["sessionId"]

    def _valid_metadata(self):
        return {
            "proofId": "a" * 64,
            "tier": "silent",
            "protocol": "test-protocol",
            "videoHash": "b" * 64,
            "sourceHash": "c" * 64,
            "timestamp": "2024-01-01T00:00:00Z",
        }

    def _upload_chunk(self, session_id, chunk_index, data, declared_size=None, content_type="application/octet-stream"):
        headers = {}
        if declared_size is not None:
            headers["X-Declared-Size"] = str(declared_size)
        return self.client.put(
            f"/api/stego/upload-session/{session_id}/chunk/{chunk_index}",
            data={"chunk": (io.BytesIO(data), f"chunk{chunk_index}.bin", content_type)},
            content_type="multipart/form-data",
            headers=headers,
        )

    def test_no_declared_size_works(self):
        """Upload session without declared size should work normally."""
        session_id = self._create_session()

        # Upload first chunk without declared size
        response = self._upload_chunk(session_id, 0, b"chunk0")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["bytes"], 6)

        # Upload second chunk without declared size
        response = self._upload_chunk(session_id, 1, b"chunk1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["bytes"], 6)

    def test_first_chunk_declares_size(self):
        """First chunk can declare total expected size."""
        session_id = self._create_session()

        # First chunk declares 100 bytes total
        response = self._upload_chunk(session_id, 0, b"chunk0", declared_size=100)
        self.assertEqual(response.status_code, 200)

        # Second chunk without declared size should work
        response = self._upload_chunk(session_id, 1, b"chunk1")
        self.assertEqual(response.status_code, 200)

    def test_consistent_declared_size_accepted(self):
        """Same declared size on all chunks should be accepted."""
        session_id = self._create_session()

        response = self._upload_chunk(session_id, 0, b"chunk0", declared_size=100)
        self.assertEqual(response.status_code, 200)

        response = self._upload_chunk(session_id, 1, b"chunk1", declared_size=100)
        self.assertEqual(response.status_code, 200)

    def test_inconsistent_declared_size_rejected(self):
        """Different declared size on subsequent chunk should be rejected."""
        session_id = self._create_session()

        # First chunk declares 100 bytes
        response = self._upload_chunk(session_id, 0, b"chunk0", declared_size=100)
        self.assertEqual(response.status_code, 200)

        # Second chunk declares different size - should be rejected
        response = self._upload_chunk(session_id, 1, b"chunk1", declared_size=200)
        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertEqual(body["error"], "declared size mismatch")
        self.assertEqual(body["expected"], 100)
        self.assertEqual(body["received"], 200)

        # Previously accepted chunk should still exist (preserve on conflict)
        # Verify by trying to commit
        response = self.client.post(
            f"/api/stego/upload-session/{session_id}/commit",
            data={"metadata": json.dumps(self._valid_metadata())},
            content_type="multipart/form-data",
        )
        # Should fail because total uploaded (6) != declared (100)
        self.assertEqual(response.status_code, 400)

    def test_total_exceeds_declared_rejected(self):
        """Upload exceeding declared total size should be rejected."""
        session_id = self._create_session()

        # Declare 10 bytes total
        response = self._upload_chunk(session_id, 0, b"chunk0", declared_size=10)
        self.assertEqual(response.status_code, 200)

        # Second chunk pushes total to 12 bytes (exceeds 10)
        response = self._upload_chunk(session_id, 1, b"chunk1", declared_size=10)
        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertEqual(body["error"], "total uploaded bytes exceeds declared size")
        self.assertEqual(body["declared"], 10)
        self.assertEqual(body["uploaded"], 12)

    def test_commit_validates_total_matches_declared(self):
        """Commit should fail if total uploaded doesn't match declared size."""
        session_id = self._create_session()

        # Declare 100 bytes
        response = self._upload_chunk(session_id, 0, b"chunk0", declared_size=100)
        self.assertEqual(response.status_code, 200)

        # Only uploaded 6 bytes, try to commit
        response = self.client.post(
            f"/api/stego/upload-session/{session_id}/commit",
            data={"metadata": json.dumps(self._valid_metadata())},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertEqual(body["error"], "total uploaded bytes does not match declared size")
        self.assertEqual(body["declared"], 100)
        self.assertEqual(body["uploaded"], 6)

    def test_commit_succeeds_when_total_matches_declared(self):
        """Commit should succeed when total uploaded matches declared size."""
        session_id = self._create_session()

        # Declare 12 bytes (6 + 6)
        response = self._upload_chunk(session_id, 0, b"chunk0", declared_size=12)
        self.assertEqual(response.status_code, 200)

        response = self._upload_chunk(session_id, 1, b"chunk1", declared_size=12)
        self.assertEqual(response.status_code, 200)

        # Commit should work (may fail for other reasons like metadata validation, but not size mismatch)
        with patch("app.embed_metadata") as mock_embed:
            mock_embed.return_value = None
            response = self.client.post(
                f"/api/stego/upload-session/{session_id}/commit",
                data={"metadata": json.dumps(self._valid_metadata())},
                content_type="multipart/form-data",
            )
            # Should not fail with size mismatch error
            body = response.get_json()
            if response.status_code == 400:
                self.assertNotIn("declared size", body.get("error", ""))
                self.assertNotIn("total uploaded", body.get("error", ""))

    def test_negative_declared_size_rejected(self):
        """Negative declared size should be rejected."""
        session_id = self._create_session()

        response = self._upload_chunk(session_id, 0, b"chunk0", declared_size=-1)
        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertEqual(body["error"], "X-Declared-Size must be non-negative")

    def test_non_integer_declared_size_rejected(self):
        """Non-integer declared size should be rejected."""
        session_id = self._create_session()

        response = self.client.put(
            f"/api/stego/upload-session/{session_id}/chunk/0",
            data={"chunk": (io.BytesIO(b"chunk0"), "chunk0.bin", "application/octet-stream")},
            content_type="multipart/form-data",
            headers={"X-Declared-Size": "not-an-integer"},
        )
        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertEqual(body["error"], "X-Declared-Size must be an integer")

    def test_zero_declared_size_with_empty_chunks(self):
        """Zero declared size should work with empty chunks."""
        session_id = self._create_session()

        response = self._upload_chunk(session_id, 0, b"", declared_size=0)
        self.assertEqual(response.status_code, 200)

        response = self.client.post(
            f"/api/stego/upload-session/{session_id}/commit",
            data={"metadata": json.dumps(self._valid_metadata())},
            content_type="multipart/form-data",
        )
        # Should not fail for size mismatch
        body = response.get_json()
        if response.status_code == 400:
            self.assertNotIn("declared size", body.get("error", ""))
            self.assertNotIn("total uploaded", body.get("error", ""))

    def test_declared_size_persists_across_requests(self):
        """Declared size should persist in session metadata file."""
        import tempfile
        from pathlib import Path

        session_id = self._create_session()

        # Upload with declared size
        response = self._upload_chunk(session_id, 0, b"chunk0", declared_size=100)
        self.assertEqual(response.status_code, 200)

        # Check metadata file exists
        session_dir = Path(tempfile.gettempdir()) / f"harpocrates-session-{session_id}"
        metadata_path = session_dir / "session.json"
        self.assertTrue(metadata_path.exists())

        with metadata_path.open("r") as f:
            meta = json.load(f)
        self.assertEqual(meta["declared_size"], 100)
        self.assertEqual(meta["total_uploaded"], 6)


if __name__ == "__main__":
    unittest.main(verbosity=2)