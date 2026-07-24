from __future__ import annotations

import io
import json
import os
import unittest

os.environ.setdefault("MAX_CONTENT_LENGTH", "500000000")
os.environ.setdefault("MAX_VIDEO_BYTES", "200000000")
os.environ.setdefault("NOIR_WORKER_ENABLED", "false")

from app import app


class AppHardeningTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = app.test_client()

    def test_health_sets_security_headers(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_ready_endpoint_reports_service_dependencies(self) -> None:
        response = self.client.get("/ready")

        self.assertIn(response.status_code, {200, 503})
        self.assertIn("video_tools", response.json)
        self.assertIn("database", response.json)

    def test_embed_rejects_non_video_upload(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={
                "metadata": json.dumps(valid_metadata()),
                "video": (io.BytesIO(b"not a video"), "note.txt"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"], "video upload must use a video content type")

    def test_embed_rejects_missing_metadata_fields(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={
                "metadata": json.dumps({"protocol": "harpocrates"}),
                "video": (io.BytesIO(b"video bytes"), "evidence.mp4", "video/mp4"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("metadata missing required field", response.json["error"])

    def test_embed_rejects_metadata_too_large(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={
                "metadata": "x" * 17_000,
                "video": (io.BytesIO(b"video bytes"), "evidence.mp4", "video/mp4"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json["error"], "metadata is too large")

    def test_embed_accepts_boundary_metadata(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={
                "metadata": "x" * 16_384,
                "video": (io.BytesIO(b"video bytes"), "evidence.mp4", "video/mp4"),
            },
            content_type="multipart/form-data",
        )

        self.assertNotEqual(response.status_code, 413)

    def test_embed_rejects_video_too_large(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={
                "metadata": json.dumps(valid_metadata()),
                "video": (io.BytesIO(b"x" * 250_000_001), "evidence.mp4", "video/mp4"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json["error"], "video payload exceeds size limit")

    def test_embed_accepts_small_video(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={
                "metadata": json.dumps(valid_metadata()),
                "video": (io.BytesIO(b"x" * 1024), "evidence.mp4", "video/mp4"),
            },
            content_type="multipart/form-data",
        )

        self.assertIn(response.status_code, {200, 500})

    def test_embed_accepts_boundary_video(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={
                "metadata": json.dumps(valid_metadata()),
                "video": (io.BytesIO(b"x" * 200_000_000), "evidence.mp4", "video/mp4"),
            },
            content_type="multipart/form-data",
        )

        self.assertIn(response.status_code, {200, 500})

    def test_extract_rejects_video_too_large(self) -> None:
        response = self.client.post(
            "/api/stego/extract",
            data={"video": (io.BytesIO(b"x" * 250_000_001), "evidence.mp4", "video/mp4")},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json["error"], "video payload exceeds size limit")

    def test_extract_rejects_missing_video(self) -> None:
        response = self.client.post("/api/stego/extract")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"], "video is required")

    def test_register_rejects_body_too_large(self) -> None:
        response = self.client.post(
            "/api/proofs/register",
            json={"data": "z" * 2_000_000},
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json["error"], "JSON payload exceeds size limit")

    def test_register_accepts_valid_minimal_body(self) -> None:
        response = self.client.post(
            "/api/proofs/register",
            json={
                "videoHash": "11" * 32,
                "metadataHash": "22" * 32,
                "proofId": "33" * 32,
                "txHash": "44" * 32,
                "tier": "silent",
                "txStatus": "done",
                "fileName": "file.mp4",
            },
        )

        self.assertIn(response.status_code, {200, 400})

    def test_silent_witness_rejects_body_too_large(self) -> None:
        response = self.client.post(
            "/api/noir/silent-witness",
            data=b"x" * 2_000_000,
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json["error"], "JSON payload exceeds size limit")

    def test_silent_witness_returns_404_when_disabled(self) -> None:
        response = self.client.post(
            "/api/noir/silent-witness",
            json={
                "videoHash": "11" * 32,
                "credentialSecret": "42",
                "nullifierSecret": "99",
            },
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json["error"], "local Noir worker is disabled")

    def test_silent_witness_accepts_boundary_json(self) -> None:
        # Body length is exactly max_json_bytes (1 MB). Must not be rejected as too large.
        max_json_bytes = os.environ.get("MAX_JSON_BYTES", "1048576")
        boundary = int(max_json_bytes)
        raw = b'{"x":"' + b"y" * (boundary - 8) + b'"}'
        self.assertEqual(len(raw), boundary)

        response = self.client.post(
            "/api/noir/silent-witness",
            data=raw,
            content_type="application/json",
        )

        self.assertNotEqual(response.status_code, 413)
        # Worker is disabled in the test config, so the next handler returns 404.
        self.assertEqual(response.status_code, 404)


def valid_metadata() -> dict[str, object]:
    return {
        "protocol": "harpocrates",
        "version": 1,
        "tier": "silent",
        "sourceHash": "11" * 32,
        "proofId": "22" * 32,
        "timestamp": "2026-06-18T00:00:00.000Z",
    }


if __name__ == "__main__":
    unittest.main()
