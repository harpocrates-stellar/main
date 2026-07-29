from __future__ import annotations

import io
import json
import unittest

from app import app


class AppHardeningTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = app.test_client()

    def tearDown(self) -> None:
        # Clean up any test routes registered on the shared app instance.
        for rule in list(self.client.application.url_map.iter_rules()):
            if rule.rule.startswith("/__test_"):
                self.client.application.url_map._rules.remove(rule)

    # ------------------------------------------------------------------
    # Health / Ready
    # ------------------------------------------------------------------

    def test_health_sets_security_headers(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_health_returns_request_id(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertIn("X-Request-Id", response.headers)
        self.assertTrue(response.headers["X-Request-Id"])

    def test_health_returns_standard_envelope(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["ok"], True)
        self.assertIn("request_id", response.json)
        self.assertEqual(response.json["service"], "harpocrates-stego")

    def test_ready_endpoint_reports_service_dependencies(self) -> None:
        response = self.client.get("/ready")

        self.assertIn(response.status_code, {200, 503})
        self.assertIn("video_tools", response.json)
        self.assertIn("database", response.json)
        self.assertIn("request_id", response.json)

    # ------------------------------------------------------------------
    # Error envelope shape
    # ------------------------------------------------------------------

    def test_error_response_includes_code_message_and_request_id(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["ok"], False)
        self.assertIn("error", response.json)
        self.assertIn("code", response.json["error"])
        self.assertIn("message", response.json["error"])
        self.assertIn("request_id", response.json["error"])
        self.assertEqual(response.json["error"]["code"], "VALIDATION_ERROR")
        self.assertEqual(
            response.json["error"]["message"], "video and metadata are required"
        )

    def test_error_response_request_id_header_matches_body(self) -> None:
        response = self.client.post(
            "/api/stego/embed",
            data={},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        header_id = response.headers.get("X-Request-Id")
        body_id = response.json["error"]["request_id"]
        self.assertEqual(header_id, body_id)

    def test_forwarded_x_request_id_is_preserved(self) -> None:
        response = self.client.get(
            "/health",
            headers={"X-Request-Id": "caller-supplied-uuid"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Request-Id"], "caller-supplied-uuid")
        self.assertEqual(response.json["request_id"], "caller-supplied-uuid")

    # ------------------------------------------------------------------
    # Embed validation errors
    # ------------------------------------------------------------------

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
        self.assertEqual(response.json["ok"], False)
        self.assertEqual(response.json["error"]["code"], "VALIDATION_ERROR")
        self.assertEqual(
            response.json["error"]["message"],
            "video upload must use a video content type",
        )

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
        self.assertEqual(response.json["ok"], False)
        self.assertEqual(response.json["error"]["code"], "VALIDATION_ERROR")
        self.assertIn(
            "metadata missing required field",
            response.json["error"]["message"],
        )

    # ------------------------------------------------------------------
    # Success envelope shape
    # ------------------------------------------------------------------

    def test_proofs_endpoint_returns_standard_envelope(self) -> None:
        response = self.client.get("/api/proofs")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["ok"], True)
        self.assertIn("request_id", response.json)
        self.assertIn("events", response.json)

    def test_proofs_by_video_rejects_invalid_hash_with_envelope(self) -> None:
        response = self.client.get("/api/proofs/by-video/not-hex")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["ok"], False)
        self.assertEqual(response.json["error"]["code"], "VALIDATION_ERROR")
        self.assertIn("request_id", response.json["error"])

    # ------------------------------------------------------------------
    # Internal errors do not leak details
    # ------------------------------------------------------------------

    def test_internal_error_does_not_leak_stack_trace(self) -> None:
        """The generic RuntimeError handler must never expose raw exception text."""
        from unittest.mock import patch

        def _raise_runtime():
            raise RuntimeError("secret credentials should not leak")

        with patch.dict(
            self.client.application.view_functions,
            {"health": _raise_runtime},
        ):
            response = self.client.get("/health")

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json["ok"], False)
        self.assertEqual(response.json["error"]["code"], "INTERNAL_ERROR")
        self.assertEqual(response.json["error"]["message"], "internal server error")
        self.assertNotIn("secret", response.json["error"]["message"])
        self.assertNotIn("credentials", response.json["error"]["message"])

    # ------------------------------------------------------------------
    # Payload too large
    # ------------------------------------------------------------------

    def test_request_too_large_returns_payload_too_large_code(self) -> None:
        """Verify the 413 envelope carries the PAYLOAD_TOO_LARGE error code."""
        original_max = self.client.application.config.get("MAX_CONTENT_LENGTH")
        try:
            self.client.application.config["MAX_CONTENT_LENGTH"] = 16
            response = self.client.post(
                "/api/proofs/register",
                data="x" * 128,
                content_type="application/json",
            )

            self.assertEqual(response.status_code, 413)
            self.assertEqual(response.json["ok"], False)
            self.assertEqual(response.json["error"]["code"], "PAYLOAD_TOO_LARGE")
            self.assertIn("request_id", response.json["error"])
        finally:
            self.client.application.config["MAX_CONTENT_LENGTH"] = original_max


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
