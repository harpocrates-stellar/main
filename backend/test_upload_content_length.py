"""Focused coverage for the pre-buffering upload Content-Length gate (issue #261).

A ``multipart/form-data`` upload that declares a ``Content-Length`` above the
deployment's per-file upload budget must be rejected from the request headers
alone — before Werkzeug parses the body into memory/temp files and before the
bounded streaming wrapper starts spooling it to disk.

Each app-level test builds a fresh Flask app with an intentionally tiny
``MAX_VIDEO_BYTES`` so the declared boundary can be exercised with synthetic
~1 MiB bodies (all zeros; no real media, secrets, or credentials are used).
"""
from __future__ import annotations

import io
import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

# Benign defaults so ``create_app`` needs no live database or video toolchain,
# matching the existing backend test harness style.
os.environ.setdefault("DATABASE_URL", "")
os.environ.setdefault("NOIR_WORKER_ENABLED", "false")
os.environ.setdefault("TRUSTED_PROXIES", "")

_EMBED_METADATA = {
    "protocol": "harpocrates",
    "version": 1,
    "tier": "silent",
    "sourceHash": "11" * 32,
    "proofId": "22" * 32,
    "timestamp": "2026-06-18T00:00:00.000Z",
}

# The bounded streaming wrapper only engages above this many declared bytes, so
# the padded bodies below also exercise the streaming path.
_SYNTHETIC_PAD_STEP = 4096


def _make_fresh_app():
    """Return ``(app_module, app, client)`` from a freshly imported module."""
    import importlib
    import app as app_module

    importlib.reload(app_module)
    flask_app = app_module.create_app()
    flask_app.config["TESTING"] = True
    return app_module, flask_app, flask_app.test_client()


def _declared_limit(app_module) -> int:
    return app_module.declared_upload_limit_bytes(app_module.load_config())


def _embed_form(pad_bytes: int) -> dict:
    """Multipart form with a tiny video plus an optional padding form field."""
    form = {
        "metadata": json.dumps(_EMBED_METADATA),
        "video": (io.BytesIO(b"\x00" * 16), "test.mp4", "video/mp4"),
    }
    if pad_bytes > 0:
        # Padding the framing (not the video part) raises the declared
        # Content-Length while keeping the payload itself trivially small.
        form["pad"] = "p" * pad_bytes
    return form


class DeclaredUploadLimitTest(unittest.TestCase):
    """Pure boundary tests for the declared-body budget helper."""

    def setUp(self):
        import app as app_module

        self.app_module = app_module

    def test_defaults_to_video_budget_plus_multipart_framing(self):
        config = SimpleNamespace(max_video_bytes=4096, max_content_length=10_000_000)
        self.assertEqual(
            self.app_module.declared_upload_limit_bytes(config),
            4096 + self.app_module.UPLOAD_MULTIPART_OVERHEAD_BYTES,
        )

    def test_upload_max_bytes_overrides_the_video_budget(self):
        config = SimpleNamespace(
            upload_max_bytes=2048,
            max_video_bytes=4096,
            max_content_length=10_000_000,
        )
        self.assertEqual(
            self.app_module.declared_upload_limit_bytes(config),
            2048 + self.app_module.UPLOAD_MULTIPART_OVERHEAD_BYTES,
        )

    def test_global_content_cap_wins_when_it_is_lower(self):
        config = SimpleNamespace(max_video_bytes=4096, max_content_length=5000)
        self.assertEqual(self.app_module.declared_upload_limit_bytes(config), 5000)

    def test_zero_or_missing_global_cap_is_ignored(self):
        config = SimpleNamespace(max_video_bytes=4096, max_content_length=0)
        self.assertEqual(
            self.app_module.declared_upload_limit_bytes(config),
            4096 + self.app_module.UPLOAD_MULTIPART_OVERHEAD_BYTES,
        )


class UploadContentLengthGateTest(unittest.TestCase):
    """End-to-end gate behaviour on the real Flask app."""

    def setUp(self):
        self._previous_max_video = os.environ.get("MAX_VIDEO_BYTES")
        # A 1 KiB video budget makes the ~1 MiB declared boundary reachable
        # with synthetic bodies instead of 250 MiB of test data.
        os.environ["MAX_VIDEO_BYTES"] = "1024"
        self.app_module, self.app, self.client = _make_fresh_app()
        self.limit = _declared_limit(self.app_module)

    def tearDown(self):
        if self._previous_max_video is None:
            os.environ.pop("MAX_VIDEO_BYTES", None)
        else:
            os.environ["MAX_VIDEO_BYTES"] = self._previous_max_video

    def _assert_payload_too_large(self, response):
        self.assertEqual(response.status_code, 413)
        body = response.get_json()
        self.assertIsInstance(body, dict)
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"]["code"], "PAYLOAD_TOO_LARGE")
        self.assertIn("request_id", body["error"])

    def test_oversized_embed_rejected_before_body_is_parsed(self):
        with patch.object(
            self.app_module, "create_streaming_file_storage"
        ) as streaming_factory:
            response = self.client.post(
                "/api/stego/embed",
                data=_embed_form(self.limit + _SYNTHETIC_PAD_STEP),
                content_type="multipart/form-data",
            )
        self._assert_payload_too_large(response)
        # The view (which would parse the body and wrap the video part) never
        # ran, so no part was buffered or streamed.
        streaming_factory.assert_not_called()

    def test_body_under_the_declared_limit_is_not_gated(self):
        response = self.client.post(
            "/api/stego/embed",
            data=_embed_form(self.limit - 2 * _SYNTHETIC_PAD_STEP),
            content_type="multipart/form-data",
        )
        # It reaches the upload view; whether it later succeeds is irrelevant,
        # but the body-size gate must not be the thing that rejects it.
        self.assertNotEqual(response.status_code, 413)

    def test_oversized_chunk_rejected_before_body_is_parsed(self):
        session = self.client.post("/api/stego/upload-session")
        self.assertEqual(session.status_code, 200)
        session_id = session.get_json()["sessionId"]

        with patch.object(
            self.app_module, "create_streaming_file_storage"
        ) as streaming_factory:
            response = self.client.put(
                "/api/stego/upload-session/%s/chunk/0" % session_id,
                data={
                    "chunk": (
                        io.BytesIO(b"\x00" * 16),
                        "chunk.bin",
                        "application/octet-stream",
                    ),
                    "pad": "p" * (self.limit + _SYNTHETIC_PAD_STEP),
                },
                content_type="multipart/form-data",
            )
        self._assert_payload_too_large(response)
        streaming_factory.assert_not_called()

    def test_oversized_commit_rejected_before_body_is_parsed(self):
        session = self.client.post("/api/stego/upload-session")
        self.assertEqual(session.status_code, 200)
        session_id = session.get_json()["sessionId"]

        response = self.client.post(
            "/api/stego/upload-session/%s/commit" % session_id,
            data={
                "metadata": json.dumps(_EMBED_METADATA),
                "pad": "p" * (self.limit + _SYNTHETIC_PAD_STEP),
            },
            content_type="multipart/form-data",
        )
        self._assert_payload_too_large(response)

    def test_non_multipart_body_is_not_gated(self):
        response = self.client.post(
            "/api/stego/embed",
            data=json.dumps(_EMBED_METADATA),
            content_type="application/json",
        )
        # JSON payloads have their own bound; the upload gate must not fire.
        self.assertNotEqual(response.status_code, 413)

    def test_multipart_route_outside_the_upload_surface_is_not_gated(self):
        response = self.client.post(
            "/api/proofs/register",
            data={"pad": "p" * (self.limit + _SYNTHETIC_PAD_STEP)},
            content_type="multipart/form-data",
        )
        # /api/proofs/register is a JSON route; the upload gate is scoped to
        # the /api/stego/ upload surface and must not reject it.
        self.assertNotEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main(verbosity=2)
