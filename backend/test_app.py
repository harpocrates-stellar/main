from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import app as app_module
import stego
from metrics import collector as metrics_collector


REAL_TEMPORARY_DIRECTORY = tempfile.TemporaryDirectory


class AppHardeningTest(unittest.TestCase):
    def setUp(self) -> None:
        metrics_collector.reset()
        self.client = app_module.app.test_client()

    def test_health_sets_security_headers(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Harpocrates-Release"], "harpocrates-1.0.0")
        self.assertEqual(response.headers["X-Harpocrates-Network"], "testnet")


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

    def test_embed_success_removes_temp_directory(self) -> None:
        def fake_embed(source_path: Path, output_path: Path, _metadata: dict[str, object]) -> None:
            if not source_path.exists():
                raise RuntimeError("source upload was not saved")
            output_path.write_bytes(b"embedded video bytes")

        response = self.post_with_tracked_tempdirs(
            "/api/stego/embed",
            {
                "metadata": json.dumps(valid_metadata()),
                "video": video_upload(),
            },
            patch.object(app_module, "embed_metadata", side_effect=fake_embed),
            patch.object(app_module, "insert_proof_event", return_value={"id": 1}),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"embedded video bytes")

    def test_embed_ffmpeg_failure_removes_temp_directory(self) -> None:
        def require_video_tool(binary: str) -> str:
            if binary == "ffmpeg":
                raise RuntimeError("ffmpeg is required for steganography processing")
            return binary

        response = self.post_with_tracked_tempdirs(
            "/api/stego/embed",
            {
                "metadata": json.dumps(valid_metadata()),
                "video": video_upload(),
            },
            patch.object(stego, "_require", side_effect=require_video_tool),
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json["error"], "ffmpeg is required for steganography processing")

    def test_embed_ffprobe_failure_removes_temp_directory(self) -> None:
        def require_video_tool(binary: str) -> str:
            if binary == "ffprobe":
                raise RuntimeError("ffprobe is required for steganography processing")
            return binary

        response = self.post_with_tracked_tempdirs(
            "/api/stego/embed",
            {
                "metadata": json.dumps(valid_metadata()),
                "video": video_upload(),
            },
            patch.object(stego, "_require", side_effect=require_video_tool),
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json["error"], "ffprobe is required for steganography processing")

    def test_extract_failure_removes_temp_directory(self) -> None:
        response = self.post_with_tracked_tempdirs(
            "/api/stego/extract",
            {"video": video_upload()},
            patch.object(app_module, "extract_metadata", side_effect=RuntimeError("metadata extraction failed")),
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json["error"], "metadata extraction failed")

    def test_embed_database_failure_removes_temp_directory(self) -> None:
        def fake_embed(_source_path: Path, output_path: Path, _metadata: dict[str, object]) -> None:
            output_path.write_bytes(b"embedded video bytes")

        response = self.post_with_tracked_tempdirs(
            "/api/stego/embed",
            {
                "metadata": json.dumps(valid_metadata()),
                "video": video_upload(),
            },
            patch.object(app_module, "embed_metadata", side_effect=fake_embed),
            patch.object(app_module, "insert_proof_event", side_effect=RuntimeError("database write failed")),
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json["error"], "database write failed")

    def test_extract_database_failure_removes_temp_directory(self) -> None:
        response = self.post_with_tracked_tempdirs(
            "/api/stego/extract",
            {"video": video_upload()},
            patch.object(app_module, "extract_metadata", return_value=valid_metadata()),
            patch.object(app_module, "insert_proof_event", side_effect=RuntimeError("database write failed")),
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json["error"], "database write failed")

    def post_with_tracked_tempdirs(self, path: str, data: dict[str, object], *patches):
        observed: list[Path] = []
        with REAL_TEMPORARY_DIRECTORY(prefix="harpocrates-route-test-") as parent:
            temp_root = Path(parent)
            tempdir_factory = tracking_temporary_directory_factory(temp_root, observed)
            with ExitStack() as stack:
                stack.enter_context(patch.object(app_module.tempfile, "TemporaryDirectory", tempdir_factory))
                for patcher in patches:
                    stack.enter_context(patcher)
                response = self.client.post(path, data=data, content_type="multipart/form-data")

            self.assertGreaterEqual(len(observed), 1)
            for temp_path in observed:
                self.assertFalse(temp_path.exists(), f"{temp_path} was not removed")
            self.assertEqual(list(temp_root.iterdir()), [])
            return response

    def test_metrics_exposes_request_counts_status_and_latency(self) -> None:
        self.client.get("/health")
        response = self.client.get("/metrics")

        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response.content_type)
        metrics_text = response.data.decode("utf-8")

        self.assertIn("# HELP harpocrates_requests_total", metrics_text)
        self.assertIn('# TYPE harpocrates_requests_total counter', metrics_text)
        self.assertIn('harpocrates_requests_total{endpoint="/health",method="GET",status="200"} 1', metrics_text)

        self.assertIn("# HELP harpocrates_request_duration_seconds", metrics_text)
        self.assertIn('# TYPE harpocrates_request_duration_seconds histogram', metrics_text)
        self.assertIn('harpocrates_request_duration_seconds_count{endpoint="/health",method="GET",status="200"} 1', metrics_text)

    def test_metrics_privacy_excludes_sensitive_identifiers_and_parameterizes_routes(self) -> None:
        video_hash = "a" * 64
        self.client.get(f"/api/proofs/by-video/{video_hash}")
        response = self.client.get("/metrics")

        self.assertEqual(response.status_code, 200)
        metrics_text = response.data.decode("utf-8")

        # Must NOT leak individual video hash parameter
        self.assertNotIn(video_hash, metrics_text)
        # Must expose parameterized route rule
        self.assertIn('endpoint="/api/proofs/by-video/<video_hash>"', metrics_text)

    def test_metrics_records_bounded_upload_size_histogram(self) -> None:
        self.client.post(
            "/api/stego/embed",
            data={
                "metadata": json.dumps(valid_metadata()),
                "video": video_upload(),
            },
            content_type="multipart/form-data",
        )
        response = self.client.get("/metrics")

        self.assertEqual(response.status_code, 200)
        metrics_text = response.data.decode("utf-8")

        self.assertIn("# HELP harpocrates_upload_bytes_total", metrics_text)
        self.assertIn('# TYPE harpocrates_upload_bytes_total histogram', metrics_text)
        self.assertIn('harpocrates_upload_bytes_total_bucket{endpoint="/api/stego/embed",method="POST",le="', metrics_text)

    def test_metrics_protection_token_authentication(self) -> None:
        with patch.dict(app_module.os.environ, {"METRICS_TOKEN": "secret-scraping-token"}):
            token_app = app_module.create_app()
            token_client = token_app.test_client()

            token_client.get("/health")

            # Missing token -> 401
            res_unauth = token_client.get("/metrics")
            self.assertEqual(res_unauth.status_code, 401)
            self.assertEqual(res_unauth.json["error"], "unauthorized metrics access")

            # Invalid Bearer token -> 401
            res_invalid = token_client.get("/metrics", headers={"Authorization": "Bearer wrong-token"})
            self.assertEqual(res_invalid.status_code, 401)

            # Valid Bearer token -> 200
            res_bearer = token_client.get("/metrics", headers={"Authorization": "Bearer secret-scraping-token"})
            self.assertEqual(res_bearer.status_code, 200)
            self.assertIn("harpocrates_requests_total", res_bearer.data.decode("utf-8"))

            # Valid X-Metrics-Token -> 200
            res_header = token_client.get("/metrics", headers={"X-Metrics-Token": "secret-scraping-token"})
            self.assertEqual(res_header.status_code, 200)

    def test_metrics_isolation_disabled_endpoint(self) -> None:
        with patch.dict(app_module.os.environ, {"METRICS_ENABLED": "false"}):
            disabled_app = app_module.create_app()
            disabled_client = disabled_app.test_client()

            res = disabled_client.get("/metrics")
            self.assertEqual(res.status_code, 404)
            self.assertEqual(res.json["error"], "metrics service disabled")



def tracking_temporary_directory_factory(temp_root: Path, observed: list[Path]):
    class TrackingTemporaryDirectory:
        def __init__(self, *args, **kwargs) -> None:
            kwargs["dir"] = temp_root
            self._manager = REAL_TEMPORARY_DIRECTORY(*args, **kwargs)
            observed.append(Path(self._manager.name))

        def __enter__(self):
            return self._manager.__enter__()

        def __exit__(self, exc_type, exc, traceback):
            return self._manager.__exit__(exc_type, exc, traceback)

    return TrackingTemporaryDirectory


def valid_metadata() -> dict[str, object]:
    return {
        "protocol": "harpocrates",
        "version": 1,
        "tier": "silent",
        "sourceHash": "11" * 32,
        "proofId": "22" * 32,
        "timestamp": "2026-06-18T00:00:00.000Z",
    }


def video_upload() -> tuple[io.BytesIO, str, str]:
    return io.BytesIO(b"video bytes"), "evidence.mp4", "video/mp4"


if __name__ == "__main__":
    unittest.main()
