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


REAL_TEMPORARY_DIRECTORY = tempfile.TemporaryDirectory


class AppHardeningTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = app_module.app.test_client()

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
