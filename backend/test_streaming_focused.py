"""Focused coverage for bounded-chunk stream upload hashing."""

from __future__ import annotations

import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.exceptions import RequestEntityTooLarge

from streaming_upload import (
    DEFAULT_CHUNK_BYTES,
    MAX_CHUNK_BYTES,
    MIN_CHUNK_BYTES,
    StreamingFileStorage,
    clamp_chunk_bytes,
    hash_paths_concat,
    hash_stream_to_path,
    sha256_path_bounded,
)


class TestChunkBounds(unittest.TestCase):
    def test_clamp_defaults_and_bounds(self):
        self.assertEqual(clamp_chunk_bytes(None), DEFAULT_CHUNK_BYTES)
        self.assertEqual(clamp_chunk_bytes(100), 100)
        self.assertEqual(clamp_chunk_bytes(100, enforce_min=True), MIN_CHUNK_BYTES)
        self.assertEqual(clamp_chunk_bytes(10_000_000), MAX_CHUNK_BYTES)
        self.assertEqual(clamp_chunk_bytes(32_768), 32_768)


class TestHashStreamToPath(unittest.TestCase):
    def test_positive_hash_matches_sha256(self):
        payload = b"The quick brown fox jumps over the lazy dog"
        expected = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            digest, written = hash_stream_to_path(
                io.BytesIO(payload), dest, chunk_size=16, max_size=1024
            )
            self.assertEqual(digest, expected)
            self.assertEqual(written, len(payload))
            self.assertEqual(dest.read_bytes(), payload)

    def test_negative_oversized_aborts_without_partial_dest(self):
        payload = b"X" * 10_000
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            with self.assertRaises(RequestEntityTooLarge):
                hash_stream_to_path(
                    io.BytesIO(payload), dest, chunk_size=1024, max_size=4096
                )
            self.assertFalse(dest.exists())

    def test_boundary_exact_max_size_accepted(self):
        payload = b"Y" * 4096
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            digest, written = hash_stream_to_path(
                io.BytesIO(payload), dest, chunk_size=1024, max_size=4096
            )
            self.assertEqual(written, 4096)
            self.assertEqual(digest, hashlib.sha256(payload).hexdigest())


class TestStreamingFileStorage(unittest.TestCase):
    def test_flask_endpoint_streams_without_buffering(self):
        large_video_data = b"MOCK_VIDEO_DATA" * 350_000  # ~5MB
        max_memory_used = [0]

        class MemoryTrackingStream:
            def __init__(self, data):
                self.data = data
                self.position = 0

            def read(self, size=-1):
                if size == -1 or size > len(self.data) - self.position:
                    size = len(self.data) - self.position
                max_memory_used[0] = max(max_memory_used[0], size if size > 0 else 0)
                if size <= 0:
                    return b""
                chunk = self.data[self.position : self.position + size]
                self.position += size
                return chunk

        mock_stream = MemoryTrackingStream(large_video_data)
        with tempfile.TemporaryDirectory() as tmp_dir:
            streaming_file = StreamingFileStorage(
                stream=mock_stream,
                filename="large_video.mp4",
                content_type="video/mp4",
                max_size=10_000_000,
                chunk_size=8192,
            )
            output_path = Path(tmp_dir) / "output.mp4"
            streaming_file.save(str(output_path))

            self.assertTrue(output_path.exists())
            self.assertEqual(output_path.read_bytes(), large_video_data)
            expected_hash = hashlib.sha256(large_video_data).hexdigest()
            self.assertEqual(streaming_file.computed_hash, expected_hash)
            self.assertLessEqual(max_memory_used[0], 8192)
            self.assertGreater(len(large_video_data), 1_000_000)

    def test_size_limit_enforcement(self):
        large_data = b"X" * 1_000_000
        streaming_file = StreamingFileStorage(
            stream=io.BytesIO(large_data),
            filename="oversized.mp4",
            content_type="video/mp4",
            max_size=500_000,
            chunk_size=8192,
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "oversized.mp4"
            with self.assertRaises(RequestEntityTooLarge) as cm:
                streaming_file.save(str(output_path))
            self.assertIn("exceeds size limit", str(cm.exception))
            self.assertFalse(output_path.exists())

    def test_hash_computation_during_streaming(self):
        test_data = b"The quick brown fox jumps over the lazy dog"
        expected_hash = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        streaming_file = StreamingFileStorage(
            stream=io.BytesIO(test_data),
            filename="test.mp4",
            content_type="video/mp4",
            max_size=1000,
            chunk_size=8,
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            destination = os.path.join(tmp_dir, "streamed.mp4")
            streaming_file.save(destination)
            self.assertEqual(streaming_file.computed_hash, expected_hash)
            self.assertEqual(streaming_file.bytes_written, len(test_data))


class TestConcatAndBoundedHash(unittest.TestCase):
    def test_hash_paths_concat_matches_joined_bytes(self):
        parts = [b"aaa", b"bbbb", b"cccccc"]
        joined = b"".join(parts)
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for i, part in enumerate(parts):
                path = Path(tmp) / f"chunk-{i}"
                path.write_bytes(part)
                paths.append(path)
            dest = Path(tmp) / "combined"
            digest, written = hash_paths_concat(paths, dest, chunk_size=2, max_size=100)
            self.assertEqual(written, len(joined))
            self.assertEqual(dest.read_bytes(), joined)
            self.assertEqual(digest, hashlib.sha256(joined).hexdigest())
            self.assertEqual(sha256_path_bounded(dest, chunk_size=3), digest)

    def test_regression_empty_stream(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "empty.bin"
            digest, written = hash_stream_to_path(io.BytesIO(b""), dest, chunk_size=4096)
            self.assertEqual(written, 0)
            self.assertEqual(digest, hashlib.sha256(b"").hexdigest())
            self.assertTrue(dest.exists())
            self.assertEqual(dest.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
