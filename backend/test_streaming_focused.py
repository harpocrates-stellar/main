"""Focused coverage for bounded-chunk stream upload hashing."""

from __future__ import annotations

import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.exceptions import ClientDisconnected, RequestEntityTooLarge

from quarantine import isolate_upload

from streaming_upload import (
    DEFAULT_CHUNK_BYTES,
    MAX_CHUNK_BYTES,
    MIN_CHUNK_BYTES,
    PrematureUploadTerminationError,
    ResumableUploadSessionStore,
    StreamingFileStorage,
    UPLOAD_TERMINATED_PREMATURELY,
    clamp_chunk_bytes,
    hash_paths_concat,
    hash_stream_to_path,
    resolve_max_bytes,
    sha256_path_bounded,
)


class TestChunkBounds(unittest.TestCase):
    def test_clamp_defaults_and_bounds(self):
        self.assertEqual(clamp_chunk_bytes(None), DEFAULT_CHUNK_BYTES)
        self.assertEqual(clamp_chunk_bytes(100), 100)
        self.assertEqual(clamp_chunk_bytes(100, enforce_min=True), MIN_CHUNK_BYTES)
        self.assertEqual(clamp_chunk_bytes(10_000_000), MAX_CHUNK_BYTES)
        self.assertEqual(clamp_chunk_bytes(32_768), 32_768)


class TestResolveMaxBytes(unittest.TestCase):
    def test_explicit_positive_resolved(self):
        self.assertEqual(resolve_max_bytes(1024), 1024)

    def test_explicit_zero_byte_allowance_resolved(self):
        self.assertEqual(resolve_max_bytes(0), 0)

    def test_absent_limit_returns_none(self):
        with patch("streaming_upload._upload_config", return_value=None):
            self.assertIsNone(resolve_max_bytes())

    def test_config_zero_byte_allowance_does_not_fall_back(self):
        from types import SimpleNamespace

        config = SimpleNamespace(upload_max_bytes=0, max_video_bytes=4096)
        with patch("streaming_upload._upload_config", return_value=config):
            self.assertEqual(resolve_max_bytes(), 0)

    def test_config_absent_upload_max_falls_back_to_video_bytes(self):
        from types import SimpleNamespace

        config = SimpleNamespace(upload_max_bytes=None, max_video_bytes=4096)
        with patch("streaming_upload._upload_config", return_value=config):
            self.assertEqual(resolve_max_bytes(), 4096)


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

    def test_zero_byte_allowance_empty_stream_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            digest, written = hash_stream_to_path(
                io.BytesIO(b""), dest, chunk_size=1024, max_size=0
            )
            self.assertEqual(written, 0)
            self.assertEqual(digest, hashlib.sha256(b"").hexdigest())
            self.assertTrue(dest.exists())
            self.assertEqual(dest.stat().st_size, 0)

    def test_zero_byte_allowance_non_empty_stream_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            with self.assertRaises(RequestEntityTooLarge):
                hash_stream_to_path(
                    io.BytesIO(b"data"), dest, chunk_size=1024, max_size=0
                )
            self.assertFalse(dest.exists())

    def test_absent_limit_allows_stream(self):
        payload = b"Z" * 8192
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.bin"
            digest, written = hash_stream_to_path(
                io.BytesIO(payload), dest, chunk_size=1024, max_size=None
            )
            self.assertEqual(written, 8192)
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

    def test_zero_byte_allowance_accepts_empty(self):
        streaming_file = StreamingFileStorage(
            stream=io.BytesIO(b""),
            filename="empty.bin",
            max_size=0,
            chunk_size=1024,
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            dest = Path(tmp_dir) / "empty.bin"
            streaming_file.save(str(dest))
            self.assertEqual(streaming_file.bytes_written, 0)
            self.assertEqual(streaming_file.computed_hash, hashlib.sha256(b"").hexdigest())

    def test_zero_byte_allowance_rejects_non_empty(self):
        streaming_file = StreamingFileStorage(
            stream=io.BytesIO(b"payload"),
            filename="rejected.bin",
            max_size=0,
            chunk_size=1024,
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            dest = Path(tmp_dir) / "rejected.bin"
            with self.assertRaises(RequestEntityTooLarge):
                streaming_file.save(str(dest))
            self.assertFalse(dest.exists())

    def test_absent_limit_accepts_payload(self):
        streaming_file = StreamingFileStorage(
            stream=io.BytesIO(b"unlimited data"),
            filename="unlimited.bin",
            max_size=None,
            chunk_size=1024,
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            dest = Path(tmp_dir) / "unlimited.bin"
            streaming_file.save(str(dest))
            self.assertEqual(streaming_file.bytes_written, len(b"unlimited data"))


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

    def test_zero_byte_allowance_concat_empty_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            p1 = Path(tmp) / "empty1.bin"
            p2 = Path(tmp) / "empty2.bin"
            p1.write_bytes(b"")
            p2.write_bytes(b"")
            dest = Path(tmp) / "out.bin"
            digest, written = hash_paths_concat([p1, p2], dest, max_size=0)
            self.assertEqual(written, 0)
            self.assertEqual(digest, hashlib.sha256(b"").hexdigest())

    def test_zero_byte_allowance_concat_non_empty_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p1 = Path(tmp) / "chunk.bin"
            p1.write_bytes(b"data")
            dest = Path(tmp) / "out.bin"
            with self.assertRaises(RequestEntityTooLarge):
                hash_paths_concat([p1], dest, max_size=0)
            self.assertFalse(dest.exists())

    def test_absent_limit_concat_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            p1 = Path(tmp) / "chunk1.bin"
            p2 = Path(tmp) / "chunk2.bin"
            p1.write_bytes(b"hello ")
            p2.write_bytes(b"world")
            dest = Path(tmp) / "out.bin"
            digest, written = hash_paths_concat([p1, p2], dest, max_size=None)
            self.assertEqual(written, 11)
            self.assertEqual(dest.read_bytes(), b"hello world")
            self.assertEqual(digest, hashlib.sha256(b"hello world").hexdigest())


class _DisconnectingStream:
    """Synthetic stream that yields optional chunks before simulating a disconnect."""

    def __init__(self, chunks: list[bytes], exc: Exception):
        self._chunks = list(chunks)
        self._exc = exc

    def read(self, _size: int = -1) -> bytes:
        if self._chunks:
            return self._chunks.pop(0)
        raise self._exc


class TestPrematureUploadTermination(unittest.TestCase):
    def test_valid_empty_stream_succeeds_without_premature_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest_none = Path(tmp) / "empty-none.bin"
            digest, written = hash_stream_to_path(
                io.BytesIO(b""), dest_none, chunk_size=1024, expected_size=None
            )
            self.assertEqual(written, 0)
            self.assertEqual(digest, hashlib.sha256(b"").hexdigest())

            dest_zero = Path(tmp) / "empty-zero.bin"
            digest_z, written_z = hash_stream_to_path(
                io.BytesIO(b""), dest_zero, chunk_size=1024, expected_size=0
            )
            self.assertEqual(written_z, 0)
            self.assertEqual(digest_z, hashlib.sha256(b"").hexdigest())

    def test_disconnected_input_at_zero_bytes_differs_from_empty_stream(self):
        for exc in (ClientDisconnected(), ConnectionResetError("peer reset"), EOFError("unexpected eof")):
            with self.subTest(exc=type(exc).__name__), tempfile.TemporaryDirectory() as tmp:
                dest = Path(tmp) / "out.bin"
                stream = _DisconnectingStream([], exc)
                with self.assertRaises(PrematureUploadTerminationError) as cm:
                    hash_stream_to_path(stream, dest, chunk_size=1024, temp_dir=tmp)
                self.assertEqual(cm.exception.code, UPLOAD_TERMINATED_PREMATURELY)
                self.assertEqual(cm.exception.status_code, 400)
                self.assertEqual(cm.exception.bytes_received, 0)
                self.assertFalse(dest.exists())
                self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_mid_stream_disconnect_cleans_up_partial_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "partial.mp4"
            stream = _DisconnectingStream([b"chunk-1-", b"chunk-2-"], ConnectionResetError("dropped"))
            with self.assertRaises(PrematureUploadTerminationError) as cm:
                hash_stream_to_path(stream, dest, chunk_size=8, temp_dir=tmp)
            self.assertEqual(cm.exception.code, UPLOAD_TERMINATED_PREMATURELY)
            self.assertEqual(cm.exception.bytes_received, 16)
            self.assertFalse(dest.exists())
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_truncated_stream_below_expected_size_raises_premature_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "truncated.bin"
            with self.assertRaises(PrematureUploadTerminationError) as cm:
                hash_stream_to_path(
                    io.BytesIO(b"short"),
                    dest,
                    chunk_size=1024,
                    expected_size=64,
                    temp_dir=tmp,
                )
            self.assertEqual(cm.exception.code, UPLOAD_TERMINATED_PREMATURELY)
            self.assertEqual(cm.exception.bytes_received, 5)
            self.assertEqual(cm.exception.expected_bytes, 64)
            self.assertFalse(dest.exists())
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_partial_evidence_never_enters_processing_job(self):
        processing_called = []
        stream = _DisconnectingStream(
            [b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00"],
            ClientDisconnected(),
        )
        storage = StreamingFileStorage(
            stream=stream,
            filename="evidence.mp4",
            content_type="video/mp4",
            max_size=1024,
            chunk_size=16,
        )
        with self.assertRaises(PrematureUploadTerminationError) as cm:
            with isolate_upload(storage, filename="evidence.mp4", content_type="video/mp4") as path:
                processing_called.append(path)
        self.assertEqual(cm.exception.code, UPLOAD_TERMINATED_PREMATURELY)
        self.assertEqual(processing_called, [])
        self.assertIsNone(storage.computed_hash)

    def test_resumable_chunk_disconnect_does_not_persist_partial_chunk(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ResumableUploadSessionStore(tmp, default_chunk_size=16)
            session, token = store.create_session(owner="GABC123")
            stream = _DisconnectingStream([b"partial-chunk"], ConnectionResetError("reset"))
            with self.assertRaises(PrematureUploadTerminationError) as cm:
                store.write_chunk(
                    session.session_id,
                    0,
                    stream,
                    session_token=token,
                    owner="GABC123",
                )
            self.assertEqual(cm.exception.code, UPLOAD_TERMINATED_PREMATURELY)
            self.assertEqual(cm.exception.bytes_received, len(b"partial-chunk"))
            progress = store.get_progress(session.session_id, session_token=token, owner="GABC123")
            self.assertEqual(progress["receivedChunks"], [])
            self.assertEqual(progress["totalBytes"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
