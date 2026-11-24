"""Focused coverage for upload cancellation and admission release."""

from __future__ import annotations

import io
import tempfile
import threading
import time
import unittest
from pathlib import Path

from admission import AdmissionController, AdmissionState
from streaming_upload import (
    UploadCancelledError,
    UploadSessionRegistry,
    UploadState,
    hash_stream_to_path,
)


class _CancellingStream:
    def __init__(self, cancellation, payload: bytes):
        self.cancellation = cancellation
        self.payload = payload
        self.position = 0
        self.cancelled = False

    def read(self, size=-1):
        if self.cancelled:
            return b""
        end = min(self.position + size, len(self.payload))
        chunk = self.payload[self.position:end]
        self.position = end
        if self.cancellation.state is not UploadState.CANCELLED:
            self.cancellation.cancel()
            self.cancelled = True
        return chunk


class AdmissionCancellationTest(unittest.TestCase):
    def test_queued_cancellation_releases_capacity(self):
        controller = AdmissionController(
            max_concurrent=1,
            max_queue=1,
            max_per_identity=4,
            timeout_seconds=1.0,
        )
        self.assertTrue(controller.acquire("holder")[0])
        ticket = controller.create_ticket("queued")
        result = {}

        def queued_acquire():
            result["outcome"] = controller.acquire_ticket("queued", ticket=ticket)

        worker = threading.Thread(target=queued_acquire)
        worker.start()
        time.sleep(0.05)

        self.assertTrue(controller.cancel(ticket.id))
        worker.join(timeout=1.0)

        self.assertFalse(worker.is_alive())
        self.assertEqual(result["outcome"][:2], (False, "cancelled"))
        self.assertEqual(ticket.state, AdmissionState.CANCELLED)

        controller.release("holder")
        self.assertTrue(controller.acquire("after")[0])

    def test_active_cancellation_completes_on_release(self):
        controller = AdmissionController(
            max_concurrent=1,
            max_queue=0,
            max_per_identity=2,
            timeout_seconds=0.1,
        )
        ticket = controller.create_ticket("active")
        outcome = controller.acquire_ticket("active", ticket=ticket)
        self.assertEqual(outcome[:2], (True, "ok"))

        self.assertTrue(controller.cancel(ticket.id))
        self.assertEqual(ticket.state, AdmissionState.CANCELLING)

        controller.release("active")
        self.assertEqual(ticket.state, AdmissionState.CANCELLED)
        self.assertTrue(controller.acquire("after")[0])

    def test_cancel_unknown_ticket_is_false(self):
        controller = AdmissionController(1, 0, 1, 0.1)
        self.assertFalse(controller.cancel("missing"))


class UploadCancellationTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.registry = UploadSessionRegistry()

    def test_temp_files_remain_until_active_writer_stops(self):
        session_dir = self.root / "session"
        session_dir.mkdir()
        blob = session_dir / "chunk-0"
        blob.write_bytes(b"partial")
        session = self.registry.create("session-1", session_dir)

        with session.writer():
            self.assertTrue(session.cancel())
            self.assertEqual(session.state, UploadState.CANCELLED)
            self.assertTrue(blob.exists())

        self.assertFalse(blob.exists())
        self.assertFalse(session_dir.exists())
        self.assertTrue(session.cleanup_done)

    def test_cancel_without_writer_cleans_immediately(self):
        session_dir = self.root / "session"
        session_dir.mkdir()
        (session_dir / "chunk-0").write_bytes(b"partial")
        session = self.registry.create("session-2", session_dir)

        self.registry.cancel("session-2")

        self.assertFalse(session_dir.exists())
        self.assertEqual(session.state, UploadState.CANCELLED)

    def test_cancel_terminal_session_is_refused(self):
        session = self.registry.create("session-3", self.root / "session")
        self.assertTrue(session.cancel())
        self.assertFalse(self.registry.cancel("session-3"))
        self.assertIsNone(self.registry.cancel("missing"))

    def test_streaming_checks_cancellation_before_next_chunk(self):
        session_dir = self.root / "session"
        session_dir.mkdir()
        session = self.registry.create("session-4", session_dir)
        source = _CancellingStream(session, b"x" * 128)
        destination = session_dir / "chunk-0"

        with self.assertRaises(UploadCancelledError):
            with session.writer():
                hash_stream_to_path(
                    source,
                    destination,
                    chunk_size=64,
                    max_size=1024,
                    temp_dir=session_dir,
                    cancellation=session,
                )

        self.assertFalse(destination.exists())
        self.assertEqual(session.state, UploadState.CANCELLED)


if __name__ == "__main__":
    unittest.main()
