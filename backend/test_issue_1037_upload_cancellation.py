from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as app_module  # noqa: E402
from admission import AdmissionController  # noqa: E402
from streaming_upload import (  # noqa: E402
    UPLOAD_STATE_CANCELLED,
    UPLOAD_STATE_CANCELLING,
    UPLOAD_STATE_QUEUED,
    UPLOAD_STATE_RECEIVING,
    UploadCancelledError,
    UploadSessionCancellationCoordinator,
    hash_stream_to_path,
)


class UploadCancellationUnitTests(unittest.TestCase):
    def test_cancelling_queued_waiter_releases_queue_and_identity_immediately(self) -> None:
        controller = AdmissionController(
            max_concurrent=1,
            max_queue=1,
            max_per_identity=2,
            timeout_seconds=5.0,
        )
        coordinator = UploadSessionCancellationCoordinator()
        with tempfile.TemporaryDirectory() as tmp_root:
            session_dir = Path(tmp_root) / "session-queued"
            session_dir.mkdir()
            coordinator.register_session("s-queued", session_dir)

            # Hold the sole execution slot.
            holder, reason = controller.acquire_lease("holder")
            self.assertIsNotNone(holder)
            self.assertEqual(reason, "ok")
            assert holder is not None

            queued_ready = threading.Event()
            outcomes: list[tuple[object, str]] = []

            def _waiter() -> None:
                cancel_ev = coordinator.ensure_session("s-queued", session_dir)
                coordinator.add_cancel_hook("s-queued", controller.notify_cancelled)
                lease, res = controller.acquire_lease(
                    "client-q",
                    cancel_event=cancel_ev,
                    on_queued=lambda: (
                        coordinator.mark_queued("s-queued"),
                        queued_ready.set(),
                    ),
                )
                outcomes.append((lease, res))

            worker = threading.Thread(target=_waiter)
            worker.start()
            self.assertTrue(queued_ready.wait(timeout=2.0))
            status_before = coordinator.get_status("s-queued")
            assert status_before is not None
            self.assertEqual(status_before["state"], UPLOAD_STATE_QUEUED)

            cancel_result = coordinator.cancel("s-queued")
            assert cancel_result is not None
            self.assertEqual(cancel_result["state"], UPLOAD_STATE_CANCELLED)
            self.assertTrue(cancel_result["cleaned"])
            self.assertFalse(session_dir.exists())

            worker.join(timeout=1.0)
            self.assertFalse(worker.is_alive())
            self.assertEqual(outcomes, [(None, "cancelled")])

            # Queue space was freed immediately: another caller can now enter the queue
            # and acquire as soon as holder releases.
            holder.release()
            next_lease, next_reason = controller.acquire_lease("client-q")
            self.assertIsNotNone(next_lease)
            self.assertEqual(next_reason, "ok")
            assert next_lease is not None
            next_lease.release()

    def test_receiving_cancellation_defers_file_cleanup_until_active_writer_stops(self) -> None:
        controller = AdmissionController(
            max_concurrent=1,
            max_queue=0,
            max_per_identity=2,
            timeout_seconds=0.2,
        )
        coordinator = UploadSessionCancellationCoordinator()
        with tempfile.TemporaryDirectory() as tmp_root:
            session_dir = Path(tmp_root) / "session-receiving"
            session_dir.mkdir()
            staged_chunk = session_dir / "chunk-0"
            staged_chunk.write_bytes(b"already-staged")
            coordinator.register_session("s-recv", session_dir)

            writer_entered = threading.Event()
            allow_writer_exit = threading.Event()
            writer_errors: list[Exception] = []

            class _PausingStream:
                def __init__(self) -> None:
                    self._calls = 0

                def read(self, _size: int = -1) -> bytes:
                    self._calls += 1
                    if self._calls == 1:
                        return b"a" * 64
                    writer_entered.set()
                    allow_writer_exit.wait(timeout=2.0)
                    return b"b" * 64

            def _writer() -> None:
                lease, _ = controller.acquire_lease("writer-id")
                assert lease is not None
                coordinator.add_cancel_hook("s-recv", lambda: None if lease.release() else None)
                try:
                    with coordinator.writer_scope("s-recv") as cancel_ev:
                        hash_stream_to_path(
                            _PausingStream(),  # type: ignore[arg-type]
                            session_dir / "chunk-1",
                            chunk_size=64,
                            temp_dir=session_dir,
                            cancel_event=cancel_ev,
                        )
                except UploadCancelledError as exc:
                    writer_errors.append(exc)
                finally:
                    lease.release()

            t = threading.Thread(target=_writer)
            t.start()
            self.assertTrue(writer_entered.wait(timeout=2.0))
            st_active = coordinator.get_status("s-recv")
            assert st_active is not None
            self.assertEqual(st_active["state"], UPLOAD_STATE_RECEIVING)
            self.assertEqual(st_active["activeWriters"], 1)

            # Cancel while the writer is actively paused inside hash_stream_to_path.
            res = coordinator.cancel("s-recv")
            assert res is not None
            self.assertEqual(res["state"], UPLOAD_STATE_CANCELLING)
            self.assertEqual(res["activeWriters"], 1)
            self.assertFalse(res["cleaned"])
            # Temporary files MUST still exist while the active writer has not stopped!
            self.assertTrue(session_dir.exists())
            self.assertTrue(staged_chunk.exists())

            # Admission capacity MUST already be released even before the writer exits!
            peer_lease, peer_reason = controller.acquire_lease("peer-id")
            self.assertIsNotNone(peer_lease)
            self.assertEqual(peer_reason, "ok")
            assert peer_lease is not None
            peer_lease.release()

            # Let the writer unwind; writer_scope exit must now clean session_dir.
            allow_writer_exit.set()
            t.join(timeout=2.0)
            self.assertFalse(t.is_alive())
            self.assertEqual(len(writer_errors), 1)
            self.assertFalse(session_dir.exists())

            st_final = coordinator.get_status("s-recv")
            assert st_final is not None
            self.assertEqual(st_final["state"], UPLOAD_STATE_CANCELLED)
            self.assertEqual(st_final["activeWriters"], 0)
            self.assertTrue(st_final["cleaned"])


class UploadCancellationRouteTests(unittest.TestCase):
    def _build_app(self, extra_env: dict[str, str] | None = None):
        env = {
            "RATELIMIT_ENABLED": "false",
            "MAX_CONCURRENT_REQUESTS": "1",
            "MAX_QUEUE_SIZE": "1",
            "ADMISSION_TIMEOUT_SECONDS": "2.0",
        }
        if extra_env:
            env.update(extra_env)
        with patch.dict(os.environ, env, clear=False):
            return app_module.create_app()

    def test_http_cancel_lifecycle_and_completed_session_conflict(self) -> None:
        flask_app = self._build_app()
        client = flask_app.test_client()

        missing = client.post("/api/stego/upload-session/does-not-exist/cancel")
        self.assertEqual(missing.status_code, 404)

        s1 = client.post("/api/stego/upload-session").get_json()["sessionId"]
        put_ok = client.put(
            f"/api/stego/upload-session/{s1}/chunk/0",
            data={"chunk": (io.BytesIO(b"\x00\x00\x00\x18ftypmp42" + b"x" * 64), "c0")},
            content_type="multipart/form-data",
        )
        self.assertEqual(put_ok.status_code, 200)

        cancelled = client.post(f"/api/stego/upload-session/{s1}/cancel")
        self.assertEqual(cancelled.status_code, 200)
        body = cancelled.get_json()
        self.assertEqual(body["state"], "cancelled")
        self.assertTrue(body["cleaned"])

        # Subsequent chunk upload or commit on a cancelled session fails closed with 409.
        after_cancel = client.put(
            f"/api/stego/upload-session/{s1}/chunk/1",
            data={"chunk": (io.BytesIO(b"more"), "c1")},
            content_type="multipart/form-data",
        )
        self.assertEqual(after_cancel.status_code, 409)
        self.assertEqual(after_cancel.get_json()["error"]["code"], "UPLOAD_CANCELLED")

        # Completed session cannot be cancelled retroactively (409 UPLOAD_ALREADY_COMPLETED).
        s2 = client.post("/api/stego/upload-session").get_json()["sessionId"]
        client.put(
            f"/api/stego/upload-session/{s2}/chunk/0",
            data={"chunk": (io.BytesIO(b"\x00\x00\x00\x18ftypmp42" + b"y" * 64), "c0")},
            content_type="multipart/form-data",
        )

        def _fake_embed(_src, dst, _meta):
            Path(dst).write_bytes(b"synthetic-mp4")

        valid_meta = {
            "version": 2,
            "proofId": "proof-1037",
            "tier": "verified",
            "timestamp": "2026-11-15T00:00:00Z",
        }
        with (
            patch.object(app_module, "sniff_media_type_path", return_value="video/mp4"),
            patch.object(app_module, "embed_metadata", side_effect=_fake_embed),
            patch.object(app_module, "validate_embed_metadata", return_value=None),
            patch.object(app_module, "insert_proof_event", return_value={"id": 1}),
        ):
            commit_ok = client.post(
                f"/api/stego/upload-session/{s2}/commit",
                data={"metadata": json.dumps(valid_meta)},
                content_type="multipart/form-data",
            )
        self.assertEqual(commit_ok.status_code, 200)

        cancel_after_complete = client.post(f"/api/stego/upload-session/{s2}/cancel")
        self.assertEqual(cancel_after_complete.status_code, 409)
        self.assertEqual(
            cancel_after_complete.get_json()["error"]["code"],
            "UPLOAD_ALREADY_COMPLETED",
        )


if __name__ == "__main__":
    unittest.main()
