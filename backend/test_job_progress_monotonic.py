"""Focused tests for monotonic stage revisions and terminal job guards."""

from __future__ import annotations

import importlib
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import db


class _JobsIsolation(unittest.TestCase):
    """Run each test against an empty in-memory job table."""

    def setUp(self) -> None:
        self._saved_jobs = dict(db._JOBS)
        db._JOBS.clear()

    def tearDown(self) -> None:
        db._JOBS.clear()
        db._JOBS.update(self._saved_jobs)

    def _running_job(self, job_type: str = "embed", payload: dict | None = None) -> int:
        job_id = db.enqueue_job(job_type, payload or {})
        db._JOBS[job_id]["status"] = "running"
        return job_id


class MonotonicStageRevisionTests(_JobsIsolation):
    def test_rejects_regressing_stage_revision_regardless_of_clock(self) -> None:
        job_id = self._running_job()
        self.assertTrue(db.report_job_progress(job_id, "hashing_source", None, stage_revision=1, now=10.0))
        self.assertTrue(db.report_job_progress(job_id, "embedding", 50.0, stage_revision=2, now=12.0))

        # Even with a much later timestamp, an older stage_revision is rejected.
        self.assertFalse(db.report_job_progress(job_id, "hashing_source", None, stage_revision=1, now=999.0))
        self.assertEqual(db.get_job(job_id)["progress"], {"phase": "embedding", "percent": 50.0})

        # Same stage_revision continues to accept updates after throttle interval.
        self.assertTrue(db.report_job_progress(job_id, "embedding", 80.0, stage_revision=2, now=14.0))
        self.assertEqual(db.get_job(job_id)["progress"], {"phase": "embedding", "percent": 80.0})

        # Advancing to a higher stage_revision succeeds, then regressing is rejected.
        self.assertTrue(db.report_job_progress(job_id, "hashing_output", None, stage_revision=3, now=16.0))
        self.assertFalse(db.report_job_progress(job_id, "embedding", 99.0, stage_revision=2, now=20.0))
        self.assertEqual(db.get_job(job_id)["progress"], {"phase": "hashing_output", "percent": None})

    def test_throttled_higher_stage_still_blocks_regressing_stage(self) -> None:
        job_id = self._running_job()
        self.assertTrue(db.report_job_progress(job_id, "embedding", 90.0, stage_revision=2, now=10.0))
        # Stage 3 arrives within throttle window: throttled, but advances _stage_revision to 3.
        self.assertFalse(db.report_job_progress(job_id, "hashing_output", None, stage_revision=3, now=10.4))
        # Late stage 2 update after throttle window is still rejected.
        self.assertFalse(db.report_job_progress(job_id, "embedding", 95.0, stage_revision=2, now=12.0))
        self.assertEqual(db.get_job(job_id)["progress"], {"phase": "embedding", "percent": 90.0})
        # Stage 3 update after throttle window succeeds.
        self.assertTrue(db.report_job_progress(job_id, "hashing_output", None, stage_revision=3, now=12.0))
        self.assertEqual(db.get_job(job_id)["progress"], {"phase": "hashing_output", "percent": None})

    def test_invalid_stage_revision_raises_value_error(self) -> None:
        job_id = self._running_job()
        for bad_rev in (-1, True, False, "2", 1.5):
            with self.subTest(stage_revision=bad_rev), self.assertRaises(ValueError):
                db.report_job_progress(job_id, "embedding", 10, stage_revision=bad_rev, now=1.0)  # type: ignore[arg-type]
        self.assertIsNone(db.get_job(job_id)["progress"])

    def test_omitted_stage_revision_stays_backwards_compatible(self) -> None:
        job_id = self._running_job()
        self.assertTrue(db.report_job_progress(job_id, "embedding", 10, now=1.0))
        self.assertFalse(db.report_job_progress(job_id, "embedding", 20, now=1.5))
        self.assertTrue(db.report_job_progress(job_id, "embedding", 40, now=2.0))
        self.assertEqual(db.get_job(job_id)["progress"], {"phase": "embedding", "percent": 40.0})


class TerminalJobStateTests(_JobsIsolation):
    def test_terminal_jobs_cannot_return_to_running_or_accept_progress(self) -> None:
        for terminal_state in ("completed", "failed", "cancelled"):
            with self.subTest(terminal_state=terminal_state):
                job_id = db.enqueue_job("embed", {})
                if terminal_state == "cancelled":
                    self.assertTrue(db.cancel_job(job_id))
                else:
                    leased = db.lease_job("worker-1", ["embed"])
                    self.assertIsNotNone(leased)
                    self.assertEqual(leased["id"], job_id)
                    if terminal_state == "completed":
                        db.complete_job(job_id, {"ok": True})
                    else:
                        db.fail_job(job_id, "fatal error", is_fatal=True)

                # Non-fatal fail_job must not reset a terminal job back to pending/running.
                db.fail_job(job_id, "late shutdown timeout", is_fatal=False)
                self.assertEqual(db.get_job(job_id)["status"], terminal_state)
                self.assertIsNone(db.lease_job("worker-2", ["embed"]))
                self.assertEqual(db.get_job(job_id)["status"], terminal_state)

                # complete_job must not overwrite another terminal state.
                db.complete_job(job_id, {"overwritten": True})
                self.assertEqual(db.get_job(job_id)["status"], terminal_state)

                # Progress updates are rejected for terminal jobs.
                self.assertFalse(db.report_job_progress(job_id, "embedding", 50.0, stage_revision=2, now=50.0))

    def test_non_fatal_retry_resets_stage_revision_for_next_attempt(self) -> None:
        job_id = db.enqueue_job("embed", {})
        db.lease_job("worker-1", ["embed"])
        self.assertTrue(db.report_job_progress(job_id, "hashing_output", None, stage_revision=3, now=10.0))
        db.fail_job(job_id, "transient error", is_fatal=False)
        self.assertEqual(db.get_job(job_id)["status"], "pending")
        retried = db.lease_job("worker-2", ["embed"])
        self.assertIsNotNone(retried)
        self.assertEqual(retried["id"], job_id)
        self.assertTrue(db.report_job_progress(job_id, "hashing_source", None, stage_revision=1, now=10.2))
        self.assertEqual(db.get_job(job_id)["progress"], {"phase": "hashing_source", "percent": None})


class WorkerStageRevisionEmissionTests(_JobsIsolation):
    @classmethod
    def setUpClass(cls) -> None:
        if "worker" in sys.modules:
            cls.worker = sys.modules["worker"]
            return
        fake_app = types.ModuleType("app")
        fake_app.safe_filename = lambda name: name
        fake_app.normalize_filename = lambda name: name
        fake_app.redact_metadata = lambda meta: meta
        prev_app = sys.modules.get("app")
        sys.modules["app"] = fake_app
        try:
            cls.worker = importlib.import_module("worker")
        finally:
            if prev_app is None:
                sys.modules.pop("app", None)
            else:
                sys.modules["app"] = prev_app

    def _load_worker(self):
        return self.worker

    def test_process_embed_emits_monotonic_stage_revisions(self) -> None:
        worker = self._load_worker()
        job_id = self._running_job("embed", {"metadata": {"proofId": "aa" * 32}, "filename": "clip.mp4"})
        recorded: list[tuple[str, float | None, int | None]] = []

        def fake_report(jid, phase, percent=None, *, stage_revision=None, **kwargs):
            recorded.append((phase, percent, stage_revision))
            return db.report_job_progress(jid, phase, percent, stage_revision=stage_revision, **kwargs)

        def fake_embed(source, output, metadata, progress_callback=None):
            progress_callback(1, 2)
            progress_callback(2, 2)

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "in.mp4"
            source.write_bytes(b"video")
            with patch.object(worker, "get_job_input_path", return_value=source), \
                 patch.object(worker, "get_job_output_path", return_value=Path(tmp) / "out.mp4"), \
                 patch.object(worker, "sha256_file", return_value="ab" * 32), \
                 patch.object(worker, "embed_metadata", side_effect=fake_embed), \
                 patch.object(worker, "insert_proof_event", return_value=1), \
                 patch.object(worker, "report_job_progress", side_effect=fake_report):
                worker.process_embed(db.get_job(job_id))

        self.assertEqual(
            recorded,
            [
                ("hashing_source", None, 1),
                ("embedding", 50.0, 2),
                ("embedding", 100.0, 2),
                ("hashing_output", None, 3),
                ("recording", None, 4),
            ],
        )

    def test_process_silent_witness_emits_stage_revision(self) -> None:
        worker = self._load_worker()
        job_id = self._running_job(
            "silent_witness",
            {"video_hash": "aa" * 32, "credential_secret": "CRED", "nullifier_secret": "NULL"},
        )
        recorded: list[tuple[str, int | None]] = []

        def fake_report(jid, phase, percent=None, *, stage_revision=None, **kwargs):
            recorded.append((phase, stage_revision))
            return db.report_job_progress(jid, phase, percent, stage_revision=stage_revision, **kwargs)

        with patch.object(worker, "generate_silent_witness", return_value={"proof": "00"}), \
             patch.object(worker, "report_job_progress", side_effect=fake_report):
            worker.process_silent_witness(db.get_job(job_id))

        self.assertEqual(recorded, [("generating_proof", 1)])


if __name__ == "__main__":
    unittest.main()
