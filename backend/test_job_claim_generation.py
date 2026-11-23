"""Claim-generation fencing for worker results (issue #1104).

A worker that loses its claim (the shutdown grace period expires and the job is
released, then another worker leases it) must not be able to overwrite the newer
result, progress or failure state when its thread finishes late.
"""

from __future__ import annotations

import threading
import time
import unittest
from datetime import UTC, datetime, timedelta
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


class ClaimGenerationStoreTests(_JobsIsolation):
    def test_each_lease_returns_a_new_generation(self) -> None:
        job_id = db.enqueue_job("embed", {})
        first = db.lease_job("worker-a", ["embed"])
        self.assertEqual(first["_claim_generation"], 1)
        db.fail_job(job_id, "transient", is_fatal=False, generation=1)
        second = db.lease_job("worker-b", ["embed"])
        self.assertGreater(second["_claim_generation"], first["_claim_generation"])

    def test_current_claim_commits_its_result(self) -> None:
        job_id = db.enqueue_job("embed", {})
        claim = db.lease_job("worker-a", ["embed"])
        self.assertTrue(db.complete_job(job_id, {"ok": 1}, generation=claim["_claim_generation"]))
        self.assertEqual(db.get_job(job_id)["status"], "completed")
        self.assertEqual(db.get_job(job_id)["result"], {"ok": 1})

    def test_replaced_worker_cannot_overwrite_newer_result(self) -> None:
        job_id = db.enqueue_job("embed", {})
        old = db.lease_job("worker-a", ["embed"])["_claim_generation"]
        # grace period expired: the old claim is released...
        self.assertTrue(db.fail_job(job_id, "grace exceeded", is_fatal=False, generation=old))
        # ...and another worker leases and finishes the job.
        new = db.lease_job("worker-b", ["embed"])["_claim_generation"]
        self.assertTrue(db.complete_job(job_id, {"from": "b"}, generation=new))

        # The first worker's thread finishes late: every write is fenced.
        with self.assertLogs("db", level="WARNING") as logs:
            self.assertFalse(db.complete_job(job_id, {"from": "a"}, generation=old))
            self.assertFalse(db.fail_job(job_id, "late error", is_fatal=True, generation=old))
        job = db.get_job(job_id)
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["result"], {"from": "b"})
        self.assertNotIn("late error", str(job.get("error")))
        self.assertTrue(any("job_claim_stale" in line for line in logs.output))

    def test_release_alone_fences_the_old_claim(self) -> None:
        job_id = db.enqueue_job("embed", {})
        old = db.lease_job("worker-a", ["embed"])["_claim_generation"]
        db.fail_job(job_id, "grace exceeded", is_fatal=False, generation=old)
        # Not re-leased yet: a late completion must not mark the pending job done.
        self.assertFalse(db.complete_job(job_id, {"from": "a"}, generation=old))
        self.assertEqual(db.get_job(job_id)["status"], "pending")
        self.assertIsNone(db.get_job(job_id)["result"])

    def test_stale_progress_and_heartbeat_are_ignored(self) -> None:
        job_id = db.enqueue_job("embed", {})
        old = db.lease_job("worker-a", ["embed"])["_claim_generation"]
        db.fail_job(job_id, "grace exceeded", is_fatal=False, generation=old)
        new = db.lease_job("worker-b", ["embed"])["_claim_generation"]
        self.assertTrue(db.report_job_progress(job_id, "embedding", 40, now=10.0, generation=new))
        self.assertFalse(db.report_job_progress(job_id, "embedding", 90, now=20.0, generation=old))
        self.assertEqual(db.get_job(job_id)["progress"], {"phase": "embedding", "percent": 40.0})
        leased_heartbeat = db.get_job(job_id)["heartbeat_at"]
        later = datetime(2030, 1, 1, tzinfo=UTC)
        db.heartbeat_job(job_id, generation=old, now=later)
        self.assertEqual(db.get_job(job_id)["heartbeat_at"], leased_heartbeat)
        db.heartbeat_job(job_id, generation=new, now=later)
        self.assertEqual(db.get_job(job_id)["heartbeat_at"], later.isoformat())

    def test_stale_heartbeat_reclaim_fences_the_old_claim(self) -> None:
        job_id = db.enqueue_job("embed", {})
        start = datetime(2030, 1, 1, tzinfo=UTC)
        old = db.lease_job("worker-a", ["embed"], now=start)["_claim_generation"]
        # worker A stops heartbeating; the main loop reclaims the job...
        reclaimed = db.reclaim_stale_jobs(now=start + timedelta(seconds=301))
        self.assertEqual([item["id"] for item in reclaimed], [job_id])
        # ...and worker B leases and finishes it.
        new = db.lease_job("worker-b", ["embed"], now=start + timedelta(seconds=302))["_claim_generation"]
        self.assertGreater(new, old)
        self.assertTrue(db.complete_job(job_id, {"from": "b"}, generation=new))
        # Worker A was only slow, not dead: its late writes are fenced.
        with self.assertLogs("db", level="WARNING"):
            self.assertFalse(db.complete_job(job_id, {"from": "a"}, generation=old))
        self.assertEqual(db.get_job(job_id)["result"], {"from": "b"})

    def test_late_result_cannot_overwrite_a_deadline_failure(self) -> None:
        job_id = db.enqueue_job("embed", {})
        gen = db.lease_job("worker-a", ["embed"])["_claim_generation"]
        # The processing deadline expires while the work thread is still running.
        self.assertTrue(db.fail_job(job_id, "Processing deadline exceeded", is_fatal=True, generation=gen))
        with self.assertLogs("db", level="WARNING") as logs:
            self.assertFalse(db.complete_job(job_id, {"late": True}, generation=gen))
        job = db.get_job(job_id)
        self.assertEqual(job["status"], "failed")
        self.assertIsNone(job["result"])
        self.assertTrue(any("job_claim_settled" in line for line in logs.output))

    def test_calls_without_generation_keep_previous_behaviour(self) -> None:
        job_id = db.enqueue_job("embed", {})
        db.lease_job("worker-a", ["embed"])
        db.fail_job(job_id, "transient", is_fatal=False)
        self.assertEqual(db.get_job(job_id)["status"], "pending")
        db.lease_job("worker-b", ["embed"])
        self.assertTrue(db.complete_job(job_id, {"ok": 1}))
        self.assertEqual(db.get_job(job_id)["status"], "completed")


class ClaimConcurrencyTests(_JobsIsolation):
    def test_release_waits_for_an_inflight_completion_and_does_not_revert_it(self) -> None:
        job_id = db.enqueue_job("embed", {})
        gen = db.lease_job("worker-a", ["embed"])["_claim_generation"]
        inside_check = threading.Event()
        real_check = db._claim_is_current

        def slow_check(job, generation, action):
            ok = real_check(job, generation, action)
            if action == "complete":
                inside_check.set()
                time.sleep(0.2)  # widen the check-then-write window
            return ok

        results = {}
        with patch.object(db, "_claim_is_current", side_effect=slow_check):
            completer = threading.Thread(
                target=lambda: results.setdefault("complete", db.complete_job(job_id, {"r": 1}, generation=gen))
            )
            completer.start()
            self.assertTrue(inside_check.wait(2.0))
            # The grace-period release arrives while the completion is mid-flight.
            with self.assertLogs("db", level="WARNING"):
                results["release"] = db.fail_job(job_id, "grace exceeded", is_fatal=False, generation=gen)
            completer.join(2.0)

        self.assertTrue(results["complete"])
        self.assertFalse(results["release"])
        job = db.get_job(job_id)
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["result"], {"r": 1})


class WorkerFencingTests(_JobsIsolation):
    """End to end through ``run_worker`` with the real in-memory queue."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            import worker
        except ImportError as exc:  # pragma: no cover - depends on the baseline
            raise unittest.SkipTest(f"worker module does not import on this baseline: {exc}")
        cls.worker = worker

    def test_late_result_after_grace_release_does_not_complete_job(self) -> None:
        worker = self.worker
        stop_event = threading.Event()
        job_id = db.enqueue_job("embed", {})
        finished = threading.Event()

        def slow_embed(job):
            stop_event.set()
            time.sleep(0.4)  # outlives the 0.1 s grace period
            finished.set()
            return {"from": "old-claim"}

        watchdog = threading.Timer(5.0, stop_event.set)  # never hang the suite
        watchdog.start()
        self.addCleanup(watchdog.cancel)
        with patch.object(worker, "init_db"), \
             patch.object(worker, "process_embed", side_effect=slow_embed), \
             patch.object(worker, "heartbeat_loop"), \
             patch.object(worker, "tx_verification_loop"), \
             patch.object(worker, "run_indexer_loop"):
            worker.run_worker(stop_event=stop_event, grace_period_seconds=0.1)
            self.assertEqual(db.get_job(job_id)["status"], "pending")
            self.assertTrue(finished.wait(2.0))
            time.sleep(0.1)  # let the old work thread reach complete_job

        job = db.get_job(job_id)
        self.assertEqual(job["status"], "pending")
        self.assertIsNone(job["result"])
        self.assertEqual(job["_claim_generation"], 2)


if __name__ == "__main__":
    unittest.main()
