"""Processing deadlines: queue expiry vs. execution timeout, and artifact cleanup
that waits for the active process to stop writing (issue #1109)."""

import os
import threading
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import db
from config import (
    JOB_EXECUTION_TIMEOUT_SECONDS_DEFAULT,
    JOB_QUEUE_TTL_SECONDS_DEFAULT,
    load_config,
)
from storage import sweep_job_files


class _JobsIsolation(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = dict(db._JOBS)
        db._JOBS.clear()

    def tearDown(self) -> None:
        db._JOBS.clear()
        db._JOBS.update(self._saved)


class DeadlineConfigTests(unittest.TestCase):
    def test_both_deadlines_are_disabled_by_default(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("HARPOCRATES_JOB_QUEUE_TTL_SECONDS", None)
            os.environ.pop("HARPOCRATES_JOB_EXECUTION_TIMEOUT_SECONDS", None)
            cfg = load_config()
        self.assertEqual(JOB_QUEUE_TTL_SECONDS_DEFAULT, 0)
        self.assertEqual(JOB_EXECUTION_TIMEOUT_SECONDS_DEFAULT, 0)
        self.assertEqual(cfg.job_queue_ttl_seconds, 0)
        self.assertEqual(cfg.job_execution_timeout_seconds, 0)

    def test_deadlines_are_configured_independently(self) -> None:
        env = {
            "HARPOCRATES_JOB_QUEUE_TTL_SECONDS": "600",
            "HARPOCRATES_JOB_EXECUTION_TIMEOUT_SECONDS": "120",
        }
        with patch.dict(os.environ, env):
            cfg = load_config()
        self.assertEqual(cfg.job_queue_ttl_seconds, 600)
        self.assertEqual(cfg.job_execution_timeout_seconds, 120)

    def test_invalid_deadlines_are_rejected(self) -> None:
        for raw, message in (("-1", "must be non-negative"), ("soon", "must be an integer")):
            with (
                self.subTest(raw=raw),
                patch.dict(os.environ, {"HARPOCRATES_JOB_EXECUTION_TIMEOUT_SECONDS": raw}),
                self.assertRaisesRegex(RuntimeError, message),
            ):
                load_config()


class QueueExpiryTests(_JobsIsolation):
    def test_pending_job_expires_after_queue_ttl(self) -> None:
        job_id = db.enqueue_job("embed", {})
        queued_at = db.get_job(job_id)["_queued_at"]

        self.assertEqual(db.expire_queued_jobs(60, now=queued_at + 59.9), 0)
        self.assertEqual(db.get_job(job_id)["status"], "pending")

        with self.assertLogs("db", level="WARNING") as logs:
            self.assertEqual(db.expire_queued_jobs(60, now=queued_at + 60), 1)
        job = db.get_job(job_id)
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["failure_reason"], db.JOB_QUEUE_EXPIRED)
        self.assertIn("reason=queue_expired", logs.output[0])
        self.assertIsNone(db.lease_job("worker-a", ["embed"]))

    def test_queue_expiry_never_touches_a_running_job(self) -> None:
        job_id = db.enqueue_job("embed", {})
        queued_at = db.get_job(job_id)["_queued_at"]
        db.lease_job("worker-a", ["embed"])

        self.assertEqual(db.expire_queued_jobs(60, now=queued_at + 3600), 0)
        self.assertEqual(db.get_job(job_id)["status"], "running")

    def test_retryable_release_restarts_the_queue_clock(self) -> None:
        job_id = db.enqueue_job("embed", {})
        db._JOBS[job_id]["_queued_at"] -= 3600  # waited an hour before the lease
        db.lease_job("worker-a", ["embed"])
        db.fail_job(job_id, "transient", is_fatal=False)

        self.assertEqual(db.expire_queued_jobs(60), 0)
        self.assertEqual(db.get_job(job_id)["status"], "pending")

    def test_disabled_queue_expiry_keeps_previous_behaviour(self) -> None:
        job_id = db.enqueue_job("embed", {})
        db._JOBS[job_id]["_queued_at"] -= 10 * 86_400

        self.assertEqual(db.expire_queued_jobs(0), 0)
        self.assertEqual(db.lease_job("worker-a", ["embed"])["id"], job_id)


class ExecutionTimeoutTests(_JobsIsolation):
    def test_running_job_times_out_after_execution_timeout(self) -> None:
        job_id = db.enqueue_job("embed", {})
        started_at = db.lease_job("worker-a", ["embed"])["_started_at"]

        self.assertFalse(db.time_out_job(job_id, 30, now=started_at + 29.9))
        self.assertEqual(db.get_job(job_id)["status"], "running")

        with self.assertLogs("db", level="WARNING"):
            self.assertTrue(db.time_out_job(job_id, 30, now=started_at + 30))
        job = db.get_job(job_id)
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["failure_reason"], db.JOB_EXECUTION_TIMEOUT)
        self.assertTrue(db.job_writer_active(job_id))

    def test_time_spent_in_the_queue_does_not_count_as_execution(self) -> None:
        job_id = db.enqueue_job("embed", {})
        db._JOBS[job_id]["_queued_at"] -= 3600  # long wait in the queue
        db._JOBS[job_id]["created_at"] = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        db.lease_job("worker-a", ["embed"])

        self.assertFalse(db.time_out_job(job_id, 30))
        self.assertEqual(db.get_job(job_id)["status"], "running")

    def test_late_result_after_timeout_is_dropped(self) -> None:
        job_id = db.enqueue_job("embed", {})
        started_at = db.lease_job("worker-a", ["embed"])["_started_at"]
        with self.assertLogs("db", level="WARNING"):
            db.time_out_job(job_id, 30, now=started_at + 31)

        with self.assertLogs("db", level="WARNING") as logs:
            db.complete_job(job_id, {"late": True})
            db.fail_job(job_id, "late retryable error", is_fatal=False)
        job = db.get_job(job_id)
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["failure_reason"], db.JOB_EXECUTION_TIMEOUT)
        self.assertIsNone(job["result"])
        self.assertTrue(any("job_deadline_final" in line for line in logs.output))

    def test_finished_job_is_never_timed_out(self) -> None:
        job_id = db.enqueue_job("embed", {})
        started_at = db.lease_job("worker-a", ["embed"])["_started_at"]
        db.complete_job(job_id, {"ok": True})

        self.assertFalse(db.time_out_job(job_id, 30, now=started_at + 3600))
        self.assertEqual(db.get_job(job_id)["status"], "completed")
        self.assertFalse(db.job_writer_active(job_id))


class ArtifactCleanupTests(_JobsIsolation):
    def _old_file(self, directory: Path, name: str) -> Path:
        path = directory / name
        path.write_bytes(b"partial")
        old = time.time() - 7 * 86_400
        os.utime(path, (old, old))
        return path

    def test_artifacts_are_kept_while_the_timed_out_process_is_still_writing(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            job_id = db.enqueue_job("embed", {})
            started_at = db.lease_job("worker-a", ["embed"])["_started_at"]
            with self.assertLogs("db", level="WARNING"):
                db.time_out_job(job_id, 30, now=started_at + 31)
            db._JOBS[job_id]["failed_at"] = (datetime.now(UTC) - timedelta(days=7)).isoformat()
            output = self._old_file(directory, f"job_{job_id}_output.mp4")

            # Terminal and far past the TTL, but its process has not stopped.
            self.assertEqual(sweep_job_files(directory, ttl_seconds=60), 0)
            self.assertTrue(output.exists())

            self.assertTrue(db.release_job_writer(job_id))
            self.assertEqual(sweep_job_files(directory, ttl_seconds=60), 1)
            self.assertFalse(output.exists())

    def test_release_without_a_deadline_reports_nothing_to_clean(self) -> None:
        job_id = db.enqueue_job("embed", {})
        db.lease_job("worker-a", ["embed"])
        db.complete_job(job_id, {"ok": True})

        self.assertFalse(db.release_job_writer(job_id))


class ConcurrencyTests(_JobsIsolation):
    def test_timeout_and_completion_racing_leave_one_consistent_outcome(self) -> None:
        for _ in range(50):
            db._JOBS.clear()
            job_id = db.enqueue_job("embed", {})
            started_at = db.lease_job("worker-a", ["embed"])["_started_at"]
            barrier = threading.Barrier(2)

            def complete(barrier=barrier, job_id=job_id) -> None:
                barrier.wait()
                db.complete_job(job_id, {"r": 1})

            def time_out(barrier=barrier, job_id=job_id, started_at=started_at) -> None:
                barrier.wait()
                db.time_out_job(job_id, 30, now=started_at + 31)

            threads = [threading.Thread(target=complete), threading.Thread(target=time_out)]
            with patch.object(db.logger, "warning"):  # either side may win the race
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(2.0)

            job = db.get_job(job_id)
            if job["status"] == "completed":
                self.assertEqual(job["result"], {"r": 1})
                self.assertNotIn("failure_reason", job)
                self.assertFalse(db.job_writer_active(job_id))
            else:
                self.assertEqual(job["failure_reason"], db.JOB_EXECUTION_TIMEOUT)
                self.assertIsNone(job["result"])
                self.assertTrue(db.job_writer_active(job_id))


class WorkerDeadlineTests(_JobsIsolation):
    """End-to-end through ``run_worker`` (skipped when ``worker`` cannot import)."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            import worker  # noqa: F401
        except ImportError as exc:  # baseline import errors on main
            raise unittest.SkipTest(f"worker module not importable: {exc}")

    def test_execution_timeout_fails_job_and_cleans_output_after_the_writer_stops(self) -> None:
        import worker

        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "out.mp4"
            stop_event = threading.Event()
            watchdog = threading.Timer(5.0, stop_event.set)  # never hang the suite
            watchdog.start()
            self.addCleanup(watchdog.cancel)
            writer_running = threading.Event()
            writer_may_finish = threading.Event()
            seen_while_writing = {}

            def slow_embed(job):
                output.write_bytes(b"partial")
                writer_running.set()
                writer_may_finish.wait(3.0)
                return {"late": True}

            def observe_then_stop() -> None:
                deadline = time.time() + 3.0
                while time.time() < deadline:
                    job = db.get_job(job_id)
                    if job and job.get("failure_reason") == db.JOB_EXECUTION_TIMEOUT:
                        seen_while_writing["output_exists"] = output.exists()
                        seen_while_writing["writer_active"] = db.job_writer_active(job_id)
                        break
                    time.sleep(0.02)
                writer_may_finish.set()
                time.sleep(0.3)
                stop_event.set()

            job_id = db.enqueue_job("embed", {})
            observer = threading.Thread(target=observe_then_stop)
            observer.start()
            with patch.object(worker, "init_db"), \
                    patch.object(worker, "process_embed", side_effect=slow_embed), \
                    patch.object(worker, "get_job_output_path", return_value=output), \
                    patch.object(worker, "heartbeat_loop"), \
                    patch.object(worker, "tx_verification_loop"), \
                    patch.object(worker, "run_indexer_loop"), \
                    patch.object(worker, "sweep_job_files"):
                worker.run_worker(
                    stop_event=stop_event,
                    grace_period_seconds=0.1,
                    execution_timeout_seconds=0.2,
                )
            observer.join(5.0)

        job = db.get_job(job_id)
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["failure_reason"], db.JOB_EXECUTION_TIMEOUT)
        self.assertIsNone(job["result"])
        self.assertEqual(seen_while_writing, {"output_exists": True, "writer_active": True})
        self.assertFalse(output.exists())
        self.assertFalse(db.job_writer_active(job_id))

    def test_late_timed_out_thread_does_not_touch_the_next_job(self) -> None:
        import worker

        stop_event = threading.Event()
        watchdog = threading.Timer(5.0, stop_event.set)  # never hang the suite
        watchdog.start()
        self.addCleanup(watchdog.cancel)
        heartbeat_stops = {}
        zombie_may_finish = threading.Event()
        zombie_done = threading.Event()
        second = {}

        def fake_heartbeat_loop(job_id, hb_stop_event, *args):
            heartbeat_stops[job_id] = hb_stop_event

        def embed(job):
            if job["id"] == first_id:
                zombie_may_finish.wait(3.0)  # still running after its timeout
                return {"late": True}
            # Second job: let the timed-out thread of the first job return now.
            zombie_may_finish.set()
            zombie_done.wait(3.0)
            second["own_heartbeat_stopped"] = heartbeat_stops[job["id"]].is_set()
            stop_event.set()
            return {"second": True}

        real_release = db.release_job_writer

        def release_and_signal(job_id):
            released = real_release(job_id)
            if job_id == first_id:
                zombie_done.set()
            return released

        first_id = db.enqueue_job("embed", {})
        second_id = db.enqueue_job("embed", {})
        with patch.object(worker, "init_db"), \
                patch.object(worker, "process_embed", side_effect=embed), \
                patch.object(worker, "heartbeat_loop", side_effect=fake_heartbeat_loop), \
                patch.object(worker, "release_job_writer", side_effect=release_and_signal), \
                patch.object(worker, "_remove_partial_output"), \
                patch.object(worker, "tx_verification_loop"), \
                patch.object(worker, "run_indexer_loop"), \
                patch.object(worker, "sweep_job_files"):
            worker.run_worker(
                stop_event=stop_event,
                grace_period_seconds=2.0,
                execution_timeout_seconds=0.2,
            )

        self.assertEqual(db.get_job(first_id)["failure_reason"], db.JOB_EXECUTION_TIMEOUT)
        self.assertEqual(db.get_job(second_id)["status"], "completed")
        self.assertEqual(db.get_job(second_id)["result"], {"second": True})
        # The first job's late thread must stop its own heartbeat, not the second job's.
        self.assertEqual(second, {"own_heartbeat_stopped": False})


if __name__ == "__main__":
    unittest.main()
