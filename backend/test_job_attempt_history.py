"""Bounded per-job worker attempt history (issue #1107)."""

import json
import threading
import time
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import db


class _JobsIsolation(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = dict(db._JOBS)
        db._JOBS.clear()

    def tearDown(self) -> None:
        db._JOBS.clear()
        db._JOBS.update(self._saved)


class AttemptHistoryTests(_JobsIsolation):
    def test_lease_progress_and_completion_are_recorded(self) -> None:
        job_id = db.enqueue_job("embed", {})
        self.assertNotIn("attempts", db.get_job(job_id))

        leased = db.lease_job("worker-a", ["embed"])
        db.report_job_progress(job_id, "embedding", 42.04, now=100.0)
        db.complete_job(job_id, {"ok": True})

        self.assertEqual(len(leased["attempts"]), 1)
        (attempt,) = db.get_job(job_id)["attempts"]
        self.assertEqual(attempt["attempt"], 1)
        self.assertEqual(attempt["worker_id"], "worker-a")
        self.assertEqual(attempt["outcome"], db.ATTEMPT_COMPLETED)
        self.assertIsNone(attempt["reason"])
        self.assertEqual(attempt["progress"], {"phase": "embedding", "percent": 42.0})
        self.assertIsNotNone(attempt["leased_at"])
        self.assertIsNotNone(attempt["ended_at"])

    def test_release_and_retry_open_a_new_attempt(self) -> None:
        job_id = db.enqueue_job("embed", {})
        db.lease_job("worker-a", ["embed"])
        db.report_job_progress(job_id, "hashing_source", now=100.0)
        db.fail_job(job_id, "Worker shutdown grace period exceeded", reason="shutdown_grace_exceeded")
        db.lease_job("worker-b", ["embed"])
        db.fail_job(job_id, "boom", is_fatal=True, reason="ValueError")

        first, second = db.get_job(job_id)["attempts"]
        self.assertEqual(
            (first["attempt"], first["worker_id"], first["outcome"], first["reason"]),
            (1, "worker-a", db.ATTEMPT_RELEASED, "shutdown_grace_exceeded"),
        )
        self.assertEqual(first["progress"], {"phase": "hashing_source", "percent": None})
        self.assertEqual(
            (second["attempt"], second["worker_id"], second["outcome"], second["reason"]),
            (2, "worker-b", db.ATTEMPT_FAILED, "ValueError"),
        )
        # Progress of the second attempt is its own, not the first one's.
        self.assertIsNone(second["progress"])

    def test_stale_heartbeat_reclaim_closes_the_attempt_as_released(self) -> None:
        job_id = db.enqueue_job("embed", {})
        leased = datetime(2030, 1, 1, tzinfo=UTC)
        db.lease_job("worker-a", ["embed"], now=leased)
        db.reclaim_stale_jobs(now=leased + timedelta(seconds=301))
        db.lease_job("worker-b", ["embed"], now=leased + timedelta(seconds=302))

        first, second = db.get_job(job_id)["attempts"]
        self.assertEqual(
            (first["worker_id"], first["outcome"], first["reason"]),
            ("worker-a", db.ATTEMPT_RELEASED, db.STALE_HEARTBEAT_REASON),
        )
        self.assertIsNotNone(first["ended_at"])
        self.assertEqual((second["attempt"], second["outcome"]), (2, None))

    def test_history_is_bounded_and_keeps_counting(self) -> None:
        job_id = db.enqueue_job("embed", {})
        total = db.JOB_ATTEMPT_HISTORY_LIMIT + 3
        for _ in range(total):
            db.lease_job("worker-a", ["embed"])
            db.fail_job(job_id, "transient", reason="TimeoutError")

        attempts = db.get_job(job_id)["attempts"]
        self.assertEqual(len(attempts), db.JOB_ATTEMPT_HISTORY_LIMIT)
        self.assertEqual(attempts[0]["attempt"], total - db.JOB_ATTEMPT_HISTORY_LIMIT + 1)
        self.assertEqual(attempts[-1]["attempt"], total)

    def test_history_at_exactly_the_limit_drops_nothing(self) -> None:
        job_id = db.enqueue_job("embed", {})
        for _ in range(db.JOB_ATTEMPT_HISTORY_LIMIT):
            db.lease_job("worker-a", ["embed"])
            db.fail_job(job_id, "transient")

        attempts = db.get_job(job_id)["attempts"]
        self.assertEqual([a["attempt"] for a in attempts], list(range(1, db.JOB_ATTEMPT_HISTORY_LIMIT + 1)))

    def test_writes_without_an_open_attempt_leave_history_untouched(self) -> None:
        job_id = db.enqueue_job("embed", {})
        db.lease_job("worker-a", ["embed"])
        db.complete_job(job_id, {"ok": True})
        before = [dict(a) for a in db.get_job(job_id)["attempts"]]

        db.complete_job(job_id, {"again": True})
        db.fail_job(job_id, "late", reason="RuntimeError")

        self.assertEqual(db.get_job(job_id)["attempts"], before)

    def test_leased_copy_does_not_alias_the_stored_history(self) -> None:
        job_id = db.enqueue_job("embed", {})
        leased = db.lease_job("worker-a", ["embed"])
        leased["attempts"][0]["outcome"] = "tampered"

        self.assertIsNone(db.get_job(job_id)["attempts"][0]["outcome"])


class AttemptPrivacyTests(_JobsIsolation):
    SECRET_PATH = "/srv/harpocrates/private/uploads/job_7_input.mp4"
    PROOF_SECRET = "credential-secret-0xDEADBEEF"
    MEDIA = b"\x00\x00\x00\x18ftypmp42"

    def test_history_never_contains_payload_paths_or_secrets(self) -> None:
        job_id = db.enqueue_job(
            "silent_witness",
            {
                "filename": "holiday.mp4",
                "input_path": self.SECRET_PATH,
                "credential_secret": self.PROOF_SECRET,
                "media": self.MEDIA.hex(),
            },
        )
        db.lease_job("worker-a", ["silent_witness"])
        db.report_job_progress(job_id, "generating_proof", now=100.0)
        # Error text quoting a private path and a secret, plus a reason with spaces and slashes.
        db.fail_job(
            job_id,
            f"open({self.SECRET_PATH}) failed with {self.PROOF_SECRET}",
            reason=f"FileNotFoundError: {self.SECRET_PATH}",
        )
        db.lease_job("worker-b", ["silent_witness"])
        db.fail_job(job_id, f"bad secret {self.PROOF_SECRET}", is_fatal=True, reason="ValueError")

        attempts = db.get_job(job_id)["attempts"]
        serialized = json.dumps(attempts)
        for forbidden in (self.SECRET_PATH, "/srv/", self.PROOF_SECRET, "holiday.mp4", self.MEDIA.hex()):
            self.assertNotIn(forbidden, serialized)
        allowed_keys = {"attempt", "worker_id", "leased_at", "ended_at", "outcome", "reason", "progress"}
        for attempt in attempts:
            self.assertEqual(set(attempt), allowed_keys)
        # A reason that is not a plain code is dropped, not cleaned: nothing of the path survives.
        self.assertIsNone(attempts[0]["reason"])
        self.assertNotIn("harpocrates", serialized)
        self.assertNotIn("job_7_input", serialized)
        self.assertEqual(attempts[1]["reason"], "ValueError")

    def test_reason_codes_are_short_and_never_free_text(self) -> None:
        for rejected in (None, 42, "", " /:() ", "Value Error", "a/b", "x" * 65, "1Error", "err\nX"):
            with self.subTest(value=rejected):
                self.assertIsNone(db._attempt_code(rejected))
        for accepted in ("ValueError", "shutdown_grace_exceeded", "x" * 64):
            with self.subTest(value=accepted):
                self.assertEqual(db._attempt_code(accepted), accepted)

    def test_worker_id_that_is_not_a_plain_code_is_not_recorded(self) -> None:
        job_id = db.enqueue_job("embed", {})
        db.lease_job("worker /srv/private", ["embed"])

        self.assertIsNone(db.get_job(job_id)["attempts"][0]["worker_id"])


class WorkerAttemptTests(_JobsIsolation):
    """End-to-end through ``run_worker`` (skipped when ``worker`` cannot import)."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            import worker  # noqa: F401
        except ImportError as exc:  # baseline import errors on main
            raise unittest.SkipTest(f"worker module not importable: {exc}")

    def _run(self, embed, *, grace: float = 2.0) -> None:
        import worker

        stop_event = threading.Event()
        watchdog = threading.Timer(5.0, stop_event.set)  # never hang the suite
        watchdog.start()
        self.addCleanup(watchdog.cancel)
        with (
            patch.object(worker, "init_db"),
            patch.object(worker, "process_embed", side_effect=lambda job: embed(job, stop_event)),
            patch.object(worker, "heartbeat_loop"),
            patch.object(worker, "tx_verification_loop"),
            patch.object(worker, "run_indexer_loop"),
            patch.object(worker, "sweep_job_files"),
        ):
            worker.run_worker(stop_event=stop_event, grace_period_seconds=grace)

    def test_worker_records_error_type_not_error_text(self) -> None:
        import worker

        def embed(job, stop_event):
            stop_event.set()
            raise ValueError("cannot read /srv/private/job_1_input.mp4")

        job_id = db.enqueue_job("embed", {})
        self._run(embed)

        (attempt,) = db.get_job(job_id)["attempts"]
        self.assertEqual(attempt["worker_id"], worker.WORKER_ID)
        self.assertEqual((attempt["outcome"], attempt["reason"]), (db.ATTEMPT_FAILED, "ValueError"))
        self.assertNotIn("/srv/private", json.dumps(attempt))

    def test_worker_records_release_on_shutdown_grace(self) -> None:
        def embed(job, stop_event):
            stop_event.set()
            time.sleep(0.4)
            return {"late": True}

        job_id = db.enqueue_job("embed", {})
        self._run(embed, grace=0.1)

        attempt = db.get_job(job_id)["attempts"][0]
        self.assertEqual(
            (attempt["outcome"], attempt["reason"]),
            (db.ATTEMPT_RELEASED, "shutdown_grace_exceeded"),
        )


if __name__ == "__main__":
    unittest.main()
