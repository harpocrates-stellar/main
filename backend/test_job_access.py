"""Job endpoints are capability-scoped: sequential ids alone reveal nothing."""

from __future__ import annotations

import unittest

import db


class JobAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        import app as app_module

        self.app = app_module.create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.job_id = db.enqueue_job(
            "silent_witness",
            {
                "video_hash": "ab" * 32,
                "credential_secret": "12345",
                "nullifier_secret": "67890",
            },
        )
        self.token = db.get_job_access_token(self.job_id)

    def tearDown(self) -> None:
        db._JOBS.pop(self.job_id, None)

    def test_enumerating_ids_without_token_yields_nothing(self) -> None:
        for job_id in range(max(1, self.job_id - 2), self.job_id + 3):
            self.assertEqual(self.client.get(f"/api/jobs/{job_id}").status_code, 404)
            self.assertEqual(
                self.client.get(f"/api/jobs/{job_id}/download").status_code, 404
            )

    def test_wrong_token_is_rejected(self) -> None:
        response = self.client.get(
            f"/api/jobs/{self.job_id}", headers={"X-Job-Token": "not-the-token"}
        )
        self.assertEqual(response.status_code, 404)

    def test_cancel_requires_token(self) -> None:
        self.assertEqual(self.client.post(f"/api/jobs/{self.job_id}/cancel").status_code, 400)
        self.assertEqual(db.get_job(self.job_id)["status"], "pending")
        response = self.client.post(
            f"/api/jobs/{self.job_id}/cancel", headers={"X-Job-Token": self.token}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(db.get_job(self.job_id)["status"], "cancelled")

    def test_status_view_never_contains_secrets(self) -> None:
        db.complete_job(self.job_id, {"metadata": {"name": "private"}, "proof": "p"})
        response = self.client.get(
            f"/api/jobs/{self.job_id}", headers={"X-Job-Token": self.token}
        )
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        for secret in ("12345", "67890", "credential_secret", "private", self.token, "payload"):
            self.assertNotIn(secret, body)
        job = response.get_json()["job"]
        self.assertEqual(job["id"], self.job_id)
        self.assertEqual(job["status"], "completed")
        self.assertTrue(job["result_available"])


if __name__ == "__main__":
    unittest.main()
