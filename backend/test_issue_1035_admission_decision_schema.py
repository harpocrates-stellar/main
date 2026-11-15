from __future__ import annotations

import io
import json
import os
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as app_module  # noqa: E402
from admission import (  # noqa: E402
    ADMISSION_CATEGORY_ADMITTED,
    ADMISSION_CATEGORY_IDENTITY_QUOTA,
    ADMISSION_CATEGORY_PROCESSING_CAPACITY,
    ADMISSION_CATEGORY_QUEUE_SATURATION,
    ADMISSION_DECISION_SCHEMA,
    MAX_RETRY_AFTER_SECONDS,
    MIN_RETRY_AFTER_SECONDS,
    AdmissionController,
    build_admission_decision,
    clamp_retry_after_seconds,
)


class AdmissionDecisionSchemaUnitTests(unittest.TestCase):
    def test_distinguishes_all_categories_and_bounds_retry_guidance(self) -> None:
        self.assertEqual(clamp_retry_after_seconds(0.0), MIN_RETRY_AFTER_SECONDS)
        self.assertEqual(clamp_retry_after_seconds(-50), MIN_RETRY_AFTER_SECONDS)
        self.assertEqual(clamp_retry_after_seconds(99_999.0), MAX_RETRY_AFTER_SECONDS)
        self.assertEqual(clamp_retry_after_seconds(float("inf")), MAX_RETRY_AFTER_SECONDS)

        ok_dec = build_admission_decision("ok", timeout_seconds=5.0)
        self.assertTrue(ok_dec.admitted)
        self.assertEqual(ok_dec.category, ADMISSION_CATEGORY_ADMITTED)
        self.assertEqual(ok_dec.retry_after_seconds, 0)

        # Extreme timeout values remain bounded to [1, 300].
        id_dec = build_admission_decision("identity_limit", timeout_seconds=0.01)
        self.assertFalse(id_dec.admitted)
        self.assertEqual(id_dec.category, ADMISSION_CATEGORY_IDENTITY_QUOTA)
        self.assertEqual(id_dec.http_status, 429)
        self.assertEqual(id_dec.retry_after_seconds, 1)

        q_dec = build_admission_decision("queue_full", timeout_seconds=5000.0)
        self.assertFalse(q_dec.admitted)
        self.assertEqual(q_dec.category, ADMISSION_CATEGORY_QUEUE_SATURATION)
        self.assertEqual(q_dec.http_status, 503)
        self.assertEqual(q_dec.retry_after_seconds, MAX_RETRY_AFTER_SECONDS)

        cap_dec = build_admission_decision("timeout", timeout_seconds=5000.0)
        self.assertFalse(cap_dec.admitted)
        self.assertEqual(cap_dec.category, ADMISSION_CATEGORY_PROCESSING_CAPACITY)
        self.assertEqual(cap_dec.http_status, 503)
        self.assertEqual(cap_dec.retry_after_seconds, MAX_RETRY_AFTER_SECONDS)

    def test_controller_decisions_never_disclose_other_users(self) -> None:
        controller = AdmissionController(
            max_concurrent=1,
            max_queue=1,
            max_per_identity=1,
            timeout_seconds=0.05,
        )
        secret_peer = "secret-peer-198.51.100.77"
        d1 = controller.decide(secret_peer)
        self.assertTrue(d1.admitted)

        try:
            # Same identity hits identity_quota (429).
            same_peer = controller.decide(secret_peer)
            self.assertEqual(same_peer.category, ADMISSION_CATEGORY_IDENTITY_QUOTA)
            self.assertNotIn(secret_peer, json.dumps(same_peer.to_api_dict()))

            # Hold the single queue slot from a second secret peer while testing a third caller.
            entered_queue = threading.Event()
            q_outcomes = []

            def _queue_holder() -> None:
                entered_queue.set()
                q_outcomes.append(controller.decide("secret-peer-203.0.113.9"))

            # Use a longer timeout temporarily so queue stays full while caller-3 probes.
            controller.timeout_seconds = 0.25
            t = threading.Thread(target=_queue_holder)
            t.start()
            entered_queue.wait(timeout=1.0)
            # Spin briefly until _current_queue == 1.
            while controller._current_queue < 1 and t.is_alive():
                pass

            q_sat = controller.decide("observer-caller")
            self.assertEqual(q_sat.category, ADMISSION_CATEGORY_QUEUE_SATURATION)
            serialized_q = json.dumps(q_sat.to_api_dict())
            self.assertNotIn(secret_peer, serialized_q)
            self.assertNotIn("203.0.113.9", serialized_q)
            self.assertNotIn("observer-caller", serialized_q)

            t.join(timeout=2.0)
            self.assertEqual(len(q_outcomes), 1)
            self.assertEqual(q_outcomes[0].category, ADMISSION_CATEGORY_PROCESSING_CAPACITY)
            self.assertNotIn(secret_peer, json.dumps(q_outcomes[0].to_api_dict()))
        finally:
            controller.release(secret_peer)


class AdmissionDecisionRouteTests(unittest.TestCase):
    def _build_app(self, extra_env: dict[str, str] | None = None):
        env = {
            "RATELIMIT_ENABLED": "false",
            "MAX_CONCURRENT_REQUESTS": "1",
            "MAX_QUEUE_SIZE": "1",
            "MAX_CONCURRENT_PER_IDENTITY": "1",
            "ADMISSION_TIMEOUT_SECONDS": "200.0",
        }
        if extra_env:
            env.update(extra_env)
        with patch.dict(os.environ, env, clear=False):
            return app_module.create_app()

    def test_preflight_endpoint_and_overload_responses_follow_stable_schema(self) -> None:
        flask_app = self._build_app()
        controller: AdmissionController = flask_app.extensions["admission_controller"]
        controller.max_queue = 0
        client = flask_app.test_client()

        preflight_ok = client.get(
            "/api/stego/upload-admission",
            headers={"X-Forwarded-For": "192.0.2.10"},
        )
        self.assertEqual(preflight_ok.status_code, 200)
        p_body = preflight_ok.get_json()
        self.assertEqual(p_body["schema"], ADMISSION_DECISION_SCHEMA)
        self.assertEqual(p_body["admission"]["category"], ADMISSION_CATEGORY_ADMITTED)
        self.assertEqual(
            preflight_ok.headers["X-Upload-Admission-Schema"],
            ADMISSION_DECISION_SCHEMA,
        )

        # Hold the sole slot under another user IP; observer must see queue_saturation (503)
        # with Retry-After clamped to <= 300 and zero mention of 198.51.100.99.
        controller.acquire("198.51.100.99")
        try:
            rejected_other = client.post(
                "/api/stego/embed",
                headers={"X-Forwarded-For": "192.0.2.10"},
                data={"video": (io.BytesIO(b"synthetic"), "v.mp4")},
                content_type="multipart/form-data",
            )
            self.assertEqual(rejected_other.status_code, 503)
            r_json = rejected_other.get_json()
            self.assertEqual(r_json["schema"], ADMISSION_DECISION_SCHEMA)
            self.assertEqual(
                r_json["admission"]["category"],
                ADMISSION_CATEGORY_QUEUE_SATURATION,
            )
            self.assertEqual(r_json["reason"], "queue_full")
            self.assertEqual(
                r_json["admission"]["retryAfterSeconds"],
                MAX_RETRY_AFTER_SECONDS,
            )
            self.assertEqual(rejected_other.headers["Retry-After"], "300")
            self.assertNotIn("198.51.100.99", rejected_other.get_data(as_text=True))

            # Same user hitting identity_quota receives 429 identity_quota.
            rejected_same = client.post(
                "/api/stego/embed",
                headers={"X-Forwarded-For": "198.51.100.99"},
                data={"video": (io.BytesIO(b"synthetic"), "v.mp4")},
                content_type="multipart/form-data",
            )
            self.assertEqual(rejected_same.status_code, 429)
            s_json = rejected_same.get_json()
            self.assertEqual(
                s_json["admission"]["category"],
                ADMISSION_CATEGORY_IDENTITY_QUOTA,
            )
            self.assertEqual(s_json["reason"], "identity_limit")
            self.assertLessEqual(
                int(rejected_same.headers["Retry-After"]),
                MAX_RETRY_AFTER_SECONDS,
            )
            self.assertNotIn("198.51.100.99", rejected_same.get_data(as_text=True))
        finally:
            controller.release("198.51.100.99")


if __name__ == "__main__":
    unittest.main()
