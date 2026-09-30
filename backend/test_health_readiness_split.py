"""HTTP-level coverage for the liveness/readiness split (issue #282).

`GET /health` is liveness: it answers 200 whenever the process is up, whatever
the dependencies are doing. `GET /ready` is readiness: it answers 503 while a
critical dependency is down, and 200 once the dependency is healthy again.

The existing suite only asserted `response.status_code in {200, 503}` for
`/ready`, which cannot fail when the split regresses — these tests make the
split itself observable.
"""

from __future__ import annotations

import contextlib
import os
import time
import unittest
from unittest.mock import patch

import app as app_module
from readiness import ReadinessManager

_ENV_KEYS = ("APP_ENV", "DATABASE_URL", "NOIR_WORKER_ENABLED")


@contextlib.contextmanager
def _client_with_dependencies(*, database_ok: bool, video_tools_ok: bool):
    """Fresh app whose critical readiness probes are forced to a known state.

    `create_app` binds the probes into the ReadinessManager at construction
    time, so the patch has to be active while the app is built. A fresh app is
    required per case because the manager caches probe results for 5s.
    """
    saved = {key: os.environ.get(key) for key in _ENV_KEYS}
    os.environ.setdefault("APP_ENV", "testing")
    os.environ.setdefault("DATABASE_URL", "")
    os.environ.setdefault("NOIR_WORKER_ENABLED", "false")

    try:
        with patch.object(app_module, "check_db", return_value=database_ok), patch.object(
            app_module, "video_tooling_ready", return_value=video_tools_ok
        ):
            yield app_module.create_app().test_client()
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class HealthIsLivenessTest(unittest.TestCase):
    def test_health_stays_200_when_every_critical_dependency_is_down(self):
        with _client_with_dependencies(database_ok=False, video_tools_ok=False) as client:
            response = client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["ok"])
        self.assertEqual(response.json["service"], "harpocrates-stego")

    def test_health_does_not_leak_dependency_status(self):
        # Liveness must stay a process check; dependency reporting belongs to
        # /ready, otherwise a liveness probe would start failing per dependency.
        with _client_with_dependencies(database_ok=False, video_tools_ok=False) as client:
            payload = client.get("/health").json

        self.assertNotIn("database", payload)
        self.assertNotIn("video_tools", payload)


class ReadyIsReadinessTest(unittest.TestCase):
    def test_ready_is_503_when_a_critical_dependency_is_down(self):
        with _client_with_dependencies(database_ok=True, video_tools_ok=False) as client:
            response = client.get("/ready")

        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.json["ok"])
        self.assertEqual(response.json["video_tools"], "missing")

    def test_ready_is_503_when_the_database_dependency_is_down(self):
        with _client_with_dependencies(database_ok=False, video_tools_ok=True) as client:
            response = client.get("/ready")

        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.json["ok"])
        self.assertEqual(response.json["database"], "not_configured")

    def test_ready_is_200_when_every_critical_dependency_is_up(self):
        with _client_with_dependencies(database_ok=True, video_tools_ok=True) as client:
            response = client.get("/ready")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["ok"])
        self.assertEqual(response.json["database"], "connected")
        self.assertEqual(response.json["video_tools"], "available")

    def test_liveness_and_readiness_disagree_while_a_dependency_is_down(self):
        # The separation contract in a single assertion pair.
        with _client_with_dependencies(database_ok=False, video_tools_ok=False) as client:
            health = client.get("/health")
            ready = client.get("/ready")

        self.assertEqual(health.status_code, 200)
        self.assertEqual(ready.status_code, 503)


class ReadinessRecoveryTest(unittest.TestCase):
    """Readiness must flip both ways as a dependency fails and recovers."""

    def _manager(self, healthy: dict[str, bool]) -> ReadinessManager:
        # ttl of 0 keeps the probe fresh so each check reflects `healthy` now.
        manager = ReadinessManager(timeout_seconds=0.5, cache_ttl_seconds=0.0)
        manager.add_dependency("database", lambda: healthy["up"], critical=True)
        return manager

    def test_flips_to_ready_once_the_dependency_comes_back(self):
        healthy = {"up": False}
        manager = self._manager(healthy)

        self.assertFalse(manager.check()["ok"])

        healthy["up"] = True

        self.assertTrue(manager.check()["ok"])

    def test_flips_back_to_not_ready_when_the_dependency_fails(self):
        healthy = {"up": True}
        manager = self._manager(healthy)

        self.assertTrue(manager.check()["ok"])

        healthy["up"] = False

        self.assertFalse(manager.check()["ok"])

    def test_non_critical_dependency_does_not_block_readiness(self):
        manager = ReadinessManager(timeout_seconds=0.5, cache_ttl_seconds=0.0)
        manager.add_dependency("database", lambda: True, critical=True)
        manager.add_dependency("telemetry", lambda: False, critical=False)

        result = manager.check()

        self.assertTrue(result["ok"])
        self.assertEqual(result["telemetry"], "disconnected")

    def test_not_ready_is_reported_as_non_initializing_after_a_probe_runs(self):
        # A dependency that has been probed and failed must report a terminal
        # status, otherwise the readiness body can never explain a 503.
        manager = ReadinessManager(timeout_seconds=0.5, cache_ttl_seconds=0.0)
        manager.add_dependency("database", lambda: False, critical=True)

        result = manager.check()

        self.assertFalse(result["ok"])
        self.assertEqual(result["database"], "not_configured")

    def test_slow_dependency_stays_within_the_configured_deadline(self):
        def slow_probe() -> bool:
            time.sleep(1.0)
            return True

        manager = ReadinessManager(timeout_seconds=0.2, cache_ttl_seconds=0.0)
        manager.add_dependency("slow", slow_probe, critical=True)

        started = time.time()
        result = manager.check()
        elapsed = time.time() - started

        self.assertLess(elapsed, 0.8)
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
