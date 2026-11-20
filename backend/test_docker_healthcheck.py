"""Regression coverage for Docker HEALTHCHECK instructions.

Validates that backend and frontend Dockerfiles declare a HEALTHCHECK that
probes the public liveness surfaces (/health and SPA root) without embedding
secrets or real media paths.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

BACKEND_DOCKERFILE = Path(__file__).resolve().parent / "Dockerfile"
FRONTEND_DOCKERFILE = Path(__file__).resolve().parent.parent / "frontend" / "Dockerfile"

HEALTHCHECK_RE = re.compile(
    r"^HEALTHCHECK\b(?P<flags>.*?)\s+CMD\s+(?P<cmd>.+)$",
    re.MULTILINE | re.DOTALL,
)


def _parse_healthchecks(text: str) -> list[dict[str, str]]:
    return [
        {"flags": m.group("flags").strip(), "cmd": m.group("cmd").strip()}
        for m in HEALTHCHECK_RE.finditer(text)
    ]


class TestDockerHealthcheck(unittest.TestCase):
    def test_backend_dockerfile_has_healthcheck_probing_health(self):
        text = BACKEND_DOCKERFILE.read_text(encoding="utf-8")
        checks = _parse_healthchecks(text)
        self.assertEqual(len(checks), 1, "backend Dockerfile must declare exactly one HEALTHCHECK")
        cmd = checks[0]["cmd"]
        self.assertIn("/health", cmd)
        self.assertNotIn("/ready", cmd)
        self.assertIn("127.0.0.1:5050", cmd)
        self.assertIn("--interval=", checks[0]["flags"] + " " + text)
        # Privacy: no credentials, media paths, or private-key material in the probe.
        lowered = cmd.lower()
        for banned in ("password", "secret", "private_key", "witness", ".mp4", "database_url"):
            self.assertNotIn(banned, lowered)

    def test_frontend_dockerfile_has_healthcheck_probing_root(self):
        text = FRONTEND_DOCKERFILE.read_text(encoding="utf-8")
        checks = _parse_healthchecks(text)
        self.assertEqual(len(checks), 1, "frontend Dockerfile must declare exactly one HEALTHCHECK")
        cmd = checks[0]["cmd"]
        self.assertIn("127.0.0.1:8080", cmd)
        self.assertTrue("wget" in cmd or "curl" in cmd)

    def test_missing_healthcheck_is_detected(self):
        self.assertEqual(_parse_healthchecks("FROM scratch\nCMD [\"true\"]\n"), [])

    def test_malformed_healthcheck_without_cmd_ignored(self):
        # HEALTHCHECK without CMD is invalid Docker — parser must not invent a pass.
        self.assertEqual(_parse_healthchecks("HEALTHCHECK --interval=30s\n"), [])

    def test_oversized_probe_url_rejected_by_convention(self):
        # Boundary: probe command should stay small / URL-only (no huge payloads).
        text = BACKEND_DOCKERFILE.read_text(encoding="utf-8")
        checks = _parse_healthchecks(text)
        self.assertLess(len(checks[0]["cmd"]), 240)


if __name__ == "__main__":
    unittest.main()
