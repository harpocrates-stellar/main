"""Tests for per-domain blueprint registration and URL map snapshot conformance."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import app as app_module

BACKEND_DIR = Path(__file__).resolve().parent
SNAPSHOT_PATH = BACKEND_DIR / "url_map_snapshot.json"

EXPECTED_BLUEPRINTS = {
    "stego",
    "proofs",
    "lineage",
    "jobs",
    "time_attestation",
    "c2pa",
    "schemas",
}


def _extract_live_url_map(flask_app) -> dict[str, list[str]]:
    routes: dict[str, set[str]] = {}
    for rule in flask_app.url_map.iter_rules():
        if rule.endpoint == "static" or rule.rule.startswith("/__test_"):
            continue
        routes.setdefault(rule.rule, set()).update(
            set(rule.methods) - {"HEAD", "OPTIONS"}
        )
    return {rule: sorted(methods) for rule, methods in sorted(routes.items())}


class UrlMapSnapshotTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = app_module.app

    def test_url_map_matches_committed_snapshot(self) -> None:
        self.assertTrue(
            SNAPSHOT_PATH.exists(),
            f"Committed URL map snapshot missing at {SNAPSHOT_PATH}",
        )
        committed = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
        live = _extract_live_url_map(self.app)
        self.assertEqual(live, committed)

    def test_expected_domain_blueprints_are_registered(self) -> None:
        self.assertEqual(set(self.app.blueprints.keys()), EXPECTED_BLUEPRINTS)

    def test_app_py_stays_under_600_lines(self) -> None:
        app_py = BACKEND_DIR / "app.py"
        line_count = len(app_py.read_text(encoding="utf-8").splitlines())
        self.assertLess(
            line_count,
            600,
            f"backend/app.py has {line_count} lines (must be under 600)",
        )


if __name__ == "__main__":
    unittest.main()
