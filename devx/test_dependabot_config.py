"""Tests for devx/dependabot_config.py.

Coverage:
  Positive: canonical .github/dependabot.yml validates cleanly.
  Negative: each validation rule fires on invalid configurations.
  Boundary: schedule intervals, open PR limits, file size.
  Security/Privacy: sensitive credential patterns in config files are caught.
"""
from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path

# Make devx/ importable when run from the repo root or the devx/ directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import dependabot_config as dc


def _minimal_valid_config() -> dict:
    """Smallest valid dependabot configuration meeting repository policy."""
    return {
        "version": 2,
        "updates": [
            {
                "package-ecosystem": "npm",
                "directory": "/frontend",
                "schedule": {"interval": "weekly"},
                "open-pull-requests-limit": 5,
                "groups": {
                    "patch-dependencies": {
                        "patterns": ["*"],
                        "exclude-patterns": ["@stellar/*", "@noir-lang/*"],
                        "update-types": ["patch"],
                    },
                    "stellar-dependencies": {"patterns": ["@stellar/*"]},
                    "proof-system-dependencies": {"patterns": ["@noir-lang/*"]},
                },
            },
            {
                "package-ecosystem": "npm",
                "directory": "/cli",
                "schedule": {"interval": "weekly"},
                "open-pull-requests-limit": 5,
                "groups": {
                    "patch-dependencies": {
                        "patterns": ["*"],
                        "exclude-patterns": ["@stellar/*"],
                        "update-types": ["patch"],
                    },
                    "stellar-dependencies": {"patterns": ["@stellar/*"]},
                },
            },
            {
                "package-ecosystem": "pip",
                "directory": "/backend",
                "schedule": {"interval": "weekly"},
                "open-pull-requests-limit": 5,
                "groups": {
                    "patch-dependencies": {
                        "patterns": ["*"],
                        "update-types": ["patch"],
                    },
                },
            },
            {
                "package-ecosystem": "cargo",
                "directory": "/contracts",
                "schedule": {"interval": "weekly"},
                "open-pull-requests-limit": 5,
                "groups": {
                    "patch-dependencies": {
                        "patterns": ["*"],
                        "exclude-patterns": ["soroban-*", "stellar-*"],
                        "update-types": ["patch"],
                    },
                    "stellar-soroban-dependencies": {"patterns": ["soroban-*"]},
                },
            },
            {
                "package-ecosystem": "github-actions",
                "directory": "/",
                "schedule": {"interval": "weekly"},
                "open-pull-requests-limit": 5,
                "groups": {
                    "patch-dependencies": {
                        "patterns": ["*"],
                        "update-types": ["patch"],
                    },
                },
            },
        ],
    }


class TestDependabotConfigPositive(unittest.TestCase):

    def test_canonical_file(self):
        canonical_path = Path(__file__).resolve().parent.parent / ".github" / "dependabot.yml"
        self.assertTrue(canonical_path.is_file(), f"canonical file missing: {canonical_path}")
        exit_code = dc.check_file(canonical_path)
        self.assertEqual(exit_code, 0)

    def test_minimal_valid_structure(self):
        findings = dc.validate_dependabot_config(_minimal_valid_config())
        self.assertEqual(findings, [])


class TestDependabotConfigNegative(unittest.TestCase):

    def test_non_dict_root(self):
        findings = dc.validate_dependabot_config("string")
        self.assertIn("root must be a mapping (dict)", findings)

    def test_invalid_version(self):
        cfg = _minimal_valid_config()
        cfg["version"] = 1
        findings = dc.validate_dependabot_config(cfg)
        self.assertTrue(any("version must be 2" in f for f in findings))

    def test_missing_updates_list(self):
        cfg = _minimal_valid_config()
        cfg["updates"] = "not-a-list"
        findings = dc.validate_dependabot_config(cfg)
        self.assertTrue(any("`updates` must be a list" in f for f in findings))

    def test_missing_required_surface(self):
        cfg = _minimal_valid_config()
        cfg["updates"] = [
            u for u in cfg["updates"]
            if not (u.get("package-ecosystem") == "cargo" and u.get("directory") == "/contracts")
        ]
        findings = dc.validate_dependabot_config(cfg)
        self.assertTrue(any("ecosystem=cargo directory=/contracts" in f for f in findings))

    def test_unsupported_interval(self):
        cfg = _minimal_valid_config()
        cfg["updates"][0]["schedule"]["interval"] = "daily"
        findings = dc.validate_dependabot_config(cfg)
        self.assertTrue(any("interval must be one of" in f for f in findings))

    def test_missing_schedule(self):
        cfg = _minimal_valid_config()
        del cfg["updates"][0]["schedule"]
        findings = dc.validate_dependabot_config(cfg)
        self.assertTrue(any("missing `schedule` mapping" in f for f in findings))

    def test_invalid_pr_limit(self):
        cfg = _minimal_valid_config()
        cfg["updates"][0]["open-pull-requests-limit"] = 99
        findings = dc.validate_dependabot_config(cfg)
        self.assertTrue(any("open-pull-requests-limit" in f for f in findings))

    def test_missing_patch_group(self):
        cfg = _minimal_valid_config()
        cfg["updates"][2]["groups"] = {
            "all": {"patterns": ["*"], "update-types": ["major"]}
        }
        findings = dc.validate_dependabot_config(cfg)
        self.assertTrue(any("must configure a group for patch updates" in f for f in findings))

    def test_missing_stellar_isolation_in_frontend(self):
        cfg = _minimal_valid_config()
        cfg["updates"][0]["groups"] = {
            "patch-dependencies": {
                "patterns": ["*"],
                "update-types": ["patch"],
            }
        }
        findings = dc.validate_dependabot_config(cfg)
        self.assertTrue(any("Stellar dependencies must be excluded" in f for f in findings))

    def test_missing_noir_isolation_in_frontend(self):
        cfg = _minimal_valid_config()
        cfg["updates"][0]["groups"] = {
            "patch-dependencies": {
                "patterns": ["*"],
                "exclude-patterns": ["@stellar/*"],
                "update-types": ["patch"],
            },
            "stellar-dependencies": {"patterns": ["@stellar/*"]},
        }
        findings = dc.validate_dependabot_config(cfg)
        self.assertTrue(any("Noir and proof-system dependencies must be excluded" in f for f in findings))

    def test_missing_soroban_isolation_in_contracts(self):
        cfg = _minimal_valid_config()
        cfg["updates"][3]["groups"] = {
            "patch-dependencies": {
                "patterns": ["*"],
                "update-types": ["patch"],
            }
        }
        findings = dc.validate_dependabot_config(cfg)
        self.assertTrue(any("Soroban / Stellar contract dependencies must be excluded" in f for f in findings))


class TestDependabotConfigFileIO(unittest.TestCase):

    def test_file_not_found(self):
        self.assertEqual(dc.check_file(Path("/nonexistent/file.yml")), 2)

    def test_invalid_yaml(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as tf:
            tf.write("version: [unclosed list")
            tf_path = Path(tf.name)
        try:
            self.assertEqual(dc.check_file(tf_path), 3)
        finally:
            tf_path.unlink(missing_ok=True)

    def test_sensitive_credential_caught(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as tf:
            tf.write("api_token: secret12345678\nversion: 2\n")
            tf_path = Path(tf.name)
        try:
            self.assertEqual(dc.check_file(tf_path), 1)
        finally:
            tf_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
