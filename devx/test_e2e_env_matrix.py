from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import e2e_env_matrix as matrix


class E2EEnvMatrixTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture_path = (
            Path(__file__).resolve().parent
            / "fixtures"
            / "e2e-env-matrix"
            / "profiles.json"
        )
        self.fixture = matrix.load_profiles(self.fixture_path)

    def test_fixture_loads_and_has_core_and_adversarial(self) -> None:
        self.assertEqual(self.fixture["schema_version"], 1)
        groups = {p["group"] for p in self.fixture["profiles"]}
        self.assertEqual(groups, {"core", "adversarial"})
        self.assertGreaterEqual(len(self.fixture["profiles"]), 5)

    def test_select_profiles_group_filter(self) -> None:
        core = matrix.select_profiles(self.fixture, "core")
        self.assertTrue(core)
        self.assertTrue(all(p["group"] == "core" for p in core))
        with self.assertRaisesRegex(matrix.MatrixError, "no profiles"):
            matrix.select_profiles(self.fixture, "missing")

    def test_privacy_safe_rejects_secret_echo(self) -> None:
        with self.assertRaisesRegex(matrix.MatrixError, "sensitive"):
            matrix.assert_privacy_safe(
                {"error": {"message": "credentialSecret=abc"}},
                context="unit",
            )
        # Safe envelope must pass.
        matrix.assert_privacy_safe(
            {"ok": False, "error": {"code": "VALIDATION_ERROR", "message": "invalid tier"}},
            context="unit",
        )

    def test_rejects_unsupported_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            path.write_text(
                json.dumps({"schema_version": 99, "profiles": []}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(matrix.MatrixError, "schema_version"):
                matrix.load_profiles(path)

    def test_compatibility_notes_present(self) -> None:
        compat = self.fixture.get("compatibility") or {}
        for key in ("rollback", "threat_model", "api_version"):
            self.assertIn(key, compat)


if __name__ == "__main__":
    unittest.main()
