from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

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

    def test_select_single_profile_and_group_intersection(self) -> None:
        profile = self.fixture["profiles"][0]
        for group in (None, "all", profile["group"]):
            with self.subTest(group=group):
                self.assertEqual(
                    matrix.select_profiles(self.fixture, group, profile["id"]),
                    [profile],
                )
        other_group = "adversarial" if profile["group"] == "core" else "core"
        with self.assertRaisesRegex(matrix.MatrixError, "no profiles"):
            matrix.select_profiles(self.fixture, other_group, profile["id"])

    def test_list_text_and_json_without_running_profiles(self) -> None:
        for group in ("all", "core", "adversarial"):
            expected = matrix.select_profiles(self.fixture, group)
            for as_json in (False, True):
                with self.subTest(group=group, json=as_json):
                    args = ["--list", "--group", group]
                    if as_json:
                        args.append("--json")
                    output = io.StringIO()
                    with patch.object(matrix, "run_profile") as run, redirect_stdout(output):
                        self.assertEqual(matrix.main(args), 0)
                    run.assert_not_called()
                    if as_json:
                        self.assertEqual(json.loads(output.getvalue()), [
                            {"id": p["id"], "group": p["group"],
                             "description": matrix.describe_profile(p)} for p in expected
                        ])
                    else:
                        self.assertEqual(output.getvalue().splitlines(), [
                            f"{p['id']} ({p['group']}): {matrix.describe_profile(p)}"
                            for p in expected
                        ])

    def test_profile_cli_runs_only_selected_profile_and_preserves_exit_status(self) -> None:
        profile = self.fixture["profiles"][-1]
        for ok in (True, False):
            with self.subTest(ok=ok):
                output = io.StringIO()
                result = {"id": profile["id"], "ok": ok}
                with patch.object(matrix, "run_profile", return_value=result) as run:
                    with redirect_stdout(output):
                        code = matrix.main(["--profile", profile["id"], "--json"])
                run.assert_called_once_with(profile)
                self.assertEqual(code, 0 if ok else 1)
                summary = json.loads(output.getvalue())
                self.assertEqual(summary["total"], 1)
                self.assertEqual(summary["results"], [result])

    def test_unknown_profile_cli_reports_valid_ids_without_running(self) -> None:
        for extra in ([], ["--list"], ["--list", "--json"], ["--group", "core"]):
            with self.subTest(extra=extra):
                errors = io.StringIO()
                with patch.object(matrix, "run_profile") as run, redirect_stderr(errors):
                    with self.assertRaises(SystemExit) as raised:
                        matrix.main(["--profile", "does-not-exist", *extra])
                self.assertEqual(raised.exception.code, 2)
                run.assert_not_called()
                self.assertIn("unknown profile ID", errors.getvalue())
                for profile in self.fixture["profiles"]:
                    self.assertIn(profile["id"], errors.getvalue())

    def test_list_json_subprocess_uses_custom_fixture_without_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "profiles.json"
            fixture.write_text(json.dumps({
                "schema_version": 1,
                "profiles": [{"id": "custom", "group": "core"}],
            }), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(Path(matrix.__file__)), "--fixture", str(fixture),
                 "--list", "--json", "--profile", "custom"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout), [{
                "id": "custom", "group": "core",
                "description": "Boot succeeds; no checks configured",
            }])
            proc = subprocess.run(
                [sys.executable, str(Path(matrix.__file__)), "--fixture", str(fixture),
                 "--profile", "missing"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("valid IDs: custom", proc.stderr)
            self.assertEqual(proc.stdout, "")

    def test_descriptions_cover_checks_boot_rejection_and_explicit_text(self) -> None:
        self.assertEqual(matrix.describe_profile({"checks": ["health_ok", "ready_shape"]}),
                         "Checks: health_ok, ready_shape")
        self.assertEqual(matrix.describe_profile({"expect_boot": False}),
                         "Expected boot rejection")
        self.assertEqual(matrix.describe_profile({
            "expect_boot": False, "expect_boot_error_substring": "Wildcard CORS",
        }), "Expected boot rejection: Wildcard CORS")
        self.assertEqual(matrix.describe_profile({"description": "Custom description"}),
                         "Custom description")
        for profile in self.fixture["profiles"]:
            self.assertTrue(matrix.describe_profile(profile))

    def test_existing_execution_options_preserve_summary_and_order(self) -> None:
        for group in ("all", "core", "adversarial"):
            for as_json in (False, True):
                with self.subTest(group=group, json=as_json):
                    args = [] if group == "all" else ["--group", group]
                    if as_json:
                        args.append("--json")
                    expected = matrix.select_profiles(self.fixture, group)
                    output = io.StringIO()
                    with patch.object(matrix, "run_profile", side_effect=lambda p: {
                        "id": p["id"], "ok": True,
                    }) as run, redirect_stdout(output):
                        self.assertEqual(matrix.main(args), 0)
                    self.assertEqual([call.args[0] for call in run.call_args_list], expected)
                    if as_json:
                        summary = json.loads(output.getvalue())
                        self.assertEqual(summary["group"], group)
                        self.assertEqual(summary["total"], len(expected))
                        self.assertEqual(summary["passed"], len(expected))
                        self.assertEqual(summary["failed"], 0)
                        self.assertEqual(summary["compatibility"], self.fixture["compatibility"])
                    else:
                        self.assertIn(f"group={group} passed={len(expected)}/{len(expected)}",
                                      output.getvalue())

    def test_conflicting_group_and_profile_is_usage_error(self) -> None:
        profile = self.fixture["profiles"][0]
        other_group = "adversarial" if profile["group"] == "core" else "core"
        for extra in ([], ["--list", "--json"]):
            with self.subTest(extra=extra):
                with patch.object(matrix, "run_profile") as run:
                    with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                        matrix.main(["--profile", profile["id"], "--group", other_group, *extra])
                self.assertEqual(raised.exception.code, 2)
                run.assert_not_called()

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
