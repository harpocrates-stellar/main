"""Tests for the threat-model checklist orchestration."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from devx import threat_model_check


class ThreatModelCheckTests(unittest.TestCase):
    @patch("devx.threat_model_check.subprocess.run")
    def test_run_check_passes_on_zero_exit(self, mock_run):
        mock_run.return_value.returncode = 0

        self.assertTrue(threat_model_check.run_check(["python", "check.py"]))
        mock_run.assert_called_once()

    @patch("devx.threat_model_check.subprocess.run")
    def test_run_check_fails_on_nonzero_exit(self, mock_run):
        mock_run.return_value.returncode = 1

        self.assertFalse(threat_model_check.run_check(["python", "check.py"]))

    @patch(
        "devx.threat_model_check.subprocess.run",
        side_effect=OSError("command unavailable"),
    )
    def test_run_check_handles_os_error(self, _mock_run):
        self.assertFalse(threat_model_check.run_check(["python", "check.py"]))

    @patch("devx.threat_model_check.run_check", return_value=True)
    def test_main_succeeds_when_all_checks_pass(self, _mock_run_check):
        output = io.StringIO()

        with redirect_stdout(output):
            result = threat_model_check.main()

        self.assertEqual(result, 0)
        self.assertIn("Overall: SUCCESS", output.getvalue())

    @patch(
        "devx.threat_model_check.run_check",
        side_effect=[True, False, True, True],
    )
    def test_main_fails_when_check_fails(self, _mock_run_check):
        output = io.StringIO()

        with redirect_stdout(output):
            result = threat_model_check.main()

        self.assertEqual(result, 1)

        text = output.getvalue()
        self.assertIn("compatibility: FAIL", text)
        self.assertIn("Overall: FAILURE (1 check(s) failed)", text)

    @patch("devx.threat_model_check.subprocess.run")
    def test_check_output_is_not_exposed(self, mock_run):
        mock_run.return_value.returncode = 1

        output = io.StringIO()

        with redirect_stdout(output):
            threat_model_check.run_check(["python", "check.py"])

        mock_run.assert_called_once_with(
            ["python", "check.py"],
            cwd=threat_model_check.ROOT,
            stdout=threat_model_check.subprocess.DEVNULL,
            stderr=threat_model_check.subprocess.DEVNULL,
            check=False,
        )


if __name__ == "__main__":
    unittest.main()