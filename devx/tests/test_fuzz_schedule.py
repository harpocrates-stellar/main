import re
import unittest
from pathlib import Path

WF = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "fuzz-scheduled.yml"


class FuzzScheduleTests(unittest.TestCase):
    def setUp(self):
        self.text = WF.read_text(encoding="utf-8")

    def test_no_unresolved_placeholders(self):
        self.assertNotIn("SET THIS", self.text)

    def test_scheduled_and_manually_dispatchable(self):
        self.assertRegex(self.text, r"(?m)^\s+schedule:")
        self.assertRegex(self.text, r"(?m)^\s+- cron: ")
        self.assertIn("workflow_dispatch:", self.text)

    def test_read_only_token(self):
        self.assertRegex(self.text, r"(?m)^permissions:\s*\n\s+contents:\s*read\s*$")
        self.assertNotRegex(self.text, r":\s*write\b")

    def test_every_job_has_a_timeout(self):
        self.assertGreaterEqual(self.text.count("timeout-minutes:"), self.text.count("runs-on:"))

    def test_no_secrets_and_no_privileged_trigger(self):
        self.assertNotIn("secrets.", self.text)
        self.assertNotIn("pull_request_target", self.text)

    def test_checkout_does_not_persist_credentials(self):
        self.assertGreaterEqual(self.text.count("persist-credentials: false"), self.text.count("actions/checkout"))

    def test_inputs_only_flow_through_env(self):
        for line in self.text.splitlines():
            if "${{ inputs." in line:
                self.assertTrue(line.strip().startswith(("ITERATIONS:", "FUZZ_SEED:")), line)

    def test_failure_artifacts_are_short_lived_and_failure_only(self):
        for days in re.findall(r"retention-days:\s*(\d+)", self.text):
            self.assertLessEqual(int(days), 14)
        self.assertIn("if: failure()", self.text)


if __name__ == "__main__":
    unittest.main()