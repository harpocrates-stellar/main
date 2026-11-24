"""Focused tests for devx/check_contributor_commands.py.

Fixtures are synthetic Markdown files and temporary checkouts; no documented
command is ever executed and no network or credentials are involved.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

try:
    from devx import check_contributor_commands as commands
except ImportError:  # pragma: no cover - direct `pytest devx/test_...py` invocation
    import check_contributor_commands as commands  # type: ignore[no-redef]


class ContributorCommandCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.doc = self.root / "CONTRIBUTING.md"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write_doc(self, body: str) -> None:
        self.doc.write_text(body.strip() + "\n", encoding="utf-8")

    def _write_json(self, relative: str, payload: dict[str, object]) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")

    def test_current_contributor_docs_reference_committed_entry_points(self) -> None:
        self.assertEqual(
            commands.check_documents([Path("CONTRIBUTING.md")], root=commands.ROOT), []
        )

    def test_missing_python_entry_point_reports_document_line(self) -> None:
        self._write_doc(
            """
            # Verification

            ```bash
            python3 devx/compatibility_report.py --check
            ```
            """
        )
        findings = commands.check_document(self.doc, self.root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].document, self.doc)
        self.assertEqual(findings[0].line, 4)
        self.assertIn("devx/compatibility_report.py", findings[0].command)
        self.assertIn("not committed", findings[0].reason)
        self.assertIn("CONTRIBUTING.md:4", findings[0].format(self.root))

    def test_committed_entry_point_clears_finding(self) -> None:
        self._write_doc(
            """
            ```bash
            python3 devx/compatibility_report.py --check
            ```
            """
        )
        script = self.root / "devx" / "compatibility_report.py"
        script.parent.mkdir(parents=True)
        script.write_text("# committed entry point\n", encoding="utf-8")
        self.assertEqual(commands.check_document(self.doc, self.root), [])

    def test_obsolete_npm_workspace_command_is_detected_then_fixed(self) -> None:
        self._write_doc(
            """
            ```bash
            npm run build --workspace=frontend
            ```
            """
        )
        self._write_json("frontend/package.json", {"scripts": {"build": "vite build"}})

        findings = commands.check_document(self.doc, self.root)
        self.assertTrue(
            any("workspace manifest 'package.json'" in f.reason for f in findings)
        )

        self._write_json("package.json", {"workspaces": ["frontend"]})
        self.assertEqual(commands.check_document(self.doc, self.root), [])

    def test_undeclared_npm_script_is_detected(self) -> None:
        self._write_doc(
            """
            ```bash
            npm run lint --workspace=frontend
            ```
            """
        )
        self._write_json("package.json", {"workspaces": ["frontend"]})
        self._write_json("frontend/package.json", {"scripts": {"build": "vite build"}})

        findings = commands.check_document(self.doc, self.root)
        self.assertEqual(len(findings), 1)
        self.assertIn("npm script 'lint' is not declared", findings[0].reason)

    def test_cd_scopes_npm_command_to_committed_workspace(self) -> None:
        self._write_doc(
            """
            ```bash
            cd frontend
            npm run test
            ```
            """
        )
        self._write_json("frontend/package.json", {"scripts": {"test": "vitest run"}})
        # No root package.json: the command is only valid from frontend/.
        self.assertEqual(commands.check_document(self.doc, self.root), [])

    def test_generated_output_paths_are_not_treated_as_entry_points(self) -> None:
        self._write_doc(
            """
            ```bash
            python devx/generate_api_schema.py --output openapi.json
            ```
            """
        )
        script = self.root / "devx" / "generate_api_schema.py"
        script.parent.mkdir(parents=True)
        script.write_text("# committed entry point\n", encoding="utf-8")

        self.assertEqual(commands.check_document(self.doc, self.root), [])
        self.assertFalse((self.root / "openapi.json").exists())

    def test_pytest_target_directory_is_validated(self) -> None:
        self._write_doc(
            """
            ```bash
            python -m pytest devx -q
            ```
            """
        )
        self.assertEqual(len(commands.check_document(self.doc, self.root)), 1)
        (self.root / "devx").mkdir()
        self.assertEqual(commands.check_document(self.doc, self.root), [])

    def test_cli_reports_locations_and_exit_codes(self) -> None:
        self._write_doc(
            """
            # Verification

            ```bash
            python3 devx/missing_tool.py
            ```
            """
        )
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = commands.main([self.doc.name, "--root", str(self.root)])
        self.assertEqual(code, 1)
        self.assertIn("CONTRIBUTING.md:4", stderr.getvalue())

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = commands.main([self.doc.name, "--root", str(self.root), "--json"])
        self.assertEqual(code, 1)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload[0]["line"], 4)
        self.assertEqual(payload[0]["document"], self.doc.as_posix())

        (self.root / "devx").mkdir()
        (self.root / "devx" / "missing_tool.py").write_text(
            "# fixed\n", encoding="utf-8"
        )
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = commands.main([self.doc.name, "--root", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("committed entry points", stdout.getvalue())

    def test_missing_explicit_document_returns_usage_error(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = commands.main(["DOES_NOT_EXIST.md", "--root", str(self.root)])
        self.assertEqual(code, 2)
        self.assertIn("document not found", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
