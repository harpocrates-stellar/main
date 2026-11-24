from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from validate_example_env import (
    ValidationError,
    _format_result,
    _frontend_env_keys,
    _python_env_keys,
    compare_example,
)


class ValidateExampleEnvironmentTest(unittest.TestCase):
    def test_reports_missing_and_obsolete_keys_without_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            example = Path(tmp) / ".env.example"
            example.write_text(
                "# TOKEN is described in prose, not configured\n"
                "# OPTIONAL=synthetic-optional-value\n"
                "CURRENT=synthetic-secret-value\n"
                "OBSOLETE=another-synthetic-value\n",
                encoding="utf-8",
            )

            result = compare_example(
                "backend",
                example,
                {"CURRENT", "MISSING", "OPTIONAL"},
            )

        self.assertEqual(result.missing, ("MISSING",))
        self.assertEqual(result.obsolete, ("OBSOLETE",))
        rendered = "\n".join(_format_result(result))
        self.assertNotIn("synthetic-secret-value", rendered)
        self.assertNotIn("synthetic-optional-value", rendered)
        self.assertNotIn("another-synthetic-value", rendered)

    def test_finds_literal_and_helper_based_python_lookups(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "config.py"
            source.write_text(
                "import os\n"
                "def _read(name):\n"
                "    return os.getenv(name)\n"
                "def load():\n"
                "    os.getenv('DIRECT')\n"
                "    _read('HELPER')\n"
                "    return os.environ['SUBSCRIPT']\n",
                encoding="utf-8",
            )

            self.assertEqual(
                _python_env_keys(source),
                {"DIRECT", "HELPER", "SUBSCRIPT"},
            )

    def test_rejects_malformed_python_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "config.py"
            source.write_text("def broken(:\n", encoding="utf-8")

            with self.assertRaisesRegex(ValidationError, "line 1"):
                _python_env_keys(source)

    def test_finds_frontend_vite_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "config.ts"
            source.write_text(
                "const api = import.meta.env.VITE_API_BASE;\n"
                "const release = process.env?.VITE_RELEASE_ID;\n",
                encoding="utf-8",
            )

            self.assertEqual(
                _frontend_env_keys([source]),
                {"VITE_API_BASE", "VITE_RELEASE_ID"},
            )


if __name__ == "__main__":
    unittest.main()
