from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from devx import client_consolidation_report as report


class ClientConsolidationReportTest(unittest.TestCase):
    def _fixture_root(self, root: Path) -> None:
        (root / "frontend" / "src").mkdir(parents=True)
        (root / "backend").mkdir()
        (root / "frontend" / "src" / "verifierInputs.ts").write_text(
            "export function encodeFieldToBytes32Hex() {}\n"
            "export class VerifierInputError {}\n"
            "function privateHelper() {}\n",
            encoding="utf-8",
        )
        (root / "backend" / "verifier_inputs.py").write_text(
            "def encode_field_to_bytes32_hex():\n    pass\n"
            "class VerifierInputError:\n    pass\n"
            "def _private_helper():\n    pass\n",
            encoding="utf-8",
        )
        (root / "frontend" / "src" / "consumer.ts").write_text(
            "import { encodeFieldToBytes32Hex } from './verifierInputs'\n",
            encoding="utf-8",
        )
        (root / "frontend" / "src" / "consumer.test.ts").write_text(
            "import { encodeFieldToBytes32Hex } from './verifierInputs'\n",
            encoding="utf-8",
        )
        (root / "backend" / "consumer.py").write_text(
            "from verifier_inputs import encode_field_to_bytes32_hex\n",
            encoding="utf-8",
        )
        (root / "backend" / "test_consumer.py").write_text(
            "from verifier_inputs import encode_field_to_bytes32_hex\n",
            encoding="utf-8",
        )

    def test_reports_duplicate_exports_and_only_active_import_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._fixture_root(root)
            source_paths = [
                root / "frontend" / "src" / "verifierInputs.ts",
                root / "frontend" / "src" / "consumer.ts",
                root / "backend" / "verifier_inputs.py",
                root / "backend" / "consumer.py",
            ]
            before = {path: path.read_bytes() for path in source_paths}

            result = report.build_report(root)

            self.assertEqual(
                {path: path.read_bytes() for path in source_paths},
                before,
            )
        self.assertTrue(result["read_only"])
        self.assertEqual(result["status"], "multiple_implementations")
        duplicates = {
            entry["name"] for entry in result["duplicate_exported_entry_points"]
        }
        self.assertEqual(
            duplicates,
            {"encode_field_to_bytes32_hex", "verifier_input_error"},
        )
        by_id = {item["id"]: item for item in result["implementations"]}
        self.assertEqual(
            [item["path"] for item in by_id["browser"]["active_import_paths"]],
            ["frontend/src/consumer.ts"],
        )
        self.assertEqual(
            [item["path"] for item in by_id["backend"]["active_import_paths"]],
            ["backend/consumer.py"],
        )

    def test_fails_closed_for_malformed_implementation_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._fixture_root(root)
            (root / "backend" / "verifier_inputs.py").write_text(
                "def broken(:\n    pass\n", encoding="utf-8"
            )

            with self.assertRaisesRegex(
                report.ConsolidationReportError, "malformed Python source"
            ):
                report.build_report(root)

    def test_reports_no_duplicate_when_export_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._fixture_root(root)
            (root / "backend" / "verifier_inputs.py").write_text(
                "def backend_only():\n    pass\n", encoding="utf-8"
            )

            result = report.build_report(root)

        self.assertEqual(result["status"], "no_duplicate_entry_points")
        self.assertEqual(result["duplicate_exported_entry_points"], [])


if __name__ == "__main__":
    unittest.main()
