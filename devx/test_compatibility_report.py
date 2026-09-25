from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import compatibility_report as report


class CompatibilityReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = report.read_json_bounded(report.DEFAULT_MANIFEST)

    def test_builds_report_for_current_tree(self) -> None:
        built = report.build_report()
        report.validate_report(built)
        self.assertEqual(built["format"], report.FORMAT)
        self.assertEqual(built["schema_version"], 1)
        self.assertEqual(built["release_id"], "harpocrates-1.0.0")
        self.assertEqual(len(built["layers"]), 5)
        self.assertFalse(built["privacy"]["includes_private_material"])
        # Version/protocol alignment should hold even if digests drifted.
        self.assertIn(
            built["status"],
            {"compatible", "version_compatible_digest_drift"},
        )
        for layer in built["layers"]:
            self.assertEqual(layer["status"], "compatible", layer)

    def test_stable_write_and_verify_roundtrip(self) -> None:
        built = report.stabilize(report.build_report())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "compatibility-report.json"
            report.write_report(built, path)
            loaded = report.read_json_bounded(path)
            self.assertEqual(report.canonical_json(loaded), report.canonical_json(built))

    def test_rejects_sensitive_fields_in_manifest(self) -> None:
        poisoned = copy.deepcopy(self.manifest)
        poisoned["witness"] = "should-never-appear"
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(poisoned, handle)
            path = Path(handle.name)
        self.addCleanup(path.unlink)
        with self.assertRaisesRegex(report.ReportError, "forbidden sensitive"):
            report.read_json_bounded(path)

    def test_rejects_oversized_manifest(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            handle.write('{"x":"' + ("a" * (report.MAX_MANIFEST_BYTES + 10)) + '"}')
            path = Path(handle.name)
        self.addCleanup(path.unlink)
        with self.assertRaisesRegex(report.ReportError, "exceeds"):
            report.read_json_bounded(path)

    def test_detects_frontend_version_drift(self) -> None:
        # Mutate package.json temporarily via monkeypatch of read helpers.
        original = report.read_json_bounded

        def fake_json(path: Path, limit: int = report.MAX_MANIFEST_BYTES) -> dict:
            data = original(path, limit)
            if path.name == "package.json" and "frontend" in str(path):
                data = copy.deepcopy(data)
                data["version"] = "9.9.9"
            return data

        report.read_json_bounded = fake_json  # type: ignore[assignment]
        self.addCleanup(lambda: setattr(report, "read_json_bounded", original))
        built = report.build_report()
        frontend = next(layer for layer in built["layers"] if layer["name"] == "frontend")
        self.assertEqual(frontend["status"], "incompatible")
        self.assertEqual(built["status"], "incompatible")

    def test_proof_system_aliases(self) -> None:
        self.assertTrue(report._proof_systems_compatible("ultrahonk-v1", "ultra_honk"))
        self.assertFalse(report._proof_systems_compatible("ultrahonk-v1", "groth16"))

    def test_cli_check_exit_code(self) -> None:
        code = report.main(["--check", "--stable"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
