"""Unit tests for the fail-closed Wasm size-budget gate (#346)."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import wasm_size_budget as wsb

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "devx" / "wasm_size_budget.json"
RUST_PATH = (
    ROOT / "contracts" / "contracts" / "harpocrates-registry" / "src" / "wasm_budget.rs"
)

BUDGET = {
    "max_size_bytes": 128_000,
    "min_size_bytes": 10_000,
    "regression_band_pct": 15,
}


class ManifestTest(unittest.TestCase):
    def test_committed_manifest_is_valid(self) -> None:
        manifest = wsb.load_manifest(MANIFEST)
        self.assertEqual(manifest["schema_version"], 1)
        self.assertIn("registry", manifest["budgets"])
        self.assertEqual(manifest["budgets"]["registry"]["max_size_bytes"], 128_000)
        self.assertEqual(manifest["budgets"]["registry"]["min_size_bytes"], 10_000)
        self.assertEqual(manifest["budgets"]["registry"]["regression_band_pct"], 15)

    def test_manifest_missing_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(wsb.WasmBudgetError, "not found"):
                wsb.load_manifest(Path(tmp) / "missing.json")

    def test_manifest_malformed_json_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaisesRegex(wsb.WasmBudgetError, "not valid JSON"):
                wsb.load_manifest(path)

    def test_manifest_missing_required_keys_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
            with self.assertRaisesRegex(wsb.WasmBudgetError, "missing keys"):
                wsb.load_manifest(path)

    def test_manifest_unsupported_schema_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            manifest = {
                "schema_version": 99,
                "target": "wasm32v1-none",
                "artifact": "x.wasm",
                "description": "d",
                "budgets": {"registry": dict(BUDGET)},
                "baseline": {},
            }
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(wsb.WasmBudgetError, "schema_version"):
                wsb.load_manifest(path)

    def test_manifest_budget_missing_fields_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            manifest = {
                "schema_version": 1,
                "target": "wasm32v1-none",
                "artifact": "x.wasm",
                "description": "d",
                "budgets": {"registry": {"max_size_bytes": 1}},
                "baseline": {},
            }
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(wsb.WasmBudgetError, "missing keys"):
                wsb.load_manifest(path)

    def test_manifest_non_integer_budget_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            manifest = {
                "schema_version": 1,
                "target": "wasm32v1-none",
                "artifact": "x.wasm",
                "description": "d",
                "budgets": {
                    "registry": {
                        "max_size_bytes": "big",
                        "min_size_bytes": 10,
                        "regression_band_pct": 15,
                    }
                },
                "baseline": {},
            }
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(wsb.WasmBudgetError, "must be an integer"):
                wsb.load_manifest(path)


class RustConstantsTest(unittest.TestCase):
    def test_rust_constants_match_manifest(self) -> None:
        rust_budgets = wsb.load_rust_budgets(RUST_PATH)
        manifest = wsb.load_manifest(MANIFEST)
        self.assertEqual(rust_budgets, manifest["budgets"]["registry"])

    def test_missing_rust_constant_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "wasm_budget.rs"
            path.write_text("// no constants here", encoding="utf-8")
            with self.assertRaisesRegex(wsb.WasmBudgetError, "not found"):
                wsb.load_rust_budgets(path)

    def test_missing_rust_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(wsb.WasmBudgetError, "cannot read"):
                wsb.load_rust_budgets(Path(tmp) / "absent.rs")


class MeasureTest(unittest.TestCase):
    def test_measure_returns_size_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "harpocrates_registry.wasm"
            artifact.write_bytes(b"\x00asm" + b"\x01" * 1023)
            measured = wsb.measure(artifact)
            self.assertEqual(measured["size_bytes"], 1027)
            self.assertRegex(measured["sha256"], r"^[0-9a-f]{64}$")

    def test_measure_missing_artifact_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(wsb.WasmBudgetError, "not found"):
                wsb.measure(Path(tmp) / "absent.wasm")

    def test_measure_empty_artifact_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "empty.wasm"
            artifact.write_bytes(b"")
            with self.assertRaisesRegex(wsb.WasmBudgetError, "empty"):
                wsb.measure(artifact)


class CheckBudgetsTest(unittest.TestCase):
    def test_within_budget_passes(self) -> None:
        measured = {"size_bytes": 120_000, "sha256": "0" * 64}
        self.assertEqual(wsb.check_budgets(measured, BUDGET, None), [])

    def test_hard_max_boundary_is_inclusive(self) -> None:
        measured = {"size_bytes": BUDGET["max_size_bytes"], "sha256": "0" * 64}
        self.assertEqual(wsb.check_budgets(measured, BUDGET, None), [])

    def test_hard_min_boundary_is_inclusive(self) -> None:
        measured = {"size_bytes": BUDGET["min_size_bytes"], "sha256": "0" * 64}
        self.assertEqual(wsb.check_budgets(measured, BUDGET, None), [])

    def test_oversized_artifact_fails(self) -> None:
        measured = {"size_bytes": BUDGET["max_size_bytes"] + 1, "sha256": "0" * 64}
        failures = wsb.check_budgets(measured, BUDGET, None)
        self.assertEqual(len(failures), 1)
        self.assertIn("exceeds budget", failures[0])

    def test_undersized_artifact_fails(self) -> None:
        measured = {"size_bytes": BUDGET["min_size_bytes"] - 1, "sha256": "0" * 64}
        failures = wsb.check_budgets(measured, BUDGET, None)
        self.assertEqual(len(failures), 1)
        self.assertIn("below the minimum", failures[0])

    def test_baseline_within_band_passes(self) -> None:
        baseline = {"size_bytes": 100_000, "sha256": "1" * 64}
        for size in (85_000, 100_000, 115_000):
            measured = {"size_bytes": size, "sha256": "0" * 64}
            self.assertEqual(wsb.check_budgets(measured, BUDGET, baseline), [])

    def test_baseline_growth_beyond_band_fails(self) -> None:
        baseline = {"size_bytes": 100_000, "sha256": "1" * 64}
        measured = {"size_bytes": 115_001, "sha256": "0" * 64}
        failures = wsb.check_budgets(measured, BUDGET, baseline)
        self.assertEqual(len(failures), 1)
        self.assertIn("baseline", failures[0])

    def test_baseline_shrink_beyond_band_fails(self) -> None:
        baseline = {"size_bytes": 100_000, "sha256": "1" * 64}
        measured = {"size_bytes": 84_999, "sha256": "0" * 64}
        failures = wsb.check_budgets(measured, BUDGET, baseline)
        self.assertEqual(len(failures), 1)
        self.assertIn("shrank", failures[0])

    def test_missing_or_zero_baseline_skips_band_check(self) -> None:
        measured = {"size_bytes": 50_000, "sha256": "0" * 64}
        self.assertEqual(wsb.check_budgets(measured, BUDGET, None), [])
        self.assertEqual(wsb.check_budgets(measured, BUDGET, {"size_bytes": 0}), [])

    def test_null_baseline_size_skips_band_check(self) -> None:
        measured = {"size_bytes": 50_000, "sha256": "0" * 64}
        self.assertEqual(wsb.check_budgets(measured, BUDGET, {"size_bytes": None}), [])


class SelectBudgetTest(unittest.TestCase):
    def test_single_budget_is_selected_automatically(self) -> None:
        manifest = {"budgets": {"registry": BUDGET}}
        name, budget = wsb.select_budget(manifest, None)
        self.assertEqual(name, "registry")
        self.assertEqual(budget, BUDGET)

    def test_multiple_budgets_require_explicit_name(self) -> None:
        manifest = {"budgets": {"registry": BUDGET, "verifier": BUDGET}}
        with self.assertRaisesRegex(wsb.WasmBudgetError, "pass --budget"):
            wsb.select_budget(manifest, None)

    def test_unknown_budget_fails(self) -> None:
        with self.assertRaisesRegex(wsb.WasmBudgetError, "unknown budget"):
            wsb.select_budget({"budgets": {"registry": BUDGET}}, "nope")


class RecordTest(unittest.TestCase):
    def test_record_writes_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            manifest = {
                "schema_version": 1,
                "target": "wasm32v1-none",
                "artifact": "x.wasm",
                "description": "d",
                "budgets": {"registry": dict(BUDGET)},
                "baseline": {"size_bytes": None, "sha256": None},
            }
            path.write_text(json.dumps(manifest), encoding="utf-8")
            reloaded = wsb.load_manifest(path)
            wsb.record({"size_bytes": 123_456, "sha256": "a" * 64}, path, reloaded)
            updated = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(updated["baseline"]["size_bytes"], 123_456)
            self.assertEqual(updated["baseline"]["sha256"], "a" * 64)


class ResolveArtifactTest(unittest.TestCase):
    def test_resolves_target_placeholder_from_repo_root(self) -> None:
        manifest = {"artifact": "contracts/target/{target}/release/harpocrates_registry.wasm"}
        resolved = wsb.resolve_artifact(manifest, target="wasm32v1-none")
        self.assertEqual(
            resolved,
            ROOT / "contracts" / "target" / "wasm32v1-none" / "release" / "harpocrates_registry.wasm",
        )


class CliTest(unittest.TestCase):
    def test_cli_check_failure_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "harpocrates_registry.wasm"
            artifact.write_bytes(b"\x00asm" + b"\x01" * 500)  # below min size
            exit_code = wsb.main(
                [
                    "--check",
                    "--manifest",
                    str(MANIFEST),
                    "--artifact",
                    str(artifact),
                ]
            )
            self.assertEqual(exit_code, 1)

    def test_cli_check_success_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "harpocrates_registry.wasm"
            artifact.write_bytes(b"\x00asm" + b"\x01" * 119_999)
            exit_code = wsb.main(
                [
                    "--check",
                    "--manifest",
                    str(MANIFEST),
                    "--artifact",
                    str(artifact),
                ]
            )
            self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
