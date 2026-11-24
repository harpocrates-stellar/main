"""Tests for the cross-layer protocol compatibility manifest (#1224)."""

from __future__ import annotations

import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

# Make devx/ importable when run from the repo root or the devx/ directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import protocol_compatibility as pc


class ParseU32ConstantsTest(unittest.TestCase):
    def test_resolves_literals_aliases_and_underscores(self) -> None:
        source = """
            pub const BASE: u32 = 1;
            pub const ALIAS: u32 = BASE;
            pub const BIG: u32 = 65_536;
            pub const HEX: u32 = 0x10;
        """
        consts = pc.parse_u32_constants(source)
        self.assertEqual(consts, {"BASE": 1, "ALIAS": 1, "BIG": 65536, "HEX": 16})

    def test_resolves_only_requested_names(self) -> None:
        source = """
            pub const NEEDED: u32 = 2;
            pub const ELSEWHERE: u32 = OTHER_MODULE_VALUE;
        """
        self.assertEqual(
            pc.parse_u32_constants(source, names={"NEEDED"}), {"NEEDED": 2}
        )

    def test_missing_constant_is_rejected(self) -> None:
        with self.assertRaisesRegex(pc.ProtocolManifestError, "unresolved"):
            pc.parse_u32_constants("pub const A: u32 = MISSING;", names={"A"})

    def test_cycles_are_rejected(self) -> None:
        source = "pub const A: u32 = B;\npub const B: u32 = A;"
        with self.assertRaisesRegex(pc.ProtocolManifestError, "cyclic"):
            pc.parse_u32_constants(source, names={"A"})


class RepositoryBaselineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = pc.load_manifest(pc.DEFAULT_MANIFEST)
        self.release = pc.load_release_manifest()

    def test_recorded_baseline_matches_the_tree(self) -> None:
        self.assertEqual(pc.compare_manifest(self.manifest, self.release), [])

    def test_report_is_compatible(self) -> None:
        report = pc.build_report(self.manifest, self.release)
        self.assertEqual(report["status"], "compatible")
        self.assertEqual(report["format"], pc.REPORT_FORMAT)
        self.assertEqual(set(report["layers"]), set(pc.LAYERS))
        self.assertEqual(report["findings"], [])

    def test_baseline_binds_the_release_manifest(self) -> None:
        baseline = self.manifest["baseline"]
        self.assertEqual(baseline["release_id"], self.release["release_id"])
        self.assertEqual(baseline["network"], self.release["network"])
        self.assertEqual(baseline["protocol"], self.release["protocol"])

    def test_detects_api_schema_drift(self) -> None:
        drifted = copy.deepcopy(self.manifest)
        drifted["layers"]["api"]["schema_sha256"] = "0" * 64
        findings = pc.compare_manifest(drifted, self.release)
        self.assertTrue(any("api.schema_sha256" in f for f in findings), findings)

    def test_detects_circuit_schema_drift(self) -> None:
        drifted = copy.deepcopy(self.manifest)
        drifted["layers"]["circuit"]["input_schema_sha256"] = "f" * 64
        findings = pc.compare_manifest(drifted, self.release)
        self.assertTrue(
            any("circuit.input_schema_sha256" in f for f in findings), findings
        )

    def test_detects_cli_version_drift(self) -> None:
        drifted = copy.deepcopy(self.manifest)
        drifted["layers"]["cli"]["version"] = "9.9.9"
        findings = pc.compare_manifest(drifted, self.release)
        self.assertTrue(any("cli.version" in f for f in findings), findings)

    def test_detects_baseline_release_drift(self) -> None:
        drifted = copy.deepcopy(self.manifest)
        drifted["baseline"]["release_id"] = "harpocrates-9.9.9"
        findings = pc.compare_manifest(drifted, self.release)
        self.assertTrue(any("baseline.release_id" in f for f in findings), findings)

    def test_rejects_mixed_circuit_and_verifier_versions(self) -> None:
        drifted = copy.deepcopy(self.manifest)
        drifted["layers"]["contract"]["expected_circuit_version"] = 1
        findings = pc.compare_manifest(drifted, self.release)
        self.assertTrue(any("circuit.circuit_version" in f for f in findings), findings)

    def test_rejects_circuit_outside_contract_window(self) -> None:
        drifted = copy.deepcopy(self.manifest)
        drifted["layers"]["contract"]["max_supported_circuit_version"] = 1
        findings = pc.compare_manifest(drifted, self.release)
        self.assertTrue(any("exceeds contract window" in f for f in findings), findings)


class ManifestValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = pc.load_manifest(pc.DEFAULT_MANIFEST)

    def test_unknown_field_is_rejected(self) -> None:
        poisoned = copy.deepcopy(self.manifest)
        poisoned["extra"] = True
        with self.assertRaisesRegex(pc.ProtocolManifestError, "unknown fields"):
            pc.validate_manifest(poisoned)

    def test_missing_layer_is_rejected(self) -> None:
        poisoned = copy.deepcopy(self.manifest)
        del poisoned["layers"]["cli"]
        with self.assertRaisesRegex(pc.ProtocolManifestError, "exactly api, cli"):
            pc.validate_manifest(poisoned)

    def test_sensitive_field_is_rejected(self) -> None:
        poisoned = copy.deepcopy(self.manifest)
        poisoned["witness"] = "must-not-appear"
        with self.assertRaisesRegex(pc.ProtocolManifestError, "forbidden sensitive"):
            pc.validate_manifest(poisoned)

    def test_malformed_digest_is_rejected(self) -> None:
        poisoned = copy.deepcopy(self.manifest)
        poisoned["layers"]["api"]["schema_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(pc.ProtocolManifestError, "SHA-256"):
            pc.validate_manifest(poisoned)

    def test_missing_manifest_file_is_a_typed_error(self) -> None:
        with self.assertRaisesRegex(pc.ProtocolManifestError, "cannot read"):
            pc.load_manifest(Path("/nonexistent/protocol-compatibility.json"))


class CommandLineTest(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = pc.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_check_passes_for_the_committed_baseline(self) -> None:
        code, out, _ = self._run(["--check"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["status"], "compatible")

    def test_check_fails_for_an_incompatible_manifest(self) -> None:
        drifted = pc.load_manifest(pc.DEFAULT_MANIFEST)
        drifted["layers"]["cli"]["manifest_version"] = 99
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "protocol.json"
            pc.write_manifest(drifted, path)
            code, out, err = self._run(["--manifest", str(path), "--check"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["status"], "incompatible")
        self.assertIn("cli.manifest_version", err)

    def test_missing_manifest_exits_two(self) -> None:
        code, _, err = self._run(
            ["--manifest", "/nonexistent/protocol.json", "--check"]
        )
        self.assertEqual(code, 2)
        self.assertIn("protocol compatibility failed", err)

    def test_write_regenerates_a_loadable_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "protocol.json"
            code, _, _ = self._run(["--write", "--output", str(output)])
            self.assertEqual(code, 0)
            regenerated = pc.load_manifest(output)
        self.assertEqual(
            regenerated["layers"], pc.load_manifest(pc.DEFAULT_MANIFEST)["layers"]
        )


if __name__ == "__main__":
    unittest.main()
