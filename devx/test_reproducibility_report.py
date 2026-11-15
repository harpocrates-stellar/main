"""Focused devx coverage for the two-build artifact reproducibility comparison report."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ZK_TOOLS = REPO_ROOT / "zk" / "tools"
for candidate in (str(REPO_ROOT), str(ZK_TOOLS)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

import artifact_manifest as am
import build_circuits as bc

WASM_HEADER = b"\x00asm\x01\x00\x00\x00"


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _wasm_custom_section(name: str, body: bytes) -> bytes:
    encoded = name.encode("utf-8")
    payload = _uleb128(len(encoded)) + encoded + body
    return b"\x00" + _uleb128(len(payload)) + payload


def _wasm_code_section(code_bytes: bytes) -> bytes:
    return b"\x0a" + _uleb128(len(code_bytes)) + code_bytes


class ReproducibilityComparisonReportTest(unittest.TestCase):
    def _create_workspace(self, root: Path) -> Path:
        circuit_dir = root / "zk" / "noir" / "silent_witness"
        (circuit_dir / "src").mkdir(parents=True)
        (circuit_dir / "Nargo.toml").write_text(
            '[package]\nname = "silent_witness"\ntype = "bin"\n',
            encoding="utf-8",
        )
        (circuit_dir / "src" / "main.nr").write_text(
            "fn main(pub_input: pub Field) { assert(pub_input == pub_input); }\n",
            encoding="utf-8",
        )
        raw_lock = json.loads((REPO_ROOT / "zk" / "toolchain.lock.json").read_text(encoding="utf-8"))
        raw_lock["artifacts"] = [
            {
                "path": "zk/noir/silent_witness/target/silent_witness.json",
                "kind": "json",
                "role": "acir",
                "required": True,
            },
            {
                "path": "zk/noir/silent_witness/target/vk",
                "kind": "binary",
                "role": "verification_key",
                "required": True,
            },
            {
                "path": "zk/noir/silent_witness/target/verifier.wasm",
                "kind": "wasm",
                "role": "verifier_wasm",
                "required": True,
            },
        ]
        lock_file = root / "zk" / "toolchain.lock.json"
        lock_file.write_text(json.dumps(raw_lock, indent=2), encoding="utf-8")
        return lock_file

    def test_wasm_and_json_metadata_variance_vs_executable_code_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo = base / "repo"
            lock_file = self._create_workspace(repo)
            report_file = base / "report.json"
            manifest_file = repo / "zk" / "artifacts.manifest.json"
            toolchain = bc.ToolchainInfo(
                expected_nargo="1.0.0-beta.9",
                expected_bb="0.87.0",
                actual_nargo="1.0.0-beta.9",
                actual_bb="0.87.0",
                proving_scheme="ultra_honk",
                oracle_hash="keccak",
            )

            # Pass 1: custom section `producers` + JSON `file_map` differ by isolated dir,
            # while WASM code section, ACIR bytecode, and binary VK stay identical.
            def metadata_only_runner(cmd, **kwargs):
                cwd = Path(kwargs["cwd"]).resolve()
                target = cwd / "target"
                if cmd == ["nargo", "compile"]:
                    target.mkdir(parents=True, exist_ok=True)
                    (target / "silent_witness.json").write_text(
                        json.dumps(
                            {
                                "bytecode": "CANONICAL_ACIR_BYTES",
                                "file_map": {"0": str(cwd / "src" / "main.nr")},
                            }
                        ),
                        encoding="utf-8",
                    )
                    wasm_bytes = (
                        WASM_HEADER
                        + _wasm_code_section(b"\x01\x00\x41\x2a\x0b")
                        + _wasm_custom_section("producers", str(cwd).encode("utf-8"))
                    )
                    (target / "verifier.wasm").write_bytes(wasm_bytes)
                elif cmd[:2] == ["bb", "write_vk"]:
                    (target / "vk").write_bytes(b"\x55" * 64)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            stderr_buf = io.StringIO()
            with redirect_stderr(stderr_buf):
                status, report = bc.run_isolated_double_build(
                    toolchain,
                    repo_root=repo,
                    lock_path=lock_file,
                    manifest_path=manifest_file,
                    report_path=report_file,
                    circuits=("silent_witness",),
                    runner=metadata_only_runner,
                )

            self.assertEqual(status, bc.EXIT_OK)
            self.assertTrue(report["reproducible"])
            self.assertEqual(report["verdict"], "reproducible_with_metadata_variance")
            self.assertEqual(report["summary"]["nondeterministic_metadata"], 2)
            self.assertEqual(report["summary"]["identical"], 1)
            self.assertEqual(report["summary"]["changed_executable"], 0)
            self.assertTrue(manifest_file.is_file())

            # Privacy check: neither host tmp directory nor circuit payload appears in report/signals.
            serialized_report = report_file.read_text(encoding="utf-8")
            self.assertNotIn(str(base), serialized_report)
            self.assertNotIn("CANONICAL_ACIR_BYTES", serialized_report)
            self.assertNotIn("CANONICAL_ACIR_BYTES", stderr_buf.getvalue())

            # Pass 2: mutate executable WASM code section and binary VK on second build.
            build_count = {"n": 0}

            def executable_drift_runner(cmd, **kwargs):
                cwd = Path(kwargs["cwd"]).resolve()
                target = cwd / "target"
                if cmd == ["nargo", "compile"]:
                    build_count["n"] += 1
                    target.mkdir(parents=True, exist_ok=True)
                    (target / "silent_witness.json").write_text(
                        json.dumps({"bytecode": "CANONICAL_ACIR_BYTES"}),
                        encoding="utf-8",
                    )
                    code = (
                        b"\x01\x00\x41\x2a\x0b"
                        if build_count["n"] == 1
                        else b"\x01\x00\x41\x2b\x0b"
                    )
                    (target / "verifier.wasm").write_bytes(WASM_HEADER + _wasm_code_section(code))
                elif cmd[:2] == ["bb", "write_vk"]:
                    vk_byte = b"\x55" if build_count["n"] == 1 else b"\x66"
                    (target / "vk").write_bytes(vk_byte * 64)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            drift_report_file = base / "drift_report.json"
            drift_manifest_file = base / "should_not_exist.manifest.json"
            with redirect_stderr(io.StringIO()):
                drift_status, drift_report = bc.run_isolated_double_build(
                    toolchain,
                    repo_root=repo,
                    lock_path=lock_file,
                    manifest_path=drift_manifest_file,
                    report_path=drift_report_file,
                    circuits=("silent_witness",),
                    runner=executable_drift_runner,
                )

            self.assertEqual(drift_status, bc.EXIT_DRIFT)
            self.assertFalse(drift_report["reproducible"])
            self.assertEqual(drift_report["verdict"], "executable_or_provenance_drift")
            self.assertEqual(drift_report["summary"]["changed_executable"], 2)
            self.assertEqual(drift_report["summary"]["identical"], 1)
            self.assertTrue(drift_report_file.is_file())
            self.assertFalse(drift_manifest_file.exists())

    def test_report_detects_toolchain_provenance_and_policy_drift(self) -> None:
        base_doc = {
            "format": am.MANIFEST_FORMAT,
            "version": am.MANIFEST_VERSION,
            "toolchain": {"nargo": "1.0.0-beta.9", "barretenberg": "0.87.0"},
            "normalization_policy_sha256": "a" * 64,
            "provenance": {"zk/noir/silent_witness/src/main.nr": "b" * 64},
            "artifacts": [],
            "skipped": [],
        }
        drifted_doc = {
            **base_doc,
            "toolchain": {"nargo": "1.0.0-beta.9", "barretenberg": "0.88.0"},
            "normalization_policy_sha256": "f" * 64,
            "provenance": {"zk/noir/silent_witness/src/main.nr": "c" * 64},
        }
        report = am.build_reproducibility_report(base_doc, drifted_doc)
        self.assertFalse(report["reproducible"])
        self.assertFalse(report["normalization_policy_match"])
        self.assertEqual(report["summary"]["toolchain_drift_count"], 1)
        self.assertEqual(report["summary"]["provenance_drift_count"], 1)
        passed, fatal, _ = am.evaluate_reproducibility_report(report)
        self.assertFalse(passed)
        self.assertEqual(len(fatal), 3)


if __name__ == "__main__":
    unittest.main()
