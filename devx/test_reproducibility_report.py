"""Tests for two-build artifact reproducibility comparison reports.

Covers:
- Isolated output directory staging and canonical digest comparison
- Distinguishing nondeterministic metadata-only drift from changed executable artifacts
- Missing artifact and policy drift boundary cases
- JSON and Markdown report generation and privacy guarantees
- CLI argument parsing for build_circuits.py and artifact_manifest.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ZK_TOOLS = REPO_ROOT / "zk" / "tools"
if str(ZK_TOOLS) not in sys.path:
    sys.path.insert(0, str(ZK_TOOLS))

import artifact_manifest as am  # noqa: E402
import build_circuits as bc  # noqa: E402


def _make_synthetic_repo(tmp_path: Path) -> tuple[Path, Path]:
    """Create a minimal synthetic repo with one circuit and a toolchain lock."""
    repo = tmp_path / "repo"
    circuit_src = repo / "zk" / "noir" / "silent_witness" / "src"
    circuit_src.mkdir(parents=True)
    (repo / "zk" / "noir" / "silent_witness" / "Nargo.toml").write_text(
        '[package]\nname = "silent_witness"\ntype = "bin"\n',
        encoding="utf-8",
    )
    (circuit_src / "main.nr").write_text("fn main() {}\n", encoding="utf-8")

    lock_data = {
        "format": "harpocrates.zk-toolchain-lock",
        "version": 1,
        "toolchain": {
            "nargo": {"version": "1.0.0-beta.9"},
            "barretenberg": {"version": "0.87.0"},
            "proving_scheme": "ultra_honk",
            "oracle_hash": "keccak",
        },
        "environment": {
            "SOURCE_DATE_EPOCH": "0",
            "TZ": "UTC",
        },
        "limits": {
            "max_artifact_bytes": 1048576,
            "max_artifacts": 16,
            "max_provenance_files": 32,
            "max_circuits": 16,
        },
        "normalization": {
            "json": {
                "volatile_keys": ["debug_symbols", "file_map", "warnings"],
            },
            "wasm": {
                "strip_custom_sections": ["producers", "name"],
            },
        },
        "provenance_sources": {
            "globs": ["zk/noir/*/Nargo.toml", "zk/noir/*/src/*.nr"],
        },
        "artifacts": [
            {
                "path": "zk/noir/silent_witness/target/silent_witness.json",
                "kind": "json",
                "role": "acir",
                "required": True,
            },
            {
                "path": "zk/noir/silent_witness/target/vk",
                "kind": "binary",
                "role": "vk",
                "required": True,
            },
        ],
    }
    lock_path = repo / "zk" / "toolchain.lock.json"
    lock_path.write_text(json.dumps(lock_data, indent=2), encoding="utf-8")
    return repo, lock_path


def _make_fake_runner(
    repo: Path,
    *,
    build_acir_payloads: list[dict],
    build_vk_payloads: list[bytes],
):
    """Fake subprocess runner that simulates two builds and delegates artifact_manifest.py."""
    compile_count = {"n": 0}
    vk_count = {"n": 0}
    seen_roots: list[str] = []

    def runner(cmd, **kwargs):
        cmd_list = list(cmd)
        if cmd_list[0] == sys.executable and str(bc.TOOL_MANIFEST) in cmd_list[1]:
            if "--root" in cmd_list:
                idx = cmd_list.index("--root")
                seen_roots.append(cmd_list[idx + 1])
            rc = am.main(cmd_list[2:])
            return subprocess.CompletedProcess(cmd_list, rc, stdout="", stderr="")

        if cmd_list[:2] == ["nargo", "check"]:
            return subprocess.CompletedProcess(cmd_list, 0, stdout="", stderr="")

        if cmd_list[:2] == ["nargo", "compile"]:
            idx = compile_count["n"]
            compile_count["n"] += 1
            target = repo / "zk" / "noir" / "silent_witness" / "target"
            target.mkdir(parents=True, exist_ok=True)
            payload = build_acir_payloads[min(idx, len(build_acir_payloads) - 1)]
            (target / "silent_witness.json").write_text(json.dumps(payload), encoding="utf-8")
            return subprocess.CompletedProcess(cmd_list, 0, stdout="", stderr="")

        if cmd_list[:2] == ["bb", "write_vk"]:
            idx = vk_count["n"]
            vk_count["n"] += 1
            target = repo / "zk" / "noir" / "silent_witness" / "target"
            target.mkdir(parents=True, exist_ok=True)
            vk_bytes = build_vk_payloads[min(idx, len(build_vk_payloads) - 1)]
            (target / "vk").write_bytes(vk_bytes)
            return subprocess.CompletedProcess(cmd_list, 0, stdout="", stderr="")

        raise AssertionError(f"unexpected command: {cmd_list}")

    return runner, seen_roots


def _toolchain() -> bc.ToolchainInfo:
    return bc.ToolchainInfo(
        expected_nargo="1.0.0-beta.9",
        expected_bb="0.87.0",
        actual_nargo="1.0.0-beta.9",
        actual_bb="0.87.0",
        proving_scheme="ultra_honk",
        oracle_hash="keccak",
    )


def test_two_build_reproducible_in_isolated_dirs(tmp_path: Path) -> None:
    repo, lock_path = _make_synthetic_repo(tmp_path)
    manifest_out = tmp_path / "artifacts.manifest.json"
    report_out = tmp_path / "repro-report.json"

    acir = {"bytecode": "0xdeadbeef", "debug_symbols": "host-a"}
    vk = b"\x01\x02\x03\x04"
    runner, seen_roots = _make_fake_runner(
        repo,
        build_acir_payloads=[acir, acir],
        build_vk_payloads=[vk, vk],
    )

    rc = bc.run_two_build_comparison(
        toolchain=_toolchain(),
        lock_path=lock_path,
        manifest_path=manifest_out,
        repo_root=repo,
        runner=runner,
        report_path=report_out,
    )

    assert rc == bc.EXIT_OK
    assert manifest_out.is_file()
    assert report_out.is_file()
    assert len(seen_roots) == 2
    assert seen_roots[0] != seen_roots[1]
    assert seen_roots[0].endswith("build_1")
    assert seen_roots[1].endswith("build_2")

    report = json.loads(report_out.read_text(encoding="utf-8"))
    assert report["format"] == am.REPRODUCIBILITY_REPORT_FORMAT
    assert report["status"] == "reproducible"
    assert report["has_executable_drift"] is False
    assert report["has_metadata_only_drift"] is False
    assert report["isolated_output_dirs"] == {"first": "build_1", "second": "build_2"}
    assert report["summary"]["reproducible"] == 2
    assert report["summary"]["metadata_only_drift"] == 0
    assert report["summary"]["executable_drift"] == 0


def test_distinguishes_nondeterministic_metadata_from_executable_drift(tmp_path: Path) -> None:
    repo, lock_path = _make_synthetic_repo(tmp_path)
    manifest_out = tmp_path / "artifacts.manifest.json"
    report_out = tmp_path / "repro-report.json"

    # Same bytecode, different volatile metadata (debug_symbols + file_map)
    acir_1 = {"bytecode": "0xabcd", "debug_symbols": "secret-host-1", "file_map": {"1": "/a"}}
    acir_2 = {"bytecode": "0xabcd", "debug_symbols": "secret-host-2", "file_map": {"1": "/b"}}
    vk = b"\xaa\xbb\xcc"

    # Default mode: strict (metadata-only drift fails with EXIT_DRIFT)
    runner_strict, _ = _make_fake_runner(
        repo,
        build_acir_payloads=[acir_1, acir_2],
        build_vk_payloads=[vk, vk],
    )
    rc_strict = bc.run_two_build_comparison(
        toolchain=_toolchain(),
        lock_path=lock_path,
        manifest_path=manifest_out,
        repo_root=repo,
        runner=runner_strict,
        report_path=report_out,
        allow_metadata_drift=False,
    )
    assert rc_strict == bc.EXIT_DRIFT
    assert not manifest_out.exists()

    report_text = report_out.read_text(encoding="utf-8")
    # Privacy check: never leak artifact content or volatile metadata strings
    assert "secret-host-1" not in report_text
    assert "secret-host-2" not in report_text
    assert "0xabcd" not in report_text

    report = json.loads(report_text)
    assert report["status"] == "reproducible_with_metadata_drift"
    assert report["has_metadata_only_drift"] is True
    assert report["has_executable_drift"] is False
    assert report["summary"]["metadata_only_drift"] == 1
    assert report["summary"]["reproducible"] == 1
    assert report["summary"]["executable_drift"] == 0

    by_path = {row["path"]: row for row in report["artifacts"]}
    assert by_path["zk/noir/silent_witness/target/silent_witness.json"]["classification"] == "metadata_only_drift"
    assert by_path["zk/noir/silent_witness/target/vk"]["classification"] == "reproducible"

    # With allow_metadata_drift=True: canonical digests match, so exits 0 and writes manifest
    runner_allow, _ = _make_fake_runner(
        repo,
        build_acir_payloads=[acir_1, acir_2],
        build_vk_payloads=[vk, vk],
    )
    rc_allow = bc.run_two_build_comparison(
        toolchain=_toolchain(),
        lock_path=lock_path,
        manifest_path=manifest_out,
        repo_root=repo,
        runner=runner_allow,
        report_path=report_out,
        allow_metadata_drift=True,
    )
    assert rc_allow == bc.EXIT_OK
    assert manifest_out.is_file()


def test_executable_artifact_drift_fails_even_when_metadata_drift_allowed(tmp_path: Path) -> None:
    repo, lock_path = _make_synthetic_repo(tmp_path)
    manifest_out = tmp_path / "artifacts.manifest.json"
    report_out = tmp_path / "repro-report.md"

    acir_1 = {"bytecode": "0x1111", "debug_symbols": "same"}
    acir_2 = {"bytecode": "0x2222", "debug_symbols": "same"}
    vk = b"\xaa\xbb\xcc"

    runner, _ = _make_fake_runner(
        repo,
        build_acir_payloads=[acir_1, acir_2],
        build_vk_payloads=[vk, vk],
    )
    rc = bc.run_two_build_comparison(
        toolchain=_toolchain(),
        lock_path=lock_path,
        manifest_path=manifest_out,
        repo_root=repo,
        runner=runner,
        report_path=report_out,
        report_format="markdown",
        allow_metadata_drift=True,
    )

    assert rc == bc.EXIT_DRIFT
    assert not manifest_out.exists()
    md = report_out.read_text(encoding="utf-8")
    assert "# Two-Build Artifact Reproducibility Comparison Report" in md
    assert "`non_reproducible`" in md
    assert "`executable_drift`" in md
    assert "0x1111" not in md
    assert "0x2222" not in md


def test_missing_artifact_boundary_in_comparison_report() -> None:
    first = {
        "format": am.MANIFEST_FORMAT,
        "version": am.MANIFEST_VERSION,
        "toolchain": {"nargo": "1.0.0-beta.9"},
        "normalization_policy_sha256": "a" * 64,
        "provenance": {},
        "artifacts": [
            {
                "path": "zk/noir/silent_witness/target/silent_witness.json",
                "kind": "json",
                "role": "acir",
                "raw_bytes": 10,
                "normalized_bytes": 10,
                "raw_sha256": "1" * 64,
                "normalized_sha256": "1" * 64,
            }
        ],
    }
    second = {**first, "artifacts": []}

    report = am.build_comparison_report(first, second, first_dir="build_1", second_dir="build_2")
    assert report["status"] == "non_reproducible"
    assert report["summary"]["missing"] == 1
    assert report["artifacts"][0]["classification"] == "missing_in_second"


def test_cli_parsers_accept_report_flags() -> None:
    bc_args = bc.create_parser().parse_args(
        ["build", "--report", "out.json", "--report-format", "markdown", "--allow-metadata-drift"]
    )
    assert bc_args.report == "out.json"
    assert bc_args.report_format == "markdown"
    assert bc_args.allow_metadata_drift is True

    am_args = am.build_parser().parse_args(
        [
            "compare",
            "a.json",
            "b.json",
            "--report",
            "r.json",
            "--report-format",
            "json",
            "--allow-metadata-drift",
            "--first-dir",
            "build_1",
            "--second-dir",
            "build_2",
        ]
    )
    assert am_args.report == "r.json"
    assert am_args.allow_metadata_drift is True
    assert am_args.first_dir == "build_1"
    assert am_args.second_dir == "build_2"
