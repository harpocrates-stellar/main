"""Unit tests for the unified circuit build driver (zk/tools/build_circuits.py).

Covers:
- Argument parsing for subcommands build, generate, export, prepare-soroban
- Toolchain lock reading and verification with mocked subprocess calls
- Toolchain mismatch handling (nargo version drift, bb version drift, missing binaries)
- VK transformation for Soroban verifier (1764 -> 1760 bytes endian swap, 1760 passthrough, invalid lengths)
- Artifact hex export for proof, public inputs, and verification key
- Circuit compilation and prove workflows with mocked runner
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import build_circuits as bc

REPO_ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = REPO_ROOT / "zk" / "toolchain.lock.json"


@pytest.fixture()
def sample_lock(tmp_path: Path) -> Path:
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
    }
    lock_file = tmp_path / "toolchain.lock.json"
    lock_file.write_text(json.dumps(lock_data), encoding="utf-8")
    return lock_file


# ==============================================================================
# Argument Parsing Tests
# ==============================================================================


class TestArgumentParsing:
    def test_build_defaults(self):
        parser = bc.create_parser()
        args = parser.parse_args(["build"])
        assert args.subcommand == "build"
        assert args.circuit == "all"
        assert not args.single
        assert not args.verify
        assert not args.check_coverage
        assert not args.prove

    def test_build_specific_circuit_and_flags(self):
        parser = bc.create_parser()
        args = parser.parse_args(["build", "silent_witness", "--prove", "--vk"])
        assert args.subcommand == "build"
        assert args.circuit == "silent_witness"
        assert args.prove
        assert args.vk

    def test_build_modes(self):
        parser = bc.create_parser()
        args_single = parser.parse_args(["build", "all", "--single"])
        assert args_single.single
        args_verify = parser.parse_args(["build", "--verify"])
        assert args_verify.verify
        args_cov = parser.parse_args(["build", "--check-coverage"])
        assert args_cov.check_coverage

    def test_generate_silent_witness_positional(self):
        parser = bc.create_parser()
        args = parser.parse_args([
            "generate",
            "silent_witness",
            "00" * 32,
            "12345",
            "67890",
            "/tmp/output",
        ])
        assert args.subcommand == "generate"
        assert args.circuit == "silent_witness"
        assert args.args == ["00" * 32, "12345", "67890", "/tmp/output"]

    def test_generate_flags(self):
        parser = bc.create_parser()
        args = parser.parse_args([
            "generate",
            "silent_witness",
            "--video-hash",
            "aa" * 32,
            "--credential-secret",
            "999",
            "--nullifier-secret",
            "888",
            "--output-dir",
            "/custom/dir",
        ])
        assert args.circuit == "silent_witness"
        assert args.video_hash == "aa" * 32
        assert args.credential_secret == "999"
        assert args.nullifier_secret == "888"
        assert args.output_dir == "/custom/dir"

    def test_generate_aggregator(self):
        parser = bc.create_parser()
        args = parser.parse_args([
            "generate",
            "silent_witness_aggregator",
            "--video-hashes",
            "11" * 32,
            "22" * 32,
            "--credential-secret",
            "100",
            "--nullifier-secret",
            "200",
        ])
        assert args.circuit == "silent_witness_aggregator"
        assert args.video_hashes == ["11" * 32, "22" * 32]

    def test_export_args(self):
        parser = bc.create_parser()
        args = parser.parse_args(["export", "silent_witness_aggregator", "--output", "out.json"])
        assert args.subcommand == "export"
        assert args.circuit == "silent_witness_aggregator"
        assert args.output == "out.json"

    def test_prepare_soroban_args(self):
        parser = bc.create_parser()
        args = parser.parse_args(["prepare-soroban", "silent_witness", "--target-dir", "custom/target"])
        assert args.subcommand == "prepare-soroban"
        assert args.circuit == "silent_witness"
        assert args.target_dir == "custom/target"


# ==============================================================================
# Toolchain Verification Tests
# ==============================================================================


class TestToolchainChecks:
    def test_toolchain_match_success(self, sample_lock: Path):
        def fake_runner(cmd, **kwargs):
            if cmd[0] == "nargo":
                return subprocess.CompletedProcess(cmd, 0, stdout="nargo version = 1.0.0-beta.9\n", stderr="")
            if cmd[0] == "bb":
                return subprocess.CompletedProcess(cmd, 0, stdout="0.87.0\n", stderr="")
            raise AssertionError(f"unexpected command {cmd}")

        info = bc.check_toolchain(lock_path=sample_lock, runner=fake_runner)
        assert info.actual_nargo == "1.0.0-beta.9"
        assert info.actual_bb == "0.87.0"
        assert info.proving_scheme == "ultra_honk"
        assert info.oracle_hash == "keccak"

    def test_toolchain_nargo_version_drift(self, sample_lock: Path):
        def fake_runner(cmd, **kwargs):
            if cmd[0] == "nargo":
                return subprocess.CompletedProcess(cmd, 0, stdout="nargo version = 0.31.0\n", stderr="")
            if cmd[0] == "bb":
                return subprocess.CompletedProcess(cmd, 0, stdout="0.87.0\n", stderr="")
            return subprocess.CompletedProcess(cmd, 0)

        with pytest.raises(bc.BuildError, match=r"nargo version drift: expected 1\.0\.0-beta\.9, found 0\.31\.0"):
            bc.check_toolchain(lock_path=sample_lock, runner=fake_runner)

    def test_toolchain_bb_version_drift(self, sample_lock: Path):
        def fake_runner(cmd, **kwargs):
            if cmd[0] == "nargo":
                return subprocess.CompletedProcess(cmd, 0, stdout="nargo version = 1.0.0-beta.9\n", stderr="")
            if cmd[0] == "bb":
                return subprocess.CompletedProcess(cmd, 0, stdout="0.86.0\n", stderr="")
            return subprocess.CompletedProcess(cmd, 0)

        with pytest.raises(bc.BuildError, match=r"bb version drift: expected 0\.87\.0, found 0\.86\.0"):
            bc.check_toolchain(lock_path=sample_lock, runner=fake_runner)

    def test_toolchain_nargo_not_found(self, sample_lock: Path):
        def fake_runner(cmd, **kwargs):
            if cmd[0] == "nargo":
                raise FileNotFoundError("nargo not found")
            return subprocess.CompletedProcess(cmd, 0)

        with pytest.raises(bc.BuildError, match=r"nargo not on PATH"):
            bc.check_toolchain(lock_path=sample_lock, runner=fake_runner)

    def test_toolchain_bb_not_found(self, sample_lock: Path):
        def fake_runner(cmd, **kwargs):
            if cmd[0] == "nargo":
                return subprocess.CompletedProcess(cmd, 0, stdout="nargo version = 1.0.0-beta.9\n")
            if cmd[0] == "bb":
                raise FileNotFoundError("bb not found")
            return subprocess.CompletedProcess(cmd, 0)

        with pytest.raises(bc.BuildError, match=r"bb not on PATH"):
            bc.check_toolchain(lock_path=sample_lock, runner=fake_runner)


# ==============================================================================
# Export Tests
# ==============================================================================


class TestExport:
    def test_export_success(self, tmp_path: Path):
        target_dir = tmp_path / "target"
        target_dir.mkdir()
        (target_dir / "proof").write_bytes(b"\x01\x02\x03")
        (target_dir / "public_inputs").write_bytes(b"\xaa\xbb")
        (target_dir / "vk").write_bytes(b"\xcc\xdd")

        out_file = tmp_path / "exported.json"
        args = bc.create_parser().parse_args([
            "export",
            "dummy_circuit",
            "--target-dir",
            str(target_dir),
            "--output",
            str(out_file),
        ])

        rc = bc.cmd_export(args)
        assert rc == bc.EXIT_OK

        saved = json.loads(out_file.read_text(encoding="utf-8"))
        assert saved["proof"] == "010203"
        assert saved["publicInputs"] == "aabb"
        assert saved["verificationKey"] == "ccdd"

    def test_export_missing_file_fails(self, tmp_path: Path):
        target_dir = tmp_path / "target"
        target_dir.mkdir()
        (target_dir / "proof").write_bytes(b"\x01")
        # missing public_inputs and vk

        args = bc.create_parser().parse_args([
            "export",
            "dummy",
            "--target-dir",
            str(target_dir),
        ])
        with pytest.raises(bc.BuildError, match=r"Missing publicInputs artifact"):
            bc.cmd_export(args)


# ==============================================================================
# Prepare Soroban Tests
# ==============================================================================


class TestPrepareSoroban:
    def test_prepare_soroban_1764_bytes(self, tmp_path: Path):
        target_dir = tmp_path / "target"
        target_dir.mkdir()

        # 4-byte header + 32 header bytes (4 x 8-byte pairs) + 1728 payload bytes = 1764 bytes
        header_prefix = b"\x00\x00\x00\x00"
        header_32 = bytearray()
        for i in range(4):
            # first 4 bytes A, second 4 bytes B
            first = bytes([i * 2] * 4)
            second = bytes([i * 2 + 1] * 4)
            header_32.extend(first + second)

        payload = bytes([0xFF] * 1728)
        vk_data = header_prefix + bytes(header_32) + payload
        assert len(vk_data) == 1764

        (target_dir / "vk").write_bytes(vk_data)
        (target_dir / "proof").write_bytes(b"dummy_proof")
        (target_dir / "public_inputs").write_bytes(b"dummy_pi")

        args = bc.create_parser().parse_args([
            "prepare-soroban",
            "silent_witness",
            "--target-dir",
            str(target_dir),
        ])

        rc = bc.cmd_prepare_soroban(args)
        assert rc == bc.EXIT_OK

        soroban_vk = (target_dir / "vk_soroban").read_bytes()
        assert len(soroban_vk) == 1760

        # Verify the 4-byte halves were swapped in the first 32 bytes
        for i in range(4):
            expected_first = bytes([i * 2 + 1] * 4)
            expected_second = bytes([i * 2] * 4)
            assert soroban_vk[i * 8 : i * 8 + 4] == expected_first
            assert soroban_vk[i * 8 + 4 : i * 8 + 8] == expected_second

        # Remainder unchanged
        assert soroban_vk[32:] == payload

    def test_prepare_soroban_1760_bytes_passthrough(self, tmp_path: Path):
        target_dir = tmp_path / "target"
        target_dir.mkdir()
        vk_data = bytes([0x42] * 1760)
        (target_dir / "vk").write_bytes(vk_data)
        (target_dir / "proof").write_bytes(b"")
        (target_dir / "public_inputs").write_bytes(b"")

        args = bc.create_parser().parse_args([
            "prepare-soroban",
            "silent_witness",
            "--target-dir",
            str(target_dir),
        ])
        rc = bc.cmd_prepare_soroban(args)
        assert rc == bc.EXIT_OK
        assert (target_dir / "vk_soroban").read_bytes() == vk_data

    def test_prepare_soroban_invalid_length(self, tmp_path: Path):
        target_dir = tmp_path / "target"
        target_dir.mkdir()
        (target_dir / "vk").write_bytes(b"too_short")

        args = bc.create_parser().parse_args([
            "prepare-soroban",
            "silent_witness",
            "--target-dir",
            str(target_dir),
        ])
        with pytest.raises(bc.BuildError, match=r"Unexpected VK length 9"):
            bc.cmd_prepare_soroban(args)


# ==============================================================================
# Circuit Build Subprocess Workflow Tests
# ==============================================================================


class TestBuildWorkflows:
    def test_compile_circuit_runs_expected_subprocesses(self, tmp_path: Path):
        commands_run = []

        def fake_runner(cmd, **kwargs):
            commands_run.append(cmd)
            # Create dummy target artifacts on nargo compile
            if "compile" in cmd:
                target = tmp_path / "zk" / "noir" / "silent_witness" / "target"
                target.mkdir(parents=True, exist_ok=True)
                (target / "silent_witness.json").write_text("{}", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        toolchain = bc.ToolchainInfo(
            expected_nargo="1.0.0-beta.9",
            expected_bb="0.87.0",
            actual_nargo="1.0.0-beta.9",
            actual_bb="0.87.0",
            proving_scheme="ultra_honk",
            oracle_hash="keccak",
        )

        circuit_dir = tmp_path / "zk" / "noir" / "silent_witness"
        circuit_dir.mkdir(parents=True, exist_ok=True)

        bc.compile_circuit(
            "silent_witness",
            toolchain,
            repo_root=tmp_path,
            clean=True,
            runner=fake_runner,
            write_vk_flag=True,
            prove=True,
        )

        cmd_names = [c[0] for c in commands_run]
        assert cmd_names == ["nargo", "nargo", "bb", "nargo", "bb", "bb"]
        assert commands_run[0] == ["nargo", "check"]
        assert commands_run[1] == ["nargo", "compile"]
        assert commands_run[2][:2] == ["bb", "write_vk"]
        assert commands_run[3] == ["nargo", "execute", "witness"]
        assert commands_run[4][:2] == ["bb", "prove"]
        assert commands_run[5][:2] == ["bb", "verify"]

    def test_build_report_and_compare_report_flags(self):
        parser = bc.create_parser()
        build_args = parser.parse_args(
            [
                "build",
                "--report",
                "out/report.json",
                "--work-dir",
                "out/work",
                "--strict-raw",
            ]
        )
        assert build_args.report == "out/report.json"
        assert build_args.work_dir == "out/work"
        assert build_args.strict_raw is True

        cmp_args = parser.parse_args(
            [
                "compare-report",
                "first.json",
                "second.json",
                "--output",
                "cmp.json",
                "--isolated",
                "--strict-raw",
            ]
        )
        assert cmp_args.subcommand == "compare-report"
        assert cmp_args.first == "first.json"
        assert cmp_args.second == "second.json"
        assert cmp_args.output == "cmp.json"
        assert cmp_args.isolated is True
        assert cmp_args.strict_raw is True


def _write_isolated_repo_fixture(repo_root: Path) -> Path:
    circuit_dir = repo_root / "zk" / "noir" / "silent_witness"
    (circuit_dir / "src").mkdir(parents=True)
    (circuit_dir / "Nargo.toml").write_text(
        '[package]\nname = "silent_witness"\ntype = "bin"\n',
        encoding="utf-8",
    )
    (circuit_dir / "src" / "main.nr").write_text(
        "fn main(pub_in: pub Field) { assert(pub_in == pub_in); }\n",
        encoding="utf-8",
    )
    (circuit_dir / "Prover.toml").write_text(
        'credential_secret = "999999999"\n',
        encoding="utf-8",
    )
    stale_target = circuit_dir / "target"
    stale_target.mkdir()
    (stale_target / "stale.bin").write_bytes(b"STALE_PREEXISTING_ARTIFACT")

    pub_dir = repo_root / "frontend" / "public" / "noir"
    pub_dir.mkdir(parents=True)
    (pub_dir / "silent_witness.json").write_text(
        json.dumps({"bytecode": "PUBLISHED_ACIR_V1"}),
        encoding="utf-8",
    )

    raw_lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
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
            "path": "frontend/public/noir/silent_witness.json",
            "kind": "json",
            "role": "published_acir",
            "required": False,
        },
    ]
    lock_file = repo_root / "zk" / "toolchain.lock.json"
    lock_file.write_text(json.dumps(raw_lock, indent=2), encoding="utf-8")
    return lock_file


class TestIsolatedDoubleBuild:
    def test_stage_isolated_workspace_excludes_targets_and_private_inputs(self, tmp_path: Path):
        repo = tmp_path / "repo"
        lock_file = _write_isolated_repo_fixture(repo)
        isolated = tmp_path / "isolated_1"

        staged_lock = bc.stage_isolated_workspace(repo, isolated, lock_file)
        assert staged_lock.is_file()
        assert (isolated / "zk" / "noir" / "silent_witness" / "src" / "main.nr").is_file()
        assert (isolated / "frontend" / "public" / "noir" / "silent_witness.json").is_file()
        assert not (isolated / "zk" / "noir" / "silent_witness" / "target").exists()
        assert not (isolated / "zk" / "noir" / "silent_witness" / "Prover.toml").exists()

        with pytest.raises(bc.BuildError):
            bc.stage_isolated_workspace(repo, repo, lock_file)
        with pytest.raises(bc.BuildError):
            bc.stage_isolated_workspace(repo, repo / "zk" / "noir" / "nested", lock_file)

    def test_isolated_double_build_succeeds_with_metadata_variance_and_promotes_targets(
        self,
        tmp_path: Path,
    ):
        repo = tmp_path / "repo"
        lock_file = _write_isolated_repo_fixture(repo)
        manifest_out = repo / "zk" / "artifacts.manifest.json"
        report_out = tmp_path / "repro-report.json"
        work_dir = tmp_path / "work"
        observed_compile_cwds: list[Path] = []

        def fake_runner(cmd, **kwargs):
            if cmd[:2] == ["nargo", "--version"]:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout="nargo version = 1.0.0-beta.9\n", stderr=""
                )
            if cmd[:2] == ["bb", "--version"]:
                return subprocess.CompletedProcess(cmd, 0, stdout="0.87.0\n", stderr="")
            cwd = Path(kwargs["cwd"]).resolve()
            if cmd == ["nargo", "compile"]:
                observed_compile_cwds.append(cwd)
                target = cwd / "target"
                target.mkdir(parents=True, exist_ok=True)
                # Embed the isolated build cwd inside volatile metadata!
                (target / "silent_witness.json").write_text(
                    json.dumps(
                        {
                            "bytecode": "DETERMINISTIC_ACIR_BYTECODE",
                            "file_map": {"0": str(cwd / "src" / "main.nr")},
                            "debug_symbols": f"compiled-at-{cwd}",
                        }
                    ),
                    encoding="utf-8",
                )
            elif cmd[:2] == ["bb", "write_vk"]:
                target = cwd / "target"
                (target / "vk").write_bytes(b"\x11" * 64)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        args = bc.create_parser().parse_args(
            [
                "build",
                "--lock",
                str(lock_file),
                "--manifest",
                str(manifest_out),
                "--report",
                str(report_out),
                "--work-dir",
                str(work_dir),
            ]
        )
        rc = bc.cmd_build(args, repo_root=repo, runner=fake_runner)
        assert rc == bc.EXIT_OK

        # Verify two distinct isolated workspaces outside repo_root were used.
        assert len(observed_compile_cwds) == 2
        assert observed_compile_cwds[0] != observed_compile_cwds[1]
        assert repo.resolve() not in observed_compile_cwds[0].parents
        assert repo.resolve() not in observed_compile_cwds[1].parents

        # Report distinguishes nondeterministic metadata from changed executable artifacts.
        report = json.loads(report_out.read_text(encoding="utf-8"))
        assert report["reproducible"] is True
        assert report["verdict"] == "reproducible_with_metadata_variance"
        assert report["builds"]["isolated_directories"] is True
        assert report["summary"]["nondeterministic_metadata"] == 1
        assert report["summary"]["identical"] == 2
        assert report["summary"]["changed_executable"] == 0

        # Targets were promoted cleanly into repo_root, replacing stale.bin.
        promoted_target = repo / "zk" / "noir" / "silent_witness" / "target"
        assert (promoted_target / "silent_witness.json").is_file()
        assert (promoted_target / "vk").read_bytes() == b"\x11" * 64
        assert not (promoted_target / "stale.bin").exists()
        assert manifest_out.is_file()

        # Under --strict-raw, metadata variance exits with EXIT_DRIFT.
        strict_args = bc.create_parser().parse_args(
            [
                "build",
                "--lock",
                str(lock_file),
                "--manifest",
                str(tmp_path / "strict.manifest.json"),
                "--strict-raw",
            ]
        )
        assert bc.cmd_build(strict_args, repo_root=repo, runner=fake_runner) == bc.EXIT_DRIFT

    def test_isolated_double_build_fails_closed_on_executable_drift(self, tmp_path: Path):
        repo = tmp_path / "repo"
        lock_file = _write_isolated_repo_fixture(repo)
        manifest_out = repo / "zk" / "artifacts.manifest.json"
        report_out = tmp_path / "drift-report.json"
        pass_counter = {"compile": 0}

        def drifting_runner(cmd, **kwargs):
            if cmd[:2] == ["nargo", "--version"]:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout="nargo version = 1.0.0-beta.9\n", stderr=""
                )
            if cmd[:2] == ["bb", "--version"]:
                return subprocess.CompletedProcess(cmd, 0, stdout="0.87.0\n", stderr="")
            cwd = Path(kwargs["cwd"]).resolve()
            if cmd == ["nargo", "compile"]:
                pass_counter["compile"] += 1
                target = cwd / "target"
                target.mkdir(parents=True, exist_ok=True)
                (target / "silent_witness.json").write_text(
                    json.dumps({"bytecode": f"ACIR_PASS_{pass_counter['compile']}"}),
                    encoding="utf-8",
                )
            elif cmd[:2] == ["bb", "write_vk"]:
                target = cwd / "target"
                (target / "vk").write_bytes(b"\x22" * 64)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        args = bc.create_parser().parse_args(
            [
                "build",
                "--lock",
                str(lock_file),
                "--manifest",
                str(manifest_out),
                "--report",
                str(report_out),
            ]
        )
        rc = bc.cmd_build(args, repo_root=repo, runner=drifting_runner)
        assert rc == bc.EXIT_DRIFT
        assert not manifest_out.exists()
        # Pre-existing repo target directory was NOT overwritten on failure.
        assert (repo / "zk" / "noir" / "silent_witness" / "target" / "stale.bin").is_file()

        report = json.loads(report_out.read_text(encoding="utf-8"))
        assert report["reproducible"] is False
        assert report["verdict"] == "executable_or_provenance_drift"
        assert report["summary"]["changed_executable"] == 1
