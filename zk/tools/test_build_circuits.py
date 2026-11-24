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
import sys
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


# ==============================================================================
# Atomic manifest promotion (#1220)
# ==============================================================================


class FakeManifestRunner:
    """Dispatch fake subprocesses for the build driver's manifest workflow."""

    def __init__(
        self,
        *,
        write_output: bool = True,
        verify_status: int = 0,
        fail_nargo_check: bool = False,
    ) -> None:
        self.write_output = write_output
        self.verify_status = verify_status
        self.fail_nargo_check = fail_nargo_check
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        cmd = list(cmd)
        self.calls.append(cmd)
        if cmd[0] == "nargo":
            if "--version" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout="nargo version = 1.0.0-beta.9\n", stderr=""
                )
            if self.fail_nargo_check and "check" in cmd:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[0] == "bb":
            if "--version" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="0.87.0\n", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[0] == sys.executable:
            if "check-coverage" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            if "write" in cmd:
                if self.write_output:
                    output = Path(cmd[cmd.index("--output") + 1])
                    output.write_text(
                        '{"format":"harpocrates.zk-artifact-manifest","version":1}\n',
                        encoding="utf-8",
                    )
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            if "verify" in cmd:
                return subprocess.CompletedProcess(
                    cmd, self.verify_status, stdout="", stderr=""
                )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def manifest_calls(self, action: str) -> list[list[str]]:
        return [c for c in self.calls if c[0] == sys.executable and action in c]

    def arg(self, cmd: list[str], flag: str) -> str:
        return cmd[cmd.index(flag) + 1]


def _single_build_args(tmp_path: Path, manifest_path: Path):
    lock_path = tmp_path / "zk" / "toolchain.lock.json"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(
        json.dumps(
            {
                "format": "harpocrates.zk-toolchain-lock",
                "version": 1,
                "toolchain": {
                    "nargo": {"version": "1.0.0-beta.9"},
                    "barretenberg": {"version": "0.87.0"},
                    "proving_scheme": "ultra_honk",
                    "oracle_hash": "keccak",
                },
                "environment": {"SOURCE_DATE_EPOCH": "0", "TZ": "UTC"},
            }
        ),
        encoding="utf-8",
    )
    return bc.create_parser().parse_args(
        [
            "build",
            "all",
            "--single",
            "--manifest",
            str(manifest_path),
            "--lock",
            str(lock_path),
        ]
    )


class TestManifestPromotion:
    def test_single_build_verifies_staged_manifest_before_promotion(
        self, tmp_path: Path
    ):
        manifest_path = tmp_path / "zk" / "artifacts.manifest.json"
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_text("previous\n", encoding="utf-8")
        args = _single_build_args(tmp_path, manifest_path)
        runner = FakeManifestRunner()

        rc = bc.cmd_build(args, repo_root=tmp_path, runner=runner)

        assert rc == bc.EXIT_OK
        write_calls = runner.manifest_calls("write")
        verify_calls = runner.manifest_calls("verify")
        assert len(write_calls) == 1
        assert len(verify_calls) == 1
        staged = Path(runner.arg(write_calls[0], "--output"))
        # Staged on the target's filesystem (a sibling directory) so the final
        # rename is atomic, but never at the published path itself.
        assert staged.parent.parent == manifest_path.parent
        assert staged != manifest_path
        assert runner.arg(verify_calls[0], "--manifest") == str(staged)
        assert not staged.exists()
        assert json.loads(manifest_path.read_text(encoding="utf-8"))["version"] == 1
        assert list(manifest_path.parent.glob(f".{manifest_path.name}.*")) == []

    def test_failed_verification_retains_previous_manifest(self, tmp_path: Path):
        manifest_path = tmp_path / "zk" / "artifacts.manifest.json"
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_text("previous\n", encoding="utf-8")
        args = _single_build_args(tmp_path, manifest_path)
        runner = FakeManifestRunner(verify_status=bc.EXIT_DRIFT)

        with pytest.raises(bc.BuildError, match="previous manifest retained"):
            bc.cmd_build(args, repo_root=tmp_path, runner=runner)

        assert manifest_path.read_text(encoding="utf-8") == "previous\n"
        assert list(manifest_path.parent.glob(f".{manifest_path.name}.*")) == []

    def test_missing_staged_output_retains_previous_manifest(self, tmp_path: Path):
        manifest_path = tmp_path / "zk" / "artifacts.manifest.json"
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_text("previous\n", encoding="utf-8")
        args = _single_build_args(tmp_path, manifest_path)
        runner = FakeManifestRunner(write_output=False)

        with pytest.raises(bc.BuildError, match="produced no output"):
            bc.cmd_build(args, repo_root=tmp_path, runner=runner)

        assert manifest_path.read_text(encoding="utf-8") == "previous\n"

    def test_failed_build_retains_previous_manifest(self, tmp_path: Path):
        manifest_path = tmp_path / "zk" / "artifacts.manifest.json"
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_text("previous\n", encoding="utf-8")
        (tmp_path / "zk" / "noir" / "silent_witness").mkdir(parents=True)
        args = _single_build_args(tmp_path, manifest_path)
        runner = FakeManifestRunner(fail_nargo_check=True)

        with pytest.raises(bc.BuildError, match="nargo check failed"):
            bc.cmd_build(args, repo_root=tmp_path, runner=runner)

        assert manifest_path.read_text(encoding="utf-8") == "previous\n"
        assert runner.manifest_calls("write") == []

    def test_publish_manifest_file_is_atomic(self, tmp_path: Path):
        manifest_path = tmp_path / "zk" / "artifacts.manifest.json"
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_text("previous\n", encoding="utf-8")
        source = tmp_path / "second.json"
        source.write_text("new\n", encoding="utf-8")
        lock_path = tmp_path / "lock.json"
        lock_path.write_text("{}", encoding="utf-8")
        runner = FakeManifestRunner()

        bc.publish_manifest_file(
            source,
            manifest_path,
            lock_path,
            repo_root=tmp_path,
            runner=runner,
        )

        assert manifest_path.read_text(encoding="utf-8") == "new\n"
        assert source.read_text(encoding="utf-8") == "new\n"
        assert len(runner.manifest_calls("verify")) == 1
