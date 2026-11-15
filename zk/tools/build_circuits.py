#!/usr/bin/env python3
"""Unified circuit build, generation, export, and Soroban artifact preparation tool.

Provides a single tested entry point for building Noir circuits, generating
UltraHonk proofs, exporting proof hex artifacts, and preparing Soroban verifier keys.
All actions enforce toolchain versions pinned in ``zk/toolchain.lock.json``.

Subcommands:
    build           Compile circuits, generate verification keys, and optionally prove/verify.
                    Supports single-circuit builds or isolated double-build reproducibility checks.
    compare-report  Emit a structured two-build artifact reproducibility comparison report.
    generate        Generate witness and proof for a specific circuit (e.g. silent_witness or aggregator).
    export          Export proof, public inputs, and verification key as hex JSON for any circuit.
    prepare-soroban Convert bb UltraHonk verification key into Soroban big-endian verifier format.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import artifact_manifest as _am
except ImportError:
    from zk.tools import artifact_manifest as _am

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOCK = REPO_ROOT / "zk" / "toolchain.lock.json"
DEFAULT_MANIFEST = REPO_ROOT / "zk" / "artifacts.manifest.json"
TOOL_MANIFEST = REPO_ROOT / "zk" / "tools" / "artifact_manifest.py"

DEFAULT_CIRCUITS: tuple[str, ...] = (
    "silent_witness",
    "silent_witness_helper",
    "silent_witness_aggregator",
    "silent_witness_aggregator_helper",
    "revocation_witness",
    "revocation_witness_helper",
    "selective_disclosure",
    "redacted_ancestry",
    "redacted_ancestry_helper",
)

BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_USAGE = 2
EXIT_FATAL = 3

HERMETIC_ENV = {
    "SOURCE_DATE_EPOCH": "0",
    "TZ": "UTC",
    "LC_ALL": "C",
    "LANG": "C",
    "NARGO_BACKEND_PATH": "",
    "RUST_BACKTRACE": "0",
    "PYTHONHASHSEED": "0",
}


class BuildError(RuntimeError):
    """Fatal build error; carries no private material."""

    def __init__(self, message: str, exit_code: int = EXIT_FATAL) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def signal(event: str, detail: str = "", **fields: Any) -> None:
    """Emit one privacy-safe structured signal on stderr."""
    payload = {"event": event, "detail": detail, **fields} if detail else {"event": event, **fields}
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), file=sys.stderr)


def get_hermetic_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(HERMETIC_ENV)
    return env


def apply_umask() -> None:
    if hasattr(os, "umask"):
        try:
            os.umask(0o022)
        except OSError:
            pass


@dataclass(frozen=True)
class ToolchainInfo:
    expected_nargo: str
    expected_bb: str
    actual_nargo: str
    actual_bb: str
    proving_scheme: str
    oracle_hash: str


def load_toolchain_lock(lock_path: Path) -> dict[str, Any]:
    if not lock_path.is_file():
        raise BuildError(f"toolchain lock missing: {lock_path}")
    try:
        return json.loads(lock_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise BuildError(f"unreadable toolchain lock: {exc}") from exc


def extract_semver(text: str) -> str:
    match = re.search(r"(\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?)|(\d+\.\d+\.\d+)", text)
    return match.group(0) if match else ""


def check_toolchain(
    lock_path: Path | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> ToolchainInfo:
    lock_path = lock_path or DEFAULT_LOCK
    lock = load_toolchain_lock(lock_path)
    toolchain = lock.get("toolchain", {})
    expected_nargo = toolchain.get("nargo", {}).get("version", "")
    expected_bb = toolchain.get("barretenberg", {}).get("version", "")
    proving_scheme = toolchain.get("proving_scheme", "ultra_honk")
    oracle_hash = toolchain.get("oracle_hash", "keccak")

    # Verify nargo
    try:
        proc_nargo = runner(
            ["nargo", "--version"],
            capture_output=True,
            text=True,
            check=False,
            env=get_hermetic_env(),
        )
    except FileNotFoundError as exc:
        raise BuildError("nargo not on PATH; see zk/noir/README.md") from exc

    if proc_nargo.returncode != 0:
        raise BuildError("nargo not on PATH; see zk/noir/README.md")

    actual_nargo = extract_semver((proc_nargo.stdout or "") + (proc_nargo.stderr or ""))
    if actual_nargo != expected_nargo:
        raise BuildError(
            f"nargo version drift: expected {expected_nargo}, found {actual_nargo or 'unknown'}"
        )

    # Verify bb
    try:
        proc_bb = runner(
            ["bb", "--version"],
            capture_output=True,
            text=True,
            check=False,
            env=get_hermetic_env(),
        )
    except FileNotFoundError as exc:
        raise BuildError("bb not on PATH; see zk/noir/README.md") from exc

    if proc_bb.returncode != 0:
        raise BuildError("bb not on PATH; see zk/noir/README.md")

    actual_bb = extract_semver((proc_bb.stdout or "") + (proc_bb.stderr or ""))
    if actual_bb != expected_bb:
        raise BuildError(
            f"bb version drift: expected {expected_bb}, found {actual_bb or 'unknown'}"
        )

    signal("toolchain.pinned", detail=f"nargo={actual_nargo} bb={actual_bb}")
    return ToolchainInfo(
        expected_nargo=expected_nargo,
        expected_bb=expected_bb,
        actual_nargo=actual_nargo,
        actual_bb=actual_bb,
        proving_scheme=proving_scheme,
        oracle_hash=oracle_hash,
    )


def run_command(
    cmd: Sequence[str],
    cwd: Path,
    err_msg: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> subprocess.CompletedProcess[str]:
    try:
        proc = runner(
            list(cmd),
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
            env=get_hermetic_env(),
        )
    except FileNotFoundError as exc:
        raise BuildError(f"{err_msg}: command {cmd[0]} not found") from exc

    if proc.returncode != 0:
        err_detail = proc.stderr.strip() or proc.stdout.strip()
        msg = f"{err_msg}: {err_detail}" if err_detail else err_msg
        raise BuildError(msg)
    return proc


def normalize_vk_layout(target_dir: Path) -> None:
    for name in ("vk", "vk_fields.json"):
        dir_path = target_dir / name
        nested_file = dir_path / name
        if dir_path.is_dir() and nested_file.is_file():
            tmp_file = target_dir / f"{name}.tmp"
            nested_file.rename(tmp_file)
            shutil.rmtree(dir_path)
            tmp_file.rename(dir_path)


def compile_circuit(
    circuit: str,
    toolchain: ToolchainInfo,
    repo_root: Path = REPO_ROOT,
    clean: bool = True,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    write_vk_flag: bool | None = None,
    prove: bool = False,
) -> None:
    circuit_dir = repo_root / "zk" / "noir" / circuit
    if not circuit_dir.is_dir():
        signal("circuit.skipped", detail=circuit)
        return

    target_dir = circuit_dir / "target"
    if clean and target_dir.exists():
        shutil.rmtree(target_dir, ignore_errors=True)

    target_dir.mkdir(parents=True, exist_ok=True)

    run_command(["nargo", "check"], circuit_dir, f"nargo check failed for {circuit}", runner=runner)
    run_command(["nargo", "compile"], circuit_dir, f"nargo compile failed for {circuit}", runner=runner)
    signal("circuit.compiled", detail=circuit)

    should_write_vk = write_vk_flag
    if should_write_vk is None:
        should_write_vk = circuit in ("silent_witness", "silent_witness_aggregator")

    bytecode_path = target_dir / f"{circuit}.json"
    if should_write_vk and bytecode_path.is_file():
        run_command(
            [
                "bb",
                "write_vk",
                "--scheme",
                toolchain.proving_scheme,
                "--oracle_hash",
                toolchain.oracle_hash,
                "--bytecode_path",
                f"./target/{circuit}.json",
                "--output_path",
                "./target",
                "--output_format",
                "bytes_and_fields",
            ],
            circuit_dir,
            f"bb write_vk failed for {circuit}",
            runner=runner,
        )
        normalize_vk_layout(target_dir)
        signal("vk.written", detail=circuit)

    if prove:
        run_command(
            ["nargo", "execute", "witness"],
            circuit_dir,
            f"nargo execute witness failed for {circuit}",
            runner=runner,
        )
        run_command(
            [
                "bb",
                "prove",
                "--scheme",
                toolchain.proving_scheme,
                "--oracle_hash",
                toolchain.oracle_hash,
                "--bytecode_path",
                f"./target/{circuit}.json",
                "--witness_path",
                "./target/witness.gz",
                "--output_path",
                "./target",
                "--output_format",
                "bytes_and_fields",
            ],
            circuit_dir,
            f"bb prove failed for {circuit}",
            runner=runner,
        )
        run_command(
            [
                "bb",
                "verify",
                "--scheme",
                toolchain.proving_scheme,
                "--oracle_hash",
                toolchain.oracle_hash,
                "--vk_path",
                "./target/vk",
                "--proof_path",
                "./target/proof",
                "--public_inputs_path",
                "./target/public_inputs",
            ],
            circuit_dir,
            f"bb verify failed for {circuit}",
            runner=runner,
        )
        signal("proof.verified", detail=circuit)


IGNORED_ISOLATED_STAGE_PATTERNS = shutil.ignore_patterns(
    "target",
    "Prover.toml",
    "Verifier.toml",
    "*.gz",
    "proof",
    "public_inputs",
    "__pycache__",
)

_PRIVATE_STAGE_NAMES = frozenset({"Prover.toml", "Verifier.toml", "proof", "public_inputs"})


def build_all_circuits(
    label: str,
    toolchain: ToolchainInfo,
    repo_root: Path = REPO_ROOT,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    circuits: Sequence[str] = DEFAULT_CIRCUITS,
) -> None:
    signal("build.start", detail=label)
    for circuit in circuits:
        compile_circuit(circuit, toolchain, repo_root=repo_root, runner=runner)
    signal("build.done", detail=label)


def stage_isolated_workspace(
    repo_root: Path,
    isolated_root: Path,
    lock_path: Path,
) -> Path:
    """Stage clean circuit sources and lock metadata into an isolated directory.

    Excludes pre-existing ``target/`` directories and private witness inputs
    (``Prover.toml``, ``Verifier.toml``, ``*.gz``, ``proof``, ``public_inputs``)
    so each isolated build compiles from clean source only.
    """
    try:
        lock = _am.load_lock(lock_path)
    except _am.BuildError as exc:
        raise BuildError(str(exc), exit_code=EXIT_FATAL) from exc

    resolved_repo = repo_root.resolve()
    resolved_isolated = isolated_root.resolve()
    circuit_root_dir = (resolved_repo / lock.circuit_root).resolve()

    if resolved_isolated == resolved_repo or resolved_isolated in resolved_repo.parents:
        raise BuildError(
            "isolated build directory must not equal or contain repository root",
            exit_code=EXIT_USAGE,
        )
    if resolved_isolated == circuit_root_dir or circuit_root_dir in resolved_isolated.parents:
        raise BuildError(
            "isolated build directory must not reside inside circuit source root",
            exit_code=EXIT_USAGE,
        )

    if resolved_isolated.exists():
        shutil.rmtree(resolved_isolated)
    resolved_isolated.mkdir(parents=True, exist_ok=True)

    staged_lock = resolved_isolated / "zk" / "toolchain.lock.json"
    staged_lock.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(lock_path, staged_lock)
    try:
        rel_lock = lock_path.resolve().relative_to(resolved_repo)
        custom_staged_lock = resolved_isolated / rel_lock
        if custom_staged_lock != staged_lock:
            custom_staged_lock.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(lock_path, custom_staged_lock)
            staged_lock = custom_staged_lock
    except ValueError:
        pass

    src_circuits = resolved_repo / lock.circuit_root
    if src_circuits.is_dir():
        dst_circuits = resolved_isolated / lock.circuit_root
        shutil.copytree(
            src_circuits,
            dst_circuits,
            ignore=IGNORED_ISOLATED_STAGE_PATTERNS,
            dirs_exist_ok=True,
        )

    for pattern in lock.provenance_globs:
        for src_file in sorted(resolved_repo.glob(pattern)):
            if not src_file.is_file():
                continue
            rel_file = src_file.resolve().relative_to(resolved_repo)
            if (
                "target" in rel_file.parts
                or rel_file.name in _PRIVATE_STAGE_NAMES
                or rel_file.suffix == ".gz"
            ):
                continue
            dst_file = resolved_isolated / rel_file
            if not dst_file.exists():
                dst_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src_file, dst_file)

    for decl in lock.artifacts:
        rel_str = str(decl.get("path", ""))
        if not rel_str or rel_str.startswith("/") or ".." in rel_str.split("/"):
            continue
        if "target" in Path(rel_str).parts:
            continue
        src_art = resolved_repo / rel_str
        if src_art.is_file():
            dst_art = resolved_isolated / rel_str
            dst_art.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src_art, dst_art)

    return staged_lock


def _promote_isolated_targets(
    isolated_root: Path,
    repo_root: Path,
    circuits: Sequence[str] = DEFAULT_CIRCUITS,
    circuit_root: str = "zk/noir",
) -> None:
    base_rel = Path(circuit_root)
    for circuit in circuits:
        src_target = isolated_root / base_rel / circuit / "target"
        if not src_target.is_dir():
            continue
        dst_target = repo_root / base_rel / circuit / "target"
        if dst_target.exists():
            shutil.rmtree(dst_target)
        dst_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src_target, dst_target)


def _digest_isolated_build(
    isolated_root: Path,
    staged_lock_path: Path,
    label: str,
) -> dict[str, Any]:
    lock = _am.load_lock(staged_lock_path)
    manifest_doc, run = _am.build_manifest(lock, isolated_root)
    for entry in run.fatal:
        _am.signal("run.fatal", path=entry.path, state=entry.state)
    for entry in run.missing_required:
        _am.signal("run.fatal", path=entry.path, state=entry.state)
    if run.fatal or run.missing_required:
        raise BuildError(f"manifest write failed on {label} build", exit_code=EXIT_FATAL)
    (isolated_root / "artifacts.manifest.json").write_text(
        _am.serialize_manifest(manifest_doc),
        encoding="utf-8",
    )
    return manifest_doc


def run_isolated_double_build(
    toolchain: ToolchainInfo,
    *,
    repo_root: Path = REPO_ROOT,
    lock_path: Path | None = None,
    manifest_path: Path | None = None,
    report_path: Path | None = None,
    work_dir: Path | None = None,
    strict_raw: bool = False,
    circuits: Sequence[str] = DEFAULT_CIRCUITS,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[int, dict[str, Any]]:
    """Run two full builds in isolated directories and compare canonical digests."""
    resolved_lock = lock_path or (repo_root / "zk" / "toolchain.lock.json")
    try:
        lock = _am.load_lock(resolved_lock)
    except _am.BuildError as exc:
        raise BuildError(str(exc), exit_code=EXIT_FATAL) from exc

    if work_dir is not None:
        resolved_repo = repo_root.resolve()
        resolved_work = work_dir.resolve()
        circuit_root_dir = (resolved_repo / lock.circuit_root).resolve()
        if resolved_work == resolved_repo or resolved_work in resolved_repo.parents:
            raise BuildError(
                "work directory must not equal or contain repository root",
                exit_code=EXIT_USAGE,
            )
        if resolved_work == circuit_root_dir or circuit_root_dir in resolved_work.parents:
            raise BuildError(
                "work directory must not reside inside circuit source root",
                exit_code=EXIT_USAGE,
            )
        work_dir.mkdir(parents=True, exist_ok=True)
        work_ctx: Any = nullcontext(str(work_dir))
    else:
        work_ctx = tempfile.TemporaryDirectory(prefix="harpocrates-repro-")

    with work_ctx as raw_work:
        work = Path(raw_work)
        isolated_1 = work / "build_1"
        isolated_2 = work / "build_2"

        staged_lock_1 = stage_isolated_workspace(repo_root, isolated_1, resolved_lock)
        staged_lock_2 = stage_isolated_workspace(repo_root, isolated_2, resolved_lock)
        signal("reproducibility.isolated.staged", builds=2)

        build_all_circuits(
            "first",
            toolchain,
            repo_root=isolated_1,
            runner=runner,
            circuits=circuits,
        )
        first_doc = _digest_isolated_build(isolated_1, staged_lock_1, "first")

        build_all_circuits(
            "second",
            toolchain,
            repo_root=isolated_2,
            runner=runner,
            circuits=circuits,
        )
        second_doc = _digest_isolated_build(isolated_2, staged_lock_2, "second")

        report = _am.build_reproducibility_report(
            first_doc,
            second_doc,
            first_label="build_1",
            second_label="build_2",
            isolated_directories=True,
        )
        if report_path is not None:
            _am.write_reproducibility_report(report, report_path)

        passed, fatal_findings, metadata_notices = _am.evaluate_reproducibility_report(
            report,
            strict_raw=strict_raw,
        )
        for notice in metadata_notices:
            _am.signal("reproducibility.metadata_only", detail=notice)

        if not passed:
            for finding in fatal_findings:
                _am.signal("drift.finding", detail=finding)
            _am.signal(
                "compare.failed",
                findings=len(fatal_findings),
                verdict=report["verdict"],
            )
            signal(
                "run.failed",
                detail="builds are not reproducible",
                verdict=report["verdict"],
            )
            return EXIT_DRIFT, report

        _am.signal(
            "compare.ok",
            artifacts=report["summary"]["total_artifacts"],
            nondeterministic_metadata=report["summary"]["nondeterministic_metadata"],
            verdict=report["verdict"],
        )
        _promote_isolated_targets(
            isolated_2,
            repo_root,
            circuits=circuits,
            circuit_root=lock.circuit_root,
        )
        if manifest_path is not None:
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(_am.serialize_manifest(second_doc), encoding="utf-8")
        signal("run.ok", detail="reproducible; manifest written", verdict=report["verdict"])
        return EXIT_OK, report


def run_manifest_tool(
    args: Sequence[str],
    repo_root: Path = REPO_ROOT,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int:
    cmd = [sys.executable, str(TOOL_MANIFEST), *args]
    proc = runner(
        cmd,
        cwd=str(repo_root),
        check=False,
        env=get_hermetic_env(),
    )
    return proc.returncode


def cmd_build(
    args: argparse.Namespace,
    repo_root: Path = REPO_ROOT,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int:
    apply_umask()
    lock_path = Path(args.lock) if args.lock else (repo_root / "zk" / "toolchain.lock.json")
    manifest_path = Path(args.manifest) if args.manifest else (repo_root / "zk" / "artifacts.manifest.json")

    # If check-coverage requested
    if args.check_coverage:
        return _am.main(["--lock", str(lock_path), "--root", str(repo_root), "check-coverage"])

    circuit = args.circuit or "all"
    if args.all:
        circuit = "all"

    # For builds, check coverage gate first when building all
    if circuit == "all":
        cov_status = _am.main(["--lock", str(lock_path), "--root", str(repo_root), "check-coverage"])
        if cov_status != 0:
            raise BuildError("circuit coverage check failed; see drift.finding above", exit_code=cov_status)

    toolchain = check_toolchain(lock_path=lock_path, runner=runner)

    if circuit != "all":
        compile_circuit(
            circuit,
            toolchain,
            repo_root=repo_root,
            clean=args.clean,
            runner=runner,
            write_vk_flag=args.vk if args.vk else None,
            prove=args.prove,
        )
        signal("circuit.done", detail=circuit)
        return EXIT_OK

    # Building all circuits under specified mode
    mode = "double"
    if args.single:
        mode = "single"
    elif args.verify:
        mode = "verify"

    if mode == "single":
        build_all_circuits("single", toolchain, repo_root=repo_root, runner=runner)
        status = _am.main(
            ["--lock", str(lock_path), "--root", str(repo_root), "write", "--output", str(manifest_path)]
        )
        if status != 0:
            raise BuildError("manifest write failed", exit_code=status)
        signal("run.ok", detail="manifest written")
        return EXIT_OK

    if mode == "verify":
        build_all_circuits("verify", toolchain, repo_root=repo_root, runner=runner)
        return _am.main(
            ["--lock", str(lock_path), "--root", str(repo_root), "verify", "--manifest", str(manifest_path)]
        )

    # Isolated double build with canonical digest comparison report
    report_path = Path(args.report) if getattr(args, "report", None) else None
    work_dir = Path(args.work_dir) if getattr(args, "work_dir", None) else None
    strict_raw = bool(getattr(args, "strict_raw", False))
    declared_circuits = tuple(sorted(_am.declared_circuit_names(_am.load_lock(lock_path))))
    active_circuits = declared_circuits or DEFAULT_CIRCUITS
    status, _ = run_isolated_double_build(
        toolchain,
        repo_root=repo_root,
        lock_path=lock_path,
        manifest_path=manifest_path,
        report_path=report_path,
        work_dir=work_dir,
        strict_raw=strict_raw,
        circuits=active_circuits,
        runner=runner,
    )
    return status


def cmd_compare_report(args: argparse.Namespace) -> int:
    cli_args: list[str] = ["compare-report", args.first, args.second]
    if args.output:
        cli_args.extend(["--output", args.output])
    if args.first_label:
        cli_args.extend(["--first-label", args.first_label])
    if args.second_label:
        cli_args.extend(["--second-label", args.second_label])
    if args.isolated:
        cli_args.append("--isolated")
    if args.strict_raw:
        cli_args.append("--strict-raw")
    return _am.main(cli_args)


def cmd_export(args: argparse.Namespace, repo_root: Path = REPO_ROOT) -> int:
    circuit = args.circuit or "silent_witness"
    target_dir = Path(args.target_dir) if args.target_dir else (repo_root / "zk" / "noir" / circuit / "target")

    files = {
        "proof": target_dir / "proof",
        "publicInputs": target_dir / "public_inputs",
        "verificationKey": target_dir / "vk",
    }

    for key, path in files.items():
        if not path.is_file():
            raise BuildError(f"Missing {key} artifact at {path}. Run build first.")

    result = {
        "proof": files["proof"].read_bytes().hex(),
        "publicInputs": files["publicInputs"].read_bytes().hex(),
        "verificationKey": files["verificationKey"].read_bytes().hex(),
    }

    output_str = json.dumps(result, indent=2)
    print(output_str)

    if args.output:
        Path(args.output).write_text(output_str, encoding="utf-8")

    return EXIT_OK


def cmd_prepare_soroban(args: argparse.Namespace, repo_root: Path = REPO_ROOT) -> int:
    circuit = args.circuit or "silent_witness"
    target_dir = Path(args.target_dir) if args.target_dir else (repo_root / "zk" / "noir" / circuit / "target")
    vk_path = target_dir / "vk"
    soroban_vk_path = target_dir / "vk_soroban"

    if not vk_path.is_file():
        raise BuildError(f"Missing VK artifact at {vk_path}. Run build first.")

    vk = vk_path.read_bytes()
    if len(vk) == 1764:
        stripped = bytearray(vk[4:])
        for offset in range(0, 32, 8):
            first = stripped[offset : offset + 4]
            second = stripped[offset + 4 : offset + 8]
            stripped[offset : offset + 4] = second
            stripped[offset + 4 : offset + 8] = first
        soroban_vk_path.write_bytes(bytes(stripped))
    elif len(vk) == 1760:
        soroban_vk_path.write_bytes(vk)
    else:
        raise BuildError(
            f"Unexpected VK length {len(vk)}. Expected 1764 from bb or 1760 for Soroban verifier."
        )

    result = {
        "vk": str(vk_path),
        "vkBytes": len(vk),
        "sorobanVk": str(soroban_vk_path),
        "sorobanVkBytes": len(soroban_vk_path.read_bytes()),
        "proof": str(target_dir / "proof"),
        "publicInputs": str(target_dir / "public_inputs"),
    }

    output_str = json.dumps(result, indent=2)
    print(output_str)

    if args.output:
        Path(args.output).write_text(output_str, encoding="utf-8")

    return EXIT_OK


def _generate_silent_witness(
    video_hash: str,
    credential_secret: str,
    nullifier_secret: str,
    output_dir: str | None,
    toolchain: ToolchainInfo,
    repo_root: Path = REPO_ROOT,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int:
    if not re.match(r"^[0-9a-fA-F]{64}$", video_hash):
        raise BuildError("video hash must be a 32-byte hex string", exit_code=EXIT_USAGE)

    hi_hex = video_hash[:32]
    lo_hex = video_hash[32:]
    hi_dec = str(int(hi_hex, 16))
    lo_dec = str(int(lo_hex, 16))

    helper_dir = repo_root / "zk" / "noir" / "silent_witness_helper"
    circuit_dir = repo_root / "zk" / "noir" / "silent_witness"
    helper_toml = helper_dir / "Prover.toml"
    circuit_toml = circuit_dir / "Prover.toml"

    helper_backup = helper_toml.read_text(encoding="utf-8") if helper_toml.is_file() else None
    circuit_backup = circuit_toml.read_text(encoding="utf-8") if circuit_toml.is_file() else None

    try:
        helper_toml.write_text(
            f'credential_secret = "{credential_secret}"\n'
            f'nullifier_secret = "{nullifier_secret}"\n'
            f'video_hash_hi = "{hi_dec}"\n'
            f'video_hash_lo = "{lo_dec}"\n',
            encoding="utf-8",
        )

        proc_helper = run_command(
            ["nargo", "execute", "generated_helper"],
            helper_dir,
            "silent_witness_helper execution failed",
            runner=runner,
        )
        combined_out = proc_helper.stdout + proc_helper.stderr
        raw_fields = re.findall(r"Field\((-?\d+)\)", combined_out)
        values = [int(v) % BN254_MODULUS for v in raw_fields]
        if len(values) != 2:
            raise BuildError(f"Expected 2 Field values from helper, got {len(values)}: {values}")

        credential_root = f"0x{values[0]:064x}"
        nullifier = f"0x{values[1]:064x}"

        circuit_toml.write_text(
            f'credential_secret = "{credential_secret}"\n'
            f'nullifier_secret = "{nullifier_secret}"\n'
            f'video_hash_hi = "{hi_dec}"\n'
            f'video_hash_lo = "{lo_dec}"\n'
            f'credential_root = "{credential_root}"\n'
            f'nullifier = "{nullifier}"\n',
            encoding="utf-8",
        )

        run_command(["nargo", "check"], circuit_dir, "nargo check failed", runner=runner)
        run_command(["nargo", "execute", "witness"], circuit_dir, "witness execution failed", runner=runner)
        run_command(
            [
                "bb",
                "prove",
                "--scheme",
                toolchain.proving_scheme,
                "--oracle_hash",
                toolchain.oracle_hash,
                "--bytecode_path",
                "./target/silent_witness.json",
                "--witness_path",
                "./target/witness.gz",
                "--output_path",
                "./target",
                "--output_format",
                "bytes_and_fields",
            ],
            circuit_dir,
            "bb prove failed",
            runner=runner,
        )
        run_command(
            [
                "bb",
                "verify",
                "--scheme",
                toolchain.proving_scheme,
                "--oracle_hash",
                toolchain.oracle_hash,
                "--vk_path",
                "./target/vk",
                "--proof_path",
                "./target/proof",
                "--public_inputs_path",
                "./target/public_inputs",
            ],
            circuit_dir,
            "bb verify failed",
            runner=runner,
        )

        out_path = Path(output_dir) if output_dir else (circuit_dir / "target" / "generated" / video_hash.lower())
        out_path.mkdir(parents=True, exist_ok=True)

        proof_file = circuit_dir / "target" / "proof"
        public_inputs_file = circuit_dir / "target" / "public_inputs"

        dst_proof = out_path / "proof"
        dst_public_inputs = out_path / "public_inputs"

        shutil.copyfile(proof_file, dst_proof)
        shutil.copyfile(public_inputs_file, dst_public_inputs)

        proof_bytes = dst_proof.read_bytes()
        public_inputs_bytes = dst_public_inputs.read_bytes()

        manifest = {
            "videoHash": video_hash.lower(),
            "credentialRoot": credential_root.removeprefix("0x"),
            "nullifier": nullifier.removeprefix("0x"),
            "proof": proof_bytes.hex(),
            "publicInputs": public_inputs_bytes.hex(),
            "proofBytes": len(proof_bytes),
            "publicInputBytes": len(public_inputs_bytes),
            "proofPath": str(dst_proof),
            "publicInputsPath": str(dst_public_inputs),
        }
        print(json.dumps(manifest))
        return EXIT_OK
    finally:
        if helper_backup is not None:
            helper_toml.write_text(helper_backup, encoding="utf-8")
        if circuit_backup is not None:
            circuit_toml.write_text(circuit_backup, encoding="utf-8")


def _generate_aggregator(
    video_hashes: list[str],
    credential_secret: str,
    nullifier_secret: str,
    output_dir: str | None,
    toolchain: ToolchainInfo,
    repo_root: Path = REPO_ROOT,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int:
    batch_count = len(video_hashes)
    if batch_count < 1 or batch_count > 8:
        err = {
            "protocol": "harpocrates",
            "version": 1,
            "type": "error",
            "reasonCode": "oversized",
            "detail": f"batch size must be between 1 and 8 (got {batch_count})",
        }
        print(json.dumps(err))
        return EXIT_OK

    for i, vh in enumerate(video_hashes):
        if not re.match(r"^[0-9a-fA-F]{64}$", vh):
            err = {
                "protocol": "harpocrates",
                "version": 1,
                "type": "error",
                "reasonCode": "malformed",
                "detail": f"video hash {i} must be a 32-byte hex string",
            }
            print(json.dumps(err))
            return EXIT_OK

    helper_dir = repo_root / "zk" / "noir" / "silent_witness_aggregator_helper"
    circuit_dir = repo_root / "zk" / "noir" / "silent_witness_aggregator"
    helper_toml = helper_dir / "Prover.toml"
    circuit_toml = circuit_dir / "Prover.toml"

    helper_backup = helper_toml.read_text(encoding="utf-8") if helper_toml.is_file() else None
    circuit_backup = circuit_toml.read_text(encoding="utf-8") if circuit_toml.is_file() else None

    try:
        helper_content = [
            f'credential_secret = "{credential_secret}"',
            f'nullifier_secret = "{nullifier_secret}"',
        ]
        for i in range(batch_count):
            vh = video_hashes[i]
            hi_dec = str(int(vh[:32], 16))
            lo_dec = str(int(vh[32:], 16))
            helper_content.append(f'video_hash_hi_{i} = "{hi_dec}"')
            helper_content.append(f'video_hash_lo_{i} = "{lo_dec}"')
        for i in range(batch_count, 8):
            helper_content.append(f'video_hash_hi_{i} = "0"')
            helper_content.append(f'video_hash_lo_{i} = "0"')

        helper_toml.write_text("\n".join(helper_content) + "\n", encoding="utf-8")

        proc_helper = run_command(
            ["nargo", "execute", "generated_helper"],
            helper_dir,
            "silent_witness_aggregator_helper execution failed",
            runner=runner,
        )
        combined_out = proc_helper.stdout + proc_helper.stderr
        raw_fields = re.findall(r"Field\((-?\d+)\)", combined_out)
        values = [int(v) % BN254_MODULUS for v in raw_fields]
        if len(values) != 16:
            err = {
                "protocol": "harpocrates",
                "version": 1,
                "type": "error",
                "reasonCode": "dependency-failure",
                "detail": f"Expected 16 field values from aggregator helper, got {len(values)}",
            }
            print(json.dumps(err))
            return EXIT_OK

        pairs = [f"0x{v:064x}" for v in values]

        circuit_content = [
            f'credential_secret = "{credential_secret}"',
            f'nullifier_secret = "{nullifier_secret}"',
        ]
        for i in range(8):
            cr_root = pairs[i * 2]
            nullifier = pairs[i * 2 + 1]
            if i < batch_count:
                vh = video_hashes[i]
                hi_dec = str(int(vh[:32], 16))
                lo_dec = str(int(vh[32:], 16))
            else:
                hi_dec = "0"
                lo_dec = "0"
            circuit_content.append(f'video_hash_hi_{i} = "{hi_dec}"')
            circuit_content.append(f'video_hash_lo_{i} = "{lo_dec}"')
            circuit_content.append(f'credential_root_{i} = "{cr_root}"')
            circuit_content.append(f'nullifier_{i} = "{nullifier}"')

        circuit_toml.write_text("\n".join(circuit_content) + "\n", encoding="utf-8")

        run_command(["nargo", "check"], circuit_dir, "nargo check failed", runner=runner)
        run_command(["nargo", "execute", "witness"], circuit_dir, "witness execution failed", runner=runner)
        run_command(
            [
                "bb",
                "prove",
                "--scheme",
                toolchain.proving_scheme,
                "--oracle_hash",
                toolchain.oracle_hash,
                "--bytecode_path",
                "./target/silent_witness_aggregator.json",
                "--witness_path",
                "./target/witness.gz",
                "--output_path",
                "./target",
                "--output_format",
                "bytes_and_fields",
            ],
            circuit_dir,
            "bb prove failed",
            runner=runner,
        )
        run_command(
            [
                "bb",
                "verify",
                "--scheme",
                toolchain.proving_scheme,
                "--oracle_hash",
                toolchain.oracle_hash,
                "--vk_path",
                "./target/vk",
                "--proof_path",
                "./target/proof",
                "--public_inputs_path",
                "./target/public_inputs",
            ],
            circuit_dir,
            "bb verify failed",
            runner=runner,
        )

        all_args_str = " ".join([*video_hashes, credential_secret, nullifier_secret])
        batch_id = hashlib.sha256(all_args_str.encode("utf-8")).hexdigest()

        out_path = Path(output_dir) if output_dir else (circuit_dir / "target" / "generated" / f"batch-{batch_id}")
        out_path.mkdir(parents=True, exist_ok=True)

        proof_file = circuit_dir / "target" / "proof"
        public_inputs_file = circuit_dir / "target" / "public_inputs"

        dst_proof = out_path / "proof"
        dst_public_inputs = out_path / "public_inputs"

        shutil.copyfile(proof_file, dst_proof)
        shutil.copyfile(public_inputs_file, dst_public_inputs)

        proof_bytes = dst_proof.read_bytes()
        public_inputs_bytes = dst_public_inputs.read_bytes()

        manifest = {
            "protocol": "harpocrates",
            "version": 1,
            "type": "aggregated_batch",
            "batchId": batch_id,
            "batchSize": batch_count,
            "maxBatchSize": 8,
            "videoHashes": [vh.lower() for vh in video_hashes],
            "proof": proof_bytes.hex(),
            "publicInputs": public_inputs_bytes.hex(),
            "proofBytes": len(proof_bytes),
            "publicInputBytes": len(public_inputs_bytes),
            "proofPath": str(dst_proof),
            "publicInputsPath": str(dst_public_inputs),
        }
        print(json.dumps(manifest))
        return EXIT_OK
    except Exception as exc:
        err = {
            "protocol": "harpocrates",
            "version": 1,
            "type": "error",
            "reasonCode": "dependency-failure",
            "detail": f"Aggregator script failed unexpectedly: {exc}",
        }
        print(json.dumps(err))
        return EXIT_OK
    finally:
        if helper_backup is not None:
            helper_toml.write_text(helper_backup, encoding="utf-8")
        if circuit_backup is not None:
            circuit_toml.write_text(circuit_backup, encoding="utf-8")


def _generate_generic_circuit(
    circuit: str,
    output_dir: str | None,
    toolchain: ToolchainInfo,
    repo_root: Path = REPO_ROOT,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int:
    circuit_dir = repo_root / "zk" / "noir" / circuit
    if not circuit_dir.is_dir():
        raise BuildError(f"Circuit directory does not exist: {circuit_dir}")

    run_command(["nargo", "check"], circuit_dir, f"nargo check failed for {circuit}", runner=runner)
    run_command(["nargo", "execute", "witness"], circuit_dir, f"witness execution failed for {circuit}", runner=runner)
    run_command(
        [
            "bb",
            "prove",
            "--scheme",
            toolchain.proving_scheme,
            "--oracle_hash",
            toolchain.oracle_hash,
            "--bytecode_path",
            f"./target/{circuit}.json",
            "--witness_path",
            "./target/witness.gz",
            "--output_path",
            "./target",
            "--output_format",
            "bytes_and_fields",
        ],
        circuit_dir,
        f"bb prove failed for {circuit}",
        runner=runner,
    )

    out_path = Path(output_dir) if output_dir else (circuit_dir / "target" / "generated")
    out_path.mkdir(parents=True, exist_ok=True)

    proof_file = circuit_dir / "target" / "proof"
    public_inputs_file = circuit_dir / "target" / "public_inputs"

    dst_proof = out_path / "proof"
    dst_public_inputs = out_path / "public_inputs"

    shutil.copyfile(proof_file, dst_proof)
    shutil.copyfile(public_inputs_file, dst_public_inputs)

    proof_bytes = dst_proof.read_bytes()
    public_inputs_bytes = dst_public_inputs.read_bytes()

    manifest = {
        "circuit": circuit,
        "proof": proof_bytes.hex(),
        "publicInputs": public_inputs_bytes.hex(),
        "proofBytes": len(proof_bytes),
        "publicInputBytes": len(public_inputs_bytes),
        "proofPath": str(dst_proof),
        "publicInputsPath": str(dst_public_inputs),
    }
    print(json.dumps(manifest))
    return EXIT_OK


def cmd_generate(
    args: argparse.Namespace,
    repo_root: Path = REPO_ROOT,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int:
    apply_umask()
    toolchain = check_toolchain(runner=runner)
    circuit = args.circuit

    # Dissect positional args and optional flags
    pos_args: list[str] = list(args.args or [])

    if circuit == "silent_witness":
        video_hash = args.video_hash or (pos_args[0] if len(pos_args) > 0 else "")
        credential_secret = args.credential_secret or (pos_args[1] if len(pos_args) > 1 else "")
        nullifier_secret = args.nullifier_secret or (pos_args[2] if len(pos_args) > 2 else "")
        output_dir = args.output_dir or (pos_args[3] if len(pos_args) > 3 else None)

        if not video_hash or not credential_secret or not nullifier_secret:
            raise BuildError(
                "usage: generate silent_witness <video-hash-hex> <credential-secret-field> <nullifier-secret-field> [output-dir]",
                exit_code=EXIT_USAGE,
            )

        return _generate_silent_witness(
            video_hash=video_hash,
            credential_secret=credential_secret,
            nullifier_secret=nullifier_secret,
            output_dir=output_dir,
            toolchain=toolchain,
            repo_root=repo_root,
            runner=runner,
        )

    if circuit == "silent_witness_aggregator":
        video_hashes = list(args.video_hashes or [])
        credential_secret = args.credential_secret or ""
        nullifier_secret = args.nullifier_secret or ""
        output_dir = args.output_dir

        if pos_args:
            # Parse like generate-silent-witness-aggregator.sh
            # Last 2 or 3 args are secrets and optional output_dir
            if len(pos_args) >= 4:
                second_last = pos_args[-2]
                last_arg = pos_args[-1]
                if second_last.isdigit() and last_arg.isdigit():
                    credential_secret = second_last
                    nullifier_secret = last_arg
                    video_hashes = pos_args[:-2]
                elif second_last.isdigit():
                    credential_secret = pos_args[-3]
                    nullifier_secret = second_last
                    output_dir = last_arg
                    video_hashes = pos_args[:-3]
                else:
                    err = {
                        "protocol": "harpocrates",
                        "version": 1,
                        "type": "error",
                        "reasonCode": "malformed",
                        "detail": "invalid arguments. Provide field decimal secrets.",
                    }
                    print(json.dumps(err))
                    return EXIT_OK
            else:
                err = {
                    "protocol": "harpocrates",
                    "version": 1,
                    "type": "error",
                    "reasonCode": "malformed",
                    "detail": "usage: generate silent_witness_aggregator <hash0> [<hash1>...] <cred_secret> <null_secret> [output-dir]",
                }
                print(json.dumps(err))
                return EXIT_OK

        if not video_hashes or not credential_secret or not nullifier_secret:
            err = {
                "protocol": "harpocrates",
                "version": 1,
                "type": "error",
                "reasonCode": "malformed",
                "detail": "Missing required arguments for aggregator",
            }
            print(json.dumps(err))
            return EXIT_OK

        return _generate_aggregator(
            video_hashes=video_hashes,
            credential_secret=credential_secret,
            nullifier_secret=nullifier_secret,
            output_dir=output_dir,
            toolchain=toolchain,
            repo_root=repo_root,
            runner=runner,
        )

    # Any other circuit
    return _generate_generic_circuit(
        circuit=circuit,
        output_dir=args.output_dir or (pos_args[0] if pos_args else None),
        toolchain=toolchain,
        repo_root=repo_root,
        runner=runner,
    )


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build_circuits.py",
        description="Unified driver for Noir circuit building, proof generation, and artifact export.",
    )
    parser.add_argument(
        "--check-toolchain",
        action="store_true",
        help="Check toolchain versions against zk/toolchain.lock.json and exit.",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to execute")

    # --- build ---
    p_build = subparsers.add_parser("build", help="Build circuit(s)")
    p_build.add_argument("circuit", nargs="?", default="all", help="Circuit name or 'all'")
    p_build.add_argument("--circuit", dest="circuit_opt", default=None, help="Explicit circuit name")
    p_build.add_argument("--all", action="store_true", help="Build all declared circuits")
    p_build.add_argument("--single", action="store_true", help="Build once and write manifest")
    p_build.add_argument("--verify", action="store_true", help="Build once and verify against manifest")
    p_build.add_argument("--check-coverage", action="store_true", help="Coverage gate check only")
    p_build.add_argument("--double", action="store_true", help="Double build and compare (default for all)")
    p_build.add_argument("--prove", action="store_true", help="Execute witness and generate proof")
    p_build.add_argument("--vk", action="store_true", help="Force writing verification key")
    p_build.add_argument("--clean", action="store_true", default=True, help="Clean target before build")
    p_build.add_argument("--manifest", default=None, help="Path to manifest file")
    p_build.add_argument("--lock", default=None, help="Path to toolchain lock file")
    p_build.add_argument(
        "--report",
        default=None,
        help="Optional path to write structured two-build reproducibility comparison report JSON",
    )
    p_build.add_argument(
        "--work-dir",
        default=None,
        help="Optional parent directory for isolated build_1 and build_2 workspaces",
    )
    p_build.add_argument(
        "--strict-raw",
        action="store_true",
        help="Treat nondeterministic raw metadata differences as fatal drift",
    )

    # --- compare-report ---
    p_report = subparsers.add_parser(
        "compare-report",
        help="Emit a structured two-build reproducibility comparison report from two manifests",
    )
    p_report.add_argument("first", help="First build manifest path")
    p_report.add_argument("second", help="Second build manifest path")
    p_report.add_argument(
        "--output",
        default=None,
        help="Optional path to write report JSON (prints to stdout when omitted)",
    )
    p_report.add_argument("--first-label", default="build_1", help="Label for first build")
    p_report.add_argument("--second-label", default="build_2", help="Label for second build")
    p_report.add_argument(
        "--isolated",
        action="store_true",
        help="Record that both manifests came from isolated output directories",
    )
    p_report.add_argument(
        "--strict-raw",
        action="store_true",
        help="Treat nondeterministic raw metadata differences as fatal drift",
    )

    # --- generate ---
    p_gen = subparsers.add_parser("generate", help="Generate proof and public inputs for a circuit")
    p_gen.add_argument("circuit", help="Circuit name to generate proof for")
    p_gen.add_argument("args", nargs="*", help="Positional arguments for generation")
    p_gen.add_argument("--video-hash", default=None, help="Video hash (32-byte hex string)")
    p_gen.add_argument("--video-hashes", nargs="+", default=None, help="List of video hashes")
    p_gen.add_argument("--credential-secret", default=None, help="Credential secret field decimal")
    p_gen.add_argument("--nullifier-secret", default=None, help="Nullifier secret field decimal")
    p_gen.add_argument("--output-dir", default=None, help="Output directory for generated artifacts")
    p_gen.add_argument("--verifier-scope", default="0", help="Verifier scope (optional)")
    p_gen.add_argument("--epoch", type=int, default=0, help="Epoch (optional)")

    # --- export ---
    p_exp = subparsers.add_parser("export", help="Export proof, public inputs, and VK as hex JSON")
    p_exp.add_argument("circuit", nargs="?", default="silent_witness", help="Circuit name")
    p_exp.add_argument("--circuit", dest="circuit_opt", default=None, help="Explicit circuit name")
    p_exp.add_argument("--target-dir", default=None, help="Circuit target directory")
    p_exp.add_argument("--output", default=None, help="Output JSON file path")

    # --- prepare-soroban ---
    p_soroban = subparsers.add_parser("prepare-soroban", help="Prepare VK artifact for Soroban verifier")
    p_soroban.add_argument("circuit", nargs="?", default="silent_witness", help="Circuit name")
    p_soroban.add_argument("--circuit", dest="circuit_opt", default=None, help="Explicit circuit name")
    p_soroban.add_argument("--target-dir", default=None, help="Circuit target directory")
    p_soroban.add_argument("--output", default=None, help="Output JSON file path")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.check_toolchain:
        try:
            check_toolchain()
            return EXIT_OK
        except BuildError as exc:
            signal("build.error", detail=str(exc))
            return exc.exit_code

    if not args.subcommand:
        parser.print_help()
        return EXIT_USAGE

    try:
        # Reconcile explicit circuit flags
        if hasattr(args, "circuit_opt") and args.circuit_opt:
            args.circuit = args.circuit_opt

        if args.subcommand == "build":
            return cmd_build(args)
        if args.subcommand == "compare-report":
            return cmd_compare_report(args)
        if args.subcommand == "export":
            return cmd_export(args)
        if args.subcommand == "prepare-soroban":
            return cmd_prepare_soroban(args)
        if args.subcommand == "generate":
            return cmd_generate(args)

        parser.print_help()
        return EXIT_USAGE
    except BuildError as exc:
        signal("build.error", detail=str(exc))
        return exc.exit_code


if __name__ == "__main__":
    sys.exit(main())
