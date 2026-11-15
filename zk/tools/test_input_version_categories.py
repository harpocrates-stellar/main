"""Focused tests for stable circuit input version error categories (#1208).

Verifies:
- Unsupported input_schema_version and circuit_version values fail under the
  stable ``unsupported_input_version`` category before invoking nargo or bb.
- Version mismatches are strictly distinguished from ``unsatisfied_constraint``
  and ``malformed_input`` categories and exit codes.
- Boundary cases (version 0, negative, u32 overflow / dirty upper bytes,
  downgraded v1 vs current v2, future v3, boolean / non-numeric) are covered.
- Rejection messages and structured signals never echo private witness material.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_TOOLS_DIR = str(Path(__file__).resolve().parent)
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

import build_circuits as bc
import validate_prover_inputs as vpi
from validate_prover_inputs import (
    EXIT_MALFORMED_INPUT,
    EXIT_OK,
    EXIT_UNSATISFIED_CONSTRAINT,
    EXIT_UNSUPPORTED_VERSION,
    ProverErrorCategory,
    ProverInputValidationError,
    classify_prover_execution_error,
    load_schema,
    validate_envelope_inputs,
    validate_prover_inputs,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "zk" / "noir" / "circuit_input_schema_v1.json"
VECTORS_PATH = REPO_ROOT / "zk" / "vectors" / "circuit_input_schema_v1.json"


def _synthetic_prover_data(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "credential_secret": "12345",
        "nullifier_secret": "67890",
        "video_hash_hi": "1",
        "video_hash_lo": "2",
        "verifier_scope": "0",
        "epoch": "0",
        "circuit_version": "2",
    }
    base.update(overrides)
    return base


def test_schema_declares_supported_versions_and_error_categories() -> None:
    schema = load_schema(SCHEMA_PATH)
    assert schema["supported_versions"]["input_schema"] == {
        "min": 1,
        "max": 1,
        "current": 1,
    }
    assert schema["supported_versions"]["circuits"]["silent_witness"] == 2
    assert schema["supported_versions"]["circuits"]["selective_disclosure"] == 1
    assert schema["error_categories"] == [
        "unsupported_input_version",
        "malformed_input",
        "unsatisfied_constraint",
        "prover_execution_failed",
    ]


def test_supported_versions_pass_validation() -> None:
    schema = load_schema(SCHEMA_PATH)
    validate_prover_inputs(
        _synthetic_prover_data(input_schema_version="1", circuit_version="2"),
        schema=schema,
        circuit="silent_witness",
    )
    validate_prover_inputs(
        _synthetic_prover_data(circuit_version="1"),
        schema=schema,
        circuit="selective_disclosure",
    )


@pytest.mark.parametrize(
    ("bad_version", "expected_code"),
    [
        (0, "deprecated_input_version"),
        ("0", "deprecated_input_version"),
        (2, "unsupported_input_schema"),
        ("2", "unsupported_input_schema"),
        (99, "unsupported_input_schema"),
        (-1, "unsupported_input_schema"),
        ("v2", "malformed_input_version"),
        (True, "malformed_input_version"),
        (1 << 32, "malformed_input_version"),
    ],
)
def test_unsupported_input_schema_versions_classified_stably(
    bad_version: object,
    expected_code: str,
) -> None:
    schema = load_schema(SCHEMA_PATH)
    secret_marker = "9876543210123456789"
    data = _synthetic_prover_data(
        credential_secret=secret_marker,
        input_schema_version=bad_version,
    )

    with pytest.raises(ProverInputValidationError) as exc_info:
        validate_prover_inputs(data, schema=schema, circuit="silent_witness")

    err = exc_info.value
    assert err.category == ProverErrorCategory.UNSUPPORTED_INPUT_VERSION
    assert err.code == expected_code
    assert err.exit_code == EXIT_UNSUPPORTED_VERSION
    assert secret_marker not in str(err)
    assert secret_marker not in json.dumps(err.to_dict())


@pytest.mark.parametrize(
    ("bad_circuit_version", "expected_code"),
    [
        ("0", "deprecated_circuit_version"),
        ("1", "deprecated_circuit_version"),
        ("3", "unsupported_circuit_version"),
        ("99", "unsupported_circuit_version"),
        (str(1 << 32), "malformed_circuit_version"),
        ("-1", "malformed_circuit_version"),
        ("two", "malformed_circuit_version"),
    ],
)
def test_unsupported_circuit_versions_classified_stably(
    bad_circuit_version: str,
    expected_code: str,
) -> None:
    schema = load_schema(SCHEMA_PATH)
    data = _synthetic_prover_data(circuit_version=bad_circuit_version)

    with pytest.raises(ProverInputValidationError) as exc_info:
        validate_prover_inputs(data, schema=schema, circuit="silent_witness")

    err = exc_info.value
    assert err.category == ProverErrorCategory.UNSUPPORTED_INPUT_VERSION
    assert err.code == expected_code
    assert err.field == "circuit_version"
    assert err.exit_code == EXIT_UNSUPPORTED_VERSION
    assert bad_circuit_version not in str(err)


def test_version_mismatch_checked_before_malformed_witness_fields() -> None:
    """An unsupported version fails immediately even if witness fields are missing or malformed."""
    schema = load_schema(SCHEMA_PATH)
    incomplete_future_envelope = {
        "input_schema_version": 2,
        "credential_secret": "not_even_a_field",
    }
    with pytest.raises(ProverInputValidationError) as exc_info:
        validate_prover_inputs(incomplete_future_envelope, schema=schema)

    assert exc_info.value.category == ProverErrorCategory.UNSUPPORTED_INPUT_VERSION
    assert exc_info.value.code == "unsupported_input_schema"


def test_conformance_vectors_match_stable_error_categories() -> None:
    schema = load_schema(SCHEMA_PATH)
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))

    for case in vectors["cases"]:
        envelope = case["input"]
        if case.get("accept"):
            prepared = validate_envelope_inputs(envelope, schema=schema)
            assert list(prepared.keys()) == schema["input_fields"]
        else:
            with pytest.raises(ProverInputValidationError) as exc_info:
                validate_envelope_inputs(envelope, schema=schema)
            assert exc_info.value.category.value == case["error_category"]
            if case["reject_code"] == "unsupported_input_schema":
                assert (
                    exc_info.value.category
                    == ProverErrorCategory.UNSUPPORTED_INPUT_VERSION
                )
            else:
                assert exc_info.value.category == ProverErrorCategory.MALFORMED_INPUT


def test_build_prove_fails_before_invoking_prover_on_version_mismatch(
    tmp_path: Path,
) -> None:
    commands_run: list[list[str]] = []

    def fail_if_called(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands_run.append(list(cmd))
        raise AssertionError(f"expensive prover subprocess should not run: {cmd}")

    circuit_dir = tmp_path / "zk" / "noir" / "silent_witness"
    circuit_dir.mkdir(parents=True)
    (circuit_dir / "Prover.toml").write_text(
        'credential_secret = "12345"\n'
        'nullifier_secret = "67890"\n'
        'video_hash_hi = "1"\n'
        'video_hash_lo = "2"\n'
        'verifier_scope = "0"\n'
        'epoch = "0"\n'
        'circuit_version = "1"\n',
        encoding="utf-8",
    )

    toolchain = bc.ToolchainInfo(
        expected_nargo="1.0.0-beta.9",
        expected_bb="0.87.0",
        actual_nargo="1.0.0-beta.9",
        actual_bb="0.87.0",
        proving_scheme="ultra_honk",
        oracle_hash="keccak",
    )

    with pytest.raises(bc.BuildError) as exc_info:
        bc.compile_circuit(
            "silent_witness",
            toolchain,
            repo_root=tmp_path,
            runner=fail_if_called,
            prove=True,
        )

    assert commands_run == []
    assert exc_info.value.category == ProverErrorCategory.UNSUPPORTED_INPUT_VERSION.value
    assert exc_info.value.code == "deprecated_circuit_version"
    assert exc_info.value.exit_code == EXIT_UNSUPPORTED_VERSION


def test_cmd_generate_fails_before_toolchain_or_prover_on_unsupported_input_version(
    tmp_path: Path,
) -> None:
    commands_run: list[list[str]] = []

    def fail_if_called(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands_run.append(list(cmd))
        raise AssertionError(f"subprocess should not run: {cmd}")

    args = bc.create_parser().parse_args(
        [
            "generate",
            "silent_witness",
            "--video-hash",
            "11" * 32,
            "--credential-secret",
            "12345",
            "--nullifier-secret",
            "67890",
            "--input-schema-version",
            "2",
        ]
    )

    with pytest.raises(bc.BuildError) as exc_info:
        bc.cmd_generate(args, repo_root=tmp_path, runner=fail_if_called)

    assert commands_run == []
    assert exc_info.value.category == ProverErrorCategory.UNSUPPORTED_INPUT_VERSION.value
    assert exc_info.value.code == "unsupported_input_schema"
    assert exc_info.value.exit_code == EXIT_UNSUPPORTED_VERSION


def test_distinguishes_unsatisfied_constraint_from_version_mismatch(
    tmp_path: Path,
) -> None:
    commands_run: list[list[str]] = []

    def fake_runner(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands_run.append(list(cmd))
        if cmd[:2] == ["nargo", "compile"]:
            target = tmp_path / "zk" / "noir" / "silent_witness" / "target"
            target.mkdir(parents=True, exist_ok=True)
            (target / "silent_witness.json").write_text("{}", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[:2] == ["nargo", "execute"]:
            return subprocess.CompletedProcess(
                cmd,
                1,
                stdout="",
                stderr='error: Failed assertion: "malformed" (secret=12345)',
            )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    circuit_dir = tmp_path / "zk" / "noir" / "silent_witness"
    circuit_dir.mkdir(parents=True)
    (circuit_dir / "Prover.toml").write_text(
        'credential_secret = "12345"\n'
        'nullifier_secret = "67890"\n'
        'video_hash_hi = "1"\n'
        'video_hash_lo = "2"\n'
        'verifier_scope = "0"\n'
        'epoch = "0"\n'
        'circuit_version = "2"\n',
        encoding="utf-8",
    )

    toolchain = bc.ToolchainInfo(
        expected_nargo="1.0.0-beta.9",
        expected_bb="0.87.0",
        actual_nargo="1.0.0-beta.9",
        actual_bb="0.87.0",
        proving_scheme="ultra_honk",
        oracle_hash="keccak",
    )

    with pytest.raises(bc.BuildError) as exc_info:
        bc.compile_circuit(
            "silent_witness",
            toolchain,
            repo_root=tmp_path,
            runner=fake_runner,
            write_vk_flag=False,
            prove=True,
        )

    assert ["bb", "prove"] not in [c[:2] for c in commands_run]
    assert exc_info.value.category == ProverErrorCategory.UNSATISFIED_CONSTRAINT.value
    assert exc_info.value.code == "unsatisfied_circuit_constraint"
    assert exc_info.value.exit_code == EXIT_UNSATISFIED_CONSTRAINT
    assert exc_info.value.exit_code != EXIT_UNSUPPORTED_VERSION
    assert "12345" not in str(exc_info.value)


def test_classify_prover_execution_error_categories() -> None:
    assert classify_prover_execution_error('Failed assertion: "circuit version mismatch"') == (
        ProverErrorCategory.UNSUPPORTED_INPUT_VERSION,
        "circuit_version_mismatch",
    )
    assert classify_prover_execution_error('Failed assertion: "malformed"') == (
        ProverErrorCategory.UNSATISFIED_CONSTRAINT,
        "unsatisfied_circuit_constraint",
    )
    assert classify_prover_execution_error("Cannot satisfy constraint at opcode 14") == (
        ProverErrorCategory.UNSATISFIED_CONSTRAINT,
        "unsatisfied_circuit_constraint",
    )
    assert classify_prover_execution_error("backend worker crashed with signal 9") == (
        ProverErrorCategory.PROVER_EXECUTION_FAILED,
        "prover_execution_failed",
    )


def test_cli_json_categories_and_exit_codes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    valid_toml = REPO_ROOT / "zk" / "noir" / "silent_witness" / "Prover.toml.example"
    assert vpi.main([str(valid_toml), "--schema", str(SCHEMA_PATH)]) == EXIT_OK
    capsys.readouterr()

    version_toml = tmp_path / "silent_witness" / "Prover.toml"
    version_toml.parent.mkdir(parents=True)
    version_toml.write_text(
        'credential_secret = "12345"\n'
        'nullifier_secret = "67890"\n'
        'video_hash_hi = "1"\n'
        'video_hash_lo = "2"\n'
        'verifier_scope = "0"\n'
        'epoch = "0"\n'
        'circuit_version = "99"\n',
        encoding="utf-8",
    )
    rc_ver = vpi.main(
        [str(version_toml), "--schema", str(SCHEMA_PATH), "--json"]
    )
    captured_ver = capsys.readouterr()
    assert rc_ver == EXIT_UNSUPPORTED_VERSION
    payload_ver = json.loads(captured_ver.err.strip())
    assert payload_ver == {
        "category": "unsupported_input_version",
        "code": "unsupported_circuit_version",
        "field": "circuit_version",
    }

    malformed_toml = tmp_path / "silent_witness" / "bad.toml"
    malformed_toml.write_text('credential_secret = "not_a_number"\n', encoding="utf-8")
    rc_mal = vpi.main(
        [str(malformed_toml), "--schema", str(SCHEMA_PATH), "--json"]
    )
    captured_mal = capsys.readouterr()
    assert rc_mal == EXIT_MALFORMED_INPUT
    payload_mal = json.loads(captured_mal.err.strip())
    assert payload_mal["category"] == "malformed_input"
    assert "not_a_number" not in captured_mal.err
