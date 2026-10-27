"""Unit tests for validate_prover_inputs.py.

Verifies:
- Committed Prover.toml.example files validate (or appropriate schema/required fields).
- Missing required fields fail with field names.
- Out-of-range field elements fail with field names.
- Hex formatting and decimal formatting are parsed correctly.
- Error messages never print witness values.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_prover_inputs import (  # noqa: E402
    ProverInputValidationError,
    load_schema,
    parse_field_element,
    parse_prover_toml,
    validate_field_element,
    validate_prover_file,
    validate_prover_inputs,
    main,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "zk" / "noir" / "circuit_input_schema_v1.json"
BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def test_schema_loads():
    schema = load_schema(SCHEMA_PATH)
    assert schema["format"] == "harpocrates.circuit-input-schema"
    assert int(schema["field_modulus"]) == BN254_MODULUS


def test_silent_witness_prover_toml_example_validates():
    example_path = REPO_ROOT / "zk" / "noir" / "silent_witness" / "Prover.toml.example"
    validate_prover_file(example_path, schema_path=SCHEMA_PATH)


def test_silent_witness_aggregator_prover_toml_example_validates():
    example_path = (
        REPO_ROOT
        / "zk"
        / "noir"
        / "silent_witness_aggregator"
        / "Prover.toml.example"
    )
    validate_prover_file(
        example_path,
        schema_path=SCHEMA_PATH,
        required_fields=["credential_secret", "nullifier_secret"],
    )


def test_selective_disclosure_prover_toml_example_validates():
    example_path = (
        REPO_ROOT
        / "zk"
        / "noir"
        / "selective_disclosure"
        / "Prover.toml.example"
    )
    validate_prover_file(
        example_path,
        schema_path=SCHEMA_PATH,
        required_fields=[
            "schema_hash",
            "issuer_namespace",
            "schema_version",
            "credential_root",
            "nullifier",
            "video_hash_hi",
            "video_hash_lo",
            "verifier_digest",
            "circuit_version",
            "evidence_digest",
            "predicate_commitment",
            "num_attributes",
            "attr_values",
            "attr_blindings",
            "num_predicates",
            "predicates",
        ],
    )


def test_parse_field_element_valid():
    assert parse_field_element("0") == 0
    assert parse_field_element("12345") == 12345
    assert parse_field_element("0x10") == 16
    assert parse_field_element("0X2a") == 42
    assert parse_field_element(100) == 100


def test_parse_field_element_invalid():
    assert parse_field_element("") is None
    assert parse_field_element("not_a_number") is None
    assert parse_field_element("-1") is None
    assert parse_field_element(True) is None
    assert parse_field_element(False) is None
    assert parse_field_element("0xGHI") is None


def test_validate_field_element_out_of_range():
    with pytest.raises(ProverInputValidationError) as exc:
        validate_field_element(str(BN254_MODULUS), "credential_secret", BN254_MODULUS)
    assert exc.value.code == "field_element_out_of_range"
    assert exc.value.field == "credential_secret"
    # Never leak value in error representation
    assert str(BN254_MODULUS) not in str(exc.value)


def test_validate_field_element_malformed():
    secret_value = "secret_forbidden_string_12345"
    with pytest.raises(ProverInputValidationError) as exc:
        validate_field_element(secret_value, "nullifier_secret", BN254_MODULUS)
    assert exc.value.code == "malformed_field_element"
    assert exc.value.field == "nullifier_secret"
    # Never leak value
    assert secret_value not in str(exc.value)


def test_missing_required_field():
    prover_data = {
        "credential_secret": "12345",
        "video_hash_hi": "1",
        "video_hash_lo": "2",
        "verifier_scope": "0",
        "epoch": "0",
    }
    schema = load_schema(SCHEMA_PATH)
    with pytest.raises(ProverInputValidationError) as exc:
        validate_prover_inputs(prover_data, schema=schema)
    assert exc.value.code == "missing_required_field"
    assert exc.value.field == "nullifier_secret"


def test_no_witness_values_in_error_message(capsys):
    secret_val = "999888777666555444333222111"
    prover_data = {
        "credential_secret": secret_val,
        "nullifier_secret": "invalid_hex_val_abc_xyz",
        "video_hash_hi": "1",
        "video_hash_lo": "2",
        "verifier_scope": "0",
        "epoch": "0",
    }
    schema = load_schema(SCHEMA_PATH)
    with pytest.raises(ProverInputValidationError) as exc:
        validate_prover_inputs(prover_data, schema=schema)

    msg = str(exc.value)
    assert "invalid_hex_val_abc_xyz" not in msg
    assert secret_val not in msg
    assert "nullifier_secret" in msg


def test_cli_exit_code_and_stderr(tmp_path, capsys):
    bad_toml = tmp_path / "Prover.toml"
    bad_toml.write_text("credential_secret = 'not_a_hex_or_dec'\n", encoding="utf-8")

    code = main([str(bad_toml), "--schema", str(SCHEMA_PATH)])
    assert code != 0
    captured = capsys.readouterr()
    assert "not_a_hex_or_dec" not in captured.stderr
    assert "not_a_hex_or_dec" not in captured.stdout
    assert "missing_required_field" in captured.stderr or "malformed_field_element" in captured.stderr


def test_cli_success(tmp_path):
    example_path = REPO_ROOT / "zk" / "noir" / "silent_witness" / "Prover.toml.example"
    code = main([str(example_path), "--schema", str(SCHEMA_PATH)])
    assert code == 0
