"""Focused tests for pre-prover circuit input version checks and error categories."""

from __future__ import annotations

import json
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from circuit_input_version import (
    CIRCUIT_INPUT_SCHEMA_VERSION,
    CURRENT_CIRCUIT_VERSION,
    CircuitInputErrorCategory,
    CircuitInputVersionError,
    check_circuit_input_version,
    check_circuit_version,
    check_input_schema_version,
    classify_prover_failure,
    validate_before_prove,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SILENT_WITNESS_MAIN = REPO_ROOT / "zk" / "noir" / "silent_witness" / "src" / "main.nr"
INPUT_SCHEMA_JSON = REPO_ROOT / "zk" / "noir" / "circuit_input_schema_v1.json"


def test_supported_versions_pass_and_invoke_prover() -> None:
    prover = MagicMock(return_value={"proof": "synthetic-ok"})
    payload = {
        "input_schema_version": CIRCUIT_INPUT_SCHEMA_VERSION,
        "circuit_version": CURRENT_CIRCUIT_VERSION,
        "credential_secret": "12345",
    }

    result = validate_before_prove(payload, prover)

    assert result == {"proof": "synthetic-ok"}
    prover.assert_called_once_with(payload)


def test_omitted_input_schema_version_defaults_to_supported_v1() -> None:
    prover = MagicMock(return_value="ok")
    payload = {"circuit_version": CURRENT_CIRCUIT_VERSION}

    assert validate_before_prove(payload, prover) == "ok"
    prover.assert_called_once_with(payload)


@pytest.mark.parametrize("bad_version", [0, 1, 3, 99])
def test_unsupported_circuit_version_fails_before_prover(bad_version: int) -> None:
    prover = MagicMock(side_effect=AssertionError("prover must not be invoked"))
    payload = {
        "input_schema_version": CIRCUIT_INPUT_SCHEMA_VERSION,
        "circuit_version": bad_version,
        "credential_secret": "synthetic-secret-99999",
    }

    with pytest.raises(CircuitInputVersionError) as exc_info:
        validate_before_prove(payload, prover)

    err = exc_info.value
    assert err.category is CircuitInputErrorCategory.UNSUPPORTED_CIRCUIT_VERSION
    assert err.code == "unsupported_circuit_version"
    assert err.signal() == {
        "errorCategory": "unsupported_circuit_version",
        "field": "circuit_version",
    }
    assert "synthetic-secret-99999" not in str(err)
    assert str(bad_version) not in str(err)
    prover.assert_not_called()


@pytest.mark.parametrize("bad_schema", [0, 2, 99])
def test_unsupported_input_schema_version_fails_before_prover(bad_schema: int) -> None:
    prover = MagicMock(side_effect=AssertionError("prover must not be invoked"))
    payload = {
        "input_schema_version": bad_schema,
        "circuit_version": CURRENT_CIRCUIT_VERSION,
    }

    with pytest.raises(CircuitInputVersionError) as exc_info:
        validate_before_prove(payload, prover)

    err = exc_info.value
    assert err.category is CircuitInputErrorCategory.UNSUPPORTED_INPUT_SCHEMA_VERSION
    assert err.signal() == {
        "errorCategory": "unsupported_input_schema_version",
        "field": "input_schema_version",
    }
    prover.assert_not_called()


@pytest.mark.parametrize("malformed", [None, True, False, "2", 2.0, -1, []])
def test_malformed_circuit_version_fails_before_prover(malformed: object) -> None:
    prover = MagicMock(side_effect=AssertionError("prover must not be invoked"))
    payload = {"circuit_version": malformed}

    with pytest.raises(CircuitInputVersionError) as exc_info:
        validate_before_prove(payload, prover)

    err = exc_info.value
    assert err.category is CircuitInputErrorCategory.MALFORMED_CIRCUIT_VERSION
    assert err.signal() == {
        "errorCategory": "malformed_circuit_version",
        "field": "circuit_version",
    }
    prover.assert_not_called()


@pytest.mark.parametrize("malformed", [None, True, False, "1", 1.0, -1])
def test_malformed_input_schema_version_rejected(malformed: object) -> None:
    with pytest.raises(CircuitInputVersionError) as exc_info:
        check_input_schema_version(malformed)

    assert exc_info.value.category is CircuitInputErrorCategory.MALFORMED_CIRCUIT_VERSION
    assert exc_info.value.field == "input_schema_version"


def test_classify_distinguishes_version_mismatch_from_unsatisfied_constraint() -> None:
    version_err = CircuitInputVersionError(
        CircuitInputErrorCategory.UNSUPPORTED_CIRCUIT_VERSION
    )
    schema_err = CircuitInputVersionError(
        CircuitInputErrorCategory.UNSUPPORTED_INPUT_SCHEMA_VERSION,
        field="input_schema_version",
    )
    noir_version_err = RuntimeError("Assertion failed: circuit version mismatch")
    noir_constraint_err = RuntimeError("Assertion failed: malformed")
    noir_domain_err = RuntimeError("Assertion failed: unsupported")

    assert classify_prover_failure(version_err) is CircuitInputErrorCategory.UNSUPPORTED_CIRCUIT_VERSION
    assert classify_prover_failure(schema_err) is CircuitInputErrorCategory.UNSUPPORTED_INPUT_SCHEMA_VERSION
    assert classify_prover_failure(noir_version_err) is CircuitInputErrorCategory.UNSUPPORTED_CIRCUIT_VERSION
    assert classify_prover_failure(noir_constraint_err) is CircuitInputErrorCategory.CIRCUIT_CONSTRAINT_UNSATISFIED
    assert classify_prover_failure(noir_domain_err) is CircuitInputErrorCategory.CIRCUIT_CONSTRAINT_UNSATISFIED


def test_direct_helpers_accept_current_versions() -> None:
    assert check_input_schema_version(CIRCUIT_INPUT_SCHEMA_VERSION) == CIRCUIT_INPUT_SCHEMA_VERSION
    assert check_circuit_version(CURRENT_CIRCUIT_VERSION) == CURRENT_CIRCUIT_VERSION
    assert check_circuit_input_version(CURRENT_CIRCUIT_VERSION) == CURRENT_CIRCUIT_VERSION


def test_constants_match_noir_circuit_and_schema_json() -> None:
    noir_src = SILENT_WITNESS_MAIN.read_text(encoding="utf-8")
    match = re.search(r"global\s+CURRENT_CIRCUIT_VERSION:\s*u32\s*=\s*(\d+);", noir_src)
    assert match is not None, "CURRENT_CIRCUIT_VERSION global not found in silent_witness/src/main.nr"
    assert int(match.group(1)) == CURRENT_CIRCUIT_VERSION
    assert 'assert(\n        circuit_version == CURRENT_CIRCUIT_VERSION as Field,\n        "circuit version mismatch",' in noir_src

    schema = json.loads(INPUT_SCHEMA_JSON.read_text(encoding="utf-8"))
    assert schema["version"] == CIRCUIT_INPUT_SCHEMA_VERSION
    assert schema["artifact_abis"]["scoped_v2"]["circuit_version"] == CURRENT_CIRCUIT_VERSION
