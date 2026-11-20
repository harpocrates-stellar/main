"""Schema and drift guards for the redacted_ancestry synthetic vectors (#356).

These tests do not execute Noir. They keep the fixture corpus versioned,
privacy-safe, and aligned with the circuit's stable assert codes, so CI can
catch drift without the nargo toolchain.

Run from the repository root:

    python -m pytest zk/tools -q
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ZK_ROOT = Path(__file__).resolve().parents[1]
VECTORS = ZK_ROOT / "noir" / "fixtures" / "redacted_ancestry_vectors.json"
CIRCUIT = ZK_ROOT / "noir" / "redacted_ancestry" / "src" / "main.nr"

FORBIDDEN_KEYS = {
    "private_key",
    "credential_secret_hex",
    "witness_bytes",
    "proof_hex",
    "real_media",
}


@pytest.fixture(scope="module")
def data() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def test_versioned_circuit_id(data: dict) -> None:
    assert data["_circuit"] == "redacted_ancestry/v1"
    assert data["_version"] == "1.0.0"
    assert data["_operation"] == "redact"
    assert data["_min_ancestry_depth"] == 1
    assert data["_max_ancestry_depth"] == 4


def test_operation_field_is_ascii_redact(data: dict) -> None:
    # The circuit binds the registry Symbol "redact" as an ASCII field element
    # rather than inventing a numeric operation enum.
    value = int(data["_operation_field_hex"], 16)
    assert value.to_bytes((value.bit_length() + 7) // 8, "big") == b"redact"


def test_positive_and_negative_corpus(data: dict) -> None:
    positives = data["positive_cases"]
    negatives = data["negative_cases"]
    assert len(positives) >= 2
    assert len(negatives) >= 10
    for case in positives:
        assert case["expect"] == "pass"
        assert str(case["id"]).startswith("ra-pos-")
    for case in negatives:
        assert case["expect_fail_with"]
        assert str(case["id"]).startswith("ra-neg-")


def test_depth_boundaries_documented(data: dict) -> None:
    depths = {case.get("depth") for case in data["positive_cases"]}
    assert 1 in depths
    assert data["_max_ancestry_depth"] in depths
    ids = {case["id"] for case in data["negative_cases"]}
    assert "ra-neg-002-zero-depth" in ids
    assert "ra-neg-003-oversized-depth" in ids


def test_negative_messages_match_circuit_asserts(data: dict) -> None:
    # Every declared failure code must be an actual assert message in the
    # circuit, so the corpus cannot drift from the implementation.
    source = CIRCUIT.read_text(encoding="utf-8")
    for case in data["negative_cases"]:
        message = case["expect_fail_with"]
        assert f'"{message}"' in source, f"assert message not found in circuit: {message}"


def test_non_redact_operation_is_not_the_ascii_field(data: dict) -> None:
    redact = int(data["_operation_field_hex"], 16)
    for case in data["negative_cases"]:
        if case["id"] == "ra-neg-001-non-redact-operation":
            assert case["operation_type"] != "redact"
            assert redact != 0


def test_privacy_notes_present_and_no_sensitive_keys(data: dict) -> None:
    assert len(data["privacy_notes"]) >= 2
    blob = json.dumps(data).lower()
    for key in FORBIDDEN_KEYS:
        assert key not in blob


def test_witness_is_synthetic_nonnegative_integers(data: dict) -> None:
    witness = data["witness"]
    assert witness
    for key, value in witness.items():
        assert isinstance(value, int), key
        assert not isinstance(value, bool), key
        assert value >= 0, key
