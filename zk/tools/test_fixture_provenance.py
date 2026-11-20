"""Focused tests for fixture provenance (#1212)."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixture_provenance import (  # noqa: E402
    FixtureProvenanceError,
    load_provenance,
    validate_fixture,
)

def _fixture(**overrides):
    base = {
        "provenance": {
            "generator": "harpocrates-vectors",
            "generator_version": 1,
            "statement_schema": "silent_witness/v2",
        },
        "witness": {"a": "0xdeadbeef", "b": "0x01"},
        "public_inputs": {"circuit_version": 2},
    }
    base.update(overrides)
    return base

def test_matching_schema_passes():
    prov = validate_fixture(_fixture(), expected_schema="silent_witness/v2")
    assert prov.generator == "harpocrates-vectors"
    assert prov.generator_version == 1
    assert prov.statement_schema == "silent_witness/v2"

def test_conflicting_schema_rejects():
    with pytest.raises(FixtureProvenanceError) as exc:
        validate_fixture(_fixture(), expected_schema="silent_witness/v1")
    assert exc.value.code == "schema_mismatch"
    assert exc.value.field == "provenance.statement_schema"

def test_missing_provenance_rejects():
    fx = _fixture()
    del fx["provenance"]
    with pytest.raises(FixtureProvenanceError) as exc:
        validate_fixture(fx, expected_schema="silent_witness/v2")
    assert exc.value.code == "missing_provenance"

def test_missing_provenance_field_rejects():
    fx = _fixture()
    del fx["provenance"]["generator_version"]
    with pytest.raises(FixtureProvenanceError) as exc:
        load_provenance(fx)
    assert exc.value.code == "missing_provenance_field"
    assert exc.value.field == "generator_version"

def test_invalid_generator_version_rejects():
    fx = _fixture()
    fx["provenance"]["generator_version"] = 0
    with pytest.raises(FixtureProvenanceError) as exc:
        load_provenance(fx)
    assert exc.value.code == "invalid_generator_version"

def test_unsupported_statement_schema_rejects():
    fx = _fixture()
    fx["provenance"]["statement_schema"] = "bogus/v9"
    with pytest.raises(FixtureProvenanceError) as exc:
        load_provenance(fx)
    assert exc.value.code == "unsupported_statement_schema"

def test_validation_does_not_mutate_witness_bytes():
    fx = _fixture()
    before = copy.deepcopy(fx)
    h0 = hashlib.sha256(json.dumps(fx["witness"], sort_keys=True).encode()).hexdigest()
    validate_fixture(fx, expected_schema="silent_witness/v2")
    h1 = hashlib.sha256(json.dumps(fx["witness"], sort_keys=True).encode()).hexdigest()
    assert h0 == h1
    assert fx == before

def test_error_messages_never_leak_witness_values():
    fx = _fixture()
    fx["witness"]["sentinel"] = "DO_NOT_LEAK_THIS_VALUE"
    with pytest.raises(FixtureProvenanceError) as exc:
        validate_fixture(fx, expected_schema="silent_witness/v1")
    assert "DO_NOT_LEAK_THIS_VALUE" not in str(exc.value)
