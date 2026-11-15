from __future__ import annotations

import argparse
import copy
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from zk.tools import build_circuits
from zk.tools.proof_fixture_provenance import (
    COMMITTED_CIRCUIT_FIXTURES,
    EXIT_OK,
    EXIT_REJECTED,
    EXIT_USAGE,
    MAX_FIXTURE_BYTES,
    PROVENANCE_ENVELOPE_KEY,
    PROVENANCE_FORMAT,
    PROVENANCE_VERSION,
    REPO_ROOT,
    FixtureProvenanceError,
    FixtureRejectCode,
    build_fixture_provenance,
    extract_witness_inputs,
    load_and_validate_fixture_file,
    main,
    validate_proof_fixture,
)


def _sample_fixture(
    *,
    circuit: str = "silent_witness",
    schema: str = "silent_witness/v2",
    schema_version: int = 2,
    frame_bytes: int | None = 256,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        PROVENANCE_ENVELOPE_KEY: {
            "format": PROVENANCE_FORMAT,
            "provenance_version": PROVENANCE_VERSION,
            "circuit": circuit,
            "vector_generator": "zk/tools/build_circuits.py",
            "vector_generator_version": "1.0.0",
            "statement_schema": schema,
            "statement_schema_version": schema_version,
        },
        "public_inputs": {
            "credential_root": "0x" + "11" * 32,
            "nullifier": "0x" + "22" * 32,
        },
        "witness": {
            "credential_secret": "CANARY_WITNESS_SECRET_991122",
            "nullifier_secret": "CANARY_NULLIFIER_SECRET_884400",
        },
    }
    if frame_bytes is not None:
        payload["public_inputs_len"] = frame_bytes
    return payload


def test_committed_fixtures_carry_valid_provenance_outside_witness(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = main(["--check-all"])
    assert rc == EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert out["checked"] == len(COMMITTED_CIRCUIT_FIXTURES)

    for circuit_name, rel_path in COMMITTED_CIRCUIT_FIXTURES:
        fixture_path = REPO_ROOT / rel_path
        raw = json.loads(fixture_path.read_text(encoding="utf-8"))
        prov = validate_proof_fixture(raw, selected_circuit=circuit_name)
        assert prov.circuit == circuit_name
        assert prov.provenance_version == PROVENANCE_VERSION
        assert prov.statement_schema_version >= 1
        assert prov.vector_generator
        assert prov.vector_generator_version


def test_extract_witness_inputs_keeps_provenance_out_of_secret_witness() -> None:
    fixture = _sample_fixture()
    witness = extract_witness_inputs(fixture, selected_circuit="silent_witness")
    assert set(witness.keys()) == {"credential_secret", "nullifier_secret"}
    assert PROVENANCE_ENVELOPE_KEY not in witness
    assert "vector_generator" not in witness
    assert "statement_schema" not in witness

    # Mutating returned copy must not mutate source fixture.
    witness["credential_secret"] = "mutated"
    assert fixture["witness"]["credential_secret"] == "CANARY_WITNESS_SECRET_991122"


@pytest.mark.parametrize(
    ("container_key", "leaked_key", "leaked_val"),
    [
        ("witness", "vector_generator", "zk/tools/gen.py"),
        ("witness", "vector_generator_version", "1.0.0"),
        ("witness", "statement_schema", "silent_witness/v2"),
        ("witness", "statement_schema_version", 2),
        ("witness", "fixture_provenance", {"format": PROVENANCE_FORMAT}),
        ("private_inputs", "statement_schema", "redacted_ancestry/v1"),
        ("privateInputs", "vector_generator", "frontend/prover"),
    ],
)
def test_rejects_provenance_metadata_inside_witness_containers(
    container_key: str,
    leaked_key: str,
    leaked_val: Any,
) -> None:
    fixture = _sample_fixture()
    fixture[container_key] = {
        "credential_secret": "CANARY_WITNESS_SECRET_991122",
        leaked_key: leaked_val,
    }
    with pytest.raises(FixtureProvenanceError) as exc_info:
        validate_proof_fixture(fixture, selected_circuit="silent_witness")
    assert exc_info.value.code is FixtureRejectCode.PROVENANCE_IN_WITNESS
    assert leaked_key in exc_info.value.field
    assert "CANARY_WITNESS_SECRET_991122" not in str(exc_info.value)


def test_rejects_provenance_inside_nested_case_private_inputs() -> None:
    raw = json.loads(
        (REPO_ROOT / "zk/noir/fixtures/redacted_ancestry_vectors.json").read_text(
            encoding="utf-8"
        )
    )
    tampered_witness = copy.deepcopy(raw)
    tampered_witness["witness"]["statement_schema"] = "redacted_ancestry/v1"
    with pytest.raises(FixtureProvenanceError) as witness_err:
        validate_proof_fixture(tampered_witness, selected_circuit="redacted_ancestry")
    assert witness_err.value.code is FixtureRejectCode.PROVENANCE_IN_WITNESS
    assert witness_err.value.field == "witness.statement_schema"

    tampered_nested = copy.deepcopy(raw)
    tampered_nested["positive_cases"][0]["private_inputs"] = {
        "parent_blinding": 33333,
        "statement_schema": "redacted_ancestry/v1",
    }
    with pytest.raises(FixtureProvenanceError) as exc_info:
        validate_proof_fixture(tampered_nested, selected_circuit="redacted_ancestry")
    assert exc_info.value.code is FixtureRejectCode.PROVENANCE_IN_WITNESS
    assert (
        exc_info.value.field
        == "positive_cases[0].private_inputs.statement_schema"
    )


@pytest.mark.parametrize(
    "secret_key",
    [
        "credential_secret",
        "nullifier_secret",
        "parent_blinding",
        "redaction_seed",
        "attr_values",
        "witness",
        "private_inputs",
    ],
)
def test_rejects_secret_witness_fields_inside_provenance_envelope(
    secret_key: str,
) -> None:
    fixture = _sample_fixture()
    fixture[PROVENANCE_ENVELOPE_KEY][secret_key] = "CANARY_SECRET_LEAK_777"
    with pytest.raises(FixtureProvenanceError) as exc_info:
        validate_proof_fixture(fixture, selected_circuit="silent_witness")
    assert exc_info.value.code is FixtureRejectCode.SECRET_IN_PROVENANCE
    assert exc_info.value.field == f"{PROVENANCE_ENVELOPE_KEY}.{secret_key}"
    assert "CANARY_SECRET_LEAK_777" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("fixture_circuit", "declared_schema", "declared_ver", "selected_circuit", "expected_code"),
    [
        (
            "redacted_ancestry",
            "redacted_ancestry/v1",
            1,
            "silent_witness",
            FixtureRejectCode.SCHEMA_CIRCUIT_CONFLICT,
        ),
        (
            "silent_witness",
            "silent_witness/v2",
            2,
            "selective_disclosure",
            FixtureRejectCode.SCHEMA_CIRCUIT_CONFLICT,
        ),
        (
            "revocation_witness",
            "silent_witness/v2",
            2,
            "silent_witness",
            FixtureRejectCode.CIRCUIT_MISMATCH,
        ),
        (
            "silent_witness",
            "silent_witness/v2",
            1,
            "silent_witness",
            FixtureRejectCode.SCHEMA_VERSION_CONFLICT,
        ),
        (
            "redacted_ancestry",
            "redacted_ancestry/v1",
            2,
            "redacted_ancestry",
            FixtureRejectCode.SCHEMA_VERSION_CONFLICT,
        ),
    ],
)
def test_rejects_declared_schema_conflicts_with_selected_circuit(
    fixture_circuit: str,
    declared_schema: str,
    declared_ver: int,
    selected_circuit: str,
    expected_code: FixtureRejectCode,
) -> None:
    fixture = _sample_fixture(
        circuit=fixture_circuit,
        schema=declared_schema,
        schema_version=declared_ver,
        frame_bytes=None,
    )
    with pytest.raises(FixtureProvenanceError) as exc_info:
        validate_proof_fixture(fixture, selected_circuit=selected_circuit)
    assert exc_info.value.code is expected_code
    assert "CANARY_WITNESS_SECRET_991122" not in json.dumps(exc_info.value.signal())


def test_rejects_frame_length_and_legacy_circuit_conflicts() -> None:
    # 128-byte browser frame mislabeled as 256-byte silent_witness/v2
    mismatch_len = _sample_fixture(
        circuit="silent_witness",
        schema="silent_witness/v2",
        schema_version=2,
        frame_bytes=128,
    )
    with pytest.raises(FixtureProvenanceError) as exc_info:
        validate_proof_fixture(mismatch_len, selected_circuit="silent_witness")
    assert exc_info.value.code is FixtureRejectCode.FRAME_LENGTH_SCHEMA_CONFLICT

    # Matching 128-byte silent_witness/browser_v1 is accepted
    browser_ok = _sample_fixture(
        circuit="silent_witness",
        schema="silent_witness/browser_v1",
        schema_version=1,
        frame_bytes=128,
    )
    prov = validate_proof_fixture(browser_ok, selected_circuit="silent_witness")
    assert prov.statement_schema == "silent_witness/browser_v1"

    # Legacy `_circuit` label conflicting with `statement_schema` is rejected
    legacy_conflict = _sample_fixture(
        circuit="redacted_ancestry",
        schema="redacted_ancestry/v1",
        schema_version=1,
        frame_bytes=256,
    )
    legacy_conflict["_circuit"] = "revocation_witness/v1"
    with pytest.raises(FixtureProvenanceError) as legacy_err:
        validate_proof_fixture(legacy_conflict, selected_circuit="redacted_ancestry")
    assert legacy_err.value.code is FixtureRejectCode.SCHEMA_CIRCUIT_CONFLICT
    assert legacy_err.value.field == "_circuit"


def test_build_circuits_export_records_provenance_and_rejects_conflicting_schema(
    tmp_path: Path,
) -> None:
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    (target_dir / "proof").write_bytes(b"\xaa" * 32)
    (target_dir / "public_inputs").write_bytes(b"\xbb" * 256)
    (target_dir / "vk").write_bytes(b"\xcc" * 64)
    out_json = tmp_path / "exported.json"

    args_ok = argparse.Namespace(
        circuit="redacted_ancestry",
        target_dir=str(target_dir),
        output=str(out_json),
        statement_schema=None,
        statement_schema_version=None,
    )
    assert build_circuits.cmd_export(args_ok, repo_root=tmp_path) == EXIT_OK
    exported = json.loads(out_json.read_text(encoding="utf-8"))
    prov = validate_proof_fixture(exported, selected_circuit="redacted_ancestry")
    assert prov.statement_schema == "redacted_ancestry/v1"
    assert prov.statement_schema_version == 1
    assert prov.vector_generator == "zk/tools/build_circuits.py"

    # Exporting redacted_ancestry while declaring silent_witness/v2 must fail closed.
    args_conflict = argparse.Namespace(
        circuit="redacted_ancestry",
        target_dir=str(target_dir),
        output=str(out_json),
        statement_schema="silent_witness/v2",
        statement_schema_version=2,
    )
    with pytest.raises(build_circuits.BuildError) as exc_info:
        build_circuits.cmd_export(args_conflict, repo_root=tmp_path)
    assert exc_info.value.exit_code == EXIT_USAGE
    assert "schema_circuit_conflict" in str(exc_info.value)


def test_cli_single_fixture_and_privacy_safe_rejection(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture_file = tmp_path / "fixture.json"
    fixture_file.write_text(json.dumps(_sample_fixture()), encoding="utf-8")

    assert main(["--circuit", "silent_witness", str(fixture_file)]) == EXIT_OK
    ok_payload = json.loads(capsys.readouterr().out)
    assert ok_payload["ok"] is True

    # Selecting wrong circuit rejects with structured stderr signal and zero secret leakage.
    rc_bad = main(["--circuit", "redacted_ancestry", str(fixture_file)])
    assert rc_bad == EXIT_REJECTED
    captured = capsys.readouterr()
    err_signal = json.loads(captured.err)
    assert err_signal == {
        "field": "fixture_provenance.statement_schema",
        "reject_code": "schema_circuit_conflict",
    }
    assert "CANARY_WITNESS_SECRET_991122" not in captured.err
    assert "CANARY_WITNESS_SECRET_991122" not in captured.out

    # Missing required --circuit returns EXIT_USAGE.
    assert main([str(fixture_file)]) == EXIT_USAGE
    capsys.readouterr()


def test_file_loader_bounds_size_and_malformed_json(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    with pytest.raises(FixtureProvenanceError) as miss_err:
        load_and_validate_fixture_file(missing, selected_circuit="silent_witness")
    assert miss_err.value.code is FixtureRejectCode.MISSING_FILE

    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not-json", encoding="utf-8")
    with pytest.raises(FixtureProvenanceError) as json_err:
        load_and_validate_fixture_file(bad_json, selected_circuit="silent_witness")
    assert json_err.value.code is FixtureRejectCode.MALFORMED_JSON

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAX_FIXTURE_BYTES + 1))
    with pytest.raises(FixtureProvenanceError) as size_err:
        load_and_validate_fixture_file(oversized, selected_circuit="silent_witness")
    assert size_err.value.code is FixtureRejectCode.OVERSIZED_FIXTURE


def test_build_fixture_provenance_helper_rejects_unknown_circuit() -> None:
    prov = build_fixture_provenance(
        circuit="selective_disclosure",
        vector_generator="zk/tools/selective_disclosure_gen.py",
        vector_generator_version="1.2.3",
    )
    assert prov["statement_schema"] == "selective_disclosure/v1"
    assert prov["statement_schema_version"] == 1

    with pytest.raises(FixtureProvenanceError) as exc_info:
        build_fixture_provenance(
            circuit="nonexistent_circuit",
            vector_generator="zk/tools/gen.py",
            vector_generator_version="1.0.0",
        )
    assert exc_info.value.code is FixtureRejectCode.UNKNOWN_CIRCUIT


def test_browser_proof_fixture_mjs_validator_enforces_schema_and_witness_separation() -> None:
    node_bin = shutil.which("node")
    if node_bin is None:
        pytest.skip("node binary not available on PATH")

    mjs_url = (
        (REPO_ROOT / "zk/regression/generate_browser_proof_fixture.mjs")
        .resolve()
        .as_uri()
    )
    script = f"""
import assert from 'node:assert/strict';
import {{
  BROWSER_FIXTURE_GENERATOR,
  BROWSER_FIXTURE_GENERATOR_VERSION,
  validateFixtureSchemaForCircuit,
}} from {json.dumps(mjs_url)};

const valid = {{
  fixture_provenance: {{
    format: 'harpocrates.proof-fixture-provenance',
    provenance_version: 1,
    circuit: 'silent_witness',
    vector_generator: BROWSER_FIXTURE_GENERATOR,
    vector_generator_version: BROWSER_FIXTURE_GENERATOR_VERSION,
    statement_schema: 'silent_witness/browser_v1',
    statement_schema_version: 1,
  }},
  witness: {{ credential_secret: '12345' }},
}};

const out = validateFixtureSchemaForCircuit(valid, 'silent_witness');
assert.equal(out.statement_schema, 'silent_witness/browser_v1');

assert.throws(
  () => validateFixtureSchemaForCircuit(valid, 'redacted_ancestry'),
  /schema_circuit_conflict/
);

assert.throws(
  () => validateFixtureSchemaForCircuit({{
    ...valid,
    witness: {{ credential_secret: '12345', vector_generator: 'leaked' }},
  }}, 'silent_witness'),
  /provenance_in_witness/
);
"""
    proc = subprocess.run(
        [node_bin, "--input-type=module", "-e", script],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
