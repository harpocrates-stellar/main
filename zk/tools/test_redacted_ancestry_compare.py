from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from zk.tools.redacted_ancestry_compare import (
    BN254_SCALAR_MODULUS,
    EXIT_COMPATIBLE,
    EXIT_INCOMPATIBLE,
    EXIT_USAGE,
    EXPECTED_DOMAIN_TAG,
    MAX_ANCESTRY_DEPTH,
    MAX_STATEMENT_FILE_BYTES,
    MIN_ANCESTRY_DEPTH,
    OPERATION_REDACT,
    REDACTED_ANCESTRY_PUBLIC_FIELDS,
    IncompatibilityCode,
    StatementRejectCode,
    StatementValidationError,
    compare_ancestry_statements,
    load_statement_file,
    main,
    parse_ancestry_statement,
    render_markdown_report,
)

# Published synthetic values from zk/noir/redacted_ancestry/Prover.toml.example
SYNTHETIC_V1_FIELDS: dict[str, str] = {
    "parent_commitment": "0x0ba525932854b5452d78deea15b3cf24576aae19531419f725a029bd954618aa",
    "derivative_digest": "0x195fcb9607ac65b82ca64c952448321d6c2a8d1e2941f205a7bbdd935ac188fe",
    "parameters_digest": "0x1306ddb1d4f1e454474db5009b3e8f7294636b92c59171057551e57cb07f6e16",
    "operation_type": hex(OPERATION_REDACT),
    "ancestry_root": "0x1627772c1aab4cf343673524cda17c6630773be5e7f351b592dd6fe84fe131ba",
    "nullifier": "0x29cbb2cf20b9b51284a3d40d8bd81d269aa12cd73ef2b152a094184031da81c1",
    "depth": "1",
    "domain_tag": hex(EXPECTED_DOMAIN_TAG),
}

SYNTHETIC_V2_ROTATED_ROOT = (
    "0x2299887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbb"
)
SYNTHETIC_V2_ROTATED_NULLIFIER = (
    "0x1f0e0d0c0b0a09080706050403020100ffeeddccbbaa99887766554433221100"
)


def _make_envelope(
    *,
    version: int = 1,
    overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    fields = copy.deepcopy(SYNTHETIC_V1_FIELDS)
    if version != 1:
        fields["ancestry_root"] = SYNTHETIC_V2_ROTATED_ROOT
        fields["nullifier"] = SYNTHETIC_V2_ROTATED_NULLIFIER
    if overrides:
        fields.update(overrides)
    return {
        "statement_schema": f"redacted_ancestry/v{version}",
        "circuit_version": version,
        "public_inputs": fields,
    }


def _encode_wire_hex(fields: dict[str, str]) -> str:
    chunks: list[str] = []
    for name in REDACTED_ANCESTRY_PUBLIC_FIELDS:
        raw = fields[name]
        scalar = int(raw, 16) if raw.startswith(("0x", "0X")) else int(raw, 10)
        chunks.append(f"{scalar:064x}")
    return "".join(chunks)


def test_cross_version_compatible_original_and_derivative_bindings() -> None:
    v1_stmt = _make_envelope(version=1)
    v2_stmt = _make_envelope(version=2)

    report = compare_ancestry_statements(v1_stmt, v2_stmt)
    assert report.compatible is True
    assert report.cross_version is True
    assert report.left_circuit_version == 1
    assert report.right_circuit_version == 2
    assert report.original_binding_equal is True
    assert report.derivative_binding_equal is True
    assert report.lineage_context_equal is True
    assert report.domain_binding_equal is True
    assert report.ancestry_root_relation == "rotated_with_circuit_version"
    assert report.nullifier_relation == "rotated_with_circuit_version"
    assert report.incompatible_changes == ()


def test_same_version_identical_and_distinct_nullifier_binder() -> None:
    left = _make_envelope(version=1)
    right_same = _make_envelope(version=1)
    report_same = compare_ancestry_statements(left, right_same)
    assert report_same.compatible is True
    assert report_same.cross_version is False
    assert report_same.ancestry_root_relation == "identical_same_version"
    assert report_same.nullifier_relation == "identical"

    right_rebound = _make_envelope(
        version=1,
        overrides={
            "nullifier": "0x111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0001"
        },
    )
    report_rebound = compare_ancestry_statements(left, right_rebound)
    assert report_rebound.compatible is True
    assert report_rebound.nullifier_relation == "distinct_binder"
    assert report_rebound.incompatible_changes == ()


def test_wire_hex_and_structured_json_parse_identically() -> None:
    wire_hex = _encode_wire_hex(SYNTHETIC_V1_FIELDS)
    browser_proof = {
        "artifactVersion": "redacted_ancestry/v1",
        "publicInputs": wire_hex,
    }
    structured = _make_envelope(version=1)

    report = compare_ancestry_statements(browser_proof, structured)
    assert report.compatible is True
    assert all(entry.equal for entry in report.field_comparisons)


@pytest.mark.parametrize(
    ("override_field", "override_val", "expected_code"),
    [
        (
            "parent_commitment",
            "0x0aa525932854b5452d78deea15b3cf24576aae19531419f725a029bd954618bb",
            IncompatibilityCode.ORIGINAL_BINDING_CHANGED,
        ),
        (
            "derivative_digest",
            "0x185fcb9607ac65b82ca64c952448321d6c2a8d1e2941f205a7bbdd935ac188ff",
            IncompatibilityCode.DERIVATIVE_DIGEST_CHANGED,
        ),
        (
            "parameters_digest",
            "0x1406ddb1d4f1e454474db5009b3e8f7294636b92c59171057551e57cb07f6e17",
            IncompatibilityCode.PARAMETERS_DIGEST_CHANGED,
        ),
        (
            "depth",
            str(MAX_ANCESTRY_DEPTH),
            IncompatibilityCode.DEPTH_CHANGED,
        ),
        (
            "domain_tag",
            "0x1b73cc6eda5fc8454c3bf62ef9defb0e6e1f7d999ab6857a39692821856ad61e",
            IncompatibilityCode.DOMAIN_TAG_CHANGED,
        ),
    ],
)
def test_identifies_incompatible_original_and_derivative_changes_across_versions(
    override_field: str,
    override_val: str,
    expected_code: IncompatibilityCode,
) -> None:
    v1_stmt = _make_envelope(version=1)
    v2_changed = _make_envelope(
        version=2, overrides={override_field: override_val}
    )

    report = compare_ancestry_statements(v1_stmt, v2_changed)
    assert report.compatible is False
    codes = {change.code for change in report.incompatible_changes}
    assert expected_code in codes


def test_detects_cross_version_root_and_nullifier_reuse_and_same_version_root_drift() -> None:
    v1_stmt = _make_envelope(version=1)
    # Reusing v1 ancestry_root and nullifier in a v2 statement violates CIRCUIT_VERSION binding.
    v2_unrotated = _make_envelope(
        version=2,
        overrides={
            "ancestry_root": SYNTHETIC_V1_FIELDS["ancestry_root"],
            "nullifier": SYNTHETIC_V1_FIELDS["nullifier"],
        },
    )
    cross_report = compare_ancestry_statements(v1_stmt, v2_unrotated)
    assert cross_report.compatible is False
    cross_codes = {c.code for c in cross_report.incompatible_changes}
    assert IncompatibilityCode.CROSS_VERSION_ANCESTRY_ROOT_REUSED in cross_codes
    assert IncompatibilityCode.CROSS_VERSION_NULLIFIER_REUSED in cross_codes

    # Diverging ancestry_root within v1 when all underlying bindings match is incompatible.
    v1_tampered_root = _make_envelope(
        version=1,
        overrides={"ancestry_root": SYNTHETIC_V2_ROTATED_ROOT},
    )
    same_report = compare_ancestry_statements(v1_stmt, v1_tampered_root)
    assert same_report.compatible is False
    assert [c.code for c in same_report.incompatible_changes] == [
        IncompatibilityCode.SAME_VERSION_ANCESTRY_ROOT_MISMATCH
    ]


def test_identifies_public_input_layout_and_slot_count_changes() -> None:
    v1_stmt = _make_envelope(version=1)

    # 9-slot wire frame in hypothetical v2
    nine_slot_hex = _encode_wire_hex(SYNTHETIC_V1_FIELDS) + ("00" * 31 + "01")
    v2_extra_slot = parse_ancestry_statement(nine_slot_hex, circuit_version=2)
    count_report = compare_ancestry_statements(v1_stmt, v2_extra_slot)
    assert count_report.compatible is False
    count_codes = {c.code for c in count_report.incompatible_changes}
    assert IncompatibilityCode.PUBLIC_INPUT_COUNT_CHANGED in count_codes
    assert IncompatibilityCode.PUBLIC_INPUT_LAYOUT_CHANGED in count_codes

    # Reordered 8-slot layout in hypothetical v2 (swapping nullifier and depth)
    reordered_fields = [
        "parent_commitment",
        "derivative_digest",
        "parameters_digest",
        "operation_type",
        "ancestry_root",
        "depth",
        "nullifier",
        "domain_tag",
    ]
    v2_reordered = _make_envelope(version=2)
    v2_reordered["public_fields"] = reordered_fields
    layout_report = compare_ancestry_statements(v1_stmt, v2_reordered)
    assert layout_report.compatible is False
    assert IncompatibilityCode.PUBLIC_INPUT_LAYOUT_CHANGED in {
        c.code for c in layout_report.incompatible_changes
    }


@pytest.mark.parametrize(
    ("overrides", "expected_reject"),
    [
        ({"parent_commitment": "0"}, StatementRejectCode.ZERO_STATEMENT_FIELD),
        ({"derivative_digest": "0"}, StatementRejectCode.ZERO_STATEMENT_FIELD),
        ({"parameters_digest": "0"}, StatementRejectCode.ZERO_STATEMENT_FIELD),
        ({"ancestry_root": "0"}, StatementRejectCode.ZERO_STATEMENT_FIELD),
        ({"nullifier": "0"}, StatementRejectCode.ZERO_STATEMENT_FIELD),
        ({"operation_type": "0x63726f70"}, StatementRejectCode.UNSUPPORTED_OPERATION_TYPE),
        ({"depth": "0"}, StatementRejectCode.DEPTH_OUT_OF_RANGE),
        ({"depth": str(MAX_ANCESTRY_DEPTH + 1)}, StatementRejectCode.DEPTH_OUT_OF_RANGE),
        (
            {"derivative_digest": SYNTHETIC_V1_FIELDS["parent_commitment"]},
            StatementRejectCode.ANCESTRY_CYCLE,
        ),
        (
            {"parent_commitment": str(BN254_SCALAR_MODULUS)},
            StatementRejectCode.NON_CANONICAL_FIELD,
        ),
    ],
)
def test_rejects_malformed_zeroed_cyclic_and_out_of_range_statements(
    overrides: dict[str, str],
    expected_reject: StatementRejectCode,
) -> None:
    bad = _make_envelope(version=1, overrides=overrides)
    with pytest.raises(StatementValidationError) as exc_info:
        parse_ancestry_statement(bad)
    assert exc_info.value.code is expected_reject

    # Boundary depths 1 and 4 are accepted.
    for valid_depth in (MIN_ANCESTRY_DEPTH, MAX_ANCESTRY_DEPTH):
        ok = _make_envelope(version=1, overrides={"depth": str(valid_depth)})
        parsed = parse_ancestry_statement(ok)
        assert parsed.depth_int() == valid_depth


@pytest.mark.parametrize(
    "private_key",
    [
        "private_path",
        "ancestry_path",
        "lineage_path",
        "intermediate_ancestors",
        "witness",
        "private_inputs",
        "parent_hash_hi",
        "parent_blinding",
        "mask_commitment",
        "redaction_seed",
        "credential_secret",
        "nullifier_secret",
    ],
)
def test_never_reveals_private_paths_witness_values_or_filesystem_paths(
    private_key: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    canary_secret = "CANARY_PRIVATE_LINEAGE_PATH_NODE_998877"
    secret_dir = tmp_path / "private_operator_dir_445566"
    secret_dir.mkdir(exist_ok=True)

    leaked_payload = _make_envelope(version=1)
    leaked_payload[private_key] = [canary_secret]

    with pytest.raises(StatementValidationError) as exc_info:
        parse_ancestry_statement(leaked_payload, side="left")
    assert exc_info.value.code is StatementRejectCode.PRIVATE_PATH_OR_WITNESS_PRESENT
    assert exc_info.value.field == "private_input_redacted"
    assert canary_secret not in str(exc_info.value)

    left_file = secret_dir / "left_with_private_path.json"
    right_file = secret_dir / "right_clean.json"
    left_file.write_text(json.dumps(leaked_payload), encoding="utf-8")
    right_file.write_text(json.dumps(_make_envelope(version=2)), encoding="utf-8")

    rc = main([str(left_file), str(right_file)])
    assert rc == EXIT_USAGE
    captured = capsys.readouterr()
    assert canary_secret not in captured.out
    assert canary_secret not in captured.err
    assert "private_operator_dir_445566" not in captured.out
    assert "private_operator_dir_445566" not in captured.err

    # Also verify compatible and incompatible CLI reports never echo filesystem paths or raw digests.
    clean_left = secret_dir / "left_v1.json"
    clean_left.write_text(json.dumps(_make_envelope(version=1)), encoding="utf-8")

    rc_ok = main([str(clean_left), str(right_file), "--format", "json"])
    assert rc_ok == EXIT_COMPATIBLE
    out_json = capsys.readouterr().out
    assert "private_operator_dir_445566" not in out_json
    assert SYNTHETIC_V1_FIELDS["parent_commitment"][2:] not in out_json.lower()

    bad_right = secret_dir / "right_v2_bad.json"
    bad_right.write_text(
        json.dumps(_make_envelope(version=2, overrides={"depth": "3"})),
        encoding="utf-8",
    )
    rc_diff = main([str(clean_left), str(bad_right), "--format", "markdown"])
    assert rc_diff == EXIT_INCOMPATIBLE
    out_md = capsys.readouterr().out
    assert "INCOMPATIBLE" in out_md
    assert "depth_changed" in out_md
    assert "private_operator_dir_445566" not in out_md


def test_file_loader_rejects_missing_oversized_and_wrong_schema(tmp_path: Path) -> None:
    with pytest.raises(StatementValidationError) as miss_err:
        load_statement_file(tmp_path / "missing.json", side="left")
    assert miss_err.value.code is StatementRejectCode.MISSING_INPUT

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAX_STATEMENT_FILE_BYTES + 1))
    with pytest.raises(StatementValidationError) as size_err:
        load_statement_file(oversized, side="right")
    assert size_err.value.code is StatementRejectCode.OVERSIZED_INPUT

    wrong_schema = _make_envelope(version=1)
    wrong_schema["statement_schema"] = "silent_witness/v2"
    with pytest.raises(StatementValidationError) as schema_err:
        parse_ancestry_statement(wrong_schema)
    assert schema_err.value.code is StatementRejectCode.UNSUPPORTED_SCHEMA

    report = compare_ancestry_statements(_make_envelope(version=1), _make_envelope(version=2))
    md = render_markdown_report(report)
    assert "`COMPATIBLE` (`cross-version`)" in md
