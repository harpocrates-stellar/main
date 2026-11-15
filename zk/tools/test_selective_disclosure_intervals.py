"""Focused conformance, oracle, privacy, and sync tests for interval intersection predicates (#1209).

Run from the repository root:

    python -m pytest zk/tools/test_selective_disclosure_intervals.py -q
"""

from __future__ import annotations

import itertools
import json
import re
from pathlib import Path

import pytest

from zk.tools import selective_disclosure_intervals as sdi

REPO_ROOT = Path(__file__).resolve().parents[2]
CIRCUIT_PATH = REPO_ROOT / "zk" / "noir" / "selective_disclosure" / "src" / "main.nr"
PROVER_TOML_PATH = REPO_ROOT / "zk" / "noir" / "selective_disclosure" / "Prover.toml"
SCHEMA_TS_PATH = REPO_ROOT / "frontend" / "src" / "types" / "schema.ts"
PROVER_TS_PATH = REPO_ROOT / "frontend" / "src" / "selectiveDisclosure.ts"

FORBIDDEN_KEYS = {
    "private_key",
    "credential_secret_hex",
    "witness_bytes",
    "proof_hex",
    "real_media",
}

NOIR_GLOBAL_RE = re.compile(
    r"^\s*global\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[^=]+=\s*"
    r"([0-9][0-9_]*|0x[0-9a-fA-F][0-9a-fA-F_]*)\s*;",
    re.MULTILINE,
)


def independent_pointwise_oracle(
    value: int,
    clauses: list[sdi.IntervalClause],
) -> bool:
    """Independent reference oracle: integer ``value`` satisfies every clause literally."""
    for clause in clauses:
        lower_ok = (value >= clause.lower) if clause.lower_inclusive else (value > clause.lower)
        upper_ok = (value <= clause.upper) if clause.upper_inclusive else (value < clause.upper)
        if not (lower_ok and upper_ok):
            return False
    return True


@pytest.fixture(scope="module")
def corpus() -> dict:
    return json.loads(sdi.DEFAULT_FIXTURE_PATH.read_text(encoding="utf-8"))


def test_cli_check_passes_and_detects_drift(tmp_path: Path) -> None:
    assert sdi.main(["--check"]) == sdi.EXIT_OK

    missing = tmp_path / "missing_vectors.json"
    assert sdi.main(["--check", "--output", str(missing)]) == sdi.EXIT_DRIFT

    generated = tmp_path / "generated_vectors.json"
    assert sdi.main(["--generate", "--output", str(generated)]) == sdi.EXIT_OK
    assert sdi.main(["--check", "--output", str(generated)]) == sdi.EXIT_OK
    assert b"\r" not in generated.read_bytes()

    tampered = json.loads(generated.read_text(encoding="utf-8"))
    tampered["_version"] = "9.9.9"
    generated.write_text(json.dumps(tampered, indent=2) + "\n", encoding="utf-8")
    assert sdi.main(["--check", "--output", str(generated)]) == sdi.EXIT_DRIFT


def test_fixture_metadata_and_privacy_hygiene(corpus: dict) -> None:
    assert corpus["_circuit"] == "selective_disclosure/v1"
    assert corpus["_version"] == "1.0.0"
    assert corpus["_predicate_type_id"] == sdi.INTERVAL_INTERSECTION_PREDICATE_TYPE == 3
    assert corpus["_predicate_type_name"] == "IntervalIntersection"
    assert corpus["_max_interval_clauses"] == sdi.MAX_INTERVAL_CLAUSES == 4
    assert len(corpus["privacy_notes"]) >= 3

    serialized = json.dumps(corpus).lower()
    for forbidden in FORBIDDEN_KEYS:
        assert forbidden not in serialized

    assert len(corpus["positive_cases"]) >= 8
    assert len(corpus["negative_cases"]) >= 16


def test_pack_unpack_canonical_interval_bijection() -> None:
    endpoints = [0, 1, 18, 25, (1 << 32) - 1, sdi.U64_MAX - 1, sdi.U64_MAX]
    seen_packings: set[int] = set()

    for lo in endpoints:
        for hi in endpoints:
            for lo_inc in (False, True):
                for hi_inc in (False, True):
                    packed = sdi.pack_canonical_interval_conjunction(lo, hi, lo_inc, hi_inc)
                    assert 0 <= packed < sdi.BN254_SCALAR_MODULUS
                    assert packed < 4 * sdi.TWO_POW_128
                    assert packed not in seen_packings
                    seen_packings.add(packed)
                    assert sdi.unpack_canonical_interval_conjunction(packed) == (
                        lo,
                        hi,
                        lo_inc,
                        hi_inc,
                    )

    with pytest.raises(sdi.IntervalPredicateError) as exc_info:
        sdi.unpack_canonical_interval_conjunction(4 * sdi.TWO_POW_128)
    assert exc_info.value.code == "invalid_packed_interval"


def test_exhaustive_small_grid_matches_independent_pointwise_oracle() -> None:
    """Every 2-clause combination over {0, 1, 2, 4, 5} matches the pointwise oracle."""
    coords = [0, 1, 2, 4, 5]
    probe_values = [0, 1, 2, 3, 4, 5, 6]
    single_clauses = [
        sdi.IntervalClause(lo, hi, lo_inc, hi_inc)
        for lo in coords
        for hi in coords
        for lo_inc in (False, True)
        for hi_inc in (False, True)
    ]

    for c1 in single_clauses[::3]:
        for c2 in single_clauses[::2]:
            clauses = [c1, c2]
            reduced = sdi.reduce_interval_conjunction(clauses)
            expected_members = [
                v for v in probe_values if independent_pointwise_oracle(v, clauses)
            ]
            actual_members = [v for v in probe_values if reduced.contains(v)]
            assert actual_members == expected_members
            assert reduced.is_empty == (len(expected_members) == 0)
            if expected_members:
                assert reduced.min_valid_u64 == min(expected_members)
                assert reduced.max_valid_u64 == max(expected_members)
            else:
                assert reduced.min_valid_u64 is None
                assert reduced.max_valid_u64 is None


def test_u64_max_edge_grid_matches_independent_pointwise_oracle() -> None:
    hi_coords = [sdi.U64_MAX - 2, sdi.U64_MAX - 1, sdi.U64_MAX]
    single_clauses = [
        sdi.IntervalClause(lo, hi, lo_inc, hi_inc)
        for lo in hi_coords
        for hi in hi_coords
        for lo_inc in (False, True)
        for hi_inc in (False, True)
    ]

    for c1 in single_clauses:
        for c2 in single_clauses[::4]:
            clauses = [c1, c2]
            reduced = sdi.reduce_interval_conjunction(clauses)
            expected_members = [
                v for v in hi_coords if independent_pointwise_oracle(v, clauses)
            ]
            actual_members = [v for v in hi_coords if reduced.contains(v)]
            assert actual_members == expected_members
            assert reduced.is_empty == (len(expected_members) == 0)


def test_all_four_clause_permutations_yield_identical_canonical_conjunction_and_commitment() -> None:
    base_clauses = [
        sdi.IntervalClause(10, 100, True, True),
        sdi.IntervalClause(20, 80, False, True),
        sdi.IntervalClause(15, 60, True, False),
        sdi.IntervalClause(20, 70, True, True),
    ]
    baseline_conj = sdi.reduce_interval_conjunction(base_clauses)
    assert baseline_conj.notation == "(20, 60)"
    assert baseline_conj.min_valid_u64 == 21
    assert baseline_conj.max_valid_u64 == 59

    baseline_stmt = sdi.build_public_statement_preview(
        attr_values=[35, 12345678],
        attr_blindings=[111111, 222222],
        num_attributes=2,
        active_predicates=[sdi.encode_interval_predicate(0, base_clauses)],
    )
    baseline_pred_comm = baseline_stmt["fields_hex"]["predicate_commitment"]

    for perm in itertools.permutations(base_clauses):
        conj = sdi.reduce_interval_conjunction(list(perm))
        assert conj == baseline_conj
        stmt = sdi.build_public_statement_preview(
            attr_values=[48, 87654321],
            attr_blindings=[999999, 777777],
            num_attributes=2,
            active_predicates=[sdi.encode_interval_predicate(0, list(perm))],
        )
        assert stmt["fields_hex"]["predicate_commitment"] == baseline_pred_comm


def test_certified_value_remains_hidden_in_public_statements_and_commitments(
    corpus: dict,
) -> None:
    cases_by_id = {case["id"]: case for case in corpus["positive_cases"]}
    case_a = cases_by_id["sd-int-pos-005-four-clause-order-a-hidden-min"]
    case_b = cases_by_id["sd-int-pos-006-four-clause-order-b-hidden-max"]

    pub_a = case_a["public_statement"]
    pub_b = case_b["public_statement"]

    assert (
        pub_a["fields_hex"]["predicate_commitment"]
        == pub_b["fields_hex"]["predicate_commitment"]
    )
    assert (
        pub_a["fields_hex"]["credential_root"]
        != pub_b["fields_hex"]["credential_root"]
    )
    assert pub_a["fields_hex"]["nullifier"] != pub_b["fields_hex"]["nullifier"]
    assert len(pub_a["wire_public_inputs_hex"]) == 704
    assert len(pub_b["wire_public_inputs_hex"]) == 704

    for case in [*corpus["positive_cases"], *corpus["negative_cases"]]:
        pub_json = json.dumps(case["public_statement"])
        pred_json = json.dumps(case["encoded_predicate"])
        assert "certified_attr_value" not in pub_json
        assert "certified_attr_blinding" not in pub_json
        assert "certified_attr_value" not in pred_json
        assert "certified_attr_blinding" not in pred_json

    secret_val_a_hex = f"{21:064x}"
    secret_val_b_hex = f"{59:064x}"
    assert secret_val_a_hex not in json.dumps(pub_a)
    assert secret_val_b_hex not in json.dumps(pub_b)


def test_fixture_vectors_execute_against_circuit_and_pointwise_oracle(
    corpus: dict,
) -> None:
    padding = {
        "predicate_type": "0",
        "attr_index": 0,
        "public_value": "0",
        "set_values": ["0"] * sdi.MAX_SET_MEMBERS,
        "set_len": 0,
        "lower_bound": "0",
        "upper_bound": "0",
    }

    for case in corpus["positive_cases"]:
        clauses = [
            sdi.IntervalClause(
                c["lower"],
                c["upper"],
                c["lower_inclusive"],
                c["upper_inclusive"],
            )
            for c in case["clauses"]
        ]
        opening = case["prover_only_synthetic_opening"]
        certified_val = opening["certified_attr_value"]
        assert independent_pointwise_oracle(certified_val, clauses)

        preds = [case["encoded_predicate"]] + [padding] * (sdi.MAX_PREDICATES - 1)
        fields_hex = case["public_statement"]["fields_hex"]
        ok, err = sdi.evaluate_selective_disclosure_circuit(
            circuit_version=sdi.CURRENT_CIRCUIT_VERSION,
            verifier_digest=int(fields_hex["verifier_digest"], 16),
            credential_root=int(fields_hex["credential_root"], 16),
            nullifier=int(fields_hex["nullifier"], 16),
            predicate_commitment=int(fields_hex["predicate_commitment"], 16),
            num_attributes=2,
            attr_values=[certified_val, opening["secondary_attr_value"]] + [0] * 14,
            attr_blindings=[
                opening["certified_attr_blinding"],
                opening["secondary_attr_blinding"],
            ]
            + [0] * 14,
            num_predicates=1,
            predicates=preds,
        )
        assert ok and err is None, case["id"]

    for case in corpus["negative_cases"]:
        opening = case["prover_only_synthetic_opening"]
        certified_val = opening["certified_attr_value"]
        if case["expect_fail_with"] == "empty interval intersection":
            clauses = [
                sdi.IntervalClause(
                    c["lower"],
                    c["upper"],
                    c["lower_inclusive"],
                    c["upper_inclusive"],
                )
                for c in case["clauses"]
            ]
            reduced = sdi.reduce_interval_conjunction(clauses)
            assert reduced.is_empty
            for probe in {0, 1, 17, 18, 19, 20, 25, sdi.U64_MAX - 1, sdi.U64_MAX}:
                assert not independent_pointwise_oracle(probe, clauses)

        preds = [case["encoded_predicate"]] + [padding] * (sdi.MAX_PREDICATES - 1)
        fields_hex = case["public_statement"]["fields_hex"]
        ok, err = sdi.evaluate_selective_disclosure_circuit(
            circuit_version=sdi.CURRENT_CIRCUIT_VERSION,
            verifier_digest=int(fields_hex["verifier_digest"], 16),
            credential_root=int(fields_hex["credential_root"], 16),
            nullifier=int(fields_hex["nullifier"], 16),
            predicate_commitment=int(fields_hex["predicate_commitment"], 16),
            num_attributes=2,
            attr_values=[certified_val, opening["secondary_attr_value"]] + [0] * 14,
            attr_blindings=[
                opening["certified_attr_blinding"],
                opening["secondary_attr_blinding"],
            ]
            + [0] * 14,
            num_predicates=1,
            predicates=preds,
        )
        assert not ok
        assert err == case["expect_fail_with"], case["id"]


def test_encode_interval_predicate_rejects_invalid_and_empty_inputs_safely() -> None:
    with pytest.raises(sdi.IntervalPredicateError) as empty_clauses_exc:
        sdi.reduce_interval_conjunction([])
    assert empty_clauses_exc.value.code == "empty_clause_list"

    with pytest.raises(sdi.IntervalPredicateError) as oversized_exc:
        sdi.reduce_interval_conjunction(
            [sdi.IntervalClause(10, 30) for _ in range(sdi.MAX_INTERVAL_CLAUSES + 1)]
        )
    assert oversized_exc.value.code == "oversized_clause_list"

    with pytest.raises(sdi.IntervalPredicateError) as empty_intersection_exc:
        sdi.encode_interval_predicate(
            0,
            [
                sdi.IntervalClause(10, 18, True, False),
                sdi.IntervalClause(18, 25, True, True),
            ],
        )
    assert empty_intersection_exc.value.code == "empty_interval_intersection"

    with pytest.raises(sdi.IntervalPredicateError) as bad_attr_exc:
        sdi.encode_interval_predicate(
            sdi.MAX_ATTRIBUTES,
            [sdi.IntervalClause(10, 30)],
        )
    assert bad_attr_exc.value.code == "attr_index_out_of_bounds"

    with pytest.raises(sdi.IntervalPredicateError) as bad_u64_exc:
        sdi.IntervalClause(-1, 10)
    assert bad_u64_exc.value.code == "bound_out_of_u64_range"


def test_existing_equality_set_membership_and_range_remain_compatible() -> None:
    large_field_attr = sdi.BN254_SCALAR_MODULUS - 7
    eq_pred = {
        "predicate_type": str(sdi.EQ_PREDICATE_TYPE),
        "attr_index": 1,
        "public_value": str(large_field_attr),
        "set_values": ["0"] * sdi.MAX_SET_MEMBERS,
        "set_len": 0,
        "lower_bound": "0",
        "upper_bound": "0",
    }
    set_pred = {
        "predicate_type": str(sdi.SET_MEMBERSHIP_PREDICATE_TYPE),
        "attr_index": 1,
        "public_value": "0",
        "set_values": [str(large_field_attr), "42"] + ["0"] * 6,
        "set_len": 2,
        "lower_bound": "0",
        "upper_bound": "0",
    }
    range_pred = {
        "predicate_type": str(sdi.RANGE_PREDICATE_TYPE),
        "attr_index": 0,
        "public_value": "0",
        "set_values": ["0"] * sdi.MAX_SET_MEMBERS,
        "set_len": 0,
        "lower_bound": "18",
        "upper_bound": "99",
    }
    interval_pred = sdi.encode_interval_predicate(
        0,
        [
            sdi.IntervalClause(10, 30, True, True),
            sdi.IntervalClause(18, 25, False, True),
        ],
    )

    active = [eq_pred, set_pred, range_pred, interval_pred]
    padding = {
        "predicate_type": "0",
        "attr_index": 0,
        "public_value": "0",
        "set_values": ["0"] * sdi.MAX_SET_MEMBERS,
        "set_len": 0,
        "lower_bound": "0",
        "upper_bound": "0",
    }
    padded_preds = active + [padding] * (sdi.MAX_PREDICATES - len(active))
    attrs = [21, large_field_attr] + [0] * 14
    blindings = [111111, 222222] + [0] * 14
    preview = sdi.build_public_statement_preview(
        attr_values=attrs,
        attr_blindings=blindings,
        num_attributes=2,
        active_predicates=active,
    )
    fields_hex = preview["fields_hex"]

    ok, err = sdi.evaluate_selective_disclosure_circuit(
        circuit_version=sdi.CURRENT_CIRCUIT_VERSION,
        verifier_digest=int(fields_hex["verifier_digest"], 16),
        credential_root=int(fields_hex["credential_root"], 16),
        nullifier=int(fields_hex["nullifier"], 16),
        predicate_commitment=int(fields_hex["predicate_commitment"], 16),
        num_attributes=2,
        attr_values=attrs,
        attr_blindings=blindings,
        num_predicates=len(active),
        predicates=padded_preds,
    )
    assert ok and err is None


def test_noir_circuit_and_typescript_constants_and_asserts_stay_synced(
    corpus: dict,
) -> None:
    noir_source = CIRCUIT_PATH.read_text(encoding="utf-8")
    assert "unconstrained fn" not in noir_source

    noir_globals = {
        name: int(val.replace("_", ""), 0)
        for name, val in NOIR_GLOBAL_RE.findall(noir_source)
    }
    expected_globals = {
        "MAX_ATTRIBUTES": sdi.MAX_ATTRIBUTES,
        "MAX_PREDICATES": sdi.MAX_PREDICATES,
        "MAX_SET_MEMBERS": sdi.MAX_SET_MEMBERS,
        "MAX_INTERVAL_CLAUSES": sdi.MAX_INTERVAL_CLAUSES,
        "CURRENT_CIRCUIT_VERSION": sdi.CURRENT_CIRCUIT_VERSION,
        "EQ_PREDICATE_TYPE": sdi.EQ_PREDICATE_TYPE,
        "SET_MEMBERSHIP_PREDICATE_TYPE": sdi.SET_MEMBERSHIP_PREDICATE_TYPE,
        "RANGE_PREDICATE_TYPE": sdi.RANGE_PREDICATE_TYPE,
        "INTERVAL_INTERSECTION_PREDICATE_TYPE": sdi.INTERVAL_INTERSECTION_PREDICATE_TYPE,
        "TWO_POW_64": sdi.TWO_POW_64,
        "TWO_POW_128": sdi.TWO_POW_128,
        "U64_MAX": sdi.U64_MAX,
    }
    for key, expected_val in expected_globals.items():
        assert noir_globals.get(key) == expected_val, f"Noir global mismatch on {key}"

    for case in corpus["negative_cases"]:
        msg = case["expect_fail_with"]
        assert f'"{msg}"' in noir_source, f"Circuit missing assert literal: {msg}"

    prover_toml = PROVER_TOML_PATH.read_text(encoding="utf-8")
    assert "predicate_type =" in prover_toml
    assert "lower_bound =" in prover_toml
    assert "upper_bound =" in prover_toml

    schema_ts = SCHEMA_TS_PATH.read_text(encoding="utf-8")
    assert "'IntervalIntersection'" in schema_ts
    assert "MAX_INTERVAL_CLAUSES: 4" in schema_ts

    prover_ts = PROVER_TS_PATH.read_text(encoding="utf-8")
    assert "case 'IntervalIntersection':" in prover_ts
    assert "predicate_type: '3'" in prover_ts
