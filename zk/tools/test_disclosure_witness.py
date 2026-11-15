from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from zk.tools.disclosure_witness import (
    BN254_SCALAR_MODULUS,
    EXIT_OK,
    EXIT_REJECTED,
    MAX_ATTRIBUTES,
    MAX_PREDICATES,
    MAX_SET_MEMBERS,
    MAX_WITNESS_JSON_BYTES,
    MIN_ATTRIBUTES,
    MIN_PREDICATES,
    PREDICATE_TYPE_EQUALITY,
    PREDICATE_TYPE_RANGE,
    PREDICATE_TYPE_SET_MEMBERSHIP,
    DisclosureWitnessError,
    check_disclosure_attribute_count,
    check_disclosure_predicate_count,
    encode_predicate_type,
    main,
    prepare_disclosure_witness,
    prepare_disclosure_witness_from_mapping,
)


class _ForbiddenElementAccessSequence(Sequence[dict[str, Any]]):
    """Sequence that fails immediately if an oversized check reads any element."""

    def __init__(self, length: int) -> None:
        self._length = length
        self.element_reads = 0

    def __len__(self) -> int:
        return self._length

    def __getitem__(self, index: int) -> dict[str, Any]:  # type: ignore[override]
        self.element_reads += 1
        raise AssertionError(
            f"oversized list accessed element {index} before rejection"
        )


def test_predicate_and_attribute_count_boundaries() -> None:
    for count in range(MIN_PREDICATES, MAX_PREDICATES + 1):
        assert check_disclosure_predicate_count(count) == count

    with pytest.raises(DisclosureWitnessError) as over_pred:
        check_disclosure_predicate_count(MAX_PREDICATES + 1)
    assert over_pred.value.code == "predicates_oversize"
    assert over_pred.value.signal() == {
        "field": "num_predicates",
        "rejectCode": "predicates_oversize",
    }

    with pytest.raises(DisclosureWitnessError) as under_pred:
        check_disclosure_predicate_count(-1)
    assert under_pred.value.code == "predicates_undersize"

    for bad in (True, False, "8", 2.5, None):
        with pytest.raises(DisclosureWitnessError) as mal:
            check_disclosure_predicate_count(bad)
        assert mal.value.code == "malformed_num_predicates"

    for attr_count in range(MIN_ATTRIBUTES, MAX_ATTRIBUTES + 1):
        assert check_disclosure_attribute_count(attr_count) == attr_count

    with pytest.raises(DisclosureWitnessError) as under_attr:
        check_disclosure_attribute_count(0)
    assert under_attr.value.code == "attributes_undersize"

    with pytest.raises(DisclosureWitnessError) as over_attr:
        check_disclosure_attribute_count(MAX_ATTRIBUTES + 1)
    assert over_attr.value.code == "attributes_oversize"


def test_rejects_oversized_predicate_list_before_reading_or_allocating() -> None:
    trap_preds = _ForbiddenElementAccessSequence(MAX_PREDICATES + 1)

    with pytest.raises(DisclosureWitnessError) as exc_info:
        prepare_disclosure_witness(
            attr_values=[18, 12345678],
            attr_blindings=[111111, 222222],
            predicates=trap_preds,
            num_attributes=2,
            num_predicates=MAX_PREDICATES + 1,
        )
    assert exc_info.value.code == "predicates_oversize"
    assert exc_info.value.field == "predicates"
    assert trap_preds.element_reads == 0

    # Unbounded iterators/generators are rejected without materialization.
    def _infinite_generator() -> Iterator[dict[str, Any]]:
        while True:
            yield {"predicate_type": "Equality", "attr_index": 0, "public_value": 1}

    with pytest.raises(DisclosureWitnessError) as gen_err:
        prepare_disclosure_witness(
            attr_values=[18],
            attr_blindings=[111111],
            predicates=_infinite_generator(),
        )
    assert gen_err.value.code == "malformed_predicates"


def test_preserves_supported_predicate_order_and_canonical_encoding() -> None:
    assert encode_predicate_type("Equality") == PREDICATE_TYPE_EQUALITY == 0
    assert encode_predicate_type("SetMembership") == PREDICATE_TYPE_SET_MEMBERSHIP == 1
    assert encode_predicate_type("Range") == PREDICATE_TYPE_RANGE == 2
    assert encode_predicate_type(0) == 0
    assert encode_predicate_type(1) == 1
    assert encode_predicate_type(2) == 2

    # Worked age-and-country example order from docs/zk-selective-disclosure-spec.md §5.2,
    # followed by an Equality predicate to exercise all 3 supported types in order.
    predicates = [
        {
            "predicateType": "Range",
            "attrIndex": 0,
            "lowerBound": 18,
            "upperBound": 99,
        },
        {
            "predicateType": "SetMembership",
            "attrIndex": 1,
            "setValues": [12345678, 87654321],
            "setLen": 2,
        },
        {
            "predicateType": "Equality",
            "attrIndex": 0,
            "publicValue": "0x12",
        },
    ]

    witness = prepare_disclosure_witness(
        attr_values=[18, 12345678],
        attr_blindings=[111111, 222222],
        predicates=predicates,
        num_attributes=2,
        num_predicates=3,
    )

    assert witness["num_attributes"] == "2"
    assert witness["num_predicates"] == "3"
    assert len(witness["attr_values"]) == MAX_ATTRIBUTES
    assert len(witness["attr_blindings"]) == MAX_ATTRIBUTES
    assert len(witness["predicates"]) == MAX_PREDICATES

    # Exact active order preserved at slots 0, 1, 2:
    assert witness["predicates"][0] == {
        "predicate_type": "2",
        "attr_index": "0",
        "public_value": "0",
        "set_values": ["0"] * MAX_SET_MEMBERS,
        "set_len": "0",
        "lower_bound": "18",
        "upper_bound": "99",
    }
    assert witness["predicates"][1] == {
        "predicate_type": "1",
        "attr_index": "1",
        "public_value": "0",
        "set_values": ["12345678", "87654321", "0", "0", "0", "0", "0", "0"],
        "set_len": "2",
        "lower_bound": "0",
        "upper_bound": "0",
    }
    assert witness["predicates"][2] == {
        "predicate_type": "0",
        "attr_index": "0",
        "public_value": "18",
        "set_values": ["0"] * MAX_SET_MEMBERS,
        "set_len": "0",
        "lower_bound": "0",
        "upper_bound": "0",
    }

    # Inactive slots 3..7 are zero-padded without reordering active slots.
    for slot in range(3, MAX_PREDICATES):
        assert witness["predicates"][slot]["predicate_type"] == "0"
        assert witness["predicates"][slot]["public_value"] == "0"
        assert witness["predicates"][slot]["set_len"] == "0"


def test_accepts_zero_and_exact_max_predicate_boundaries() -> None:
    empty = prepare_disclosure_witness(
        attr_values=[42],
        attr_blindings=[99],
        predicates=[],
        num_attributes=1,
        num_predicates=0,
    )
    assert empty["num_predicates"] == "0"
    assert len(empty["predicates"]) == MAX_PREDICATES

    max_list = [
        {"predicate_type": 0, "attr_index": 0, "public_value": idx + 10}
        for idx in range(MAX_PREDICATES)
    ]
    at_max = prepare_disclosure_witness(
        attr_values=[42],
        attr_blindings=[99],
        predicates=max_list,
        num_attributes=1,
        num_predicates=MAX_PREDICATES,
    )
    assert at_max["num_predicates"] == str(MAX_PREDICATES)
    assert [p["public_value"] for p in at_max["predicates"]] == [
        str(idx + 10) for idx in range(MAX_PREDICATES)
    ]


def test_rejects_oversized_set_members_attributes_and_mismatched_counts() -> None:
    # Oversized set_values (> 8)
    with pytest.raises(DisclosureWitnessError) as over_set:
        prepare_disclosure_witness(
            attr_values=[18],
            attr_blindings=[111],
            predicates=[
                {
                    "predicate_type": "SetMembership",
                    "attr_index": 0,
                    "set_values": list(range(1, MAX_SET_MEMBERS + 2)),
                    "set_len": MAX_SET_MEMBERS + 1,
                }
            ],
        )
    assert over_set.value.code == "set_members_oversize"

    # Empty set for SetMembership
    with pytest.raises(DisclosureWitnessError) as empty_set:
        prepare_disclosure_witness(
            attr_values=[18],
            attr_blindings=[111],
            predicates=[
                {
                    "predicate_type": "SetMembership",
                    "attr_index": 0,
                    "set_values": [],
                    "set_len": 0,
                }
            ],
        )
    assert empty_set.value.code == "set_members_undersize"

    # Oversized attributes (> 16)
    with pytest.raises(DisclosureWitnessError) as over_attrs:
        prepare_disclosure_witness(
            attr_values=[1] * (MAX_ATTRIBUTES + 1),
            attr_blindings=[2] * (MAX_ATTRIBUTES + 1),
            predicates=[],
        )
    assert over_attrs.value.code == "attributes_oversize"

    # Mismatched num_predicates vs len(predicates)
    with pytest.raises(DisclosureWitnessError) as count_mismatch:
        prepare_disclosure_witness(
            attr_values=[18],
            attr_blindings=[111],
            predicates=[{"predicate_type": 0, "attr_index": 0, "public_value": 18}],
            num_predicates=2,
        )
    assert count_mismatch.value.code == "predicate_count_mismatch"

    # Out-of-range attr_index and field modulus
    with pytest.raises(DisclosureWitnessError) as bad_idx:
        prepare_disclosure_witness(
            attr_values=[18],
            attr_blindings=[111],
            predicates=[{"predicate_type": 0, "attr_index": 1, "public_value": 18}],
        )
    assert bad_idx.value.code == "predicate_attr_out_of_range"

    with pytest.raises(DisclosureWitnessError) as bad_mod:
        prepare_disclosure_witness(
            attr_values=[BN254_SCALAR_MODULUS],
            attr_blindings=[111],
            predicates=[],
        )
    assert bad_mod.value.code == "field_element_out_of_range"


def test_privacy_safety_and_cli_validation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    canary_secret = "999888777666555444333222111"
    bad_payload = {
        "numAttributes": 1,
        "attrValues": [canary_secret],
        "attrBlindings": ["777777777777"],
        "numPredicates": 9,
        "predicates": [
            {"predicateType": "Equality", "attrIndex": 0, "publicValue": canary_secret}
            for _ in range(9)
        ],
    }
    with pytest.raises(DisclosureWitnessError) as exc_info:
        prepare_disclosure_witness_from_mapping(bad_payload)
    assert exc_info.value.code == "predicates_oversize"
    assert canary_secret not in str(exc_info.value)

    bad_file = tmp_path / "oversized_preds.json"
    bad_file.write_text(json.dumps(bad_payload), encoding="utf-8")
    assert main([str(bad_file)]) == EXIT_REJECTED
    captured = capsys.readouterr()
    assert json.loads(captured.err) == {
        "field": "predicates",
        "rejectCode": "predicates_oversize",
    }
    assert canary_secret not in captured.err

    ok_file = tmp_path / "valid_witness.json"
    ok_file.write_text(
        json.dumps(
            {
                "numAttributes": 1,
                "attrValues": ["18"],
                "attrBlindings": ["111"],
                "numPredicates": 1,
                "predicates": [
                    {"predicateType": "Equality", "attrIndex": 0, "publicValue": "18"}
                ],
            }
        ),
        encoding="utf-8",
    )
    assert main([str(ok_file)]) == EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out == {
        "num_attributes": 1,
        "num_predicates": 1,
        "ok": True,
        "padded_predicate_slots": MAX_PREDICATES,
    }
    assert canary_secret not in json.dumps(out)

    huge_file = tmp_path / "huge.json"
    huge_file.write_bytes(b" " * (MAX_WITNESS_JSON_BYTES + 1))
    assert main([str(huge_file)]) == EXIT_REJECTED
    assert json.loads(capsys.readouterr().err)["rejectCode"] == "oversized_input"
