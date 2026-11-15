#!/usr/bin/env python3
"""Bounded selective-disclosure witness preparation (#1210).

Enforces protocol size bounds on selective-disclosure predicate, set-member,
and attribute lists *before* padded witness allocation, commitment hashing, or
Noir proving while preserving the documented predicate order and encoding:

    Equality      -> 0
    SetMembership -> 1
    Range         -> 2

Constants stay in lockstep with ``zk/noir/selective_disclosure/src/main.nr``
and ``frontend/src/types/schema.ts`` (verified by
``zk/tools/test_bound_constants_sync.py``):

    MIN_ATTRIBUTES  = 1
    MAX_ATTRIBUTES  = 16
    MIN_PREDICATES  = 0
    MAX_PREDICATES  = 8
    MIN_SET_MEMBERS = 1
    MAX_SET_MEMBERS = 8

All rejections emit a privacy-safe ``(code, field)`` pair and never echo
attribute values, blindings, set elements, or predicate bounds.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

MIN_ATTRIBUTES: Final[int] = 1
MAX_ATTRIBUTES: Final[int] = 16

MIN_PREDICATES: Final[int] = 0
MAX_PREDICATES: Final[int] = 8

MIN_SET_MEMBERS: Final[int] = 1
MAX_SET_MEMBERS: Final[int] = 8

CURRENT_CIRCUIT_VERSION: Final[int] = 1

BN254_SCALAR_MODULUS: Final[int] = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)

MAX_WITNESS_JSON_BYTES: Final[int] = 256 * 1024

PREDICATE_TYPE_EQUALITY: Final[int] = 0
PREDICATE_TYPE_SET_MEMBERSHIP: Final[int] = 1
PREDICATE_TYPE_RANGE: Final[int] = 2

PREDICATE_TYPE_ENCODING: Final[dict[str, int]] = {
    "Equality": PREDICATE_TYPE_EQUALITY,
    "SetMembership": PREDICATE_TYPE_SET_MEMBERSHIP,
    "Range": PREDICATE_TYPE_RANGE,
}

SUPPORTED_PREDICATE_CODES: Final[frozenset[int]] = frozenset(
    PREDICATE_TYPE_ENCODING.values()
)

EXIT_OK: Final[int] = 0
EXIT_REJECTED: Final[int] = 1
EXIT_USAGE: Final[int] = 2

_DECIMAL_RE: Final[re.Pattern[str]] = re.compile(r"^(?:0|[1-9][0-9]{0,77})$")
_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^0[xX][0-9a-fA-F]{1,64}$")


class DisclosureWitnessError(ValueError):
    """Privacy-safe witness preparation error that never echoes secret values."""

    def __init__(self, code: str, field: str = "predicates") -> None:
        self.code = code
        self.field = field
        super().__init__(f"{code}:{field}")

    def signal(self) -> dict[str, str]:
        return {"rejectCode": self.code, "field": self.field}


def _is_bounded_sequence(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    )


def _require_non_bool_int(value: object, *, code: str, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise DisclosureWitnessError(code, field)
    return value


def _encode_field_decimal(value: object, *, field: str) -> str:
    """Validate a BN254 scalar field element and return its canonical decimal string."""
    if isinstance(value, bool):
        raise DisclosureWitnessError("malformed_field_element", field)
    if isinstance(value, int):
        scalar = value
    elif isinstance(value, str):
        stripped = value.strip()
        if _DECIMAL_RE.fullmatch(stripped) is not None:
            scalar = int(stripped, 10)
        elif _HEX_RE.fullmatch(stripped) is not None:
            scalar = int(stripped, 16)
        else:
            raise DisclosureWitnessError("malformed_field_element", field)
    else:
        raise DisclosureWitnessError("malformed_field_element", field)

    if scalar < 0 or scalar >= BN254_SCALAR_MODULUS:
        raise DisclosureWitnessError("field_element_out_of_range", field)
    return str(scalar)


def check_disclosure_predicate_count(
    count: object,
    *,
    field: str = "num_predicates",
) -> int:
    """Validate ``count`` is an integer within ``[MIN_PREDICATES, MAX_PREDICATES]``."""
    parsed = _require_non_bool_int(
        count, code="malformed_num_predicates", field=field
    )
    if parsed < MIN_PREDICATES:
        raise DisclosureWitnessError("predicates_undersize", field)
    if parsed > MAX_PREDICATES:
        raise DisclosureWitnessError("predicates_oversize", field)
    return parsed


def check_disclosure_attribute_count(
    count: object,
    *,
    field: str = "num_attributes",
) -> int:
    """Validate ``count`` is an integer within ``[MIN_ATTRIBUTES, MAX_ATTRIBUTES]``."""
    parsed = _require_non_bool_int(
        count, code="malformed_num_attributes", field=field
    )
    if parsed < MIN_ATTRIBUTES:
        raise DisclosureWitnessError("attributes_undersize", field)
    if parsed > MAX_ATTRIBUTES:
        raise DisclosureWitnessError("attributes_oversize", field)
    return parsed


def encode_predicate_type(
    predicate_type: object,
    *,
    field: str = "predicate_type",
) -> int:
    """Return the canonical numeric code (`0`, `1`, `2`) for a supported predicate type."""
    if isinstance(predicate_type, bool):
        raise DisclosureWitnessError("unsupported_predicate_type", field)
    if isinstance(predicate_type, int):
        if predicate_type in SUPPORTED_PREDICATE_CODES:
            return predicate_type
        raise DisclosureWitnessError("unsupported_predicate_type", field)
    if isinstance(predicate_type, str):
        if predicate_type in PREDICATE_TYPE_ENCODING:
            return PREDICATE_TYPE_ENCODING[predicate_type]
        if predicate_type in {"0", "1", "2"}:
            return int(predicate_type, 10)
        raise DisclosureWitnessError("unsupported_predicate_type", field)
    raise DisclosureWitnessError("unsupported_predicate_type", field)


def _zero_padded_predicate() -> dict[str, Any]:
    return {
        "predicate_type": str(PREDICATE_TYPE_EQUALITY),
        "attr_index": "0",
        "public_value": "0",
        "set_values": ["0"] * MAX_SET_MEMBERS,
        "set_len": "0",
        "lower_bound": "0",
        "upper_bound": "0",
    }


def _validate_single_predicate(
    pred: object,
    *,
    index: int,
    num_attributes: int,
) -> dict[str, Any]:
    prefix = f"predicates[{index}]"
    if not isinstance(pred, Mapping):
        raise DisclosureWitnessError("malformed_predicate", prefix)

    raw_type = (
        pred["predicate_type"]
        if "predicate_type" in pred
        else pred.get("predicateType")
    )
    pred_code = encode_predicate_type(raw_type, field=f"{prefix}.predicate_type")

    raw_attr_idx = (
        pred["attr_index"] if "attr_index" in pred else pred.get("attrIndex")
    )
    attr_idx = _require_non_bool_int(
        raw_attr_idx,
        code="malformed_attr_index",
        field=f"{prefix}.attr_index",
    )
    if attr_idx < 0 or attr_idx >= num_attributes:
        raise DisclosureWitnessError(
            "predicate_attr_out_of_range", f"{prefix}.attr_index"
        )

    raw_pub = (
        pred["public_value"]
        if "public_value" in pred
        else pred.get("publicValue", 0)
    )
    pub_dec = _encode_field_decimal(
        0 if raw_pub is None else raw_pub,
        field=f"{prefix}.public_value",
    )

    raw_set_vals = (
        pred["set_values"]
        if "set_values" in pred
        else pred.get("setValues", ())
    )
    if raw_set_vals is None:
        raw_set_vals = ()
    if not _is_bounded_sequence(raw_set_vals):
        raise DisclosureWitnessError(
            "malformed_set_values", f"{prefix}.set_values"
        )
    assert isinstance(raw_set_vals, Sequence)

    # Reject oversized set_values BEFORE allocating or encoding elements.
    if len(raw_set_vals) > MAX_SET_MEMBERS:
        raise DisclosureWitnessError(
            "set_members_oversize", f"{prefix}.set_values"
        )

    raw_set_len = (
        pred["set_len"] if "set_len" in pred else pred.get("setLen")
    )
    if raw_set_len is None:
        set_len = (
            len(raw_set_vals)
            if pred_code == PREDICATE_TYPE_SET_MEMBERSHIP
            else 0
        )
    else:
        set_len = _require_non_bool_int(
            raw_set_len,
            code="malformed_set_len",
            field=f"{prefix}.set_len",
        )

    if set_len < 0:
        raise DisclosureWitnessError(
            "set_members_undersize", f"{prefix}.set_len"
        )
    if set_len > MAX_SET_MEMBERS:
        raise DisclosureWitnessError(
            "set_members_oversize", f"{prefix}.set_len"
        )

    if pred_code == PREDICATE_TYPE_SET_MEMBERSHIP:
        if set_len < MIN_SET_MEMBERS:
            raise DisclosureWitnessError(
                "set_members_undersize", f"{prefix}.set_len"
            )
        if len(raw_set_vals) < set_len:
            raise DisclosureWitnessError(
                "set_length_mismatch", f"{prefix}.set_values"
            )
    elif set_len > len(raw_set_vals) and len(raw_set_vals) > 0:
        raise DisclosureWitnessError(
            "set_length_mismatch", f"{prefix}.set_values"
        )

    encoded_set_vals = [
        _encode_field_decimal(val, field=f"{prefix}.set_values[{j}]")
        for j, val in enumerate(raw_set_vals)
    ]
    if len(encoded_set_vals) < MAX_SET_MEMBERS:
        encoded_set_vals.extend(["0"] * (MAX_SET_MEMBERS - len(encoded_set_vals)))

    raw_lower = (
        pred["lower_bound"]
        if "lower_bound" in pred
        else pred.get("lowerBound", 0)
    )
    raw_upper = (
        pred["upper_bound"]
        if "upper_bound" in pred
        else pred.get("upperBound", 0)
    )
    lower_dec = _encode_field_decimal(
        0 if raw_lower is None else raw_lower,
        field=f"{prefix}.lower_bound",
    )
    upper_dec = _encode_field_decimal(
        0 if raw_upper is None else raw_upper,
        field=f"{prefix}.upper_bound",
    )

    return {
        "predicate_type": str(pred_code),
        "attr_index": str(attr_idx),
        "public_value": pub_dec,
        "set_values": encoded_set_vals,
        "set_len": str(set_len),
        "lower_bound": lower_dec,
        "upper_bound": upper_dec,
    }


def prepare_disclosure_witness(
    *,
    attr_values: object,
    attr_blindings: object,
    predicates: object,
    num_attributes: object = None,
    num_predicates: object = None,
) -> dict[str, Any]:
    """Validate bounds before allocation and return canonical padded Noir witness inputs.

    Preserves the caller's exact predicate sequence at ``predicates[0..num_predicates]``
    and canonical predicate type codes (`0`, `1`, `2`), padding inactive trailing
    slots up to ``MAX_PREDICATES = 8``.
    """
    # 1. Bound predicate list size FIRST before any array allocation or hashing.
    if not _is_bounded_sequence(predicates):
        raise DisclosureWitnessError("malformed_predicates", "predicates")
    assert isinstance(predicates, Sequence)

    pred_list_len = len(predicates)
    if pred_list_len > MAX_PREDICATES:
        raise DisclosureWitnessError("predicates_oversize", "predicates")

    if num_predicates is None:
        resolved_num_preds = pred_list_len
    else:
        resolved_num_preds = check_disclosure_predicate_count(
            num_predicates, field="num_predicates"
        )
        if resolved_num_preds != pred_list_len:
            raise DisclosureWitnessError(
                "predicate_count_mismatch", "num_predicates"
            )

    # 2. Bound attribute and blinding list sizes BEFORE allocating [Field; 16].
    if not _is_bounded_sequence(attr_values):
        raise DisclosureWitnessError("malformed_attr_values", "attr_values")
    if not _is_bounded_sequence(attr_blindings):
        raise DisclosureWitnessError(
            "malformed_attr_blindings", "attr_blindings"
        )
    assert isinstance(attr_values, Sequence)
    assert isinstance(attr_blindings, Sequence)

    if len(attr_values) > MAX_ATTRIBUTES:
        raise DisclosureWitnessError("attributes_oversize", "attr_values")
    if len(attr_blindings) > MAX_ATTRIBUTES:
        raise DisclosureWitnessError("attributes_oversize", "attr_blindings")

    if num_attributes is None:
        resolved_num_attrs = check_disclosure_attribute_count(
            len(attr_values), field="attr_values"
        )
    else:
        resolved_num_attrs = check_disclosure_attribute_count(
            num_attributes, field="num_attributes"
        )

    if len(attr_values) < resolved_num_attrs:
        raise DisclosureWitnessError("attribute_count_mismatch", "attr_values")
    if len(attr_blindings) < resolved_num_attrs or len(attr_blindings) != len(
        attr_values
    ):
        raise DisclosureWitnessError(
            "attribute_count_mismatch", "attr_blindings"
        )

    # 3. Validate each active predicate in caller order before padding.
    prepared_active = [
        _validate_single_predicate(
            predicates[idx], index=idx, num_attributes=resolved_num_attrs
        )
        for idx in range(resolved_num_preds)
    ]

    encoded_attrs = [
        _encode_field_decimal(v, field=f"attr_values[{idx}]")
        for idx, v in enumerate(attr_values)
    ]
    encoded_blindings = [
        _encode_field_decimal(b, field=f"attr_blindings[{idx}]")
        for idx, b in enumerate(attr_blindings)
    ]

    # 4. Allocate fixed-length padded arrays only after all bounds succeed.
    if len(encoded_attrs) < MAX_ATTRIBUTES:
        encoded_attrs.extend(["0"] * (MAX_ATTRIBUTES - len(encoded_attrs)))
    if len(encoded_blindings) < MAX_ATTRIBUTES:
        encoded_blindings.extend(
            ["0"] * (MAX_ATTRIBUTES - len(encoded_blindings))
        )

    padded_predicates = list(prepared_active)
    while len(padded_predicates) < MAX_PREDICATES:
        padded_predicates.append(_zero_padded_predicate())

    return {
        "num_attributes": str(resolved_num_attrs),
        "attr_values": encoded_attrs,
        "attr_blindings": encoded_blindings,
        "num_predicates": str(resolved_num_preds),
        "predicates": padded_predicates,
    }


def prepare_disclosure_witness_from_mapping(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Prepare witness inputs from a camelCase or snake_case input mapping."""
    if not isinstance(payload, Mapping):
        raise DisclosureWitnessError("malformed_input", "witness")

    attr_values = (
        payload["attr_values"]
        if "attr_values" in payload
        else payload.get("attrValues")
    )
    attr_blindings = (
        payload["attr_blindings"]
        if "attr_blindings" in payload
        else payload.get("attrBlindings")
    )
    predicates = payload.get("predicates")
    num_attributes = (
        payload["num_attributes"]
        if "num_attributes" in payload
        else payload.get("numAttributes")
    )
    num_predicates = (
        payload["num_predicates"]
        if "num_predicates" in payload
        else payload.get("numPredicates")
    )
    return prepare_disclosure_witness(
        attr_values=attr_values,
        attr_blindings=attr_blindings,
        predicates=predicates,
        num_attributes=num_attributes,
        num_predicates=num_predicates,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate selective-disclosure predicate and attribute bounds "
            "before witness allocation and proving."
        )
    )
    parser.add_argument(
        "input_json",
        type=Path,
        help="Path to selective-disclosure witness request JSON.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if not args.input_json.is_file():
            raise DisclosureWitnessError("missing_file", "input_json")
        if args.input_json.stat().st_size > MAX_WITNESS_JSON_BYTES:
            raise DisclosureWitnessError("oversized_input", "input_json")
        raw = args.input_json.read_bytes()
        if len(raw) > MAX_WITNESS_JSON_BYTES:
            raise DisclosureWitnessError("oversized_input", "input_json")
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DisclosureWitnessError("malformed_json", "input_json") from exc
        if not isinstance(parsed, Mapping):
            raise DisclosureWitnessError("malformed_json", "input_json")
        prepared = prepare_disclosure_witness_from_mapping(parsed)
    except OSError:
        err = DisclosureWitnessError("missing_file", "input_json")
        print(
            json.dumps(err.signal(), sort_keys=True, separators=(",", ":")),
            file=sys.stderr,
        )
        return EXIT_USAGE
    except DisclosureWitnessError as err:
        print(
            json.dumps(err.signal(), sort_keys=True, separators=(",", ":")),
            file=sys.stderr,
        )
        return EXIT_REJECTED

    print(
        json.dumps(
            {
                "ok": True,
                "num_attributes": int(prepared["num_attributes"]),
                "num_predicates": int(prepared["num_predicates"]),
                "padded_predicate_slots": len(prepared["predicates"]),
            },
            sort_keys=True,
        )
    )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
