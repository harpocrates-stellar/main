#!/usr/bin/env python3
"""Canonical interval-intersection predicates and synthetic vectors for selective disclosure.

Implements issuer-certified interval conjunction predicates (`predicate_type == 3`)
for ``zk/noir/selective_disclosure/src/main.nr`` without revealing certified
attribute values in public statements, commitments, or diagnostic errors.

Canonical conjunction rule
--------------------------
Given ``1 <= m <= MAX_INTERVAL_CLAUSES`` (``4``) constituent intervals
``I_j = (lo_j, hi_j, lower_inclusive_j, upper_inclusive_j)`` over ``u64``
attribute values (``0 <= lo_j, hi_j <= 2^64 - 1``):

* ``L* = max_j lo_j``
* ``lower_inclusive* = all(lower_inclusive_j for j where lo_j == L*)``
* ``U* = min_j hi_j``
* ``upper_inclusive* = all(upper_inclusive_j for j where hi_j == U*)``

The reduced canonical interval ``(L*, U*, lower_inclusive*, upper_inclusive*)``
is order-independent and packed injectively into ``Predicate.public_value`` as::

    canonical_flags = (1 if lower_inclusive* else 0) + (2 if upper_inclusive* else 0)
    public_value    = L* + (U* << 64) + (canonical_flags << 128)

Because ``public_value < 2^130 < p_BN254``, the packing is collision-free in the
BN254 scalar field and binds the canonical conjunction directly into
``predicate_commitment`` without exposing ``attr_values`` or requiring extra
in-circuit Pedersen hashes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FIXTURE_PATH = (
    REPO_ROOT / "zk" / "noir" / "fixtures" / "selective_disclosure_interval_vectors.json"
)

BN254_SCALAR_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)

MAX_ATTRIBUTES = 16
MAX_PREDICATES = 8
MAX_SET_MEMBERS = 8
MAX_INTERVAL_CLAUSES = 4
CURRENT_CIRCUIT_VERSION = 1

EQ_PREDICATE_TYPE = 0
SET_MEMBERSHIP_PREDICATE_TYPE = 1
RANGE_PREDICATE_TYPE = 2
INTERVAL_INTERSECTION_PREDICATE_TYPE = 3

U64_MAX = (1 << 64) - 1
TWO_POW_64 = 1 << 64
TWO_POW_128 = 1 << 128

PUBLIC_INPUT_FIELD_ORDER: tuple[str, ...] = (
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
)

DEMO_SCHEMA_HASH = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
DEMO_ISSUER_NAMESPACE = 0x1111111111111111111111111111111111111111111111111111111111111111
DEMO_SCHEMA_VERSION = 1
DEMO_VIDEO_HASH_HI = 1234
DEMO_VIDEO_HASH_LO = 5678
DEMO_VERIFIER_DIGEST = 42
DEMO_EVIDENCE_DIGEST = 9999

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_USAGE = 2


class IntervalPredicateError(ValueError):
    """Privacy-safe error raised during interval predicate preparation."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _require_non_bool_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise IntervalPredicateError(
            "invalid_integer",
            f"{label} must be an integer",
        )
    return value


def _require_u64(value: Any, label: str) -> int:
    parsed = _require_non_bool_int(value, label)
    if parsed < 0 or parsed > U64_MAX:
        raise IntervalPredicateError(
            "bound_out_of_u64_range",
            f"{label} must be within [0, 2^64 - 1]",
        )
    return parsed


def _require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise IntervalPredicateError(
            "invalid_boolean",
            f"{label} must be a boolean",
        )
    return value


def format_interval_notation(
    lower: int,
    upper: int,
    lower_inclusive: bool,
    upper_inclusive: bool,
) -> str:
    left = "[" if lower_inclusive else "("
    right = "]" if upper_inclusive else ")"
    return f"{left}{lower}, {upper}{right}"


@dataclass(frozen=True)
class IntervalClause:
    """Single inclusive/exclusive u64 interval bound certified by an issuer or policy."""

    lower: int
    upper: int
    lower_inclusive: bool = True
    upper_inclusive: bool = True

    def __post_init__(self) -> None:
        _require_u64(self.lower, "clause.lower")
        _require_u64(self.upper, "clause.upper")
        _require_bool(self.lower_inclusive, "clause.lower_inclusive")
        _require_bool(self.upper_inclusive, "clause.upper_inclusive")

    @property
    def notation(self) -> str:
        return format_interval_notation(
            self.lower,
            self.upper,
            self.lower_inclusive,
            self.upper_inclusive,
        )

    def contains(self, value: int) -> bool:
        checked = _require_u64(value, "candidate_value")
        lo_ok = checked > self.lower or (self.lower_inclusive and checked == self.lower)
        hi_ok = checked < self.upper or (self.upper_inclusive and checked == self.upper)
        return lo_ok and hi_ok

    def to_dict(self) -> dict[str, Any]:
        return {
            "lower": self.lower,
            "upper": self.upper,
            "lower_inclusive": self.lower_inclusive,
            "upper_inclusive": self.upper_inclusive,
            "notation": self.notation,
        }


@dataclass(frozen=True)
class CanonicalIntervalConjunction:
    """Canonical order-independent conjunction of 1..=MAX_INTERVAL_CLAUSES intervals."""

    lower: int
    upper: int
    lower_inclusive: bool
    upper_inclusive: bool
    canonical_flags: int
    packed_public_value: int
    is_empty: bool
    min_valid_u64: int | None
    max_valid_u64: int | None

    @property
    def notation(self) -> str:
        return format_interval_notation(
            self.lower,
            self.upper,
            self.lower_inclusive,
            self.upper_inclusive,
        )

    def contains(self, value: int) -> bool:
        checked = _require_u64(value, "candidate_value")
        if self.is_empty or self.min_valid_u64 is None or self.max_valid_u64 is None:
            return False
        return self.min_valid_u64 <= checked <= self.max_valid_u64

    def to_dict(self) -> dict[str, Any]:
        return {
            "lower": self.lower,
            "upper": self.upper,
            "lower_inclusive": self.lower_inclusive,
            "upper_inclusive": self.upper_inclusive,
            "notation": self.notation,
            "canonical_flags": self.canonical_flags,
            "packed_public_value_dec": str(self.packed_public_value),
            "packed_public_value_hex": hex(self.packed_public_value),
            "is_empty": self.is_empty,
            "min_valid_u64": self.min_valid_u64,
            "max_valid_u64": self.max_valid_u64,
        }


def pack_canonical_interval_conjunction(
    lower: int,
    upper: int,
    lower_inclusive: bool,
    upper_inclusive: bool,
) -> int:
    """Pack canonical conjunction bounds and endpoint inclusivity into one BN254 Field."""
    checked_lo = _require_u64(lower, "lower")
    checked_hi = _require_u64(upper, "upper")
    checked_lo_inc = _require_bool(lower_inclusive, "lower_inclusive")
    checked_hi_inc = _require_bool(upper_inclusive, "upper_inclusive")
    canonical_flags = (1 if checked_lo_inc else 0) + (2 if checked_hi_inc else 0)
    packed = checked_lo + checked_hi * TWO_POW_64 + canonical_flags * TWO_POW_128
    if packed >= BN254_SCALAR_MODULUS:
        raise IntervalPredicateError(
            "field_overflow",
            "packed canonical interval exceeds BN254 scalar modulus",
        )
    return packed


def unpack_canonical_interval_conjunction(packed: int) -> tuple[int, int, bool, bool]:
    """Invert ``pack_canonical_interval_conjunction`` and reject non-canonical bits."""
    checked = _require_non_bool_int(packed, "packed_public_value")
    if checked < 0 or checked >= 4 * TWO_POW_128:
        raise IntervalPredicateError(
            "invalid_packed_interval",
            "packed canonical interval exceeds 130-bit domain",
        )
    lower = checked & U64_MAX
    upper = (checked >> 64) & U64_MAX
    flags = checked >> 128
    lower_inclusive = (flags & 1) != 0
    upper_inclusive = (flags & 2) != 0
    return lower, upper, lower_inclusive, upper_inclusive


def reduce_interval_conjunction(
    clauses: Sequence[IntervalClause],
) -> CanonicalIntervalConjunction:
    """Compute the canonical conjunction of 1..=MAX_INTERVAL_CLAUSES interval clauses."""
    clause_count = len(clauses)
    if clause_count < 1:
        raise IntervalPredicateError(
            "empty_clause_list",
            "interval intersection predicate requires at least 1 clause",
        )
    if clause_count > MAX_INTERVAL_CLAUSES:
        raise IntervalPredicateError(
            "oversized_clause_list",
            f"interval intersection predicate supports at most {MAX_INTERVAL_CLAUSES} clauses",
        )

    eff_lo = clauses[0].lower
    eff_inc_lo = clauses[0].lower_inclusive
    eff_hi = clauses[0].upper
    eff_inc_hi = clauses[0].upper_inclusive

    for clause in clauses[1:]:
        if clause.lower > eff_lo:
            eff_lo = clause.lower
            eff_inc_lo = clause.lower_inclusive
        elif clause.lower == eff_lo:
            eff_inc_lo = eff_inc_lo and clause.lower_inclusive

        if clause.upper < eff_hi:
            eff_hi = clause.upper
            eff_inc_hi = clause.upper_inclusive
        elif clause.upper == eff_hi:
            eff_inc_hi = eff_inc_hi and clause.upper_inclusive

    canonical_flags = (1 if eff_inc_lo else 0) + (2 if eff_inc_hi else 0)
    packed = pack_canonical_interval_conjunction(
        eff_lo,
        eff_hi,
        eff_inc_lo,
        eff_inc_hi,
    )

    lo_overflow = (not eff_inc_lo) and eff_lo == U64_MAX
    hi_underflow = (not eff_inc_hi) and eff_hi == 0
    min_candidate = eff_lo if eff_inc_lo else (eff_lo + 1 if eff_lo < U64_MAX else eff_lo)
    max_candidate = eff_hi if eff_inc_hi else (eff_hi - 1 if eff_hi > 0 else 0)
    non_empty = (not lo_overflow) and (not hi_underflow) and (min_candidate <= max_candidate)

    return CanonicalIntervalConjunction(
        lower=eff_lo,
        upper=eff_hi,
        lower_inclusive=eff_inc_lo,
        upper_inclusive=eff_inc_hi,
        canonical_flags=canonical_flags,
        packed_public_value=packed,
        is_empty=not non_empty,
        min_valid_u64=min_candidate if non_empty else None,
        max_valid_u64=max_candidate if non_empty else None,
    )


def encode_clause_inclusivity_mask(clauses: Sequence[IntervalClause]) -> int:
    """Encode per-clause inclusivity flags in bits ``0..2*len(clauses)-1``."""
    mask = 0
    for idx, clause in enumerate(clauses):
        if clause.lower_inclusive:
            mask |= 1 << (2 * idx)
        if clause.upper_inclusive:
            mask |= 1 << (2 * idx + 1)
    return mask


def encode_interval_predicate(
    attr_index: int,
    clauses: Sequence[IntervalClause],
    *,
    require_non_empty: bool = True,
) -> dict[str, Any]:
    """Encode an ``IntervalIntersection`` Noir ``Predicate`` witness entry.

    Never accepts or inspects secret attribute values, guaranteeing witness
    encoding errors cannot leak certified values.
    """
    checked_attr = _require_non_bool_int(attr_index, "attr_index")
    if checked_attr < 0 or checked_attr >= MAX_ATTRIBUTES:
        raise IntervalPredicateError(
            "attr_index_out_of_bounds",
            f"attr_index must be in [0, {MAX_ATTRIBUTES - 1}]",
        )

    conjunction = reduce_interval_conjunction(clauses)
    if require_non_empty and conjunction.is_empty:
        raise IntervalPredicateError(
            "empty_interval_intersection",
            f"interval conjunction {conjunction.notation} has an empty u64 intersection",
        )

    set_values = [0] * MAX_SET_MEMBERS
    for idx, clause in enumerate(clauses):
        set_values[2 * idx] = clause.lower
        set_values[2 * idx + 1] = clause.upper

    clause_mask = encode_clause_inclusivity_mask(clauses)
    packed_set_len = len(clauses) | (clause_mask << 8)

    return {
        "predicate_type": str(INTERVAL_INTERSECTION_PREDICATE_TYPE),
        "attr_index": checked_attr,
        "public_value": str(conjunction.packed_public_value),
        "set_values": [str(v) for v in set_values],
        "set_len": packed_set_len,
        "lower_bound": str(conjunction.lower),
        "upper_bound": str(conjunction.upper),
    }


def _reference_field_hash(domain: bytes, fields: Sequence[int]) -> int:
    """Deterministic BN254-field commitment model for toolchain-free CI vectors.

    Real UltraHonk proofs use ``std::hash::pedersen_hash`` inside Noir/Barretenberg.
    For offline Python conformance vectors, this collision-resistant SHA-256 -> Fr
    compression preserves identical binding dependencies:
    - ``credential_root`` depends on ``(attr_values, attr_blindings, num_attributes)``
    - ``predicate_commitment`` depends ONLY on ``(predicate_type, attr_index, public_value)``
    - ``nullifier`` depends on ``(credential_root, video_hash_hi, video_hash_lo, evidence_digest)``
    """
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(len(fields).to_bytes(4, "big"))
    for field_val in fields:
        normalized = field_val % BN254_SCALAR_MODULUS
        digest.update(normalized.to_bytes(32, "big"))
    raw = int.from_bytes(digest.digest(), "big")
    reduced = raw % (BN254_SCALAR_MODULUS - 1) + 1
    return reduced


def compute_reference_credential_root(
    attr_values: Sequence[int],
    attr_blindings: Sequence[int],
    num_attributes: int,
) -> int:
    commitments = [
        _reference_field_hash(b"HP_SD_ATTR_COMMIT_V1", (attr_values[i], attr_blindings[i]))
        for i in range(MAX_ATTRIBUTES)
    ]
    current = commitments[0]
    for i in range(1, MAX_ATTRIBUTES):
        nxt = _reference_field_hash(b"HP_SD_CRED_ROOT_V1", (current, commitments[i]))
        if i < num_attributes:
            current = nxt
    return current


def compute_reference_predicate_commitment(
    predicates: Sequence[dict[str, Any]],
    num_predicates: int,
) -> int:
    current = 0
    for i in range(MAX_PREDICATES):
        pred = predicates[i]
        nxt = _reference_field_hash(
            b"HP_SD_PRED_COMMIT_V1",
            (
                current,
                int(pred["predicate_type"]),
                int(pred["attr_index"]),
                int(pred["public_value"]),
            ),
        )
        if i < num_predicates:
            current = nxt
    return current


def compute_reference_nullifier(
    credential_root: int,
    video_hash_hi: int,
    video_hash_lo: int,
    evidence_digest: int,
) -> int:
    return _reference_field_hash(
        b"HP_SD_NULLIFIER_V1",
        (credential_root, video_hash_hi, video_hash_lo, evidence_digest),
    )


def encode_public_statement_wire_hex(statement: dict[str, int]) -> str:
    """Serialize the 11 public Field inputs in canonical 352-byte big-endian order."""
    chunks: list[bytes] = []
    for name in PUBLIC_INPUT_FIELD_ORDER:
        val = statement[name]
        if val < 0 or val >= BN254_SCALAR_MODULUS:
            raise IntervalPredicateError(
                "public_input_out_of_field",
                f"{name} exceeds BN254 scalar field modulus",
            )
        chunks.append(val.to_bytes(32, "big"))
    return b"".join(chunks).hex()


def _default_padding_predicate() -> dict[str, Any]:
    return {
        "predicate_type": "0",
        "attr_index": 0,
        "public_value": "0",
        "set_values": ["0"] * MAX_SET_MEMBERS,
        "set_len": 0,
        "lower_bound": "0",
        "upper_bound": "0",
    }


def build_public_statement_preview(
    *,
    attr_values: Sequence[int],
    attr_blindings: Sequence[int],
    num_attributes: int,
    active_predicates: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    """Derive a public selective-disclosure statement without embedding witness secrets."""
    padded_attrs = list(attr_values) + [0] * (MAX_ATTRIBUTES - len(attr_values))
    padded_blindings = list(attr_blindings) + [0] * (MAX_ATTRIBUTES - len(attr_blindings))
    padded_preds = list(active_predicates) + [
        _default_padding_predicate()
        for _ in range(MAX_PREDICATES - len(active_predicates))
    ]

    credential_root = compute_reference_credential_root(
        padded_attrs,
        padded_blindings,
        num_attributes,
    )
    predicate_commitment = compute_reference_predicate_commitment(
        padded_preds,
        len(active_predicates),
    )
    nullifier = compute_reference_nullifier(
        credential_root,
        DEMO_VIDEO_HASH_HI,
        DEMO_VIDEO_HASH_LO,
        DEMO_EVIDENCE_DIGEST,
    )

    numeric_statement = {
        "schema_hash": DEMO_SCHEMA_HASH,
        "issuer_namespace": DEMO_ISSUER_NAMESPACE,
        "schema_version": DEMO_SCHEMA_VERSION,
        "credential_root": credential_root,
        "nullifier": nullifier,
        "video_hash_hi": DEMO_VIDEO_HASH_HI,
        "video_hash_lo": DEMO_VIDEO_HASH_LO,
        "verifier_digest": DEMO_VERIFIER_DIGEST,
        "circuit_version": CURRENT_CIRCUIT_VERSION,
        "evidence_digest": DEMO_EVIDENCE_DIGEST,
        "predicate_commitment": predicate_commitment,
    }
    return {
        "fields_hex": {k: f"0x{v:064x}" for k, v in numeric_statement.items()},
        "wire_public_inputs_hex": encode_public_statement_wire_hex(numeric_statement),
    }


def evaluate_selective_disclosure_circuit(
    *,
    circuit_version: int,
    verifier_digest: int,
    credential_root: int,
    nullifier: int,
    predicate_commitment: int,
    num_attributes: int,
    attr_values: Sequence[int],
    attr_blindings: Sequence[int],
    num_predicates: int,
    predicates: Sequence[dict[str, Any]],
    video_hash_hi: int = DEMO_VIDEO_HASH_HI,
    video_hash_lo: int = DEMO_VIDEO_HASH_LO,
    evidence_digest: int = DEMO_EVIDENCE_DIGEST,
) -> tuple[bool, str | None]:
    """Mirror the assertion order and exact failure codes of ``selective_disclosure/src/main.nr``."""
    valid_types = {
        EQ_PREDICATE_TYPE,
        SET_MEMBERSHIP_PREDICATE_TYPE,
        RANGE_PREDICATE_TYPE,
        INTERVAL_INTERSECTION_PREDICATE_TYPE,
    }
    for i in range(MAX_PREDICATES):
        is_active = i < num_predicates
        pred_type = int(predicates[i]["predicate_type"])
        if is_active and pred_type not in valid_types:
            return False, "unsupported predicate type"

    if circuit_version != CURRENT_CIRCUIT_VERSION:
        return False, "circuit version mismatch"

    if num_attributes <= 0:
        return False, "malformed"
    if num_attributes > MAX_ATTRIBUTES:
        return False, "oversized"
    if num_predicates > MAX_PREDICATES:
        return False, "oversized"

    for i in range(MAX_PREDICATES):
        is_active = i < num_predicates
        pred = predicates[i]
        attr_idx = int(pred["attr_index"])
        pred_type = int(pred["predicate_type"])
        set_len = int(pred["set_len"])

        if is_active and (attr_idx < 0 or attr_idx >= num_attributes):
            return False, "malformed"

        if is_active and pred_type == SET_MEMBERSHIP_PREDICATE_TYPE:
            if set_len <= 0:
                return False, "malformed"
            if set_len > MAX_SET_MEMBERS:
                return False, "oversized"

        if is_active and pred_type == INTERVAL_INTERSECTION_PREDICATE_TYPE:
            num_clauses = set_len & 255
            if num_clauses <= 0:
                return False, "malformed"
            if num_clauses > MAX_INTERVAL_CLAUSES:
                return False, "oversized"

    derived_root = compute_reference_credential_root(
        attr_values,
        attr_blindings,
        num_attributes,
    )
    if derived_root != credential_root:
        return False, "malformed"

    for i in range(MAX_PREDICATES):
        pred = predicates[i]
        is_active = i < num_predicates
        if not is_active:
            continue

        pred_type = int(pred["predicate_type"])
        attr_idx = int(pred["attr_index"])
        attr_val = attr_values[attr_idx]
        pub_val = int(pred["public_value"])
        set_vals = [int(v) for v in pred["set_values"]]
        set_len = int(pred["set_len"])
        lo_bound = int(pred["lower_bound"])
        hi_bound = int(pred["upper_bound"])

        if pred_type == EQ_PREDICATE_TYPE and attr_val != pub_val:
            return False, "malformed"

        if pred_type == SET_MEMBERSHIP_PREDICATE_TYPE and not any(
            set_vals[j] == attr_val for j in range(set_len)
        ):
            return False, "malformed"

        if pred_type in (RANGE_PREDICATE_TYPE, INTERVAL_INTERSECTION_PREDICATE_TYPE):
            if not (0 <= attr_val <= U64_MAX):
                return False, "malformed"
            if not (0 <= lo_bound <= U64_MAX):
                return False, "malformed"
            if not (0 <= hi_bound <= U64_MAX):
                return False, "malformed"

        if pred_type == RANGE_PREDICATE_TYPE and (
            attr_val < lo_bound or attr_val > hi_bound
        ):
            return False, "malformed"

        if pred_type == INTERVAL_INTERSECTION_PREDICATE_TYPE:
            num_clauses = set_len & 255
            clause_mask = set_len >> 8
            if num_clauses < 1:
                return False, "malformed"
            if num_clauses > MAX_INTERVAL_CLAUSES:
                return False, "oversized"
            if clause_mask >= 256:
                return False, "malformed"

            inc_flags = [((clause_mask >> bit) & 1) != 0 for bit in range(8)]
            clause_los = [0] * MAX_INTERVAL_CLAUSES
            clause_his = [0] * MAX_INTERVAL_CLAUSES

            for j in range(MAX_INTERVAL_CLAUSES):
                if j >= num_clauses:
                    if inc_flags[2 * j] or inc_flags[2 * j + 1]:
                        return False, "malformed"
                    if set_vals[2 * j] != 0 or set_vals[2 * j + 1] != 0:
                        return False, "malformed"
                else:
                    raw_lo = set_vals[2 * j]
                    raw_hi = set_vals[2 * j + 1]
                    if not (0 <= raw_lo <= U64_MAX) or not (0 <= raw_hi <= U64_MAX):
                        return False, "malformed"
                    clause_los[j] = raw_lo
                    clause_his[j] = raw_hi

            eff_lo = clause_los[0]
            eff_inc_lo = inc_flags[0]
            eff_hi = clause_his[0]
            eff_inc_hi = inc_flags[1]

            for j in range(1, num_clauses):
                c_lo = clause_los[j]
                c_inc_lo = inc_flags[2 * j]
                c_hi = clause_his[j]
                c_inc_hi = inc_flags[2 * j + 1]

                if c_lo > eff_lo:
                    eff_lo = c_lo
                    eff_inc_lo = c_inc_lo
                elif c_lo == eff_lo:
                    eff_inc_lo = eff_inc_lo and c_inc_lo

                if c_hi < eff_hi:
                    eff_hi = c_hi
                    eff_inc_hi = c_inc_hi
                elif c_hi == eff_hi:
                    eff_inc_hi = eff_inc_hi and c_inc_hi

            expected_packed = pack_canonical_interval_conjunction(
                eff_lo,
                eff_hi,
                eff_inc_lo,
                eff_inc_hi,
            )
            if eff_lo != lo_bound or eff_hi != hi_bound or pub_val != expected_packed:
                return False, "non-canonical interval bounds"

            lo_overflow = (not eff_inc_lo) and eff_lo == U64_MAX
            hi_underflow = (not eff_inc_hi) and eff_hi == 0
            min_valid = eff_lo if eff_inc_lo else (eff_lo + 1 if eff_lo < U64_MAX else eff_lo)
            max_valid = eff_hi if eff_inc_hi else (eff_hi - 1 if eff_hi > 0 else 0)
            if lo_overflow or hi_underflow or min_valid > max_valid:
                return False, "empty interval intersection"

            if attr_val < min_valid or attr_val > max_valid:
                return False, "interval bound unsatisfied"

            for j in range(num_clauses):
                lo_ok = attr_val > clause_los[j] or (
                    inc_flags[2 * j] and attr_val == clause_los[j]
                )
                hi_ok = attr_val < clause_his[j] or (
                    inc_flags[2 * j + 1] and attr_val == clause_his[j]
                )
                if not (lo_ok and hi_ok):
                    return False, "interval bound unsatisfied"

    derived_pred_commitment = compute_reference_predicate_commitment(
        predicates,
        num_predicates,
    )
    if derived_pred_commitment != predicate_commitment:
        return False, "predicate commitment mismatch"

    derived_nullifier = compute_reference_nullifier(
        credential_root,
        video_hash_hi,
        video_hash_lo,
        evidence_digest,
    )
    if derived_nullifier != nullifier:
        return False, "malformed"

    if verifier_digest == 0:
        return False, "malformed"

    return True, None


def _build_positive_case(
    *,
    case_id: str,
    description: str,
    clauses: Sequence[IntervalClause],
    synthetic_certified_value: int,
    synthetic_attr_blinding: int,
    secondary_attr_value: int = 12345678,
    secondary_attr_blinding: int = 222222,
) -> dict[str, Any]:
    conjunction = reduce_interval_conjunction(clauses)
    encoded_pred = encode_interval_predicate(0, clauses, require_non_empty=True)

    attr_values = [synthetic_certified_value, secondary_attr_value] + [0] * 14
    attr_blindings = [synthetic_attr_blinding, secondary_attr_blinding] + [0] * 14
    public_preview = build_public_statement_preview(
        attr_values=attr_values,
        attr_blindings=attr_blindings,
        num_attributes=2,
        active_predicates=[encoded_pred],
    )

    padded_preds = [encoded_pred] + [
        _default_padding_predicate() for _ in range(MAX_PREDICATES - 1)
    ]
    ok, err = evaluate_selective_disclosure_circuit(
        circuit_version=CURRENT_CIRCUIT_VERSION,
        verifier_digest=DEMO_VERIFIER_DIGEST,
        credential_root=int(public_preview["fields_hex"]["credential_root"], 16),
        nullifier=int(public_preview["fields_hex"]["nullifier"], 16),
        predicate_commitment=int(
            public_preview["fields_hex"]["predicate_commitment"], 16
        ),
        num_attributes=2,
        attr_values=attr_values,
        attr_blindings=attr_blindings,
        num_predicates=1,
        predicates=padded_preds,
    )
    if not ok:
        raise IntervalPredicateError(
            "invalid_positive_vector",
            f"positive vector {case_id} failed self-check with {err!r}",
        )

    return {
        "id": case_id,
        "description": description,
        "attr_index": 0,
        "clauses": [c.to_dict() for c in clauses],
        "canonical_conjunction": conjunction.to_dict(),
        "encoded_predicate": encoded_pred,
        "public_statement": public_preview,
        "prover_only_synthetic_opening": {
            "certified_attr_value": synthetic_certified_value,
            "certified_attr_blinding": synthetic_attr_blinding,
            "secondary_attr_value": secondary_attr_value,
            "secondary_attr_blinding": secondary_attr_blinding,
        },
        "expect": "pass",
    }


def _build_negative_case(
    *,
    case_id: str,
    description: str,
    clauses: Sequence[IntervalClause],
    synthetic_certified_value: int,
    synthetic_attr_blinding: int,
    expect_fail_with: str,
    predicate_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if clauses:
        conjunction_dict: dict[str, Any] | None = reduce_interval_conjunction(
            clauses
        ).to_dict()
        encoded_pred = encode_interval_predicate(0, clauses, require_non_empty=False)
    else:
        conjunction_dict = None
        encoded_pred = {
            "predicate_type": str(INTERVAL_INTERSECTION_PREDICATE_TYPE),
            "attr_index": 0,
            "public_value": "0",
            "set_values": ["0"] * MAX_SET_MEMBERS,
            "set_len": 0,
            "lower_bound": "0",
            "upper_bound": "0",
        }

    if predicate_overrides:
        encoded_pred = {**encoded_pred, **predicate_overrides}

    attr_values = [synthetic_certified_value, 12345678] + [0] * 14
    attr_blindings = [synthetic_attr_blinding, 222222] + [0] * 14
    public_preview = build_public_statement_preview(
        attr_values=attr_values,
        attr_blindings=attr_blindings,
        num_attributes=2,
        active_predicates=[encoded_pred],
    )

    padded_preds = [encoded_pred] + [
        _default_padding_predicate() for _ in range(MAX_PREDICATES - 1)
    ]
    ok, err = evaluate_selective_disclosure_circuit(
        circuit_version=CURRENT_CIRCUIT_VERSION,
        verifier_digest=DEMO_VERIFIER_DIGEST,
        credential_root=int(public_preview["fields_hex"]["credential_root"], 16),
        nullifier=int(public_preview["fields_hex"]["nullifier"], 16),
        predicate_commitment=int(
            public_preview["fields_hex"]["predicate_commitment"], 16
        ),
        num_attributes=2,
        attr_values=attr_values,
        attr_blindings=attr_blindings,
        num_predicates=1,
        predicates=padded_preds,
    )
    if ok or err != expect_fail_with:
        raise IntervalPredicateError(
            "invalid_negative_vector",
            f"negative vector {case_id} expected {expect_fail_with!r}, got ok={ok} err={err!r}",
        )

    return {
        "id": case_id,
        "description": description,
        "attr_index": 0,
        "clauses": [c.to_dict() for c in clauses],
        "canonical_conjunction": conjunction_dict,
        "encoded_predicate": encoded_pred,
        "public_statement": public_preview,
        "prover_only_synthetic_opening": {
            "certified_attr_value": synthetic_certified_value,
            "certified_attr_blinding": synthetic_attr_blinding,
            "secondary_attr_value": 12345678,
            "secondary_attr_blinding": 222222,
        },
        "expect_fail_with": expect_fail_with,
    }


def generate_interval_vector_corpus() -> dict[str, Any]:
    """Generate the deterministic boundary and empty-intersection vector corpus."""
    clauses_order_a = [
        IntervalClause(10, 100, True, True),
        IntervalClause(20, 80, False, True),
        IntervalClause(15, 60, True, False),
        IntervalClause(20, 70, True, True),
    ]
    clauses_order_b = [
        IntervalClause(20, 70, True, True),
        IntervalClause(15, 60, True, False),
        IntervalClause(10, 100, True, True),
        IntervalClause(20, 80, False, True),
    ]

    positive_cases = [
        _build_positive_case(
            case_id="sd-int-pos-001-half-open-lower-interior",
            description="[10, 30] intersect (18, 25] -> (18, 25] satisfied at minimum integer 19",
            clauses=[
                IntervalClause(10, 30, True, True),
                IntervalClause(18, 25, False, True),
            ],
            synthetic_certified_value=19,
            synthetic_attr_blinding=111111,
        ),
        _build_positive_case(
            case_id="sd-int-pos-002-half-open-upper-boundary",
            description="[10, 30] intersect (18, 25] -> (18, 25] satisfied at inclusive upper bound 25",
            clauses=[
                IntervalClause(10, 30, True, True),
                IntervalClause(18, 25, False, True),
            ],
            synthetic_certified_value=25,
            synthetic_attr_blinding=111112,
        ),
        _build_positive_case(
            case_id="sd-int-pos-003-closed-singleton-touching",
            description="[10, 18] intersect [18, 30] -> [18, 18] satisfied at singleton 18",
            clauses=[
                IntervalClause(10, 18, True, True),
                IntervalClause(18, 30, True, True),
            ],
            synthetic_certified_value=18,
            synthetic_attr_blinding=111113,
        ),
        _build_positive_case(
            case_id="sd-int-pos-004-open-singleton-interior",
            description="(17, 25] intersect [10, 19) -> (17, 19) satisfied at unique integer 18",
            clauses=[
                IntervalClause(17, 25, False, True),
                IntervalClause(10, 19, True, False),
            ],
            synthetic_certified_value=18,
            synthetic_attr_blinding=111114,
        ),
        _build_positive_case(
            case_id="sd-int-pos-005-four-clause-order-a-hidden-min",
            description="4-clause intersection [10, 100] & (20, 80] & [15, 60) & [20, 70] -> (20, 60) at 21",
            clauses=clauses_order_a,
            synthetic_certified_value=21,
            synthetic_attr_blinding=313371,
        ),
        _build_positive_case(
            case_id="sd-int-pos-006-four-clause-order-b-hidden-max",
            description="Permuted 4-clause intersection -> identical predicate_commitment with distinct hidden value 59",
            clauses=clauses_order_b,
            synthetic_certified_value=59,
            synthetic_attr_blinding=919191,
        ),
        _build_positive_case(
            case_id="sd-int-pos-007-u64-zero-lower-boundary",
            description="[0, 100) intersect [0, 10] -> [0, 10] satisfied at u64 minimum 0",
            clauses=[
                IntervalClause(0, 100, True, False),
                IntervalClause(0, 10, True, True),
            ],
            synthetic_certified_value=0,
            synthetic_attr_blinding=444444,
        ),
        _build_positive_case(
            case_id="sd-int-pos-008-u64-max-upper-boundary",
            description="(U64_MAX - 10, U64_MAX] intersect [U64_MAX - 5, U64_MAX] satisfied at U64_MAX",
            clauses=[
                IntervalClause(U64_MAX - 10, U64_MAX, False, True),
                IntervalClause(U64_MAX - 5, U64_MAX, True, True),
            ],
            synthetic_certified_value=U64_MAX,
            synthetic_attr_blinding=555555,
        ),
    ]

    forged_inclusive_packed = pack_canonical_interval_conjunction(18, 25, True, True)
    oversized_pred_override = {
        "predicate_type": str(INTERVAL_INTERSECTION_PREDICATE_TYPE),
        "attr_index": 0,
        "public_value": str(pack_canonical_interval_conjunction(16, 24, True, True)),
        "set_values": ["10", "30", "12", "28", "14", "26", "16", "24"],
        "set_len": 5 | (255 << 8),
        "lower_bound": "16",
        "upper_bound": "24",
    }
    dirty_inactive_slot_override = {
        "set_values": ["10", "30", "99", "0", "0", "0", "0", "0"],
    }

    negative_cases = [
        _build_negative_case(
            case_id="sd-int-neg-001-excluded-lower-boundary",
            description="Reject certified value 18 on half-open intersection [10, 30] & (18, 25] -> (18, 25]",
            clauses=[
                IntervalClause(10, 30, True, True),
                IntervalClause(18, 25, False, True),
            ],
            synthetic_certified_value=18,
            synthetic_attr_blinding=111111,
            expect_fail_with="interval bound unsatisfied",
        ),
        _build_negative_case(
            case_id="sd-int-neg-002-excluded-upper-boundary",
            description="Reject certified value 25 on half-open intersection [10, 25) & [18, 30] -> [18, 25)",
            clauses=[
                IntervalClause(10, 25, True, False),
                IntervalClause(18, 30, True, True),
            ],
            synthetic_certified_value=25,
            synthetic_attr_blinding=111111,
            expect_fail_with="interval bound unsatisfied",
        ),
        _build_negative_case(
            case_id="sd-int-neg-003-outside-tighter-third-clause",
            description="Reject certified value 22 satisfying [10, 50] & [20, 40] but failing [25, 35]",
            clauses=[
                IntervalClause(10, 50, True, True),
                IntervalClause(20, 40, True, True),
                IntervalClause(25, 35, True, True),
            ],
            synthetic_certified_value=22,
            synthetic_attr_blinding=111111,
            expect_fail_with="interval bound unsatisfied",
        ),
        _build_negative_case(
            case_id="sd-int-neg-004-empty-disjoint-intervals",
            description="Reject disjoint intervals [10, 15] & [20, 25] -> [20, 15]",
            clauses=[
                IntervalClause(10, 15, True, True),
                IntervalClause(20, 25, True, True),
            ],
            synthetic_certified_value=18,
            synthetic_attr_blinding=111111,
            expect_fail_with="empty interval intersection",
        ),
        _build_negative_case(
            case_id="sd-int-neg-005-empty-touching-right-open",
            description="Reject touching intervals [10, 18) & [18, 25] -> [18, 18)",
            clauses=[
                IntervalClause(10, 18, True, False),
                IntervalClause(18, 25, True, True),
            ],
            synthetic_certified_value=18,
            synthetic_attr_blinding=111111,
            expect_fail_with="empty interval intersection",
        ),
        _build_negative_case(
            case_id="sd-int-neg-006-empty-touching-left-open",
            description="Reject touching intervals (18, 25] & [10, 18] -> (18, 18]",
            clauses=[
                IntervalClause(18, 25, False, True),
                IntervalClause(10, 18, True, True),
            ],
            synthetic_certified_value=18,
            synthetic_attr_blinding=111111,
            expect_fail_with="empty interval intersection",
        ),
        _build_negative_case(
            case_id="sd-int-neg-007-empty-open-singleton",
            description="Reject open singleton (18, 25) & (10, 30) & [18, 18] -> (18, 18)",
            clauses=[
                IntervalClause(18, 25, False, False),
                IntervalClause(10, 30, False, False),
                IntervalClause(18, 18, True, True),
            ],
            synthetic_certified_value=18,
            synthetic_attr_blinding=111111,
            expect_fail_with="empty interval intersection",
        ),
        _build_negative_case(
            case_id="sd-int-neg-008-empty-adjacent-open-integers",
            description="Reject open unit integer interval (18, 25] & [10, 19) -> (18, 19) with no u64 member",
            clauses=[
                IntervalClause(18, 25, False, True),
                IntervalClause(10, 19, True, False),
            ],
            synthetic_certified_value=18,
            synthetic_attr_blinding=111111,
            expect_fail_with="empty interval intersection",
        ),
        _build_negative_case(
            case_id="sd-int-neg-009-empty-zero-upper-exclusive",
            description="Reject u64 domain underflow interval [0, 0)",
            clauses=[
                IntervalClause(0, 0, True, False),
            ],
            synthetic_certified_value=0,
            synthetic_attr_blinding=111111,
            expect_fail_with="empty interval intersection",
        ),
        _build_negative_case(
            case_id="sd-int-neg-010-empty-u64-max-lower-exclusive",
            description="Reject u64 domain overflow interval (U64_MAX, U64_MAX]",
            clauses=[
                IntervalClause(U64_MAX, U64_MAX, False, True),
            ],
            synthetic_certified_value=U64_MAX,
            synthetic_attr_blinding=111111,
            expect_fail_with="empty interval intersection",
        ),
        _build_negative_case(
            case_id="sd-int-neg-011-non-canonical-inclusivity-claim",
            description="Reject forged inclusive public_value [18, 25] when clauses reduce to (18, 25]",
            clauses=[
                IntervalClause(10, 30, True, True),
                IntervalClause(18, 25, False, True),
            ],
            synthetic_certified_value=20,
            synthetic_attr_blinding=111111,
            expect_fail_with="non-canonical interval bounds",
            predicate_overrides={"public_value": str(forged_inclusive_packed)},
        ),
        _build_negative_case(
            case_id="sd-int-neg-012-non-canonical-widened-bound",
            description="Reject non-canonical lower_bound 10 when clauses [10, 30] & [18, 25] reduce to 18",
            clauses=[
                IntervalClause(10, 30, True, True),
                IntervalClause(18, 25, True, True),
            ],
            synthetic_certified_value=20,
            synthetic_attr_blinding=111111,
            expect_fail_with="non-canonical interval bounds",
            predicate_overrides={"lower_bound": "10"},
        ),
        _build_negative_case(
            case_id="sd-int-neg-013-oversized-clause-count",
            description="Reject num_clauses = 5 above MAX_INTERVAL_CLAUSES = 4",
            clauses=[],
            synthetic_certified_value=20,
            synthetic_attr_blinding=111111,
            expect_fail_with="oversized",
            predicate_overrides=oversized_pred_override,
        ),
        _build_negative_case(
            case_id="sd-int-neg-014-zero-clause-count",
            description="Reject num_clauses = 0 on active IntervalIntersection predicate",
            clauses=[],
            synthetic_certified_value=20,
            synthetic_attr_blinding=111111,
            expect_fail_with="malformed",
        ),
        _build_negative_case(
            case_id="sd-int-neg-015-nonzero-inactive-clause-slot",
            description="Reject non-zero bound in inactive clause slot j >= num_clauses",
            clauses=[
                IntervalClause(10, 30, True, True),
            ],
            synthetic_certified_value=20,
            synthetic_attr_blinding=111111,
            expect_fail_with="malformed",
            predicate_overrides=dirty_inactive_slot_override,
        ),
        _build_negative_case(
            case_id="sd-int-neg-016-field-overflow-certified-value",
            description="Reject certified Field value 2^64 + 20 that would wrap modulo 2^64 without non-truncation check",
            clauses=[
                IntervalClause(10, 30, True, True),
                IntervalClause(18, 25, False, True),
            ],
            synthetic_certified_value=TWO_POW_64 + 20,
            synthetic_attr_blinding=111111,
            expect_fail_with="malformed",
        ),
    ]

    return {
        "_description": (
            "Synthetic conformance vectors for selective_disclosure issuer-certified "
            "interval intersection predicates (#1209). Public statements bind the "
            "canonical reduced interval conjunction without revealing certified "
            "attribute values or blindings."
        ),
        "_circuit": "selective_disclosure/v1",
        "_version": "1.0.0",
        "_compiler": ">=1.0.0",
        "_predicate_type_id": INTERVAL_INTERSECTION_PREDICATE_TYPE,
        "_predicate_type_name": "IntervalIntersection",
        "_max_interval_clauses": MAX_INTERVAL_CLAUSES,
        "_commitment_model": "reference_sha256_bn254_v1",
        "privacy_notes": [
            "Public statements carry only the 11 wire fields (352 bytes); certified attribute values and blindings never appear in public_statement or encoded_predicate.",
            "predicate_commitment hashes the canonical reduced interval packing L* + U* * 2^64 + canonical_flags * 2^128, making commitments invariant to clause order and hidden attribute values.",
            "All prover_only_synthetic_opening entries use small deterministic test integers and never represent real credentials or media.",
        ],
        "positive_cases": positive_cases,
        "negative_cases": negative_cases,
    }


def serialize_corpus(corpus: dict[str, Any]) -> str:
    return json.dumps(corpus, indent=2, sort_keys=False) + "\n"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate or verify selective_disclosure interval intersection vectors.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--generate",
        action="store_true",
        help="Write the canonical interval vector fixture to disk.",
    )
    mode.add_argument(
        "--check",
        action="store_true",
        help="Verify the on-disk fixture matches the canonical generator output.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_FIXTURE_PATH,
        help="Target JSON path (defaults to zk/noir/fixtures/selective_disclosure_interval_vectors.json).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    target = Path(args.output)

    expected_text = serialize_corpus(generate_interval_vector_corpus())

    if args.generate:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(expected_text.encode("utf-8"))
        return EXIT_OK

    if not target.is_file():
        print(
            f"drift: missing interval vector fixture at {target}",
            file=sys.stderr,
        )
        return EXIT_DRIFT

    actual_text = target.read_text(encoding="utf-8")
    if actual_text != expected_text:
        print(
            f"drift: {target} does not match canonical generator output",
            file=sys.stderr,
        )
        return EXIT_DRIFT

    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
