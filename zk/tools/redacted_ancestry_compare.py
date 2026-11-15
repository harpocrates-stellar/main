#!/usr/bin/env python3
"""Redaction ancestry public-statement comparison tool (#1211).

Compares canonical original (`parent_commitment`) and derivative
(`derivative_digest`, `parameters_digest`, `operation_type`, `depth`,
`domain_tag`) public bindings across `redacted_ancestry` circuit versions and
identifies incompatible public-input changes without revealing private lineage
paths, witness openings, or local filesystem paths.

Privacy & fail-closed invariants:
1. Any input containing private witness openings (`parent_hash_hi`,
   `parent_hash_lo`, `parent_blinding`, `mask_commitment`, `redaction_seed`,
   `credential_secret`, `nullifier_secret`) or private ancestry path structures
   (`private_path`, `ancestry_path`, `lineage_path`, `intermediate_ancestors`,
   `witness`, `private_inputs`, etc.) is rejected immediately before parsing
   statement values.
2. Canonical 32-byte big-endian BN254 field encodings are compared in constant
   time via :func:`hmac.compare_digest`.
3. Reports, CLI output, and exceptions emit only slot indices, public field
   names, circuit version integers, booleans, and stable reason codes — never
   witness values, raw field secrets, or local filesystem paths.
"""

from __future__ import annotations

import argparse
import hmac
import json
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Final

BN254_SCALAR_MODULUS: Final[int] = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)

FIELD_BYTE_WIDTH: Final[int] = 32
CANONICAL_PUBLIC_SLOT_COUNT: Final[int] = 8
CANONICAL_FRAME_BYTES: Final[int] = FIELD_BYTE_WIDTH * CANONICAL_PUBLIC_SLOT_COUNT  # 256

OPERATION_REDACT: Final[int] = 0x726564616374  # ASCII "redact"
MIN_ANCESTRY_DEPTH: Final[int] = 1
MAX_ANCESTRY_DEPTH: Final[int] = 4

EXPECTED_DOMAIN_TAG: Final[int] = int(
    "0x1a73cc6eda5fc8454c3bf62ef9defb0e6e1f7d999ab6857a39692821856ad61d", 16
)

MAX_STATEMENT_FILE_BYTES: Final[int] = 256 * 1024

EXIT_COMPATIBLE: Final[int] = 0
EXIT_INCOMPATIBLE: Final[int] = 1
EXIT_USAGE: Final[int] = 2

REDACTED_ANCESTRY_PUBLIC_FIELDS: Final[tuple[str, ...]] = (
    "parent_commitment",
    "derivative_digest",
    "parameters_digest",
    "operation_type",
    "ancestry_root",
    "nullifier",
    "depth",
    "domain_tag",
)

NON_ZERO_PUBLIC_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "parent_commitment",
        "derivative_digest",
        "parameters_digest",
        "ancestry_root",
        "nullifier",
    }
)

FORBIDDEN_PRIVATE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "witness",
        "private_inputs",
        "privateInputs",
        "secret_inputs",
        "secretInputs",
        "secrets",
        "opening",
        "openings",
        "parent_hash_hi",
        "parent_hash_lo",
        "parent_blinding",
        "mask_commitment",
        "redaction_seed",
        "credential_secret",
        "nullifier_secret",
        "parentHashHi",
        "parentHashLo",
        "parentBlinding",
        "maskCommitment",
        "redactionSeed",
        "credentialSecret",
        "nullifierSecret",
        "private_path",
        "privatePath",
        "private_paths",
        "privatePaths",
        "ancestry_path",
        "ancestryPath",
        "lineage_path",
        "lineagePath",
        "merkle_path",
        "merklePath",
        "intermediate_ancestors",
        "intermediateAncestors",
        "intermediate_hashes",
        "unredacted_parent",
    }
)

_SCHEMA_VERSION_RE: Final[re.Pattern[str]] = re.compile(
    r"^redacted_ancestry/v([1-9]\d*)$"
)
_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]+$")
_DEC_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9]{1,78}$")


class StatementRejectCode(str, Enum):
    """Fail-closed validation codes for malformed or privacy-violating inputs."""

    MISSING_INPUT = "missing_input"
    OVERSIZED_INPUT = "oversized_input"
    MALFORMED_INPUT = "malformed_input"
    PRIVATE_PATH_OR_WITNESS_PRESENT = "private_path_or_witness_present"
    UNSUPPORTED_SCHEMA = "unsupported_schema"
    INVALID_CIRCUIT_VERSION = "invalid_circuit_version"
    NON_CANONICAL_FIELD = "non_canonical_field"
    ZERO_STATEMENT_FIELD = "zero_statement_field"
    UNSUPPORTED_OPERATION_TYPE = "unsupported_operation_type"
    DEPTH_OUT_OF_RANGE = "depth_out_of_range"
    ANCESTRY_CYCLE = "ancestry_cycle"


class IncompatibilityCode(str, Enum):
    """Public-input incompatibility categories across statement versions."""

    PUBLIC_INPUT_COUNT_CHANGED = "public_input_count_changed"
    PUBLIC_INPUT_LAYOUT_CHANGED = "public_input_layout_changed"
    ORIGINAL_BINDING_CHANGED = "original_binding_changed"
    DERIVATIVE_DIGEST_CHANGED = "derivative_digest_changed"
    PARAMETERS_DIGEST_CHANGED = "parameters_digest_changed"
    OPERATION_TYPE_CHANGED = "operation_type_changed"
    DEPTH_CHANGED = "depth_changed"
    DOMAIN_TAG_CHANGED = "domain_tag_changed"
    SAME_VERSION_ANCESTRY_ROOT_MISMATCH = "same_version_ancestry_root_mismatch"
    CROSS_VERSION_ANCESTRY_ROOT_REUSED = "cross_version_ancestry_root_reused"
    CROSS_VERSION_NULLIFIER_REUSED = "cross_version_nullifier_reused"


class StatementValidationError(ValueError):
    """Privacy-safe validation error that never echoes values or file paths."""

    def __init__(
        self,
        code: StatementRejectCode,
        *,
        side: str = "input",
        field: str = "statement",
    ) -> None:
        self.code = code
        self.side = side
        self.field = field
        super().__init__(f"{code.value}:{side}:{field}")

    def signal(self) -> dict[str, str]:
        return {
            "reject_code": self.code.value,
            "side": self.side,
            "field": self.field,
        }


@dataclass(frozen=True)
class IncompatibleChange:
    """One incompatible public-input difference between left and right statements."""

    code: IncompatibilityCode
    slot: int | None
    field: str
    reason: str

    def to_dict(self) -> dict[str, int | str | None]:
        return {
            "code": self.code.value,
            "slot": self.slot,
            "field": self.field,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CanonicalAncestryStatement:
    """Validated canonical public statement for a `redacted_ancestry` proof."""

    circuit_version: int
    statement_schema: str
    declared_public_fields: tuple[str, ...]
    slot_count: int
    fields_be32: dict[str, bytes]

    def has_canonical_layout(self) -> bool:
        return (
            self.slot_count == CANONICAL_PUBLIC_SLOT_COUNT
            and self.declared_public_fields == REDACTED_ANCESTRY_PUBLIC_FIELDS
        )

    def depth_int(self) -> int | None:
        raw = self.fields_be32.get("depth")
        if raw is None:
            return None
        return int.from_bytes(raw, "big")


@dataclass(frozen=True)
class FieldComparisonEntry:
    """Privacy-safe per-slot comparison summary (no raw field digests leaked)."""

    slot: int
    field: str
    binding_role: str
    version_scoped: bool
    equal: bool

    def to_dict(self) -> dict[str, bool | int | str]:
        return {
            "slot": self.slot,
            "field": self.field,
            "binding_role": self.binding_role,
            "version_scoped": self.version_scoped,
            "equal": self.equal,
        }


@dataclass(frozen=True)
class ComparisonReport:
    """Result of comparing two `redacted_ancestry` public statements."""

    compatible: bool
    cross_version: bool
    left_circuit_version: int
    right_circuit_version: int
    left_schema: str
    right_schema: str
    original_binding_equal: bool
    derivative_binding_equal: bool
    lineage_context_equal: bool
    domain_binding_equal: bool
    ancestry_root_relation: str
    nullifier_relation: str
    field_comparisons: tuple[FieldComparisonEntry, ...]
    incompatible_changes: tuple[IncompatibleChange, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_format": "harpocrates.redacted-ancestry-comparison",
            "report_version": 1,
            "compatible": self.compatible,
            "cross_version": self.cross_version,
            "left": {
                "circuit_version": self.left_circuit_version,
                "statement_schema": self.left_schema,
            },
            "right": {
                "circuit_version": self.right_circuit_version,
                "statement_schema": self.right_schema,
            },
            "bindings": {
                "original_binding_equal": self.original_binding_equal,
                "derivative_binding_equal": self.derivative_binding_equal,
                "lineage_context_equal": self.lineage_context_equal,
                "domain_binding_equal": self.domain_binding_equal,
                "ancestry_root_relation": self.ancestry_root_relation,
                "nullifier_relation": self.nullifier_relation,
            },
            "field_comparisons": [entry.to_dict() for entry in self.field_comparisons],
            "incompatible_change_count": len(self.incompatible_changes),
            "incompatible_changes": [
                change.to_dict() for change in self.incompatible_changes
            ],
        }


_FIELD_ROLES: Final[dict[str, tuple[str, bool]]] = {
    "parent_commitment": ("original_parent_binding", False),
    "derivative_digest": ("derivative_binding", False),
    "parameters_digest": ("derivative_parameters_binding", False),
    "operation_type": ("lineage_operation_binding", False),
    "ancestry_root": ("versioned_statement_root", True),
    "nullifier": ("versioned_replay_binder", True),
    "depth": ("lineage_depth_binding", False),
    "domain_tag": ("protocol_domain_binding", False),
}


def _scan_for_private_keys(node: Any, *, side: str) -> None:
    """Reject any input containing private witness openings or private paths."""
    if isinstance(node, Mapping):
        for key, value in node.items():
            key_str = str(key)
            if key_str in FORBIDDEN_PRIVATE_KEYS:
                raise StatementValidationError(
                    StatementRejectCode.PRIVATE_PATH_OR_WITNESS_PRESENT,
                    side=side,
                    field="private_input_redacted",
                )
            _scan_for_private_keys(value, side=side)
    elif isinstance(node, list):
        for item in node:
            _scan_for_private_keys(item, side=side)


def _encode_canonical_field_be32(
    raw_value: Any,
    *,
    side: str,
    field: str,
) -> bytes:
    """Parse an int, decimal string, or 0x-hex string into canonical 32B BE."""
    if isinstance(raw_value, bool):
        raise StatementValidationError(
            StatementRejectCode.NON_CANONICAL_FIELD, side=side, field=field
        )
    if isinstance(raw_value, int):
        scalar = raw_value
    elif isinstance(raw_value, str):
        text = raw_value.strip()
        if text.startswith(("0x", "0X")):
            hex_body = text[2:]
            if not hex_body or len(hex_body) > 64 or _HEX_RE.fullmatch(hex_body) is None:
                raise StatementValidationError(
                    StatementRejectCode.NON_CANONICAL_FIELD, side=side, field=field
                )
            scalar = int(hex_body, 16)
        elif _DEC_RE.fullmatch(text) is not None:
            scalar = int(text, 10)
        else:
            raise StatementValidationError(
                StatementRejectCode.NON_CANONICAL_FIELD, side=side, field=field
            )
    else:
        raise StatementValidationError(
            StatementRejectCode.NON_CANONICAL_FIELD, side=side, field=field
        )

    if scalar < 0 or scalar >= BN254_SCALAR_MODULUS:
        raise StatementValidationError(
            StatementRejectCode.NON_CANONICAL_FIELD, side=side, field=field
        )
    return scalar.to_bytes(FIELD_BYTE_WIDTH, "big")


def _resolve_circuit_version(
    mapping: Mapping[str, Any],
    *,
    default_version: int | None,
    side: str,
) -> tuple[int, str]:
    """Extract and cross-check `circuit_version` and `statement_schema`."""
    schema_candidates: list[str] = []
    for key in ("statement_schema", "artifactVersion", "_circuit"):
        val = mapping.get(key)
        if val is not None:
            if not isinstance(val, str):
                raise StatementValidationError(
                    StatementRejectCode.UNSUPPORTED_SCHEMA, side=side, field=key
                )
            schema_candidates.append(val)

    prov = mapping.get("fixture_provenance")
    prov_schema_ver: int | None = None
    if prov is not None:
        if not isinstance(prov, Mapping):
            raise StatementValidationError(
                StatementRejectCode.MALFORMED_INPUT,
                side=side,
                field="fixture_provenance",
            )
        prov_schema = prov.get("statement_schema")
        if prov_schema is not None:
            if not isinstance(prov_schema, str):
                raise StatementValidationError(
                    StatementRejectCode.UNSUPPORTED_SCHEMA,
                    side=side,
                    field="fixture_provenance.statement_schema",
                )
            schema_candidates.append(prov_schema)
        raw_psv = prov.get("statement_schema_version")
        if raw_psv is not None:
            if isinstance(raw_psv, bool) or not isinstance(raw_psv, int) or raw_psv < 1:
                raise StatementValidationError(
                    StatementRejectCode.INVALID_CIRCUIT_VERSION,
                    side=side,
                    field="fixture_provenance.statement_schema_version",
                )
            prov_schema_ver = raw_psv

    parsed_versions: set[int] = set()
    for candidate in schema_candidates:
        match = _SCHEMA_VERSION_RE.fullmatch(candidate)
        if match is None:
            raise StatementValidationError(
                StatementRejectCode.UNSUPPORTED_SCHEMA,
                side=side,
                field="statement_schema",
            )
        parsed_versions.add(int(match.group(1)))

    explicit_ver = mapping.get("circuit_version")
    if explicit_ver is not None:
        if (
            isinstance(explicit_ver, bool)
            or not isinstance(explicit_ver, int)
            or explicit_ver < 1
        ):
            raise StatementValidationError(
                StatementRejectCode.INVALID_CIRCUIT_VERSION,
                side=side,
                field="circuit_version",
            )
        parsed_versions.add(explicit_ver)

    if prov_schema_ver is not None:
        parsed_versions.add(prov_schema_ver)

    if default_version is not None:
        if isinstance(default_version, bool) or default_version < 1:
            raise StatementValidationError(
                StatementRejectCode.INVALID_CIRCUIT_VERSION,
                side=side,
                field="circuit_version",
            )
        if not parsed_versions:
            parsed_versions.add(default_version)
        elif parsed_versions != {default_version}:
            raise StatementValidationError(
                StatementRejectCode.INVALID_CIRCUIT_VERSION,
                side=side,
                field="circuit_version",
            )

    if len(parsed_versions) > 1:
        raise StatementValidationError(
            StatementRejectCode.INVALID_CIRCUIT_VERSION,
            side=side,
            field="circuit_version",
        )

    version = next(iter(parsed_versions)) if parsed_versions else 1
    return version, f"redacted_ancestry/v{version}"


def _validate_semantic_invariants(
    fields_be32: Mapping[str, bytes],
    *,
    side: str,
) -> None:
    """Enforce public statement invariants shared by all `redacted_ancestry` versions."""
    zero32 = b"\x00" * FIELD_BYTE_WIDTH
    for field_name in REDACTED_ANCESTRY_PUBLIC_FIELDS:
        if field_name not in fields_be32:
            continue
        raw = fields_be32[field_name]
        if field_name in NON_ZERO_PUBLIC_FIELDS and hmac.compare_digest(raw, zero32):
            raise StatementValidationError(
                StatementRejectCode.ZERO_STATEMENT_FIELD,
                side=side,
                field=field_name,
            )

    op_bytes = fields_be32.get("operation_type")
    if op_bytes is not None:
        expected_op = OPERATION_REDACT.to_bytes(FIELD_BYTE_WIDTH, "big")
        if not hmac.compare_digest(op_bytes, expected_op):
            raise StatementValidationError(
                StatementRejectCode.UNSUPPORTED_OPERATION_TYPE,
                side=side,
                field="operation_type",
            )

    depth_bytes = fields_be32.get("depth")
    if depth_bytes is not None:
        depth_val = int.from_bytes(depth_bytes, "big")
        if depth_val < MIN_ANCESTRY_DEPTH or depth_val > MAX_ANCESTRY_DEPTH:
            raise StatementValidationError(
                StatementRejectCode.DEPTH_OUT_OF_RANGE,
                side=side,
                field="depth",
            )

    parent_bytes = fields_be32.get("parent_commitment")
    deriv_bytes = fields_be32.get("derivative_digest")
    if (
        parent_bytes is not None
        and deriv_bytes is not None
        and hmac.compare_digest(parent_bytes, deriv_bytes)
    ):
        raise StatementValidationError(
            StatementRejectCode.ANCESTRY_CYCLE,
            side=side,
            field="derivative_digest",
        )


def parse_ancestry_statement(
    source: str | bytes | Mapping[str, Any],
    *,
    circuit_version: int | None = None,
    side: str = "input",
) -> CanonicalAncestryStatement:
    """Parse a canonical `redacted_ancestry` public statement without witness leakage.

    Accepts:
    - A 256-byte (`bytes`) or 512-hex-char (`str`, optional `0x` prefix) public
      input wire frame (or another multiple of 32 bytes to surface public-input
      slot-count incompatibilities during version comparison).
    - A JSON mapping (or JSON text string) containing either `publicInputs` /
      `public_inputs_hex` wire hex or a `public_inputs` / `statement` field
      dictionary (or top-level public statement fields).
    """
    if isinstance(source, bytes):
        if len(source) == 0 or len(source) % FIELD_BYTE_WIDTH != 0:
            raise StatementValidationError(
                StatementRejectCode.MALFORMED_INPUT, side=side, field="frame"
            )
        ver = circuit_version if circuit_version is not None else 1
        if isinstance(ver, bool) or ver < 1:
            raise StatementValidationError(
                StatementRejectCode.INVALID_CIRCUIT_VERSION,
                side=side,
                field="circuit_version",
            )
        slot_count = len(source) // FIELD_BYTE_WIDTH
        fields_be32: dict[str, bytes] = {}
        declared_names: list[str] = []
        for idx in range(slot_count):
            chunk = source[idx * FIELD_BYTE_WIDTH : (idx + 1) * FIELD_BYTE_WIDTH]
            field_name = (
                REDACTED_ANCESTRY_PUBLIC_FIELDS[idx]
                if idx < CANONICAL_PUBLIC_SLOT_COUNT
                else f"slot_{idx}"
            )
            scalar = int.from_bytes(chunk, "big")
            if scalar >= BN254_SCALAR_MODULUS:
                raise StatementValidationError(
                    StatementRejectCode.NON_CANONICAL_FIELD,
                    side=side,
                    field=field_name,
                )
            fields_be32[field_name] = chunk
            declared_names.append(field_name)
        if slot_count == CANONICAL_PUBLIC_SLOT_COUNT:
            _validate_semantic_invariants(fields_be32, side=side)
        return CanonicalAncestryStatement(
            circuit_version=ver,
            statement_schema=f"redacted_ancestry/v{ver}",
            declared_public_fields=tuple(declared_names),
            slot_count=slot_count,
            fields_be32=fields_be32,
        )

    if isinstance(source, str):
        stripped = source.strip()
        if not stripped:
            raise StatementValidationError(
                StatementRejectCode.MALFORMED_INPUT, side=side, field="statement"
            )
        if stripped.startswith("{"):
            try:
                decoded = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise StatementValidationError(
                    StatementRejectCode.MALFORMED_INPUT, side=side, field="json"
                ) from exc
            if not isinstance(decoded, Mapping):
                raise StatementValidationError(
                    StatementRejectCode.MALFORMED_INPUT, side=side, field="json"
                )
            return parse_ancestry_statement(
                decoded, circuit_version=circuit_version, side=side
            )

        hex_str = stripped[2:] if stripped.startswith(("0x", "0X")) else stripped
        if (
            len(hex_str) == 0
            or len(hex_str) % (FIELD_BYTE_WIDTH * 2) != 0
            or _HEX_RE.fullmatch(hex_str) is None
        ):
            raise StatementValidationError(
                StatementRejectCode.MALFORMED_INPUT, side=side, field="frame_hex"
            )
        return parse_ancestry_statement(
            bytes.fromhex(hex_str), circuit_version=circuit_version, side=side
        )

    if not isinstance(source, Mapping):
        raise StatementValidationError(
            StatementRejectCode.MALFORMED_INPUT, side=side, field="statement"
        )

    # Privacy gate first: reject any private witness or private ancestry path keys.
    _scan_for_private_keys(source, side=side)

    ver, schema = _resolve_circuit_version(
        source, default_version=circuit_version, side=side
    )

    raw_public_fields = source.get("public_fields")
    custom_layout: tuple[str, ...] | None = None
    if raw_public_fields is not None:
        if not isinstance(raw_public_fields, list) or not all(
            isinstance(item, str) and item for item in raw_public_fields
        ):
            raise StatementValidationError(
                StatementRejectCode.MALFORMED_INPUT,
                side=side,
                field="public_fields",
            )
        for item in raw_public_fields:
            if item in FORBIDDEN_PRIVATE_KEYS:
                raise StatementValidationError(
                    StatementRejectCode.PRIVATE_PATH_OR_WITNESS_PRESENT,
                    side=side,
                    field="private_input_redacted",
                )
        custom_layout = tuple(raw_public_fields)

    # Wire-hex envelope (`publicInputs` from browser proof or `public_inputs_hex`)
    for hex_key in ("publicInputs", "public_inputs_hex"):
        if hex_key in source and isinstance(source[hex_key], str):
            parsed_wire = parse_ancestry_statement(
                source[hex_key], circuit_version=ver, side=side
            )
            if custom_layout is not None:
                if len(custom_layout) != parsed_wire.slot_count:
                    raise StatementValidationError(
                        StatementRejectCode.MALFORMED_INPUT,
                        side=side,
                        field="public_fields",
                    )
                remapped = {
                    custom_layout[idx]: parsed_wire.fields_be32[
                        parsed_wire.declared_public_fields[idx]
                    ]
                    for idx in range(parsed_wire.slot_count)
                }
                if custom_layout == REDACTED_ANCESTRY_PUBLIC_FIELDS:
                    _validate_semantic_invariants(remapped, side=side)
                return CanonicalAncestryStatement(
                    circuit_version=ver,
                    statement_schema=schema,
                    declared_public_fields=custom_layout,
                    slot_count=parsed_wire.slot_count,
                    fields_be32=remapped,
                )
            return CanonicalAncestryStatement(
                circuit_version=ver,
                statement_schema=schema,
                declared_public_fields=parsed_wire.declared_public_fields,
                slot_count=parsed_wire.slot_count,
                fields_be32=parsed_wire.fields_be32,
            )

    # Mapping statement (`public_inputs` dict, `statement` dict, or top-level keys)
    field_container: Mapping[str, Any] | None = None
    for dict_key in ("public_inputs", "statement"):
        candidate = source.get(dict_key)
        if isinstance(candidate, Mapping):
            field_container = candidate
            break
    if field_container is None:
        field_container = source

    if custom_layout is not None:
        ordered_fields = custom_layout
    else:
        present_canonical = [
            f for f in REDACTED_ANCESTRY_PUBLIC_FIELDS if f in field_container
        ]
        extra_public = [
            str(k)
            for k in field_container
            if str(k) not in REDACTED_ANCESTRY_PUBLIC_FIELDS
            and str(k)
            not in {
                "circuit_version",
                "statement_schema",
                "artifactVersion",
                "_circuit",
                "fixture_provenance",
                "public_fields",
                "proof",
                "proofBytes",
                "publicInputBytes",
            }
        ]
        if not present_canonical and not extra_public:
            raise StatementValidationError(
                StatementRejectCode.MALFORMED_INPUT, side=side, field="public_inputs"
            )
        ordered_fields = (*present_canonical, *extra_public)

    encoded_fields: dict[str, bytes] = {}
    for fname in ordered_fields:
        if fname not in field_container:
            raise StatementValidationError(
                StatementRejectCode.MALFORMED_INPUT, side=side, field=fname
            )
        encoded_fields[fname] = _encode_canonical_field_be32(
            field_container[fname], side=side, field=fname
        )

    if ordered_fields == REDACTED_ANCESTRY_PUBLIC_FIELDS:
        _validate_semantic_invariants(encoded_fields, side=side)

    return CanonicalAncestryStatement(
        circuit_version=ver,
        statement_schema=schema,
        declared_public_fields=ordered_fields,
        slot_count=len(ordered_fields),
        fields_be32=encoded_fields,
    )


def _ct_equal_field(
    left: CanonicalAncestryStatement,
    right: CanonicalAncestryStatement,
    field: str,
) -> bool:
    lb = left.fields_be32.get(field)
    rb = right.fields_be32.get(field)
    if lb is None or rb is None:
        return False
    return hmac.compare_digest(lb, rb)


def compare_ancestry_statements(
    left_input: CanonicalAncestryStatement | str | bytes | Mapping[str, Any],
    right_input: CanonicalAncestryStatement | str | bytes | Mapping[str, Any],
    *,
    left_version: int | None = None,
    right_version: int | None = None,
) -> ComparisonReport:
    """Compare two `redacted_ancestry` statements across circuit versions."""
    left = (
        left_input
        if isinstance(left_input, CanonicalAncestryStatement)
        else parse_ancestry_statement(
            left_input, circuit_version=left_version, side="left"
        )
    )
    right = (
        right_input
        if isinstance(right_input, CanonicalAncestryStatement)
        else parse_ancestry_statement(
            right_input, circuit_version=right_version, side="right"
        )
    )

    cross_version = left.circuit_version != right.circuit_version
    incompatible: list[IncompatibleChange] = []

    # 1. Check public-input count and slot layout compatibility first.
    if (
        left.slot_count != CANONICAL_PUBLIC_SLOT_COUNT
        or right.slot_count != CANONICAL_PUBLIC_SLOT_COUNT
        or left.slot_count != right.slot_count
    ):
        incompatible.append(
            IncompatibleChange(
                code=IncompatibilityCode.PUBLIC_INPUT_COUNT_CHANGED,
                slot=None,
                field="public_inputs",
                reason=(
                    f"public input slot count incompatible "
                    f"(left={left.slot_count}, right={right.slot_count}, "
                    f"canonical={CANONICAL_PUBLIC_SLOT_COUNT})"
                ),
            )
        )

    if (
        left.declared_public_fields != REDACTED_ANCESTRY_PUBLIC_FIELDS
        or right.declared_public_fields != REDACTED_ANCESTRY_PUBLIC_FIELDS
    ):
        incompatible.append(
            IncompatibleChange(
                code=IncompatibilityCode.PUBLIC_INPUT_LAYOUT_CHANGED,
                slot=None,
                field="public_fields",
                reason="public input slot ordering or field names diverge from canonical 8-field layout",
            )
        )

    field_entries: list[FieldComparisonEntry] = []
    eq_map: dict[str, bool] = {}
    for slot_idx, field_name in enumerate(REDACTED_ANCESTRY_PUBLIC_FIELDS):
        role, version_scoped = _FIELD_ROLES[field_name]
        is_eq = _ct_equal_field(left, right, field_name)
        eq_map[field_name] = is_eq
        field_entries.append(
            FieldComparisonEntry(
                slot=slot_idx,
                field=field_name,
                binding_role=role,
                version_scoped=version_scoped,
                equal=is_eq,
            )
        )

    original_equal = eq_map["parent_commitment"]
    derivative_equal = eq_map["derivative_digest"] and eq_map["parameters_digest"]
    lineage_equal = eq_map["operation_type"] and eq_map["depth"]
    domain_equal = eq_map["domain_tag"]
    root_equal = eq_map["ancestry_root"]
    nullifier_equal = eq_map["nullifier"]

    # 2. Check canonical original & derivative bindings when layouts are canonical.
    if left.has_canonical_layout() and right.has_canonical_layout():
        if not eq_map["parent_commitment"]:
            incompatible.append(
                IncompatibleChange(
                    code=IncompatibilityCode.ORIGINAL_BINDING_CHANGED,
                    slot=0,
                    field="parent_commitment",
                    reason="canonical original parent commitment differs between statements",
                )
            )
        if not eq_map["derivative_digest"]:
            incompatible.append(
                IncompatibleChange(
                    code=IncompatibilityCode.DERIVATIVE_DIGEST_CHANGED,
                    slot=1,
                    field="derivative_digest",
                    reason="canonical derivative digest differs between statements",
                )
            )
        if not eq_map["parameters_digest"]:
            incompatible.append(
                IncompatibleChange(
                    code=IncompatibilityCode.PARAMETERS_DIGEST_CHANGED,
                    slot=2,
                    field="parameters_digest",
                    reason="redaction parameters digest differs between statements",
                )
            )
        if not eq_map["operation_type"]:
            incompatible.append(
                IncompatibleChange(
                    code=IncompatibilityCode.OPERATION_TYPE_CHANGED,
                    slot=3,
                    field="operation_type",
                    reason="lineage operation identifier differs between statements",
                )
            )
        if not eq_map["depth"]:
            incompatible.append(
                IncompatibleChange(
                    code=IncompatibilityCode.DEPTH_CHANGED,
                    slot=6,
                    field="depth",
                    reason="claimed lineage ancestry depth differs between statements",
                )
            )
        if not eq_map["domain_tag"]:
            incompatible.append(
                IncompatibleChange(
                    code=IncompatibilityCode.DOMAIN_TAG_CHANGED,
                    slot=7,
                    field="domain_tag",
                    reason="protocol/version/network domain tag differs between statements",
                )
            )

        # 3. Version-dependent ancestry_root and nullifier transitions.
        core_bindings_match = (
            original_equal and derivative_equal and lineage_equal and domain_equal
        )
        if cross_version:
            if root_equal:
                incompatible.append(
                    IncompatibleChange(
                        code=IncompatibilityCode.CROSS_VERSION_ANCESTRY_ROOT_REUSED,
                        slot=4,
                        field="ancestry_root",
                        reason=(
                            "ancestry_root must rotate when CIRCUIT_VERSION changes "
                            "across circuit versions"
                        ),
                    )
                )
            if nullifier_equal:
                incompatible.append(
                    IncompatibleChange(
                        code=IncompatibilityCode.CROSS_VERSION_NULLIFIER_REUSED,
                        slot=5,
                        field="nullifier",
                        reason=(
                            "nullifier bound to ancestry_root must rotate across "
                            "distinct circuit versions"
                        ),
                    )
                )
        elif core_bindings_match and not root_equal:
            incompatible.append(
                IncompatibleChange(
                    code=IncompatibilityCode.SAME_VERSION_ANCESTRY_ROOT_MISMATCH,
                    slot=4,
                    field="ancestry_root",
                    reason=(
                        "ancestry_root diverges within the same circuit version "
                        "despite identical original, derivative, and depth bindings"
                    ),
                )
            )

    if cross_version:
        ancestry_root_relation = (
            "reused_across_versions_invalid"
            if root_equal
            else "rotated_with_circuit_version"
        )
        nullifier_relation = (
            "reused_across_versions_invalid"
            if nullifier_equal
            else "rotated_with_circuit_version"
        )
    else:
        ancestry_root_relation = (
            "identical_same_version" if root_equal else "diverged_same_version"
        )
        nullifier_relation = "identical" if nullifier_equal else "distinct_binder"

    return ComparisonReport(
        compatible=len(incompatible) == 0,
        cross_version=cross_version,
        left_circuit_version=left.circuit_version,
        right_circuit_version=right.circuit_version,
        left_schema=left.statement_schema,
        right_schema=right.statement_schema,
        original_binding_equal=original_equal,
        derivative_binding_equal=derivative_equal,
        lineage_context_equal=lineage_equal,
        domain_binding_equal=domain_equal,
        ancestry_root_relation=ancestry_root_relation,
        nullifier_relation=nullifier_relation,
        field_comparisons=tuple(field_entries),
        incompatible_changes=tuple(incompatible),
    )


def load_statement_file(
    path: Path,
    *,
    circuit_version: int | None = None,
    side: str = "input",
) -> CanonicalAncestryStatement:
    """Read a statement file with bounded size and zero filesystem path leakage."""
    try:
        if not path.is_file():
            raise StatementValidationError(
                StatementRejectCode.MISSING_INPUT, side=side, field="file"
            )
        size = path.stat().st_size
        if size > MAX_STATEMENT_FILE_BYTES:
            raise StatementValidationError(
                StatementRejectCode.OVERSIZED_INPUT, side=side, field="file"
            )
        raw = path.read_bytes()
    except OSError as exc:
        raise StatementValidationError(
            StatementRejectCode.MISSING_INPUT, side=side, field="file"
        ) from exc

    if len(raw) > MAX_STATEMENT_FILE_BYTES:
        raise StatementValidationError(
            StatementRejectCode.OVERSIZED_INPUT, side=side, field="file"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StatementValidationError(
            StatementRejectCode.MALFORMED_INPUT, side=side, field="encoding"
        ) from exc

    return parse_ancestry_statement(text, circuit_version=circuit_version, side=side)


def render_markdown_report(report: ComparisonReport) -> str:
    """Render a concise privacy-safe Markdown summary of the comparison."""
    status = "COMPATIBLE" if report.compatible else "INCOMPATIBLE"
    mode = "cross-version" if report.cross_version else "same-version"
    lines = [
        "# Redaction Ancestry Statement Comparison Report",
        "",
        f"- **Status:** `{status}` (`{mode}`)",
        f"- **Left schema:** `{report.left_schema}` (circuit version `{report.left_circuit_version}`)",
        f"- **Right schema:** `{report.right_schema}` (circuit version `{report.right_circuit_version}`)",
        f"- **Original binding (`parent_commitment`):** `{'match' if report.original_binding_equal else 'mismatch'}`",
        f"- **Derivative bindings (`derivative_digest`, `parameters_digest`):** `{'match' if report.derivative_binding_equal else 'mismatch'}`",
        f"- **Lineage context (`operation_type`, `depth`):** `{'match' if report.lineage_context_equal else 'mismatch'}`",
        f"- **Domain binding (`domain_tag`):** `{'match' if report.domain_binding_equal else 'mismatch'}`",
        f"- **Ancestry root relation:** `{report.ancestry_root_relation}`",
        f"- **Nullifier relation:** `{report.nullifier_relation}`",
        "",
        "## Public Slot Comparison",
        "",
        "| Slot | Field | Role | Version-Scoped | Equal |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in report.field_comparisons:
        lines.append(
            f"| {entry.slot} | `{entry.field}` | `{entry.binding_role}` | "
            f"`{'yes' if entry.version_scoped else 'no'}` | "
            f"`{'yes' if entry.equal else 'no'}` |"
        )
    lines.append("")
    lines.append("## Incompatible Public-Input Changes")
    lines.append("")
    if not report.incompatible_changes:
        lines.append("None.")
    else:
        for change in report.incompatible_changes:
            slot_label = f"slot {change.slot}" if change.slot is not None else "layout"
            lines.append(
                f"- `{change.code.value}` ({slot_label}, `{change.field}`): {change.reason}"
            )
    lines.append("")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compare canonical original and derivative redaction ancestry "
            "public statements across circuit versions without revealing "
            "private paths or witness openings."
        )
    )
    parser.add_argument(
        "left",
        type=Path,
        help="Left public statement file (JSON envelope or 256-byte hex frame).",
    )
    parser.add_argument(
        "right",
        type=Path,
        help="Right public statement file (JSON envelope or 256-byte hex frame).",
    )
    parser.add_argument(
        "--left-version",
        type=int,
        default=None,
        help="Explicit circuit version integer for left statement (default: from schema or 1).",
    )
    parser.add_argument(
        "--right-version",
        type=int,
        default=None,
        help="Explicit circuit version integer for right statement (default: from schema or 1).",
    )
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="Output report format (default: json).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        left_stmt = load_statement_file(
            args.left, circuit_version=args.left_version, side="left"
        )
        right_stmt = load_statement_file(
            args.right, circuit_version=args.right_version, side="right"
        )
        report = compare_ancestry_statements(left_stmt, right_stmt)
    except StatementValidationError as err:
        print(
            json.dumps(err.signal(), sort_keys=True, separators=(",", ":")),
            file=sys.stderr,
        )
        return EXIT_USAGE

    if args.format == "markdown":
        print(render_markdown_report(report), end="")
    else:
        print(json.dumps(report.to_dict(), indent=2))

    return EXIT_COMPATIBLE if report.compatible else EXIT_INCOMPATIBLE


if __name__ == "__main__":
    raise SystemExit(main())
