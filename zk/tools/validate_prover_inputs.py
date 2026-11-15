"""Prover.toml input validator for Noir circuits.

Validates Prover.toml contents against zk/noir/circuit_input_schema_v1.json,
including strict canonical field encoding and unambiguous textual scope
identifier rules before witness generation.
Guarantees that error messages name fields, never values (privacy safe).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from collections.abc import Mapping
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

DEFAULT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "noir" / "circuit_input_schema_v1.json"
)
BN254_FIELD_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)
MAX_SCOPE_IDENTIFIER_BYTES = 64
SCOPE_DOMAIN_PREFIX = "harpocrates:scope:"

# Field element pattern: decimal or hex integer (\A...\Z prevents trailing newline match)
_DECIMAL_RE = re.compile(r"\A(?:0|[1-9][0-9]*)\Z")
_HEX_RE = re.compile(r"\A0[xX][0-9a-fA-F]+\Z")

# Canonical textual scope identifier: v:<verifier>:p:<purpose>
# Lowercase ASCII alphanumeric segments separated by single '-' or '_', no whitespace,
# no trailing newline, no extra colons, and no implicit/omitted purpose segment.
_CANONICAL_SCOPE_ID_RE = re.compile(
    r"\Av:(?P<verifier>[a-z0-9]+(?:[_-][a-z0-9]+)*):p:(?P<purpose>[a-z0-9]+(?:[_-][a-z0-9]+)*)\Z"
)
_RESERVED_UNSCOPED_ALIASES = frozenset({"0", "global", "unscoped", "none", "null"})


class ProverInputValidationError(ValueError):
    """Privacy-safe prover input validation error."""

    def __init__(self, code: str, field: str | None = None) -> None:
        self.code = code
        self.field = field
        message = f"{code}: {field}" if field else code
        super().__init__(message)


def parse_prover_toml(content: str) -> dict[str, Any]:
    """Parse a TOML string into a dictionary."""
    try:
        return tomllib.loads(content)
    except (tomllib.TOMLDecodeError, TypeError, ValueError) as exc:
        raise ProverInputValidationError("malformed_toml") from exc


def load_schema(schema_path: Path | str | None = None) -> dict[str, Any]:
    """Load the circuit input schema JSON."""
    path = Path(schema_path) if schema_path else DEFAULT_SCHEMA_PATH
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProverInputValidationError("schema_load_failed") from exc
    if not isinstance(data, dict):
        raise ProverInputValidationError("invalid_schema")
    return data


def parse_field_element(val: Any) -> int | None:
    """Parse an integer or string into an integer if it's a valid decimal or hex representation.

    Returns None if the value cannot be parsed as a non-negative integer.
    """
    if isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val if val >= 0 else None
    if isinstance(val, str):
        v = val.strip()
        if not v or len(v) > 80:
            return None
        if _DECIMAL_RE.match(v):
            return int(v, 10)
        if _HEX_RE.match(v):
            return int(v, 16)
        return None
    return None


def validate_field_element(
    val: Any,
    field_name: str,
    field_modulus: int,
) -> int:
    """Validate that val is a valid field element strictly less than field_modulus.

    Errors name the field only; no values are reflected in error messages.
    """
    parsed = parse_field_element(val)
    if parsed is None:
        raise ProverInputValidationError("malformed_field_element", field_name)
    if parsed >= field_modulus:
        raise ProverInputValidationError("field_element_out_of_range", field_name)
    return parsed


def validate_canonical_scope_field(
    val: Any,
    field_modulus: int = BN254_FIELD_MODULUS,
    field_name: str = "verifier_scope",
) -> int:
    """Validate that a numeric scope field uses exact canonical encoding before witness solve.

    Accepted canonical encodings:
      - Non-boolean Python `int` in `[0, field_modulus)`.
      - Exact minimal base-10 ASCII string (`"0"` or `"[1-9][0-9]*"`) with no
        whitespace, signs, leading zeros, hex prefixes, or raw textual labels,
        representing an integer in `[0, field_modulus)`.
    """
    if isinstance(val, bool):
        raise ProverInputValidationError("noncanonical_scope_identifier", field_name)
    if isinstance(val, int):
        if val < 0:
            raise ProverInputValidationError("noncanonical_scope_identifier", field_name)
        if val >= field_modulus:
            raise ProverInputValidationError("field_element_out_of_range", field_name)
        return val
    if isinstance(val, str):
        if not val or len(val) > 80 or not val.isascii() or not _DECIMAL_RE.match(val):
            raise ProverInputValidationError("noncanonical_scope_identifier", field_name)
        parsed = int(val, 10)
        if parsed >= field_modulus:
            raise ProverInputValidationError("field_element_out_of_range", field_name)
        return parsed
    raise ProverInputValidationError("noncanonical_scope_identifier", field_name)


def validate_canonical_scope_identifier(
    scope_id: Any,
    field_name: str = "verifier_scope_id",
) -> str:
    """Validate an unambiguous canonical textual scope identifier (`v:<verifier>:p:<purpose>`).

    Rejects uppercase characters, leading/trailing/internal whitespace, omitted
    or empty `:p:<purpose>` segments, extra colons, repeated or boundary `-`/`_`
    separators, non-ASCII / Unicode homoglyphs, overlong (>64-byte) strings, and
    reserved unscoped lookalikes (`0`, `global`, `unscoped`, `none`, `null`).
    """
    if not isinstance(scope_id, str):
        raise ProverInputValidationError("noncanonical_scope_identifier", field_name)
    if (
        not scope_id
        or len(scope_id) > MAX_SCOPE_IDENTIFIER_BYTES
        or not scope_id.isascii()
        or unicodedata.normalize("NFC", scope_id) != scope_id
    ):
        raise ProverInputValidationError("noncanonical_scope_identifier", field_name)
    match = _CANONICAL_SCOPE_ID_RE.match(scope_id)
    if match is None:
        raise ProverInputValidationError("noncanonical_scope_identifier", field_name)
    if match.group("verifier") in _RESERVED_UNSCOPED_ALIASES:
        raise ProverInputValidationError("noncanonical_scope_identifier", field_name)
    return scope_id


def derive_scope_field_from_identifier(
    scope_id: Any,
    field_modulus: int = BN254_FIELD_MODULUS,
    field_name: str = "verifier_scope_id",
) -> int:
    """Derive a canonical BN254 scope field from a validated textual scope identifier.

    Matches `deriveScopeField` in `frontend/src/seedVault.ts`:
      `SHA-256("harpocrates:scope:{scope_id}") % BN254_FIELD_MODULUS`, mapping `0 -> 1`.
    """
    canonical_id = validate_canonical_scope_identifier(scope_id, field_name=field_name)
    digest = hashlib.sha256(f"{SCOPE_DOMAIN_PREFIX}{canonical_id}".encode("ascii")).digest()
    reduced = int.from_bytes(digest, "big") % field_modulus
    return 1 if reduced == 0 else reduced


def resolve_prover_scope(
    raw_scope: Any = None,
    *,
    scope_id: Any | None = None,
    field_modulus: int = BN254_FIELD_MODULUS,
) -> str:
    """Resolve and validate a prover scope input into its exact canonical decimal field string.

    - When `scope_id` is supplied, validates `scope_id` as a canonical textual
      identifier (`v:<verifier>:p:<purpose>`), derives its field element, and if
      `raw_scope` is also explicitly supplied, verifies exact equality.
    - When `scope_id` is omitted, accepts either an exact canonical field
      encoding (`"0"` or minimal decimal `< field_modulus`) or a canonical
      `v:<verifier>:p:<purpose>` identifier string, rejecting all ambiguous or
      noncanonical variants before witness generation.
    """
    if scope_id is not None:
        derived = derive_scope_field_from_identifier(
            scope_id,
            field_modulus=field_modulus,
            field_name="verifier_scope_id",
        )
        if raw_scope is not None:
            explicit = validate_canonical_scope_field(
                raw_scope,
                field_modulus=field_modulus,
                field_name="verifier_scope",
            )
            if explicit != derived:
                raise ProverInputValidationError(
                    "scope_binding_mismatch",
                    "verifier_scope",
                )
        return str(derived)

    if raw_scope is None:
        return "0"

    if isinstance(raw_scope, str) and raw_scope.startswith("v:"):
        derived = derive_scope_field_from_identifier(
            raw_scope,
            field_modulus=field_modulus,
            field_name="verifier_scope",
        )
        return str(derived)

    canonical_int = validate_canonical_scope_field(
        raw_scope,
        field_modulus=field_modulus,
        field_name="verifier_scope",
    )
    return str(canonical_int)


def validate_prover_inputs(
    prover_data: Mapping[str, Any],
    schema: Mapping[str, Any] | None = None,
    required_fields: list[str] | None = None,
    *,
    expected_scope_id: str | None = None,
) -> None:
    """Validate prover data mapping against schema.

    - Verifies required_fields (defaults to schema["input_fields"]) are present.
    - Enforces exact canonical encoding on `verifier_scope` and optional
      `verifier_scope_id` / `expected_scope_id` binding before witness solve.
    - Verifies all other present scalar field values conform to field element
      syntax and are strictly < field_modulus.
    - Never prints or includes values in raised errors.
    """
    if schema is None:
        schema = load_schema()

    raw_modulus = schema.get("field_modulus")
    if not raw_modulus:
        raise ProverInputValidationError("invalid_schema")
    field_modulus = int(raw_modulus)

    reqs = (
        required_fields
        if required_fields is not None
        else schema.get("input_fields", [])
    )

    for field in reqs:
        if field not in prover_data:
            raise ProverInputValidationError("missing_required_field", field)

    scope_field_int: int | None = None
    if "verifier_scope" in prover_data:
        scope_field_int = validate_canonical_scope_field(
            prover_data["verifier_scope"],
            field_modulus=field_modulus,
            field_name="verifier_scope",
        )

    inline_scope_id = prover_data.get("verifier_scope_id")
    if inline_scope_id is not None:
        derived_inline = derive_scope_field_from_identifier(
            inline_scope_id,
            field_modulus=field_modulus,
            field_name="verifier_scope_id",
        )
        if scope_field_int is not None and scope_field_int != derived_inline:
            raise ProverInputValidationError("scope_binding_mismatch", "verifier_scope")
        scope_field_int = derived_inline

    if expected_scope_id is not None:
        derived_expected = derive_scope_field_from_identifier(
            expected_scope_id,
            field_modulus=field_modulus,
            field_name="verifier_scope_id",
        )
        if scope_field_int is not None and scope_field_int != derived_expected:
            raise ProverInputValidationError("scope_binding_mismatch", "verifier_scope")

    for field, val in prover_data.items():
        if field in ("verifier_scope", "verifier_scope_id"):
            continue
        if isinstance(val, (int, str)):
            validate_field_element(val, field, field_modulus)


def validate_prover_file(
    file_path: Path | str,
    schema_path: Path | str | None = None,
    required_fields: list[str] | None = None,
    *,
    expected_scope_id: str | None = None,
) -> None:
    """Validate a Prover.toml file path."""
    path = Path(file_path)
    if not path.is_file():
        raise ProverInputValidationError("file_not_found")
    content = path.read_text(encoding="utf-8")
    data = parse_prover_toml(content)
    schema = load_schema(schema_path)
    validate_prover_inputs(
        data,
        schema=schema,
        required_fields=required_fields,
        expected_scope_id=expected_scope_id,
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for validate_prover_inputs."""
    parser = argparse.ArgumentParser(
        description="Validate Prover.toml inputs against circuit input schema."
    )
    parser.add_argument("prover_toml", help="Path to Prover.toml")
    parser.add_argument(
        "--schema",
        default=None,
        help="Path to circuit_input_schema_v1.json (optional)",
    )
    parser.add_argument(
        "--required-fields",
        nargs="*",
        default=None,
        help="Explicit list of required fields (optional, overrides schema input_fields)",
    )
    parser.add_argument(
        "--scope-id",
        default=None,
        help="Canonical textual scope identifier (v:<verifier>:p:<purpose>) to cross-check against verifier_scope",
    )

    args = parser.parse_args(argv)

    try:
        validate_prover_file(
            args.prover_toml,
            schema_path=args.schema,
            required_fields=args.required_fields,
            expected_scope_id=args.scope_id,
        )
        return 0
    except ProverInputValidationError as exc:
        if exc.field:
            sys.stderr.write(f"Error: {exc.code} for field '{exc.field}'\n")
        else:
            sys.stderr.write(f"Error: {exc.code}\n")
        return 1
    except OSError:
        sys.stderr.write("Error: unexpected_validation_failure\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
