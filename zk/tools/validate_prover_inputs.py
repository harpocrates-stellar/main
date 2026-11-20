"""Prover.toml input validator for Noir circuits.

Validates Prover.toml contents against zk/noir/circuit_input_schema_v1.json.
Guarantees that error messages name fields, never values (privacy safe).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

DEFAULT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "noir" / "circuit_input_schema_v1.json"
)

# Field element pattern: decimal or hex integer
_DECIMAL_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
_HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")


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
    except Exception as exc:
        raise ProverInputValidationError("malformed_toml") from exc


def load_schema(schema_path: Path | str | None = None) -> dict[str, Any]:
    """Load the circuit input schema JSON."""
    path = Path(schema_path) if schema_path else DEFAULT_SCHEMA_PATH
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        raise ProverInputValidationError("schema_load_failed") from exc


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


def validate_prover_inputs(
    prover_data: Mapping[str, Any],
    schema: Mapping[str, Any] | None = None,
    required_fields: list[str] | None = None,
) -> None:
    """Validate prover data mapping against schema.

    - Verifies required_fields (defaults to schema["input_fields"]) are present.
    - Verifies all present field values (both required and known optional/public frame fields)
      conform to field element syntax and are strictly < field_modulus.
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

    for field, val in prover_data.items():
        if isinstance(val, (int, str)):
            validate_field_element(val, field, field_modulus)


def validate_prover_file(
    file_path: Path | str,
    schema_path: Path | str | None = None,
    required_fields: list[str] | None = None,
) -> None:
    """Validate a Prover.toml file path."""
    path = Path(file_path)
    if not path.is_file():
        raise ProverInputValidationError("file_not_found")
    content = path.read_text(encoding="utf-8")
    data = parse_prover_toml(content)
    schema = load_schema(schema_path)
    validate_prover_inputs(data, schema=schema, required_fields=required_fields)


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

    args = parser.parse_args(argv)

    try:
        validate_prover_file(
            args.prover_toml,
            schema_path=args.schema,
            required_fields=args.required_fields,
        )
        return 0
    except ProverInputValidationError as exc:
        if exc.field:
            sys.stderr.write(f"Error: {exc.code} for field '{exc.field}'\n")
        else:
            sys.stderr.write(f"Error: {exc.code}\n")
        return 1
    except Exception:
        sys.stderr.write("Error: unexpected_validation_failure\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
