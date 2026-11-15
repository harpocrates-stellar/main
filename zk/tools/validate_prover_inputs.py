"""Prover.toml and circuit-input envelope validator for Noir circuits.

Validates Prover.toml and JSON input envelopes against
``zk/noir/circuit_input_schema_v1.json`` before invoking any witness generator
or proving backend. Exposes stable error categories that distinguish unsupported
input/circuit versions from malformed inputs and unsatisfied circuit constraints.
Guarantees that error messages name fields and categories only, never values
(privacy safe).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping
from enum import Enum
from pathlib import Path
from typing import Any

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
_VIDEO_HASH_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")

MAX_U32 = (1 << 32) - 1
MAX_SAFE_INT = (1 << 53) - 1

EXIT_OK = 0
EXIT_MALFORMED_INPUT = 1
EXIT_UNSUPPORTED_VERSION = 4
EXIT_UNSATISFIED_CONSTRAINT = 5


class ProverErrorCategory(str, Enum):
    """Stable error categories across prover input preflight and execution."""

    UNSUPPORTED_INPUT_VERSION = "unsupported_input_version"
    MALFORMED_INPUT = "malformed_input"
    UNSATISFIED_CONSTRAINT = "unsatisfied_constraint"
    PROVER_EXECUTION_FAILED = "prover_execution_failed"


VERSION_ERROR_CODES: frozenset[str] = frozenset(
    {
        "unsupported_input_schema",
        "unsupported_input_version",
        "deprecated_input_version",
        "malformed_input_version",
        "unsupported_circuit_version",
        "deprecated_circuit_version",
        "malformed_circuit_version",
        "circuit_version_mismatch",
    }
)

CONSTRAINT_ERROR_CODES: frozenset[str] = frozenset(
    {
        "unsatisfied_circuit_constraint",
    }
)

_VERSION_STDERR_MARKERS: tuple[str, ...] = (
    "circuit version mismatch",
    "unsupported_input_schema",
    "unsupported_input_version",
    "unsupported_circuit_version",
    "deprecated_circuit_version",
    "deprecated_input_version",
)

_CONSTRAINT_STDERR_MARKERS: tuple[str, ...] = (
    "failed assertion",
    "assertion failed",
    "cannot satisfy constraint",
    "unsatisfied constraint",
    '"malformed"',
    ": malformed",
    '"revoked"',
    ": revoked",
    '"oversized"',
    ": oversized",
    '"unsupported"',
    ": unsupported",
)


def category_for_code(code: str) -> ProverErrorCategory:
    """Resolve the canonical stable error category for a validation/prover code."""
    if code in VERSION_ERROR_CODES:
        return ProverErrorCategory.UNSUPPORTED_INPUT_VERSION
    if code in CONSTRAINT_ERROR_CODES:
        return ProverErrorCategory.UNSATISFIED_CONSTRAINT
    if code == "prover_execution_failed":
        return ProverErrorCategory.PROVER_EXECUTION_FAILED
    return ProverErrorCategory.MALFORMED_INPUT


def exit_code_for_category(category: ProverErrorCategory) -> int:
    """Return the deterministic CLI exit code for an error category."""
    if category == ProverErrorCategory.UNSUPPORTED_INPUT_VERSION:
        return EXIT_UNSUPPORTED_VERSION
    if category == ProverErrorCategory.UNSATISFIED_CONSTRAINT:
        return EXIT_UNSATISFIED_CONSTRAINT
    return EXIT_MALFORMED_INPUT


class ProverInputValidationError(ValueError):
    """Privacy-safe prover input validation error with stable category."""

    def __init__(
        self,
        code: str,
        field: str | None = None,
        *,
        category: ProverErrorCategory | None = None,
    ) -> None:
        self.code = code
        self.field = field
        self.category = category if category is not None else category_for_code(code)
        message = f"{code}: {field}" if field else code
        super().__init__(message)

    @property
    def exit_code(self) -> int:
        return exit_code_for_category(self.category)

    def to_dict(self) -> dict[str, str]:
        payload: dict[str, str] = {
            "category": self.category.value,
            "code": self.code,
        }
        if self.field:
            payload["field"] = self.field
        return payload


def parse_prover_toml(content: str) -> dict[str, Any]:
    """Parse a TOML string into a dictionary."""
    try:
        return tomllib.loads(content)
    except (tomllib.TOMLDecodeError, ValueError, TypeError) as exc:
        raise ProverInputValidationError("malformed_toml") from exc


def load_schema(schema_path: Path | str | None = None) -> dict[str, Any]:
    """Load the circuit input schema JSON."""
    path = Path(schema_path) if schema_path else DEFAULT_SCHEMA_PATH
    try:
        with open(path, encoding="utf-8") as f:
            loaded = json.load(f)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProverInputValidationError("schema_load_failed") from exc
    if not isinstance(loaded, dict):
        raise ProverInputValidationError("invalid_schema")
    return loaded


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


def _resolve_input_version_bounds(schema: Mapping[str, Any]) -> tuple[int, int]:
    supported = schema.get("supported_versions")
    if isinstance(supported, Mapping):
        input_bounds = supported.get("input_schema")
        if isinstance(input_bounds, Mapping):
            min_v = int(input_bounds.get("min", schema.get("version", 1)))
            max_v = int(input_bounds.get("max", schema.get("version", 1)))
            return min_v, max_v
    default_v = int(schema.get("version", 1))
    return default_v, default_v


def _resolve_expected_circuit_version(
    schema: Mapping[str, Any],
    prover_data: Mapping[str, Any],
    circuit: str | None = None,
    expected_circuit_version: int | None = None,
) -> int | None:
    if expected_circuit_version is not None:
        return expected_circuit_version

    inferred_circuit = circuit
    if inferred_circuit is None and "predicates" in prover_data:
        inferred_circuit = "selective_disclosure"

    supported = schema.get("supported_versions")
    if isinstance(supported, Mapping):
        circuits = supported.get("circuits")
        if isinstance(circuits, Mapping):
            if inferred_circuit is not None:
                raw_expected = circuits.get(inferred_circuit)
                return int(raw_expected) if raw_expected is not None else None
            if schema.get("id") == "silent_witness/input-v1" and "silent_witness" in circuits:
                return int(circuits["silent_witness"])

    artifact_abis = schema.get("artifact_abis")
    if isinstance(artifact_abis, Mapping) and inferred_circuit in (None, "silent_witness"):
        scoped_v2 = artifact_abis.get("scoped_v2")
        if isinstance(scoped_v2, Mapping) and "circuit_version" in scoped_v2:
            return int(scoped_v2["circuit_version"])

    return None


def validate_input_versions(
    prover_data: Mapping[str, Any],
    schema: Mapping[str, Any] | None = None,
    *,
    circuit: str | None = None,
    input_schema_version: Any = None,
    expected_circuit_version: int | None = None,
) -> None:
    """Validate input-envelope and circuit versions before invoking any prover.

    Version mismatches always raise ``ProverInputValidationError`` under
    ``ProverErrorCategory.UNSUPPORTED_INPUT_VERSION`` and run prior to witness
    field checks or backend execution so callers can distinguish version drift
    from malformed witness values and unsatisfied circuit constraints.
    """
    if schema is None:
        schema = load_schema()

    min_input_v, max_input_v = _resolve_input_version_bounds(schema)

    version_field_name: str | None = None
    raw_input_version: Any = input_schema_version
    if raw_input_version is not None:
        version_field_name = "input_schema_version"
    elif "input_schema_version" in prover_data:
        version_field_name = "input_schema_version"
        raw_input_version = prover_data["input_schema_version"]
    elif "inputSchemaVersion" in prover_data:
        version_field_name = "inputSchemaVersion"
        raw_input_version = prover_data["inputSchemaVersion"]

    if version_field_name is not None:
        parsed_input_v = parse_field_element(raw_input_version)
        if parsed_input_v is None or parsed_input_v > MAX_U32:
            if isinstance(raw_input_version, int) and not isinstance(raw_input_version, bool) and raw_input_version < 0:
                raise ProverInputValidationError(
                    "unsupported_input_schema",
                    version_field_name,
                    category=ProverErrorCategory.UNSUPPORTED_INPUT_VERSION,
                )
            raise ProverInputValidationError(
                "malformed_input_version",
                version_field_name,
                category=ProverErrorCategory.UNSUPPORTED_INPUT_VERSION,
            )
        if parsed_input_v < min_input_v:
            raise ProverInputValidationError(
                "deprecated_input_version",
                version_field_name,
                category=ProverErrorCategory.UNSUPPORTED_INPUT_VERSION,
            )
        if parsed_input_v > max_input_v:
            raise ProverInputValidationError(
                "unsupported_input_schema",
                version_field_name,
                category=ProverErrorCategory.UNSUPPORTED_INPUT_VERSION,
            )

    if "circuit_version" in prover_data:
        raw_circuit_v = prover_data["circuit_version"]
        parsed_circuit_v = parse_field_element(raw_circuit_v)
        if parsed_circuit_v is None or parsed_circuit_v > MAX_U32:
            raise ProverInputValidationError(
                "malformed_circuit_version",
                "circuit_version",
                category=ProverErrorCategory.UNSUPPORTED_INPUT_VERSION,
            )

        expected_cv = _resolve_expected_circuit_version(
            schema,
            prover_data,
            circuit=circuit,
            expected_circuit_version=expected_circuit_version,
        )
        if expected_cv is not None:
            if parsed_circuit_v < expected_cv:
                raise ProverInputValidationError(
                    "deprecated_circuit_version",
                    "circuit_version",
                    category=ProverErrorCategory.UNSUPPORTED_INPUT_VERSION,
                )
            if parsed_circuit_v > expected_cv:
                raise ProverInputValidationError(
                    "unsupported_circuit_version",
                    "circuit_version",
                    category=ProverErrorCategory.UNSUPPORTED_INPUT_VERSION,
                )


def validate_envelope_inputs(
    envelope: Mapping[str, Any],
    schema: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    """Validate a Silent Witness JSON input envelope before proving.

    Enforces version compatibility first (``unsupported_input_version``), then
    structural and BN254 field range checks (``malformed_input``). Returns the
    normalized Noir input mapping on success.
    """
    if not isinstance(envelope, Mapping):
        raise ProverInputValidationError("invalid_input")
    if schema is None:
        schema = load_schema()

    if "inputSchemaVersion" in envelope:
        raw_ver = envelope["inputSchemaVersion"]
        if isinstance(raw_ver, bool) or not isinstance(raw_ver, int):
            raise ProverInputValidationError(
                "malformed_input_version",
                "inputSchemaVersion",
                category=ProverErrorCategory.UNSUPPORTED_INPUT_VERSION,
            )
        validate_input_versions(envelope, schema=schema)

    raw_modulus = schema.get("field_modulus")
    if not raw_modulus:
        raise ProverInputValidationError("invalid_schema")
    field_modulus = int(raw_modulus)

    video_hash = envelope.get("videoHash")
    if not isinstance(video_hash, str) or not _VIDEO_HASH_HEX_RE.match(video_hash):
        raise ProverInputValidationError("invalid_input", "videoHash")

    cred_raw = envelope.get("credentialSecret")
    null_raw = envelope.get("nullifierSecret")
    scope_raw = envelope.get("verifierScope", "0")
    epoch_raw = envelope.get("epoch", 0)

    if not isinstance(cred_raw, str):
        raise ProverInputValidationError("invalid_input", "credentialSecret")
    if not isinstance(null_raw, str):
        raise ProverInputValidationError("invalid_input", "nullifierSecret")
    if not isinstance(scope_raw, str):
        raise ProverInputValidationError("invalid_input", "verifierScope")
    if isinstance(epoch_raw, bool) or not isinstance(epoch_raw, int) or epoch_raw < 0 or epoch_raw > MAX_SAFE_INT:
        raise ProverInputValidationError("invalid_input", "epoch")

    credential = validate_field_element(cred_raw, "credentialSecret", field_modulus)
    nullifier = validate_field_element(null_raw, "nullifierSecret", field_modulus)
    scope = validate_field_element(scope_raw, "verifierScope", field_modulus)

    return {
        "credential_secret": str(credential),
        "nullifier_secret": str(nullifier),
        "video_hash_hi": str(int(video_hash[:32], 16)),
        "video_hash_lo": str(int(video_hash[32:], 16)),
        "verifier_scope": str(scope),
        "epoch": str(epoch_raw),
    }


def classify_prover_execution_error(detail: str) -> tuple[ProverErrorCategory, str]:
    """Classify a witness/prover failure into a stable privacy-safe category.

    Inspects backend diagnostic text in memory without echoing any witness or
    input values in the returned category/code pair.
    """
    lowered = detail.lower()
    for marker in _VERSION_STDERR_MARKERS:
        if marker in lowered:
            return (
                ProverErrorCategory.UNSUPPORTED_INPUT_VERSION,
                "circuit_version_mismatch",
            )
    for marker in _CONSTRAINT_STDERR_MARKERS:
        if marker in lowered:
            return (
                ProverErrorCategory.UNSATISFIED_CONSTRAINT,
                "unsatisfied_circuit_constraint",
            )
    return (
        ProverErrorCategory.PROVER_EXECUTION_FAILED,
        "prover_execution_failed",
    )


def validate_prover_inputs(
    prover_data: Mapping[str, Any],
    schema: Mapping[str, Any] | None = None,
    required_fields: list[str] | None = None,
    *,
    circuit: str | None = None,
    input_schema_version: Any = None,
    expected_circuit_version: int | None = None,
) -> None:
    """Validate prover data mapping against schema.

    - Validates input_schema_version and circuit_version first under the stable
      ``unsupported_input_version`` category before checking witness constraints.
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

    validate_input_versions(
        prover_data,
        schema=schema,
        circuit=circuit,
        input_schema_version=input_schema_version,
        expected_circuit_version=expected_circuit_version,
    )

    reqs = (
        required_fields
        if required_fields is not None
        else schema.get("input_fields", [])
    )

    for field in reqs:
        if field not in prover_data:
            raise ProverInputValidationError("missing_required_field", field)

    for field, val in prover_data.items():
        if isinstance(val, int | str):
            validate_field_element(val, field, field_modulus)


def validate_prover_file(
    file_path: Path | str,
    schema_path: Path | str | None = None,
    required_fields: list[str] | None = None,
    *,
    circuit: str | None = None,
    input_schema_version: Any = None,
    expected_circuit_version: int | None = None,
) -> None:
    """Validate a Prover.toml file path."""
    path = Path(file_path)
    if not path.is_file():
        raise ProverInputValidationError("file_not_found")
    content = path.read_text(encoding="utf-8")
    data = parse_prover_toml(content)
    schema = load_schema(schema_path)
    inferred_circuit = circuit or path.resolve().parent.name
    validate_prover_inputs(
        data,
        schema=schema,
        required_fields=required_fields,
        circuit=inferred_circuit,
        input_schema_version=input_schema_version,
        expected_circuit_version=expected_circuit_version,
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
        "--circuit",
        default=None,
        help="Explicit circuit name for circuit_version verification (optional)",
    )
    parser.add_argument(
        "--input-schema-version",
        default=None,
        help="Explicit input schema version to validate before proving (optional)",
    )
    parser.add_argument(
        "--expected-circuit-version",
        type=int,
        default=None,
        help="Override expected circuit_version u32 value (optional)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Emit privacy-safe structured JSON category output on stderr",
    )

    args = parser.parse_args(argv)

    try:
        validate_prover_file(
            args.prover_toml,
            schema_path=args.schema,
            required_fields=args.required_fields,
            circuit=args.circuit,
            input_schema_version=args.input_schema_version,
            expected_circuit_version=args.expected_circuit_version,
        )
        return EXIT_OK
    except ProverInputValidationError as exc:
        if args.json_output:
            sys.stderr.write(json.dumps(exc.to_dict(), sort_keys=True) + "\n")
        elif exc.field:
            sys.stderr.write(
                f"Error [{exc.category.value}]: {exc.code} for field '{exc.field}'\n"
            )
        else:
            sys.stderr.write(f"Error [{exc.category.value}]: {exc.code}\n")
        return exc.exit_code
    except OSError:
        sys.stderr.write("Error [malformed_input]: file_read_failed\n")
        return EXIT_MALFORMED_INPUT


if __name__ == "__main__":
    sys.exit(main())
