"""Pre-prover circuit input version guard and stable error categories.

Host-side guard that mirrors the Noir circuit and input schema constants:

    CURRENT_CIRCUIT_VERSION = 2        # zk/noir/silent_witness/src/main.nr
    CIRCUIT_INPUT_SCHEMA_VERSION = 1   # zk/noir/circuit_input_schema_v1.json

Unsupported or malformed circuit input versions are rejected *before* invoking
an expensive prover, with stable machine-readable error categories that never
echo secrets, witness material, or raw user inputs and are clearly distinct
from unsatisfied circuit constraints.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from enum import StrEnum
from typing import Final, TypeVar

CURRENT_CIRCUIT_VERSION: Final[int] = 2
CIRCUIT_INPUT_SCHEMA_VERSION: Final[int] = 1
SUPPORTED_CIRCUIT_VERSIONS: Final[frozenset[int]] = frozenset({CURRENT_CIRCUIT_VERSION})
SUPPORTED_INPUT_SCHEMA_VERSIONS: Final[frozenset[int]] = frozenset({CIRCUIT_INPUT_SCHEMA_VERSION})

_NOIR_VERSION_MISMATCH_MARKER: Final[str] = "circuit version mismatch"

T = TypeVar("T")


class CircuitInputErrorCategory(StrEnum):
    """Stable, privacy-safe error categories for circuit input validation and proving."""

    UNSUPPORTED_CIRCUIT_VERSION = "unsupported_circuit_version"
    UNSUPPORTED_INPUT_SCHEMA_VERSION = "unsupported_input_schema_version"
    MALFORMED_CIRCUIT_VERSION = "malformed_circuit_version"
    CIRCUIT_CONSTRAINT_UNSATISFIED = "circuit_constraint_unsatisfied"


class CircuitInputVersionError(ValueError):
    """Privacy-safe rejection for unsupported or malformed circuit input versions."""

    def __init__(self, category: CircuitInputErrorCategory, field: str = "circuit_version") -> None:
        self.category = category
        self.code = category.value
        self.field = field
        super().__init__(self.code)

    def signal(self) -> dict[str, str]:
        return {"errorCategory": self.code, "field": self.field}


def check_input_schema_version(input_schema_version: object) -> int:
    """Validate the circuit input envelope schema version before proving."""
    if isinstance(input_schema_version, bool) or not isinstance(input_schema_version, int):
        raise CircuitInputVersionError(
            CircuitInputErrorCategory.MALFORMED_CIRCUIT_VERSION,
            field="input_schema_version",
        )
    if input_schema_version < 0:
        raise CircuitInputVersionError(
            CircuitInputErrorCategory.MALFORMED_CIRCUIT_VERSION,
            field="input_schema_version",
        )
    if input_schema_version not in SUPPORTED_INPUT_SCHEMA_VERSIONS:
        raise CircuitInputVersionError(
            CircuitInputErrorCategory.UNSUPPORTED_INPUT_SCHEMA_VERSION,
            field="input_schema_version",
        )
    return input_schema_version


def check_circuit_version(circuit_version: object) -> int:
    """Validate the target circuit version before invoking the prover."""
    if isinstance(circuit_version, bool) or not isinstance(circuit_version, int):
        raise CircuitInputVersionError(
            CircuitInputErrorCategory.MALFORMED_CIRCUIT_VERSION,
            field="circuit_version",
        )
    if circuit_version < 0:
        raise CircuitInputVersionError(
            CircuitInputErrorCategory.MALFORMED_CIRCUIT_VERSION,
            field="circuit_version",
        )
    if circuit_version not in SUPPORTED_CIRCUIT_VERSIONS:
        raise CircuitInputVersionError(
            CircuitInputErrorCategory.UNSUPPORTED_CIRCUIT_VERSION,
            field="circuit_version",
        )
    return circuit_version


def check_circuit_input_version(
    circuit_version: object,
    *,
    input_schema_version: object = CIRCUIT_INPUT_SCHEMA_VERSION,
) -> int:
    """Validate both input schema version and circuit version before proving.

    Returns the validated ``circuit_version`` integer on success.
    """
    check_input_schema_version(input_schema_version)
    return check_circuit_version(circuit_version)


def validate_before_prove(
    payload: Mapping[str, object],
    prover_fn: Callable[[Mapping[str, object]], T],
) -> T:
    """Run version checks before invoking ``prover_fn``.

    Guarantees that unsupported or malformed versions fail closed without
    invoking an expensive prover.
    """
    input_schema_version = payload.get("input_schema_version", CIRCUIT_INPUT_SCHEMA_VERSION)
    circuit_version = payload.get("circuit_version")
    check_circuit_input_version(
        circuit_version,
        input_schema_version=input_schema_version,
    )
    return prover_fn(payload)


def classify_prover_failure(error: Exception | str) -> CircuitInputErrorCategory:
    """Classify a proving or pre-proving failure into a stable error category.

    Distinguishes version mismatches from unsatisfied circuit constraints.
    """
    if isinstance(error, CircuitInputVersionError):
        return error.category

    message = str(error).lower()
    if _NOIR_VERSION_MISMATCH_MARKER in message:
        return CircuitInputErrorCategory.UNSUPPORTED_CIRCUIT_VERSION
    return CircuitInputErrorCategory.CIRCUIT_CONSTRAINT_UNSATISFIED
