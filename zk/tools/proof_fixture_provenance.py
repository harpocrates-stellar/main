#!/usr/bin/env python3
"""Proof fixture provenance and statement-schema validator (#1212).

Records vector generator and statement schema versions in proof fixtures while
enforcing two hard protocol invariants:

1. **Provenance stays outside secret witness contents.** Generator and schema
   metadata live exclusively in the outer ``fixture_provenance`` envelope. Any
   provenance key found inside secret witness containers — or any secret/witness
   field placed inside ``fixture_provenance`` — is rejected before proving or
   verification.
2. **Selected-circuit schema binding.** Loading or validating a proof fixture
   for a selected circuit rejects any declared ``statement_schema``,
   ``statement_schema_version``, or public-frame byte width that conflicts with
   that circuit's supported statement schemas.

All rejection errors carry only a stable :class:`FixtureRejectCode` and a
structural field path — never secret witness values, openings, or proof bytes.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Final

PROVENANCE_ENVELOPE_KEY: Final[str] = "fixture_provenance"
PROVENANCE_FORMAT: Final[str] = "harpocrates.proof-fixture-provenance"
PROVENANCE_VERSION: Final[int] = 1

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
FIXTURES_DIR: Final[Path] = REPO_ROOT / "zk" / "noir" / "fixtures"

MAX_FIXTURE_BYTES: Final[int] = 4 * 1024 * 1024

EXIT_OK: Final[int] = 0
EXIT_REJECTED: Final[int] = 1
EXIT_USAGE: Final[int] = 2

#: Allowed statement schemas and their exact integer schema version + byte width
#: (``None`` when the fixture is a symbolic vector corpus without raw wire bytes)
#: for every protocol circuit.
CIRCUIT_STATEMENT_SCHEMAS: Final[dict[str, dict[str, tuple[int, int | None]]]] = {
    "silent_witness": {
        "silent_witness/browser_v1": (1, 128),
        "silent_witness/v1": (1, 160),
        "silent_witness/v2": (2, 256),
    },
    "silent_witness_aggregator": {
        "silent_witness_aggregator/v1": (1, None),
    },
    "revocation_witness": {
        "revocation_witness/v1": (1, 128),
    },
    "selective_disclosure": {
        "selective_disclosure/v1": (1, 352),
    },
    "redacted_ancestry": {
        "redacted_ancestry/v1": (1, 256),
    },
}

DEFAULT_CIRCUIT_SCHEMA: Final[dict[str, tuple[str, int]]] = {
    "silent_witness": ("silent_witness/v2", 2),
    "silent_witness_aggregator": ("silent_witness_aggregator/v1", 1),
    "revocation_witness": ("revocation_witness/v1", 1),
    "selective_disclosure": ("selective_disclosure/v1", 1),
    "redacted_ancestry": ("redacted_ancestry/v1", 1),
}

COMMITTED_CIRCUIT_FIXTURES: Final[tuple[tuple[str, str], ...]] = (
    ("redacted_ancestry", "zk/noir/fixtures/redacted_ancestry_vectors.json"),
    ("silent_witness", "zk/noir/fixtures/scoped_nullifier_vectors.json"),
    ("revocation_witness", "zk/noir/fixtures/revocation_vectors.json"),
    ("silent_witness_aggregator", "zk/noir/fixtures/aggregation_vectors.json"),
)

ALLOWED_PROVENANCE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "format",
        "provenance_version",
        "circuit",
        "vector_generator",
        "vector_generator_version",
        "statement_schema",
        "statement_schema_version",
    }
)

PROVENANCE_METADATA_KEYS: Final[frozenset[str]] = frozenset(
    {
        PROVENANCE_ENVELOPE_KEY,
        "provenance_version",
        "vector_generator",
        "vector_generator_version",
        "statement_schema",
        "statement_schema_version",
    }
)

WITNESS_CONTAINER_KEYS: Final[frozenset[str]] = frozenset(
    {
        "witness",
        "private_inputs",
        "privateInputs",
        "secret_inputs",
        "secretInputs",
        "secrets",
    }
)

FORBIDDEN_SECRET_KEYS_IN_PROVENANCE: Final[frozenset[str]] = frozenset(
    {
        "witness",
        "private_inputs",
        "privateInputs",
        "credential_secret",
        "nullifier_secret",
        "credentialSecret",
        "nullifierSecret",
        "parent_blinding",
        "redaction_seed",
        "mask_commitment",
        "parent_hash_hi",
        "parent_hash_lo",
        "attr_values",
        "attr_blindings",
        "attrValues",
        "attrBlindings",
        "leaves",
        "private_key",
    }
)

_SEMVER_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$"
)


class FixtureRejectCode(str, Enum):
    """Stable privacy-safe rejection codes for proof fixture validation."""

    MISSING_FILE = "missing_file"
    OVERSIZED_FIXTURE = "oversized_fixture"
    MALFORMED_JSON = "malformed_json"
    UNKNOWN_CIRCUIT = "unknown_circuit"
    MISSING_PROVENANCE = "missing_provenance"
    MALFORMED_PROVENANCE = "malformed_provenance"
    PROVENANCE_IN_WITNESS = "provenance_in_witness"
    SECRET_IN_PROVENANCE = "secret_in_provenance"
    CIRCUIT_MISMATCH = "circuit_mismatch"
    SCHEMA_CIRCUIT_CONFLICT = "schema_circuit_conflict"
    SCHEMA_VERSION_CONFLICT = "schema_version_conflict"
    FRAME_LENGTH_SCHEMA_CONFLICT = "frame_length_schema_conflict"


class FixtureProvenanceError(ValueError):
    """Raised when a proof fixture violates provenance or schema invariants."""

    def __init__(self, code: FixtureRejectCode, field: str) -> None:
        self.code = code
        self.field = field
        super().__init__(f"{code.value}:{field}")

    def signal(self) -> dict[str, str]:
        return {"reject_code": self.code.value, "field": self.field}


@dataclass(frozen=True)
class FixtureProvenance:
    """Validated provenance metadata attached to a proof fixture envelope."""

    circuit: str
    vector_generator: str
    vector_generator_version: str
    statement_schema: str
    statement_schema_version: int
    provenance_version: int = PROVENANCE_VERSION

    def to_dict(self) -> dict[str, int | str]:
        return {
            "format": PROVENANCE_FORMAT,
            "provenance_version": self.provenance_version,
            "circuit": self.circuit,
            "vector_generator": self.vector_generator,
            "vector_generator_version": self.vector_generator_version,
            "statement_schema": self.statement_schema,
            "statement_schema_version": self.statement_schema_version,
        }


def build_fixture_provenance(
    *,
    circuit: str,
    vector_generator: str,
    vector_generator_version: str,
    statement_schema: str | None = None,
    statement_schema_version: int | None = None,
) -> dict[str, int | str]:
    """Construct and validate a canonical ``fixture_provenance`` dictionary."""
    if circuit not in CIRCUIT_STATEMENT_SCHEMAS:
        raise FixtureProvenanceError(FixtureRejectCode.UNKNOWN_CIRCUIT, "circuit")

    default_schema, default_ver = DEFAULT_CIRCUIT_SCHEMA[circuit]
    resolved_schema = statement_schema if statement_schema is not None else default_schema
    resolved_ver = (
        statement_schema_version
        if statement_schema_version is not None
        else default_ver
    )

    candidate = {
        PROVENANCE_ENVELOPE_KEY: {
            "format": PROVENANCE_FORMAT,
            "provenance_version": PROVENANCE_VERSION,
            "circuit": circuit,
            "vector_generator": vector_generator,
            "vector_generator_version": vector_generator_version,
            "statement_schema": resolved_schema,
            "statement_schema_version": resolved_ver,
        }
    }
    validated = validate_proof_fixture(candidate, selected_circuit=circuit)
    return validated.to_dict()


def _scan_witness_node_for_provenance(node: Any, path: str) -> None:
    """Ensure no provenance metadata keys were injected into secret witness data."""
    if isinstance(node, Mapping):
        for key, value in node.items():
            key_str = str(key)
            child_path = f"{path}.{key_str}"
            if key_str in PROVENANCE_METADATA_KEYS:
                raise FixtureProvenanceError(
                    FixtureRejectCode.PROVENANCE_IN_WITNESS,
                    child_path,
                )
            _scan_witness_node_for_provenance(value, child_path)
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            _scan_witness_node_for_provenance(item, f"{path}[{idx}]")


def _enforce_witness_provenance_separation(node: Any, path: str = "root") -> None:
    """Walk the fixture tree to verify all witness blocks exclude provenance."""
    if isinstance(node, Mapping):
        for key, value in node.items():
            key_str = str(key)
            child_path = key_str if path == "root" else f"{path}.{key_str}"
            if key_str in WITNESS_CONTAINER_KEYS:
                _scan_witness_node_for_provenance(value, child_path)
            elif key_str != PROVENANCE_ENVELOPE_KEY:
                _enforce_witness_provenance_separation(value, child_path)
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            _enforce_witness_provenance_separation(item, f"{path}[{idx}]")


def _extract_declared_frame_len(fixture: Mapping[str, Any]) -> int | None:
    """Return declared public-input byte length if present in fixture metadata."""
    for key in ("public_inputs_len", "publicInputBytes"):
        val = fixture.get(key)
        if isinstance(val, int) and not isinstance(val, bool):
            return val
    constants = fixture.get("circuit_constants")
    if isinstance(constants, Mapping):
        total = constants.get("public_input_total_bytes")
        if isinstance(total, int) and not isinstance(total, bool):
            return total
    return None


def validate_proof_fixture(
    fixture: Mapping[str, Any],
    *,
    selected_circuit: str,
) -> FixtureProvenance:
    """Validate provenance separation and circuit-schema compatibility."""
    if selected_circuit not in CIRCUIT_STATEMENT_SCHEMAS:
        raise FixtureProvenanceError(
            FixtureRejectCode.UNKNOWN_CIRCUIT, "selected_circuit"
        )
    if not isinstance(fixture, Mapping):
        raise FixtureProvenanceError(FixtureRejectCode.MALFORMED_JSON, "fixture")

    # 1. Verify secret witness sections contain zero provenance metadata first.
    _enforce_witness_provenance_separation(fixture)

    raw_prov = fixture.get(PROVENANCE_ENVELOPE_KEY)
    if raw_prov is None:
        raise FixtureProvenanceError(
            FixtureRejectCode.MISSING_PROVENANCE, PROVENANCE_ENVELOPE_KEY
        )
    if not isinstance(raw_prov, Mapping):
        raise FixtureProvenanceError(
            FixtureRejectCode.MALFORMED_PROVENANCE, PROVENANCE_ENVELOPE_KEY
        )

    # 2. Reject secret/witness keys or unknown keys inside fixture_provenance.
    for key in raw_prov:
        key_str = str(key)
        if key_str in FORBIDDEN_SECRET_KEYS_IN_PROVENANCE:
            raise FixtureProvenanceError(
                FixtureRejectCode.SECRET_IN_PROVENANCE,
                f"{PROVENANCE_ENVELOPE_KEY}.{key_str}",
            )
        if key_str not in ALLOWED_PROVENANCE_KEYS:
            raise FixtureProvenanceError(
                FixtureRejectCode.MALFORMED_PROVENANCE,
                f"{PROVENANCE_ENVELOPE_KEY}.{key_str}",
            )

    if raw_prov.get("format") != PROVENANCE_FORMAT:
        raise FixtureProvenanceError(
            FixtureRejectCode.MALFORMED_PROVENANCE,
            f"{PROVENANCE_ENVELOPE_KEY}.format",
        )
    prov_ver = raw_prov.get("provenance_version")
    if isinstance(prov_ver, bool) or prov_ver != PROVENANCE_VERSION:
        raise FixtureProvenanceError(
            FixtureRejectCode.MALFORMED_PROVENANCE,
            f"{PROVENANCE_ENVELOPE_KEY}.provenance_version",
        )

    gen_name = raw_prov.get("vector_generator")
    if not isinstance(gen_name, str) or not gen_name.strip():
        raise FixtureProvenanceError(
            FixtureRejectCode.MALFORMED_PROVENANCE,
            f"{PROVENANCE_ENVELOPE_KEY}.vector_generator",
        )

    gen_ver = raw_prov.get("vector_generator_version")
    if not isinstance(gen_ver, str) or _SEMVER_RE.fullmatch(gen_ver) is None:
        raise FixtureProvenanceError(
            FixtureRejectCode.MALFORMED_PROVENANCE,
            f"{PROVENANCE_ENVELOPE_KEY}.vector_generator_version",
        )

    declared_circuit = raw_prov.get("circuit")
    if not isinstance(declared_circuit, str) or not declared_circuit:
        raise FixtureProvenanceError(
            FixtureRejectCode.MALFORMED_PROVENANCE,
            f"{PROVENANCE_ENVELOPE_KEY}.circuit",
        )
    if declared_circuit not in CIRCUIT_STATEMENT_SCHEMAS:
        raise FixtureProvenanceError(
            FixtureRejectCode.UNKNOWN_CIRCUIT,
            f"{PROVENANCE_ENVELOPE_KEY}.circuit",
        )

    declared_schema = raw_prov.get("statement_schema")
    if not isinstance(declared_schema, str) or not declared_schema:
        raise FixtureProvenanceError(
            FixtureRejectCode.MALFORMED_PROVENANCE,
            f"{PROVENANCE_ENVELOPE_KEY}.statement_schema",
        )

    declared_schema_ver = raw_prov.get("statement_schema_version")
    if (
        isinstance(declared_schema_ver, bool)
        or not isinstance(declared_schema_ver, int)
        or declared_schema_ver < 1
    ):
        raise FixtureProvenanceError(
            FixtureRejectCode.MALFORMED_PROVENANCE,
            f"{PROVENANCE_ENVELOPE_KEY}.statement_schema_version",
        )

    # 3. Enforce selected-circuit and statement-schema compatibility.
    allowed_for_selected = CIRCUIT_STATEMENT_SCHEMAS[selected_circuit]
    if declared_schema not in allowed_for_selected:
        raise FixtureProvenanceError(
            FixtureRejectCode.SCHEMA_CIRCUIT_CONFLICT,
            f"{PROVENANCE_ENVELOPE_KEY}.statement_schema",
        )

    if declared_circuit != selected_circuit:
        raise FixtureProvenanceError(
            FixtureRejectCode.CIRCUIT_MISMATCH,
            f"{PROVENANCE_ENVELOPE_KEY}.circuit",
        )

    expected_schema_ver, expected_frame_bytes = allowed_for_selected[declared_schema]
    if declared_schema_ver != expected_schema_ver:
        raise FixtureProvenanceError(
            FixtureRejectCode.SCHEMA_VERSION_CONFLICT,
            f"{PROVENANCE_ENVELOPE_KEY}.statement_schema_version",
        )

    # Cross-check legacy `_circuit` label if present on the fixture.
    legacy_circuit_label = fixture.get("_circuit")
    if isinstance(legacy_circuit_label, str) and legacy_circuit_label != declared_schema:
        raise FixtureProvenanceError(
            FixtureRejectCode.SCHEMA_CIRCUIT_CONFLICT,
            "_circuit",
        )

    # Cross-check public frame byte length if present and fixed by the schema.
    actual_frame_bytes = _extract_declared_frame_len(fixture)
    if (
        expected_frame_bytes is not None
        and actual_frame_bytes is not None
        and actual_frame_bytes != expected_frame_bytes
    ):
        raise FixtureProvenanceError(
            FixtureRejectCode.FRAME_LENGTH_SCHEMA_CONFLICT,
            "public_inputs_len",
        )

    return FixtureProvenance(
        circuit=declared_circuit,
        vector_generator=gen_name,
        vector_generator_version=gen_ver,
        statement_schema=declared_schema,
        statement_schema_version=declared_schema_ver,
        provenance_version=PROVENANCE_VERSION,
    )


def extract_witness_inputs(
    fixture: Mapping[str, Any],
    *,
    selected_circuit: str,
) -> dict[str, Any]:
    """Validate ``fixture`` for ``selected_circuit`` and return clean witness data.

    Returns a deep copy of ``fixture["witness"]`` guaranteed to contain no
    provenance metadata keys.
    """
    validate_proof_fixture(fixture, selected_circuit=selected_circuit)
    witness = fixture.get("witness")
    if not isinstance(witness, Mapping):
        return {}
    copied = copy.deepcopy(dict(witness))
    _scan_witness_node_for_provenance(copied, "witness")
    return copied


def load_and_validate_fixture_file(
    path: Path,
    *,
    selected_circuit: str,
) -> FixtureProvenance:
    """Read a JSON proof fixture from disk with bounded size and validate it."""
    if not path.is_file():
        raise FixtureProvenanceError(FixtureRejectCode.MISSING_FILE, path.name)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise FixtureProvenanceError(FixtureRejectCode.MISSING_FILE, path.name) from exc
    if size > MAX_FIXTURE_BYTES:
        raise FixtureProvenanceError(FixtureRejectCode.OVERSIZED_FIXTURE, path.name)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise FixtureProvenanceError(FixtureRejectCode.MISSING_FILE, path.name) from exc
    if len(raw) > MAX_FIXTURE_BYTES:
        raise FixtureProvenanceError(FixtureRejectCode.OVERSIZED_FIXTURE, path.name)
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FixtureProvenanceError(FixtureRejectCode.MALFORMED_JSON, path.name) from exc
    if not isinstance(parsed, Mapping):
        raise FixtureProvenanceError(FixtureRejectCode.MALFORMED_JSON, path.name)
    return validate_proof_fixture(parsed, selected_circuit=selected_circuit)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate proof fixture generator/schema provenance and reject "
            "fixtures whose declared schema conflicts with the selected circuit."
        )
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root for --check-all (default: auto-detected).",
    )
    parser.add_argument(
        "--check-all",
        action="store_true",
        help="Validate all committed Noir proof fixtures against their circuits.",
    )
    parser.add_argument(
        "--circuit",
        type=str,
        default=None,
        help="Selected circuit identifier when validating a single fixture file.",
    )
    parser.add_argument(
        "fixture",
        nargs="?",
        type=Path,
        default=None,
        help="Path to a JSON proof fixture to validate against --circuit.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.check_all:
        repo_root = args.repo_root.resolve()
        results = []
        for circuit_name, rel_path in COMMITTED_CIRCUIT_FIXTURES:
            target = repo_root / rel_path
            try:
                prov = load_and_validate_fixture_file(
                    target, selected_circuit=circuit_name
                )
            except FixtureProvenanceError as err:
                print(
                    json.dumps(
                        {"fixture": rel_path, **err.signal()},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    file=sys.stderr,
                )
                return EXIT_REJECTED
            results.append({"fixture": rel_path, **prov.to_dict()})
        print(json.dumps({"checked": len(results), "ok": True, "fixtures": results}, indent=2))
        return EXIT_OK

    if args.fixture is None or not args.circuit:
        parser.print_usage(sys.stderr)
        return EXIT_USAGE

    try:
        prov = load_and_validate_fixture_file(
            args.fixture.resolve(), selected_circuit=args.circuit
        )
    except FixtureProvenanceError as err:
        print(
            json.dumps(err.signal(), sort_keys=True, separators=(",", ":")),
            file=sys.stderr,
        )
        return EXIT_REJECTED

    print(json.dumps({"ok": True, "fixture_provenance": prov.to_dict()}, indent=2))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
