"""Fixture provenance loader and validator.

Records and enforces the vector-generator version and statement schema
version of a proof fixture as provenance metadata that lives outside
the secret witness contents.

A fixture is a JSON object with a top-level provenance block:

    {
      "provenance": {
        "generator": "harpocrates-vectors",
        "generator_version": 1,
        "statement_schema": "silent_witness/v2"
      },
      ... witness / public-input contents ...
    }

Rules (fail-closed):
* provenance MUST be present. Absent provenance is a hard error
  (missing_provenance), never a permissive default.
* provenance.statement_schema MUST exactly equal the schema the
  selected circuit declares (schema_mismatch).
* provenance.generator_version MUST be a positive integer
  (invalid_generator_version).
* The validator NEVER reads, hashes, or emits witness field values in
  error messages. Provenance is validated before any witness field is
  touched.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

SUPPORTED_STATEMENT_SCHEMAS: frozenset[str] = frozenset(
    {
        "silent_witness/v1",
        "silent_witness/v2",
        "revocation_witness/v1",
    }
)

class FixtureProvenanceError(ValueError):
    """Fail-closed provenance error. Messages name fields, never values."""

    def __init__(self, code: str, field: str | None = None) -> None:
        self.code = code
        self.field = field
        super().__init__(f"{code}: {field}" if field else code)

@dataclass(frozen=True)
class Provenance:
    generator: str
    generator_version: int
    statement_schema: str

def load_provenance(fixture: Mapping[str, Any]) -> Provenance:
    """Extract and structurally validate the provenance block."""
    if not isinstance(fixture, Mapping):
        raise FixtureProvenanceError("fixture_not_object")

    block = fixture.get("provenance")
    if block is None:
        raise FixtureProvenanceError("missing_provenance", "provenance")
    if not isinstance(block, Mapping):
        raise FixtureProvenanceError("invalid_provenance", "provenance")

    for required in ("generator", "generator_version", "statement_schema"):
        if required not in block:
            raise FixtureProvenanceError("missing_provenance_field", required)

    gen = block["generator"]
    if not isinstance(gen, str) or not gen:
        raise FixtureProvenanceError("invalid_generator", "generator")

    ver = block["generator_version"]
    if isinstance(ver, bool) or not isinstance(ver, int) or ver < 1:
        raise FixtureProvenanceError("invalid_generator_version", "generator_version")

    schema = block["statement_schema"]
    if not isinstance(schema, str) or schema not in SUPPORTED_STATEMENT_SCHEMAS:
        raise FixtureProvenanceError("unsupported_statement_schema", "statement_schema")

    return Provenance(generator=gen, generator_version=ver, statement_schema=schema)

def validate_fixture(fixture: Mapping[str, Any], expected_schema: str) -> Provenance:
    """Validate a fixture against the selected circuit's schema."""
    if expected_schema not in SUPPORTED_STATEMENT_SCHEMAS:
        raise FixtureProvenanceError("unsupported_expected_schema", "expected_schema")
    prov = load_provenance(fixture)
    if prov.statement_schema != expected_schema:
        raise FixtureProvenanceError("schema_mismatch", "provenance.statement_schema")
    return prov

def validate_fixture_file(path: Path | str, expected_schema: str) -> Provenance:
    """Load a fixture JSON file and validate its provenance."""
    p = Path(path)
    if not p.is_file():
        raise FixtureProvenanceError("fixture_not_found")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        raise FixtureProvenanceError("malformed_fixture_json") from exc
    return validate_fixture(data, expected_schema)
