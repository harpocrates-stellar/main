# Vector fixtures - provenance contract

Every proof fixture in this directory carries a top-level provenance
block. Provenance is metadata only and must never be folded into,
hashed into, or derived from the secret witness contents.

    {
      "provenance": {
        "generator": "harpocrates-vectors",
        "generator_version": 1,
        "statement_schema": "silent_witness/v2"
      }
    }

Fields:
- generator (string): name of the tool that produced the vectors.
- generator_version (positive int): version of that generator.
- statement_schema (enum): must match the schema the selected circuit declares.

Supported statement_schema values (kept in sync with zk/tools/fixture_provenance.py):
- silent_witness/v1
- silent_witness/v2
- revocation_witness/v1

Enforcement is fail-closed via zk/tools/fixture_provenance.py:
- absent provenance -> missing_provenance
- absent field -> missing_provenance_field
- declared schema != selected circuit schema -> schema_mismatch
- unrecognized schema string -> unsupported_statement_schema

Validation never reads or reflects witness field values.
