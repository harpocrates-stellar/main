### Added

- Record `vector_generator`, `vector_generator_version`, `statement_schema`, and `statement_schema_version` in a top-level `fixture_provenance` envelope across Noir proof fixtures and export/generation manifests, keeping provenance strictly outside secret witness contents and rejecting fixtures whose declared schema conflicts with the selected circuit (#1212).
