### Added

- Add read-only `preflight_statement` and `preflight_tier_statement` methods (plus `PreflightStage` and `StatementPreflightResult` types and canonical 128-byte browser `verifier_inputs::parse_browser_silent_witness` validation) to `HarpocratesRegistry` to validate public field structure and active registry policy without storing a proof or invoking cryptographic verification (#1199).
