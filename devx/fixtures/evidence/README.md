# Deterministic Synthetic Evidence Fixture Inventory

This directory contains the canonical inventory of all synthetic evidence fixtures used across the Harpocrates codebase for offline/CI validation.

## Purpose

The inventory maps every fixture to its generator, license, and schema version, enabling:
- **Staleness detection**: SHA256 drift detection without using real sensitive media
- **License compliance**: All fixtures use approved OSS licenses
- **Schema versioning**: Explicit schema version per fixture for forward compatibility
- **Generator traceability**: Each fixture declares its generation script/tool
- **Validator binding**: Each fixture declares its validation entry point

## Inventory Format

The inventory (`inventory.json`) follows the `harpocrates.evidence-fixture-inventory` format:

```json
{
  "schemaVersion": 1,
  "format": "harpocrates.evidence-fixture-inventory",
  "generatedBy": "devx/validate_evidence_inventory.py",
  "generatedAt": "2026-11-23T13:41:00Z",
  "fixtures": [
    {
      "id": "unique/fixture-id",
      "path": "relative/path/to/fixture.json",
      "description": "Human-readable description",
      "generator": "path/to/generator.py or CLI command",
      "license": "Apache-2.0",
      "schemaVersion": 1,
      "sha256": "hex-encoded-sha256-of-fixture-file",
      "validator": "path/to/validator.py",
      "allowSensitiveKeys": false,
      "expect": { "ok": true, "status": "valid" }
    }
  ]
}
```

### Field Reference

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier (namespaced by category) |
| `path` | Yes | Repository-relative path to fixture file |
| `description` | Yes | Human-readable purpose |
| `generator` | Yes | Script or command that produces the fixture |
| `license` | Yes | SPDX license identifier (approved: Apache-2.0, MIT, BSD-3-Clause, BSD-2-Clause, ISC, MPL-2.0) |
| `schemaVersion` | Yes | Fixture schema version (currently 1) |
| `sha256` | Yes | SHA256 of fixture file for drift detection |
| `validator` | Yes | Validation script that consumes this fixture |
| `allowSensitiveKeys` | No | If true, permits keys like `witness`, `credential_secret` in synthetic test vectors (default: false) |
| `expect` | No | Expected validation outcome for positive/negative fixtures |

## Fixture Categories

### RFC 3161 Certificate Chains (`rfc3161/`)
Synthetic X.509 certificate chains for TSA trust path validation.
- **Generator**: `devx/fixtures/rfc3161/generate.py`
- **Validator**: `devx/validate_rfc3161_chains.py`
- **Fixtures**: 5 (1 positive, 4 negative)

### C2PA Manifests (`c2pa/`)
Synthetic C2PA manifests for bounded manifest parsing validation.
- **Generator**: `devx/fixtures/c2pa/generate.py` / `cli/dist/cli.js c2pa`
- **Validators**: `devx/validate_c2pa_manifests.py`, `devx/validate_c2pa_fixture.py`
- **Fixtures**: 9 (manifests, receipts, exports)

### E2E Environment Matrix (`e2e-env-matrix/`)
Environment profiles for end-to-end integration testing.
- **Generator**: `devx/fixtures/e2e-env-matrix/generate.py`
- **Validator**: `devx/e2e_env_matrix.py`
- **Fixtures**: 1

### Noir Circuit Vectors (`noir/`)
Shared conformance vectors for Noir ZK circuits and Soroban contracts.
- **Generator**: `zk/noir/fixtures/generate.py`
- **Validator**: `nargo test`
- **Fixtures**: 3 (aggregation, revocation, scoped nullifier)
- **Note**: Marked `allowSensitiveKeys: true` — contain synthetic test vectors with placeholder values (e.g., `12345`, `67890`), not real secrets

## Validation

Run the inventory validator:

```bash
# Standard validation (warns on drift)
python3 devx/validate_evidence_inventory.py

# Strict validation (fails on drift)
python3 devx/validate_evidence_inventory.py --check-stale

# Regenerate inventory with current hashes
python3 devx/validate_evidence_inventory.py --write-inventory
```

### Exit Codes
- `0` — All fixtures valid
- `1` — Validation failure (missing, stale, schema mismatch, invalid license)
- `2` — Usage/dependency error

## Adding New Fixtures

1. Place fixture file in appropriate subdirectory under `devx/fixtures/` or `zk/noir/fixtures/`
2. Add entry to `inventory.json` with all required fields
3. Compute SHA256: `python3 -c "import hashlib; print(hashlib.sha256(open('path').read_bytes()).hexdigest())"`
4. Run validator to confirm: `python3 devx/validate_evidence_inventory.py`
5. Add test coverage in `devx/test_validate_evidence_inventory.py`

## Security & Privacy

- **No real media**: Fixtures contain only synthetic data, placeholders, or test vectors
- **No credentials**: Private keys, seeds, witnesses, nullifiers, API tokens never appear
- **Fail-closed**: Validation rejects fixtures with unexpected sensitive key patterns (unless `allowSensitiveKeys: true` for known synthetic test vectors)
- **Deterministic**: Generators must produce byte-identical output across runs

## License Compliance

All fixtures must use an approved OSS license. The inventory validates against:
- Apache-2.0
- MIT
- BSD-3-Clause
- BSD-2-Clause
- ISC
- MPL-2.0

Proprietary or copyleft licenses (GPL, AGPL) are rejected.