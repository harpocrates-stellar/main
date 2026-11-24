#!/usr/bin/env python3
"""Validate the deterministic synthetic evidence fixture inventory.

Usage:
  python3 devx/validate_evidence_inventory.py
  python3 devx/validate_evidence_inventory.py --check-stale
  python3 devx/validate_evidence_inventory.py --write-inventory

Exit codes:
  0 — inventory is valid and all fixtures match
  1 — validation failure (missing, stale, or schema mismatch)
  2 — usage / dependency error

Never prints sensitive material, private keys, media paths, or credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = Path(__file__).resolve().parent / "fixtures" / "evidence" / "inventory.json"
FORMAT = "harpocrates.evidence-fixture-inventory"
INVENTORY_SCHEMA_VERSION = 1
MAX_FIXTURE_BYTES = 8 * 1024 * 1024  # 8 MiB

# Match concrete secret-bearing field names only
SENSITIVE_KEY_RE = re.compile(
    r"^(password|secret|private[_-]?key|witness|nullifier|credential|"
    r"proof_bytes|mnemonic|api[_-]?token|access[_-]?token|refresh[_-]?token)$",
    re.IGNORECASE,
)


class InventoryError(ValueError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def read_json_bounded(path: Path, limit: int = MAX_FIXTURE_BYTES) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise InventoryError(f"cannot read {_display_path(path)}: {exc}") from exc
    if size > limit:
        raise InventoryError(f"{_display_path(path)} exceeds the {limit} byte limit")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InventoryError(f"malformed JSON in {_display_path(path)}: {exc}") from exc


def _reject_sensitive_keys(value: Any, location: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if SENSITIVE_KEY_RE.search(str(key)):
                raise InventoryError(f"{location} contains forbidden sensitive field '{key}'")
            _reject_sensitive_keys(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_sensitive_keys(child, f"{location}[{index}]")


def validate_inventory(inventory: dict[str, Any]) -> list[str]:
    """Validate inventory structure and return list of errors (empty if valid)."""
    errors: list[str] = []

    if inventory.get("format") != FORMAT:
        errors.append(f"inventory.format must be '{FORMAT}'")
    if inventory.get("schemaVersion") != INVENTORY_SCHEMA_VERSION:
        errors.append(f"inventory.schemaVersion must be {INVENTORY_SCHEMA_VERSION}")

    fixtures = inventory.get("fixtures")
    if not isinstance(fixtures, list):
        errors.append("inventory.fixtures must be a list")
        return errors

    seen_ids = set()
    for idx, fixture in enumerate(fixtures):
        prefix = f"fixtures[{idx}]"
        if not isinstance(fixture, dict):
            errors.append(f"{prefix}: must be an object")
            continue

        # Required fields
        for field in ("id", "path", "description", "generator", "license", "schemaVersion", "sha256", "validator"):
            if field not in fixture:
                errors.append(f"{prefix}: missing required field '{field}'")

        fid = fixture.get("id")
        if fid:
            if fid in seen_ids:
                errors.append(f"{prefix}: duplicate fixture id '{fid}'")
            seen_ids.add(fid)

        # Schema version check
        sv = fixture.get("schemaVersion")
        if isinstance(sv, int) and sv != 1:
            errors.append(f"{prefix}: fixture schemaVersion must be 1, got {sv}")

        # License check (allow common OSS licenses)
        valid_licenses = {"Apache-2.0", "MIT", "BSD-3-Clause", "BSD-2-Clause", "ISC", "MPL-2.0"}
        license_val = fixture.get("license")
        if license_val and license_val not in valid_licenses:
            errors.append(f"{prefix}: license '{license_val}' not in approved list")

        # Path must be relative and within repo
        rel_path = fixture.get("path")
        if rel_path:
            abs_path = ROOT / rel_path
            try:
                abs_path.resolve().relative_to(ROOT)
            except ValueError:
                errors.append(f"{prefix}: path '{rel_path}' escapes repository root")

    return errors


def check_fixtures(inventory: dict[str, Any], check_stale: bool = False) -> tuple[list[str], list[str]]:
    """Check each fixture file exists, matches hash, and is privacy-safe.
    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []
    fixtures = inventory.get("fixtures", [])

    for fixture in fixtures:
        fid = fixture.get("id", "unknown")
        rel_path = fixture.get("path")
        expected_sha256 = fixture.get("sha256")
        fschema_version = fixture.get("schemaVersion")

        if not rel_path:
            errors.append(f"{fid}: missing path")
            continue

        abs_path = ROOT / rel_path

        if not abs_path.is_file():
            errors.append(f"{fid}: fixture file not found at {rel_path}")
            continue

        # Check file size
        try:
            size = abs_path.stat().st_size
        except OSError as exc:
            errors.append(f"{fid}: cannot stat {rel_path}: {exc}")
            continue

        if size > MAX_FIXTURE_BYTES:
            errors.append(f"{fid}: fixture exceeds {MAX_FIXTURE_BYTES} byte limit ({size} bytes)")

        # Check SHA256
        actual_sha256 = sha256_file(abs_path)
        if expected_sha256 and actual_sha256 != expected_sha256:
            if check_stale:
                errors.append(f"{fid}: STALE — sha256 mismatch (expected {expected_sha256[:16]}..., got {actual_sha256[:16]}...)")
            else:
                warnings.append(f"{fid}: sha256 drift detected (expected {expected_sha256[:16]}..., got {actual_sha256[:16]}...)")

        # Validate fixture content (JSON, no sensitive keys)
        try:
            content = read_json_bounded(abs_path)
            if not fixture.get("allowSensitiveKeys", False):
                _reject_sensitive_keys(content, f"{fid}@{rel_path}")

            # Check fixture's own schemaVersion if present
            content_sv = content.get("schemaVersion")
            if content_sv is not None and fschema_version is not None and content_sv != fschema_version:
                warnings.append(f"{fid}: fixture schemaVersion ({content_sv}) != inventory schemaVersion ({fschema_version})")

        except InventoryError as exc:
            errors.append(f"{fid}: {exc}")
        except json.JSONDecodeError:
            # Non-JSON fixtures (e.g., binary) — skip content validation
            pass

    return errors, warnings


def write_inventory(inventory: dict[str, Any], output: Path) -> None:
    """Write updated inventory with current timestamp."""
    inventory["generatedAt"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    inventory["generatedBy"] = "devx/validate_evidence_inventory.py"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(canonical_json(inventory), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate evidence fixture inventory")
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument(
        "--check-stale",
        action="store_true",
        help="Fail on SHA256 drift (treat drift as error, not warning)",
    )
    parser.add_argument(
        "--write-inventory",
        action="store_true",
        help="Regenerate inventory with current hashes and timestamp",
    )
    args = parser.parse_args(argv)

    try:
        inventory = read_json_bounded(args.inventory)
    except InventoryError as exc:
        print(f"inventory load failed: {exc}", file=sys.stderr)
        return 2

    # Validate inventory structure
    struct_errors = validate_inventory(inventory)
    if struct_errors:
        for err in struct_errors:
            print(f"INVALID {err}", file=sys.stderr)
        return 1

    if args.write_inventory:
        # Update all hashes to current files
        for fixture in inventory.get("fixtures", []):
            rel_path = fixture.get("path")
            if rel_path:
                abs_path = ROOT / rel_path
                if abs_path.is_file():
                    fixture["sha256"] = sha256_file(abs_path)
        write_inventory(inventory, args.inventory)
        print(f"Inventory regenerated: {args.inventory}")
        return 0

    # Check fixtures
    errors, warnings = check_fixtures(inventory, check_stale=args.check_stale)

    for warning in warnings:
        print(f"WARN {warning}")

    if errors:
        for err in errors:
            print(f"FAIL {err}", file=sys.stderr)
        print(f"{len(errors)} error(s), {len(warnings)} warning(s)", file=sys.stderr)
        return 1

    print(f"All {len(inventory.get('fixtures', []))} fixtures valid")
    if warnings:
        print(f"{len(warnings)} warning(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())