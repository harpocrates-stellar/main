"""Tests for the evidence fixture inventory validator."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = Path(__file__).resolve().parent / "validate_evidence_inventory.py"
INVENTORY = Path(__file__).resolve().parent / "fixtures" / "evidence" / "inventory.json"


def test_cli_passes_current_inventory():
    proc = subprocess.run(
        [sys.executable, str(CLI)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "fixtures valid" in proc.stdout


def test_cli_check_stale_passes():
    proc = subprocess.run(
        [sys.executable, str(CLI), "--check-stale"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "fixtures valid" in proc.stdout


def test_inventory_structure():
    data = json.loads(INVENTORY.read_text(encoding="utf-8"))
    assert data["format"] == "harpocrates.evidence-fixture-inventory"
    assert data["schemaVersion"] == 1
    assert "fixtures" in data
    assert isinstance(data["fixtures"], list)
    assert len(data["fixtures"]) == 18

    # Verify required fields on each fixture
    for fixture in data["fixtures"]:
        for field in ("id", "path", "description", "generator", "license", "schemaVersion", "sha256", "validator"):
            assert field in fixture, f"Missing {field} in {fixture.get('id', 'unknown')}"
        assert fixture["schemaVersion"] == 1
        assert fixture["license"] in {"Apache-2.0", "MIT", "BSD-3-Clause", "BSD-2-Clause", "ISC", "MPL-2.0"}
        # Path must exist
        abs_path = ROOT / fixture["path"]
        assert abs_path.is_file(), f"Fixture file not found: {fixture['path']}"


def test_inventory_detects_missing_fixture():
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        bad_inventory = {
            "format": "harpocrates.evidence-fixture-inventory",
            "schemaVersion": 1,
            "fixtures": [
                {
                    "id": "test/missing",
                    "path": "devx/fixtures/evidence/nonexistent.json",
                    "description": "Test fixture",
                    "generator": "test",
                    "license": "Apache-2.0",
                    "schemaVersion": 1,
                    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                    "validator": "test",
                }
            ],
        }
        json.dump(bad_inventory, handle)
        bad_path = Path(handle.name)

    try:
        proc = subprocess.run(
            [sys.executable, str(CLI), "--inventory", str(bad_path)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 1
        assert "not found" in proc.stderr
    finally:
        bad_path.unlink()


def test_inventory_detects_sha256_mismatch():
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        bad_inventory = {
            "format": "harpocrates.evidence-fixture-inventory",
            "schemaVersion": 1,
            "fixtures": [
                {
                    "id": "rfc3161/valid-leaf-int-root",
                    "path": "devx/fixtures/rfc3161/valid-leaf-int-root.json",
                    "description": "Test fixture",
                    "generator": "test",
                    "license": "Apache-2.0",
                    "schemaVersion": 1,
                    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                    "validator": "test",
                }
            ],
        }
        json.dump(bad_inventory, handle)
        bad_path = Path(handle.name)

    try:
        proc = subprocess.run(
            [sys.executable, str(CLI), "--inventory", str(bad_path), "--check-stale"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 1
        assert "STALE" in proc.stderr or "sha256 mismatch" in proc.stderr
    finally:
        bad_path.unlink()


def test_inventory_rejects_invalid_license():
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        bad_inventory = {
            "format": "harpocrates.evidence-fixture-inventory",
            "schemaVersion": 1,
            "fixtures": [
                {
                    "id": "test/bad-license",
                    "path": "devx/fixtures/rfc3161/valid-leaf-int-root.json",
                    "description": "Test fixture",
                    "generator": "test",
                    "license": "GPL-3.0",  # Not in approved list
                    "schemaVersion": 1,
                    "sha256": "18d616bed79ab199461e6bab26bcff9566ffbdb2ff031a77a55d57c17168c8a6",
                    "validator": "test",
                }
            ],
        }
        json.dump(bad_inventory, handle)
        bad_path = Path(handle.name)

    try:
        proc = subprocess.run(
            [sys.executable, str(CLI), "--inventory", str(bad_path)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 1
        assert "license" in proc.stderr.lower()
    finally:
        bad_path.unlink()


def test_inventory_allows_sensitive_keys_for_test_vectors():
    # Noir fixtures have synthetic test vectors with keys like "witness", "credential_secret"
    # They should pass validation because allowSensitiveKeys is true
    proc = subprocess.run(
        [sys.executable, str(CLI)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    # Verify noir fixtures are in the inventory with allowSensitiveKeys
    data = json.loads(INVENTORY.read_text(encoding="utf-8"))
    noir_fixtures = [f for f in data["fixtures"] if f["id"].startswith("noir/")]
    for fixture in noir_fixtures:
        assert fixture.get("allowSensitiveKeys") is True, f"{fixture['id']} should allow sensitive keys"


def test_write_inventory_updates_hashes():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_inv = Path(tmpdir) / "inventory.json"
        # Copy current inventory
        import shutil
        shutil.copy2(INVENTORY, tmp_inv)

        proc = subprocess.run(
            [sys.executable, str(CLI), "--inventory", str(tmp_inv), "--write-inventory"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert "regenerated" in proc.stdout

        # Verify hashes were updated (they should be the same since files didn't change)
        updated = json.loads(tmp_inv.read_text(encoding="utf-8"))
        original = json.loads(INVENTORY.read_text(encoding="utf-8"))
        for u, o in zip(updated["fixtures"], original["fixtures"]):
            assert u["sha256"] == o["sha256"]


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))