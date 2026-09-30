"""Tests for the RFC 3161 chain fixture validator CLI."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = Path(__file__).resolve().parent / "validate_rfc3161_chains.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "rfc3161"


def test_cli_passes_bundled_fixtures():
    proc = subprocess.run(
        [sys.executable, str(CLI)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "fixtures passed" in proc.stdout


def test_cli_single_valid_fixture():
    path = FIXTURES / "valid-leaf-int-root.json"
    proc = subprocess.run(
        [sys.executable, str(CLI), str(path)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "PASS" in proc.stdout
