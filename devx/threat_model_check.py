#!/usr/bin/env python3
"""Automate the repository's threat-model security checklist."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CHECKS = (
    ("release", [sys.executable, "devx/release_guard.py"]),
    (
        "compatibility",
        [
            sys.executable,
            "devx/compatibility_report.py",
            "--verify-existing",
            "--stable",
            "--check",
        ],
    ),
    ("c2pa", [sys.executable, "devx/validate_c2pa_manifests.py"]),
    ("rfc3161", [sys.executable, "devx/validate_rfc3161_chains.py"]),
)


def run_check(command: list[str]) -> bool:
    """Run a checklist command from the repository root."""
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return False

    return result.returncode == 0


def main() -> int:
    """Run all threat-model checks and return a CI-friendly status."""
    results: dict[str, bool] = {}

    for name, command in CHECKS:
        success = run_check(command)
        results[name] = success
        print(f"{name}: {'PASS' if success else 'FAIL'}")

    failed = sum(not success for success in results.values())

    if failed:
        print(f"Overall: FAILURE ({failed} check(s) failed)")
        return 1

    print("Overall: SUCCESS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())