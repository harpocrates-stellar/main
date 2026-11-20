#!/usr/bin/env python3
"""Validate RFC 3161 TSA certificate-chain fixtures (offline / CI).

Usage:
  python3 devx/validate_rfc3161_chains.py
  python3 devx/validate_rfc3161_chains.py path/to/fixture.json

Exit codes:
  0 — all fixtures match expectations (or validate successfully)
  1 — validation or expectation failure
  2 — usage / dependency error

Never prints certificate material, private keys, or media paths.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
DEFAULT_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "rfc3161"

sys.path.insert(0, str(BACKEND))

try:
    from rfc3161_chain import validate_chain_document
except Exception as exc:  # pragma: no cover
    print(f"dependency_failure: cannot import rfc3161_chain ({type(exc).__name__})", file=sys.stderr)
    sys.exit(2)


def _load(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read fixture {path.name}: {type(exc).__name__}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"fixture {path.name} must be a JSON object")
    return data


def _check_expect(result, expect: dict | None, name: str) -> list[str]:
    if not expect:
        return [] if result.ok else [f"{name}: validation failed ({result.error_code})"]
    errors: list[str] = []
    if "ok" in expect and bool(expect["ok"]) != result.ok:
        errors.append(f"{name}: ok expected {expect['ok']} got {result.ok}")
    if "status" in expect and expect["status"] != result.status:
        errors.append(f"{name}: status expected {expect['status']} got {result.status}")
    if "errorCode" in expect and expect["errorCode"] != result.error_code:
        errors.append(f"{name}: errorCode expected {expect['errorCode']} got {result.error_code}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate RFC 3161 certificate-chain fixtures")
    parser.add_argument("paths", nargs="*", help="Fixture JSON files (default: fixtures/rfc3161/*.json)")
    args = parser.parse_args(argv)

    if args.paths:
        paths = [Path(p) for p in args.paths]
    else:
        paths = sorted(DEFAULT_FIXTURES.glob("*.json"))

    if not paths:
        print("no fixtures found", file=sys.stderr)
        return 2

    failures: list[str] = []
    passed = 0
    for path in paths:
        doc = _load(path)
        result = validate_chain_document(doc)
        expect = doc.get("expect") if isinstance(doc.get("expect"), dict) else None
        errs = _check_expect(result, expect, path.name)
        if errs:
            failures.extend(errs)
        else:
            passed += 1
            status = result.status
            code = result.error_code or "ok"
            print(f"PASS {path.name} status={status} code={code}")

    if failures:
        for item in failures:
            print(f"FAIL {item}", file=sys.stderr)
        print(f"{passed} passed, {len(failures)} failed", file=sys.stderr)
        return 1

    print(f"{passed} fixtures passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
