#!/usr/bin/env python3
"""Verify CLI package export targets exist after a clean build.

Resolves every public export defined in cli/package.json and confirms the
corresponding built artifact exists in the dist/ directory. Rejects missing
targets or paths that escape the package build directory.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CLI_PACKAGE = ROOT / "cli" / "package.json"
CLI_DIST = ROOT / "cli" / "dist"


class ExportError(ValueError):
    pass


def read_package_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExportError(f"cannot read package.json: {exc}") from exc
    if not isinstance(value, dict):
        raise ExportError("package.json must be a JSON object")
    return value


def extract_exports(package: dict[str, Any]) -> dict[str, str]:
    exports = package.get("exports")
    if not isinstance(exports, dict):
        raise ExportError("package.json missing or invalid 'exports' field")
    result: dict[str, str] = {}
    for key, value in exports.items():
        if isinstance(value, str):
            result[key] = value
        elif isinstance(value, dict):
            import_value = value.get("import") or value.get("default")
            if isinstance(import_value, str):
                result[key] = import_value
            else:
                raise ExportError(f"export '{key}' has no valid import/default string")
        else:
            raise ExportError(f"export '{key}' has unsupported type")
    return result


def resolve_export_path(export_path: str, package_root: Path, dist_root: Path) -> Path:
    if not export_path.startswith("./"):
        raise ExportError(f"export path must be relative (start with './'): {export_path}")
    rel = export_path[2:]
    if rel.startswith("dist/"):
        rel = rel[5:]
    candidate = (dist_root / rel).resolve()
    if dist_root not in candidate.parents and candidate != dist_root:
        raise ExportError(f"export path escapes dist directory: {export_path}")
    return candidate


def verify_exports(exports: dict[str, str], dist_root: Path) -> list[str]:
    missing: list[str] = []
    for name, export_path in exports.items():
        try:
            resolved = resolve_export_path(export_path, ROOT, dist_root)
        except ExportError as exc:
            missing.append(f"{name}: {exc}")
            continue
        if not resolved.is_file():
            try:
                rel = resolved.relative_to(ROOT)
            except ValueError:
                rel = resolved
            missing.append(f"{name}: missing file at {rel}")
    return missing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify CLI package export targets exist after a clean build"
    )
    parser.add_argument(
        "--package",
        type=Path,
        default=CLI_PACKAGE,
        help="Path to cli/package.json",
    )
    parser.add_argument(
        "--dist",
        type=Path,
        default=CLI_DIST,
        help="Path to cli/dist directory",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all resolved export targets without verification",
    )
    args = parser.parse_args(argv)

    try:
        package = read_package_json(args.package.resolve())
        exports = extract_exports(package)

        if args.list:
            for name, export_path in sorted(exports.items()):
                try:
                    resolved = resolve_export_path(export_path, ROOT, args.dist.resolve())
                    status = "exists" if resolved.is_file() else "MISSING"
                    print(f"{name}: {export_path} -> {resolved.relative_to(ROOT)} [{status}]")
                except ExportError as exc:
                    print(f"{name}: {export_path} -> ERROR: {exc}")
            return 0

        missing = verify_exports(exports, args.dist.resolve())
        if missing:
            print("CLI export verification failed:", file=sys.stderr)
            for item in missing:
                print(f"  - {item}", file=sys.stderr)
            return 1

        print(f"CLI export verification passed: {len(exports)} targets verified")
        return 0

    except ExportError as exc:
        print(f"CLI export verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())