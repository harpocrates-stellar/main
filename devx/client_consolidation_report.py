#!/usr/bin/env python3
"""Report competing client implementations of the verifier-input codec."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MAX_SOURCE_BYTES = 8 * 1024 * 1024
FORMAT = "harpocrates.protocol-client-consolidation-report"
SCHEMA_VERSION = 1

IMPLEMENTATIONS = (
    {
        "id": "browser",
        "path": "frontend/src/verifierInputs.ts",
        "language": "typescript",
        "import_root": "frontend/src",
    },
    {
        "id": "backend",
        "path": "backend/verifier_inputs.py",
        "language": "python",
        "import_root": "backend",
    },
)

TS_EXPORT_RE = re.compile(
    r"^\s*export\s+(?:async\s+)?(?:function|class)\s+([A-Za-z_$][\w$]*)",
    re.MULTILINE,
)
TS_IMPORT_RE = re.compile(
    r"""(?ms)^\s*import\s+(?:(?!^\s*import\b)[\s\S])*?\bfrom\s*(['"])([^'"]+)\1"""
)
TS_SIDE_EFFECT_IMPORT_RE = re.compile(r"""(?m)^\s*import\s*(['"])([^'"]+)\1""")


class ConsolidationReportError(ValueError):
    """Raised when an implementation cannot be safely inspected."""


def _read_source(path: Path) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ConsolidationReportError(f"cannot stat source: {path}") from exc
    if size > MAX_SOURCE_BYTES:
        raise ConsolidationReportError(
            f"source exceeds {MAX_SOURCE_BYTES} byte limit: {path}"
        )
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ConsolidationReportError(f"cannot read UTF-8 source: {path}") from exc


def _relative_path(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _normalized_symbol(name: str) -> str:
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", name)
    return snake.lower()


def _is_test_file(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    return (
        "test" in parts
        or "tests" in parts
        or "__tests__" in parts
        or name.startswith("test_")
        or name.endswith(("_test.py", ".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx"))
    )


def _python_entry_points(source: str, display_path: str) -> set[str]:
    try:
        tree = ast.parse(source, filename=display_path)
    except SyntaxError as exc:
        raise ConsolidationReportError(
            f"malformed Python source {display_path}:{exc.lineno}: {exc.msg}"
        ) from exc
    names = {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and not node.name.startswith("_")
    }
    return {_normalized_symbol(name) for name in names}


def _typescript_entry_points(source: str) -> set[str]:
    return {
        _normalized_symbol(match.group(1)) for match in TS_EXPORT_RE.finditer(source)
    }


def _python_imports(
    root: Path, target: Path, import_root: Path
) -> list[dict[str, Any]]:
    imports: list[dict[str, Any]] = []
    for source_path in sorted(import_root.rglob("*.py")):
        if _is_test_file(source_path):
            continue
        source = _read_source(source_path)
        try:
            tree = ast.parse(source, filename=_relative_path(source_path, root))
        except SyntaxError as exc:
            raise ConsolidationReportError(
                f"malformed Python source {_relative_path(source_path, root)}:"
                f"{exc.lineno}: {exc.msg}"
            ) from exc

        source_dir = source_path.parent
        target_resolved = target.resolve()
        for node in ast.walk(tree):
            candidates: list[Path] = []
            if isinstance(node, ast.ImportFrom) and node.module:
                parts = node.module.split(".")
                candidates.append(root.joinpath(*parts).with_suffix(".py"))
                candidates.append(source_dir.joinpath(*parts).with_suffix(".py"))
                if node.level:
                    base = source_dir
                    for _ in range(node.level):
                        base = base.parent
                    candidates.append(base.joinpath(*parts).with_suffix(".py"))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    parts = alias.name.split(".")
                    candidates.append(root.joinpath(*parts).with_suffix(".py"))

            if any(candidate.resolve() == target_resolved for candidate in candidates):
                imports.append(
                    {
                        "path": _relative_path(source_path, root),
                        "line": node.lineno,
                    }
                )
    return imports


def _typescript_imports(
    root: Path, target: Path, import_root: Path
) -> list[dict[str, Any]]:
    imports: list[dict[str, Any]] = []
    target_resolved = target.resolve()
    for source_path in sorted(
        path
        for pattern in ("*.ts", "*.tsx")
        for path in import_root.rglob(pattern)
        if not _is_test_file(path)
    ):
        source = _read_source(source_path)
        matches = [
            (match.start(), match.group(2)) for match in TS_IMPORT_RE.finditer(source)
        ]
        matches.extend(
            (match.start(), match.group(2))
            for match in TS_SIDE_EFFECT_IMPORT_RE.finditer(source)
        )
        for offset, specifier in matches:
            if not specifier.startswith("."):
                continue
            candidate = (source_path.parent / specifier).resolve()
            candidates = {
                candidate,
                candidate.with_suffix(".ts"),
                candidate.with_suffix(".tsx"),
                candidate / "index.ts",
                candidate / "index.tsx",
            }
            if target_resolved in candidates:
                imports.append(
                    {
                        "path": _relative_path(source_path, root),
                        "line": source.count("\n", 0, offset) + 1,
                    }
                )
    return imports


def build_report(root: Path = ROOT) -> dict[str, Any]:
    root = root.resolve()
    implementations: list[dict[str, Any]] = []
    entry_point_owners: dict[str, list[str]] = {}

    for spec in IMPLEMENTATIONS:
        target = root / spec["path"]
        if not target.is_file():
            raise ConsolidationReportError(
                f"required implementation is missing: {spec['path']}"
            )
        source = _read_source(target)
        if spec["language"] == "python":
            entry_points = _python_entry_points(source, spec["path"])
            active_imports = _python_imports(root, target, root / spec["import_root"])
        else:
            entry_points = _typescript_entry_points(source)
            active_imports = _typescript_imports(
                root, target, root / spec["import_root"]
            )

        for name in entry_points:
            entry_point_owners.setdefault(name, []).append(spec["id"])
        implementations.append(
            {
                "id": spec["id"],
                "path": spec["path"],
                "entry_points": sorted(entry_points),
                "active_import_paths": active_imports,
            }
        )

    duplicates = [
        {"name": name, "implementations": owners}
        for name, owners in sorted(entry_point_owners.items())
        if len(owners) > 1
    ]
    return {
        "format": FORMAT,
        "schema_version": SCHEMA_VERSION,
        "read_only": True,
        "helper": "hpx verifier-input codec",
        "status": "multiple_implementations"
        if duplicates
        else "no_duplicate_entry_points",
        "duplicate_exported_entry_points": duplicates,
        "implementations": implementations,
        "note": (
            "This report inventories implementations and production import sites "
            "for human consolidation review. It does not modify or remove code."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Report competing verifier-input codec implementations without changing source"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="repository root to inspect (defaults to this checkout)",
    )
    args = parser.parse_args(argv)
    if not args.root.is_dir():
        print(
            f"consolidation report failed: repository root not found: {args.root}",
            file=sys.stderr,
        )
        return 1
    try:
        report = build_report(args.root)
    except ConsolidationReportError as exc:
        print(f"consolidation report failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
