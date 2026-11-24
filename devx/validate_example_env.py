#!/usr/bin/env python3
"""Check committed environment examples against statically consumed keys.

Only the tracked example files and application source are inspected. Local
``.env`` files and the process environment are never read.
"""
from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
FRONTEND_ENV_REFERENCE = re.compile(
    r"(?:import\.meta\.env|process\.env)\??\.(VITE_[A-Za-z0-9_]+)"
)


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ExampleResult:
    name: str
    missing: tuple[str, ...]
    obsolete: tuple[str, ...]
    consumed_count: int
    example_count: int


def _read_example_keys(path: Path) -> set[str]:
    keys: set[str] = set()
    with path.open(encoding="utf-8") as example:
        for line in example:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                stripped = stripped[1:].lstrip()
                if "=" not in stripped:
                    continue
            if stripped.startswith("export "):
                stripped = stripped[len("export "):].lstrip()
            if "=" not in stripped:
                continue
            name = stripped.split("=", 1)[0].strip()
            if ENV_KEY.fullmatch(name):
                keys.add(name)
    return keys


def _is_env_getter(call: ast.Call, os_names: set[str]) -> bool:
    function = call.func
    if not isinstance(function, ast.Attribute):
        return False
    if function.attr == "getenv":
        return isinstance(function.value, ast.Name) and function.value.id in os_names
    if function.attr == "get" and isinstance(function.value, ast.Attribute):
        return (
            function.value.attr == "environ"
            and isinstance(function.value.value, ast.Name)
            and function.value.value.id in os_names
        )
    return False


def _is_os_environ(node: ast.expr, os_names: set[str]) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "environ"
        and isinstance(node.value, ast.Name)
        and node.value.id in os_names
    )


def _python_env_keys(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        raise ValidationError(
            f"{path}: invalid Python syntax at line {exc.lineno}"
        ) from exc

    os_names = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name == "os"
    }
    keys: set[str] = set()
    env_helpers: dict[str, set[int]] = {}
    string_constants: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        string_constants[target.id] = node.value.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            string_constants[node.target.id] = node.value.value

    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        parameters = [*function.args.posonlyargs, *function.args.args]
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Call)
                and _is_env_getter(node, os_names)
                and node.args
                and isinstance(node.args[0], ast.Name)
            ):
                for index, parameter in enumerate(parameters):
                    if parameter.arg == node.args[0].id:
                        env_helpers.setdefault(function.name, set()).add(index)

    changed = True
    while changed:
        changed = False
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            parameters = [*function.args.posonlyargs, *function.args.args]
            for node in ast.walk(function):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                    continue
                for index in env_helpers.get(node.func.id, set()):
                    if index < len(node.args) and isinstance(node.args[index], ast.Name):
                        for param_index, parameter in enumerate(parameters):
                            if parameter.arg == node.args[index].id:
                                helper_indices = env_helpers.setdefault(function.name, set())
                                if param_index not in helper_indices:
                                    helper_indices.add(param_index)
                                    changed = True

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_env_getter(node, os_names) and node.args:
            name = node.args[0]
            if isinstance(name, ast.Constant) and isinstance(name.value, str):
                keys.add(name.value)
            elif isinstance(name, ast.Name) and name.id in string_constants:
                keys.add(string_constants[name.id])

        if isinstance(node, ast.Subscript) and _is_os_environ(node.value, os_names):
            name = node.slice
            if isinstance(name, ast.Constant) and isinstance(name.value, str):
                keys.add(name.value)

    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        parameters = [*function.args.posonlyargs, *function.args.args]
        for index in env_helpers.get(function.name, set()):
            default_offset = len(parameters) - len(function.args.defaults)
            if index >= default_offset:
                default = function.args.defaults[index - default_offset]
                if isinstance(default, ast.Constant) and isinstance(default.value, str):
                    keys.add(default.value)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        for index in env_helpers.get(node.func.id, set()):
            if index < len(node.args):
                argument = node.args[index]
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    keys.add(argument.value)

    for loop in (node for node in ast.walk(tree) if isinstance(node, ast.For)):
        if not isinstance(loop.target, ast.Name):
            continue
        values = loop.iter
        if isinstance(values, (ast.Tuple, ast.List)):
            loop_keys = {
                item.value for item in values.elts
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            }
            if any(
                isinstance(node, ast.Call)
                and _is_env_getter(node, os_names)
                and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == loop.target.id
                for statement in loop.body
                for node in ast.walk(statement)
            ):
                keys.update(loop_keys)

    return keys


def _frontend_env_keys(paths: list[Path]) -> set[str]:
    keys: set[str] = set()
    for path in paths:
        source = path.read_text(encoding="utf-8")
        keys.update(FRONTEND_ENV_REFERENCE.findall(source))
    return keys


def compare_example(
    name: str, example_path: Path, consumed_keys: set[str]
) -> ExampleResult:
    example_keys = _read_example_keys(example_path)
    return ExampleResult(
        name=name,
        missing=tuple(sorted(consumed_keys - example_keys)),
        obsolete=tuple(sorted(example_keys - consumed_keys)),
        consumed_count=len(consumed_keys),
        example_count=len(example_keys),
    )


def _backend_keys() -> set[str]:
    source_files = sorted((ROOT / "backend").rglob("*.py"))
    source_files = [
        path for path in source_files
        if not path.name.startswith("test_") and path.parent.name != "tests"
    ]
    keys: set[str] = set()
    for path in source_files:
        keys.update(_python_env_keys(path))
    return keys


def _frontend_keys() -> set[str]:
    source_files = sorted((ROOT / "frontend" / "src").rglob("*"))
    return _frontend_env_keys([
        path for path in source_files
        if path.is_file()
        and path.suffix in {".ts", ".tsx", ".js", ".jsx"}
        and ".test." not in path.name
        and ".spec." not in path.name
        and "__tests__" not in path.parts
    ])


def _format_result(result: ExampleResult) -> list[str]:
    if not result.missing and not result.obsolete:
        return [
            f"{result.name}: OK "
            f"({result.consumed_count} consumed keys, "
            f"{result.example_count} example keys)"
        ]
    lines = [f"{result.name}: mismatched environment keys"]
    if result.missing:
        lines.append(f"  missing consumed keys: {', '.join(result.missing)}")
    if result.obsolete:
        lines.append(f"  obsolete example entries: {', '.join(result.obsolete)}")
    return lines


def main() -> int:
    try:
        results = (
            compare_example(
                "backend",
                ROOT / "backend" / ".env.example",
                _backend_keys(),
            ),
            compare_example(
                "frontend",
                ROOT / "frontend" / ".env.example",
                _frontend_keys(),
            ),
        )
    except (OSError, ValidationError) as exc:
        print(f"environment example validation failed: {exc}", file=sys.stderr)
        return 2

    for result in results:
        for line in _format_result(result):
            print(line)
    return 1 if any(result.missing or result.obsolete for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
