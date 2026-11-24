#!/usr/bin/env python3
"""Check that documented contributor commands point at committed entry points.

Contributor docs are executable instructions.  When an entry point is renamed
or a workspace is removed, a command can keep looking plausible while failing
on a clean checkout.  This checker reads the contributor-facing Markdown and
reports every command whose script, module, test target, npm workspace, npm
script, or ``cd`` directory is not present in the checkout.

The check is deliberately static: it never executes a documented command,
never fetches anything, and needs no credentials.  Generated paths (outputs,
reports, temporary directories) and external toolchain commands are not entry
points and are ignored, so a contributor can follow the docs before those
files exist.  Findings include ``document:line`` so a reviewer can fix the
source document rather than guessing which snippet is obsolete.

Exit codes
----------
  0   every documented entry point is committed
  1   at least one obsolete command was found
  2   an explicitly requested document could not be read
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

ROOT = Path(__file__).resolve().parents[1]

# Contributor-facing documents checked by default.  Pass explicit paths (files
# or directories) to check a different set; missing default files are skipped
# so a partial checkout does not turn into a false finding.
DEFAULT_DOCUMENTS = (
    "CONTRIBUTING.md",
    "docs/release-operations.md",
    "docs/dependency-pins.md",
    "docs/proof-artifact-retention.md",
    "devx/coverage/README.md",
    "contracts/README.md",
    "DEPLOY.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
)

PYTHON_LAUNCHERS = {"python", "python3", "py"}
# Modules that are installed outside the checkout (or are part of the stdlib).
# ``pytest``/``unittest``/``pip`` still get their path arguments checked below.
EXTERNAL_PYTHON_MODULES = {
    "pip",
    "venv",
    "ensurepip",
    "unittest",
    "pytest",
    "coverage",
    "json",
    "json.tool",
    "http",
    "site",
    "compileall",
}
ENTRY_SUFFIXES = {
    ".py",
    ".sh",
    ".mjs",
    ".js",
    ".ts",
    ".json",
    ".toml",
    ".txt",
    ".yml",
    ".yaml",
}
REPO_DIRECTORIES = {
    "backend",
    "cli",
    "contracts",
    "devx",
    "docs",
    "frontend",
    "release",
    "scripts",
    "zk",
    ".github",
}
COMMAND_PREFIXES = PYTHON_LAUNCHERS | {
    "cd",
    "gh",
    "git",
    "npm",
    "npx",
    "pip",
    "pip3",
    "pre-commit",
    "pytest",
}
OUTPUT_VALUE_OPTIONS = {
    "--output",
    "-o",
    "--out",
    "--output-path",
    "--report",
    "--report-file",
    "--log-file",
    "--dest",
    "--destination",
}
COMMAND_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")
PLACEHOLDER_RE = re.compile(r"^(?:<.*>|\$[\w{].*|\{\{.*\}\}|~.*)$")
MARKDOWN_PREFIX_RE = re.compile(r"^(?:[$>]\s*|[-*+]\s+|\d+\.\s+)+")


@dataclass(frozen=True)
class Finding:
    """One obsolete command with the location of the document that holds it."""

    document: Path
    line: int
    command: str
    reason: str

    def format(self, root: Path | None = None) -> str:
        document = self.document
        if root is not None:
            try:
                document = document.relative_to(root)
            except ValueError:
                pass
        return f"{document.as_posix()}:{self.line}: obsolete command {self.command!r} ({self.reason})"


def _display(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _dedupe(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[Path, int, str, str]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.document, finding.line, finding.command, finding.reason)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result


def _strip_comment(text: str) -> str:
    quote: str | None = None
    for index, char in enumerate(text):
        if char in {"'", '"'}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
        elif (
            char == "#" and quote is None and (index == 0 or text[index - 1].isspace())
        ):
            return text[:index]
    return text


def _split_segments(line: str) -> list[str]:
    text = MARKDOWN_PREFIX_RE.sub("", line.strip())
    text = _strip_comment(text).strip()
    if not text:
        return []
    return [
        part.strip().strip("`").strip()
        for part in COMMAND_SPLIT_RE.split(text)
        if part.strip()
    ]


def _is_placeholder(token: str) -> bool:
    return (
        bool(PLACEHOLDER_RE.match(token)) or "<dir>" in token or "<workspace>" in token
    )


def _clean_token(token: str) -> str:
    return token.strip().strip("'\"")


def _looks_like_repo_path(token: str) -> bool:
    token = _clean_token(token)
    if not token or token.startswith(("-", "/", ".", "~")) or "://" in token:
        return False
    if _is_placeholder(token) or any(char in token for char in "*?[]"):
        return False
    first = token.split("/", 1)[0]
    if first not in REPO_DIRECTORIES:
        return False
    return (
        Path(token).suffix in ENTRY_SUFFIXES
        or "/" in token
        or first in REPO_DIRECTORIES
    )


def _resolve(token: str, cwd: Path) -> Path:
    token = _clean_token(token)
    path = Path(token)
    return path if path.is_absolute() else cwd / path


def _skip_option_values(args: Sequence[str]) -> set[str]:
    skipped: set[str] = set()
    for index, arg in enumerate(args):
        if arg in OUTPUT_VALUE_OPTIONS and index + 1 < len(args):
            skipped.add(_clean_token(args[index + 1]))
        for option in OUTPUT_VALUE_OPTIONS:
            if arg.startswith(option + "="):
                skipped.add(_clean_token(arg.split("=", 1)[1]))
    return skipped


def _missing_path(
    path: Path,
    root: Path,
    document: Path,
    line: int,
    command: str,
    findings: list[Finding],
    label: str = "entry point",
) -> bool:
    if path.exists():
        return False
    findings.append(
        Finding(
            document,
            line,
            command,
            f"{label} {_display(path, root)!r} is not committed in the checkout",
        )
    )
    return True


def _check_path_arguments(
    args: Sequence[str],
    cwd: Path,
    root: Path,
    document: Path,
    line: int,
    command: str,
    findings: list[Finding],
) -> None:
    skipped = _skip_option_values(args)
    for token in args:
        if token.startswith("-") or _clean_token(token) in skipped:
            continue
        if _looks_like_repo_path(token):
            _missing_path(_resolve(token, cwd), root, document, line, command, findings)


def _check_unittest(
    args: Sequence[str],
    cwd: Path,
    root: Path,
    document: Path,
    line: int,
    command: str,
    findings: list[Finding],
) -> None:
    if "discover" in args:
        for index, token in enumerate(args):
            if token in {"-s", "--start-directory"} and index + 1 < len(args):
                _missing_path(
                    _resolve(args[index + 1], cwd),
                    root,
                    document,
                    line,
                    command,
                    findings,
                    "test directory",
                )
    _check_path_arguments(args, cwd, root, document, line, command, findings)


def _check_requirements(
    args: Sequence[str],
    cwd: Path,
    root: Path,
    document: Path,
    line: int,
    command: str,
    findings: list[Finding],
) -> None:
    for index, token in enumerate(args):
        if token in {"-r", "--requirement"} and index + 1 < len(args):
            _missing_path(
                _resolve(args[index + 1], cwd),
                root,
                document,
                line,
                command,
                findings,
                "requirements file",
            )


def _check_python(
    args: Sequence[str],
    cwd: Path,
    root: Path,
    document: Path,
    line: int,
    command: str,
    findings: list[Finding],
) -> None:
    index = 0
    while index < len(args):
        token = args[index]
        if token == "-m" and index + 1 < len(args):
            module = args[index + 1]
            remainder = args[index + 2 :]
            index += 2
            if module in EXTERNAL_PYTHON_MODULES:
                if module == "pytest":
                    _check_path_arguments(
                        remainder, cwd, root, document, line, command, findings
                    )
                elif module == "unittest":
                    _check_unittest(
                        remainder, cwd, root, document, line, command, findings
                    )
                elif module == "pip":
                    _check_requirements(
                        remainder, cwd, root, document, line, command, findings
                    )
                continue
            module_path = root / Path(*module.split("."))
            script = module_path.with_suffix(".py")
            if not script.is_file() and not (module_path / "__init__.py").is_file():
                _missing_path(
                    script,
                    root,
                    document,
                    line,
                    command,
                    findings,
                    "module entry point",
                )
            _check_path_arguments(
                remainder, cwd, root, document, line, command, findings
            )
            return
        if token in {"-r", "--requirement"} and index + 1 < len(args):
            _missing_path(
                _resolve(args[index + 1], cwd),
                root,
                document,
                line,
                command,
                findings,
                "requirements file",
            )
        elif token.endswith(".py") and _looks_like_repo_path(token):
            _missing_path(_resolve(token, cwd), root, document, line, command, findings)
        index += 1
    _check_path_arguments(args, cwd, root, document, line, command, findings)


def _read_package_json(path: Path) -> dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _check_npm(
    args: Sequence[str],
    cwd: Path,
    root: Path,
    document: Path,
    line: int,
    command: str,
    findings: list[Finding],
) -> None:
    workspaces: list[str] = []
    prefix: str | None = None
    filtered: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token in {"--workspace", "-w"} and index + 1 < len(args):
            workspaces.append(_clean_token(args[index + 1]))
            index += 2
            continue
        if token.startswith("--workspace=") or token.startswith("-w="):
            workspaces.append(_clean_token(token.split("=", 1)[1]))
            index += 1
            continue
        if token == "--prefix" and index + 1 < len(args):
            prefix = _clean_token(args[index + 1])
            index += 2
            continue
        filtered.append(token)
        index += 1

    effective_cwd = _resolve(prefix, cwd) if prefix else cwd
    subcommand = next((token for token in filtered if not token.startswith("-")), "")
    script: str | None = None
    if subcommand == "run" and len(filtered) > filtered.index(subcommand) + 1:
        candidate = filtered[filtered.index(subcommand) + 1]
        if not candidate.startswith("-"):
            script = candidate
    elif subcommand in {"test", "start", "build", "lint"}:
        script = subcommand

    if workspaces:
        root_manifest = root / "package.json"
        root_data = _read_package_json(root_manifest)
        if not root_manifest.is_file():
            _missing_path(
                root_manifest,
                root,
                document,
                line,
                command,
                findings,
                "npm workspace manifest",
            )
        elif "workspaces" not in root_data:
            findings.append(
                Finding(
                    document,
                    line,
                    command,
                    f"npm workspace manifest {_display(root_manifest, root)!r} does not declare workspaces",
                )
            )
        for workspace in workspaces:
            workspace_dir = root / workspace.lstrip("./")
            manifest = workspace_dir / "package.json"
            data = _read_package_json(manifest)
            if _missing_path(
                manifest,
                root,
                document,
                line,
                command,
                findings,
                "npm workspace manifest",
            ):
                continue
            if script and script not in (data.get("scripts") or {}):
                findings.append(
                    Finding(
                        document,
                        line,
                        command,
                        f"npm script {script!r} is not declared in {_display(manifest, root)!r}",
                    )
                )
        return

    manifest = effective_cwd / "package.json"
    data = _read_package_json(manifest)
    if subcommand in {"install", "ci", "i", "run", "test", "start", "build", "lint"}:
        _missing_path(manifest, root, document, line, command, findings, "npm manifest")
    if script and manifest.is_file() and script not in (data.get("scripts") or {}):
        findings.append(
            Finding(
                document,
                line,
                command,
                f"npm script {script!r} is not declared in {_display(manifest, root)!r}",
            )
        )


def check_command(
    segment: str,
    cwd: Path,
    root: Path,
    document: Path,
    line: int,
    findings: list[Finding],
    *,
    cloned_directory: bool = False,
) -> Path:
    """Check one shell segment and return the working directory for the next one."""
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        tokens = segment.split()
    if not tokens:
        return cwd

    launcher = tokens[0]
    args = tokens[1:]
    if launcher in {"git", "gh"} and "clone" in args:
        return cwd
    if launcher == "cd":
        if args and not _is_placeholder(args[0]):
            directory = _resolve(args[0], cwd)
            if cloned_directory:
                # A fresh clone's directory does not exist in this checkout yet.
                return directory
            if _missing_path(
                directory, root, document, line, segment, findings, "directory"
            ):
                return cwd
            return directory
        return cwd
    if launcher in PYTHON_LAUNCHERS:
        _check_python(args, cwd, root, document, line, segment, findings)
    elif launcher == "pytest":
        _check_path_arguments(args, cwd, root, document, line, segment, findings)
    elif launcher == "npm":
        _check_npm(args, cwd, root, document, line, segment, findings)
    else:
        _check_path_arguments(args, cwd, root, document, line, segment, findings)

    # Also check path arguments that are not covered by the launcher-specific
    # branches (for example a config or manifest passed to a tool).
    _check_path_arguments(tokens, cwd, root, document, line, segment, findings)
    return cwd


def check_document(document: Path, root: Path) -> list[Finding]:
    """Return all obsolete-command findings for one Markdown document."""
    findings: list[Finding] = []
    lines = document.read_text(encoding="utf-8").replace("\r\n", "\n").split("\n")
    cwd = root
    in_fence = False
    fence = ""
    cloned_directory = False

    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            marker = stripped[:3]
            if not in_fence:
                in_fence, fence, cwd = True, marker, root
            elif stripped.startswith(fence):
                in_fence, fence, cwd = False, "", root
            continue
        if not in_fence:
            continue

        for segment in _split_segments(raw_line):
            first = segment.split(" ", 1)[0]
            if first not in COMMAND_PREFIXES:
                continue
            if first in {"git", "gh"} and "clone" in segment.split():
                cloned_directory = True
            cwd = check_command(
                segment,
                cwd,
                root,
                document,
                line_number,
                findings,
                cloned_directory=cloned_directory,
            )
            if first == "cd":
                cloned_directory = False

    return _dedupe(findings)


def _markdown_files(directory: Path) -> Iterator[Path]:
    excluded_parts = {".git", "node_modules", "target", "dist", "build", "archive"}
    for path in sorted(directory.rglob("*.md")):
        relative = path.relative_to(directory).as_posix()
        if any(part in excluded_parts for part in relative.split("/")[:-1]):
            continue
        yield path


def resolve_documents(paths: Sequence[Path], root: Path) -> list[Path]:
    """Expand CLI path arguments to Markdown files, skipping absent defaults."""
    explicit = bool(paths)
    candidates: list[Path] = []
    for item in paths or [Path(name) for name in DEFAULT_DOCUMENTS]:
        path = item if item.is_absolute() else root / item
        if path.is_dir():
            candidates.extend(_markdown_files(path))
        elif path.is_file():
            candidates.append(path)
        elif explicit:
            raise FileNotFoundError(f"document not found: {_display(path, root)!r}")
    return _dedupe_paths(candidates)


def _dedupe_paths(paths: Iterable[Path]) -> list[Path]:
    seen: set[Path] = set()
    result: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            result.append(path)
    return result


def check_documents(
    paths: Sequence[Path] | None = None, root: Path = ROOT
) -> list[Finding]:
    """Check the default contributor docs, or the explicitly requested ones."""
    findings: list[Finding] = []
    for document in resolve_documents(paths or [], root):
        findings.extend(check_document(document, root))
    return _dedupe(findings)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Markdown files/directories to check (defaults to contributor docs)",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="Repository root (defaults to parent of devx)",
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit machine-readable findings"
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    try:
        findings = check_documents(args.paths, root)
    except (FileNotFoundError, OSError, UnicodeError) as exc:
        print(f"contributor command check failed: {exc}", file=sys.stderr)
        return 2

    if args.json:
        payload = [dict(asdict(f), document=f.document.as_posix()) for f in findings]
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif findings:
        print(f"Found {len(findings)} obsolete command(s):", file=sys.stderr)
        for finding in findings:
            print(finding.format(root), file=sys.stderr)
    else:
        print("All documented contributor commands reference committed entry points.")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
