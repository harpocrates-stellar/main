"""Generate a reproducible contributor check plan for changed protocol layers.

The plan is derived purely from tracked file changes (via git's diff output)
and maps each changed area to the focused test and build commands a
contributor should run. No commands are executed by this module; it only
prints the plan, so it is safe to run without network access or credentials.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence

# Ordered mapping of path prefixes to the protocol layer they belong to and the
# checks that cover them. Order matters: the first matching prefix wins.
LAYER_RULES: Sequence[tuple] = (
    ("devx/", "developer-tooling", ("python -m pytest devx",)),
    ("contracts/", "contracts", ("cargo test --workspace",)),
    ("crates/", "core-crates", ("cargo test --workspace", "cargo clippy --workspace")),
    ("sdk/", "sdk", ("cargo test --workspace",)),
    ("docs/", "documentation", ("python -m pytest devx",)),
)

BASELINE_CHECKS: Sequence[str] = (
    "python -m pytest devx",
)


@dataclass(frozen=True)
class ChangedFile:
    path: str
    status: str


@dataclass
class CheckPlan:
    layers: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)
    unmatched: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "layers": self.layers,
            "commands": self.commands,
            "unmatched": self.unmatched,
        }


def parse_name_status(output: str) -> List[ChangedFile]:
    """Parse `git diff --name-status` output into ChangedFile records.

    Renames and copies (`R100\\told\\tnew`) are reported under their new path.
    Blank lines are ignored. Output is sorted by path for reproducibility.
    """
    changes: List[ChangedFile] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            raise ValueError(f"malformed name-status line: {raw!r}")
        status = parts[0]
        path = parts[-1]
        changes.append(ChangedFile(path=path, status=status))
    return sorted(changes, key=lambda c: c.path)


def classify(changes: Iterable[ChangedFile]) -> CheckPlan:
    """Build a deterministic check plan from a set of changed files."""
    plan = CheckPlan()
    seen_layers: set = set()
    seen_commands: set = set()

    for change in changes:
        matched = False
        for prefix, layer, commands in LAYER_RULES:
            if change.path.startswith(prefix):
                matched = True
                if layer not in seen_layers:
                    seen_layers.add(layer)
                    plan.layers.append(layer)
                for command in commands:
                    if command not in seen_commands:
                        seen_commands.add(command)
                        plan.commands.append(command)
                break
        if not matched:
            plan.unmatched.append(change.path)

    for command in BASELINE_CHECKS:
        if command not in seen_commands:
            seen_commands.add(command)
            plan.commands.append(command)

    plan.layers.sort()
    plan.commands.sort()
    plan.unmatched.sort()
    return plan


def render_text(plan: CheckPlan) -> str:
    lines = ["Contributor check plan", "=" * 22]
    lines.append("Changed layers:")
    if plan.layers:
        lines.extend(f"  - {layer}" for layer in plan.layers)
    else:
        lines.append("  (none matched)")
    lines.append("Run these checks:")
    lines.extend(f"  $ {command}" for command in plan.commands)
    if plan.unmatched:
        lines.append("Files outside known layers (baseline checks only):")
        lines.extend(f"  - {path}" for path in plan.unmatched)
    return "\n".join(lines) + "\n"


def render_json(plan: CheckPlan) -> str:
    return json.dumps(plan.to_dict(), indent=2, sort_keys=True) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="contributor_check_plan",
        description="Print a check plan for files changed relative to a base.",
    )
    parser.add_argument(
        "--input",
        default="-",
        help="Path to a `git diff --name-status` capture, or '-' for stdin (default).",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.input == "-":
        source = sys.stdin.read()
    else:
        with open(args.input, "r", encoding="utf-8") as handle:
            source = handle.read()
    try:
        changes = parse_name_status(source)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    plan = classify(changes)
    output = render_json(plan) if args.format == "json" else render_text(plan)
    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
