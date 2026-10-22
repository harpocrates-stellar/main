#!/usr/bin/env python3
"""Remove one explicit Noir constraint at a time and check that tests notice.

Only production assert/assert_eq calls are mutation targets. Test functions,
comments and strings are excluded. No third-party Python packages are needed.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tempfile
import time
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path

INCOMPLETE_STATUSES = ("error", "timeout", "budget_exceeded", "not_run")
MUTATION_STATUSES = ("killed", "survived", *INCOMPLETE_STATUSES)


@dataclass(frozen=True)
class Constraint:
    kind: str
    function: str
    start: int
    end: int
    line: int
    column: int


def _mask_noncode(source: str) -> str:
    masked = list(source)
    i = 0
    while i < len(source):
        start = i
        if source.startswith("//", i):
            end = source.find("\n", i)
            i = len(source) if end < 0 else end
        elif source.startswith("/*", i):
            depth = 1
            i += 2
            while i < len(source) and depth:
                if source.startswith("/*", i):
                    depth += 1
                    i += 2
                elif source.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            if depth:
                raise ValueError("Unterminated block comment")
        elif source[i] in ('"', "'"):
            quote = source[i]
            i += 1
            while i < len(source) and source[i] != quote:
                i += 2 if source[i] == "\\" else 1
            if i >= len(source):
                raise ValueError("Unterminated string")
            i += 1
        else:
            i += 1
            continue
        for j in range(start, i):
            if source[j] not in "\r\n":
                masked[j] = " "
    return "".join(masked)


def find_constraints(source: str) -> list[Constraint]:
    tokens = list(
        re.finditer(r"::|[A-Za-z_][A-Za-z_0-9]*|[^\s]", _mask_noncode(source))
    )
    values = [t.group() for t in tokens]
    pairs: dict[int, int] = {}
    stack: list[int] = []
    for i, value in enumerate(values):
        if value in ("(", "[", "{"):
            stack.append(i)
        elif value in (")", "]", "}"):
            if not stack or values[stack[-1]] != {")": "(", "]": "[", "}": "{"}[value]:
                raise ValueError(f"Unbalanced delimiter at offset {tokens[i].start()}")
            pairs[stack.pop()] = i
    if stack:
        raise ValueError("Unbalanced source delimiters")

    functions: list[tuple[int, int, str, bool]] = []
    is_test = False
    i = 0
    while i < len(tokens):
        if values[i : i + 2] == ["#", "["]:
            close = pairs[i + 1]
            is_test |= values[i + 2] == "test"
            i = close + 1
            continue
        if values[i] == "fn":
            name = values[i + 1]
            body = i + 2
            while body < len(tokens) and values[body] not in ("{", ";"):
                body = pairs[body] + 1 if values[body] in ("(", "[") else body + 1
            if body == len(tokens):
                raise ValueError(f"Missing body for function {name}")
            if values[body] == "{":
                close = pairs[body]
                functions.append(
                    (tokens[body].start(), tokens[close].end(), name, is_test)
                )
                i = close
            is_test = False
        i += 1

    constraints = []
    for i, token in enumerate(tokens):
        kind = values[i]
        if kind not in ("assert", "assert_eq") or values[i + 1 : i + 2] != ["("]:
            continue
        if i and values[i - 1] in ("fn", "."):
            continue
        owner = next((f for f in functions if f[0] < token.start() < f[1]), None)
        if owner and owner[3]:
            continue
        start = i
        while start >= 2 and values[start - 1] == "::":
            start -= 2
        offset = tokens[start].start()
        constraints.append(
            Constraint(
                kind,
                owner[2] if owner else "<module>",
                offset,
                tokens[pairs[i + 1]].end(),
                source.count("\n", 0, offset) + 1,
                offset - source.rfind("\n", 0, offset),
            )
        )
    return constraints


def mutate(source: str, constraint: Constraint) -> str:
    original = source[constraint.start : constraint.end]
    comment = original.replace("/*", "/ *").replace("*/", "* /")
    replacement = f"/* constraint removed: {comment} */ ()"
    return source[: constraint.start] + replacement + source[constraint.end :]


@dataclass(frozen=True)
class Circuit:
    name: str
    path: Path
    sources: tuple[Path, ...]


def discover_circuits(noir_root: Path) -> list[Circuit]:
    root = noir_root.resolve()

    def load(package: Path) -> dict:
        manifest = package / "Nargo.toml"
        if not package.is_relative_to(root) or not manifest.is_file():
            raise ValueError(f"Local package must exist inside {root}: {package}")
        return tomllib.loads(manifest.read_text(encoding="utf-8"))

    def sources(package: Path, visited: set[Path]) -> set[Path]:
        if package in visited:
            return set()
        visited.add(package)
        config = load(package)
        found = set((package / "src").rglob("*.nr"))
        if not found:
            raise ValueError(f"No Noir source files in {package / 'src'}")
        for dependency in config.get("dependencies", {}).values():
            if isinstance(dependency, dict) and "path" in dependency:
                found.update(sources((package / dependency["path"]).resolve(), visited))
        return found

    circuits = []
    for manifest in sorted(root.rglob("Nargo.toml")):
        if "target" in manifest.relative_to(root).parts:
            continue
        config = load(manifest.parent)
        if config.get("package", {}).get("type") == "bin":
            circuits.append(
                Circuit(
                    config["package"]["name"],
                    manifest.parent,
                    tuple(sorted(sources(manifest.parent, set()))),
                )
            )
    if not circuits:
        raise ValueError(f"No Noir binary packages found in {root}")
    return circuits


def _events(output: str) -> list[dict]:
    events = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def classify_run(returncode: int, output: str) -> str:
    events = _events(output)
    summaries = [
        e
        for e in events
        if e.get("type") == "suite" and e.get("event") in ("ok", "failed")
    ]
    completed = [
        e
        for e in events
        if e.get("type") == "test" and e.get("event") in ("ok", "failed")
    ]
    if not summaries or not completed:
        return "error"
    passed = sum(e.get("passed", 0) for e in summaries)
    failed = sum(e.get("failed", 0) for e in summaries)
    if passed + failed != len(completed):
        return "error"
    if failed != sum(e["event"] == "failed" for e in completed):
        return "error"
    if returncode == 0 and failed == 0:
        return "passed"
    if returncode == 1 and failed > 0:
        return "failed"
    return "error"


def run_tests(
    nargo: str, package: Path, timeout: float, deadline: float
) -> tuple[dict, str]:
    started = time.monotonic()
    remaining = deadline - started
    if remaining <= 0:
        return {
            "status": "budget_exceeded",
            "elapsed_seconds": 0,
        }, "Budget exhausted before execution"
    try:
        process = subprocess.run(
            [nargo, "test", "--format", "json", "--silence-warnings", "--force"],
            cwd=package,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=min(timeout, remaining),
            check=False,
        )
        output = process.stdout
        status = classify_run(process.returncode, output)
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or b""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        status = "budget_exceeded" if remaining <= timeout else "timeout"
    except OSError as exc:
        output, status = str(exc), "error"
    record = {
        "status": status,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "failed_tests": [
            e.get("name")
            for e in _events(output)
            if e.get("type") == "test" and e.get("event") == "failed"
        ],
    }
    return record, output


def run_campaign(
    noir_root: Path,
    nargo: str,
    report_dir: Path,
    timeout: float,
    budget: float,
    selected: list[str] | None = None,
) -> dict:
    started = time.monotonic()
    report_dir.mkdir(parents=True, exist_ok=True)
    report = {"circuits": [], "budget_seconds": budget}
    with tempfile.TemporaryDirectory(prefix="noir-constraints-") as tmp:
        root = Path(tmp) / "noir"
        shutil.copytree(
            noir_root, root, ignore=shutil.ignore_patterns("target", "proofs", ".git")
        )
        circuits = discover_circuits(root)
        if selected:
            unknown = set(selected) - {c.name for c in circuits}
            if unknown:
                raise ValueError(f"Unknown circuits: {', '.join(sorted(unknown))}")
            circuits = [c for c in circuits if c.name in selected]
        for circuit in circuits:
            circuit_started = time.monotonic()
            originals = {p: p.read_text(encoding="utf-8") for p in circuit.sources}
            targets = [
                (p, c)
                for p, source in originals.items()
                for c in find_constraints(source)
            ]
            mutations = [
                dict(asdict(c), source=p.relative_to(root).as_posix(), status="not_run")
                for p, c in targets
            ]
            entry = {"name": circuit.name, "mutations": mutations, "baseline": None}
            report["circuits"].append(entry)
            if targets:
                baseline, output = run_tests(
                    nargo, circuit.path, timeout, started + budget
                )
                entry["baseline"] = baseline
                (report_dir / f"{circuit.name}-baseline.log").write_text(
                    output, encoding="utf-8"
                )
                if baseline["status"] == "passed":
                    for index, ((path, constraint), result) in enumerate(
                        zip(targets, mutations), 1
                    ):
                        if time.monotonic() >= started + budget:
                            break
                        try:
                            path.write_text(
                                mutate(originals[path], constraint), encoding="utf-8"
                            )
                            outcome, output = run_tests(
                                nargo, circuit.path, timeout, started + budget
                            )
                        finally:
                            path.write_text(originals[path], encoding="utf-8")
                        result.update(outcome)
                        result["status"] = {
                            "passed": "survived",
                            "failed": "killed",
                        }.get(
                            outcome["status"],
                            outcome["status"],
                        )
                        result["log"] = f"{circuit.name}-{index:03}.log"
                        (report_dir / result["log"]).write_text(
                            output, encoding="utf-8"
                        )
                        print(
                            f"{circuit.name}: {result['status']} {result['source']}:"
                            f"{constraint.line}:{constraint.column}",
                            flush=True,
                        )
            entry["counts"] = {
                state: sum(m["status"] == state for m in mutations)
                for state in MUTATION_STATUSES
            }
            entry["elapsed_seconds"] = round(time.monotonic() - circuit_started, 3)
            print(
                f"{circuit.name}: {len(targets)} constraints; {entry['counts']}",
                flush=True,
            )
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    counts = {
        state: sum(c["counts"][state] for c in report["circuits"])
        for state in MUTATION_STATUSES
    }
    report["counts"] = counts
    incomplete = (
        not sum(counts.values())
        or any(counts[s] for s in INCOMPLETE_STATUSES)
        or any(
            c["baseline"] and c["baseline"]["status"] != "passed"
            for c in report["circuits"]
        )
        or report["elapsed_seconds"] > budget
    )
    report["exit_code"] = 2 if incomplete else 1 if counts["survived"] else 0
    return report


def render_summary(report: dict) -> str:
    lines = [
        "## Circuit constraint mutation results",
        "",
        "| Circuit | Constraints | Killed | Survived | Errors / untested | Seconds |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for circuit in report["circuits"]:
        counts = circuit["counts"]
        errors = sum(counts[s] for s in INCOMPLETE_STATUSES)
        lines.append(
            f"| {circuit['name']} | {len(circuit['mutations'])} | {counts['killed']} | "
            f"{counts['survived']} | {errors} | {circuit['elapsed_seconds']} |"
        )
    lines += [
        "",
        f"Elapsed: {report['elapsed_seconds']} s; budget: {report['budget_seconds']} s.",
        "",
    ]
    for circuit in report["circuits"]:
        if circuit["baseline"] and circuit["baseline"]["status"] != "passed":
            lines.append(
                f"- {circuit['name']}: baseline {circuit['baseline']['status']}; mutations not scored."
            )
        for mutation in circuit["mutations"]:
            if mutation["status"] != "killed":
                lines.append(
                    f"- {mutation['status']}: `{mutation['source']}:{mutation['line']}` "
                    f"({mutation['function']})"
                )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--noir-root", type=Path, default=Path(__file__).resolve().parents[1] / "noir"
    )
    parser.add_argument(
        "--nargo",
        default="nargo",
        help="Nargo executable; use zk/toolchain.lock.json version",
    )
    parser.add_argument(
        "--circuit",
        action="append",
        help="Limit to named package(s); default: discover all",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List current constraints without running Nargo",
    )
    parser.add_argument(
        "--report-dir", type=Path, default=Path("tmp/constraint-mutations")
    )
    parser.add_argument(
        "--summary",
        type=Path,
        help="Append Markdown to this file, e.g. GITHUB_STEP_SUMMARY",
    )
    parser.add_argument("--timeout-seconds", type=float, default=180)
    parser.add_argument("--budget-seconds", type=float, default=2100)
    args = parser.parse_args(argv)
    if args.timeout_seconds <= 0 or args.budget_seconds <= 0:
        parser.error("Timeout and budget must be positive")
    try:
        if args.list:
            for circuit in discover_circuits(args.noir_root):
                if args.circuit and circuit.name not in args.circuit:
                    continue
                inventory = [
                    dict(asdict(c), source=str(p.relative_to(args.noir_root.resolve())))
                    for p in circuit.sources
                    for c in find_constraints(p.read_text(encoding="utf-8"))
                ]
                print(json.dumps({"circuit": circuit.name, "constraints": inventory}))
            return 0
        report = run_campaign(
            args.noir_root,
            args.nargo,
            args.report_dir,
            args.timeout_seconds,
            args.budget_seconds,
            args.circuit,
        )
        args.report_dir.joinpath("report.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        summary = render_summary(report)
        args.report_dir.joinpath("summary.md").write_text(summary, encoding="utf-8")
        if args.summary:
            with args.summary.open("a", encoding="utf-8") as stream:
                stream.write(summary)
        print(summary)
        return report["exit_code"]
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Mutation campaign error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
