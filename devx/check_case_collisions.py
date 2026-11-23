#!/usr/bin/env python3
"""Reject source paths that collide on case-insensitive release filesystems.

macOS (APFS/HFS+) and Windows (NTFS) treat ``README.md`` and ``readme.md`` as
the same file, and macOS stores decomposed Unicode while Linux stores composed
Unicode. A tree that is fine on one host can therefore lose a file, fail to
check out, or ship different bytes from another host. This gate reads the git
index (never the working tree) and reports every group of paths that would
collide after Unicode NFC normalization and case folding.

Paths are compared with ``str.casefold`` and normalised to NFC, so the finding
set is identical on every platform and independent of the host filesystem.
Output is deterministic: groups are ordered by their normalized key and each
group's paths are sorted.

Exit codes:
  0  no collisions
  1  collisions found (report written to stdout)
  2  the path source could not be read
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import unicodedata
from collections.abc import Callable, Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "harpocrates.source-path-case-collision"
SCHEMA_VERSION = 1
EXIT_OK = 0
EXIT_COLLISION = 1
EXIT_USAGE = 2
MAX_INPUT_BYTES = 64 * 1024 * 1024


class CollisionCheckError(RuntimeError):
    """Raised when the path source cannot be read."""


def normalize_key(path: str) -> str:
    """Return the portable identity of a path.

    NFC first so a decomposed macOS filename and its composed equivalent share
    a key, then ``casefold`` so the comparison does not depend on the host's
    case sensitivity.
    """
    return unicodedata.normalize("NFC", path).casefold()


def find_case_collisions(paths: Iterable[str]) -> list[dict[str, object]]:
    """Group paths that collide on a case-insensitive filesystem.

    Duplicate entries for the exact same path are one file and are not a
    collision. Groups are sorted by normalized key, then by path, so two runs
    over the same set produce identical output.
    """
    groups: dict[str, set[str]] = {}
    for path in paths:
        if not path:
            continue
        groups.setdefault(normalize_key(path), set()).add(path)

    collisions = [
        {"key": key, "paths": sorted(group)}
        for key, group in groups.items()
        if len(group) > 1
    ]
    collisions.sort(key=lambda item: (item["key"], item["paths"]))
    return collisions


def parse_path_list(raw: bytes) -> list[str]:
    """Split a NUL- or newline-delimited path list (git-style fixtures)."""
    separator = b"\0" if b"\0" in raw else b"\n"
    return [
        item.decode("utf-8", "surrogateescape") for item in raw.split(separator) if item
    ]


def collect_tracked_paths(
    root: Path,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> list[str]:
    """Return the paths recorded in the git index, without touching the tree."""
    try:
        proc = runner(
            ["git", "-C", str(root), "ls-files", "-z", "--cached"],
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise CollisionCheckError("git is not installed") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or b"").decode("utf-8", "replace").strip()
        raise CollisionCheckError(f"git ls-files failed: {detail or 'unknown error'}")
    return parse_path_list(proc.stdout or b"")


def read_paths_file(path: Path) -> list[str]:
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise CollisionCheckError(f"path list exceeds {MAX_INPUT_BYTES} bytes")
        raw = path.read_bytes()
    except OSError as exc:
        raise CollisionCheckError(f"cannot read path list: {exc}") from exc
    return parse_path_list(raw)


def build_report(paths: Iterable[str]) -> dict[str, object]:
    path_list = list(paths)
    collisions = find_case_collisions(path_list)
    return {
        "format": FORMAT,
        "schema_version": SCHEMA_VERSION,
        "checked_paths": len(path_list),
        "status": "fail" if collisions else "pass",
        "collisions": collisions,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect tracked paths that collide on case-insensitive filesystems"
    )
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument(
        "--paths-from",
        type=Path,
        default=None,
        help="read paths from a NUL- or newline-delimited file instead of git",
    )
    parser.add_argument(
        "--output", type=Path, default=None, help="write the report here"
    )
    args = parser.parse_args(argv)

    try:
        if args.paths_from is not None:
            paths = read_paths_file(args.paths_from.resolve())
        else:
            paths = collect_tracked_paths(args.root.resolve())
    except CollisionCheckError as exc:
        print(f"case-collision check failed: {exc}", file=sys.stderr)
        return EXIT_USAGE

    report = build_report(paths)
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")

    if report["collisions"]:
        for collision in report["collisions"]:
            print(
                "case collision: " + " | ".join(collision["paths"]),
                file=sys.stderr,
            )
        return EXIT_COLLISION
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
