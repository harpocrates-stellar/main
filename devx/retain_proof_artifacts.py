#!/usr/bin/env python3
"""Stage CI proof artifacts for retention under explicit privacy rules.

Fail closed: any policy violation aborts with exit code 2 and writes nothing.
Messages contain only stable codes, never file names or contents.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path

SCHEMA = "hpx-artifact-retention/1"
DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 25 * 1024 * 1024

# Only these file types can ever be retained.
ALLOWED_SUFFIXES = frozenset({".proof", ".vk", ".json", ".sha256", ".hex"})

# Presence of any of these in the source is a violation (real media, keys, witnesses).
DENIED_SUFFIXES = frozenset({
    ".mp4", ".m4v", ".mov", ".mkv", ".webm", ".avi", ".wav", ".mp3",
    ".png", ".jpg", ".jpeg", ".gif",
    ".pem", ".key", ".p12", ".pfx",
    ".gz", ".wtns",
})
DENIED_NAME_PARTS = ("prover.toml", "secret", "seed", "private", "mnemonic", ".env")

# JSON keys that must never appear (exact match, case/dash-insensitive).
FORBIDDEN_JSON_KEYS = frozenset({
    "witness", "secret", "seed", "privatekey", "private_key", "credentialsecret",
    "credential_secret", "nullifiersecret", "nullifier_secret", "mnemonic",
    "password", "apikey", "api_key", "token",
})

STELLAR_SECRET_RE = re.compile(r"\bS[A-Z2-7]{55}\b")


class Violation(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _check_json_keys(node) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if str(key).lower().replace("-", "_") in FORBIDDEN_JSON_KEYS:
                raise Violation("FORBIDDEN_JSON_KEY")
            _check_json_keys(value)
    elif isinstance(node, list):
        for item in node:
            _check_json_keys(item)


def scan_file(path: Path, rel: Path, max_file_bytes: int):
    """Return (size, sha256) if retainable, None if merely not allowlisted; raise Violation otherwise."""
    if path.is_symlink():
        raise Violation("SYMLINK")
    lowered_parts = [p.lower() for p in rel.parts]
    if any(part in lowered_parts[i] for part in DENIED_NAME_PARTS for i in range(len(lowered_parts))):
        raise Violation("DENIED_NAME")
    suffix = path.suffix.lower()
    if suffix in DENIED_SUFFIXES:
        raise Violation("DENIED_TYPE")
    if suffix not in ALLOWED_SUFFIXES:
        return None
    size = path.stat().st_size
    if size > max_file_bytes:
        raise Violation("OVERSIZED")
    data = path.read_bytes()
    text = data.decode("utf-8", "ignore")
    if "PRIVATE KEY" in text or STELLAR_SECRET_RE.search(text):
        raise Violation("SECRET_CONTENT")
    if suffix == ".json":
        try:
            _check_json_keys(json.loads(data))
        except (ValueError, RecursionError):
            raise Violation("MALFORMED_JSON")
    return size, hashlib.sha256(data).hexdigest()


def collect(src_dirs, max_file_bytes: int, max_total_bytes: int):
    entries, skipped, total = [], 0, 0
    for index, src in enumerate(src_dirs):
        root = Path(src)
        if not root.is_dir() or root.is_symlink():
            raise Violation("MISSING_SOURCE")
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            for d in dirnames:
                if (Path(dirpath) / d).is_symlink():
                    raise Violation("SYMLINK")
            for name in sorted(filenames):
                path = Path(dirpath) / name
                rel = path.relative_to(root)
                result = scan_file(path, rel, max_file_bytes)
                if result is None:
                    skipped += 1
                    continue
                size, digest = result
                total += size
                if total > max_total_bytes:
                    raise Violation("TOTAL_TOO_LARGE")
                entries.append({
                    "path": f"src{index}/{rel.as_posix()}",
                    "sha256": digest,
                    "size": size,
                    "_abs": path,
                })
    if not entries:
        raise Violation("NOTHING_TO_RETAIN")
    return entries, skipped, total


def write_output(out_dir: Path, entries, skipped: int, total: int) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for e in entries:
        dest = out_dir / e["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(e["_abs"], dest)
    manifest = {
        "schema": SCHEMA,
        "files": [{k: e[k] for k in ("path", "sha256", "size")} for e in entries],
        "skippedNotAllowlisted": skipped,
        "totalBytes": total,
    }
    (out_dir / "retention-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--src", action="append", required=True, help="source dir (repeatable)")
    parser.add_argument("--out", required=True, help="output dir (must be empty or absent)")
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES)
    parser.add_argument("--dry-run", action="store_true", help="check only; write nothing")
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    try:
        if out_dir.exists() and (not out_dir.is_dir() or any(out_dir.iterdir())):
            raise Violation("OUT_NOT_EMPTY")
        entries, skipped, total = collect(args.src, args.max_file_bytes, args.max_total_bytes)
        if not args.dry_run:
            write_output(out_dir, entries, skipped, total)
    except Violation as v:
        print(f"policy violation: {v.code}", file=sys.stderr)
        return 2
    except OSError:
        print("io error", file=sys.stderr)
        return 3

    print(f"retained {len(entries)} files ({total} bytes), skipped {skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())