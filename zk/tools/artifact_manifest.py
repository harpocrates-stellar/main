#!/usr/bin/env python3
"""Reproducible-artifact manifest tool for the Harpocrates zk pipeline.

Guarantees that generated ACIR bundles, verification keys, and WASM artifacts
match their source and the pinned toolchain in ``zk/toolchain.lock.json``.

    write           normalize every declared artifact, digest it, and emit a manifest
    verify          re-digest the working tree and fail on any drift from a manifest
    compare         diff two manifests (the double-build reproducibility check)
    check-coverage  fail when the lock and the source tree disagree about which
                    circuits exist, so no circuit can ship unpinned
    write-browser   digest published browser ACIR and emit the browser manifest
    verify-browser  fail if published ACIR drifts from the browser manifest or
                    from the matching build-target ACIR when both are on disk
    write-provenance  digest lock-declared circuit sources and emit published provenance
    verify-provenance fail if circuit sources drift from the committed provenance

State machine
-------------
Each artifact moves through exactly one terminal state per run::

    DECLARED ──not on disk──▶ MISSING      (fatal if `required`, else SKIPPED)
             ──over limit───▶ OVERSIZE     (fatal)
             ──unreadable───▶ UNREADABLE   (fatal)
             ──normalized───▶ DIGESTED     (success)

`verify` and `compare` add one more transition on a DIGESTED artifact:
``MATCHED`` or ``DRIFTED``. There is no partial success: a run that ends with
any fatal state exits non-zero and the manifest is not written, so a half-built
tree can never be promoted into a manifest.

Privacy
-------
Signals are structured JSON on stderr and carry only repo-relative paths,
byte counts, digests, and state names. Artifact *contents* — which for the
witness pipeline may be derived from private material — are never logged, never
echoed on failure, and never embedded in the manifest.

Determinism
-----------
Digests are taken over the *normalized* form defined by the lock file, so a
rebuild on a different host with the same pinned toolchain produces an
identical manifest. Normalization only removes fields the lock file names; it
can never mask a change to circuit semantics.

See docs/zk-reproducible-builds.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MANIFEST_FORMAT = "harpocrates.zk-artifact-manifest"
MANIFEST_VERSION = 1

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOCK = REPO_ROOT / "zk" / "toolchain.lock.json"
DEFAULT_MANIFEST = REPO_ROOT / "zk" / "artifacts.manifest.json"
DEFAULT_BROWSER_MANIFEST = REPO_ROOT / "zk" / "browser.artifacts.manifest.json"

BROWSER_MANIFEST_FORMAT = "harpocrates.zk-browser-artifact-manifest"
PROVENANCE_FORMAT = "harpocrates.zk-circuit-provenance"
DEFAULT_PROVENANCE = REPO_ROOT / "zk" / "circuit.provenance.json"
PUBLISHED_ACIR_ROLE = "published_acir"
ACIR_ROLE = "acir"

DEFAULT_CIRCUIT_ROOT = "zk/noir"
DEFAULT_PACKAGE_FILE = "Nargo.toml"

MAX_MANIFEST_PATH_CHARS = 512
MAX_PATH_ERROR_PREVIEW = 96
MAX_VALIDATION_ERROR_CHARS = 240
_DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:")

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_USAGE = 2
EXIT_FATAL = 3


class ArtifactState:
    """Terminal states an artifact can reach in a single run."""

    MISSING = "missing"
    SKIPPED = "skipped"
    OVERSIZE = "oversize"
    UNREADABLE = "unreadable"
    DIGESTED = "digested"
    MATCHED = "matched"
    DRIFTED = "drifted"


FATAL_STATES = frozenset({ArtifactState.OVERSIZE, ArtifactState.UNREADABLE})


class BuildError(RuntimeError):
    """Fatal, non-recoverable condition. Carries no artifact content."""


class PathValidationError(BuildError):
    """Deterministic, length-bounded validation error for escaping or invalid paths."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        message = f"invalid manifest path [{code}]: {detail}"
        if len(message) > MAX_VALIDATION_ERROR_CHARS:
            message = message[: MAX_VALIDATION_ERROR_CHARS - 3] + "..."
        super().__init__(message)


def _bounded_path_preview(raw_path: Any) -> str:
    """Return a deterministic, sanitized, bounded preview of a path string."""
    if not isinstance(raw_path, str):
        return f"<{type(raw_path).__name__}>"
    sanitized_chars: list[str] = []
    for ch in raw_path:
        codepoint = ord(ch)
        if codepoint < 32 or codepoint == 127:
            sanitized_chars.append(f"\\x{codepoint:02x}")
        else:
            sanitized_chars.append(ch)
    sanitized = "".join(sanitized_chars)
    if len(sanitized) <= MAX_PATH_ERROR_PREVIEW:
        return sanitized
    omitted = len(sanitized) - 64
    return f"{sanitized[:64]}...<+{omitted} chars>"


def validate_relative_manifest_path(
    raw_path: Any,
    *,
    field_name: str = "artifact path",
) -> str:
    """Validate a manifest/lock relative path without touching the filesystem."""
    if not isinstance(raw_path, str):
        raise PathValidationError(
            "path_non_string",
            f"{field_name} must be a non-empty relative POSIX string, got {_bounded_path_preview(raw_path)}",
        )
    if not raw_path or not raw_path.strip():
        raise PathValidationError(
            "path_empty",
            f"{field_name} must be a non-empty relative POSIX path",
        )
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_path):
        raise PathValidationError(
            "path_control_char",
            f"{field_name} '{_bounded_path_preview(raw_path)}' contains disallowed control characters",
        )
    if len(raw_path) > MAX_MANIFEST_PATH_CHARS:
        raise PathValidationError(
            "path_overlong",
            f"{field_name} '{_bounded_path_preview(raw_path)}' exceeds {MAX_MANIFEST_PATH_CHARS} chars (len={len(raw_path)})",
        )
    if "\\" in raw_path:
        raise PathValidationError(
            "path_backslash",
            f"{field_name} '{_bounded_path_preview(raw_path)}' must use '/' separators and stay inside release directory",
        )
    if raw_path.startswith("/") or _DRIVE_PREFIX_RE.match(raw_path):
        raise PathValidationError(
            "path_absolute",
            f"{field_name} '{_bounded_path_preview(raw_path)}' must be relative and stay inside release directory",
        )
    parts = raw_path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise PathValidationError(
            "path_traversal",
            f"{field_name} '{_bounded_path_preview(raw_path)}' must not traverse outside release directory",
        )
    return "/".join(parts)


def _validate_provenance_glob(raw_glob: Any) -> str:
    """Validate a provenance glob pattern so it cannot traverse outside release_dir."""
    if not isinstance(raw_glob, str) or not raw_glob or not raw_glob.strip():
        raise PathValidationError(
            "path_empty",
            "provenance glob must be a non-empty relative POSIX pattern",
        )
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_glob):
        raise PathValidationError(
            "path_control_char",
            f"provenance glob '{_bounded_path_preview(raw_glob)}' contains control characters",
        )
    if len(raw_glob) > MAX_MANIFEST_PATH_CHARS:
        raise PathValidationError(
            "path_overlong",
            f"provenance glob '{_bounded_path_preview(raw_glob)}' exceeds {MAX_MANIFEST_PATH_CHARS} chars",
        )
    if "\\" in raw_glob:
        raise PathValidationError(
            "path_backslash",
            f"provenance glob '{_bounded_path_preview(raw_glob)}' must use '/' separators",
        )
    if raw_glob.startswith("/") or _DRIVE_PREFIX_RE.match(raw_glob):
        raise PathValidationError(
            "path_absolute",
            f"provenance glob '{_bounded_path_preview(raw_glob)}' must be relative to release directory",
        )
    parts = raw_glob.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise PathValidationError(
            "path_traversal",
            f"provenance glob '{_bounded_path_preview(raw_glob)}' must not escape release directory",
        )
    return raw_glob


def _is_alias_entry(entry: Path) -> bool:
    """Return True if entry is a symbolic link or Windows directory junction."""
    try:
        if entry.is_symlink():
            return True
    except OSError:
        return False
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction is not None:
        try:
            if isjunction(entry):
                return True
        except OSError:
            return False
    return False


def _strip_extended_drive_prefix(raw_target: str) -> str:
    if raw_target.startswith("\\\\?\\UNC\\"):
        return "\\\\" + raw_target[8:]
    if raw_target.startswith("\\\\?\\"):
        return raw_target[4:]
    return raw_target


def _is_strictly_inside(candidate: Path, resolved_root: Path) -> bool:
    return candidate != resolved_root and candidate.is_relative_to(resolved_root)


def _resolve_release_root(release_dir: Path) -> Path:
    try:
        if not release_dir.exists() or not release_dir.is_dir():
            raise PathValidationError(
                "release_dir_invalid",
                "selected release directory does not exist or is not a directory",
            )
        return release_dir.resolve(strict=True)
    except OSError as exc:
        raise PathValidationError(
            "release_dir_invalid",
            "selected release directory cannot be resolved",
        ) from exc


def resolve_release_artifact_path(
    raw_path: Any,
    release_dir: Path,
    *,
    field_name: str = "artifact path",
) -> Path:
    """Validate and resolve aliases for ``raw_path`` inside ``release_dir``.

    Every path segment is checked for symbolic links and Windows junctions
    *before* callers stat or read any referenced artifact bytes. Any lexical
    escape or alias resolving outside ``release_dir`` fails closed with a
    deterministic, length-bounded ``PathValidationError`` that never echoes
    external host paths or file contents.
    """
    normalized = validate_relative_manifest_path(raw_path, field_name=field_name)
    resolved_root = _resolve_release_root(release_dir)

    current = resolved_root
    for segment in normalized.split("/"):
        next_entry = current / segment
        if _is_alias_entry(next_entry):
            if next_entry.is_symlink():
                try:
                    raw_link = _strip_extended_drive_prefix(os.readlink(next_entry))
                except OSError as exc:
                    raise PathValidationError(
                        "alias_escape",
                        f"{field_name} '{_bounded_path_preview(normalized)}' has an unreadable link alias",
                    ) from exc
                link_path = Path(raw_link)
                step_target = (
                    link_path.resolve(strict=False)
                    if link_path.is_absolute()
                    else (next_entry.parent / link_path).resolve(strict=False)
                )
                if not _is_strictly_inside(step_target, resolved_root):
                    raise PathValidationError(
                        "alias_escape",
                        f"{field_name} '{_bounded_path_preview(normalized)}' resolves outside selected release directory",
                    )
            resolved_step = next_entry.resolve(strict=False)
            if not _is_strictly_inside(resolved_step, resolved_root):
                raise PathValidationError(
                    "alias_escape",
                    f"{field_name} '{_bounded_path_preview(normalized)}' resolves outside selected release directory",
                )
            current = resolved_step
        else:
            current = next_entry

    resolved_final = current.resolve(strict=False)
    if not _is_strictly_inside(resolved_final, resolved_root):
        raise PathValidationError(
            "alias_escape",
            f"{field_name} '{_bounded_path_preview(normalized)}' resolves outside selected release directory",
        )
    return resolved_final


# ── Signals ─────────────────────────────────────────────────────────────────


def signal(event: str, **fields: Any) -> None:
    """Emit one privacy-safe structured signal on stderr.

    Only repo-relative paths, sizes, digests, counts, and state names are
    permitted. Callers must never pass artifact bytes.
    """
    payload = {"event": event, **fields}
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), file=sys.stderr)


# ── Lock file ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Limits:
    max_artifact_bytes: int
    max_artifacts: int
    max_provenance_files: int
    max_circuits: int


@dataclass(frozen=True)
class Lock:
    raw: dict
    limits: Limits
    volatile_json_keys: frozenset[str]
    strip_custom_sections: frozenset[str]
    artifacts: tuple[dict, ...]
    provenance_globs: tuple[str, ...]
    circuit_root: str
    package_file: str

    @property
    def toolchain(self) -> dict:
        return self.raw["toolchain"]

    @property
    def environment(self) -> dict:
        return self.raw["environment"]


def load_lock(path: Path) -> Lock:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BuildError(f"toolchain lock not found: {_rel(path)}") from exc
    except json.JSONDecodeError as exc:
        raise BuildError(f"toolchain lock is not valid JSON: {_rel(path)}") from exc

    if raw.get("format") != "harpocrates.zk-toolchain-lock":
        raise BuildError("toolchain lock has an unexpected format identifier")
    if raw.get("version") != 1:
        raise BuildError(f"unsupported toolchain lock version: {raw.get('version')!r}")

    limits_raw = raw["limits"]
    limits = Limits(
        max_artifact_bytes=int(limits_raw["max_artifact_bytes"]),
        max_artifacts=int(limits_raw["max_artifacts"]),
        max_provenance_files=int(limits_raw["max_provenance_files"]),
        max_circuits=int(limits_raw["max_circuits"]),
    )

    artifacts_raw = raw["artifacts"]
    if not isinstance(artifacts_raw, list):
        raise BuildError("toolchain lock artifacts must be a JSON array")
    artifacts = tuple(artifacts_raw)
    if len(artifacts) > limits.max_artifacts:
        raise BuildError(
            f"lock declares {len(artifacts)} artifacts, above the cap of {limits.max_artifacts}"
        )
    for entry in artifacts:
        if not isinstance(entry, dict):
            raise BuildError("toolchain lock artifact entry must be a JSON object")
        validate_relative_manifest_path(entry.get("path"), field_name="lock artifact path")

    coverage = raw.get("coverage") or {}
    circuit_root = str(coverage.get("circuit_root", DEFAULT_CIRCUIT_ROOT))
    package_file = str(coverage.get("package_file", DEFAULT_PACKAGE_FILE))
    for label, value in (("circuit_root", circuit_root), ("package_file", package_file)):
        if not value or value.startswith("/") or ".." in value.split("/"):
            raise BuildError(f"toolchain lock declares an unusable coverage {label}: {value!r}")
        validate_relative_manifest_path(value, field_name=f"coverage {label}")
    if "/" in package_file:
        raise BuildError(
            f"toolchain lock declares an unusable coverage package_file: {package_file!r}"
        )

    provenance_globs = tuple(
        _validate_provenance_glob(pattern)
        for pattern in raw["provenance_sources"]["globs"]
    )

    return Lock(
        raw=raw,
        limits=limits,
        volatile_json_keys=frozenset(raw["normalization"]["json"]["volatile_keys"]),
        strip_custom_sections=frozenset(
            raw["normalization"]["wasm"]["strip_custom_sections"]
        ),
        artifacts=artifacts,
        provenance_globs=provenance_globs,
        circuit_root=circuit_root,
        package_file=package_file,
    )


# ── Normalization ───────────────────────────────────────────────────────────


def strip_volatile(value: Any, volatile_keys: frozenset[str]) -> Any:
    """Recursively drop keys the lock file declares volatile."""
    if isinstance(value, dict):
        return {
            key: strip_volatile(item, volatile_keys)
            for key, item in value.items()
            if key not in volatile_keys
        }
    if isinstance(value, list):
        return [strip_volatile(item, volatile_keys) for item in value]
    return value


def normalize_json(data: bytes, volatile_keys: frozenset[str]) -> bytes:
    """Canonicalize a JSON artifact: volatile keys removed, keys sorted, no
    incidental whitespace."""
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BuildError("artifact declared as JSON is not valid UTF-8 JSON") from exc

    return json.dumps(
        strip_volatile(parsed, volatile_keys),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a LEB128 unsigned integer. Bounded to five bytes (u32)."""
    result = 0
    shift = 0
    for _ in range(5):
        if offset >= len(data):
            raise BuildError("truncated WASM: LEB128 ran past end of file")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7
    raise BuildError("malformed WASM: over-long LEB128")


def normalize_wasm(data: bytes, strip_sections: frozenset[str]) -> bytes:
    """Drop the custom sections named in the lock file, preserving everything
    else byte-for-byte and in order.

    Implemented as a bounded forward walk with no recursion, so a corrupted or
    hostile module fails fast rather than consuming unbounded resources.
    """
    if len(data) < 8 or data[:4] != b"\x00asm":
        raise BuildError("artifact declared as WASM lacks the \\0asm magic header")

    out = bytearray(data[:8])  # magic + version
    offset = 8

    while offset < len(data):
        section_id = data[offset]
        offset += 1
        size, after_size = _read_uleb128(data, offset)
        body_start = after_size
        body_end = body_start + size
        if body_end > len(data):
            raise BuildError("truncated WASM: section length exceeds file size")

        if section_id == 0:  # custom section
            name_len, name_start = _read_uleb128(data, body_start)
            name_end = name_start + name_len
            if name_end > body_end:
                raise BuildError("malformed WASM: custom section name exceeds section")
            name = data[name_start:name_end].decode("utf-8", errors="replace")
            if name in strip_sections:
                offset = body_end
                continue

        out += data[offset - 1 : body_end]
        offset = body_end

    return bytes(out)


def normalize(data: bytes, kind: str, lock: Lock) -> bytes:
    if kind == "json":
        return normalize_json(data, lock.volatile_json_keys)
    if kind == "wasm":
        return normalize_wasm(data, lock.strip_custom_sections)
    if kind == "binary":
        return data
    raise BuildError(f"unknown artifact kind in lock file: {kind!r}")


# ── Digesting ───────────────────────────────────────────────────────────────


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rel(path: Path, root: Path | None = None) -> str:
    """Release-relative, forward-slashed path — the only path form ever logged."""
    base = (root or REPO_ROOT).resolve(strict=False)
    try:
        return path.resolve(strict=False).relative_to(base).as_posix()
    except ValueError:
        return _bounded_path_preview(path.name)


@dataclass
class ArtifactResult:
    path: str
    kind: str
    role: str
    state: str
    raw_bytes: int | None = None
    normalized_bytes: int | None = None
    raw_sha256: str | None = None
    normalized_sha256: str | None = None

    def to_entry(self) -> dict:
        return {
            "path": self.path,
            "kind": self.kind,
            "role": self.role,
            "raw_bytes": self.raw_bytes,
            "normalized_bytes": self.normalized_bytes,
            "raw_sha256": self.raw_sha256,
            "normalized_sha256": self.normalized_sha256,
        }


def digest_artifact(declaration: dict, lock: Lock, root: Path) -> ArtifactResult:
    relative = validate_relative_manifest_path(declaration.get("path"))
    target = resolve_release_artifact_path(relative, root)
    kind = declaration["kind"]
    role = declaration.get("role", "unknown")
    required = bool(declaration.get("required", False))

    result = ArtifactResult(path=relative, kind=kind, role=role, state=ArtifactState.MISSING)

    if not target.is_file():
        result.state = ArtifactState.MISSING if required else ArtifactState.SKIPPED
        signal("artifact.state", path=relative, state=result.state, required=required)
        return result

    size = target.stat().st_size
    if size > lock.limits.max_artifact_bytes:
        result.state = ArtifactState.OVERSIZE
        result.raw_bytes = size
        signal(
            "artifact.state",
            path=relative,
            state=result.state,
            bytes=size,
            limit=lock.limits.max_artifact_bytes,
        )
        return result

    try:
        data = target.read_bytes()
    except OSError:
        result.state = ArtifactState.UNREADABLE
        signal("artifact.state", path=relative, state=result.state)
        return result

    normalized = normalize(data, kind, lock)

    result.state = ArtifactState.DIGESTED
    result.raw_bytes = len(data)
    result.normalized_bytes = len(normalized)
    result.raw_sha256 = sha256_hex(data)
    result.normalized_sha256 = sha256_hex(normalized)

    signal(
        "artifact.state",
        path=relative,
        state=result.state,
        bytes=result.raw_bytes,
        normalized_bytes=result.normalized_bytes,
        digest=result.normalized_sha256,
    )
    return result


# ── Provenance ──────────────────────────────────────────────────────────────


def collect_provenance(lock: Lock, root: Path) -> dict[str, str]:
    """Digest every source file that defines the artifacts.

    Sorted and bounded so the result is stable across filesystems with
    different directory iteration order. Resolves aliases inside ``root``
    before inspecting or reading any matched source file.
    """
    resolved_root = _resolve_release_root(root)
    found: dict[str, str] = {}
    for pattern in lock.provenance_globs:
        validated_pattern = _validate_provenance_glob(pattern)
        for matched in sorted(resolved_root.glob(validated_pattern)):
            try:
                rel_posix = matched.relative_to(resolved_root).as_posix()
            except ValueError as exc:
                raise PathValidationError(
                    "alias_escape",
                    "provenance glob matched path outside selected release directory",
                ) from exc
            resolved_source = resolve_release_artifact_path(
                rel_posix,
                resolved_root,
                field_name="provenance path",
            )
            if not resolved_source.is_file():
                continue
            if len(found) >= lock.limits.max_provenance_files:
                raise BuildError(
                    f"provenance set exceeds {lock.limits.max_provenance_files} files"
                )
            found[rel_posix] = sha256_hex(resolved_source.read_bytes())
    return dict(sorted(found.items()))


# ── Manifest ────────────────────────────────────────────────────────────────


@dataclass
class ManifestRun:
    entries: list[ArtifactResult] = field(default_factory=list)

    @property
    def fatal(self) -> list[ArtifactResult]:
        return [entry for entry in self.entries if entry.state in FATAL_STATES]

    @property
    def missing_required(self) -> list[ArtifactResult]:
        return [entry for entry in self.entries if entry.state == ArtifactState.MISSING]


def build_manifest(lock: Lock, root: Path) -> tuple[dict, ManifestRun]:
    run = ManifestRun()
    for declaration in lock.artifacts:
        run.entries.append(digest_artifact(declaration, lock, root))

    manifest = {
        "format": MANIFEST_FORMAT,
        "version": MANIFEST_VERSION,
        "toolchain": {
            "nargo": lock.toolchain["nargo"]["version"],
            "barretenberg": lock.toolchain["barretenberg"]["version"],
            "proving_scheme": lock.toolchain["proving_scheme"],
            "oracle_hash": lock.toolchain["oracle_hash"],
        },
        "environment": dict(sorted(lock.environment.items())),
        "normalization_policy_sha256": sha256_hex(
            json.dumps(lock.raw["normalization"], sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ),
        "provenance": collect_provenance(lock, root),
        "artifacts": [
            entry.to_entry()
            for entry in run.entries
            if entry.state == ArtifactState.DIGESTED
        ],
        "skipped": [
            entry.path
            for entry in run.entries
            if entry.state == ArtifactState.SKIPPED
        ],
    }
    return manifest, run


def serialize_manifest(manifest: dict) -> str:
    """Deterministic on-disk form: sorted keys, two-space indent, one trailing
    newline. Two builds that agree produce byte-identical files."""
    return json.dumps(manifest, sort_keys=True, indent=2) + "\n"


# ── Drift comparison ────────────────────────────────────────────────────────


def _validate_artifact_entry_list(
    entries: Any,
    *,
    field_name: str,
    release_dir: Path | None = None,
) -> dict[str, dict]:
    if not isinstance(entries, list):
        raise BuildError(f"{field_name} must be a JSON array")
    indexed: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise BuildError(f"every item in {field_name} must be a JSON object")
        normalized = validate_relative_manifest_path(
            entry.get("path"),
            field_name=field_name,
        )
        if release_dir is not None:
            resolve_release_artifact_path(
                normalized,
                release_dir,
                field_name=field_name,
            )
        if normalized in indexed:
            raise BuildError(f"duplicate {field_name}: {normalized}")
        indexed[normalized] = entry
    return indexed


def _validate_provenance_map(
    mapping: Any,
    *,
    release_dir: Path | None = None,
) -> dict[str, str]:
    if not isinstance(mapping, dict):
        raise BuildError("provenance must be a JSON object")
    validated: dict[str, str] = {}
    for raw_key, digest in mapping.items():
        normalized = validate_relative_manifest_path(
            raw_key,
            field_name="provenance path",
        )
        if release_dir is not None:
            resolve_release_artifact_path(
                normalized,
                release_dir,
                field_name="provenance path",
            )
        validated[normalized] = digest
    return validated


def _validate_skipped_list(
    skipped: Any,
    *,
    release_dir: Path | None = None,
) -> None:
    if skipped is None:
        return
    if not isinstance(skipped, list):
        raise BuildError("skipped must be a JSON array")
    for item in skipped:
        normalized = validate_relative_manifest_path(
            item,
            field_name="skipped artifact path",
        )
        if release_dir is not None:
            resolve_release_artifact_path(
                normalized,
                release_dir,
                field_name="skipped artifact path",
            )


def compare_manifests(expected: dict, actual: dict) -> list[str]:
    """Return a stable, human-readable list of drift findings.

    Findings name paths and digests only. A digest mismatch is reported as two
    digests, never as a content diff — dumping artifact bytes into CI logs is
    exactly the leak this pipeline exists to prevent.
    """
    findings: list[str] = []

    for key in ("format", "version"):
        if expected.get(key) != actual.get(key):
            findings.append(
                f"manifest {key}: expected {expected.get(key)!r}, got {actual.get(key)!r}"
            )

    for key, expected_value in sorted(expected.get("toolchain", {}).items()):
        actual_value = actual.get("toolchain", {}).get(key)
        if expected_value != actual_value:
            findings.append(
                f"toolchain.{key}: expected {expected_value!r}, got {actual_value!r}"
            )

    if expected.get("normalization_policy_sha256") != actual.get(
        "normalization_policy_sha256"
    ):
        findings.append(
            "normalization policy changed; artifacts digested under different rules"
        )

    expected_provenance = _validate_provenance_map(expected.get("provenance", {}))
    actual_provenance = _validate_provenance_map(actual.get("provenance", {}))
    for path in sorted(set(expected_provenance) | set(actual_provenance)):
        before = expected_provenance.get(path)
        after = actual_provenance.get(path)
        if before != after:
            findings.append(
                f"source {path}: {_short(before)} -> {_short(after)}"
            )

    expected_artifacts = _validate_artifact_entry_list(
        expected.get("artifacts", []),
        field_name="manifest artifact path",
    )
    actual_artifacts = _validate_artifact_entry_list(
        actual.get("artifacts", []),
        field_name="manifest artifact path",
    )

    for path in sorted(set(expected_artifacts) | set(actual_artifacts)):
        before = expected_artifacts.get(path)
        after = actual_artifacts.get(path)
        if before is None:
            findings.append(f"artifact {path}: unexpected, not present in the manifest")
            continue
        if after is None:
            findings.append(f"artifact {path}: missing from the rebuilt tree")
            continue
        if before.get("normalized_sha256") != after.get("normalized_sha256"):
            findings.append(
                f"artifact {path}: normalized digest "
                f"{_short(before.get('normalized_sha256'))} -> "
                f"{_short(after.get('normalized_sha256'))}"
            )
        elif before.get("raw_sha256") != after.get("raw_sha256"):
            findings.append(
                f"artifact {path}: raw bytes differ but normalize to the same digest "
                "(host metadata only; not a semantic change)"
            )

    return findings


def _short(digest: str | None) -> str:
    if digest is None:
        return "absent"
    return digest[:16]




# ── Published circuit provenance ─────────────────────────────────────────────


def build_provenance(lock: Lock, root: Path) -> dict:
    """Publish digests of the circuit sources that define declared artifacts.

    This is the toolchain-bound provenance slice of a full artifact manifest,
    writable without compiling ACIR or generating verification keys. It does not
    create a second protocol truth: globs, limits, toolchain, and declared
    artifact slots all come from ``zk/toolchain.lock.json``.
    """
    sources = collect_provenance(lock, root)
    if not sources:
        raise BuildError(
            "provenance globs matched no circuit sources; provenance not written"
        )

    declared = []
    for entry in lock.artifacts:
        declared.append(
            {
                "path": entry["path"],
                "kind": entry["kind"],
                "role": entry.get("role", "unknown"),
                "required": bool(entry.get("required", False)),
            }
        )

    return {
        "format": PROVENANCE_FORMAT,
        "version": MANIFEST_VERSION,
        "toolchain": {
            "nargo": lock.toolchain["nargo"]["version"],
            "barretenberg": lock.toolchain["barretenberg"]["version"],
            "proving_scheme": lock.toolchain["proving_scheme"],
            "oracle_hash": lock.toolchain["oracle_hash"],
        },
        "environment": dict(sorted(lock.environment.items())),
        "normalization_policy_sha256": sha256_hex(
            json.dumps(lock.raw["normalization"], sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ),
        "provenance_globs": list(lock.provenance_globs),
        "provenance": sources,
        "declared_artifacts": declared,
    }


def compare_provenance(expected: dict, actual: dict) -> list[str]:
    """Diff two provenance documents. Paths and digests only; no source bytes."""
    findings: list[str] = []

    for key in ("format", "version"):
        if expected.get(key) != actual.get(key):
            findings.append(
                f"provenance {key}: expected {expected.get(key)!r}, got {actual.get(key)!r}"
            )

    for key, expected_value in sorted(expected.get("toolchain", {}).items()):
        actual_value = actual.get("toolchain", {}).get(key)
        if expected_value != actual_value:
            findings.append(
                f"toolchain.{key}: expected {expected_value!r}, got {actual_value!r}"
            )

    if expected.get("normalization_policy_sha256") != actual.get(
        "normalization_policy_sha256"
    ):
        findings.append(
            "normalization policy changed; provenance digested under different rules"
        )

    expected_globs = [
        _validate_provenance_glob(glob_pattern)
        for glob_pattern in (expected.get("provenance_globs") or [])
    ]
    actual_globs = [
        _validate_provenance_glob(glob_pattern)
        for glob_pattern in (actual.get("provenance_globs") or [])
    ]
    if expected_globs != actual_globs:
        findings.append(
            "provenance_globs changed; source set is no longer comparable under the same policy"
        )

    expected_sources = _validate_provenance_map(expected.get("provenance", {}))
    actual_sources = _validate_provenance_map(actual.get("provenance", {}))
    for path in sorted(set(expected_sources) | set(actual_sources)):
        before = expected_sources.get(path)
        after = actual_sources.get(path)
        if before != after:
            findings.append(f"source {path}: {_short(before)} -> {_short(after)}")

    expected_declared = _validate_artifact_entry_list(
        expected.get("declared_artifacts", []),
        field_name="declared artifact path",
    )
    actual_declared = _validate_artifact_entry_list(
        actual.get("declared_artifacts", []),
        field_name="declared artifact path",
    )
    for path in sorted(set(expected_declared) | set(actual_declared)):
        before = expected_declared.get(path)
        after = actual_declared.get(path)
        if before is None:
            findings.append(
                f"declared artifact {path}: unexpected, not present in published provenance"
            )
            continue
        if after is None:
            findings.append(
                f"declared artifact {path}: missing from lock-declared artifact set"
            )
            continue
        for field_key in ("kind", "role", "required"):
            if before.get(field_key) != after.get(field_key):
                findings.append(
                    f"declared artifact {path}.{field_key}: "
                    f"expected {before.get(field_key)!r}, got {after.get(field_key)!r}"
                )

    return findings


def _load_provenance(path: Path, release_dir: Path | None = None) -> dict:
    if not path.is_file():
        raise BuildError(f"circuit provenance not found: {_rel(path, release_dir)}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BuildError(f"circuit provenance is not valid JSON: {_rel(path, release_dir)}") from exc
    if not isinstance(document, dict) or document.get("format") != PROVENANCE_FORMAT:
        raise BuildError(f"not a circuit provenance document: {_rel(path, release_dir)}")
    if document.get("version") != MANIFEST_VERSION:
        raise BuildError(
            f"unsupported circuit provenance version: {document.get('version')!r}"
        )
    for glob_pattern in document.get("provenance_globs") or []:
        _validate_provenance_glob(glob_pattern)
    _validate_provenance_map(document.get("provenance", {}), release_dir=release_dir)
    _validate_artifact_entry_list(
        document.get("declared_artifacts", []),
        field_name="declared artifact path",
        release_dir=release_dir,
    )
    return document


def _selected_release_dir(args: argparse.Namespace) -> Path:
    raw = getattr(args, "release_dir", None)
    if raw is None:
        return REPO_ROOT
    return _resolve_release_root(Path(raw))


def _selected_lock_path(args: argparse.Namespace, release_dir: Path) -> Path:
    raw_lock = getattr(args, "lock", None)
    if raw_lock is not None:
        return Path(raw_lock)
    if getattr(args, "release_dir", None) is not None:
        candidate = resolve_release_artifact_path(
            "zk/toolchain.lock.json",
            release_dir,
            field_name="lock path",
        )
        if candidate.is_file():
            return candidate
    return DEFAULT_LOCK


def command_write_provenance(args: argparse.Namespace) -> int:
    release_dir = _selected_release_dir(args)
    lock = load_lock(_selected_lock_path(args, release_dir))
    document = build_provenance(lock, release_dir)

    output = (
        Path(args.output)
        if args.output is not None
        else (
            resolve_release_artifact_path(
                "zk/circuit.provenance.json",
                release_dir,
                field_name="provenance output path",
            )
            if getattr(args, "release_dir", None) is not None
            else DEFAULT_PROVENANCE
        )
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(serialize_manifest(document), encoding="utf-8")
    signal(
        "provenance.written",
        path=_rel(output, release_dir),
        sources=len(document["provenance"]),
        declared_artifacts=len(document["declared_artifacts"]),
    )
    return EXIT_OK


def command_verify_provenance(args: argparse.Namespace) -> int:
    """Verify lock-declared circuit sources against committed provenance."""
    release_dir = _selected_release_dir(args)
    lock = load_lock(_selected_lock_path(args, release_dir))
    manifest_path = (
        Path(args.manifest)
        if args.manifest is not None
        else (
            resolve_release_artifact_path(
                "zk/circuit.provenance.json",
                release_dir,
                field_name="provenance manifest path",
            )
            if getattr(args, "release_dir", None) is not None
            else DEFAULT_PROVENANCE
        )
    )
    expected = _load_provenance(manifest_path, release_dir=release_dir)
    actual = build_provenance(lock, release_dir)

    findings = compare_provenance(expected, actual)
    if findings:
        for finding in findings:
            signal("drift.finding", detail=finding)
        signal("provenance.verify.failed", findings=len(findings))
        return EXIT_DRIFT

    signal("provenance.verify.ok", sources=len(actual["provenance"]))
    return EXIT_OK


# ── Browser published ACIR ──────────────────────────────────────────────────


def published_acir_declarations(lock: Lock) -> tuple[dict, ...]:
    """Return lock entries that ship into the browser Evidence Studio."""
    return tuple(
        entry for entry in lock.artifacts if entry.get("role") == PUBLISHED_ACIR_ROLE
    )


def published_to_build_target(published_path: str) -> str:
    """Map ``frontend/public/noir/<name>.json`` to its Noir build-target twin.

    The browser bundle is a *publish* of the compiled ACIR, not a second circuit
    truth. Pairing by stem keeps the lock file as the single declaration of
    which circuits are browser-facing.
    """
    prefix = "frontend/public/noir/"
    if not published_path.startswith(prefix) or ".." in published_path:
        raise BuildError(f"refusing to derive a build target from path: {published_path!r}")
    remainder = published_path[len(prefix) :]
    if any(sep in remainder for sep in ("/", chr(92))) or not remainder.endswith(".json"):
        raise BuildError(f"refusing to derive a build target from path: {published_path!r}")
    stem = remainder[: -len(".json")]
    if not stem or not re.fullmatch(r"[A-Za-z0-9_]+", stem):
        raise BuildError(f"refusing to derive a build target from path: {published_path!r}")
    return f"zk/noir/{stem}/target/{stem}.json"


def build_browser_manifest(lock: Lock, root: Path) -> tuple[dict, ManifestRun]:
    """Digest only ``published_acir`` entries for the browser trust boundary."""
    declarations = published_acir_declarations(lock)
    if not declarations:
        raise BuildError("toolchain lock declares no published_acir browser artifacts")

    run = ManifestRun()
    for declaration in declarations:
        # Browser publishes are optional in the general lock (required:false) so
        # a repo without a given bundle still verifies. Force required=False here
        # and treat missing as SKIPPED; the committed browser manifest then
        # decides which digests must be present.
        softened = dict(declaration)
        softened["required"] = False
        run.entries.append(digest_artifact(softened, lock, root))

    for entry in run.fatal:
        # Oversized / unreadable published ACIR is always fatal: the browser
        # trust boundary must not silently skip a corrupted public bundle.
        pass

    manifest = {
        "format": BROWSER_MANIFEST_FORMAT,
        "version": MANIFEST_VERSION,
        "toolchain": {
            "nargo": lock.toolchain["nargo"]["version"],
            "barretenberg": lock.toolchain["barretenberg"]["version"],
            "proving_scheme": lock.toolchain["proving_scheme"],
            "oracle_hash": lock.toolchain["oracle_hash"],
        },
        "normalization_policy_sha256": sha256_hex(
            json.dumps(lock.raw["normalization"], sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ),
        "artifacts": [
            entry.to_entry()
            for entry in run.entries
            if entry.state == ArtifactState.DIGESTED
        ],
        "skipped": [
            entry.path
            for entry in run.entries
            if entry.state == ArtifactState.SKIPPED
        ],
    }
    return manifest, run


def compare_published_to_targets(lock: Lock, root: Path) -> list[str]:
    """When both a published ACIR and its build target exist, digests must match.

    Findings name paths and truncated digests only — never artifact bytes.
    Missing either side is not drift: targets are often gitignored, and a
    published bundle may wait for a later publish step.
    """
    findings: list[str] = []
    for declaration in published_acir_declarations(lock):
        published_path = validate_relative_manifest_path(declaration.get("path"))
        target_path = published_to_build_target(published_path)
        published = resolve_release_artifact_path(published_path, root)
        target = resolve_release_artifact_path(target_path, root)
        if not published.is_file() or not target.is_file():
            continue

        published_decl = {
            "path": published_path,
            "kind": declaration.get("kind", "json"),
            "role": PUBLISHED_ACIR_ROLE,
            "required": True,
        }
        target_decl = {
            "path": target_path,
            "kind": declaration.get("kind", "json"),
            "role": "acir",
            "required": True,
        }
        published_result = digest_artifact(published_decl, lock, root)
        target_result = digest_artifact(target_decl, lock, root)

        if published_result.state != ArtifactState.DIGESTED:
            findings.append(
                f"browser artifact {published_path}: unusable state {published_result.state}"
            )
            continue
        if target_result.state != ArtifactState.DIGESTED:
            findings.append(
                f"build target {target_path}: unusable state {target_result.state}"
            )
            continue
        if published_result.normalized_sha256 != target_result.normalized_sha256:
            findings.append(
                f"browser artifact {published_path}: normalized digest "
                f"{_short(published_result.normalized_sha256)} disagrees with build target "
                f"{target_path} {_short(target_result.normalized_sha256)}"
            )
        else:
            signal(
                "browser.target_matched",
                path=published_path,
                target=target_path,
                digest=published_result.normalized_sha256,
            )
    return findings


def _load_browser_manifest(path: Path, release_dir: Path | None = None) -> dict:
    if not path.is_file():
        raise BuildError(f"browser manifest not found: {_rel(path, release_dir)}")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BuildError(f"browser manifest is not valid JSON: {_rel(path, release_dir)}") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != BROWSER_MANIFEST_FORMAT:
        raise BuildError(f"not a browser artifact manifest: {_rel(path, release_dir)}")
    if manifest.get("version") != MANIFEST_VERSION:
        raise BuildError(
            f"unsupported browser manifest version: {manifest.get('version')!r}"
        )
    _validate_artifact_entry_list(
        manifest.get("artifacts", []),
        field_name="browser artifact path",
        release_dir=release_dir,
    )
    _validate_skipped_list(manifest.get("skipped"), release_dir=release_dir)
    return manifest


def compare_browser_manifests(expected: dict, actual: dict) -> list[str]:
    """Diff two browser manifests. Digests and paths only; no content."""
    findings: list[str] = []

    for key in ("format", "version"):
        if expected.get(key) != actual.get(key):
            findings.append(
                f"browser manifest {key}: expected {expected.get(key)!r}, "
                f"got {actual.get(key)!r}"
            )

    for key, expected_value in sorted(expected.get("toolchain", {}).items()):
        actual_value = actual.get("toolchain", {}).get(key)
        if expected_value != actual_value:
            findings.append(
                f"toolchain.{key}: expected {expected_value!r}, got {actual_value!r}"
            )

    if expected.get("normalization_policy_sha256") != actual.get(
        "normalization_policy_sha256"
    ):
        findings.append(
            "normalization policy changed; browser artifacts digested under different rules"
        )

    expected_artifacts = _validate_artifact_entry_list(
        expected.get("artifacts", []),
        field_name="browser artifact path",
    )
    actual_artifacts = _validate_artifact_entry_list(
        actual.get("artifacts", []),
        field_name="browser artifact path",
    )

    for path in sorted(set(expected_artifacts) | set(actual_artifacts)):
        before = expected_artifacts.get(path)
        after = actual_artifacts.get(path)
        if before is None:
            findings.append(
                f"browser artifact {path}: unexpected publish, not in the browser manifest"
            )
            continue
        if after is None:
            findings.append(
                f"browser artifact {path}: missing from frontend/public/noir "
                "(declared in the browser manifest)"
            )
            continue
        if before.get("normalized_sha256") != after.get("normalized_sha256"):
            findings.append(
                f"browser artifact {path}: normalized digest "
                f"{_short(before.get('normalized_sha256'))} -> "
                f"{_short(after.get('normalized_sha256'))}"
            )
        elif before.get("raw_sha256") != after.get("raw_sha256"):
            findings.append(
                f"browser artifact {path}: raw bytes differ but normalize to the same digest "
                "(host metadata only; not a semantic change)"
            )

    return findings


def command_write_browser(args: argparse.Namespace) -> int:
    release_dir = _selected_release_dir(args)
    lock = load_lock(_selected_lock_path(args, release_dir))
    manifest, run = build_browser_manifest(lock, release_dir)
    if run.fatal:
        for entry in run.fatal:
            signal("run.fatal", path=entry.path, state=entry.state)
        raise BuildError(
            f"{len(run.fatal)} browser artifact(s) in a fatal state; "
            "browser manifest not written"
        )
    if not manifest["artifacts"]:
        raise BuildError(
            "no published browser ACIR found under frontend/public/noir; "
            "browser manifest not written"
        )

    output = (
        Path(args.output)
        if args.output is not None
        else (
            resolve_release_artifact_path(
                "zk/browser.artifacts.manifest.json",
                release_dir,
                field_name="browser manifest output path",
            )
            if getattr(args, "release_dir", None) is not None
            else DEFAULT_BROWSER_MANIFEST
        )
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(serialize_manifest(manifest), encoding="utf-8")
    signal(
        "browser.manifest.written",
        path=_rel(output, release_dir),
        artifacts=len(manifest["artifacts"]),
        skipped=len(manifest["skipped"]),
    )
    return EXIT_OK


def command_verify_browser(args: argparse.Namespace) -> int:
    """Verify published browser ACIR against the committed browser manifest.

    Also, when a matching build-target ACIR is on disk, require an identical
    normalized digest so a publish step cannot silently ship a different circuit
    than the one the reproducible-build pipeline produced.
    """
    release_dir = _selected_release_dir(args)
    lock = load_lock(_selected_lock_path(args, release_dir))
    manifest_path = (
        Path(args.manifest)
        if args.manifest is not None
        else (
            resolve_release_artifact_path(
                "zk/browser.artifacts.manifest.json",
                release_dir,
                field_name="browser manifest path",
            )
            if getattr(args, "release_dir", None) is not None
            else DEFAULT_BROWSER_MANIFEST
        )
    )
    expected = _load_browser_manifest(manifest_path, release_dir=release_dir)
    actual, run = build_browser_manifest(lock, release_dir)
    if run.fatal:
        for entry in run.fatal:
            signal("run.fatal", path=entry.path, state=entry.state)
        raise BuildError(
            f"{len(run.fatal)} browser artifact(s) in a fatal state; verify aborted"
        )

    findings = compare_browser_manifests(expected, actual)
    findings.extend(compare_published_to_targets(lock, release_dir))

    if findings:
        for finding in findings:
            signal("drift.finding", detail=finding)
        signal("browser.verify.failed", findings=len(findings))
        return EXIT_DRIFT

    signal("browser.verify.ok", artifacts=len(actual["artifacts"]))
    return EXIT_OK



# ── Circuit coverage ─────────────────────────────────────────────────────────
#
# The digest manifest is only as complete as the lock file. A circuit that is
# added to zk/noir but never declared would be compiled by nobody, digested by
# nothing, and still reachable at a public boundary — a second, unpinned
# protocol truth. This gate makes that state a build failure instead of a silent
# gap, in either direction: an undeclared package, or a declared artifact whose
# package has been renamed or removed.


def declared_circuit_names(lock: Lock) -> set[str]:
    """Circuit names the lock declares a build-target ACIR for.

    Read off the artifact paths themselves rather than a parallel list, so the
    lock file stays the single declaration of which circuits are pinned. Only
    the canonical ``<root>/<name>/target/<name>.json`` shape counts: a declared
    path that does not have that shape is not evidence of coverage.
    """
    prefix = f"{lock.circuit_root}/"
    names: set[str] = set()
    for entry in lock.artifacts:
        if entry.get("role") != ACIR_ROLE:
            continue
        relative = str(entry.get("path", ""))
        if not relative.startswith(prefix):
            continue
        parts = relative[len(prefix) :].split("/")
        if len(parts) != 3 or parts[1] != "target" or not parts[2].endswith(".json"):
            continue
        name = parts[2][: -len(".json")]
        if name and name == parts[0]:
            names.add(name)
    return names


def _is_library_package(package_toml: Path) -> bool:
    """Return True when a Nargo.toml declares ``type = \"lib\"``."""
    try:
        text = package_toml.read_text(encoding="utf-8")
    except OSError:
        return False
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if re.fullmatch(r'type\s*=\s*["\']lib["\']', line):
            return True
    return False


def discover_circuit_packages(lock: Lock, root: Path) -> list[str]:
    """Every binary Noir circuit package in the tree.

    A sibling directory without ``Nargo.toml`` (``scripts/``, ``tools/``) or a
    shared Noir library crate (``type = \"lib\"``) produces no ACIR artifact and
    is ignored, so neither a helper script, a shared library, nor a stray build
    directory can fail the gate. The walk is sorted and capped by
    ``limits.max_circuits``.
    """
    base = resolve_release_artifact_path(
        lock.circuit_root,
        root,
        field_name="coverage circuit_root",
    )
    if not base.is_dir():
        return []

    names: list[str] = []
    for path in sorted(base.iterdir()):
        resolved_pkg_dir = resolve_release_artifact_path(
            f"{lock.circuit_root}/{path.name}",
            root,
            field_name="circuit package directory",
        )
        if not resolved_pkg_dir.is_dir():
            continue
        package_toml = resolve_release_artifact_path(
            f"{lock.circuit_root}/{path.name}/{lock.package_file}",
            root,
            field_name="circuit package manifest",
        )
        if not package_toml.is_file():
            continue
        if _is_library_package(package_toml):
            continue
        if len(names) >= lock.limits.max_circuits:
            raise BuildError(
                f"circuit count exceeds {lock.limits.max_circuits}; refusing to continue"
            )
        names.append(path.name)
    return names


def check_coverage(lock: Lock, root: Path) -> list[str]:
    """Findings for circuits that exist but are unpinned, and pins with no circuit.

    Findings name circuits and paths only. No artifact is read, so nothing that
    could carry witness or key material can reach a finding.
    """
    on_disk = set(discover_circuit_packages(lock, root))
    declared = declared_circuit_names(lock)

    findings: list[str] = []
    for name in sorted(on_disk - declared):
        findings.append(
            f"circuit {name}: package on disk declares no "
            f"{lock.circuit_root}/{name}/target/{name}.json artifact; "
            "it would be built and digested by nothing"
        )
    for name in sorted(declared - on_disk):
        findings.append(
            f"circuit {name}: declared artifact has no "
            f"{lock.circuit_root}/{name}/{lock.package_file} package; "
            "the pin can never be rebuilt"
        )
    return findings


def command_check_coverage(args: argparse.Namespace) -> int:
    release_dir = _selected_release_dir(args)
    lock = load_lock(_selected_lock_path(args, release_dir))
    findings = check_coverage(lock, release_dir)
    if findings:
        for finding in findings:
            signal("drift.finding", detail=finding)
        signal("coverage.failed", findings=len(findings))
        return EXIT_DRIFT

    signal("coverage.ok", circuits=len(declared_circuit_names(lock)))
    return EXIT_OK


# ── Commands ────────────────────────────────────────────────────────────────


def _fail_on_fatal(run: ManifestRun) -> None:
    for entry in run.fatal:
        signal("run.fatal", path=entry.path, state=entry.state)
    for entry in run.missing_required:
        signal("run.fatal", path=entry.path, state=entry.state)
    if run.fatal or run.missing_required:
        raise BuildError(
            f"{len(run.fatal) + len(run.missing_required)} artifact(s) in a fatal state; "
            "manifest not written"
        )


def command_write(args: argparse.Namespace) -> int:
    release_dir = _selected_release_dir(args)
    lock = load_lock(_selected_lock_path(args, release_dir))
    manifest, run = build_manifest(lock, release_dir)
    _fail_on_fatal(run)

    output = (
        Path(args.output)
        if args.output is not None
        else (
            resolve_release_artifact_path(
                "zk/artifacts.manifest.json",
                release_dir,
                field_name="manifest output path",
            )
            if getattr(args, "release_dir", None) is not None
            else DEFAULT_MANIFEST
        )
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(serialize_manifest(manifest), encoding="utf-8")

    signal(
        "manifest.written",
        path=_rel(output, release_dir),
        artifacts=len(manifest["artifacts"]),
        skipped=len(manifest["skipped"]),
        sources=len(manifest["provenance"]),
    )
    return EXIT_OK


def command_verify(args: argparse.Namespace) -> int:
    release_dir = _selected_release_dir(args)
    lock = load_lock(_selected_lock_path(args, release_dir))
    manifest_path = (
        Path(args.manifest)
        if args.manifest is not None
        else (
            resolve_release_artifact_path(
                "zk/artifacts.manifest.json",
                release_dir,
                field_name="manifest path",
            )
            if getattr(args, "release_dir", None) is not None
            else DEFAULT_MANIFEST
        )
    )
    expected = _load_manifest(manifest_path, release_dir=release_dir)
    actual, run = build_manifest(lock, release_dir)
    _fail_on_fatal(run)

    findings = compare_manifests(expected, actual)
    if findings:
        for finding in findings:
            signal("drift.finding", detail=finding)
        signal("verify.failed", findings=len(findings))
        return EXIT_DRIFT

    signal("verify.ok", artifacts=len(actual["artifacts"]))
    return EXIT_OK


def _load_manifest(path: Path, release_dir: Path | None = None) -> dict:
    if not path.is_file():
        raise BuildError(f"manifest not found: {_rel(path, release_dir)}")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BuildError(f"manifest is not valid JSON: {_rel(path, release_dir)}") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != MANIFEST_FORMAT:
        raise BuildError(f"not an artifact manifest: {_rel(path, release_dir)}")
    _validate_artifact_entry_list(
        manifest.get("artifacts", []),
        field_name="manifest artifact path",
        release_dir=release_dir,
    )
    _validate_provenance_map(manifest.get("provenance", {}), release_dir=release_dir)
    _validate_skipped_list(manifest.get("skipped"), release_dir=release_dir)
    return manifest


def command_compare(args: argparse.Namespace) -> int:
    release_dir = (
        _selected_release_dir(args)
        if getattr(args, "release_dir", None) is not None
        else None
    )
    first = _load_manifest(Path(args.first), release_dir=release_dir)
    second = _load_manifest(Path(args.second), release_dir=release_dir)

    findings = compare_manifests(first, second)
    if findings:
        for finding in findings:
            signal("drift.finding", detail=finding)
        signal("compare.failed", findings=len(findings))
        return EXIT_DRIFT

    signal("compare.ok", artifacts=len(first.get("artifacts", [])))
    return EXIT_OK


def _add_release_dir_subarg(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--release-dir",
        default=argparse.SUPPRESS,
        help="selected release directory boundary (defaults to repository root)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--lock", default=None, help="path to zk/toolchain.lock.json"
    )
    parser.add_argument(
        "--release-dir",
        default=None,
        help="selected release directory boundary (defaults to repository root)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    write = subparsers.add_parser("write", help="write a manifest from the working tree")
    write.add_argument("--output", default=None)
    _add_release_dir_subarg(write)
    write.set_defaults(handler=command_write)

    verify = subparsers.add_parser("verify", help="fail on drift from a manifest")
    verify.add_argument("--manifest", default=None)
    _add_release_dir_subarg(verify)
    verify.set_defaults(handler=command_verify)

    compare = subparsers.add_parser("compare", help="diff two manifests (double build)")
    compare.add_argument("first")
    compare.add_argument("second")
    _add_release_dir_subarg(compare)
    compare.set_defaults(handler=command_compare)

    coverage = subparsers.add_parser(
        "check-coverage",
        help="fail when the lock and the source tree disagree about which circuits exist",
    )
    _add_release_dir_subarg(coverage)
    coverage.set_defaults(handler=command_check_coverage)

    write_browser = subparsers.add_parser(
        "write-browser",
        help="write a manifest for published browser ACIR under frontend/public/noir",
    )
    write_browser.add_argument("--output", default=None)
    _add_release_dir_subarg(write_browser)
    write_browser.set_defaults(handler=command_write_browser)

    verify_browser = subparsers.add_parser(
        "verify-browser",
        help="fail if published browser ACIR drifts from the browser manifest "
        "or from matching build-target ACIR",
    )
    verify_browser.add_argument("--manifest", default=None)
    _add_release_dir_subarg(verify_browser)
    verify_browser.set_defaults(handler=command_verify_browser)

    write_provenance = subparsers.add_parser(
        "write-provenance",
        help="write published circuit source provenance from the toolchain lock",
    )
    write_provenance.add_argument("--output", default=None)
    _add_release_dir_subarg(write_provenance)
    write_provenance.set_defaults(handler=command_write_provenance)

    verify_provenance = subparsers.add_parser(
        "verify-provenance",
        help="fail if circuit sources drift from the committed provenance document",
    )
    verify_provenance.add_argument("--manifest", default=None)
    _add_release_dir_subarg(verify_provenance)
    verify_provenance.set_defaults(handler=command_verify_provenance)

    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.handler(args))
    except BuildError as error:
        signal("run.error", reason=str(error))
        return EXIT_FATAL
    except KeyboardInterrupt:
        # Cancellation is a first-class outcome: nothing is half-written,
        # because the manifest is only written after every artifact resolves.
        signal("run.cancelled")
        return EXIT_FATAL


if __name__ == "__main__":
    os.environ.setdefault("PYTHONHASHSEED", "0")
    sys.exit(main())
