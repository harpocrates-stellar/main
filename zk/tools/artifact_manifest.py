#!/usr/bin/env python3
"""Reproducible-artifact manifest tool for the Harpocrates zk pipeline.

Guarantees that generated ACIR bundles, verification keys, and WASM artifacts
match their source and the pinned toolchain in ``zk/toolchain.lock.json``.

    write             normalize every declared artifact, digest it, and emit a manifest
    verify            re-digest the working tree and fail on any drift from a manifest
    compare           diff two manifests (the double-build reproducibility check)
    check-coverage    fail when the lock and the source tree disagree about which
                      circuits exist, so no circuit can ship unpinned
    dependency-graph  emit the source, helper, upstream-artifact, and toolchain
                      dependency graph and flag stale derived artifacts before packaging
    write-browser     digest published browser ACIR and emit the browser manifest
    verify-browser    fail if published ACIR drifts from the browser manifest or
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

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python <3.11 fallback
    tomllib = None  # type: ignore[assignment]

MANIFEST_FORMAT = "harpocrates.zk-artifact-manifest"
MANIFEST_VERSION = 1

DEPENDENCY_GRAPH_FORMAT = "harpocrates.zk-dependency-graph"
DEPENDENCY_GRAPH_VERSION = 1

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOCK = REPO_ROOT / "zk" / "toolchain.lock.json"
DEFAULT_MANIFEST = REPO_ROOT / "zk" / "artifacts.manifest.json"
DEFAULT_BROWSER_MANIFEST = REPO_ROOT / "zk" / "browser.artifacts.manifest.json"

BROWSER_MANIFEST_FORMAT = "harpocrates.zk-browser-artifact-manifest"
PROVENANCE_FORMAT = "harpocrates.zk-circuit-provenance"
DEFAULT_PROVENANCE = REPO_ROOT / "zk" / "circuit.provenance.json"
PUBLISHED_ACIR_ROLE = "published_acir"
ACIR_ROLE = "acir"
SOROBAN_VK_ROLE = "soroban_verification_key"

DEFAULT_CIRCUIT_ROOT = "zk/noir"
DEFAULT_PACKAGE_FILE = "Nargo.toml"

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

    artifacts = tuple(raw["artifacts"])
    if len(artifacts) > limits.max_artifacts:
        raise BuildError(
            f"lock declares {len(artifacts)} artifacts, above the cap of {limits.max_artifacts}"
        )

    coverage = raw.get("coverage") or {}
    circuit_root = str(coverage.get("circuit_root", DEFAULT_CIRCUIT_ROOT))
    package_file = str(coverage.get("package_file", DEFAULT_PACKAGE_FILE))
    for label, value in (("circuit_root", circuit_root), ("package_file", package_file)):
        if not value or value.startswith("/") or ".." in value.split("/"):
            raise BuildError(f"toolchain lock declares an unusable coverage {label}: {value!r}")

    return Lock(
        raw=raw,
        limits=limits,
        volatile_json_keys=frozenset(raw["normalization"]["json"]["volatile_keys"]),
        strip_custom_sections=frozenset(
            raw["normalization"]["wasm"]["strip_custom_sections"]
        ),
        artifacts=artifacts,
        provenance_globs=tuple(raw["provenance_sources"]["globs"]),
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
    """Root-relative, forward-slashed path — the only path form ever logged."""
    base = (root or REPO_ROOT).resolve()
    try:
        return path.resolve().relative_to(base).as_posix()
    except ValueError:
        return path.name


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
    relative = declaration["path"]
    kind = declaration["kind"]
    role = declaration.get("role", "unknown")
    required = bool(declaration.get("required", False))
    target = root / relative

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
    different directory iteration order.
    """
    resolved_root = root.resolve()
    found: dict[str, str] = {}
    for pattern in lock.provenance_globs:
        for path in sorted(resolved_root.glob(pattern)):
            if not path.is_file():
                continue
            if len(found) >= lock.limits.max_provenance_files:
                raise BuildError(
                    f"provenance set exceeds {lock.limits.max_provenance_files} files"
                )
            found[_rel(path, resolved_root)] = sha256_hex(path.read_bytes())
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

    expected_provenance = expected.get("provenance", {})
    actual_provenance = actual.get("provenance", {})
    for path in sorted(set(expected_provenance) | set(actual_provenance)):
        before = expected_provenance.get(path)
        after = actual_provenance.get(path)
        if before != after:
            findings.append(
                f"source {path}: {_short(before)} -> {_short(after)}"
            )

    expected_artifacts = {entry["path"]: entry for entry in expected.get("artifacts", [])}
    actual_artifacts = {entry["path"]: entry for entry in actual.get("artifacts", [])}

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

    expected_globs = list(expected.get("provenance_globs") or [])
    actual_globs = list(actual.get("provenance_globs") or [])
    if expected_globs != actual_globs:
        findings.append(
            "provenance_globs changed; source set is no longer comparable under the same policy"
        )

    expected_sources = expected.get("provenance", {})
    actual_sources = actual.get("provenance", {})
    for path in sorted(set(expected_sources) | set(actual_sources)):
        before = expected_sources.get(path)
        after = actual_sources.get(path)
        if before != after:
            findings.append(f"source {path}: {_short(before)} -> {_short(after)}")

    expected_declared = {
        entry["path"]: entry for entry in expected.get("declared_artifacts", [])
    }
    actual_declared = {
        entry["path"]: entry for entry in actual.get("declared_artifacts", [])
    }
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
        for field in ("kind", "role", "required"):
            if before.get(field) != after.get(field):
                findings.append(
                    f"declared artifact {path}.{field}: "
                    f"expected {before.get(field)!r}, got {after.get(field)!r}"
                )

    return findings


def _load_provenance(path: Path) -> dict:
    if not path.is_file():
        raise BuildError(f"circuit provenance not found: {_rel(path)}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BuildError(f"circuit provenance is not valid JSON: {_rel(path)}") from exc
    if document.get("format") != PROVENANCE_FORMAT:
        raise BuildError(f"not a circuit provenance document: {_rel(path)}")
    if document.get("version") != MANIFEST_VERSION:
        raise BuildError(
            f"unsupported circuit provenance version: {document.get('version')!r}"
        )
    return document


def command_write_provenance(args: argparse.Namespace) -> int:
    lock = load_lock(Path(args.lock))
    document = build_provenance(lock, REPO_ROOT)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(serialize_manifest(document), encoding="utf-8")
    signal(
        "provenance.written",
        path=_rel(output),
        sources=len(document["provenance"]),
        declared_artifacts=len(document["declared_artifacts"]),
    )
    return EXIT_OK


def command_verify_provenance(args: argparse.Namespace) -> int:
    """Verify lock-declared circuit sources against committed provenance."""
    lock = load_lock(Path(args.lock))
    expected = _load_provenance(Path(args.manifest))
    actual = build_provenance(lock, REPO_ROOT)

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
        published_path = declaration["path"]
        target_path = published_to_build_target(published_path)
        published = root / published_path
        target = root / target_path
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


def _load_browser_manifest(path: Path) -> dict:
    if not path.is_file():
        raise BuildError(f"browser manifest not found: {_rel(path)}")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BuildError(f"browser manifest is not valid JSON: {_rel(path)}") from exc
    if manifest.get("format") != BROWSER_MANIFEST_FORMAT:
        raise BuildError(f"not a browser artifact manifest: {_rel(path)}")
    if manifest.get("version") != MANIFEST_VERSION:
        raise BuildError(
            f"unsupported browser manifest version: {manifest.get('version')!r}"
        )
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

    expected_artifacts = {entry["path"]: entry for entry in expected.get("artifacts", [])}
    actual_artifacts = {entry["path"]: entry for entry in actual.get("artifacts", [])}

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
    lock = load_lock(Path(args.lock))
    manifest, run = build_browser_manifest(lock, REPO_ROOT)
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

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(serialize_manifest(manifest), encoding="utf-8")
    signal(
        "browser.manifest.written",
        path=_rel(output),
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
    lock = load_lock(Path(args.lock))
    expected = _load_browser_manifest(Path(args.manifest))
    actual, run = build_browser_manifest(lock, REPO_ROOT)
    if run.fatal:
        for entry in run.fatal:
            signal("run.fatal", path=entry.path, state=entry.state)
        raise BuildError(
            f"{len(run.fatal)} browser artifact(s) in a fatal state; verify aborted"
        )

    findings = compare_browser_manifests(expected, actual)
    findings.extend(compare_published_to_targets(lock, REPO_ROOT))

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
    base = root / lock.circuit_root
    if not base.is_dir():
        return []

    names: list[str] = []
    for path in sorted(base.iterdir()):
        package_toml = path / lock.package_file
        if not (path.is_dir() and package_toml.is_file()):
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
    root = _selected_root(args)
    lock = load_lock(Path(args.lock))
    findings = check_coverage(lock, root)
    if findings:
        for finding in findings:
            signal("drift.finding", detail=finding)
        signal("coverage.failed", findings=len(findings))
        return EXIT_DRIFT

    signal("coverage.ok", circuits=len(declared_circuit_names(lock)))
    return EXIT_OK


# ── Circuit build dependency graph ───────────────────────────────────────────


def transform_vk_for_soroban(vk: bytes) -> bytes | None:
    """Deterministic Soroban UltraHonk VK transformation (1764 -> 1760 bytes)."""
    if len(vk) == 1764:
        stripped = bytearray(vk[4:])
        for offset in range(0, 32, 8):
            first = stripped[offset : offset + 4]
            second = stripped[offset + 4 : offset + 8]
            stripped[offset : offset + 4] = second
            stripped[offset + 4 : offset + 8] = first
        return bytes(stripped)
    if len(vk) == 1760:
        return vk
    return None


def _parse_nargo_manifest(package_toml: Path, root: Path) -> dict[str, Any]:
    """Parse ``[package]`` and local ``[dependencies]`` from a ``Nargo.toml``."""
    try:
        raw_text = package_toml.read_text(encoding="utf-8")
    except OSError as exc:
        raise BuildError(
            f"unreadable Noir package manifest: {_rel(package_toml, root)}"
        ) from exc

    if tomllib is not None:
        try:
            parsed = tomllib.loads(raw_text)
        except ValueError as exc:
            raise BuildError(
                f"invalid Noir package manifest: {_rel(package_toml, root)}"
            ) from exc
        pkg_table = parsed.get("package") or {}
        deps_table = parsed.get("dependencies") or {}
        local_deps: dict[str, str] = {}
        if isinstance(deps_table, dict):
            for dep_name, dep_spec in sorted(deps_table.items()):
                if isinstance(dep_spec, dict) and isinstance(dep_spec.get("path"), str):
                    local_deps[str(dep_name)] = str(dep_spec["path"])
        return {
            "name": str(pkg_table.get("name") or package_toml.parent.name),
            "package_type": str(pkg_table.get("type") or "bin"),
            "compiler_version": (
                str(pkg_table["compiler_version"])
                if pkg_table.get("compiler_version") is not None
                else None
            ),
            "local_dep_paths": local_deps,
        }

    # Line-based fallback when tomllib is unavailable
    section = ""
    pkg_name = package_toml.parent.name
    pkg_type = "bin"
    compiler_ver: str | None = None
    fallback_deps: dict[str, str] = {}
    for raw_line in raw_text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if section == "package":
            m_str = re.fullmatch(r'([A-Za-z0-9_]+)\s*=\s*["\']([^"\']*)["\']', line)
            if m_str:
                k, v = m_str.group(1), m_str.group(2)
                if k == "name" and v:
                    pkg_name = v
                elif k == "type" and v:
                    pkg_type = v
                elif k == "compiler_version":
                    compiler_ver = v
        elif section == "dependencies":
            m_dep = re.search(
                r'^([A-Za-z0-9_-]+)\s*=\s*\{[^}]*path\s*=\s*["\']([^"\']+)["\']',
                line,
            )
            if m_dep:
                fallback_deps[m_dep.group(1)] = m_dep.group(2)

    return {
        "name": pkg_name,
        "package_type": pkg_type,
        "compiler_version": compiler_ver,
        "local_dep_paths": dict(sorted(fallback_deps.items())),
    }


def discover_noir_package_graph(
    lock: Lock,
    root: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
    """Discover Noir binary and library packages, their sources, and local DAG edges."""
    resolved_root = root.resolve()
    base = resolved_root / lock.circuit_root
    packages: dict[str, dict[str, Any]] = {}
    file_mtimes_ns: dict[str, int] = {}

    if not base.is_dir():
        return packages, file_mtimes_ns

    source_count = 0
    max_packages = max(lock.limits.max_circuits * 2, lock.limits.max_circuits)

    for pkg_dir in sorted(base.iterdir()):
        package_toml = pkg_dir / lock.package_file
        if not (pkg_dir.is_dir() and package_toml.is_file()):
            continue
        if len(packages) >= max_packages:
            raise BuildError(
                f"Noir package count exceeds {max_packages}; refusing to continue"
            )

        meta = _parse_nargo_manifest(package_toml, resolved_root)
        dir_name = pkg_dir.name
        src_files: list[Path] = [package_toml]
        src_dir = pkg_dir / "src"
        if src_dir.is_dir():
            src_files.extend(sorted(p for p in src_dir.rglob("*.nr") if p.is_file()))

        source_entries: list[dict[str, str]] = []
        for src_path in src_files:
            source_count += 1
            if source_count > lock.limits.max_provenance_files:
                raise BuildError(
                    f"dependency source set exceeds {lock.limits.max_provenance_files} files"
                )
            rel_src = _rel(src_path, resolved_root)
            stat = src_path.stat()
            file_mtimes_ns[rel_src] = stat.st_mtime_ns
            source_entries.append(
                {
                    "path": rel_src,
                    "sha256": sha256_hex(src_path.read_bytes()),
                }
            )

        local_dep_dirs: list[str] = []
        for dep_alias, dep_rel in sorted(meta["local_dep_paths"].items()):
            dep_dir = (pkg_dir / dep_rel).resolve()
            try:
                dep_dir.relative_to(resolved_root)
            except ValueError as exc:
                raise BuildError(
                    f"Noir dependency path for {dep_alias!r} in {dir_name} escapes workspace root"
                ) from exc
            if not (dep_dir / lock.package_file).is_file():
                raise BuildError(
                    f"Noir package {dir_name} declares missing local dependency {dep_alias!r}"
                )
            local_dep_dirs.append(dep_dir.name)

        packages[dir_name] = {
            "name": dir_name,
            "declared_name": meta["name"],
            "package_type": meta["package_type"],
            "compiler_version": meta["compiler_version"],
            "manifest_path": _rel(package_toml, resolved_root),
            "source_entries": source_entries,
            "local_dependencies": sorted(set(local_dep_dirs)),
        }

    # Resolve transitive local package dependencies and reject cycles.
    resolved_transitive: dict[str, list[str]] = {}
    visiting: list[str] = []

    def _dfs(pkg_key: str) -> list[str]:
        if pkg_key in resolved_transitive:
            return resolved_transitive[pkg_key]
        if pkg_key in visiting:
            cycle_start = visiting.index(pkg_key)
            chain = " -> ".join([*visiting[cycle_start:], pkg_key])
            raise BuildError(f"cyclic Noir package dependency detected: {chain}")
        visiting.append(pkg_key)
        ordered: list[str] = []
        for dep_key in packages[pkg_key]["local_dependencies"]:
            if dep_key not in packages:
                raise BuildError(
                    f"Noir package {pkg_key} references undiscovered local package {dep_key!r}"
                )
            for sub in _dfs(dep_key):
                if sub not in ordered:
                    ordered.append(sub)
            if dep_key not in ordered:
                ordered.append(dep_key)
        visiting.pop()
        resolved_transitive[pkg_key] = ordered
        return ordered

    for pkg_key in sorted(packages):
        packages[pkg_key]["transitive_dependencies"] = _dfs(pkg_key)
        companion: str | None = None
        if (
            packages[pkg_key]["package_type"] != "lib"
            and not pkg_key.endswith("_helper")
            and f"{pkg_key}_helper" in packages
        ):
            companion = f"{pkg_key}_helper"
        packages[pkg_key]["companion_helper"] = companion

    return packages, file_mtimes_ns


def _classify_artifact_dependencies(
    declaration: dict,
    lock: Lock,
) -> tuple[str | None, bool, list[str], list[dict[str, Any]], int]:
    """Return ``(circuit, is_derived, upstream_paths, tools, topo_tier)``."""
    rel_path = str(declaration["path"])
    role = str(declaration.get("role", "unknown"))
    kind = str(declaration.get("kind", "unknown"))

    nargo_tool = {
        "name": "nargo",
        "version": lock.toolchain["nargo"]["version"],
    }
    bb_tool = {
        "name": "barretenberg",
        "version": lock.toolchain["barretenberg"]["version"],
        "proving_scheme": lock.toolchain["proving_scheme"],
        "oracle_hash": lock.toolchain["oracle_hash"],
    }
    soroban_tool = {
        "name": "prepare-soroban",
        "driver": "zk/tools/build_circuits.py",
    }

    if role == PUBLISHED_ACIR_ROLE:
        target_acir = published_to_build_target(rel_path)
        circuit_name = target_acir[len(lock.circuit_root) + 1 :].split("/", 1)[0]
        return circuit_name, True, [target_acir], [nargo_tool], 1

    prefix = f"{lock.circuit_root}/"
    if rel_path.startswith(prefix):
        parts = rel_path[len(prefix) :].split("/")
        if len(parts) == 3 and parts[1] == "target":
            circuit_name = parts[0]
            filename = parts[2]
            primary_acir = f"{lock.circuit_root}/{circuit_name}/target/{circuit_name}.json"
            if role == ACIR_ROLE and filename == f"{circuit_name}.json":
                return circuit_name, False, [], [nargo_tool], 0
            if role == SOROBAN_VK_ROLE or filename == "vk_soroban":
                vk_path = f"{lock.circuit_root}/{circuit_name}/target/vk"
                return (
                    circuit_name,
                    True,
                    [vk_path, primary_acir],
                    [nargo_tool, bb_tool, soroban_tool],
                    2,
                )
            tools = [nargo_tool, bb_tool] if kind in ("binary", "json", "wasm") else [nargo_tool]
            return circuit_name, True, [primary_acir], tools, 1

    return None, False, [], [nargo_tool, bb_tool], 0


def build_dependency_graph(
    lock: Lock,
    root: Path,
    *,
    lock_path: Path | None = None,
    manifest: dict | None = None,
    browser_manifest: dict | None = None,
    packaging: bool = False,
) -> dict[str, Any]:
    """Build a deterministic release dependency graph and surface stale artifacts.

    Lists per-artifact source, helper (shared Noir libraries + companion
    ``*_helper`` circuits), upstream artifact, and pinned toolchain
    dependencies, and identifies stale derived artifacts before packaging.
    """
    resolved_root = root.resolve()
    effective_lock_path = (lock_path or (resolved_root / "zk" / "toolchain.lock.json")).resolve()
    lock_rel = _rel(effective_lock_path, resolved_root)
    lock_sha256 = (
        sha256_hex(effective_lock_path.read_bytes())
        if effective_lock_path.is_file()
        else sha256_hex(
            json.dumps(lock.raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
    )
    lock_mtime_ns = (
        effective_lock_path.stat().st_mtime_ns if effective_lock_path.is_file() else None
    )
    norm_policy_sha256 = sha256_hex(
        json.dumps(lock.raw["normalization"], sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    )

    packages, file_mtimes_ns = discover_noir_package_graph(lock, resolved_root)

    # Combine lock-declared artifacts with any on-disk derived Soroban VK files.
    declarations: list[dict[str, Any]] = [
        {**entry, "_declared_in_lock": True} for entry in lock.artifacts
    ]
    declared_paths = {str(entry["path"]) for entry in declarations}
    for circuit_name in sorted(declared_circuit_names(lock)):
        soroban_rel = f"{lock.circuit_root}/{circuit_name}/target/vk_soroban"
        if soroban_rel not in declared_paths and (resolved_root / soroban_rel).is_file():
            declarations.append(
                {
                    "path": soroban_rel,
                    "kind": "binary",
                    "role": SOROBAN_VK_ROLE,
                    "required": False,
                    "_declared_in_lock": False,
                }
            )

    manifest_prov = (manifest or {}).get("provenance") or {}
    manifest_arts = {
        entry["path"]: entry for entry in ((manifest or {}).get("artifacts") or [])
    }
    browser_arts = {
        entry["path"]: entry for entry in ((browser_manifest or {}).get("artifacts") or [])
    }

    raw_nodes: list[dict[str, Any]] = []
    artifact_mtimes_ns: dict[str, int] = {}

    for decl in declarations:
        rel_path = str(decl["path"])
        circuit_name, is_derived, upstream_paths, tools, topo_tier = (
            _classify_artifact_dependencies(decl, lock)
        )
        digest_res = digest_artifact(decl, lock, resolved_root)
        if digest_res.state in FATAL_STATES:
            signal("run.fatal", path=digest_res.path, state=digest_res.state)
            raise BuildError(
                f"artifact {digest_res.path} is in fatal state {digest_res.state}"
            )

        target_file = resolved_root / rel_path
        is_present = digest_res.state == ArtifactState.DIGESTED
        if is_present and target_file.is_file():
            artifact_mtimes_ns[rel_path] = target_file.stat().st_mtime_ns

        source_deps: list[dict[str, str]] = []
        helper_deps: list[dict[str, Any]] = []
        pkg = packages.get(circuit_name) if circuit_name else None
        if pkg is not None:
            source_deps = list(pkg["source_entries"])
            for dep_pkg_name in pkg["transitive_dependencies"]:
                dep_pkg = packages[dep_pkg_name]
                helper_deps.append(
                    {
                        "name": dep_pkg_name,
                        "relationship": (
                            "noir_library"
                            if dep_pkg["package_type"] == "lib"
                            else "noir_package"
                        ),
                        "manifest_path": dep_pkg["manifest_path"],
                        "sources": list(dep_pkg["source_entries"]),
                    }
                )
            companion_name = pkg.get("companion_helper")
            if companion_name and companion_name in packages:
                comp_pkg = packages[companion_name]
                helper_deps.append(
                    {
                        "name": companion_name,
                        "relationship": "companion_helper_circuit",
                        "manifest_path": comp_pkg["manifest_path"],
                        "target_acir": (
                            f"{lock.circuit_root}/{companion_name}/target/{companion_name}.json"
                        ),
                        "sources": list(comp_pkg["source_entries"]),
                    }
                )

        raw_nodes.append(
            {
                "_tier": topo_tier,
                "path": rel_path,
                "circuit": circuit_name,
                "kind": str(decl["kind"]),
                "role": str(decl.get("role", "unknown")),
                "required": bool(decl.get("required", False)),
                "declared_in_lock": bool(decl.get("_declared_in_lock", True)),
                "is_derived": is_derived,
                "present": is_present,
                "state": "present" if is_present else "missing",
                "stale": False,
                "stale_reasons": [],
                "raw_bytes": digest_res.raw_bytes,
                "normalized_bytes": digest_res.normalized_bytes,
                "normalized_sha256": digest_res.normalized_sha256,
                "upstream_artifacts": upstream_paths,
                "source_dependencies": source_deps,
                "helper_dependencies": helper_deps,
                "toolchain_dependencies": {
                    "lock_path": lock_rel,
                    "lock_sha256": lock_sha256,
                    "tools": tools,
                    "normalization_policy_sha256": norm_policy_sha256,
                },
            }
        )

    nodes_by_path = {node["path"]: node for node in raw_nodes}

    # Evaluate staleness in topological tier order so upstream staleness propagates.
    for node in sorted(raw_nodes, key=lambda item: (item["_tier"], item["path"])):
        if not node["present"]:
            continue

        path = node["path"]
        role = node["role"]
        art_mtime = artifact_mtimes_ns.get(path)
        reasons: list[str] = []

        def _add_reason(code: str, target: list[str] = reasons) -> None:
            if code not in target:
                target.append(code)

        # Published browser ACIR may come from git checkout when browser_manifest
        # is committed and build targets are absent; apply direct mtime checks to
        # build targets unconditionally and to published_acir when unpinned by
        # browser_manifest and without an on-disk upstream build target.
        upstream_present_any = any(
            nodes_by_path.get(up, {}).get("present", False)
            for up in node["upstream_artifacts"]
        )
        check_direct_mtime = role != PUBLISHED_ACIR_ROLE or (
            browser_manifest is None and not upstream_present_any
        )

        if check_direct_mtime and art_mtime is not None:
            if any(
                file_mtimes_ns.get(src["path"], 0) > art_mtime
                for src in node["source_dependencies"]
            ):
                _add_reason("older_than_source_dependency")

            if any(
                file_mtimes_ns.get(hsrc["path"], 0) > art_mtime
                for hdep in node["helper_dependencies"]
                for hsrc in hdep.get("sources", [])
            ):
                _add_reason("older_than_helper_dependency")

            if lock_mtime_ns is not None and lock_mtime_ns > art_mtime:
                _add_reason("older_than_toolchain_lock")

        if manifest is not None:
            dep_digests = {
                src["path"]: src["sha256"] for src in node["source_dependencies"]
            }
            for hdep in node["helper_dependencies"]:
                for hsrc in hdep.get("sources", []):
                    dep_digests[hsrc["path"]] = hsrc["sha256"]
            dep_digests[lock_rel] = lock_sha256
            for dep_path, current_sha in sorted(dep_digests.items()):
                recorded_sha = manifest_prov.get(dep_path)
                if recorded_sha is not None and recorded_sha != current_sha:
                    _add_reason("source_drifted_from_manifest")
                    break

            recorded_art = manifest_arts.get(path)
            if (
                recorded_art is not None
                and recorded_art.get("normalized_sha256") != node["normalized_sha256"]
            ):
                _add_reason("artifact_drifted_from_manifest")

        if role == PUBLISHED_ACIR_ROLE and browser_manifest is not None:
            recorded_browser = browser_arts.get(path)
            if (
                recorded_browser is None
                or recorded_browser.get("normalized_sha256") != node["normalized_sha256"]
            ):
                _add_reason("browser_manifest_digest_mismatch")

        if node["is_derived"]:
            for up_path in node["upstream_artifacts"]:
                up_node = nodes_by_path.get(up_path)
                up_present = bool(up_node and up_node["present"])
                if not up_present:
                    up_file = resolved_root / up_path
                    if up_file.is_file():
                        up_present = True
                if not up_present:
                    if role != PUBLISHED_ACIR_ROLE or packaging:
                        _add_reason("missing_upstream_artifact")
                    continue

                if up_node is not None and up_node["stale"]:
                    _add_reason("upstream_artifact_stale")

                if role == PUBLISHED_ACIR_ROLE:
                    if (
                        up_node is not None
                        and up_node["normalized_sha256"] != node["normalized_sha256"]
                    ):
                        _add_reason("upstream_digest_mismatch")
                else:
                    up_mtime = artifact_mtimes_ns.get(up_path)
                    if up_mtime is None and (resolved_root / up_path).is_file():
                        up_mtime = (resolved_root / up_path).stat().st_mtime_ns
                    if art_mtime is not None and up_mtime is not None and art_mtime < up_mtime:
                        _add_reason("older_than_upstream_artifact")

                    if role == SOROBAN_VK_ROLE and up_path.endswith("/target/vk"):
                        vk_file = resolved_root / up_path
                        soroban_file = resolved_root / path
                        if vk_file.is_file() and soroban_file.is_file():
                            expected_soroban = transform_vk_for_soroban(vk_file.read_bytes())
                            if (
                                expected_soroban is None
                                or soroban_file.read_bytes() != expected_soroban
                            ):
                                _add_reason("soroban_vk_mismatch")

        if reasons:
            node["stale"] = True
            node["state"] = "stale"
            node["stale_reasons"] = reasons

    serialized_artifacts: list[dict[str, Any]] = []
    stale_summary: list[dict[str, Any]] = []
    missing_required: list[str] = []

    for node in raw_nodes:
        clean_node = {k: v for k, v in node.items() if not k.startswith("_")}
        serialized_artifacts.append(clean_node)
        if clean_node["stale"]:
            stale_summary.append(
                {
                    "path": clean_node["path"],
                    "circuit": clean_node["circuit"],
                    "role": clean_node["role"],
                    "is_derived": clean_node["is_derived"],
                    "reasons": clean_node["stale_reasons"],
                }
            )
        if clean_node["required"] and not clean_node["present"]:
            missing_required.append(clean_node["path"])

    serialized_packages = [
        {
            "name": pkg["name"],
            "package_type": pkg["package_type"],
            "compiler_version": pkg["compiler_version"],
            "manifest_path": pkg["manifest_path"],
            "sources": [entry["path"] for entry in pkg["source_entries"]],
            "local_dependencies": pkg["local_dependencies"],
            "transitive_dependencies": pkg["transitive_dependencies"],
            "companion_helper": pkg["companion_helper"],
        }
        for _, pkg in sorted(packages.items())
    ]

    env_clean = {
        k: v for k, v in sorted(lock.environment.items()) if k != "description"
    }
    ready_for_packaging = len(stale_summary) == 0 and len(missing_required) == 0

    return {
        "format": DEPENDENCY_GRAPH_FORMAT,
        "version": DEPENDENCY_GRAPH_VERSION,
        "packaging_mode": bool(packaging),
        "ready_for_packaging": ready_for_packaging,
        "toolchain": {
            "lock_path": lock_rel,
            "lock_sha256": lock_sha256,
            "nargo": lock.toolchain["nargo"]["version"],
            "barretenberg": lock.toolchain["barretenberg"]["version"],
            "proving_scheme": lock.toolchain["proving_scheme"],
            "oracle_hash": lock.toolchain["oracle_hash"],
            "normalization_policy_sha256": norm_policy_sha256,
            "environment": env_clean,
        },
        "packages": serialized_packages,
        "artifacts": serialized_artifacts,
        "stale_artifacts": stale_summary,
        "missing_required_artifacts": missing_required,
        "summary": {
            "total_packages": len(serialized_packages),
            "total_artifacts": len(serialized_artifacts),
            "derived_artifacts": sum(
                1 for item in serialized_artifacts if item["is_derived"]
            ),
            "present_artifacts": sum(
                1 for item in serialized_artifacts if item["present"]
            ),
            "stale_artifacts": len(stale_summary),
            "stale_derived_artifacts": sum(
                1 for item in stale_summary if item["is_derived"]
            ),
            "missing_required_artifacts": len(missing_required),
        },
    }


def evaluate_dependency_graph(
    graph: dict[str, Any],
    *,
    check_stale: bool = False,
    packaging: bool = False,
) -> tuple[bool, list[str]]:
    """Return ``(passed, findings)`` for stale or missing-before-packaging checks."""
    findings: list[str] = []
    if check_stale or packaging:
        for item in graph.get("stale_artifacts", []):
            reasons_str = ", ".join(item.get("reasons", []))
            kind_label = "derived artifact" if item.get("is_derived") else "artifact"
            findings.append(
                f"stale {kind_label} {item['path']} ({item['role']}): {reasons_str}"
            )
    if packaging:
        for missing_path in graph.get("missing_required_artifacts", []):
            findings.append(
                f"missing required artifact before packaging: {missing_path}"
            )
    return (len(findings) == 0), findings


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


def _selected_root(args: argparse.Namespace) -> Path:
    raw = getattr(args, "root", None)
    return Path(raw).resolve() if raw is not None else REPO_ROOT


def command_write(args: argparse.Namespace) -> int:
    root = _selected_root(args)
    lock = load_lock(Path(args.lock))
    manifest, run = build_manifest(lock, root)
    _fail_on_fatal(run)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(serialize_manifest(manifest), encoding="utf-8")

    signal(
        "manifest.written",
        path=_rel(output, root),
        artifacts=len(manifest["artifacts"]),
        skipped=len(manifest["skipped"]),
        sources=len(manifest["provenance"]),
    )
    return EXIT_OK


def command_verify(args: argparse.Namespace) -> int:
    root = _selected_root(args)
    lock = load_lock(Path(args.lock))
    expected = _load_manifest(Path(args.manifest))
    actual, run = build_manifest(lock, root)
    _fail_on_fatal(run)

    findings = compare_manifests(expected, actual)
    if findings:
        for finding in findings:
            signal("drift.finding", detail=finding)
        signal("verify.failed", findings=len(findings))
        return EXIT_DRIFT

    signal("verify.ok", artifacts=len(actual["artifacts"]))
    return EXIT_OK


def _load_manifest(path: Path) -> dict:
    if not path.is_file():
        raise BuildError(f"manifest not found: {_rel(path)}")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BuildError(f"manifest is not valid JSON: {_rel(path)}") from exc
    if manifest.get("format") != MANIFEST_FORMAT:
        raise BuildError(f"not an artifact manifest: {_rel(path)}")
    return manifest


def command_compare(args: argparse.Namespace) -> int:
    first = _load_manifest(Path(args.first))
    second = _load_manifest(Path(args.second))

    findings = compare_manifests(first, second)
    if findings:
        for finding in findings:
            signal("drift.finding", detail=finding)
        signal("compare.failed", findings=len(findings))
        return EXIT_DRIFT

    signal("compare.ok", artifacts=len(first.get("artifacts", [])))
    return EXIT_OK


def command_dependency_graph(args: argparse.Namespace) -> int:
    root = _selected_root(args)
    lock_path = Path(args.lock)
    lock = load_lock(lock_path)

    manifest_doc: dict | None = None
    if args.manifest is not None:
        manifest_doc = _load_manifest(Path(args.manifest))
    else:
        default_manifest = root / "zk" / "artifacts.manifest.json"
        if default_manifest.is_file():
            manifest_doc = _load_manifest(default_manifest)

    browser_doc: dict | None = None
    if args.browser_manifest is not None:
        browser_doc = _load_browser_manifest(Path(args.browser_manifest))
    else:
        default_browser = root / "zk" / "browser.artifacts.manifest.json"
        if default_browser.is_file():
            browser_doc = _load_browser_manifest(default_browser)

    graph = build_dependency_graph(
        lock,
        root,
        lock_path=lock_path,
        manifest=manifest_doc,
        browser_manifest=browser_doc,
        packaging=bool(args.packaging),
    )
    serialized = serialize_manifest(graph)
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(serialized, encoding="utf-8")
        signal(
            "dependency_graph.written",
            path=_rel(out_path, root),
            artifacts=graph["summary"]["total_artifacts"],
            stale_artifacts=graph["summary"]["stale_artifacts"],
            ready_for_packaging=graph["ready_for_packaging"],
        )
    else:
        sys.stdout.write(serialized)

    passed, findings = evaluate_dependency_graph(
        graph,
        check_stale=bool(args.check_stale),
        packaging=bool(args.packaging),
    )
    if not passed:
        for finding in findings:
            signal("drift.finding", detail=finding)
        signal(
            "dependency_graph.failed",
            findings=len(findings),
            stale_artifacts=graph["summary"]["stale_artifacts"],
        )
        return EXIT_DRIFT

    signal(
        "dependency_graph.ok",
        artifacts=graph["summary"]["total_artifacts"],
        stale_artifacts=graph["summary"]["stale_artifacts"],
        ready_for_packaging=graph["ready_for_packaging"],
    )
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--lock", default=str(DEFAULT_LOCK), help="path to zk/toolchain.lock.json"
    )
    parser.add_argument(
        "--root",
        default=None,
        help="working tree root (defaults to repository root)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    write = subparsers.add_parser("write", help="write a manifest from the working tree")
    write.add_argument("--output", default=str(DEFAULT_MANIFEST))
    write.add_argument("--root", default=argparse.SUPPRESS)
    write.set_defaults(handler=command_write)

    verify = subparsers.add_parser("verify", help="fail on drift from a manifest")
    verify.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    verify.add_argument("--root", default=argparse.SUPPRESS)
    verify.set_defaults(handler=command_verify)

    compare = subparsers.add_parser("compare", help="diff two manifests (double build)")
    compare.add_argument("first")
    compare.add_argument("second")
    compare.set_defaults(handler=command_compare)

    coverage = subparsers.add_parser(
        "check-coverage",
        help="fail when the lock and the source tree disagree about which circuits exist",
    )
    coverage.add_argument("--root", default=argparse.SUPPRESS)
    coverage.set_defaults(handler=command_check_coverage)

    dep_graph = subparsers.add_parser(
        "dependency-graph",
        help="emit source, helper, and toolchain dependency graph and flag stale artifacts",
    )
    dep_graph.add_argument(
        "--output",
        default=None,
        help="write dependency graph JSON to path (prints to stdout when omitted)",
    )
    dep_graph.add_argument(
        "--manifest",
        default=None,
        help="optional artifact manifest baseline path",
    )
    dep_graph.add_argument(
        "--browser-manifest",
        default=None,
        help="optional browser artifact manifest baseline path",
    )
    dep_graph.add_argument(
        "--check-stale",
        action="store_true",
        help="exit non-zero if any on-disk artifact is stale relative to its dependencies",
    )
    dep_graph.add_argument(
        "--packaging",
        action="store_true",
        help="pre-packaging gate: fail on any stale artifact or missing required/upstream target",
    )
    dep_graph.add_argument("--root", default=argparse.SUPPRESS)
    dep_graph.set_defaults(handler=command_dependency_graph)

    write_browser = subparsers.add_parser(
        "write-browser",
        help="write a manifest for published browser ACIR under frontend/public/noir",
    )
    write_browser.add_argument("--output", default=str(DEFAULT_BROWSER_MANIFEST))
    write_browser.set_defaults(handler=command_write_browser)

    verify_browser = subparsers.add_parser(
        "verify-browser",
        help="fail if published browser ACIR drifts from the browser manifest "
        "or from matching build-target ACIR",
    )
    verify_browser.add_argument("--manifest", default=str(DEFAULT_BROWSER_MANIFEST))
    verify_browser.set_defaults(handler=command_verify_browser)

    write_provenance = subparsers.add_parser(
        "write-provenance",
        help="write published circuit source provenance from the toolchain lock",
    )
    write_provenance.add_argument("--output", default=str(DEFAULT_PROVENANCE))
    write_provenance.set_defaults(handler=command_write_provenance)

    verify_provenance = subparsers.add_parser(
        "verify-provenance",
        help="fail if circuit sources drift from the committed provenance document",
    )
    verify_provenance.add_argument("--manifest", default=str(DEFAULT_PROVENANCE))
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
