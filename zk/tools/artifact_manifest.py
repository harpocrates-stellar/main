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
RELEASE_MANIFEST_FORMAT = "harpocrates.zk-signed-release-manifest"
DEFAULT_RELEASE_MANIFEST = REPO_ROOT / "zk" / "release.manifest.signed.json"
RELEASE_SIGNATURE_ALGORITHM = "ed25519"
RELEASE_SIGNATURE_DOMAIN = "harpocrates.zk-release-manifest.v1"
SIGNING_KEY_ENV = "HARPOCRATES_RELEASE_SIGNING_KEY"
PUBLISHED_ACIR_ROLE = "published_acir"
EXPORTED_BUNDLE_ROLE = "exported_bundle"
ACIR_ROLE = "acir"

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


def _rel(path: Path) -> str:
    """Repo-relative, forward-slashed path — the only path form ever logged."""
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
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
    found: dict[str, str] = {}
    for pattern in lock.provenance_globs:
        for path in sorted(root.glob(pattern)):
            if not path.is_file():
                continue
            if len(found) >= lock.limits.max_provenance_files:
                raise BuildError(
                    f"provenance set exceeds {lock.limits.max_provenance_files} files"
                )
            found[_rel(path)] = sha256_hex(path.read_bytes())
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
    lock = load_lock(Path(args.lock))
    findings = check_coverage(lock, REPO_ROOT)
    if findings:
        for finding in findings:
            signal("drift.finding", detail=finding)
        signal("coverage.failed", findings=len(findings))
        return EXIT_DRIFT

    signal("coverage.ok", circuits=len(declared_circuit_names(lock)))
    return EXIT_OK


# ── Signed release manifest & offline client verification ────────────────────
#
# Binds the compiler lock, circuit source revision / provenance digests, and
# exported artifact digests into a single canonical Ed25519-signed release
# manifest. Clients verify the signature, pinned trust anchor, lock binding,
# source revision, and artifact digests strictly offline *before* loading any
# circuit artifact bytes into proving or verification code.

_ED25519_P = (1 << 255) - 19
_ED25519_L = (1 << 252) + 27742317777372353535851937790883648493
_ED25519_D = (-121665 * pow(121666, -1, _ED25519_P)) % _ED25519_P
_ED25519_I = pow(2, (_ED25519_P - 1) // 4, _ED25519_P)
_ED25519_BY = (4 * pow(5, -1, _ED25519_P)) % _ED25519_P
_ED25519_UV = (
    ((_ED25519_BY * _ED25519_BY - 1) % _ED25519_P)
    * pow((_ED25519_D * _ED25519_BY * _ED25519_BY + 1) % _ED25519_P, 3, _ED25519_P)
    * pow(
        ((_ED25519_BY * _ED25519_BY - 1) % _ED25519_P)
        * pow((_ED25519_D * _ED25519_BY * _ED25519_BY + 1) % _ED25519_P, 7, _ED25519_P),
        (_ED25519_P - 5) // 8,
        _ED25519_P,
    )
) % _ED25519_P
if ((_ED25519_D * _ED25519_BY * _ED25519_BY + 1) * _ED25519_UV * _ED25519_UV) % _ED25519_P != (
    _ED25519_BY * _ED25519_BY - 1
) % _ED25519_P:
    _ED25519_UV = (_ED25519_UV * _ED25519_I) % _ED25519_P
_ED25519_BX = _ED25519_P - _ED25519_UV if (_ED25519_UV & 1) else _ED25519_UV
_ED25519_BASE = (_ED25519_BX, _ED25519_BY, 1, (_ED25519_BX * _ED25519_BY) % _ED25519_P)
_ED25519_ZERO = (0, 1, 1, 0)

try:
    from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as _CryptoEd25519PrivateKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey as _CryptoEd25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding as _CryptoEncoding,
    )
    from cryptography.hazmat.primitives.serialization import (
        PublicFormat as _CryptoPublicFormat,
    )

    _HAS_CRYPTOGRAPHY_ED25519 = True
except ImportError:  # pragma: no cover - exercised when cryptography is absent
    _HAS_CRYPTOGRAPHY_ED25519 = False


def _ed_point_add(
    first: tuple[int, int, int, int], second: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = first
    x2, y2, z2, t2 = second
    p = _ED25519_P
    a = ((y1 - x1) * (y2 - x2)) % p
    b = ((y1 + x1) * (y2 + x2)) % p
    c = (t1 * 2 * _ED25519_D * t2) % p
    d = (z1 * 2 * z2) % p
    e = (b - a) % p
    f = (d - c) % p
    g = (d + c) % p
    h = (b + a) % p
    return ((e * f) % p, (g * h) % p, (f * g) % p, (e * h) % p)


def _ed_scalar_mul(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    acc = _ED25519_ZERO
    addend = point
    k = scalar
    while k > 0:
        if k & 1:
            acc = _ed_point_add(acc, addend)
        addend = _ed_point_add(addend, addend)
        k >>= 1
    return acc


def _ed_point_encode(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    z_inv = pow(z, -1, _ED25519_P)
    x_aff = (x * z_inv) % _ED25519_P
    y_aff = (y * z_inv) % _ED25519_P
    encoded = y_aff | ((x_aff & 1) << 255)
    return encoded.to_bytes(32, "little")


def _ed_point_decode(encoded: bytes) -> tuple[int, int, int, int] | None:
    if len(encoded) != 32:
        return None
    raw = int.from_bytes(encoded, "little")
    y = raw & ((1 << 255) - 1)
    x_sign = (raw >> 255) & 1
    if y >= _ED25519_P:
        return None
    p = _ED25519_P
    u = (y * y - 1) % p
    v = (_ED25519_D * y * y + 1) % p
    x = (u * pow(v, 3, p) * pow((u * pow(v, 7, p)) % p, (p - 5) // 8, p)) % p
    vx2 = (v * x * x) % p
    if vx2 == u:
        pass
    elif vx2 == (-u) % p:
        x = (x * _ED25519_I) % p
    else:
        return None
    if x == 0 and x_sign == 1:
        return None
    if (x & 1) != x_sign:
        x = p - x
    return (x, y, 1, (x * y) % p)


def _ed_point_equal(
    first: tuple[int, int, int, int], second: tuple[int, int, int, int]
) -> bool:
    x1, y1, z1, _ = first
    x2, y2, z2, _ = second
    p = _ED25519_P
    return ((x1 * z2 - x2 * z1) % p == 0) and ((y1 * z2 - y2 * z1) % p == 0)


def _pure_ed25519_public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise BuildError("Ed25519 signing seed must be 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return _ed_point_encode(_ed_scalar_mul(scalar, _ED25519_BASE))


def _pure_ed25519_sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != 32:
        raise BuildError("Ed25519 signing seed must be 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    prefix = digest[32:]
    pub = _ed_point_encode(_ed_scalar_mul(scalar, _ED25519_BASE))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _ED25519_L
    r_encoded = _ed_point_encode(_ed_scalar_mul(r, _ED25519_BASE))
    k = int.from_bytes(hashlib.sha512(r_encoded + pub + message).digest(), "little") % _ED25519_L
    s = (r + k * scalar) % _ED25519_L
    return r_encoded + s.to_bytes(32, "little")


def _pure_ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _ED25519_L:
        return False
    r_point = _ed_point_decode(signature[:32])
    a_point = _ed_point_decode(public_key)
    if r_point is None or a_point is None:
        return False
    k = (
        int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little")
        % _ED25519_L
    )
    lhs = _ed_scalar_mul(8 * s, _ED25519_BASE)
    rhs = _ed_point_add(_ed_scalar_mul(8, r_point), _ed_scalar_mul(8 * k, a_point))
    return _ed_point_equal(lhs, rhs)


def _decode_fixed_hex(value: Any, byte_length: int, label: str) -> bytes:
    """Parse a fixed-length hex string without echoing secret values on error."""
    if not isinstance(value, str):
        raise BuildError(f"{label} must be a {byte_length * 2}-character hex string")
    cleaned = value.strip()
    if cleaned.startswith(("0x", "0X")):
        cleaned = cleaned[2:]
    if len(cleaned) != byte_length * 2 or not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        raise BuildError(f"{label} must be a {byte_length * 2}-character hex string")
    return bytes.fromhex(cleaned)


def ed25519_public_key_from_seed(seed_hex: str) -> str:
    seed = _decode_fixed_hex(seed_hex, 32, "Ed25519 signing seed")
    if _HAS_CRYPTOGRAPHY_ED25519:
        priv = _CryptoEd25519PrivateKey.from_private_bytes(seed)
        pub = priv.public_key().public_bytes(_CryptoEncoding.Raw, _CryptoPublicFormat.Raw)
        return pub.hex()
    return _pure_ed25519_public_key(seed).hex()


def ed25519_sign_message(seed_hex: str, message: bytes) -> str:
    seed = _decode_fixed_hex(seed_hex, 32, "Ed25519 signing seed")
    if _HAS_CRYPTOGRAPHY_ED25519:
        priv = _CryptoEd25519PrivateKey.from_private_bytes(seed)
        return priv.sign(message).hex()
    return _pure_ed25519_sign(seed, message).hex()


def ed25519_verify_message(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        pub = _decode_fixed_hex(public_key_hex, 32, "Ed25519 public key")
        sig = _decode_fixed_hex(signature_hex, 64, "Ed25519 signature")
    except BuildError:
        return False
    # Enforce canonical point & non-malleable scalar bounds before backend call.
    if int.from_bytes(sig[32:], "little") >= _ED25519_L:
        return False
    if _ed_point_decode(pub) is None or _ed_point_decode(sig[:32]) is None:
        return False
    if _HAS_CRYPTOGRAPHY_ED25519:
        try:
            _CryptoEd25519PublicKey.from_public_bytes(pub).verify(sig, message)
            return True
        except (_CryptoInvalidSignature, ValueError):
            return False
    return _pure_ed25519_verify(pub, message, sig)


def derive_release_key_id(public_key_hex: str) -> str:
    pub = _decode_fixed_hex(public_key_hex, 32, "Ed25519 public key")
    return f"ed25519:{sha256_hex(pub)[:16]}"


def generate_release_signing_keypair(seed: bytes | None = None) -> tuple[str, str, str]:
    """Return ``(seed_hex, public_key_hex, key_id)`` for Ed25519 release signing."""
    raw_seed = os.urandom(32) if seed is None else bytes(seed)
    if len(raw_seed) != 32:
        raise BuildError("Ed25519 signing seed must be 32 bytes")
    seed_hex = raw_seed.hex()
    public_key_hex = ed25519_public_key_from_seed(seed_hex)
    return seed_hex, public_key_hex, derive_release_key_id(public_key_hex)


def canonical_json_bytes(document: Any) -> bytes:
    """Canonical UTF-8 JSON bytes used for deterministic hashing and signing."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _validate_source_revision_label(revision: str) -> str:
    trimmed = revision.strip()
    if not trimmed or len(trimmed) > 128 or not re.fullmatch(r"[A-Za-z0-9._:/+-]+", trimmed):
        raise BuildError("source revision must be 1..128 ASCII identifier characters")
    return trimmed


def _resolve_contained_release_path(root: Path, relative: str) -> tuple[str, Path]:
    """Validate and resolve a repo/release-relative path strictly inside ``root``."""
    if not isinstance(relative, str) or not relative.strip():
        raise BuildError("artifact path in release manifest must be a non-empty string")
    normalized = relative.replace("\\", "/").strip().removeprefix("./")
    if (
        not normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized) is not None
        or ".." in normalized.split("/")
    ):
        raise BuildError(f"artifact path escapes release directory: {relative!r}")

    resolved_root = root.resolve()
    candidate = root / normalized
    try:
        resolved_candidate = candidate.resolve()
    except OSError as exc:
        raise BuildError(f"artifact path cannot be resolved: {normalized}") from exc

    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise BuildError(f"artifact path escapes release directory: {normalized}") from exc

    return normalized, resolved_candidate


def _collect_provenance_for_root(lock: Lock, root: Path) -> dict[str, str]:
    """Digest lock-declared circuit sources keyed by ``root``-relative POSIX paths."""
    resolved_root = root.resolve()
    found: dict[str, str] = {}
    for pattern in lock.provenance_globs:
        for path in sorted(root.glob(pattern)):
            if not path.is_file():
                continue
            if len(found) >= lock.limits.max_provenance_files:
                raise BuildError(
                    f"provenance set exceeds {lock.limits.max_provenance_files} files"
                )
            try:
                rel_key = path.resolve().relative_to(resolved_root).as_posix()
            except ValueError:
                rel_key = _rel(path)
            found[rel_key] = sha256_hex(path.read_bytes())
    return dict(sorted(found.items()))


def build_release_manifest_payload(
    lock: Lock,
    root: Path,
    *,
    scope: str = "browser",
    source_revision: str | None = None,
    extra_artifacts: Iterable[str] = (),
    lock_path: Path | None = None,
) -> dict[str, Any]:
    """Build the unsigned canonical payload for a circuit artifact release manifest.

    Binds:
      1. Compiler lock (canonical digest, pinned versions, environment, normalization policy).
      2. Circuit source revision and per-file source provenance digests.
      3. Exported / published artifact digests and byte sizes.
    """
    if scope not in ("browser", "all"):
        raise BuildError(f"unsupported release manifest scope: {scope!r} (expected 'browser' or 'all')")

    provenance = _collect_provenance_for_root(lock, root)
    if not provenance:
        raise BuildError("provenance globs matched no circuit sources; release manifest not built")
    provenance_sha256 = sha256_hex(canonical_json_bytes(provenance))
    resolved_revision = (
        _validate_source_revision_label(source_revision)
        if source_revision is not None
        else f"provenance-sha256:{provenance_sha256}"
    )

    if scope == "browser":
        base_manifest, run = build_browser_manifest(lock, root)
        if run.fatal:
            for entry in run.fatal:
                signal("run.fatal", path=entry.path, state=entry.state)
            raise BuildError(
                f"{len(run.fatal)} browser artifact(s) in a fatal state; release manifest not built"
            )
        target_drift = compare_published_to_targets(lock, root)
        if target_drift:
            for finding in target_drift:
                signal("drift.finding", detail=finding)
            raise BuildError(
                "published browser ACIR disagrees with on-disk build targets; release manifest not built"
            )
    else:
        base_manifest, run = build_manifest(lock, root)
        _fail_on_fatal(run)

    artifacts_by_path: dict[str, dict[str, Any]] = {
        entry["path"]: dict(entry) for entry in base_manifest["artifacts"]
    }

    for extra_rel in extra_artifacts:
        norm_rel, resolved_extra = _resolve_contained_release_path(root, extra_rel)
        if not resolved_extra.is_file():
            raise BuildError(f"exported release artifact not found: {norm_rel}")
        inferred_kind = (
            "json"
            if norm_rel.endswith(".json")
            else ("wasm" if norm_rel.endswith(".wasm") else "binary")
        )
        extra_result = digest_artifact(
            {
                "path": norm_rel,
                "kind": inferred_kind,
                "role": EXPORTED_BUNDLE_ROLE,
                "required": True,
            },
            lock,
            root,
        )
        if extra_result.state != ArtifactState.DIGESTED:
            raise BuildError(
                f"exported release artifact {norm_rel} is unusable ({extra_result.state})"
            )
        artifacts_by_path[norm_rel] = extra_result.to_entry()

    if not artifacts_by_path:
        raise BuildError("no release artifacts found to sign; release manifest not built")
    if len(artifacts_by_path) > lock.limits.max_artifacts:
        raise BuildError(
            f"release artifact count {len(artifacts_by_path)} exceeds cap {lock.limits.max_artifacts}"
        )

    normalization_sha256 = sha256_hex(canonical_json_bytes(lock.raw["normalization"]))
    lock_rel = "zk/toolchain.lock.json"
    if lock_path is not None:
        try:
            lock_rel = lock_path.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, ValueError):
            lock_rel = lock_path.name

    return {
        "scope": scope,
        "compiler_lock": {
            "lock_path": lock_rel,
            "canonical_sha256": sha256_hex(canonical_json_bytes(lock.raw)),
            "toolchain": {
                "nargo": lock.toolchain["nargo"]["version"],
                "barretenberg": lock.toolchain["barretenberg"]["version"],
                "proving_scheme": lock.toolchain["proving_scheme"],
                "oracle_hash": lock.toolchain["oracle_hash"],
            },
            "environment": dict(sorted(lock.environment.items())),
            "normalization": {
                "volatile_json_keys": sorted(lock.volatile_json_keys),
                "strip_custom_sections": sorted(lock.strip_custom_sections),
            },
            "normalization_policy_sha256": normalization_sha256,
        },
        "source_revision": {
            "revision": resolved_revision,
            "provenance_sha256": provenance_sha256,
            "provenance": provenance,
        },
        "artifacts": [artifacts_by_path[p] for p in sorted(artifacts_by_path)],
        "skipped": sorted(base_manifest.get("skipped", [])),
    }


def _release_signing_message(payload_bytes: bytes) -> bytes:
    return f"{RELEASE_SIGNATURE_DOMAIN}:".encode() + payload_bytes


def sign_release_manifest(
    payload: dict[str, Any],
    *,
    seed_hex: str,
    key_id: str | None = None,
) -> dict[str, Any]:
    """Attach a domain-separated Ed25519 signature to a release manifest payload."""
    if not isinstance(payload, dict):
        raise BuildError("release manifest payload must be a JSON object")
    public_key_hex = ed25519_public_key_from_seed(seed_hex)
    resolved_key_id = (
        _validate_source_revision_label(key_id)
        if key_id is not None
        else derive_release_key_id(public_key_hex)
    )
    payload_bytes = canonical_json_bytes(payload)
    payload_sha256 = sha256_hex(payload_bytes)
    signature_hex = ed25519_sign_message(seed_hex, _release_signing_message(payload_bytes))

    return {
        "format": RELEASE_MANIFEST_FORMAT,
        "version": MANIFEST_VERSION,
        "payload": payload,
        "signature": {
            "algorithm": RELEASE_SIGNATURE_ALGORITHM,
            "domain": RELEASE_SIGNATURE_DOMAIN,
            "key_id": resolved_key_id,
            "public_key": public_key_hex,
            "payload_sha256": payload_sha256,
            "value": signature_hex,
        },
    }


def load_signing_seed_hex(
    *,
    key_file: Path | None = None,
    env_var: str = SIGNING_KEY_ENV,
) -> tuple[str, str | None]:
    """Load an Ed25519 signing seed from ``key_file`` or ``env_var`` without logging it."""
    raw_text: str | None = None
    if key_file is not None:
        if not key_file.is_file():
            raise BuildError(f"signing key file not found: {_rel(key_file)}")
        try:
            raw_text = key_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise BuildError(f"signing key file unreadable: {_rel(key_file)}") from exc
    else:
        env_val = os.environ.get(env_var, "").strip()
        if env_val:
            raw_text = env_val

    if not raw_text:
        raise BuildError(
            f"missing release signing key: pass --signing-key-file or set {env_var}"
        )

    if raw_text.startswith("{"):
        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise BuildError("signing key JSON is malformed") from exc
        if not isinstance(parsed, dict) or "seed" not in parsed:
            raise BuildError("signing key JSON must contain a 'seed' field")
        seed = _decode_fixed_hex(parsed["seed"], 32, "Ed25519 signing seed").hex()
        explicit_id = str(parsed["key_id"]) if parsed.get("key_id") else None
        return seed, explicit_id

    seed = _decode_fixed_hex(raw_text, 32, "Ed25519 signing seed").hex()
    return seed, None


def normalize_trusted_public_keys(
    trusted_public_keys: dict[str, str] | Iterable[str] | str,
) -> dict[str, str]:
    """Normalize pinned Ed25519 public keys into ``{key_id: public_key_hex}``."""
    normalized: dict[str, str] = {}
    if isinstance(trusted_public_keys, str):
        pub_hex = _decode_fixed_hex(trusted_public_keys, 32, "trusted Ed25519 public key").hex()
        normalized[derive_release_key_id(pub_hex)] = pub_hex
    elif isinstance(trusted_public_keys, dict):
        for raw_key_id, raw_pub in trusted_public_keys.items():
            key_id = _validate_source_revision_label(str(raw_key_id))
            pub_hex = _decode_fixed_hex(raw_pub, 32, f"trusted public key for {key_id}").hex()
            normalized[key_id] = pub_hex
    else:
        for item in trusted_public_keys:
            pub_hex = _decode_fixed_hex(item, 32, "trusted Ed25519 public key").hex()
            normalized[derive_release_key_id(pub_hex)] = pub_hex

    if not normalized:
        raise BuildError("at least one trusted Ed25519 public key is required for verification")
    return normalized


def load_trusted_public_keys(
    *,
    public_key: str | None = None,
    public_key_file: Path | None = None,
    trusted_keys_file: Path | None = None,
) -> dict[str, str]:
    """Load pinned Ed25519 public key(s) from CLI arguments or JSON keyset file."""
    merged: dict[str, str] = {}
    if public_key:
        merged.update(normalize_trusted_public_keys(public_key))

    if public_key_file is not None:
        if not public_key_file.is_file():
            raise BuildError(f"public key file not found: {_rel(public_key_file)}")
        raw = public_key_file.read_text(encoding="utf-8").strip()
        if raw.startswith("{"):
            parsed = json.loads(raw)
            if isinstance(parsed, dict) and "public_key" in parsed:
                pub_hex = _decode_fixed_hex(parsed["public_key"], 32, "Ed25519 public key").hex()
                kid = (
                    _validate_source_revision_label(str(parsed["key_id"]))
                    if parsed.get("key_id")
                    else derive_release_key_id(pub_hex)
                )
                merged[kid] = pub_hex
            elif isinstance(parsed, dict):
                merged.update(normalize_trusted_public_keys(parsed))
            else:
                raise BuildError(f"invalid public key JSON in {_rel(public_key_file)}")
        else:
            merged.update(normalize_trusted_public_keys(raw))

    if trusted_keys_file is not None:
        if not trusted_keys_file.is_file():
            raise BuildError(f"trusted keys file not found: {_rel(trusted_keys_file)}")
        try:
            parsed = json.loads(trusted_keys_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BuildError(
                f"trusted keys file is not valid JSON: {_rel(trusted_keys_file)}"
            ) from exc
        if isinstance(parsed, dict) and isinstance(parsed.get("keys"), dict):
            merged.update(normalize_trusted_public_keys(parsed["keys"]))
        elif isinstance(parsed, (dict, list)):
            merged.update(normalize_trusted_public_keys(parsed))
        else:
            raise BuildError(f"invalid trusted keys format in {_rel(trusted_keys_file)}")

    if not merged:
        raise BuildError(
            "no trusted public key supplied: pass --public-key, --public-key-file, or --trusted-keys"
        )
    return merged


def _load_signed_release_manifest(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise BuildError(f"signed release manifest not found: {_rel(path)}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BuildError(f"signed release manifest is not valid JSON: {_rel(path)}") from exc
    if not isinstance(document, dict):
        raise BuildError(f"signed release manifest must be a JSON object: {_rel(path)}")
    return document


def _verify_release_envelope_and_bindings(
    signed_manifest: dict[str, Any],
    *,
    trusted_public_keys: dict[str, str] | Iterable[str] | str,
    lock: Lock | None = None,
    root: Path | None = None,
    expected_source_revision: str | None = None,
    verify_sources: bool = True,
) -> list[str]:
    """Verify signature, trust anchor, compiler lock, and source revision offline.

    Never opens or reads any circuit artifact files on disk.
    """
    trusted_map = normalize_trusted_public_keys(trusted_public_keys)
    findings: list[str] = []

    if not isinstance(signed_manifest, dict):
        return ["release manifest must be a JSON object"]
    if signed_manifest.get("format") != RELEASE_MANIFEST_FORMAT:
        findings.append(
            f"release manifest format: expected {RELEASE_MANIFEST_FORMAT!r}, "
            f"got {signed_manifest.get('format')!r}"
        )
    if signed_manifest.get("version") != MANIFEST_VERSION:
        findings.append(
            f"release manifest version: expected {MANIFEST_VERSION!r}, "
            f"got {signed_manifest.get('version')!r}"
        )

    payload = signed_manifest.get("payload")
    signature = signed_manifest.get("signature")
    if not isinstance(payload, dict):
        findings.append("release manifest payload is missing or not an object")
    if not isinstance(signature, dict):
        findings.append("release manifest signature block is missing or not an object")
    if findings:
        return findings

    assert isinstance(payload, dict)
    assert isinstance(signature, dict)

    if signature.get("algorithm") != RELEASE_SIGNATURE_ALGORITHM:
        findings.append(
            f"signature.algorithm: expected {RELEASE_SIGNATURE_ALGORITHM!r}, "
            f"got {signature.get('algorithm')!r}"
        )
    if signature.get("domain") != RELEASE_SIGNATURE_DOMAIN:
        findings.append(
            f"signature.domain: expected {RELEASE_SIGNATURE_DOMAIN!r}, "
            f"got {signature.get('domain')!r}"
        )

    key_id = signature.get("key_id")
    manifest_pub = signature.get("public_key")
    sig_value = signature.get("value")
    declared_payload_sha = signature.get("payload_sha256")

    pinned_pub: str | None = None
    if not isinstance(key_id, str) or not key_id:
        findings.append("signature.key_id is missing or invalid")
    elif key_id not in trusted_map:
        # Also allow lookup when caller passed a raw public key whose derived ID matches
        # only if key_id was customized? No — fail closed unless pinned key_id matches,
        # or if single key matches derived ID. Require explicit key_id match for rotation safety.
        findings.append(f"signature.key_id {key_id!r} is not in trusted public keys")
    else:
        pinned_pub = trusted_map[key_id]
        if not isinstance(manifest_pub, str) or manifest_pub.lower() != pinned_pub.lower():
            findings.append(
                f"signature.public_key for {key_id!r} does not match pinned public key"
            )

    payload_bytes = canonical_json_bytes(payload)
    actual_payload_sha = sha256_hex(payload_bytes)
    if declared_payload_sha != actual_payload_sha:
        findings.append(
            f"signature.payload_sha256 mismatch: {_short(str(declared_payload_sha))} "
            f"!= {_short(actual_payload_sha)}"
        )

    if pinned_pub is not None and (
        not isinstance(sig_value, str)
        or not ed25519_verify_message(
            pinned_pub, _release_signing_message(payload_bytes), sig_value
        )
    ):
        findings.append("signature verification failed for release manifest payload")

    # Fail closed immediately on any cryptographic / envelope error before checking
    # downstream fields or touching the filesystem.
    if findings:
        return findings

    compiler_lock = payload.get("compiler_lock")
    source_rev = payload.get("source_revision")
    artifacts = payload.get("artifacts")

    if not isinstance(compiler_lock, dict):
        findings.append("payload.compiler_lock is missing or not an object")
    if not isinstance(source_rev, dict):
        findings.append("payload.source_revision is missing or not an object")
    if not isinstance(artifacts, list) or not artifacts:
        findings.append("payload.artifacts must be a non-empty list")
    if findings:
        return findings

    assert isinstance(compiler_lock, dict)
    assert isinstance(source_rev, dict)
    assert isinstance(artifacts, list)

    seen_paths: set[str] = set()
    for entry in artifacts:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            findings.append("payload.artifacts contains a malformed artifact entry")
            continue
        art_path = entry["path"]
        if art_path in seen_paths:
            findings.append(f"payload.artifacts declares duplicate path {art_path}")
        seen_paths.add(art_path)
        for digest_key in ("raw_sha256", "normalized_sha256"):
            digest_val = entry.get(digest_key)
            if not isinstance(digest_val, str) or not re.fullmatch(r"[0-9a-f]{64}", digest_val):
                findings.append(f"artifact {art_path}: invalid {digest_key}")
        for size_key in ("raw_bytes", "normalized_bytes"):
            size_val = entry.get(size_key)
            if isinstance(size_val, bool) or not isinstance(size_val, int) or size_val < 0:
                findings.append(f"artifact {art_path}: invalid {size_key}")

    if expected_source_revision is not None:
        expected_rev = _validate_source_revision_label(expected_source_revision)
        if source_rev.get("revision") != expected_rev:
            findings.append(
                f"source_revision.revision: expected {expected_rev!r}, "
                f"got {source_rev.get('revision')!r}"
            )

    declared_prov = source_rev.get("provenance")
    if not isinstance(declared_prov, dict) or not declared_prov:
        findings.append("source_revision.provenance must be a non-empty map")
    else:
        computed_prov_sha = sha256_hex(canonical_json_bytes(declared_prov))
        if source_rev.get("provenance_sha256") != computed_prov_sha:
            findings.append(
                "source_revision.provenance_sha256 disagrees with embedded provenance map"
            )

    if lock is not None:
        expected_lock_sha = sha256_hex(canonical_json_bytes(lock.raw))
        if compiler_lock.get("canonical_sha256") != expected_lock_sha:
            findings.append(
                f"compiler_lock.canonical_sha256: {_short(compiler_lock.get('canonical_sha256'))} "
                f"-> {_short(expected_lock_sha)}"
            )
        expected_toolchain = {
            "nargo": lock.toolchain["nargo"]["version"],
            "barretenberg": lock.toolchain["barretenberg"]["version"],
            "proving_scheme": lock.toolchain["proving_scheme"],
            "oracle_hash": lock.toolchain["oracle_hash"],
        }
        actual_tc = compiler_lock.get("toolchain") or {}
        for key, exp_val in sorted(expected_toolchain.items()):
            if actual_tc.get(key) != exp_val:
                findings.append(
                    f"compiler_lock.toolchain.{key}: expected {actual_tc.get(key)!r}, "
                    f"got {exp_val!r}"
                )
        expected_norm_sha = sha256_hex(canonical_json_bytes(lock.raw["normalization"]))
        if compiler_lock.get("normalization_policy_sha256") != expected_norm_sha:
            findings.append(
                "compiler_lock.normalization_policy_sha256 disagrees with local toolchain lock"
            )

        if verify_sources and root is not None and isinstance(declared_prov, dict):
            actual_prov = _collect_provenance_for_root(lock, root)
            for src_path in sorted(set(declared_prov) | set(actual_prov)):
                before = declared_prov.get(src_path)
                after = actual_prov.get(src_path)
                if before != after:
                    findings.append(f"source {src_path}: {_short(before)} -> {_short(after)}")

    return findings


def _normalize_artifact_bytes_for_verification(
    data: bytes,
    *,
    kind: str,
    path_label: str,
    volatile_json_keys: frozenset[str],
    strip_custom_sections: frozenset[str],
) -> bytes:
    if kind == "json":
        return normalize_json(data, volatile_json_keys)
    if kind == "wasm":
        return normalize_wasm(data, strip_custom_sections)
    if kind in ("binary", "bytes"):
        return data
    raise BuildError(f"{path_label}: unknown artifact kind {kind!r}")


def _verify_single_release_artifact_on_disk(
    entry: dict[str, Any],
    *,
    root: Path,
    lock: Lock | None = None,
    signed_normalization: dict[str, Any] | None = None,
) -> tuple[bytes | None, list[str]]:
    """Verify containment, size bounds, and digests for one declared release artifact."""
    art_path = str(entry["path"])
    try:
        norm_rel, resolved_file = _resolve_contained_release_path(root, art_path)
    except BuildError as exc:
        return None, [str(exc)]

    max_bytes = lock.limits.max_artifact_bytes if lock is not None else (256 * 1024 * 1024)
    declared_bytes = int(entry["raw_bytes"])
    if declared_bytes > max_bytes:
        return None, [
            f"artifact {norm_rel}: declared size {declared_bytes} exceeds cap {max_bytes}"
        ]

    try:
        st = resolved_file.stat()
    except FileNotFoundError:
        return None, [f"artifact {norm_rel}: missing from release directory"]
    except OSError:
        return None, [f"artifact {norm_rel}: unreadable metadata"]

    if not resolved_file.is_file():
        return None, [f"artifact {norm_rel}: not a regular file"]
    if st.st_size > max_bytes:
        return None, [f"artifact {norm_rel}: size {st.st_size} exceeds cap {max_bytes}"]

    kind = str(entry.get("kind", "binary"))
    if kind in ("binary", "bytes") and st.st_size != declared_bytes:
        return None, [
            f"artifact {norm_rel}: byte size mismatch (expected {declared_bytes}, got {st.st_size})"
        ]

    try:
        raw_data = resolved_file.read_bytes()
    except OSError:
        return None, [f"artifact {norm_rel}: unreadable content"]

    signed_norm = signed_normalization or {}
    volatile_keys = (
        lock.volatile_json_keys
        if lock is not None
        else frozenset(
            signed_norm.get("volatile_json_keys")
            or ("debug_symbols", "file_map", "names", "noir_version", "build_timestamp")
        )
    )
    strip_sections = (
        lock.strip_custom_sections
        if lock is not None
        else frozenset(
            signed_norm.get("strip_custom_sections")
            or (".debug_info", ".debug_line", ".debug_str", ".debug_abbrev", "producers", "name")
        )
    )
    try:
        normalized_data = _normalize_artifact_bytes_for_verification(
            raw_data,
            kind=kind,
            path_label=norm_rel,
            volatile_json_keys=volatile_keys,
            strip_custom_sections=strip_sections,
        )
    except BuildError as exc:
        return None, [str(exc)]

    actual_norm_sha = sha256_hex(normalized_data)
    expected_norm_sha = entry["normalized_sha256"]
    if actual_norm_sha != expected_norm_sha:
        msg = (
            f"artifact {norm_rel}: normalized digest {_short(expected_norm_sha)} "
            f"-> {_short(actual_norm_sha)}"
        )
        return None, [msg]

    if len(normalized_data) != int(entry["normalized_bytes"]):
        msg = (
            f"artifact {norm_rel}: normalized byte length mismatch "
            f"(expected {entry['normalized_bytes']}, got {len(normalized_data)})"
        )
        return None, [msg]

    if kind in ("binary", "bytes") and sha256_hex(raw_data) != entry["raw_sha256"]:
        msg = (
            f"artifact {norm_rel}: raw digest {_short(entry['raw_sha256'])} "
            f"-> {_short(sha256_hex(raw_data))}"
        )
        return None, [msg]

    return raw_data, []


def verify_signed_release_manifest(
    signed_manifest: dict[str, Any],
    *,
    trusted_public_keys: dict[str, str] | Iterable[str] | str,
    lock: Lock | None = None,
    root: Path | None = None,
    expected_source_revision: str | None = None,
    verify_sources: bool = True,
    verify_artifacts: bool = True,
) -> list[str]:
    """Verify a signed release manifest offline against pinned keys, lock, sources, and files."""
    findings = _verify_release_envelope_and_bindings(
        signed_manifest,
        trusted_public_keys=trusted_public_keys,
        lock=lock,
        root=root,
        expected_source_revision=expected_source_revision,
        verify_sources=verify_sources,
    )
    if findings:
        return findings

    if verify_artifacts and root is not None:
        signed_norm = signed_manifest["payload"]["compiler_lock"].get("normalization")
        for entry in signed_manifest["payload"]["artifacts"]:
            _, art_findings = _verify_single_release_artifact_on_disk(
                entry, root=root, lock=lock, signed_normalization=signed_norm
            )
            findings.extend(art_findings)

    return findings


def load_verified_release_artifact(
    artifact_path: str,
    *,
    signed_manifest: dict[str, Any] | Path,
    trusted_public_keys: dict[str, str] | Iterable[str] | str,
    root: Path = REPO_ROOT,
    lock: Lock | None = None,
    expected_source_revision: str | None = None,
    verify_sources: bool = False,
    parse_json: bool = False,
) -> bytes | Any:
    """Verify a signed release manifest offline BEFORE loading an artifact for a client.

    Guarantees fail-closed behavior:
      1. Signature, pinned trust anchor, compiler lock (if provided), and source
         revision are verified *before* any artifact file is opened or read.
      2. Only artifacts explicitly listed in the signed manifest can be loaded.
      3. Containment, byte-size bounds, and canonical/raw digests are verified
         before bytes or parsed JSON are returned to the caller.
    """
    manifest_doc = (
        _load_signed_release_manifest(signed_manifest)
        if isinstance(signed_manifest, Path)
        else signed_manifest
    )
    findings = _verify_release_envelope_and_bindings(
        manifest_doc,
        trusted_public_keys=trusted_public_keys,
        lock=lock,
        root=root,
        expected_source_revision=expected_source_revision,
        verify_sources=verify_sources,
    )
    if findings:
        raise BuildError(f"offline release manifest verification failed: {findings[0]}")

    norm_query = artifact_path.replace("\\", "/").strip().removeprefix("./")

    artifacts = {entry["path"]: entry for entry in manifest_doc["payload"]["artifacts"]}
    target_entry = artifacts.get(norm_query)
    if target_entry is None:
        raise BuildError(
            f"refusing to load unverified artifact not present in signed release manifest: {norm_query}"
        )

    signed_norm = manifest_doc["payload"]["compiler_lock"].get("normalization")
    raw_bytes, art_findings = _verify_single_release_artifact_on_disk(
        target_entry, root=root, lock=lock, signed_normalization=signed_norm
    )
    if art_findings or raw_bytes is None:
        detail = art_findings[0] if art_findings else f"artifact {norm_query}: verification failed"
        raise BuildError(f"offline artifact digest verification failed: {detail}")

    if parse_json:
        try:
            return json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BuildError(f"verified artifact {norm_query} is not valid UTF-8 JSON") from exc

    return raw_bytes


def load_verified_client_artifacts(
    *,
    signed_manifest: dict[str, Any] | Path,
    trusted_public_keys: dict[str, str] | Iterable[str] | str,
    root: Path = REPO_ROOT,
    lock: Lock | None = None,
    expected_source_revision: str | None = None,
    verify_sources: bool = False,
    roles: Iterable[str] | None = (PUBLISHED_ACIR_ROLE, EXPORTED_BUNDLE_ROLE),
) -> dict[str, bytes]:
    """Verify a signed release manifest offline and load all matching client artifacts."""
    manifest_doc = (
        _load_signed_release_manifest(signed_manifest)
        if isinstance(signed_manifest, Path)
        else signed_manifest
    )
    findings = _verify_release_envelope_and_bindings(
        manifest_doc,
        trusted_public_keys=trusted_public_keys,
        lock=lock,
        root=root,
        expected_source_revision=expected_source_revision,
        verify_sources=verify_sources,
    )
    if findings:
        raise BuildError(f"offline release manifest verification failed: {findings[0]}")

    allowed_roles = set(roles) if roles is not None else None
    signed_norm = manifest_doc["payload"]["compiler_lock"].get("normalization")
    loaded: dict[str, bytes] = {}
    for entry in manifest_doc["payload"]["artifacts"]:
        if allowed_roles is not None and entry.get("role") not in allowed_roles:
            continue
        raw_bytes, art_findings = _verify_single_release_artifact_on_disk(
            entry, root=root, lock=lock, signed_normalization=signed_norm
        )
        if art_findings or raw_bytes is None:
            detail = (
                art_findings[0]
                if art_findings
                else f"artifact {entry['path']}: verification failed"
            )
            raise BuildError(f"offline artifact digest verification failed: {detail}")
        loaded[entry["path"]] = raw_bytes

    return loaded


def command_sign_release(args: argparse.Namespace) -> int:
    lock_path = Path(args.lock)
    root = Path(args.root).resolve() if getattr(args, "root", None) else REPO_ROOT
    lock = load_lock(lock_path)
    seed_hex, file_key_id = load_signing_seed_hex(
        key_file=Path(args.signing_key_file) if args.signing_key_file else None,
        env_var=args.signing_key_env,
    )
    payload = build_release_manifest_payload(
        lock,
        root,
        scope=args.scope,
        source_revision=args.source_revision,
        extra_artifacts=args.extra_artifact or (),
        lock_path=lock_path,
    )
    signed = sign_release_manifest(
        payload,
        seed_hex=seed_hex,
        key_id=args.key_id or file_key_id,
    )

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(serialize_manifest(signed), encoding="utf-8")
    signal(
        "release.manifest.signed",
        path=_rel(output),
        scope=payload["scope"],
        key_id=signed["signature"]["key_id"],
        revision=payload["source_revision"]["revision"],
        artifacts=len(payload["artifacts"]),
        sources=len(payload["source_revision"]["provenance"]),
    )
    return EXIT_OK


def command_verify_release(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve() if getattr(args, "root", None) else REPO_ROOT
    lock = None if args.skip_lock else load_lock(Path(args.lock))
    trusted_keys = load_trusted_public_keys(
        public_key=args.public_key,
        public_key_file=Path(args.public_key_file) if args.public_key_file else None,
        trusted_keys_file=Path(args.trusted_keys) if args.trusted_keys else None,
    )
    signed_doc = _load_signed_release_manifest(Path(args.manifest))
    findings = verify_signed_release_manifest(
        signed_doc,
        trusted_public_keys=trusted_keys,
        lock=lock,
        root=root,
        expected_source_revision=args.expected_source_revision,
        verify_sources=not args.skip_sources and lock is not None,
        verify_artifacts=not args.skip_artifacts,
    )
    if findings:
        for finding in findings:
            signal("drift.finding", detail=finding)
        signal("release.verify.failed", findings=len(findings))
        return EXIT_DRIFT

    signal(
        "release.verify.ok",
        key_id=signed_doc["signature"]["key_id"],
        revision=signed_doc["payload"]["source_revision"]["revision"],
        artifacts=len(signed_doc["payload"]["artifacts"]),
    )
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
    lock = load_lock(Path(args.lock))
    manifest, run = build_manifest(lock, REPO_ROOT)
    _fail_on_fatal(run)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(serialize_manifest(manifest), encoding="utf-8")

    signal(
        "manifest.written",
        path=_rel(output),
        artifacts=len(manifest["artifacts"]),
        skipped=len(manifest["skipped"]),
        sources=len(manifest["provenance"]),
    )
    return EXIT_OK


def command_verify(args: argparse.Namespace) -> int:
    lock = load_lock(Path(args.lock))
    expected = _load_manifest(Path(args.manifest))
    actual, run = build_manifest(lock, REPO_ROOT)
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--lock", default=str(DEFAULT_LOCK), help="path to zk/toolchain.lock.json"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    write = subparsers.add_parser("write", help="write a manifest from the working tree")
    write.add_argument("--output", default=str(DEFAULT_MANIFEST))
    write.set_defaults(handler=command_write)

    verify = subparsers.add_parser("verify", help="fail on drift from a manifest")
    verify.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    verify.set_defaults(handler=command_verify)

    compare = subparsers.add_parser("compare", help="diff two manifests (double build)")
    compare.add_argument("first")
    compare.add_argument("second")
    compare.set_defaults(handler=command_compare)

    coverage = subparsers.add_parser(
        "check-coverage",
        help="fail when the lock and the source tree disagree about which circuits exist",
    )
    coverage.set_defaults(handler=command_check_coverage)

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

    sign_release = subparsers.add_parser(
        "sign-release",
        help="build and Ed25519-sign a circuit artifact release manifest",
    )
    sign_release.add_argument("--output", default=str(DEFAULT_RELEASE_MANIFEST))
    sign_release.add_argument(
        "--scope",
        choices=("browser", "all"),
        default="browser",
        help="artifact scope to bind in the signed release manifest",
    )
    sign_release.add_argument(
        "--source-revision",
        default=None,
        help="explicit source commit SHA or release tag bound in the manifest",
    )
    sign_release.add_argument(
        "--extra-artifact",
        action="append",
        default=[],
        help="additional exported release artifact path (relative to --root)",
    )
    sign_release.add_argument(
        "--signing-key-file",
        default=None,
        help="file containing 64-hex Ed25519 seed or JSON {'seed': ..., 'key_id': ...}",
    )
    sign_release.add_argument(
        "--signing-key-env",
        default=SIGNING_KEY_ENV,
        help=f"environment variable holding Ed25519 signing seed (default: {SIGNING_KEY_ENV})",
    )
    sign_release.add_argument(
        "--key-id",
        default=None,
        help="explicit signer key identifier (defaults to ed25519:<pubkey-sha256-prefix>)",
    )
    sign_release.add_argument(
        "--root",
        default=None,
        help="repository / release root directory (defaults to repo root)",
    )
    sign_release.set_defaults(handler=command_sign_release)

    verify_release = subparsers.add_parser(
        "verify-release",
        help="verify a signed release manifest offline against pinned Ed25519 public key(s)",
    )
    verify_release.add_argument("--manifest", default=str(DEFAULT_RELEASE_MANIFEST))
    verify_release.add_argument(
        "--public-key",
        default=None,
        help="pinned 64-hex Ed25519 public key",
    )
    verify_release.add_argument(
        "--public-key-file",
        default=None,
        help="file containing pinned Ed25519 public key hex or JSON",
    )
    verify_release.add_argument(
        "--trusted-keys",
        default=None,
        help="JSON file mapping key_id -> 64-hex Ed25519 public key",
    )
    verify_release.add_argument(
        "--expected-source-revision",
        default=None,
        help="fail if source_revision.revision does not match this value",
    )
    verify_release.add_argument(
        "--skip-lock",
        action="store_true",
        help="verify offline without a local zk/toolchain.lock.json (pure client bundle mode)",
    )
    verify_release.add_argument(
        "--skip-sources",
        action="store_true",
        help="skip checking local .nr sources (verify embedded provenance digest & artifacts only)",
    )
    verify_release.add_argument(
        "--skip-artifacts",
        action="store_true",
        help="verify signature, lock, and provenance bindings without reading artifact files",
    )
    verify_release.add_argument(
        "--root",
        default=None,
        help="release directory containing exported/published artifacts (defaults to repo root)",
    )
    verify_release.set_defaults(handler=command_verify_release)

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
