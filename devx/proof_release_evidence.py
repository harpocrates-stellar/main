#!/usr/bin/env python3
"""Assemble a credential-free proof artifact release evidence bundle.

The bundle is a deterministic JSON document with three evidence sections:
tool versions, artifact digests, and validation outcomes. It never runs a
documented command, reads a credential, calls a network, or touches a
witness. Inputs are bounded locale-independent JSON documents produced by the
zk tooling (``zk/toolchain.lock.json``, the committed artifact/provenance/
browser manifests, and the privacy-safe retention manifest) plus an optional
validation record describing checks that were really executed.

The important rule is honesty about absence: a proving check that was not
executed, was skipped, has an unrecognised status, or lacks its evidence label
is recorded as ``missing_evidence``. It is never promoted to ``pass`` because
a file happens to exist or because a command looks plausible. A ``pass`` is
only emitted by a validation record entry with an explicit ``pass`` status and
a short, privacy-checked evidence label.

Exit codes
----------
  0   bundle built and no check failed (missing evidence is reported, not hidden)
  1   a check failed, or --require-complete was set and evidence is missing
  2   an input was missing, malformed, oversized, or sensitive
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "zk" / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "zk" / "tools"))

from devx._io import (  # noqa: E402
    DEFAULT_SENSITIVE_KEY_RE,
    contains_sensitive_text,
    read_json_bounded,
)

import artifact_manifest as am  # noqa: E402
import build_circuits as bc  # noqa: E402

BUNDLE_FORMAT = "harpocrates.proof-release-evidence"
BUNDLE_VERSION = 1
RECORD_FORMAT = "harpocrates.proof-validation-record"
RECORD_VERSION = 1
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_LABEL_BYTES = 120
MAX_DIGESTS = 512

PASS = "pass"
FAIL = "fail"
MISSING = "missing_evidence"
STATUSES = (PASS, FAIL, MISSING)
# A record may say skipped/not_run; the bundle deliberately maps those to
# missing_evidence rather than inventing a pass.
NON_PASS_RECORD_STATUSES = frozenset({"skipped", "not_run", "not-executed", "unknown"})

TOOL_NAMES = ("nargo", "barretenberg")
TOOL_CHECK_IDS = {
    "nargo": "toolchain.nargo_version",
    "barretenberg": "toolchain.barretenberg_version",
}
PROOF_CHECK_IDS = ("proof.generate", "proof.verify")
DIGEST_SOURCES = (
    ("artifact_manifest", "zk/artifacts.manifest.json", am.MANIFEST_FORMAT),
    (
        "browser_manifest",
        "zk/browser.artifacts.manifest.json",
        am.BROWSER_MANIFEST_FORMAT,
    ),
    ("circuit_provenance", "zk/circuit.provenance.json", am.PROVENANCE_FORMAT),
    (
        "retention_manifest",
        "zk/release/retention-manifest.json",
        "hpx-artifact-retention/1",
    ),
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/ -]*$")


class EvidenceError(ValueError):
    """A bounded, privacy-safe input failure. Carries no input contents."""


def _display(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _read_json(
    path: Path, root: Path, *, required: bool = False
) -> dict[str, Any] | None:
    if not path.is_file():
        if required:
            raise EvidenceError(f"required input not found: {_display(path, root)}")
        return None
    value = read_json_bounded(
        path,
        MAX_INPUT_BYTES,
        error_factory=EvidenceError,
        display_name=_display(path, root),
        sensitive_pattern=DEFAULT_SENSITIVE_KEY_RE,
        require_dict=True,
    )
    assert isinstance(value, dict)
    return value


def _safe_path(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise EvidenceError(f"{location} has an invalid path")
    candidate = Path(value.replace("\\", "/"))
    if (
        candidate.is_absolute()
        or ".." in candidate.parts
        or value.startswith("/")
        or re.match(r"^[A-Za-z]:", value)
    ):
        raise EvidenceError(f"{location} path must stay inside the checkout")
    return candidate.as_posix()


def _label(value: Any, location: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_LABEL_BYTES
        or not LABEL_RE.fullmatch(value)
        or contains_sensitive_text(value)
    ):
        raise EvidenceError(f"{location} has an invalid or sensitive evidence label")
    return value


def _check(check_id: str, status: str, source: str, detail: str) -> dict[str, str]:
    if status not in STATUSES:
        raise EvidenceError("internal error: invalid evidence status")
    return {
        "id": check_id,
        "status": status,
        "source": source,
        "detail": _label(detail, check_id),
    }


def _load_validation_record(path: Path | None, root: Path) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    data = _read_json(path, root, required=True)
    assert data is not None
    if data.get("format") != RECORD_FORMAT or data.get("version") != RECORD_VERSION:
        raise EvidenceError("validation record has an unsupported format or version")
    checks = data.get("checks")
    if not isinstance(checks, list) or len(checks) > MAX_DIGESTS:
        raise EvidenceError("validation record checks must be a bounded array")
    record: dict[str, dict[str, Any]] = {}
    for item in checks:
        if not isinstance(item, dict):
            raise EvidenceError("validation record check must be an object")
        check_id = _label(item.get("id"), "validation record check id")
        if check_id in record:
            raise EvidenceError("validation record has a duplicate check id")
        for value in item.values():
            if isinstance(value, str) and contains_sensitive_text(value):
                raise EvidenceError("validation record contains sensitive text")
        status = item.get("status")
        if not isinstance(status, str) or len(status) > MAX_LABEL_BYTES:
            raise EvidenceError("validation record check status is invalid")
        record[check_id] = dict(item)
    return record


def _record_status(item: dict[str, Any] | None) -> str:
    if item is None:
        return MISSING
    status = item.get("status")
    if status == PASS:
        return PASS
    if status == FAIL:
        return FAIL
    # skipped / not_run / unknown / malformed statuses are all absence of
    # execution evidence. Never infer a pass from them.
    return MISSING


def _digest_entry(
    path: str,
    digest: Any,
    source: str,
    digest_type: str = "sha256",
) -> dict[str, str]:
    safe = _safe_path(path, source)
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise EvidenceError(f"{source} contains a non sha256 digest")
    return {
        "path": safe,
        "sha256": digest,
        "digest_type": digest_type,
        "source": source,
    }


def _digests_from(
    data: dict[str, Any], source: str, expected_format: str
) -> list[dict[str, str]]:
    format_key = "schema" if source == "retention_manifest" else "format"
    if data.get(format_key) != expected_format:
        raise EvidenceError(f"{source} has an unexpected format")
    entries: list[dict[str, str]] = []
    for artifact in data.get("artifacts") or []:
        if not isinstance(artifact, dict):
            raise EvidenceError(f"{source} artifact must be an object")
        for key, digest_type in (
            ("sha256", "sha256"),
            ("normalized_sha256", "normalized"),
            ("raw_sha256", "raw"),
        ):
            if key in artifact and artifact[key] is not None:
                entries.append(
                    _digest_entry(
                        artifact.get("path"), artifact[key], source, digest_type
                    )
                )
    provenance = data.get("provenance")
    if isinstance(provenance, dict):
        for path, digest in sorted(provenance.items()):
            entries.append(_digest_entry(path, digest, source))
    elif source == "retention_manifest":
        for entry in data.get("files") or []:
            if not isinstance(entry, dict):
                raise EvidenceError(f"{source} file must be an object")
            digest_item = _digest_entry(entry.get("path"), entry.get("sha256"), source)
            digest_item["path"] = "retained/" + digest_item["path"]
            entries.append(digest_item)
    elif provenance is not None:
        raise EvidenceError(f"{source} provenance must be an object")
    if len(entries) > MAX_DIGESTS:
        raise EvidenceError(f"{source} exceeds the digest cap")
    return entries


def _tool_versions(
    lock: dict[str, Any],
    record: dict[str, dict[str, Any]],
    supplied: dict[str, str],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, str]]]:
    toolchain = lock.get("toolchain")
    if not isinstance(toolchain, dict):
        raise EvidenceError("toolchain lock has no toolchain object")
    versions: dict[str, dict[str, Any]] = {}
    outcomes: list[dict[str, str]] = []
    for tool in TOOL_NAMES:
        declaration = toolchain.get(tool)
        pinned = declaration.get("version") if isinstance(declaration, dict) else None
        if not isinstance(pinned, str) or not pinned:
            raise EvidenceError(f"toolchain lock has no {tool} version")
        observed = supplied.get(tool)
        item = record.get(TOOL_CHECK_IDS[tool])
        if item and isinstance(item.get("observed"), str) and item["observed"]:
            observed = item["observed"]
        status = _record_status(item)
        if status == PASS and observed is None:
            status = MISSING
        if status == MISSING and observed is not None:
            # An unexecuted/invalid record cannot be rescued by a bare CLI
            # claim unless the record itself asserts a pass.
            status = MISSING
        if status == PASS:
            matched = bc.extract_semver(observed or "") == pinned
            status = PASS if matched else FAIL
        elif observed is not None and item is None:
            matched = bc.extract_semver(observed) == pinned
            status = PASS if matched else FAIL
        versions[tool] = {
            "pinned": pinned,
            "observed": observed,
            "status": status,
        }
        outcomes.append(
            _check(
                TOOL_CHECK_IDS[tool],
                status,
                "toolchain.lock.json",
                f"{tool} version evidence",
            )
        )
    return versions, outcomes


def _proof_outcomes(record: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    outcomes: list[dict[str, str]] = []
    for check_id in PROOF_CHECK_IDS:
        item = record.get(check_id)
        status = _record_status(item)
        if status == PASS:
            evidence = item.get("evidence") if item else None
            if not isinstance(evidence, str) or not evidence:
                status = MISSING
            else:
                _label(evidence, check_id)
        outcomes.append(
            _check(check_id, status, "validation-record", f"{check_id} outcome")
        )
    return outcomes


def build_bundle(
    root: Path,
    *,
    lock_path: Path,
    digest_paths: dict[str, Path],
    record_path: Path | None,
    tool_versions: dict[str, str],
) -> dict[str, Any]:
    """Build the evidence bundle from bounded local inputs."""
    lock = _read_json(lock_path, root, required=True)
    assert lock is not None
    if (
        lock.get("format") != "harpocrates.zk-toolchain-lock"
        or lock.get("version") != 1
    ):
        raise EvidenceError("toolchain lock has an unsupported format or version")
    record = _load_validation_record(record_path, root)

    versions, outcomes = _tool_versions(lock, record, tool_versions)

    digests: list[dict[str, str]] = []
    for source, default_relative, expected_format in DIGEST_SOURCES:
        path = digest_paths.get(source, root / default_relative)
        data = _read_json(path, root)
        if data is None:
            status, detail = MISSING, f"{source} document not present"
        else:
            found = _digests_from(data, source, expected_format)
            digests.extend(found)
            status = PASS if found else MISSING
            detail = (
                f"{source} digests collected" if found else f"{source} has no digests"
            )
        outcomes.append(_check(f"digests.{source}", status, source, detail))

    outcomes.extend(_proof_outcomes(record))
    counts = {
        status: sum(1 for item in outcomes if item["status"] == status)
        for status in STATUSES
    }
    return {
        "format": BUNDLE_FORMAT,
        "version": BUNDLE_VERSION,
        "tool_versions": versions,
        "digests": sorted(digests, key=lambda item: (item["source"], item["path"])),
        "validation_outcomes": outcomes,
        "summary": {
            **counts,
            "total": len(outcomes),
            "release_ready": counts[FAIL] == 0 and counts[MISSING] == 0,
        },
    }


def serialize(bundle: dict[str, Any]) -> str:
    return json.dumps(bundle, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def _parse_tool_version(value: str) -> tuple[str, str]:
    name, separator, version = value.partition("=")
    if not separator or name not in TOOL_NAMES or not version:
        raise EvidenceError(
            "--tool-version must be nargo=<version> or barretenberg=<version>"
        )
    return name, _label(version, "--tool-version")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="Checkout root (defaults to parent of devx)",
    )
    parser.add_argument("--lock", type=Path, default=None, help="Toolchain lock JSON")
    parser.add_argument(
        "--validation-record",
        type=Path,
        default=None,
        help="JSON record of executed checks",
    )
    parser.add_argument(
        "--tool-version",
        action="append",
        default=[],
        metavar="NAME=VERSION",
        help="Observed tool version (repeatable; nargo or barretenberg)",
    )
    for source, default_relative, _ in DIGEST_SOURCES:
        parser.add_argument(
            f"--{source.replace('_', '-')}",
            type=Path,
            default=None,
            help=f"Override {default_relative}",
        )
    parser.add_argument(
        "--out", type=Path, default=None, help="Write the bundle here (default: stdout)"
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="Exit non-zero when any check is missing_evidence as well as on failure",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    try:
        supplied = dict(_parse_tool_version(value) for value in args.tool_version)
        lock_path = args.lock or root / "zk" / "toolchain.lock.json"
        digest_paths = {
            source: getattr(args, source) or root / default_relative
            for source, default_relative, _ in DIGEST_SOURCES
        }
        record_path = args.validation_record
        out_path = args.out.resolve() if args.out else None
        inputs = [lock_path, *digest_paths.values()]
        if record_path is not None:
            inputs.append(record_path)
        if out_path is not None and out_path in {path.resolve() for path in inputs}:
            raise EvidenceError("--out must not overwrite an input document")

        bundle = build_bundle(
            root,
            lock_path=lock_path,
            digest_paths=digest_paths,
            record_path=record_path,
            tool_versions=supplied,
        )
        payload = serialize(bundle)
        if out_path is not None:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(payload, encoding="utf-8")
        else:
            sys.stdout.write(payload)
    except (EvidenceError, OSError, UnicodeError) as exc:
        print(f"proof release evidence error: {exc}", file=sys.stderr)
        return 2

    summary = bundle["summary"]
    print(
        "proof release evidence: "
        f"{summary[PASS]} pass, {summary[FAIL]} fail, "
        f"{summary[MISSING]} missing_evidence "
        f"(release_ready={str(summary['release_ready']).lower()})",
        file=sys.stderr,
    )
    if summary[FAIL] or (args.require_complete and summary[MISSING]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
