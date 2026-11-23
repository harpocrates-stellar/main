#!/usr/bin/env python3
"""Generate and verify the scoped Silent Witness statement descriptor."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

ARTIFACT_PATHS = (
    "frontend/public/noir/silent_witness.json",
    "frontend/public/noir/silent_witness_helper.json",
)
HELPER_OUTPUTS = [
    {"name": "credential_root", "type": "Field", "visibility": "public"},
    {"name": "nullifier", "type": "Field", "visibility": "public"},
    {"name": "domain_tag", "type": "Field", "visibility": "public"},
]


class DescriptorError(ValueError):
    """The descriptor cannot be generated or verified against reviewed inputs."""


def canonical_json(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def descriptor_digest(document: dict[str, Any]) -> str:
    payload = {
        key: value
        for key, value in document.items()
        if key != "descriptor_sha256"
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _signature(source: str) -> tuple[list[dict[str, str]], str | None]:
    match = re.search(r"\bfn\s+main\s*\(", source)
    if not match:
        raise DescriptorError("main function signature not found")

    start = match.end()
    depth = 1
    end = start
    while end < len(source) and depth:
        if source[end] == "(":
            depth += 1
        elif source[end] == ")":
            depth -= 1
        end += 1
    if depth:
        raise DescriptorError("unterminated main function signature")

    raw_parameters = source[start : end - 1]
    parameters: list[str] = []
    segment_start = 0
    nesting: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for index, character in enumerate(raw_parameters):
        if character in "([{":
            nesting.append(character)
        elif character in ")]}":
            if nesting and nesting[-1] == pairs[character]:
                nesting.pop()
        elif character == "," and not nesting:
            parameters.append(raw_parameters[segment_start:index])
            segment_start = index + 1
    parameters.append(raw_parameters[segment_start:])

    parsed: list[dict[str, str]] = []
    for parameter in parameters:
        parameter = re.sub(r"//.*", "", parameter).strip()
        if not parameter:
            continue
        field_match = re.match(
            r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(pub\s+)?(.+)$",
            parameter,
            flags=re.DOTALL,
        )
        if not field_match:
            raise DescriptorError(f"unrecognized main parameter: {parameter}")
        parsed.append(
            {
                "name": field_match.group(1),
                "visibility": "public" if field_match.group(2) else "private",
                "type": field_match.group(3).strip(),
            }
        )

    return_type_match = re.search(r"\s*->\s*(.+?)\s*\{", source[end:], re.DOTALL)
    return_type = return_type_match.group(1).strip() if return_type_match else None
    return parsed, return_type


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DescriptorError(f"{label} is unreadable or invalid JSON: {exc}") from exc


def build_descriptor(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    main_path = repo_root / "zk" / "noir" / "silent_witness" / "src" / "main.nr"
    helper_path = (
        repo_root / "zk" / "noir" / "silent_witness_helper" / "src" / "main.nr"
    )
    main_inputs, main_return = _signature(main_path.read_text(encoding="utf-8"))
    helper_inputs, helper_return = _signature(helper_path.read_text(encoding="utf-8"))
    if main_return is not None:
        raise DescriptorError("silent_witness.main must not declare return values")
    if helper_return != "pub (Field, Field, Field)":
        raise DescriptorError(
            f"unexpected helper public return type: {helper_return!r}"
        )

    manifest_path = repo_root / "zk" / "browser.artifacts.manifest.json"
    manifest = _read_json(manifest_path, "browser artifact manifest")
    artifacts_by_path = {
        entry.get("path"): entry for entry in manifest.get("artifacts", [])
    }
    artifact_bindings = []
    for artifact_path in ARTIFACT_PATHS:
        artifact = artifacts_by_path.get(artifact_path)
        digest = artifact.get("normalized_sha256") if artifact else None
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise DescriptorError(
                f"reviewed normalized artifact digest missing: {artifact_path}"
            )
        artifact_bindings.append(
            {"path": artifact_path, "normalized_sha256": digest}
        )

    source_bindings = []
    for source_path in (
        "zk/noir/harpocrates_common/src/lib.nr",
        "zk/noir/silent_witness/src/main.nr",
        "zk/noir/silent_witness_helper/src/main.nr",
    ):
        source_bytes = (repo_root / source_path).read_bytes()
        source_bytes = source_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        source_bindings.append(
            {
                "path": source_path,
                "sha256": hashlib.sha256(source_bytes).hexdigest(),
            }
        )

    public_inputs = [item for item in main_inputs if item["visibility"] == "public"]
    private_inputs = [item for item in main_inputs if item["visibility"] == "private"]
    descriptor: dict[str, Any] = {
        "format": "harpocrates.scoped-nullifier-statement-descriptor",
        "version": 1,
        "id": "silent_witness/scoped-v2",
        "main": {
            "function": "silent_witness.main",
            "public_inputs": public_inputs,
            "private_inputs": private_inputs,
        },
        "helper": {
            "function": "silent_witness_helper.main",
            "private_inputs": helper_inputs,
            "public_outputs": HELPER_OUTPUTS,
        },
        "public_input_order": [item["name"] for item in public_inputs],
        "encodings": {
            "credential_root": "pedersen([credential_secret])",
            "nullifier": (
                "pedersen([credential_secret, nullifier_secret, "
                "pedersen([SHA256_ID, video_hash_hi, video_hash_lo, "
                "pedersen([SCOPED_NULLIFIER_V1, verifier_scope, epoch])])])"
            ),
            "domain_tag": "harpocrates_common::expected_domain_tag()",
            "circuit_version": "CURRENT_CIRCUIT_VERSION as Field; value 2",
        },
        "reviewed_artifact_bindings": artifact_bindings,
        "source_bindings": source_bindings,
    }
    descriptor["descriptor_sha256"] = descriptor_digest(descriptor)
    return descriptor


def compare_descriptors(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    expected_digest = descriptor_digest(expected)
    actual_digest = actual.get("descriptor_sha256")
    if actual_digest != expected_digest:
        findings.append("descriptor digest is invalid")

    if expected != actual:
        expected_bindings = expected.get("reviewed_artifact_bindings")
        actual_bindings = actual.get("reviewed_artifact_bindings")
        if expected_bindings != actual_bindings:
            findings.append("reviewed artifact bindings drifted")
        if expected.get("main") != actual.get("main"):
            findings.append("main public/private input list drifted")
        if expected.get("helper") != actual.get("helper"):
            findings.append("helper input/output list drifted")
        if not findings:
            findings.append("descriptor differs from generated circuit statement")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("write", "check"), nargs="?", default="check"
    )
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--descriptor", type=Path, default=None)
    args = parser.parse_args(argv)
    descriptor_path = args.descriptor or (
        args.repo_root
        / "zk"
        / "noir"
        / "fixtures"
        / "scoped_nullifier_statement_descriptor_v1.json"
    )
    try:
        expected = build_descriptor(args.repo_root)
        if args.command == "write":
            descriptor_path.write_text(
                json.dumps(expected, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return 0
        actual = _read_json(descriptor_path, "statement descriptor")
        findings = compare_descriptors(expected, actual)
    except (OSError, DescriptorError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if findings:
        print("; ".join(findings), file=sys.stderr)
        return 1
    print(f"statement descriptor verified: {expected['descriptor_sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())