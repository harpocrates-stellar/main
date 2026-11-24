#!/usr/bin/env python3
"""Report and enforce reviewed public-input compatibility across Noir circuits."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
STATEMENT_DESCRIPTOR = "zk/noir/fixtures/scoped_nullifier_statement_descriptor_v1.json"
INPUT_SCHEMA = "zk/noir/circuit_input_schema_v1.json"
VECTOR_DIRECTORY = "zk/vectors"
VECTOR_FILENAME = re.compile(r"verifier_conformance_v\d+\.json$")

CIRCUITS: dict[str, dict[str, Any]] = {
    "silent_witness": {
        "public_inputs": [
            "video_hash_hi",
            "video_hash_lo",
            "credential_root",
            "nullifier",
            "verifier_scope",
            "epoch",
            "domain_tag",
            "circuit_version",
        ],
        "encodings": {
            "video_hash_hi": "unsigned high 128 bits of SHA-256 digest",
            "video_hash_lo": "unsigned low 128 bits of SHA-256 digest",
            "credential_root": "pedersen([credential_secret])",
            "nullifier": (
                "pedersen([credential_secret, nullifier_secret, "
                "pedersen([SHA256_ID, video_hash_hi, video_hash_lo, "
                "pedersen([SCOPED_NULLIFIER_V1, verifier_scope, epoch])])])"
            ),
            "domain_tag": (
                "pedersen([DOMAIN_PROTOCOL_FIELD, DOMAIN_VERSION_FIELD, "
                "DOMAIN_NETWORK_FIELD])"
            ),
            "circuit_version": "u32 circuit version promoted to Field; value 2",
        },
    },
    "redacted_ancestry": {
        "public_inputs": [
            "parent_commitment",
            "derivative_digest",
            "parameters_digest",
            "operation_type",
            "ancestry_root",
            "nullifier",
            "depth",
            "domain_tag",
        ],
        "encodings": {
            "nullifier": (
                "pedersen([DOMAIN_NULLIFIER, credential_secret, "
                "nullifier_secret, ancestry_root])"
            ),
            "domain_tag": (
                "pedersen([DOMAIN_PROTOCOL_FIELD, DOMAIN_VERSION_FIELD, "
                "DOMAIN_NETWORK_FIELD])"
            ),
        },
    },
    "selective_disclosure": {
        "public_inputs": [
            "schema_hash",
            "issuer_namespace",
            "schema_version",
            "credential_root",
            "nullifier",
            "video_hash_hi",
            "video_hash_lo",
            "verifier_digest",
            "circuit_version",
            "evidence_digest",
            "predicate_commitment",
        ],
        "encodings": {
            "credential_root": "Pedersen chain of attribute Pedersen commitments",
            "nullifier": (
                "pedersen([credential_root, video_hash_hi, video_hash_lo, "
                "evidence_digest])"
            ),
            "video_hash_hi": "unsigned high 128 bits of SHA-256 digest",
            "video_hash_lo": "unsigned low 128 bits of SHA-256 digest",
            "circuit_version": "u32 circuit version promoted to Field; value 1",
        },
    },
}

# An entry is reviewed only when the complete circuit-to-encoding mapping is
# unchanged. Adding a circuit or changing one encoding requires updating this.
REVIEWED_DIFFERENCES: dict[str, dict[str, str]] = {
    "credential_root": {
        "silent_witness": "pedersen([credential_secret])",
        "selective_disclosure": (
            "Pedersen chain of attribute Pedersen commitments"
        ),
    },
    "nullifier": {
        "silent_witness": (
            "pedersen([credential_secret, nullifier_secret, "
            "pedersen([SHA256_ID, video_hash_hi, video_hash_lo, "
            "pedersen([SCOPED_NULLIFIER_V1, verifier_scope, epoch])])])"
        ),
        "redacted_ancestry": (
            "pedersen([DOMAIN_NULLIFIER, credential_secret, "
            "nullifier_secret, ancestry_root])"
        ),
        "selective_disclosure": (
            "pedersen([credential_root, video_hash_hi, video_hash_lo, "
            "evidence_digest])"
        ),
    },
    "circuit_version": {
        "silent_witness": (
            "u32 circuit version promoted to Field; value 2"
        ),
        "selective_disclosure": (
            "u32 circuit version promoted to Field; value 1"
        ),
    },
}


def _main_parameters(source: str) -> list[tuple[str, bool, str]]:
    match = re.search(r"\bfn\s+main\s*\(", source)
    if not match:
        raise ValueError("main function signature not found")

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
        raise ValueError("unterminated main function signature")

    signature = source[start : end - 1]
    parameters: list[str] = []
    segment_start = 0
    nesting: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for index, character in enumerate(signature):
        if character in "([{":
            nesting.append(character)
        elif character in ")]}":
            if nesting and nesting[-1] == pairs[character]:
                nesting.pop()
        elif character == "," and not nesting:
            parameters.append(signature[segment_start:index])
            segment_start = index + 1
    parameters.append(signature[segment_start:])

    parsed: list[tuple[str, bool, str]] = []
    for parameter in parameters:
        parameter = re.sub(r"//.*", "", parameter).strip()
        if not parameter:
            continue
        match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(pub\s+)?", parameter)
        if not match:
            raise ValueError(f"unrecognized main parameter: {parameter}")
        parsed.append(
            (
                match.group(1),
                match.group(2) is not None,
                parameter[match.end() :].strip(),
            )
        )
    return parsed


def build_report(
    repo_root: Path = REPO_ROOT,
    circuit_specs: dict[str, dict[str, Any]] = CIRCUITS,
    reviewed_differences: dict[str, dict[str, str]] = REVIEWED_DIFFERENCES,
    base_ref: str | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    circuits: dict[str, Any] = {}

    for circuit, spec in circuit_specs.items():
        source_path = repo_root / "zk" / "noir" / circuit / "src" / "main.nr"
        try:
            parameters = _main_parameters(source_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append(f"{circuit}: cannot read public-input signature: {exc}")
            continue

        public_parameters = [parameter for parameter in parameters if parameter[1]]
        actual_public_inputs = [name for name, _, _ in public_parameters]
        expected_public_inputs = spec["public_inputs"]
        if actual_public_inputs != expected_public_inputs:
            errors.append(
                f"{circuit}: public-input order drift; expected {expected_public_inputs}, "
                f"found {actual_public_inputs}"
            )
        for name, _, field_type in public_parameters:
            if field_type != "Field":
                errors.append(
                    f"{circuit}.{name}: expected public type Field, found {field_type}"
                )

        unknown_encodings = set(spec["encodings"]) - set(actual_public_inputs)
        for field in sorted(unknown_encodings):
            errors.append(f"{circuit}.{field}: encoding declared for a non-public input")
        circuits[circuit] = {
            "publicInputs": [
                {"name": name, "type": field_type}
                for name, _, field_type in public_parameters
            ]
        }

    fields = sorted(
        {
            field
            for spec in circuit_specs.values()
            for field in spec["public_inputs"]
        }
    )
    shared_encodings: list[dict[str, Any]] = []
    for field in fields:
        encodings = {
            circuit: spec["encodings"][field]
            for circuit, spec in circuit_specs.items()
            if field in spec["public_inputs"] and field in spec["encodings"]
        }
        participating = [
            circuit for circuit, spec in circuit_specs.items() if field in spec["public_inputs"]
        ]
        missing = sorted(set(participating) - set(encodings))
        if len(participating) < 2:
            continue
        if missing:
            errors.append(f"{field}: missing encoding declarations for {', '.join(missing)}")
            continue

        differs = len(set(encodings.values())) > 1
        reviewed = reviewed_differences.get(field)
        if differs and reviewed != encodings:
            errors.append(
                f"{field}: unreviewed encoding difference {encodings}"
            )
        elif not differs and reviewed is not None:
            errors.append(f"{field}: stale reviewed difference {reviewed}")
        shared_encodings.append(
            {
                "field": field,
                "encodings": encodings,
                "status": "reviewed-difference" if differs else "identical",
            }
        )

    for field in reviewed_differences:
        if not any(
            item["field"] == field for item in shared_encodings
        ):
            errors.append(f"{field}: reviewed difference is no longer shared")

    layout_findings = check_reviewed_layouts(repo_root, base_ref)
    errors.extend(layout_findings)

    return {
        "format": "harpocrates.public-input-compatibility",
        "version": 1,
        "circuits": circuits,
        "sharedEncodings": shared_encodings,
        "layoutCompatibility": {
            "baseRef": base_ref,
            "status": "compatible" if not layout_findings else "incompatible",
            "errors": layout_findings,
        },
        "errors": errors,
    }


def compare_layout_snapshots(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Require each breaking layout to use a new circuit version.

    Versioned schemas are immutable: a breaking change adds a new schema while
    keeping each previously reviewed vector schema intact.
    """
    errors: list[str] = []
    old_layouts = before["layouts"]
    new_layouts = after["layouts"]

    for schema_id, old_fields in sorted(old_layouts.items()):
        new_fields = new_layouts.get(schema_id)
        if new_fields is None:
            errors.append(f"{schema_id}: reviewed vector schema was removed")
        elif new_fields != old_fields:
            errors.append(f"{schema_id}: reviewed vector schema changed in place")

    old_version = before["circuit_version"]
    new_version = after["circuit_version"]
    if after["current_layout"] != before["current_layout"] and new_version <= old_version:
        errors.append(
            "breaking silent_witness public-input layout change requires "
            f"a circuit version greater than {old_version}"
        )
    if new_version < old_version:
        errors.append(
            f"circuit version downgrade: {old_version} -> {new_version}"
        )
    return errors


def compare_circuit_interfaces(
    before: dict[str, Any], after: dict[str, Any]
) -> list[str]:
    """Require a circuit-version increase when a Noir public signature changes."""
    errors: list[str] = []
    for circuit in sorted(set(before["layouts"]) | set(after["layouts"])):
        old_layout = before["layouts"].get(circuit)
        new_layout = after["layouts"].get(circuit)
        old_version = before["versions"].get(circuit)
        new_version = after["versions"].get(circuit)
        if old_layout is None or new_layout is None or old_version is None or new_version is None:
            errors.append(f"{circuit}: circuit interface or version is missing from one revision")
            continue
        if new_version < old_version:
            errors.append(f"{circuit}: circuit version downgrade {old_version} -> {new_version}")
        if new_layout != old_layout and new_version <= old_version:
            errors.append(
                f"{circuit}: public-input layout changed without increasing "
                f"the circuit version above {old_version}"
            )
    return errors


def _snapshot_from_documents(
    statement: dict[str, Any],
    input_schema: dict[str, Any],
    vectors: list[dict[str, Any]],
    circuit_version: int,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    layouts: dict[str, list[str]] = {}

    for document in vectors:
        schemas = document.get("schemas")
        if not isinstance(schemas, dict):
            errors.append("conformance vector schema map is missing")
            continue
        document_versions: set[int] = set()
        for schema_id, fields in schemas.items():
            if not isinstance(schema_id, str) or not isinstance(fields, list) or not all(
                isinstance(field, str) for field in fields
            ):
                errors.append("conformance vector schema entry is malformed")
                continue
            schema_version = re.fullmatch(r"silent_witness/v(\d+)", schema_id)
            if schema_version is not None:
                document_versions.add(int(schema_version.group(1)))
            if schema_id in layouts and layouts[schema_id] != fields:
                errors.append(f"{schema_id}: conflicting reviewed vector schemas")
            layouts[schema_id] = fields
        constants = document.get("constants", {})
        if not isinstance(constants, dict):
            errors.append("conformance vector constants are malformed")
            constants = {}
        vector_version = constants.get("expected_circuit_version")
        if vector_version is not None and (
            not document_versions or vector_version != max(document_versions)
        ):
            errors.append("conformance vector version does not match its schema")

    public_frames = input_schema.get("public_frames")
    if not isinstance(public_frames, dict):
        errors.append("input schema public_frames map is missing")
        public_frames = {}
    for frame_name, fields in public_frames.items():
        match = re.fullmatch(r"(?:unscoped|scoped)_v(\d+)", frame_name)
        if not match:
            continue
        schema_id = f"silent_witness/v{match.group(1)}"
        if layouts.get(schema_id) != fields:
            errors.append(
                f"{frame_name}: input schema frame does not match {schema_id} vectors"
            )

    descriptor_id = statement.get("id")
    descriptor_match = (
        re.fullmatch(r"silent_witness/scoped-v(\d+)", descriptor_id)
        if isinstance(descriptor_id, str)
        else None
    )
    if descriptor_match is None:
        errors.append("statement descriptor has no versioned Silent Witness id")
        descriptor_version = -1
    else:
        descriptor_version = int(descriptor_match.group(1))

    main = statement.get("main")
    public_inputs = main.get("public_inputs") if isinstance(main, dict) else None
    if not isinstance(public_inputs, list):
        errors.append("statement descriptor main public inputs are missing")
        public_inputs = []
    descriptor_fields = [
        item.get("name")
        for item in public_inputs
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    ]
    if len(descriptor_fields) != len(public_inputs):
        errors.append("statement descriptor public-input entries are malformed")

    declared_order = statement.get("public_input_order")
    if declared_order != descriptor_fields:
        errors.append("statement descriptor public-input order is inconsistent")

    current_schema_id = f"silent_witness/v{descriptor_version}"
    if descriptor_version < 1 or layouts.get(current_schema_id) != descriptor_fields:
        errors.append(
            f"statement descriptor does not match reviewed vectors for {current_schema_id}"
        )
    scoped_frame = public_frames.get(f"scoped_v{descriptor_version}")
    if scoped_frame != descriptor_fields:
        errors.append("statement descriptor does not match the scoped input-schema frame")

    vector_versions = {
        int(match.group(1))
        for schema_id in layouts
        if (match := re.fullmatch(r"silent_witness/v(\d+)", schema_id))
    }
    if not vector_versions or max(vector_versions) != circuit_version:
        errors.append(
            "current circuit version does not match the newest reviewed "
            "Silent Witness vector schema"
        )
    if descriptor_version != circuit_version:
        errors.append("statement descriptor version does not match the circuit version")

    artifact_abis = input_schema.get("artifact_abis", {})
    if not isinstance(artifact_abis, dict):
        errors.append("input schema artifact_abis map is missing")
        artifact_abis = {}
    abi = artifact_abis.get(f"scoped_v{circuit_version}", {})
    if not isinstance(abi, dict):
        errors.append("current scoped input schema ABI is malformed")
        abi = {}
    if abi.get("circuit_version") != circuit_version:
        errors.append("input schema ABI circuit version does not match the current circuit")

    return (
        {
            "layouts": layouts,
            "current_layout": descriptor_fields,
            "circuit_version": circuit_version,
        },
        errors,
    )


def _git_text(repo_root: Path, revision: str, path: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{revision}:{path}"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode:
        raise ValueError(f"cannot read {path} at base ref {revision}")
    return result.stdout


def _git_vector_paths(repo_root: Path, revision: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", revision, "--", VECTOR_DIRECTORY],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode:
        raise ValueError(f"cannot list reviewed vectors at base ref {revision}")
    return [
        path
        for path in result.stdout.splitlines()
        if path.startswith(f"{VECTOR_DIRECTORY}/")
        and VECTOR_FILENAME.fullmatch(Path(path).name)
    ]


def _parse_circuit_version(source: str) -> int:
    match = re.search(
        r"\bglobal\s+CURRENT_CIRCUIT_VERSION\s*:\s*u32\s*=\s*(\d+)\s*;",
        source,
    )
    if match is None:
        raise ValueError("CURRENT_CIRCUIT_VERSION declaration not found")
    return int(match.group(1))


def _circuit_version_for(circuit: str, source: str) -> int:
    constant = "CIRCUIT_VERSION" if circuit == "redacted_ancestry" else "CURRENT_CIRCUIT_VERSION"
    match = re.search(
        rf"\bglobal\s+{constant}\s*:\s*(?:u32|Field)\s*=\s*(\d+)\s*;",
        source,
    )
    if match is None:
        raise ValueError(f"{circuit}: {constant} declaration not found")
    return int(match.group(1))


def _load_circuit_interfaces(
    repo_root: Path, base_ref: str | None = None
) -> tuple[dict[str, Any], list[str]]:
    layouts: dict[str, list[dict[str, str]]] = {}
    versions: dict[str, int] = {}
    errors: list[str] = []
    for circuit in CIRCUITS:
        path = f"zk/noir/{circuit}/src/main.nr"
        try:
            source = (
                _git_text(repo_root, base_ref, path)
                if base_ref is not None
                else (repo_root / path).read_text(encoding="utf-8")
            )
            parameters = _main_parameters(source)
            layouts[circuit] = [
                {"name": name, "type": field_type}
                for name, is_public, field_type in parameters
                if is_public
            ]
            versions[circuit] = _circuit_version_for(circuit, source)
        except (OSError, ValueError) as exc:
            errors.append(f"{circuit}: cannot read circuit interface: {exc}")
    return {"layouts": layouts, "versions": versions}, errors


def _read_json_text(text: str, label: str) -> dict[str, Any]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is invalid JSON") from exc
    if not isinstance(document, dict):
        raise ValueError(f"{label} must be a JSON object")
    return document


def _load_current_layout_snapshot(repo_root: Path) -> tuple[dict[str, Any], list[str]]:
    statement = _read_json_text(
        (repo_root / STATEMENT_DESCRIPTOR).read_text(encoding="utf-8"),
        "statement descriptor",
    )
    input_schema = _read_json_text(
        (repo_root / INPUT_SCHEMA).read_text(encoding="utf-8"),
        "circuit input schema",
    )
    vector_paths = sorted(
        path
        for path in (repo_root / VECTOR_DIRECTORY).glob("verifier_conformance_v*.json")
        if VECTOR_FILENAME.fullmatch(path.name)
    )
    if not vector_paths:
        raise ValueError("no reviewed verifier conformance vectors found")
    vectors = [
        _read_json_text(path.read_text(encoding="utf-8"), "conformance vectors")
        for path in vector_paths
    ]
    source = (
        repo_root / "zk/noir/silent_witness/src/main.nr"
    ).read_text(encoding="utf-8")
    snapshot, errors = _snapshot_from_documents(
        statement,
        input_schema,
        vectors,
        _parse_circuit_version(source),
    )
    errors.extend(_validate_statement_descriptor(repo_root, statement))

    return snapshot, errors


def _validate_statement_descriptor(
    repo_root: Path, statement: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    try:
        source = (
            repo_root / "zk/noir/silent_witness/src/main.nr"
        ).read_text(encoding="utf-8")
        actual_parameters = _main_parameters(source)
    except (OSError, ValueError) as exc:
        return [f"cannot read Silent Witness public-input signature: {exc}"]

    actual_public = [
        {"name": name, "type": field_type, "visibility": "public"}
        for name, is_public, field_type in actual_parameters
        if is_public
    ]
    main = statement.get("main")
    described_public = main.get("public_inputs") if isinstance(main, dict) else None
    if described_public != actual_public:
        errors.append("statement descriptor public inputs differ from circuit source")

    payload = {
        key: value for key, value in statement.items() if key != "descriptor_sha256"
    }
    digest = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    if statement.get("descriptor_sha256") != digest:
        errors.append("statement descriptor digest is invalid")
    return errors


def _load_base_layout_snapshot(
    repo_root: Path, base_ref: str
) -> tuple[dict[str, Any], list[str]]:
    statement = _read_json_text(
        _git_text(repo_root, base_ref, STATEMENT_DESCRIPTOR),
        "base statement descriptor",
    )
    input_schema = _read_json_text(
        _git_text(repo_root, base_ref, INPUT_SCHEMA),
        "base circuit input schema",
    )
    paths = _git_vector_paths(repo_root, base_ref)
    if not paths:
        raise ValueError(f"no reviewed verifier conformance vectors at base ref {base_ref}")
    vectors = [
        _read_json_text(_git_text(repo_root, base_ref, path), "base conformance vectors")
        for path in paths
    ]
    source = _git_text(repo_root, base_ref, "zk/noir/silent_witness/src/main.nr")
    return _snapshot_from_documents(
        statement,
        input_schema,
        vectors,
        _parse_circuit_version(source),
    )


def check_reviewed_layouts(repo_root: Path, base_ref: str | None = None) -> list[str]:
    """Validate reviewed descriptors and vectors, optionally against a Git base."""
    try:
        current, current_errors = _load_current_layout_snapshot(repo_root)
        errors = list(current_errors)
        current_interfaces, interface_errors = _load_circuit_interfaces(repo_root)
        errors.extend(interface_errors)
        if base_ref is not None:
            before, before_errors = _load_base_layout_snapshot(repo_root, base_ref)
            errors.extend(f"base: {error}" for error in before_errors)
            errors.extend(compare_layout_snapshots(before, current))
            before_interfaces, before_interface_errors = _load_circuit_interfaces(
                repo_root, base_ref
            )
            errors.extend(f"base: {error}" for error in before_interface_errors)
            errors.extend(
                compare_circuit_interfaces(before_interfaces, current_interfaces)
            )
        return errors
    except (OSError, ValueError) as exc:
        return [f"public-input layout gate could not verify reviewed inputs: {exc}"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument(
        "--base-ref",
        default=None,
        help="Git revision to compare reviewed layouts against (used by CI).",
    )
    args = parser.parse_args(argv)
    report = build_report(args.repo_root, base_ref=args.base_ref)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not report["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())