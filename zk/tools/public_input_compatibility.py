#!/usr/bin/env python3
"""Report and enforce reviewed public-input compatibility across Noir circuits."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

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

    return {
        "format": "harpocrates.public-input-compatibility",
        "version": 1,
        "circuits": circuits,
        "sharedEncodings": shared_encodings,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)
    report = build_report(args.repo_root)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not report["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())