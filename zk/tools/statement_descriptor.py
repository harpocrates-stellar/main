#!/usr/bin/env python3
"""Scoped-nullifier statement descriptor generator and verifier for Silent Witness.

Extracts the canonical public and private input lists from the reviewed Noir
circuit packages (`silent_witness`, `silent_witness_helper`, and
`harpocrates_common`), cross-checks them against `circuit_input_schema_v1.json`,
and cryptographically binds the resulting `descriptor_sha256` digest to the
reviewed circuit sources, toolchain lock policy, and published ACIR artifacts.

Subcommands:
    write   Generate and write `zk/scoped_nullifier.statement.json` (LF UTF-8).
    verify  Recompute from the workspace and fail closed on input or artifact drift.
    print   Emit the generated JSON descriptor to stdout without writing disk.

Privacy invariant:
    Signals on stderr report only repo-relative paths, parameter names, counts,
    and SHA-256 digests — never source contents or witness material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

DESCRIPTOR_FORMAT = "harpocrates.zk-statement-descriptor"
DESCRIPTOR_VERSION = 1
STATEMENT_ID = "silent_witness/scoped_nullifier_v1"

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DESCRIPTOR_PATH = REPO_ROOT / "zk" / "scoped_nullifier.statement.json"

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_USAGE = 2
EXIT_FATAL = 3

REVIEWED_SOURCE_PATHS: tuple[str, ...] = (
    "zk/noir/harpocrates_common/Nargo.toml",
    "zk/noir/harpocrates_common/src/lib.nr",
    "zk/noir/silent_witness/Nargo.toml",
    "zk/noir/silent_witness/src/main.nr",
    "zk/noir/silent_witness_helper/Nargo.toml",
    "zk/noir/silent_witness_helper/src/main.nr",
    "zk/noir/circuit_input_schema_v1.json",
)

SCOPED_TARGET_ARTIFACT_PATHS: tuple[str, ...] = (
    "zk/noir/silent_witness/target/silent_witness.json",
    "zk/noir/silent_witness/target/vk",
    "zk/noir/silent_witness/target/vk_fields.json",
    "zk/noir/silent_witness_helper/target/silent_witness_helper.json",
)

SCOPED_BROWSER_ARTIFACT_PATHS: tuple[str, ...] = (
    "frontend/public/noir/silent_witness.json",
    "frontend/public/noir/silent_witness_helper.json",
)

_PRIVATE_ROLES: dict[str, str] = {
    "credential_secret": "identity_preimage",
    "nullifier_secret": "nullifier_blinding_secret",
}

_PUBLIC_ROLES: dict[str, str] = {
    "video_hash_hi": "evidence_sha256_hi_128",
    "video_hash_lo": "evidence_sha256_lo_128",
    "credential_root": "credential_commitment",
    "nullifier": "scoped_nullifier",
    "verifier_scope": "verifier_scope_field",
    "epoch": "scope_epoch",
    "domain_tag": "protocol_domain_tag",
    "circuit_version": "committed_circuit_version",
}

_HELPER_OUTPUT_NAMES: tuple[str, ...] = (
    "credential_root",
    "nullifier",
    "domain_tag",
)

_MAIN_FN_RE = re.compile(
    r"fn\s+main\s*\((?P<params>[^)]*)\)\s*(?:->\s*(?P<ret>[^{]+))?\{",
    re.MULTILINE | re.DOTALL,
)
_PARAM_RE = re.compile(
    r"\A(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<pub>pub\s+)?(?P<type>[A-Za-z0-9_]+)\Z"
)
_RETURN_TUPLE_RE = re.compile(r"\Apub\s*\((?P<fields>[^)]+)\)\Z")
_CIRCUIT_VERSION_RE = re.compile(
    r"global\s+CURRENT_CIRCUIT_VERSION\s*:\s*u32\s*=\s*(?P<ver>\d+)\s*;"
)
_GLOBAL_FIELD_RE = re.compile(
    r"(?:pub\s+)?global\s+(?P<name>[A-Z0-9_]+)\s*:\s*Field\s*=\s*(?P<val>0x[0-9a-fA-F]+|\d+)\s*;"
)


class DescriptorError(RuntimeError):
    """Privacy-safe error raised when circuit sources or artifacts fail validation."""

    def __init__(self, code: str, detail: str, *, exit_code: int = EXIT_FATAL) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.exit_code = exit_code


def signal(event: str, **fields: Any) -> None:
    """Emit a deterministic privacy-safe JSON event on stderr."""
    payload = {"event": event, **fields}
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), file=sys.stderr)


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize `value` into canonical sorted UTF-8 JSON bytes without whitespace."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strip_volatile_keys(value: Any, volatile_keys: frozenset[str]) -> Any:
    if isinstance(value, dict):
        return {
            key: strip_volatile_keys(item, volatile_keys)
            for key, item in value.items()
            if key not in volatile_keys
        }
    if isinstance(value, list):
        return [strip_volatile_keys(item, volatile_keys) for item in value]
    return value


def digest_lf_normalized_file(path: Path, *, rel_path: str) -> dict[str, Any]:
    """Hash a reviewed text source after normalizing CRLF -> LF for cross-OS parity."""
    if not path.is_file():
        raise DescriptorError("missing_source", f"missing reviewed source {rel_path}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DescriptorError(
            "unreadable_source",
            f"unreadable reviewed source {rel_path}",
        ) from exc
    lf_bytes = raw.replace(b"\r\n", b"\n")
    return {
        "lf_bytes": len(lf_bytes),
        "lf_sha256": sha256_hex(lf_bytes),
        "path": rel_path,
    }


def _strip_noir_line_comments(source: str) -> str:
    cleaned_lines: list[str] = []
    for line in source.splitlines():
        comment_idx = line.find("//")
        cleaned_lines.append(line if comment_idx == -1 else line[:comment_idx])
    return "\n".join(cleaned_lines)


def parse_noir_main_signature(
    source_text: str,
    *,
    rel_path: str,
) -> tuple[list[dict[str, str]], list[str]]:
    """Extract parameter declarations and public return tuple types from Noir `fn main`."""
    cleaned = _strip_noir_line_comments(source_text)
    match = _MAIN_FN_RE.search(cleaned)
    if match is None:
        raise DescriptorError(
            "missing_entrypoint",
            f"no fn main(...) entrypoint found in {rel_path}",
        )

    raw_params = match.group("params")
    params: list[dict[str, str]] = []
    seen_names: set[str] = set()
    for piece in raw_params.split(","):
        token = " ".join(piece.strip().split())
        if not token:
            continue
        param_match = _PARAM_RE.match(token)
        if param_match is None:
            raise DescriptorError(
                "malformed_parameter",
                f"unrecognized parameter syntax in {rel_path}",
            )
        name = param_match.group("name")
        if name in seen_names:
            raise DescriptorError(
                "duplicate_parameter",
                f"duplicate parameter '{name}' in {rel_path}",
            )
        seen_names.add(name)
        visibility = "public" if param_match.group("pub") else "private"
        noir_type = param_match.group("type")
        params.append(
            {
                "name": name,
                "noir_type": noir_type,
                "visibility": visibility,
            }
        )

    raw_ret = (match.group("ret") or "").strip()
    return_types: list[str] = []
    if raw_ret:
        ret_match = _RETURN_TUPLE_RE.match(" ".join(raw_ret.split()))
        if ret_match is None:
            raise DescriptorError(
                "unsupported_return_type",
                f"unsupported return signature in {rel_path}",
            )
        return_types = [
            part.strip() for part in ret_match.group("fields").split(",") if part.strip()
        ]

    return params, return_types


def parse_noir_globals(source_text: str) -> dict[str, str]:
    cleaned = _strip_noir_line_comments(source_text)
    constants: dict[str, str] = {}
    for match in _GLOBAL_FIELD_RE.finditer(cleaned):
        constants[match.group("name")] = match.group("val")
    return constants


def parse_circuit_version(source_text: str, *, rel_path: str) -> int:
    cleaned = _strip_noir_line_comments(source_text)
    match = _CIRCUIT_VERSION_RE.search(cleaned)
    if match is None:
        raise DescriptorError(
            "missing_circuit_version",
            f"CURRENT_CIRCUIT_VERSION not declared in {rel_path}",
        )
    return int(match.group("ver"), 10)


def _load_json_file(path: Path, *, rel_path: str) -> dict[str, Any]:
    if not path.is_file():
        raise DescriptorError("missing_manifest", f"missing required JSON file {rel_path}")
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DescriptorError(
            "invalid_json",
            f"unable to parse JSON file {rel_path}",
        ) from exc
    if not isinstance(parsed, dict):
        raise DescriptorError("invalid_json", f"JSON root must be an object in {rel_path}")
    return parsed


def compute_descriptor_sha256(descriptor_without_digest: Mapping[str, Any]) -> str:
    body = {
        key: val
        for key, val in descriptor_without_digest.items()
        if key != "descriptor_sha256"
    }
    return sha256_hex(canonical_json_bytes(body))


def build_statement_descriptor(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Generate the machine-readable scoped-nullifier statement descriptor."""
    common_rel = "zk/noir/harpocrates_common/src/lib.nr"
    main_rel = "zk/noir/silent_witness/src/main.nr"
    helper_rel = "zk/noir/silent_witness_helper/src/main.nr"
    schema_rel = "zk/noir/circuit_input_schema_v1.json"
    lock_rel = "zk/toolchain.lock.json"
    browser_manifest_rel = "zk/browser.artifacts.manifest.json"

    for rel in (common_rel, main_rel, helper_rel):
        if not (repo_root / rel).is_file():
            raise DescriptorError("missing_source", f"missing reviewed source {rel}")

    common_text = (repo_root / common_rel).read_text(encoding="utf-8")
    main_text = (repo_root / main_rel).read_text(encoding="utf-8")
    helper_text = (repo_root / helper_rel).read_text(encoding="utf-8")
    schema = _load_json_file(repo_root / schema_rel, rel_path=schema_rel)
    lock = _load_json_file(repo_root / lock_rel, rel_path=lock_rel)
    browser_manifest = _load_json_file(
        repo_root / browser_manifest_rel, rel_path=browser_manifest_rel
    )

    main_params, main_returns = parse_noir_main_signature(main_text, rel_path=main_rel)
    if main_returns:
        raise DescriptorError(
            "unexpected_main_return",
            f"{main_rel} must not declare a return tuple",
        )
    circuit_version = parse_circuit_version(main_text, rel_path=main_rel)

    helper_params, helper_returns = parse_noir_main_signature(
        helper_text, rel_path=helper_rel
    )

    scoped_abi = schema.get("artifact_abis", {}).get("scoped_v2")
    scoped_frame = schema.get("public_frames", {}).get("scoped_v2")
    if not isinstance(scoped_abi, Mapping) or not isinstance(scoped_frame, list):
        raise DescriptorError(
            "invalid_input_schema",
            "circuit_input_schema_v1.json missing scoped_v2 ABI or public frame",
        )

    expected_main_names = list(scoped_abi.get("main_parameters", []))
    actual_main_names = [param["name"] for param in main_params]
    if actual_main_names != expected_main_names:
        raise DescriptorError(
            "signature_schema_mismatch",
            f"{main_rel} parameter order {actual_main_names} != schema {expected_main_names}",
        )

    # Verify private parameters strictly precede public parameters and match scoped_v2 frame.
    seen_public = False
    private_inputs: list[dict[str, Any]] = []
    public_inputs: list[dict[str, Any]] = []
    for abi_idx, param in enumerate(main_params):
        if param["noir_type"] != "Field":
            raise DescriptorError(
                "unsupported_parameter_type",
                f"parameter '{param['name']}' in {main_rel} must have type Field",
            )
        if param["visibility"] == "private":
            if seen_public:
                raise DescriptorError(
                    "interleaved_visibility",
                    f"private parameter '{param['name']}' appears after public parameters",
                )
            private_inputs.append(
                {
                    "abi_index": abi_idx,
                    "canonical_encoding": "bn254_scalar_field",
                    "name": param["name"],
                    "noir_type": param["noir_type"],
                    "role": _PRIVATE_ROLES.get(param["name"], "private_witness"),
                    "visibility": "private",
                }
            )
        else:
            seen_public = True
            pub_idx = len(public_inputs)
            public_inputs.append(
                {
                    "abi_index": abi_idx,
                    "canonical_encoding": "bn254_be_32_bytes",
                    "name": param["name"],
                    "noir_type": param["noir_type"],
                    "public_index": pub_idx,
                    "role": _PUBLIC_ROLES.get(param["name"], "public_statement_field"),
                    "visibility": "public",
                    "wire_byte_length": 32,
                    "wire_byte_offset": pub_idx * 32,
                }
            )

    actual_public_names = [entry["name"] for entry in public_inputs]
    if actual_public_names != scoped_frame:
        raise DescriptorError(
            "signature_schema_mismatch",
            f"{main_rel} public inputs {actual_public_names} != scoped_v2 frame {scoped_frame}",
        )

    if scoped_abi.get("circuit_version") != circuit_version:
        raise DescriptorError(
            "circuit_version_mismatch",
            f"CURRENT_CIRCUIT_VERSION={circuit_version} != schema {scoped_abi.get('circuit_version')}",
        )

    expected_helper_names = list(scoped_abi.get("helper_parameters", []))
    actual_helper_names = [param["name"] for param in helper_params]
    if actual_helper_names != expected_helper_names:
        raise DescriptorError(
            "signature_schema_mismatch",
            f"{helper_rel} parameters {actual_helper_names} != schema {expected_helper_names}",
        )
    if any(param["visibility"] != "private" for param in helper_params):
        raise DescriptorError(
            "unexpected_helper_visibility",
            f"{helper_rel} inputs must all be private",
        )
    expected_helper_returns = int(scoped_abi.get("helper_return_fields", 0))
    if len(helper_returns) != expected_helper_returns or any(
        ret_type != "Field" for ret_type in helper_returns
    ):
        raise DescriptorError(
            "signature_schema_mismatch",
            f"{helper_rel} return tuple length {len(helper_returns)} != {expected_helper_returns}",
        )

    common_globals = parse_noir_globals(common_text)
    required_globals = (
        "DIGEST_ALGORITHM_SHA256",
        "SCOPED_NULLIFIER_V1",
        "DOMAIN_PROTOCOL_FIELD",
        "DOMAIN_VERSION_FIELD",
        "DOMAIN_NETWORK_FIELD",
    )
    for const_name in required_globals:
        if const_name not in common_globals:
            raise DescriptorError(
                "missing_domain_constant",
                f"constant {const_name} missing from {common_rel}",
            )

    # Digest reviewed sources (LF-normalized for cross-OS determinism).
    reviewed_sources = [
        digest_lf_normalized_file(repo_root / rel, rel_path=rel)
        for rel in REVIEWED_SOURCE_PATHS
    ]

    # Cross-check and bind reviewed published ACIR artifacts against browser manifest + disk.
    volatile_keys = frozenset(
        lock.get("normalization", {}).get("json", {}).get("volatile_keys", [])
    )
    policy_sha256 = sha256_hex(canonical_json_bytes(lock.get("normalization", {})))
    manifest_policy_sha = browser_manifest.get("normalization_policy_sha256")
    if manifest_policy_sha != policy_sha256:
        raise DescriptorError(
            "normalization_policy_drift",
            "browser.artifacts.manifest.json normalization_policy_sha256 disagrees with toolchain.lock.json",
        )

    manifest_by_path = {
        entry["path"]: entry
        for entry in browser_manifest.get("artifacts", [])
        if isinstance(entry, Mapping) and "path" in entry
    }
    reviewed_browser_artifacts: list[dict[str, Any]] = []
    for rel_art in SCOPED_BROWSER_ARTIFACT_PATHS:
        if rel_art not in manifest_by_path:
            raise DescriptorError(
                "missing_reviewed_artifact",
                f"{rel_art} missing from {browser_manifest_rel}",
            )
        art_file = repo_root / rel_art
        if not art_file.is_file():
            raise DescriptorError(
                "missing_reviewed_artifact",
                f"reviewed artifact file missing on disk: {rel_art}",
            )
        try:
            parsed_art = json.loads(art_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DescriptorError(
                "corrupt_reviewed_artifact",
                f"unable to parse JSON artifact {rel_art}",
            ) from exc
        norm_bytes = canonical_json_bytes(strip_volatile_keys(parsed_art, volatile_keys))
        norm_sha = sha256_hex(norm_bytes)
        pinned = manifest_by_path[rel_art]
        if norm_sha != pinned.get("normalized_sha256") or len(norm_bytes) != pinned.get(
            "normalized_bytes"
        ):
            raise DescriptorError(
                "reviewed_artifact_drift",
                f"on-disk artifact {rel_art} drifted from {browser_manifest_rel}",
            )
        reviewed_browser_artifacts.append(
            {
                "abi_profile": "browser_v1",
                "kind": str(pinned.get("kind", "json")),
                "normalized_bytes": len(norm_bytes),
                "normalized_sha256": norm_sha,
                "path": rel_art,
                "role": str(pinned.get("role", "published_acir")),
            }
        )

    lock_artifacts_by_path = {
        entry["path"]: entry
        for entry in lock.get("artifacts", [])
        if isinstance(entry, Mapping) and "path" in entry
    }
    declared_target_artifacts: list[dict[str, Any]] = []
    for target_rel in SCOPED_TARGET_ARTIFACT_PATHS:
        if target_rel not in lock_artifacts_by_path:
            raise DescriptorError(
                "unpinned_target_artifact",
                f"target artifact {target_rel} missing from {lock_rel}",
            )
        spec = lock_artifacts_by_path[target_rel]
        declared_target_artifacts.append(
            {
                "kind": str(spec["kind"]),
                "path": target_rel,
                "required_in_full_build": bool(spec["required"]),
                "role": str(spec["role"]),
            }
        )

    toolchain_raw = lock.get("toolchain", {})
    toolchain_binding = {
        "barretenberg": str(toolchain_raw.get("barretenberg", {}).get("version", "")),
        "nargo": str(toolchain_raw.get("nargo", {}).get("version", "")),
        "normalization_policy_sha256": policy_sha256,
        "oracle_hash": str(toolchain_raw.get("oracle_hash", "")),
        "proving_scheme": str(toolchain_raw.get("proving_scheme", "")),
    }

    binding_core = {
        "declared_target_artifacts": declared_target_artifacts,
        "reviewed_browser_artifacts": reviewed_browser_artifacts,
        "reviewed_sources": reviewed_sources,
        "toolchain": toolchain_binding,
    }
    artifact_binding_sha256 = sha256_hex(canonical_json_bytes(binding_core))

    helper_inputs = [
        {
            "abi_index": idx,
            "canonical_encoding": "bn254_scalar_field",
            "name": param["name"],
            "noir_type": param["noir_type"],
            "visibility": "private",
        }
        for idx, param in enumerate(helper_params)
    ]
    helper_outputs = [
        {
            "name": (
                _HELPER_OUTPUT_NAMES[idx]
                if idx < len(_HELPER_OUTPUT_NAMES)
                else f"output_{idx}"
            ),
            "noir_type": ret_type,
            "tuple_index": idx,
            "visibility": "public",
        }
        for idx, ret_type in enumerate(helper_returns)
    ]

    descriptor: dict[str, Any] = {
        "format": DESCRIPTOR_FORMAT,
        "version": DESCRIPTOR_VERSION,
        "statement_id": STATEMENT_ID,
        "circuit": "silent_witness",
        "helper_circuit": "silent_witness_helper",
        "circuit_version": circuit_version,
        "field_modulus": str(schema["field_modulus"]),
        "verifier_wire_frame": {
            "codec": "hpx-vi/2",
            "field_bytes": 32,
            "frame_id": "silent_witness/v2",
            "public_field_count": len(public_inputs),
            "total_bytes": len(public_inputs) * 32,
        },
        "domain_constants": {
            "digest_algorithm_sha256": common_globals["DIGEST_ALGORITHM_SHA256"],
            "domain_network_field": common_globals["DOMAIN_NETWORK_FIELD"],
            "domain_protocol_field": common_globals["DOMAIN_PROTOCOL_FIELD"],
            "domain_version_field": common_globals["DOMAIN_VERSION_FIELD"],
            "scoped_nullifier_v1": common_globals["SCOPED_NULLIFIER_V1"],
        },
        "private_inputs": private_inputs,
        "public_inputs": public_inputs,
        "helper_interface": {
            "inputs": helper_inputs,
            "public_outputs": helper_outputs,
        },
        "artifact_bindings": {
            "artifact_binding_sha256": artifact_binding_sha256,
            "declared_target_artifacts": declared_target_artifacts,
            "reviewed_browser_artifacts": reviewed_browser_artifacts,
            "reviewed_sources": reviewed_sources,
            "toolchain": toolchain_binding,
        },
    }
    descriptor["descriptor_sha256"] = compute_descriptor_sha256(descriptor)
    return descriptor


def serialize_descriptor(descriptor: Mapping[str, Any]) -> bytes:
    """Format descriptor as deterministic 2-space indented pure-LF UTF-8 JSON."""
    text = json.dumps(descriptor, indent=2, sort_keys=False, ensure_ascii=True) + "\n"
    return text.encode("utf-8")


def verify_statement_descriptor(
    descriptor_path: Path = DEFAULT_DESCRIPTOR_PATH,
    *,
    repo_root: Path = REPO_ROOT,
) -> list[str]:
    """Verify a committed statement descriptor against live reviewed sources & artifacts.

    Returns a list of privacy-safe drift finding strings (empty when valid).
    """
    if not descriptor_path.is_file():
        raise DescriptorError(
            "missing_descriptor",
            f"statement descriptor not found: {descriptor_path.name}",
        )
    try:
        committed = json.loads(descriptor_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DescriptorError(
            "invalid_descriptor_json",
            f"statement descriptor is not valid UTF-8 JSON: {descriptor_path.name}",
        ) from exc
    if not isinstance(committed, dict):
        raise DescriptorError(
            "invalid_descriptor_json",
            "statement descriptor root must be a JSON object",
        )

    findings: list[str] = []

    if committed.get("format") != DESCRIPTOR_FORMAT:
        findings.append("descriptor format identifier mismatch")
    if committed.get("version") != DESCRIPTOR_VERSION:
        findings.append("descriptor version mismatch")

    claimed_sha = committed.get("descriptor_sha256")
    recomputed_committed_sha = compute_descriptor_sha256(committed)
    if not isinstance(claimed_sha, str) or claimed_sha != recomputed_committed_sha:
        findings.append(
            f"descriptor_sha256 self-check failed: claimed={claimed_sha!r} computed={recomputed_committed_sha}"
        )

    expected = build_statement_descriptor(repo_root=repo_root)

    for section in (
        "statement_id",
        "circuit",
        "helper_circuit",
        "circuit_version",
        "field_modulus",
        "verifier_wire_frame",
        "domain_constants",
        "private_inputs",
        "public_inputs",
        "helper_interface",
    ):
        if committed.get(section) != expected.get(section):
            findings.append(f"statement section '{section}' drifted from reviewed circuit")

    committed_bindings = committed.get("artifact_bindings", {})
    expected_bindings = expected["artifact_bindings"]
    if committed_bindings != expected_bindings:
        findings.append(
            "artifact_bindings drifted from reviewed sources, lock policy, or published ACIR"
        )

    if committed.get("descriptor_sha256") != expected["descriptor_sha256"]:
        findings.append(
            f"descriptor_sha256 drifted: committed={committed.get('descriptor_sha256')} expected={expected['descriptor_sha256']}"
        )

    return findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate or verify the Silent Witness scoped-nullifier statement descriptor."
    )
    sub = parser.add_subparsers(dest="subcommand")

    p_write = sub.add_parser(
        "write",
        help="Generate and write zk/scoped_nullifier.statement.json",
    )
    p_write.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_DESCRIPTOR_PATH,
        help="Output path for statement descriptor JSON",
    )

    p_verify = sub.add_parser(
        "verify",
        help="Verify committed statement descriptor against reviewed circuit artifacts",
    )
    p_verify.add_argument(
        "--descriptor",
        type=Path,
        default=DEFAULT_DESCRIPTOR_PATH,
        help="Path to committed statement descriptor JSON",
    )

    sub.add_parser(
        "print",
        help="Print the generated statement descriptor JSON to stdout",
    )
    return parser


def main(argv: Sequence[str] | None = None, *, repo_root: Path = REPO_ROOT) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.subcommand:
        parser.print_help()
        return EXIT_USAGE

    try:
        if args.subcommand == "print":
            descriptor = build_statement_descriptor(repo_root=repo_root)
            sys.stdout.write(serialize_descriptor(descriptor).decode("utf-8"))
            return EXIT_OK

        if args.subcommand == "write":
            descriptor = build_statement_descriptor(repo_root=repo_root)
            payload = serialize_descriptor(descriptor)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(payload)
            signal(
                "statement.descriptor.written",
                artifact_binding_sha256=descriptor["artifact_bindings"][
                    "artifact_binding_sha256"
                ],
                descriptor_sha256=descriptor["descriptor_sha256"],
                private_inputs=len(descriptor["private_inputs"]),
                public_inputs=len(descriptor["public_inputs"]),
            )
            return EXIT_OK

        if args.subcommand == "verify":
            findings = verify_statement_descriptor(
                args.descriptor,
                repo_root=repo_root,
            )
            if findings:
                for item in findings:
                    signal("statement.drift", detail=item)
                signal("statement.verify.failed", findings=len(findings))
                return EXIT_DRIFT
            signal("statement.verify.ok")
            return EXIT_OK
    except DescriptorError as exc:
        signal("statement.error", code=exc.code, detail=exc.detail)
        return exc.exit_code

    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
