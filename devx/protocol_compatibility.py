#!/usr/bin/env python3
"""Bind API, CLI, circuit, and contract schema versions to one baseline.

A release bundle is only coherent when every layer agrees on the protocol
baseline recorded in ``release/compatibility-manifest.json``. This tool
recomputes the public interface identity of each layer directly from the
source tree and compares it with ``release/protocol-compatibility.json``:

* **api** — backend API version plus a digest of the generated OpenAPI schema.
* **cli** — CLI package version plus the proof-manifest version it emits.
* **circuit** — circuit version, input-schema version, and input-schema digest.
* **contract** — registry interface version, compatibility-descriptor version,
  accepted verifier-input versions, and the circuit version the verifier
  expects.

The check is offline and fail-closed: it reads only the checked-out tree, never
a production endpoint, credential, witness, or proof. A mixed-layer combination
is rejected before packaging or deployment.

Usage::

    python3 devx/protocol_compatibility.py --check
    python3 devx/protocol_compatibility.py --write   # reviewed baseline change

Exit codes:
  0  the recorded baseline matches the tree (or ``--write`` succeeded)
  1  an incompatible combination was found
  2  the manifest or an input could not be read
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from devx import _io, generate_api_schema

CIRCUIT_TOOLS = ROOT / "zk" / "tools"
if str(CIRCUIT_TOOLS) not in sys.path:
    sys.path.insert(0, str(CIRCUIT_TOOLS))

import circuit_input_version as circuit_version

FORMAT = "harpocrates.cross-layer-protocol-manifest"
REPORT_FORMAT = "harpocrates.cross-layer-protocol-report"
SCHEMA_VERSION = 1
DEFAULT_MANIFEST = ROOT / "release" / "protocol-compatibility.json"
DEFAULT_RELEASE_MANIFEST = ROOT / "release" / "compatibility-manifest.json"
MAX_MANIFEST_BYTES = 128 * 1024
MAX_SOURCE_BYTES = 8 * 1024 * 1024
LAYERS = ("api", "cli", "circuit", "contract")
HEX_256 = re.compile(r"^[0-9a-f]{64}$")
SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
U32_CONST = re.compile(r"pub const\s+([A-Z0-9_]+)\s*:\s*u32\s*=\s*([A-Za-z0-9_]+)\s*;")
CLI_MANIFEST_VERSION = re.compile(r"const\s+MANIFEST_VERSION\s*=\s*(\d+)")


class ProtocolManifestError(ValueError):
    pass


def canonical_json(value: Any) -> str:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    )


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def read_json_bounded(
    path: Path,
    limit: int = MAX_MANIFEST_BYTES,
    sensitive_pattern: Any = _io.DEFAULT_SENSITIVE_KEY_RE,
) -> dict[str, Any]:
    return _io.read_json_bounded(
        path,
        limit=limit,
        error_factory=ProtocolManifestError,
        display_name=_display_path(path),
        sensitive_pattern=sensitive_pattern,
        require_dict=True,
    )


def read_text_bounded(path: Path) -> str:
    return _io.read_text_bounded(
        path,
        limit=MAX_SOURCE_BYTES,
        error_factory=ProtocolManifestError,
        display_name=_display_path(path),
    )


def parse_u32_constants(
    source: str, names: Iterable[str] | None = None
) -> dict[str, int]:
    """Resolve ``pub const NAME: u32 = VALUE;`` declarations in one file.

    Values may be decimal or hexadecimal literals, or other constants declared
    in the same file. Pass ``names`` to resolve only the constants the caller
    needs; unrelated declarations may reference other modules. Unknown names
    and cycles are rejected rather than guessed.
    """
    raw = {name: value for name, value in U32_CONST.findall(source)}
    requested = list(raw) if names is None else list(names)
    resolved: dict[str, int] = {}
    resolving: set[str] = set()

    def resolve(name: str) -> int:
        if name in resolved:
            return resolved[name]
        if name not in raw:
            raise ProtocolManifestError(f"unresolved contract constant: {name}")
        if name in resolving:
            raise ProtocolManifestError(f"cyclic contract constant: {name}")
        resolving.add(name)
        value = raw[name]
        literal = value.replace("_", "")
        if literal.isdigit():
            result = int(literal)
        elif literal.lower().startswith("0x") and len(literal) > 2:
            result = int(literal, 16)
        else:
            result = resolve(value)
        resolving.discard(name)
        resolved[name] = result
        return result

    for name in requested:
        resolve(name)
    return resolved


def _require_keys(value: dict[str, Any], keys: set[str], location: str) -> None:
    unknown = set(value) - keys
    if unknown:
        raise ProtocolManifestError(
            f"{location} has unknown fields: {', '.join(sorted(unknown))}"
        )
    missing = keys - set(value)
    if missing:
        raise ProtocolManifestError(
            f"{location} is missing fields: {', '.join(sorted(missing))}"
        )


def validate_manifest(manifest: dict[str, Any]) -> None:
    _io.reject_sensitive_keys(manifest, "manifest", error_factory=ProtocolManifestError)
    _require_keys(
        manifest, {"format", "schema_version", "baseline", "layers"}, "manifest"
    )
    if manifest["format"] != FORMAT:
        raise ProtocolManifestError("manifest.format is invalid")
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise ProtocolManifestError("manifest.schema_version must be 1")

    baseline = manifest["baseline"]
    if not isinstance(baseline, dict):
        raise ProtocolManifestError("manifest.baseline must be an object")
    _require_keys(baseline, {"release_id", "network", "protocol"}, "manifest.baseline")
    if not isinstance(baseline["release_id"], str) or not baseline["release_id"]:
        raise ProtocolManifestError("manifest.baseline.release_id must be a string")
    if not isinstance(baseline["network"], str) or not baseline["network"]:
        raise ProtocolManifestError("manifest.baseline.network must be a string")
    if not isinstance(baseline["protocol"], dict):
        raise ProtocolManifestError("manifest.baseline.protocol must be an object")

    layers = manifest["layers"]
    if not isinstance(layers, dict) or set(layers) != set(LAYERS):
        raise ProtocolManifestError(
            "manifest.layers must contain exactly api, cli, circuit, contract"
        )
    expected_keys = {
        "api": {"api_version", "schema_sha256"},
        "cli": {"version", "manifest_version"},
        "circuit": {"circuit_version", "input_schema_version", "input_schema_sha256"},
        "contract": {
            "contract_interface_version",
            "descriptor_version",
            "min_verifier_input_version",
            "max_verifier_input_version",
            "expected_circuit_version",
            "max_supported_circuit_version",
        },
    }
    for name in LAYERS:
        layer = layers[name]
        if not isinstance(layer, dict):
            raise ProtocolManifestError(f"manifest.layers.{name} must be an object")
        _require_keys(layer, expected_keys[name], f"manifest.layers.{name}")

    if not isinstance(layers["cli"]["version"], str) or not SEMVER.fullmatch(
        layers["cli"]["version"]
    ):
        raise ProtocolManifestError("manifest.layers.cli.version must be SemVer")
    for name, field in (
        ("api", "schema_sha256"),
        ("circuit", "input_schema_sha256"),
    ):
        if not isinstance(layers[name][field], str) or not HEX_256.fullmatch(
            layers[name][field]
        ):
            raise ProtocolManifestError(
                f"manifest.layers.{name}.{field} must be SHA-256"
            )
    for name in LAYERS:
        for key, value in layers[name].items():
            if key.endswith("_sha256") or key == "version":
                continue
            if not isinstance(value, int) or isinstance(value, bool):
                raise ProtocolManifestError(
                    f"manifest.layers.{name}.{key} must be an integer"
                )


def load_manifest(path: Path) -> dict[str, Any]:
    manifest = read_json_bounded(path)
    validate_manifest(manifest)
    return manifest


def load_release_manifest(path: Path = DEFAULT_RELEASE_MANIFEST) -> dict[str, Any]:
    release = read_json_bounded(path)
    for key in ("release_id", "network", "protocol", "components"):
        if key not in release:
            raise ProtocolManifestError(f"release manifest missing '{key}'")
    return release


def api_schema_digest(root: Path) -> str:
    schema = generate_api_schema.generate_schema(
        root / "backend" / "app.py", root / "backend" / "schemas"
    )
    return sha256_text(canonical_json(schema))


def circuit_input_schema_digest(root: Path) -> str:
    schema = read_json_bounded(
        root / "zk" / "noir" / "circuit_input_schema_v1.json",
        sensitive_pattern=None,
    )
    return sha256_text(canonical_json(schema))


def cli_manifest_version(root: Path) -> int:
    source = read_text_bounded(root / "cli" / "src" / "manifest.ts")
    match = CLI_MANIFEST_VERSION.search(source)
    if match is None:
        raise ProtocolManifestError(
            "cli/src/manifest.ts does not declare MANIFEST_VERSION"
        )
    return int(match.group(1))


def compute_layers(root: Path, release: dict[str, Any]) -> dict[str, dict[str, Any]]:
    components = release["components"]
    cli_pkg = read_json_bounded(root / "cli" / "package.json")
    verifier_consts = parse_u32_constants(
        read_text_bounded(
            root
            / "contracts"
            / "contracts"
            / "harpocrates-registry"
            / "src"
            / "verifier_inputs.rs"
        ),
        names={
            "COMPATIBILITY_DESCRIPTOR_VERSION",
            "MIN_VERIFIER_INPUT_VERSION",
            "MAX_VERIFIER_INPUT_VERSION",
            "EXPECTED_CIRCUIT_VERSION",
        },
    )
    registry_consts = parse_u32_constants(
        read_text_bounded(
            root / "contracts" / "contracts" / "harpocrates-registry" / "src" / "lib.rs"
        ),
        names={"MAX_SUPPORTED_CIRCUIT_VERSION"},
    )
    return {
        "api": {
            "api_version": components["backend"]["api_version"],
            "schema_sha256": api_schema_digest(root),
        },
        "cli": {
            "version": cli_pkg["version"],
            "manifest_version": cli_manifest_version(root),
        },
        "circuit": {
            "circuit_version": circuit_version.CURRENT_CIRCUIT_VERSION,
            "input_schema_version": circuit_version.CIRCUIT_INPUT_SCHEMA_VERSION,
            "input_schema_sha256": circuit_input_schema_digest(root),
        },
        "contract": {
            "contract_interface_version": components["registry"][
                "contract_interface_version"
            ],
            "descriptor_version": verifier_consts["COMPATIBILITY_DESCRIPTOR_VERSION"],
            "min_verifier_input_version": verifier_consts["MIN_VERIFIER_INPUT_VERSION"],
            "max_verifier_input_version": verifier_consts["MAX_VERIFIER_INPUT_VERSION"],
            "expected_circuit_version": verifier_consts["EXPECTED_CIRCUIT_VERSION"],
            "max_supported_circuit_version": registry_consts[
                "MAX_SUPPORTED_CIRCUIT_VERSION"
            ],
        },
    }


def build_manifest(release: dict[str, Any], root: Path = ROOT) -> dict[str, Any]:
    return {
        "format": FORMAT,
        "schema_version": SCHEMA_VERSION,
        "baseline": {
            "release_id": release["release_id"],
            "network": release["network"],
            "protocol": release["protocol"],
        },
        "layers": compute_layers(root, release),
    }


def compare_manifest(
    manifest: dict[str, Any],
    release: dict[str, Any],
    root: Path = ROOT,
    current: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    """Return deterministic findings for a mixed or drifted layer combination."""
    findings: list[str] = []
    baseline = manifest["baseline"]
    if baseline["release_id"] != release["release_id"]:
        findings.append(
            f"baseline.release_id: recorded {baseline['release_id']!r}, "
            f"release {release['release_id']!r}"
        )
    if baseline["network"] != release["network"]:
        findings.append(
            f"baseline.network: recorded {baseline['network']!r}, "
            f"release {release['network']!r}"
        )
    if baseline["protocol"] != release["protocol"]:
        findings.append(
            "baseline.protocol: recorded baseline does not match the release protocol"
        )

    current = current if current is not None else compute_layers(root, release)
    for name in LAYERS:
        recorded_layer = manifest["layers"][name]
        for key in sorted(recorded_layer):
            if recorded_layer[key] != current[name][key]:
                findings.append(
                    f"{name}.{key}: recorded {recorded_layer[key]!r}, "
                    f"current {current[name][key]!r}"
                )

    circuit = manifest["layers"]["circuit"]
    contract = manifest["layers"]["contract"]
    if circuit["circuit_version"] != contract["expected_circuit_version"]:
        findings.append(
            "circuit.circuit_version: circuit "
            f"{circuit['circuit_version']} != verifier-expected "
            f"{contract['expected_circuit_version']}"
        )
    if circuit["circuit_version"] > contract["max_supported_circuit_version"]:
        findings.append(
            "circuit.circuit_version: circuit "
            f"{circuit['circuit_version']} exceeds contract window "
            f"{contract['max_supported_circuit_version']}"
        )
    if contract["min_verifier_input_version"] > contract["max_verifier_input_version"]:
        findings.append("contract.verifier_input_versions: minimum exceeds maximum")
    if contract["descriptor_version"] < 1:
        findings.append("contract.descriptor_version: must be at least 1")

    return findings


def build_report(
    manifest: dict[str, Any], release: dict[str, Any], root: Path = ROOT
) -> dict[str, Any]:
    current = compute_layers(root, release)
    findings = compare_manifest(manifest, release, root, current=current)
    return {
        "format": REPORT_FORMAT,
        "schema_version": SCHEMA_VERSION,
        "status": "incompatible" if findings else "compatible",
        "baseline": manifest["baseline"],
        "layers": current,
        "findings": findings,
    }


def write_manifest(manifest: dict[str, Any], output: Path) -> None:
    validate_manifest(manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the cross-layer protocol compatibility baseline"
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--release-manifest", type=Path, default=DEFAULT_RELEASE_MANIFEST
    )
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero on an incompatible combination",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="regenerate the baseline manifest from the current tree",
    )
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    root = args.root.resolve()
    try:
        release = load_release_manifest(args.release_manifest.resolve())
        if args.write:
            manifest = build_manifest(release, root)
            write_manifest(manifest, (args.output or args.manifest).resolve())
        else:
            manifest = load_manifest(args.manifest.resolve())
        report = build_report(manifest, release, root)
    except ProtocolManifestError as exc:
        print(f"protocol compatibility failed: {exc}", file=sys.stderr)
        return 2

    print(canonical_json(report), end="")
    if args.check and report["status"] != "compatible":
        for finding in report["findings"]:
            print(f"incompatible: {finding}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
