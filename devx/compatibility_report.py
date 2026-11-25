#!/usr/bin/env python3
"""Publish a cross-layer compatibility report for Harpocrates.

Reuses the canonical release compatibility manifest as the single protocol
truth. The report records public version, interface, and digest alignment
across frontend, backend, circuit, verifier, and registry — never media,
witnesses, credentials, proofs, transaction blobs, or deployment secrets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "release" / "compatibility-manifest.json"
DEFAULT_BINDING = ROOT / "release" / "verifier-binding.json"
DEFAULT_REPORT = ROOT / "release" / "compatibility-report.json"
FORMAT = "harpocrates.cross-layer-compatibility-report"
SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 256 * 1024
MAX_REPORT_BYTES = 256 * 1024
MAX_SOURCE_BYTES = 8 * 1024 * 1024
LAYERS = ("frontend", "backend", "circuit", "verifier", "registry")
PROOF_SYSTEM_ALIASES = {
    "ultrahonk-v1": {"ultrahonk-v1", "ultra_honk", "ultrahonk"},
}
# Match concrete secret-bearing field names only (avoid flagging
# privacy metadata such as ``includes_private_material``).
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from devx._io import (
    DEFAULT_SENSITIVE_KEY_RE as SENSITIVE_KEY_RE,
    read_json_bounded as _io_read_json_bounded,
    read_text_bounded as _io_read_text_bounded,
    reject_sensitive_keys as _reject_sensitive_keys,
)


class ReportError(ValueError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def read_text_bounded(path: Path, limit: int = MAX_SOURCE_BYTES) -> str:
    return _io_read_text_bounded(
        path,
        limit=limit,
        error_factory=ReportError,
        display_name=_display_path(path),
    )


def read_json_bounded(path: Path, limit: int = MAX_MANIFEST_BYTES) -> dict[str, Any]:
    return _io_read_json_bounded(
        path,
        limit=limit,
        error_factory=ReportError,
        display_name=_display_path(path),
        sensitive_pattern=SENSITIVE_KEY_RE,
        require_dict=True,
    )


def _check(check_id: str, ok: bool, detail: str = "") -> dict[str, Any]:
    item: dict[str, Any] = {"id": check_id, "status": "pass" if ok else "fail"}
    if detail:
        item["detail"] = detail
    return item


def _extract_ts_const(source: str, name: str) -> str | None:
    match = re.search(
        rf"export\s+const\s+{re.escape(name)}\s*=\s*['\"]([^'\"]+)['\"]",
        source,
    )
    return match.group(1) if match else None


def _extract_python_default(source: str, env_name: str) -> str | None:
    match = re.search(
        rf'os\.getenv\(\s*["\']{re.escape(env_name)}["\']\s*,\s*["\']([^"\']+)["\']\s*\)',
        source,
    )
    return match.group(1) if match else None


def _extract_cargo_version(source: str) -> str | None:
    match = re.search(r'^version\s*=\s*"([^"]+)"', source, re.MULTILINE)
    return match.group(1) if match else None


def _proof_systems_compatible(left: str, right: str) -> bool:
    left_n = left.strip().lower().replace("-", "_")
    right_n = right.strip().lower().replace("-", "_")
    if left_n == right_n:
        return True
    for aliases in PROOF_SYSTEM_ALIASES.values():
        normalized = {a.replace("-", "_") for a in aliases}
        if left_n in normalized and right_n in normalized:
            return True
    return False


def _layer_sources(name: str) -> list[str]:
    mapping = {
        "frontend": [
            "release/compatibility-manifest.json",
            "frontend/package.json",
            "frontend/src/releaseCompatibility.ts",
        ],
        "backend": [
            "release/compatibility-manifest.json",
            "backend/config.py",
        ],
        "circuit": [
            "release/compatibility-manifest.json",
            "zk/toolchain.lock.json",
            "zk/noir/silent_witness/Nargo.toml",
        ],
        "verifier": [
            "release/compatibility-manifest.json",
            "release/verifier-binding.json",
        ],
        "registry": [
            "release/compatibility-manifest.json",
            "contracts/contracts/harpocrates-registry/Cargo.toml",
        ],
    }
    return mapping[name]


def evaluate_layers(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    components = manifest["components"]
    layers: list[dict[str, Any]] = []

    # frontend
    frontend_pkg = read_json_bounded(ROOT / "frontend" / "package.json")
    frontend_ts = read_text_bounded(ROOT / "frontend" / "src" / "releaseCompatibility.ts")
    release_id_const = _extract_ts_const(frontend_ts, "COMPATIBILITY_RELEASE_ID")
    network_const = _extract_ts_const(frontend_ts, "COMPATIBILITY_NETWORK")
    frontend_checks = [
        _check(
            "package_version_matches_manifest",
            frontend_pkg.get("version") == components["frontend"]["version"],
            f"package={frontend_pkg.get('version')} manifest={components['frontend']['version']}",
        ),
        _check(
            "release_id_binding",
            release_id_const == manifest["release_id"],
            f"const={release_id_const} manifest={manifest['release_id']}",
        ),
        _check(
            "network_binding",
            network_const == manifest["network"],
            f"const={network_const} manifest={manifest['network']}",
        ),
        _check(
            "api_version",
            components["frontend"].get("api_version") == 1,
            str(components["frontend"].get("api_version")),
        ),
        _check(
            "contract_interface_version",
            components["frontend"].get("contract_interface_version") == 1,
            str(components["frontend"].get("contract_interface_version")),
        ),
    ]
    layers.append(
        {
            "name": "frontend",
            "version": components["frontend"]["version"],
            "api_version": components["frontend"].get("api_version"),
            "sources": _layer_sources("frontend"),
            "checks": frontend_checks,
            "status": "compatible" if all(c["status"] == "pass" for c in frontend_checks) else "incompatible",
        }
    )

    # backend
    backend_cfg = read_text_bounded(ROOT / "backend" / "config.py")
    backend_release = _extract_python_default(backend_cfg, "HARPOCRATES_RELEASE_ID")
    backend_network = _extract_python_default(backend_cfg, "HARPOCRATES_RELEASE_NETWORK")
    backend_checks = [
        _check(
            "release_id_default",
            backend_release == manifest["release_id"],
            f"default={backend_release} manifest={manifest['release_id']}",
        ),
        _check(
            "network_default",
            backend_network == manifest["network"],
            f"default={backend_network} manifest={manifest['network']}",
        ),
        _check(
            "api_version",
            components["backend"].get("api_version") == 1,
            str(components["backend"].get("api_version")),
        ),
        _check(
            "version_declared",
            bool(re.fullmatch(r"\d+\.\d+\.\d+", str(components["backend"].get("version", "")))),
            str(components["backend"].get("version")),
        ),
    ]
    layers.append(
        {
            "name": "backend",
            "version": components["backend"]["version"],
            "api_version": components["backend"].get("api_version"),
            "sources": _layer_sources("backend"),
            "checks": backend_checks,
            "status": "compatible" if all(c["status"] == "pass" for c in backend_checks) else "incompatible",
        }
    )

    # circuit
    toolchain = read_json_bounded(ROOT / "zk" / "toolchain.lock.json")
    proving_scheme = str((toolchain.get("toolchain") or {}).get("proving_scheme") or "")
    circuit_proof = str(components["circuit"].get("proof_system") or "")
    nargo = read_text_bounded(ROOT / "zk" / "noir" / "silent_witness" / "Nargo.toml")
    circuit_checks = [
        _check(
            "proof_system_aligned_with_toolchain",
            _proof_systems_compatible(circuit_proof, proving_scheme),
            f"manifest={circuit_proof} toolchain={proving_scheme}",
        ),
        _check(
            "api_version",
            components["circuit"].get("api_version") == 1,
            str(components["circuit"].get("api_version")),
        ),
        _check(
            "nargo_package_present",
            'name = "silent_witness"' in nargo,
            "zk/noir/silent_witness/Nargo.toml",
        ),
    ]
    layers.append(
        {
            "name": "circuit",
            "version": components["circuit"]["version"],
            "api_version": components["circuit"].get("api_version"),
            "proof_system": circuit_proof,
            "sources": _layer_sources("circuit"),
            "checks": circuit_checks,
            "status": "compatible" if all(c["status"] == "pass" for c in circuit_checks) else "incompatible",
        }
    )

    # verifier
    binding = read_json_bounded(DEFAULT_BINDING)
    verifier_proof = str(components["verifier"].get("proof_system") or "")
    binding_proof = str(binding.get("proof_system") or "")
    binding_domain = str(binding.get("crypto_domain") or "")
    protocol_domain = str((manifest.get("protocol") or {}).get("crypto_domain") or "")
    verifier_checks = [
        _check(
            "proof_system_matches_manifest",
            binding_proof == verifier_proof,
            f"binding={binding_proof} manifest={verifier_proof}",
        ),
        _check(
            "crypto_domain_matches_protocol",
            binding_domain == protocol_domain,
            f"binding={binding_domain} protocol={protocol_domain}",
        ),
        _check(
            "public_inputs_version",
            binding.get("public_inputs_version")
            == (manifest.get("compatibility") or {}).get("proof_public_inputs_version"),
            str(binding.get("public_inputs_version")),
        ),
        _check(
            "api_version",
            components["verifier"].get("api_version") == 1,
            str(components["verifier"].get("api_version")),
        ),
    ]
    layers.append(
        {
            "name": "verifier",
            "version": components["verifier"]["version"],
            "api_version": components["verifier"].get("api_version"),
            "proof_system": verifier_proof,
            "sources": _layer_sources("verifier"),
            "checks": verifier_checks,
            "status": "compatible" if all(c["status"] == "pass" for c in verifier_checks) else "incompatible",
        }
    )

    # registry
    cargo = read_text_bounded(
        ROOT / "contracts" / "contracts" / "harpocrates-registry" / "Cargo.toml"
    )
    cargo_version = _extract_cargo_version(cargo)
    registry_checks = [
        _check(
            "cargo_version_matches_manifest",
            cargo_version == components["registry"]["version"],
            f"cargo={cargo_version} manifest={components['registry']['version']}",
        ),
        _check(
            "contract_interface_version",
            components["registry"].get("contract_interface_version") == 1,
            str(components["registry"].get("contract_interface_version")),
        ),
        _check(
            "api_version",
            components["registry"].get("api_version") == 1,
            str(components["registry"].get("api_version")),
        ),
    ]
    layers.append(
