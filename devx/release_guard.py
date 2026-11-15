#!/usr/bin/env python3
"""Fail-closed compatibility gate for a Harpocrates release bundle.

The manifest intentionally contains only public release identity and hashes.  It
must never contain witnesses, media, credentials, proofs, transaction blobs, or
private deployment credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

try:
    import secret_scanner
except ImportError:  # pragma: no cover - package-qualified import fallback
    from devx import secret_scanner  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "release" / "compatibility-manifest.json"
DEFAULT_BINDING = ROOT / "release" / "verifier-binding.json"
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$")
HEX_256 = re.compile(r"^[0-9a-f]{64}$")
DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
COMPONENTS = {"frontend", "backend", "circuit", "verifier", "registry"}
ROLLOUT_STATES = {"candidate", "staged", "active", "rollback"}
MAX_MANIFEST_BYTES = 256 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_ARTIFACT_PATH_CHARS = 512
MAX_PATH_ERROR_PREVIEW = 96
MAX_VALIDATION_ERROR_CHARS = 240


class ManifestError(ValueError):
    def __init__(self, message: str, *, code: str | None = None) -> None:
        self.code = code
        if code is not None and len(message) > MAX_VALIDATION_ERROR_CHARS:
            message = message[: MAX_VALIDATION_ERROR_CHARS - 3] + "..."
        super().__init__(message)


def _bounded_preview(raw_path: Any) -> str:
    if not isinstance(raw_path, str):
        return f"<{type(raw_path).__name__}>"
    chars: list[str] = []
    for ch in raw_path:
        cp = ord(ch)
        if cp < 32 or cp == 127:
            chars.append(f"\\x{cp:02x}")
        else:
            chars.append(ch)
    sanitized = "".join(chars)
    if len(sanitized) <= MAX_PATH_ERROR_PREVIEW:
        return sanitized
    return f"{sanitized[:64]}...<+{len(sanitized) - 64} chars>"


def _path_error(code: str, raw_path: Any, reason: str) -> ManifestError:
    preview = _bounded_preview(raw_path)
    return ManifestError(
        f"invalid artifact path [{code}]: '{preview}' {reason} (must stay inside release directory)",
        code=code,
    )


def _is_alias_entry(entry: Path) -> bool:
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


def _strip_win_prefix(raw_target: str) -> str:
    if raw_target.startswith("\\\\?\\UNC\\"):
        return "\\\\" + raw_target[8:]
    if raw_target.startswith("\\\\?\\"):
        return raw_target[4:]
    return raw_target


def resolve_release_artifact_path(
    raw_path: Any,
    release_dir: Path | None = None,
) -> Path:
    """Validate ``raw_path`` and resolve aliases inside ``release_dir`` before reading."""
    if not isinstance(raw_path, str):
        raise _path_error("path_non_string", raw_path, "is not a string")
    if not raw_path or not raw_path.strip():
        raise _path_error("path_empty", raw_path, "is empty")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_path):
        raise _path_error("path_control_char", raw_path, "contains control characters")
    if len(raw_path) > MAX_ARTIFACT_PATH_CHARS:
        raise _path_error(
            "path_overlong",
            raw_path,
            f"exceeds {MAX_ARTIFACT_PATH_CHARS} chars (len={len(raw_path)})",
        )
    if "\\" in raw_path:
        raise _path_error("path_backslash", raw_path, "uses backslash separators")
    if raw_path.startswith("/") or DRIVE_PREFIX.match(raw_path):
        raise _path_error("path_absolute", raw_path, "is absolute")
    segments = raw_path.split("/")
    if any(seg in ("", ".", "..") for seg in segments):
        raise _path_error("path_traversal", raw_path, "traverses parent or empty segments")

    selected_root = release_dir if release_dir is not None else ROOT
    try:
        if not selected_root.exists() or not selected_root.is_dir():
            raise ManifestError(
                "invalid artifact path [release_dir_invalid]: selected release directory does not exist (paths must stay inside an existing release directory)",
                code="release_dir_invalid",
            )
        resolved_root = selected_root.resolve(strict=True)
    except OSError as exc:
        raise ManifestError(
            "invalid artifact path [release_dir_invalid]: selected release directory cannot be resolved (must stay inside release directory)",
            code="release_dir_invalid",
        ) from exc

    current = resolved_root
    for seg in segments:
        next_entry = current / seg
        if _is_alias_entry(next_entry):
            if next_entry.is_symlink():
                try:
                    raw_link = _strip_win_prefix(os.readlink(next_entry))
                except OSError as exc:
                    raise _path_error("alias_escape", raw_path, "has an unreadable link alias") from exc
                link_path = Path(raw_link)
                step_target = (
                    link_path.resolve(strict=False)
                    if link_path.is_absolute()
                    else (next_entry.parent / link_path).resolve(strict=False)
                )
                if step_target == resolved_root or not step_target.is_relative_to(resolved_root):
                    raise _path_error("alias_escape", raw_path, "resolves via alias outside boundary")
            resolved_step = next_entry.resolve(strict=False)
            if resolved_step == resolved_root or not resolved_step.is_relative_to(resolved_root):
                raise _path_error("alias_escape", raw_path, "resolves via alias outside boundary")
            current = resolved_step
        else:
            current = next_entry

    resolved_final = current.resolve(strict=False)
    if resolved_final == resolved_root or not resolved_final.is_relative_to(resolved_root):
        raise _path_error("alias_escape", raw_path, "resolves outside boundary")
    return resolved_final


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ManifestError("manifest exceeds the 256 KiB limit")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest: {exc}") from exc
    if not isinstance(value, dict):
        raise ManifestError("manifest must be a JSON object")
    return value


def reject_unknown(value: dict[str, Any], allowed: set[str], location: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ManifestError(f"{location} has unknown fields: {', '.join(sorted(unknown))}")


def required_string(value: dict[str, Any], key: str, location: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ManifestError(f"{location}.{key} must be a non-empty string")
    return item


def validate_manifest(
    manifest: dict[str, Any],
    release_dir: Path | None = None,
) -> None:
    reject_unknown(manifest, {"schema_version", "release_id", "protocol", "network", "rollout", "components", "artifacts", "compatibility"}, "manifest")
    if manifest.get("schema_version") != 1:
        raise ManifestError("manifest.schema_version must be 1")
    if required_string(manifest, "release_id", "manifest") != "harpocrates-1.0.0":
        raise ManifestError("manifest.release_id is not an approved release train")
    if manifest.get("protocol") != {"name": "harpocrates", "version": 1, "crypto_domain": "harpocrates:silent-witness:v1"}:
        raise ManifestError("manifest.protocol must use the approved versioned cryptographic domain")
    network = required_string(manifest, "network", "manifest")
    if network not in {"local", "testnet", "mainnet"}:
        raise ManifestError("manifest.network must be local, testnet, or mainnet")

    rollout = manifest.get("rollout")
    if not isinstance(rollout, dict):
        raise ManifestError("manifest.rollout must be an object")
    reject_unknown(rollout, {"state", "previous_release", "max_stage_percent", "approval"}, "manifest.rollout")
    if rollout.get("state") not in ROLLOUT_STATES:
        raise ManifestError("manifest.rollout.state is invalid")
    if not isinstance(rollout.get("max_stage_percent"), int) or not 0 <= rollout["max_stage_percent"] <= 100:
        raise ManifestError("manifest.rollout.max_stage_percent must be an integer from 0 to 100")
    if rollout["state"] in {"staged", "active"} and not required_string(rollout, "approval", "manifest.rollout"):
        raise ManifestError("staged and active releases require an approval reference")
    if rollout["state"] == "rollback" and not required_string(rollout, "previous_release", "manifest.rollout"):
        raise ManifestError("rollback requires previous_release")

    components = manifest.get("components")
    if not isinstance(components, dict) or set(components) != COMPONENTS:
        raise ManifestError("manifest.components must contain exactly frontend, backend, circuit, verifier, registry")
    for name, component in components.items():
        if not isinstance(component, dict):
            raise ManifestError(f"component {name} must be an object")
        reject_unknown(component, {"version", "api_version", "proof_system", "contract_interface_version"}, f"component {name}")
        if not SEMVER.fullmatch(required_string(component, "version", f"component {name}")):
            raise ManifestError(f"component {name}.version must be SemVer")
        if component.get("api_version") != 1:
            raise ManifestError(f"component {name}.api_version must be 1")
    if components["circuit"].get("proof_system") != "ultrahonk-v1" or components["verifier"].get("proof_system") != "ultrahonk-v1":
        raise ManifestError("circuit and verifier proof systems must both be ultrahonk-v1")
    if components["registry"].get("contract_interface_version") != 1 or components["frontend"].get("contract_interface_version") != 1:
        raise ManifestError("frontend and registry must both bind contract interface version 1")

    compatibility = manifest.get("compatibility")
    if compatibility != {"metadata_version": 1, "proof_public_inputs_version": 1, "migration": None}:
        raise ManifestError("manifest.compatibility must preserve the v1 metadata and proof interfaces or provide a versioned migration")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ManifestError("manifest.artifacts must be a non-empty array")
    seen: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ManifestError("every artifact must be an object")
        reject_unknown(artifact, {"component", "path", "sha256"}, "artifact")
        component = required_string(artifact, "component", "artifact")
        raw_path = artifact.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            raise ManifestError("artifact.path must be a non-empty string")
        resolve_release_artifact_path(raw_path, release_dir=release_dir)
        digest = required_string(artifact, "sha256", "artifact")
        if component not in COMPONENTS or raw_path in seen or not HEX_256.fullmatch(digest):
            raise ManifestError("artifact component, unique path, or sha256 is invalid")
        seen.add(raw_path)
    if {a["component"] for a in artifacts} != COMPONENTS:
        raise ManifestError("each component must contribute at least one artifact")
    if rollout["state"] == "active":
        registry_paths = {a["path"] for a in artifacts if a["component"] == "registry"}
        verifier_paths = {a["path"] for a in artifacts if a["component"] == "verifier"}
        if not any(path.endswith(".wasm") for path in registry_paths):
            raise ManifestError("active release requires a digest-pinned registry WASM artifact")
        if not any(path.endswith(".wasm") for path in verifier_paths) or not any(path.endswith(".vk") for path in verifier_paths):
            raise ManifestError("active release requires digest-pinned verifier WASM and VK artifacts")


def validate_verifier_key_binding(manifest: dict[str, Any], binding: dict[str, Any]) -> None:
    """Require active releases to checksum-bind their deployed verifier key."""
    if manifest["rollout"]["state"] != "active":
        return

    verifier_keys = [
        artifact
        for artifact in manifest["artifacts"]
        if artifact["component"] == "verifier" and artifact["path"].endswith(".vk")
    ]
    if len(verifier_keys) != 1:
        raise ManifestError("active release must declare exactly one verifier VK artifact")

    artifact = verifier_keys[0]
    bound_path = binding.get("verification_key_artifact")
    bound_sha256 = binding.get("verification_key_sha256")
    if not isinstance(bound_path, str) or not isinstance(bound_sha256, str):
        raise ManifestError(
            "active release requires verification_key_artifact and verification_key_sha256"
        )
    if bound_path != artifact["path"]:
        raise ManifestError("verifier key binding path does not match the release artifact")
    if not HEX_256.fullmatch(bound_sha256):
        raise ManifestError("verification_key_sha256 must be a SHA-256 digest")
    if bound_sha256.lower() != artifact["sha256"].lower():
        raise ManifestError("verifier key binding checksum does not match the release artifact")


def verify(
    manifest_path: Path,
    require_active: bool = False,
    release_dir: Path | None = None,
) -> None:
    effective_root = release_dir if release_dir is not None else ROOT
    manifest = read_json(manifest_path)
    validate_manifest(manifest, release_dir=effective_root)
    binding_path = (
        resolve_release_artifact_path("release/verifier-binding.json", effective_root)
        if release_dir is not None
        else DEFAULT_BINDING
    )
    validate_verifier_key_binding(manifest, read_json(binding_path))
    _verify_declared_component_versions(manifest, release_dir=effective_root)
    if require_active and manifest["rollout"]["state"] != "active":
        raise ManifestError("publication requires rollout.state=active")
    mismatches: list[str] = []
    for artifact in manifest["artifacts"]:
        resolved_path = resolve_release_artifact_path(
            artifact["path"],
            release_dir=effective_root,
        )
        if not resolved_path.is_file():
            mismatches.append(f"missing artifact: {artifact['path']}")
            continue
        if resolved_path.stat().st_size > MAX_ARTIFACT_BYTES:
            mismatches.append(f"artifact exceeds 512 MiB limit: {artifact['path']}")
            continue
        if sha256_file(resolved_path) != artifact["sha256"]:
            mismatches.append(f"digest mismatch: {artifact['path']}")

        # Secret scan the artifact
        scan_errors = secret_scanner.scan_file(resolved_path)
        if scan_errors:
            mismatches.append(
                f"secret scan failed for {artifact['path']}: " + ", ".join(sorted(set(scan_errors)))
            )

    if mismatches:
        raise ManifestError("; ".join(mismatches))


def _verify_declared_component_versions(
    manifest: dict[str, Any],
    release_dir: Path | None = None,
) -> None:
    effective_root = release_dir if release_dir is not None else ROOT
    frontend_pkg = resolve_release_artifact_path("frontend/package.json", effective_root)
    frontend = read_json(frontend_pkg)
    if frontend.get("version") != manifest["components"]["frontend"]["version"]:
        raise ManifestError("frontend package version does not match manifest")
    cargo_toml = resolve_release_artifact_path(
        "contracts/contracts/harpocrates-registry/Cargo.toml",
        effective_root,
    )
    cargo = cargo_toml.read_text(encoding="utf-8")
    registry_version = re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.MULTILINE)
    if not registry_version or registry_version.group(1) != manifest["components"]["registry"]["version"]:
        raise ManifestError("registry Cargo version does not match manifest")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="verify a Harpocrates compatibility release bundle")
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--release-dir", type=Path, default=None)
    parser.add_argument("--require-active", action="store_true")
    args = parser.parse_args(argv)
    try:
        manifest_path = (
            args.manifest.resolve()
            if args.manifest is not None
            else (
                resolve_release_artifact_path(
                    "release/compatibility-manifest.json",
                    args.release_dir,
                )
                if args.release_dir is not None
                else DEFAULT_MANIFEST
            )
        )
        verify(manifest_path, args.require_active, release_dir=args.release_dir)
    except ManifestError as exc:
        print(f"release gate failed: {exc}", file=sys.stderr)
        return 1
    print("release gate passed: compatibility manifest and artifact digests are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
