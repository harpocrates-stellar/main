#!/usr/bin/env python3
"""Generate an offline release review bundle for Harpocrates.

Aggregates compatibility, artifact verification, and API schema check results
with explicit digests and missing evidence tracking. Never treats a skipped
check as a successful release gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "release" / "compatibility-manifest.json"
DEFAULT_BUNDLE = ROOT / "release" / "release-review-bundle.json"
FORMAT = "harpocrates.release-review-bundle"
SCHEMA_VERSION = 1
MAX_BUNDLE_BYTES = 512 * 1024


class BundleError(ValueError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def read_json_bounded(path: Path, limit: int = MAX_BUNDLE_BYTES) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise BundleError(f"cannot read {_display_path(path)}: {exc}") from exc
    if size > limit:
        raise BundleError(f"{_display_path(path)} exceeds the {limit} byte limit")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleError(f"malformed JSON in {_display_path(path)}: {exc}") from exc


def run_compatibility_report(manifest_path: Path) -> tuple[dict[str, Any], dict[str, str]]:
    """Run compatibility_report.py and return (report, source_digests)."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "devx" / "compatibility_report.py"), "--manifest", str(manifest_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise BundleError(f"compatibility_report failed: {result.stderr}")

    report = json.loads(result.stdout)

    source_digests: dict[str, str] = {}
    for layer in report.get("layers", []):
        for src in layer.get("sources", []):
            src_path = ROOT / src
            if src_path.is_file():
                source_digests[src] = sha256_file(src_path)

    for src in ["release/compatibility-manifest.json", "release/verifier-binding.json"]:
        src_path = ROOT / src
        if src_path.is_file() and src not in source_digests:
            source_digests[src] = sha256_file(src_path)

    return report, source_digests


def run_release_guard(manifest_path: Path) -> tuple[dict[str, Any], dict[str, str]]:
    """Run release_guard.py verify and return (result, artifact_digests)."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "devx" / "release_guard.py"), "--manifest", str(manifest_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    artifact_digests: dict[str, str] = {}
    manifest = read_json_bounded(manifest_path)
    for artifact in manifest.get("artifacts", []):
        rel = artifact.get("path", "")
        expected = artifact.get("sha256", "")
        path = ROOT / rel
        if path.is_file():
            actual = sha256_file(path)
            artifact_digests[rel] = actual

    gate_result: dict[str, Any] = {
        "status": "pass" if result.returncode == 0 else "fail",
        "message": result.stdout.strip() if result.returncode == 0 else result.stderr.strip(),
        "artifacts_checked": len(artifact_digests),
    }

    return gate_result, artifact_digests


def run_schema_check() -> tuple[dict[str, Any], dict[str, str]]:
    """Run generate_api_schema.py and return (schema, source_digests)."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "devx" / "generate_api_schema.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    source_digests: dict[str, str] = {}
    backend_files = [
        "backend/app.py",
        "backend/config.py",
        "backend/metrics.py",
    ]
    for src in backend_files:
        src_path = ROOT / src
        if src_path.is_file():
            source_digests[src] = sha256_file(src_path)

    schemas_dir = ROOT / "backend" / "schemas"
    if schemas_dir.is_dir():
        for p in sorted(schemas_dir.glob("*.json")):
            rel = str(p.relative_to(ROOT))
            source_digests[rel] = sha256_file(p)

    schema_result: dict[str, Any] = {
        "status": "pass" if result.returncode == 0 else "fail",
        "message": "schema generated" if result.returncode == 0 else result.stderr.strip(),
        "routes_count": 0,
        "schemas_loaded": 0,
    }

    if result.returncode == 0:
        try:
            schema = json.loads(result.stdout)
            schema_result["routes_count"] = len(schema.get("paths", {}))
            schema_result["schemas_loaded"] = len(schema.get("components", {}).get("schemas", {}))
            schema_result["schema_digest"] = sha256_bytes(result.stdout.encode("utf-8"))
        except json.JSONDecodeError as exc:
            schema_result["status"] = "fail"
            schema_result["message"] = f"malformed schema output: {exc}"

    return schema_result, source_digests


def build_bundle(manifest_path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    if not manifest_path.is_file():
        raise BundleError(f"manifest not found: {manifest_path}")

    manifest = read_json_bounded(manifest_path)
    release_id = manifest.get("release_id", "unknown")

    compat_report, compat_sources = run_compatibility_report(manifest_path)
    guard_result, artifact_digests = run_release_guard(manifest_path)
    schema_result, schema_sources = run_schema_check()

    all_source_digests: dict[str, str] = {}
    all_source_digests.update(compat_sources)
    all_source_digests.update(schema_sources)
    all_source_digests.update(artifact_digests)

    missing_evidence: list[dict[str, Any]] = []

    compat_status = compat_report.get("status", "unknown")
    if compat_status == "incompatible":
        missing_evidence.append({
            "check": "compatibility_report",
            "reason": "version or protocol incompatibility detected",
            "detail": compat_report.get("status"),
        })
    elif compat_status == "version_compatible_digest_drift":
        missing_evidence.append({
            "check": "compatibility_report",
            "reason": "artifact digest drift (version compatible)",
            "detail": "artifact digests do not match manifest",
        })

    if guard_result["status"] == "fail":
        missing_evidence.append({
            "check": "release_guard",
            "reason": "artifact verification failed",
            "detail": guard_result["message"],
        })

    if schema_result["status"] == "fail":
        missing_evidence.append({
            "check": "api_schema",
            "reason": "schema generation failed",
            "detail": schema_result["message"],
        })

    for layer in compat_report.get("layers", []):
        for check in layer.get("checks", []):
            if check.get("status") == "fail":
                missing_evidence.append({
                    "check": f"compatibility.layer.{layer['name']}.{check['id']}",
                    "reason": "layer check failed",
                    "detail": check.get("detail", ""),
                })

    for cross in compat_report.get("cross_layer", []):
        if cross.get("status") == "fail":
            missing_evidence.append({
                "check": f"compatibility.cross.{cross['id']}",
                "reason": "cross-layer check failed",
                "detail": cross.get("detail", ""),
            })

    gate_passed = (
        compat_status == "compatible"
        and guard_result["status"] == "pass"
        and schema_result["status"] == "pass"
        and not missing_evidence
    )

    bundle = {
        "format": FORMAT,
        "schema_version": SCHEMA_VERSION,
        "generated_by": "devx/release_review_bundle.py",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "release_id": release_id,
        "manifest_digest": sha256_file(manifest_path),
        "status": "pass" if gate_passed else "fail",
        "compatibility": {
            "report_status": compat_status,
            "layers": compat_report.get("layers", []),
            "cross_layer": compat_report.get("cross_layer", []),
            "source_digests": compat_sources,
        },
        "artifact_verification": {
            "status": guard_result["status"],
            "message": guard_result["message"],
            "artifacts_checked": guard_result["artifacts_checked"],
            "artifact_digests": artifact_digests,
        },
        "api_schema": {
            "status": schema_result["status"],
            "message": schema_result["message"],
            "routes_count": schema_result["routes_count"],
            "schemas_loaded": schema_result["schemas_loaded"],
            "schema_digest": schema_result.get("schema_digest"),
            "source_digests": schema_sources,
        },
        "missing_evidence": missing_evidence,
        "all_source_digests": all_source_digests,
        "privacy": {
            "includes_private_material": False,
            "note": "Bundle contains only public release identity, versions, interface bindings, check outcomes, and SHA-256 digests.",
        },
    }

    return bundle


def validate_bundle(bundle: dict[str, Any]) -> None:
    if bundle.get("format") != FORMAT:
        raise BundleError("bundle.format is invalid")
    if bundle.get("schema_version") != SCHEMA_VERSION:
        raise BundleError("bundle.schema_version must be 1")
    if bundle.get("status") not in {"pass", "fail"}:
        raise BundleError("bundle.status must be 'pass' or 'fail'")
    required_sections = ["compatibility", "artifact_verification", "api_schema", "missing_evidence", "all_source_digests"]
    for section in required_sections:
        if section not in bundle:
            raise BundleError(f"bundle missing required section: {section}")
    encoded = canonical_json(bundle).encode("utf-8")
    if len(encoded) > MAX_BUNDLE_BYTES:
        raise BundleError(f"bundle exceeds the {MAX_BUNDLE_BYTES} byte limit")


def write_bundle(bundle: dict[str, Any], output: Path) -> None:
    validate_bundle(bundle)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(canonical_json(bundle), encoding="utf-8")


def stabilize(bundle: dict[str, Any]) -> dict[str, Any]:
    stable = json.loads(json.dumps(bundle))
    stable.pop("generated_at", None)
    stable["generated_at"] = "committed"
    return stable


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate offline release review bundle")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument("--write", action="store_true", help="write the bundle JSON to --output")
    parser.add_argument("--stable", action="store_true", help="replace generated_at with 'committed' for reproducible git snapshots")
    parser.add_argument("--check", action="store_true", help="require all checks to pass (fail on any missing evidence)")
    parser.add_argument("--verify-existing", action="store_true", help="compare regenerated stable bundle to the file at --output")
    args = parser.parse_args(argv)

    try:
        bundle = build_bundle(args.manifest.resolve())
        if args.stable or args.write or args.verify_existing:
            bundle = stabilize(bundle)
        validate_bundle(bundle)

        if args.verify_existing:
            existing = read_json_bounded(args.output.resolve(), MAX_BUNDLE_BYTES)
            if canonical_json(existing) != canonical_json(bundle):
                raise BundleError(f"checked-in bundle at {args.output} is stale; regenerate with --write --stable")

        if args.write:
            write_bundle(bundle, args.output.resolve())

        print(canonical_json(bundle), end="")

        if args.check and bundle["status"] != "pass":
            print(f"release review bundle check failed: status={bundle['status']}", file=sys.stderr)
            if bundle["missing_evidence"]:
                for item in bundle["missing_evidence"]:
                    print(f"  MISSING: {item['check']} — {item['reason']}: {item['detail']}", file=sys.stderr)
            return 1
        return 0
    except BundleError as exc:
        print(f"release review bundle failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())