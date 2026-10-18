#!/usr/bin/env python3
"""Fail-closed Wasm size-budget gate for the Harpocrates registry (#346).

Compares the compiled registry artifact `harpocrates_registry.wasm` against
the budget declared in `devx/wasm_size_budget.json` and the constants in
`contracts/contracts/harpocrates-registry/src/wasm_budget.rs`.

Fail-closed contract:
  * a missing or unreadable artifact fails
  * a missing, malformed, or schema-invalid manifest fails
  * an artifact outside the declared [min_size_bytes, max_size_bytes] band fails
  * an artifact more than `regression_band_pct` away from the recorded
    `baseline_size_bytes` fails (a size move is a deliberate baseline migration)
  * a baseline row without a `sha256` digest is ignored -- the size budget
    still applies; the digest audit trail is best-effort

Privacy: all diagnostics carry sizes, digests, and limit values only. No
artifact bytes, proofs, witnesses, media, or keys are ever printed or logged.

Usage:
    python3 devx/wasm_size_budget.py --check
    python3 devx/wasm_size_budget.py --check --manifest devx/wasm_size_budget.json
    python3 devx/wasm_size_budget.py --record   # write measured sizes/digest back
    python3 devx/wasm_size_budget.py --print    # show the current manifest
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "devx" / "wasm_size_budget.json"
DEFAULT_CONTRACT_DIR = ROOT / "contracts" / "contracts" / "harpocrates-registry"
DEFAULT_TARGET = "wasm32v1-none"
WASM_NAME = "harpocrates_registry.wasm"

SCHEMA_VERSION = 1
REQUIRED_KEYS = {
    "schema_version",
    "target",
    "artifact",
    "description",
    "budgets",
    "baseline",
}
REQUIRED_BUDGET_KEYS = {"max_size_bytes", "min_size_bytes", "regression_band_pct"}


class WasmBudgetError(RuntimeError):
    """Raised for any fail-closed condition or budget violation."""


# ---------------------------------------------------------------------------
# Rust constant extraction
# ---------------------------------------------------------------------------


def _rust_const(rust_path: Path, const_name: str) -> int:
    """Extract a u64 constant from the budget module, fail closed."""
    try:
        text = rust_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise WasmBudgetError(f"cannot read budget constants from {rust_path}: {exc}") from exc
    match = re.search(rf"pub const {re.escape(const_name)}:\s*u64\s*=\s*([0-9_]+)", text)
    if not match:
        raise WasmBudgetError(f"constant {const_name} not found in {rust_path}")
    return int(match.group(1).replace("_", ""))


def load_rust_budgets(rust_path: Path) -> dict[str, int]:
    """Load the declared budgets from the Rust source of truth."""
    return {
        "max_size_bytes": _rust_const(rust_path, "MAX_WASM_SIZE_BYTES"),
        "min_size_bytes": _rust_const(rust_path, "MIN_WASM_SIZE_BYTES"),
        "regression_band_pct": _rust_const(rust_path, "WASM_SIZE_REGRESSION_BAND_PCT"),
    }


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def load_manifest(path: Path) -> dict[str, Any]:
    """Load and validate the budget manifest. Fails closed on any deviation."""
    if not path.is_file():
        raise WasmBudgetError(f"budget manifest not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise WasmBudgetError(f"budget manifest {path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise WasmBudgetError(f"budget manifest {path} must contain a JSON object")
    missing = REQUIRED_KEYS - set(raw)
    if missing:
        raise WasmBudgetError(f"budget manifest {path} is missing keys: {sorted(missing)}")
    if raw["schema_version"] != SCHEMA_VERSION:
        raise WasmBudgetError(
            f"budget manifest {path} has unsupported schema_version {raw['schema_version']!r}; "
            f"expected {SCHEMA_VERSION}"
        )
    if not isinstance(raw["budgets"], dict) or not raw["budgets"]:
        raise WasmBudgetError(f"budget manifest {path} must have a non-empty 'budgets' object")
    for key, value in raw["budgets"].items():
        if not isinstance(value, dict):
            raise WasmBudgetError(f"budget manifest {path}: budget {key!r} must be an object")
        missing_budget = REQUIRED_BUDGET_KEYS - set(value)
        if missing_budget:
            raise WasmBudgetError(
                f"budget manifest {path}: budget {key!r} is missing keys {sorted(missing_budget)}"
            )
        for numeric in REQUIRED_BUDGET_KEYS:
            if not isinstance(value[numeric], int) or isinstance(value[numeric], bool):
                raise WasmBudgetError(
                    f"budget manifest {path}: budget {key!r} field {numeric!r} must be an integer"
                )
    if not isinstance(raw["baseline"], dict):
        raise WasmBudgetError(f"budget manifest {path} must contain a 'baseline' object")
    return raw


def select_budget(manifest: dict[str, Any], name: str | None) -> tuple[str, dict[str, int]]:
    budgets = manifest["budgets"]
    if name is None:
        if len(budgets) == 1:
            name = next(iter(budgets))
        else:
            raise WasmBudgetError(
                "multiple budgets declared; pass --budget (one of: " + ", ".join(sorted(budgets)) + ")"
            )
    if name not in budgets:
        raise WasmBudgetError(f"unknown budget {name!r}; declared: {sorted(budgets)}")
    return name, budgets[name]


# ---------------------------------------------------------------------------
# Artifact measurement
# ---------------------------------------------------------------------------


def resolve_artifact(
    manifest: dict[str, Any],
    *,
    artifact: Path | None = None,
    target: str | None = None,
) -> Path:
    """Resolve the artifact path (repo-root relative; cargo uses the workspace target dir)."""
    if artifact is not None:
        return artifact
    rel = manifest.get("artifact") or f"contracts/target/{DEFAULT_TARGET}/release/{WASM_NAME}"
    return ROOT / rel.replace("{target}", target or manifest.get("target", DEFAULT_TARGET))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def measure(artifact_path: Path) -> dict[str, Any]:
    """Measure the artifact. Any inability to measure fails closed."""
    if not artifact_path.is_file():
        raise WasmBudgetError(f"registry Wasm artifact not found: {artifact_path} -- build it first")
    try:
        size = artifact_path.stat().st_size
    except OSError as exc:
        raise WasmBudgetError(f"cannot stat artifact {artifact_path}: {exc}") from exc
    if size <= 0:
        raise WasmBudgetError(f"artifact {artifact_path} is empty")
    return {"size_bytes": size, "sha256": sha256_file(artifact_path)}


# ---------------------------------------------------------------------------
# Budget check
# ---------------------------------------------------------------------------


def check_budgets(
    measured: dict[str, Any],
    budget: dict[str, int],
    baseline: dict[str, Any] | None,
) -> list[str]:
    failures: list[str] = []
    size = measured["size_bytes"]
    max_size = budget["max_size_bytes"]
    min_size = budget["min_size_bytes"]
    band_pct = budget["regression_band_pct"]

    if size > max_size:
        failures.append(f"size {size} bytes exceeds budget {max_size} bytes by {size - max_size}")
    if size < min_size:
        failures.append(
            f"size {size} bytes is below the minimum {min_size} bytes (wrong build profile or truncated artifact?)"
        )

    baseline_size = baseline.get("size_bytes") if isinstance(baseline, dict) else None
    if isinstance(baseline_size, int) and not isinstance(baseline_size, bool) and baseline_size > 0:
        band = baseline_size * band_pct // 100
        if size > baseline_size + band:
            failures.append(
                f"size {size} bytes exceeds the recorded baseline {baseline_size} bytes plus "
                f"{band_pct}% band ({baseline_size + band}); update the baseline deliberately"
            )
        elif size + band < baseline_size:
            failures.append(
                f"size {size} bytes shrank more than {band_pct}% below the recorded baseline "
                f"{baseline_size} bytes; update the baseline deliberately"
            )
    return failures


def record(measured: dict[str, Any], manifest_path: Path, manifest: dict[str, Any]) -> None:
    """Persist measured size and digest as the new baseline (explicit opt-in)."""
    baseline = manifest.setdefault("baseline", {})
    baseline["size_bytes"] = measured["size_bytes"]
    baseline["sha256"] = measured["sha256"]
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--check", action="store_true", help="run the budget gate (default)")
    parser.add_argument("--record", action="store_true", help="write the measured size/digest as the new baseline")
    parser.add_argument("--print", action="store_true", help="print the current manifest and exit")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST, help="path to the budget manifest")
    parser.add_argument("--artifact", type=Path, default=None, help="explicit artifact path override")
    parser.add_argument("--target", default=None, help="wasm target override, e.g. wasm32v1-none")
    parser.add_argument("--budget", default=None, help="budget name when several are declared")
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
        if args.print:
            print(json.dumps(manifest, indent=2))
            return 0

        rust_path = DEFAULT_CONTRACT_DIR / "src" / "wasm_budget.rs"
        rust_budgets = load_rust_budgets(rust_path)
        budget_name, budget = select_budget(manifest, args.budget)
        drift = {
            key: (budget.get(key), rust_budgets.get(key))
            for key in rust_budgets
            if budget.get(key) != rust_budgets.get(key)
        }
        if drift:
            print(
                "FAIL manifest budgets disagree with wasm_budget.rs constants: "
                f"{json.dumps(drift, default=str)}",
                file=sys.stderr,
            )
            return 1

        artifact_path = resolve_artifact(manifest, artifact=args.artifact, target=args.target)
        measured = measure(artifact_path)

        if args.record:
            record(measured, args.manifest, manifest)
            print(
                f"OK recorded baseline for {budget_name}: {measured['size_bytes']} bytes, "
                f"sha256 {measured['sha256']}"
            )
            return 0

        failures = check_budgets(measured, budget, manifest.get("baseline"))
        if failures:
            print(f"FAIL {budget_name} Wasm size budget violations:", file=sys.stderr)
            for failure in failures:
                print(f"  - {failure}", file=sys.stderr)
            print(
                f"artifact: {artifact_path} (sha256 {measured['sha256']})",
                file=sys.stderr,
            )
            return 1

        baseline_size = (manifest.get("baseline") or {}).get("size_bytes")
        digest_note = "baseline digest pending" if not (manifest.get("baseline") or {}).get("sha256") else "baseline digest recorded"
        print(
            f"OK {budget_name} artifact {measured['size_bytes']} bytes within budget "
            f"{budget['max_size_bytes']} bytes (baseline {baseline_size} bytes, {digest_note})"
        )
        return 0
    except WasmBudgetError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
