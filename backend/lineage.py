from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from c2pa import (
    C2paParseError,
    C2paTrustStatus,
    evaluate_c2pa_ingredient,
    parse_c2pa_manifest,
)

SUPPORTED_OPERATIONS = {"crop", "transcode", "blur", "redact", "compose"}
MAX_LINEAGE_DEPTH = 4
MAX_LINEAGE_FANOUT = 4
MAX_LINEAGE_PAYLOAD_BYTES = 4096
INTEROP_CORPUS_VERSION = 1
MAX_INTEROP_CORPUS_BYTES = 512 * 1024
DEFAULT_INTEROP_CORPUS_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "c2pa_lineage_corpus.json"
)


class LineageValidationError(ValueError):
    pass


class LineageRecordError(RuntimeError):
    pass


def canonical_lineage_manifest(manifest: dict[str, Any]) -> str:
    if not isinstance(manifest, dict):
        raise LineageValidationError("lineage manifest must be a JSON object")

    operation_type = manifest.get("operationType")
    if operation_type not in SUPPORTED_OPERATIONS:
        raise LineageValidationError("Unsupported lineage operation")

    parent_proofs = manifest.get("parentProofIds")
    if not isinstance(parent_proofs, list) or not parent_proofs:
        raise LineageValidationError("parentProofIds must be a non-empty array")

    if len(parent_proofs) > MAX_LINEAGE_FANOUT:
        raise LineageValidationError("lineage fan-out exceeds limit")

    for parent in parent_proofs:
        if not isinstance(parent, str) or not _is_hex_32(parent):
            raise LineageValidationError("parentProofIds must contain 32-byte hex values")

    required_fields = [
        "operationType",
        "parametersDigest",
        "toolIdentity",
        "toolVersion",
        "outputDigest",
        "network",
        "actorAddress",
    ]
    for field in required_fields:
        if field not in manifest:
            raise LineageValidationError(f"missing lineage field: {field}")

    if len(json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")) > MAX_LINEAGE_PAYLOAD_BYTES:
        raise LineageValidationError("lineage manifest is too large")

    normalized = {
        "protocol": "harpocrates",
        "version": 2,
        "parentProofIds": [str(parent) for parent in parent_proofs],
        "operationType": operation_type,
        "parametersDigest": str(manifest["parametersDigest"]),
        "toolIdentity": str(manifest["toolIdentity"]),
        "toolVersion": str(manifest["toolVersion"]),
        "outputDigest": str(manifest["outputDigest"]),
        "network": str(manifest["network"]),
        "actorAddress": str(manifest["actorAddress"]),
    }
    return json.dumps(normalized, separators=(",", ":"), sort_keys=True)


def lineage_manifest_digest(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_lineage_manifest(manifest).encode("utf-8")).hexdigest()


def validate_lineage_graph(
    parent_proof_ids: list[str],
    depth: int,
    actor_address: str,
    output_digest: str | None = None,
    get_lineage_fn: Any = None,
) -> None:
    """Validate lineage graph constraints.
    
    Args:
        parent_proof_ids: List of parent proof IDs
        depth: Current depth in the lineage tree
        actor_address: Address of the actor submitting the lineage
        output_digest: Output digest of the current lineage record (for cycle detection)
        get_lineage_fn: Optional function to query lineage records (for cycle detection)
    
    Raises:
        LineageValidationError: If validation fails
    """
    if depth > MAX_LINEAGE_DEPTH:
        raise LineageValidationError("lineage depth exceeds limit")
    if len(parent_proof_ids) > MAX_LINEAGE_FANOUT:
        raise LineageValidationError("lineage fan-out exceeds limit")
    if not actor_address:
        raise LineageValidationError("actorAddress is required")
    
    # Cycle detection: check if output_digest appears in parents
    if output_digest and output_digest in parent_proof_ids:
        raise LineageValidationError("lineage cycle detected: output digest appears in parents")
    
    # Transitive cycle detection: check if any parent has this output as ancestor
    if output_digest and get_lineage_fn:
        for parent_id in parent_proof_ids:
            if _contains_in_ancestry(parent_id, output_digest, get_lineage_fn):
                raise LineageValidationError("lineage cycle detected: would create circular dependency")


def _contains_in_ancestry(
    proof_id: str,
    target: str,
    get_lineage_fn: Any,
    visited: set[str] | None = None,
) -> bool:
    """Check if target appears in the ancestry of proof_id.
    
    Args:
        proof_id: Starting proof ID
        target: Target proof ID to search for
        get_lineage_fn: Function to query lineage records
        visited: Set of already visited IDs (to prevent infinite loops)
    
    Returns:
        True if target is found in ancestry, False otherwise
    """
    if visited is None:
        visited = set()
    
    if proof_id in visited:
        return False
    visited.add(proof_id)
    
    if proof_id == target:
        return True
    
    # Query the lineage record for this proof_id
    record = get_lineage_fn(proof_id)
    if not record:
        return False
    
    # Check all parents recursively
    parents = record.get("parent_proof_ids", [])
    for parent_id in parents:
        if _contains_in_ancestry(parent_id, target, get_lineage_fn, visited):
            return True
    
    return False


def _is_hex_32(value: str) -> bool:
    return len(value) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def load_interoperability_corpus(
    corpus_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Load and validate the offline C2PA + lineage interoperability corpus."""
    target = Path(corpus_path) if corpus_path is not None else DEFAULT_INTEROP_CORPUS_PATH
    raw_bytes = target.read_bytes()
    if len(raw_bytes) > MAX_INTEROP_CORPUS_BYTES:
        raise LineageValidationError("interoperability corpus exceeds maximum byte limit")

    try:
        corpus = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LineageValidationError("interoperability corpus must be valid UTF-8 JSON") from exc

    if not isinstance(corpus, dict):
        raise LineageValidationError("interoperability corpus root must be an object")
    if corpus.get("corpus_version") != INTEROP_CORPUS_VERSION:
        raise LineageValidationError("unsupported interoperability corpus_version")
    if corpus.get("offline_only") is not True:
        raise LineageValidationError("interoperability corpus must declare offline_only=true")

    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        raise LineageValidationError("interoperability corpus must contain a non-empty cases list")

    seen_ids: set[str] = set()
    for idx, item in enumerate(cases):
        if not isinstance(item, dict):
            raise LineageValidationError(f"corpus case[{idx}] must be an object")
        case_id = item.get("case_id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise LineageValidationError(f"corpus case[{idx}] missing case_id")
        if case_id in seen_ids:
            raise LineageValidationError(f"duplicate corpus case_id: {case_id}")
        seen_ids.add(case_id)

    return corpus


def evaluate_interoperability_case(case: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one offline C2PA + lineage interoperability case deterministically."""
    if not isinstance(case, dict):
        raise LineageValidationError("interoperability case must be a JSON object")
    case_id = str(case.get("case_id", "")).strip()
    if not case_id:
        raise LineageValidationError("interoperability case requires case_id")

    c2pa_raw = case.get("c2pa_manifest")
    manifest_digest: str | None = None
    c2pa_ok = False
    c2pa_trust_status = C2paTrustStatus.PARSE_FAILED.value
    c2pa_error: dict[str, str | None] | None = None
    unknown_assertion_labels: list[str] = []
    parsed_c2pa = None

    if isinstance(c2pa_raw, dict):
        canonical_bytes = json.dumps(
            c2pa_raw, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        try:
            parsed_c2pa = parse_c2pa_manifest(canonical_bytes)
            c2pa_ok = True
            c2pa_trust_status = parsed_c2pa.trust_status.value
            manifest_digest = hashlib.sha256(canonical_bytes).hexdigest()
            unknown_assertion_labels = [ua.label for ua in parsed_c2pa.unknown_assertions]
        except C2paParseError as exc:
            c2pa_error = exc.to_dict()
    elif isinstance(c2pa_raw, str):
        try:
            parsed_c2pa = parse_c2pa_manifest(c2pa_raw)
            c2pa_ok = True
            c2pa_trust_status = parsed_c2pa.trust_status.value
            manifest_digest = hashlib.sha256(c2pa_raw.encode("utf-8")).hexdigest()
            unknown_assertion_labels = [ua.label for ua in parsed_c2pa.unknown_assertions]
        except C2paParseError as exc:
            c2pa_error = exc.to_dict()
    else:
        c2pa_error = {"reason": "not_object", "field": "c2pa_manifest"}

    raw_ingredients = case.get("ingredients")
    if raw_ingredients is None and isinstance(c2pa_raw, dict):
        raw_ingredients = c2pa_raw.get("ingredients", [])
    if not isinstance(raw_ingredients, list):
        raw_ingredients = []

    ingredient_evals = [
        evaluate_c2pa_ingredient(entry, index=idx)
        for idx, entry in enumerate(raw_ingredients)
    ]
    supported_evals = [ev for ev in ingredient_evals if ev.supported]
    unsupported_evals = [ev for ev in ingredient_evals if not ev.supported]
    supported_proof_ids = {
        ev.proof_id.lower() for ev in supported_evals if ev.proof_id is not None
    }

    lineage_raw = case.get("lineage_manifest")
    lineage_status = "not_applicable"
    lineage_digest: str | None = None
    lineage_error: str | None = None

    if lineage_raw is not None:
        if not isinstance(lineage_raw, dict):
            lineage_status = "invalid"
            lineage_error = "lineage manifest must be a JSON object"
        else:
            try:
                canonical_lineage_manifest(lineage_raw)
                lineage_digest = lineage_manifest_digest(lineage_raw)
                validate_lineage_graph(
                    parent_proof_ids=lineage_raw["parentProofIds"],
                    depth=int(case.get("lineage_depth", 1)),
                    actor_address=str(lineage_raw["actorAddress"]),
                    output_digest=str(lineage_raw["outputDigest"]),
                )
                require_binding = bool(case.get("require_ingredient_binding", True))
                if c2pa_ok and parsed_c2pa is not None and require_binding:
                    declared_parents = [
                        str(pid).lower() for pid in lineage_raw["parentProofIds"]
                    ]
                    if str(lineage_raw["outputDigest"]).lower() != parsed_c2pa.binding.video_hash:
                        lineage_status = "output_binding_mismatch"
                    elif any(pid not in supported_proof_ids for pid in declared_parents):
                        lineage_status = "parent_binding_mismatch"
                    else:
                        lineage_status = "valid"
                else:
                    lineage_status = "valid"
            except LineageValidationError as exc:
                lineage_status = "invalid"
                lineage_error = str(exc)

    overall_ok = bool(c2pa_ok and lineage_status in ("valid", "not_applicable"))

    return {
        "case_id": case_id,
        "ok": overall_ok,
        "c2pa_ok": c2pa_ok,
        "c2pa_trust_status": c2pa_trust_status,
        "c2pa_error": c2pa_error,
        "manifest_digest": manifest_digest,
        "unknown_assertion_labels": unknown_assertion_labels,
        "supported_ingredient_count": len(supported_evals),
        "unsupported_ingredient_count": len(unsupported_evals),
        "unsupported_reasons": [ev.reason for ev in unsupported_evals],
        "ingredients": [ev.to_dict() for ev in ingredient_evals],
        "lineage_status": lineage_status,
        "lineage_digest": lineage_digest,
        "lineage_error": lineage_error,
    }


def run_interoperability_corpus(
    corpus_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Execute all offline interoperability corpus cases and verify expectations."""
    corpus = load_interoperability_corpus(corpus_path)
    case_results: list[dict[str, Any]] = []
    passed_count = 0

    for case in corpus["cases"]:
        actual = evaluate_interoperability_case(case)
        expected = case.get("expected", {})
        mismatches: list[str] = []

        checked_fields = (
            "ok",
            "c2pa_trust_status",
            "supported_ingredient_count",
            "unsupported_ingredient_count",
            "unsupported_reasons",
            "lineage_status",
            "manifest_digest",
            "lineage_digest",
        )
        for key in checked_fields:
            if key in expected and actual.get(key) != expected[key]:
                mismatches.append(key)

        if "c2pa_error_reason" in expected:
            actual_reason = actual["c2pa_error"]["reason"] if actual["c2pa_error"] else None
            if actual_reason != expected["c2pa_error_reason"]:
                mismatches.append("c2pa_error_reason")

        if "c2pa_error_field" in expected:
            actual_field = actual["c2pa_error"]["field"] if actual["c2pa_error"] else None
            if actual_field != expected["c2pa_error_field"]:
                mismatches.append("c2pa_error_field")

        matched = len(mismatches) == 0
        if matched:
            passed_count += 1

        case_results.append(
            {
                "case_id": actual["case_id"],
                "matched_expected": matched,
                "mismatched_fields": mismatches,
                "actual": actual,
            }
        )

    return {
        "corpus_version": corpus["corpus_version"],
        "total_cases": len(case_results),
        "passed_cases": passed_count,
        "all_passed": passed_count == len(case_results),
        "results": case_results,
    }
