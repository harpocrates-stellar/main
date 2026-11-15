from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

SUPPORTED_OPERATIONS = {"crop", "transcode", "blur", "redact", "compose"}
MAX_LINEAGE_DEPTH = 4
MAX_LINEAGE_FANOUT = 4
MAX_LINEAGE_PAYLOAD_BYTES = 4096
MAX_COMPARISON_NODES = 64


@dataclass(frozen=True)
class LineageGraphComparisonReport:
    """Deterministic comparison between two lineage/C2PA provenance graphs."""

    provenance_changed: bool
    ordering_changed: bool
    identical: bool
    added_assertions: tuple[dict[str, Any], ...]
    removed_assertions: tuple[dict[str, Any], ...]
    changed_assertions: tuple[dict[str, Any], ...]
    ordering_differences: tuple[dict[str, Any], ...]
    report_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "provenance_changed": self.provenance_changed,
            "ordering_changed": self.ordering_changed,
            "identical": self.identical,
            "added_assertions": [dict(item) for item in self.added_assertions],
            "removed_assertions": [dict(item) for item in self.removed_assertions],
            "changed_assertions": [dict(item) for item in self.changed_assertions],
            "ordering_differences": [dict(item) for item in self.ordering_differences],
            "report_digest": self.report_digest,
        }


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


def _normalize_lineage_node_assertion(
    raw_node: dict[str, Any],
    *,
    index: int,
) -> dict[str, Any]:
    if not isinstance(raw_node, dict):
        raise LineageValidationError("lineage comparison node must be a JSON object")

    manifest_src = raw_node.get("manifest") if isinstance(raw_node.get("manifest"), dict) else raw_node
    wire_str = canonical_lineage_manifest(manifest_src)
    wire_map = json.loads(wire_str)

    out_hex = str(wire_map["outputDigest"]).lower()
    if not _is_hex_32(out_hex):
        raise LineageValidationError("outputDigest must be a 32-byte hex value")

    ordered_parents = [str(p).lower() for p in wire_map["parentProofIds"]]
    if out_hex in ordered_parents:
        raise LineageValidationError("lineage cycle detected: output digest appears in parents")

    params_str = str(wire_map["parametersDigest"])
    if _is_hex_32(params_str):
        params_str = params_str.lower()

    wire_normalized = {
        **wire_map,
        "outputDigest": out_hex,
        "parametersDigest": params_str,
        "parentProofIds": ordered_parents,
    }
    wire_digest = hashlib.sha256(
        json.dumps(wire_normalized, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()

    provenance_normalized = {
        **wire_normalized,
        "parentProofIds": sorted(ordered_parents),
    }
    provenance_digest = hashlib.sha256(
        json.dumps(provenance_normalized, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()

    field_digests = {
        k: hashlib.sha256(
            json.dumps(v, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
        for k, v in provenance_normalized.items()
        if k not in ("protocol", "version")
    }

    return {
        "assertion_id": out_hex,
        "assertion_type": "lineage_manifest",
        "index": index,
        "canonical_digest": provenance_digest,
        "wire_digest": wire_digest,
        "ordered_parents": ordered_parents,
        "field_digests": field_digests,
    }


def _extract_graph_assertions(
    graph_input: list[dict[str, Any]] | dict[str, Any],
    *,
    max_nodes: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return ``(lineage_entries, c2pa_entries)`` after cycle and conflict validation."""
    from c2pa import C2paParseError, canonical_c2pa_assertion_digests

    lineage_raw: list[dict[str, Any]] = []
    c2pa_raw: Any = None

    if isinstance(graph_input, list):
        lineage_raw = graph_input
    elif isinstance(graph_input, dict):
        if "claim_generator" in graph_input and "harpocrates_binding" in graph_input:
            c2pa_raw = graph_input
            if isinstance(graph_input.get("lineage_nodes"), list):
                lineage_raw = graph_input["lineage_nodes"]
        else:
            nodes_field = graph_input.get("nodes", graph_input.get("events", []))
            if not isinstance(nodes_field, list):
                raise LineageValidationError("graph nodes must be a list")
            lineage_raw = nodes_field
            c2pa_raw = graph_input.get("c2pa_manifest")
    else:
        raise LineageValidationError("lineage graph input must be a list or JSON object")

    if len(lineage_raw) > max_nodes:
        raise LineageValidationError("lineage graph comparison exceeds maximum node limit")

    by_id: dict[str, dict[str, Any]] = {}
    ordered_lineage: list[dict[str, Any]] = []
    for idx, item in enumerate(lineage_raw):
        norm = _normalize_lineage_node_assertion(item, index=idx)
        aid = norm["assertion_id"]
        if aid in by_id:
            if by_id[aid]["canonical_digest"] != norm["canonical_digest"]:
                raise LineageValidationError(f"conflicting duplicate assertion in graph: {aid}")
            continue
        by_id[aid] = norm
        ordered_lineage.append(norm)

    def _lookup(pid: str) -> dict[str, Any] | None:
        rec = by_id.get(pid.lower())
        if rec is None:
            return None
        return {"parent_proof_ids": rec["ordered_parents"]}

    for aid, entry in by_id.items():
        for parent_id in entry["ordered_parents"]:
            if _contains_in_ancestry(parent_id, aid, _lookup):
                raise LineageValidationError("lineage cycle detected in comparison graph")

    c2pa_entries: list[dict[str, Any]] = []
    if c2pa_raw is not None:
        try:
            c2pa_entries = canonical_c2pa_assertion_digests(c2pa_raw)
        except C2paParseError as exc:
            raise LineageValidationError(f"invalid C2PA manifest in comparison: {exc.reason}") from exc

    return ordered_lineage, c2pa_entries


def compare_lineage_graphs(
    baseline_graph: list[dict[str, Any]] | dict[str, Any],
    candidate_graph: list[dict[str, Any]] | dict[str, Any],
    *,
    max_nodes: int = MAX_COMPARISON_NODES,
) -> LineageGraphComparisonReport:
    """Compare two lineage/C2PA provenance graphs deterministically by canonical digest."""
    base_lin, base_c2pa = _extract_graph_assertions(baseline_graph, max_nodes=max_nodes)
    cand_lin, cand_c2pa = _extract_graph_assertions(candidate_graph, max_nodes=max_nodes)

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    ordering_diffs: list[dict[str, Any]] = []

    def _diff_group(
        left_items: list[dict[str, Any]],
        right_items: list[dict[str, Any]],
        *,
        order_scope: str,
    ) -> None:
        left_map = {item["assertion_id"]: item for item in left_items}
        right_map = {item["assertion_id"]: item for item in right_items}

        for aid in sorted(set(right_map.keys()) - set(left_map.keys())):
            r_item = right_map[aid]
            added.append(
                {
                    "assertion_id": aid,
                    "assertion_type": r_item["assertion_type"],
                    "canonical_digest": r_item["canonical_digest"],
                }
            )

        for aid in sorted(set(left_map.keys()) - set(right_map.keys())):
            l_item = left_map[aid]
            removed.append(
                {
                    "assertion_id": aid,
                    "assertion_type": l_item["assertion_type"],
                    "canonical_digest": l_item["canonical_digest"],
                }
            )

        common_ids = sorted(set(left_map.keys()) & set(right_map.keys()))
        for aid in common_ids:
            l_item = left_map[aid]
            r_item = right_map[aid]
            if l_item["canonical_digest"] != r_item["canonical_digest"]:
                all_fkeys = sorted(
                    set(l_item["field_digests"].keys()) | set(r_item["field_digests"].keys())
                )
                diff_fields = [
                    fk
                    for fk in all_fkeys
                    if l_item["field_digests"].get(fk) != r_item["field_digests"].get(fk)
                ]
                changed.append(
                    {
                        "assertion_id": aid,
                        "assertion_type": r_item["assertion_type"],
                        "before_digest": l_item["canonical_digest"],
                        "after_digest": r_item["canonical_digest"],
                        "changed_fields": diff_fields,
                    }
                )
            elif l_item["wire_digest"] != r_item["wire_digest"]:
                ordering_diffs.append(
                    {
                        "scope": "parent_proof_ids",
                        "target_id": aid,
                        "before_wire_digest": l_item["wire_digest"],
                        "after_wire_digest": r_item["wire_digest"],
                    }
                )

        # Compare relative sequence order of common assertions.
        left_common_seq = [
            item["assertion_id"] for item in left_items if item["assertion_id"] in right_map
        ]
        right_common_seq = [
            item["assertion_id"] for item in right_items if item["assertion_id"] in left_map
        ]
        if left_common_seq != right_common_seq:
            ordering_diffs.append(
                {
                    "scope": order_scope,
                    "target_id": order_scope,
                    "before_order": left_common_seq,
                    "after_order": right_common_seq,
                }
            )

    _diff_group(base_lin, cand_lin, order_scope="graph_nodes")
    _diff_group(base_c2pa, cand_c2pa, order_scope="c2pa_assertions")

    added_sorted = sorted(added, key=lambda x: (x["assertion_type"], x["assertion_id"]))
    removed_sorted = sorted(removed, key=lambda x: (x["assertion_type"], x["assertion_id"]))
    changed_sorted = sorted(changed, key=lambda x: (x["assertion_type"], x["assertion_id"]))

    provenance_changed = bool(added_sorted or removed_sorted or changed_sorted)
    ordering_changed = bool(ordering_diffs)
    identical = not provenance_changed and not ordering_changed

    core_payload = {
        "provenance_changed": provenance_changed,
        "ordering_changed": ordering_changed,
        "identical": identical,
        "added_assertions": added_sorted,
        "removed_assertions": removed_sorted,
        "changed_assertions": changed_sorted,
        "ordering_differences": ordering_diffs,
    }
    report_digest = hashlib.sha256(
        json.dumps(core_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()

    return LineageGraphComparisonReport(
        provenance_changed=provenance_changed,
        ordering_changed=ordering_changed,
        identical=identical,
        added_assertions=tuple(added_sorted),
        removed_assertions=tuple(removed_sorted),
        changed_assertions=tuple(changed_sorted),
        ordering_differences=tuple(ordering_diffs),
        report_digest=report_digest,
    )
