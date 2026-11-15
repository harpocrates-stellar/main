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
MAX_LINEAGE_GRAPH_NODES = 64


class LineageValidationError(ValueError):
    pass


@dataclass(frozen=True)
class LineageNodeConflict:
    """Explicit privacy-safe report for a duplicate ancestry node conflict."""

    node_id: str
    first_canonical_digest: str
    conflicting_canonical_digest: str
    differing_fields: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "first_canonical_digest": self.first_canonical_digest,
            "conflicting_canonical_digest": self.conflicting_canonical_digest,
            "differing_fields": list(self.differing_fields),
        }


class LineageDuplicateConflictError(LineageValidationError):
    """Raised when the same ancestry node identifier carries conflicting canonical contents."""

    def __init__(self, conflicts: list[LineageNodeConflict] | tuple[LineageNodeConflict, ...]) -> None:
        if not conflicts:
            raise ValueError("conflicts must be non-empty")
        self.conflicts: tuple[LineageNodeConflict, ...] = tuple(conflicts)
        node_ids = ", ".join(c.node_id for c in self.conflicts)
        super().__init__(f"conflicting duplicate ancestry node(s) detected: {node_ids}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": "CONFLICTING_DUPLICATE_ANCESTRY_NODE",
            "conflicts": [c.to_dict() for c in self.conflicts],
        }


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
    ancestry_nodes: list[dict[str, Any]] | None = None,
) -> None:
    """Validate lineage graph constraints.
    
    Args:
        parent_proof_ids: List of parent proof IDs
        depth: Current depth in the lineage tree
        actor_address: Address of the actor submitting the lineage
        output_digest: Output digest of the current lineage record (for cycle detection)
        get_lineage_fn: Optional function to query lineage records (for cycle detection)
        ancestry_nodes: Optional ancestry node payloads checked for duplicate conflicts
    
    Raises:
        LineageValidationError: If validation fails
    """
    if ancestry_nodes is not None:
        conflicts = detect_conflicting_ancestry_nodes(ancestry_nodes)
        if conflicts:
            raise LineageDuplicateConflictError(conflicts)

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


def _canonicalize_ancestry_node(
    node: dict[str, Any],
) -> tuple[str, dict[str, Any], str]:
    """Normalize an ancestry node into ``(node_id, canonical_fields, canonical_digest)``."""
    if not isinstance(node, dict):
        raise LineageValidationError("ancestry node must be a JSON object")

    manifest_source = node.get("manifest") if isinstance(node.get("manifest"), dict) else node

    if "operationType" in manifest_source:
        raw_copy = dict(manifest_source)
        if isinstance(raw_copy.get("outputDigest"), str) and _is_hex_32(raw_copy["outputDigest"]):
            raw_copy["outputDigest"] = raw_copy["outputDigest"].lower()
        if isinstance(raw_copy.get("parametersDigest"), str) and _is_hex_32(raw_copy["parametersDigest"]):
            raw_copy["parametersDigest"] = raw_copy["parametersDigest"].lower()
        if isinstance(raw_copy.get("parentProofIds"), list):
            raw_copy["parentProofIds"] = [
                p.lower() if isinstance(p, str) and _is_hex_32(p) else p
                for p in raw_copy["parentProofIds"]
            ]

        canonical_str = canonical_lineage_manifest(raw_copy)
        canonical_map: dict[str, Any] = json.loads(canonical_str)
        node_id = str(canonical_map["outputDigest"]).lower()
        if not _is_hex_32(node_id):
            raise LineageValidationError("outputDigest must contain a 32-byte hex value")
        canonical_digest = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        declared_digest = node.get("manifest_digest") or node.get("manifestDigest")
        if declared_digest is not None:
            if not isinstance(declared_digest, str) or not _is_hex_32(declared_digest):
                raise LineageValidationError("manifest_digest must be a 32-byte hex value")
            if declared_digest.lower() != canonical_digest:
                raise LineageValidationError("manifest_digest does not match canonical manifest")

        return node_id, canonical_map, canonical_digest

    raw_id = (
        manifest_source.get("nodeId")
        or manifest_source.get("node_id")
        or manifest_source.get("proofId")
        or manifest_source.get("proof_id")
        or manifest_source.get("outputDigest")
        or manifest_source.get("output_digest")
    )
    if not isinstance(raw_id, str) or not _is_hex_32(raw_id):
        raise LineageValidationError("ancestry node identifier must be a 32-byte hex value")
    node_id = raw_id.lower()

    raw_parents = (
        manifest_source.get("parentProofIds")
        if "parentProofIds" in manifest_source
        else manifest_source.get("parent_proof_ids", [])
    )
    if not isinstance(raw_parents, list):
        raise LineageValidationError("ancestry node parentProofIds must be an array")
    if len(raw_parents) > MAX_LINEAGE_FANOUT:
        raise LineageValidationError("lineage fan-out exceeds limit")
    normalized_parents: list[str] = []
    for parent in raw_parents:
        if not isinstance(parent, str) or not _is_hex_32(parent):
            raise LineageValidationError("parentProofIds must contain 32-byte hex values")
        normalized_parents.append(parent.lower())

    canonical_root: dict[str, Any] = {
        "nodeType": "proof",
        "nodeId": node_id,
        "parentProofIds": normalized_parents,
    }

    field_aliases = (
        ("videoHash", ("videoHash", "video_hash"), True),
        ("metadataHash", ("metadataHash", "metadata_hash"), True),
        ("tier", ("tier",), False),
        ("network", ("network",), False),
        ("contractId", ("contractId", "contract_id"), False),
        ("actorAddress", ("actorAddress", "actor_address"), False),
    )
    for canonical_key, candidates, is_hex in field_aliases:
        for candidate in candidates:
            if candidate in manifest_source and manifest_source[candidate] is not None:
                val = manifest_source[candidate]
                if not isinstance(val, str):
                    raise LineageValidationError(f"invalid type for ancestry field: {canonical_key}")
                cleaned = val.strip()
                if is_hex:
                    if not _is_hex_32(cleaned):
                        raise LineageValidationError(f"invalid hex digest for ancestry field: {canonical_key}")
                    cleaned = cleaned.lower()
                canonical_root[canonical_key] = cleaned
                break

    canonical_bytes = json.dumps(
        canonical_root, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    if len(canonical_bytes) > MAX_LINEAGE_PAYLOAD_BYTES:
        raise LineageValidationError("ancestry node payload is too large")
    canonical_digest = hashlib.sha256(canonical_bytes).hexdigest()
    return node_id, canonical_root, canonical_digest


def detect_conflicting_ancestry_nodes(
    nodes: list[dict[str, Any]],
) -> list[LineageNodeConflict]:
    """Detect ancestry nodes sharing an identifier with different canonical contents.

    Exact canonical repeats (same identifier and identical canonical digest) are
    treated as idempotent duplicates and produce no conflict.
    """
    if not isinstance(nodes, list):
        raise LineageValidationError("ancestry nodes must be a list")

    first_seen: dict[str, tuple[str, dict[str, Any]]] = {}
    conflicts: list[LineageNodeConflict] = []
    seen_conflict_pairs: set[tuple[str, str, str]] = set()

    for node in nodes:
        node_id, canonical_map, canonical_digest = _canonicalize_ancestry_node(node)
        if node_id not in first_seen:
            first_seen[node_id] = (canonical_digest, canonical_map)
            continue

        first_digest, first_map = first_seen[node_id]
        if canonical_digest == first_digest:
            continue

        pair_key = (node_id, first_digest, canonical_digest)
        if pair_key in seen_conflict_pairs:
            continue
        seen_conflict_pairs.add(pair_key)

        all_keys = sorted(set(first_map.keys()) | set(canonical_map.keys()))
        differing = tuple(
            key for key in all_keys if first_map.get(key) != canonical_map.get(key)
        )
        conflicts.append(
            LineageNodeConflict(
                node_id=node_id,
                first_canonical_digest=first_digest,
                conflicting_canonical_digest=canonical_digest,
                differing_fields=differing,
            )
        )

    return conflicts


def build_lineage_graph_view(
    nodes: list[dict[str, Any]],
    *,
    max_nodes: int = MAX_LINEAGE_GRAPH_NODES,
) -> dict[str, Any]:
    """Validate duplicate ancestry invariants before constructing a lineage graph view.

    Raises:
        LineageDuplicateConflictError: When duplicate identifiers carry conflicting
            canonical contents (raised strictly before graph edges are built).
        LineageValidationError: On malformed payloads, oversized graphs, or cycles.
    """
    if not isinstance(nodes, list):
        raise LineageValidationError("ancestry nodes must be a list")
    if len(nodes) > max_nodes:
        raise LineageValidationError("ancestry node count exceeds limit")

    conflicts = detect_conflicting_ancestry_nodes(nodes)
    if conflicts:
        raise LineageDuplicateConflictError(conflicts)

    deduped_by_id: dict[str, tuple[dict[str, Any], str]] = {}
    deduplicated_count = 0
    for node in nodes:
        node_id, canonical_map, canonical_digest = _canonicalize_ancestry_node(node)
        if node_id in deduped_by_id:
            deduplicated_count += 1
            continue
        deduped_by_id[node_id] = (canonical_map, canonical_digest)

    def _lookup_record(pid: str) -> dict[str, Any] | None:
        entry = deduped_by_id.get(pid.lower())
        if entry is None:
            return None
        return {"parent_proof_ids": list(entry[0].get("parentProofIds", []))}

    for node_id, (canonical_map, _digest) in deduped_by_id.items():
        parents = list(canonical_map.get("parentProofIds", []))
        if node_id in parents:
            raise LineageValidationError("lineage cycle detected: output digest appears in parents")
        for parent_id in parents:
            if _contains_in_ancestry(parent_id, node_id, _lookup_record):
                raise LineageValidationError("lineage cycle detected: would create circular dependency")

    graph_nodes: list[dict[str, Any]] = []
    graph_edges: list[dict[str, str]] = []
    for node_id in sorted(deduped_by_id.keys()):
        canonical_map, canonical_digest = deduped_by_id[node_id]
        parents = list(canonical_map.get("parentProofIds", []))
        node_summary: dict[str, Any] = {
            "node_id": node_id,
            "canonical_digest": canonical_digest,
            "parent_proof_ids": parents,
        }
        if "operationType" in canonical_map:
            node_summary["operation_type"] = canonical_map["operationType"]
        graph_nodes.append(node_summary)
        for parent_id in parents:
            graph_edges.append(
                {
                    "parent_id": parent_id,
                    "child_id": node_id,
                    "canonical_digest": canonical_digest,
                }
            )

    return {
        "nodes": graph_nodes,
        "edges": graph_edges,
        "deduplicated_count": deduplicated_count,
    }
