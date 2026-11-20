from __future__ import annotations

import hashlib
import json
import os
from typing import Any

SUPPORTED_OPERATIONS = {"crop", "transcode", "blur", "redact", "compose"}
MAX_LINEAGE_DEPTH = 4
MAX_LINEAGE_FANOUT = 4
MAX_LINEAGE_PAYLOAD_BYTES = 4096
MAX_LINEAGE_REPORT_ENTRIES = 50


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


def _normalize_optional_binding(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise LineageValidationError(f"{field_name} must be a non-empty string")
    return value.strip()


def _extract_binding(record: dict[str, Any]) -> tuple[str | None, str | None]:
    """Extract (network, contract_id) from a lineage record or manifest."""
    if not isinstance(record, dict):
        return None, None
    manifest = record.get("manifest") if isinstance(record.get("manifest"), dict) else {}
    raw_network = record.get("network") if "network" in record else manifest.get("network")
    raw_contract = (
        record.get("contractId")
        if "contractId" in record
        else record.get("contract_id")
        if "contract_id" in record
        else manifest.get("contractId")
        if "contractId" in manifest
        else manifest.get("contract_id")
    )
    network = raw_network.strip() if isinstance(raw_network, str) and raw_network.strip() else None
    contract_id = raw_contract.strip() if isinstance(raw_contract, str) and raw_contract.strip() else None
    return network, contract_id


def _validate_edge_binding(
    *,
    parent_id: str,
    parent_record: dict[str, Any],
    child_network: str | None,
    child_contract_id: str | None,
) -> None:
    """Validate that parent and child endpoints share compatible network and contract bindings."""
    parent_network, parent_contract_id = _extract_binding(parent_record)

    if child_network is not None and parent_network is not None and parent_network != child_network:
        raise LineageValidationError(
            f"lineage network mismatch: parent {parent_id} is bound to {parent_network!r}, expected {child_network!r}"
        )

    if child_contract_id is not None and parent_contract_id is not None and parent_contract_id != child_contract_id:
        raise LineageValidationError(
            f"lineage contract binding mismatch: parent {parent_id} is bound to {parent_contract_id!r}, expected {child_contract_id!r}"
        )


def validate_lineage_edges_report(
    parent_proof_ids: list[str],
    *,
    get_lineage_fn: Any,
    network: str | None = None,
    contract_id: str | None = None,
    max_entries: int = MAX_LINEAGE_REPORT_ENTRIES,
) -> dict[str, Any]:
    """Evaluate lineage edges and return a bounded report preserving valid unrelated branches.

    Args:
        parent_proof_ids: Candidate parent proof IDs to evaluate.
        get_lineage_fn: Callable returning the lineage record for a proof ID (or None).
        network: Child endpoint network identifier/passphrase.
        contract_id: Child endpoint Soroban contract ID.
        max_entries: Maximum number of entries to include per list in the report.

    Returns:
        A dict with ``valid_branches``, ``rejected_edges``, ``total_evaluated``,
        and ``truncated`` indicating whether the report was bounded.
    """
    norm_network = _normalize_optional_binding(network, "network")
    norm_contract_id = _normalize_optional_binding(contract_id, "contractId")
    limit = max(1, min(max_entries, MAX_LINEAGE_REPORT_ENTRIES))

    valid_branches: list[str] = []
    rejected_edges: list[dict[str, str]] = []
    truncated = False

    for parent_id in parent_proof_ids:
        parent_record = get_lineage_fn(parent_id) if get_lineage_fn else None
        if not parent_record:
            if len(valid_branches) < limit:
                valid_branches.append(parent_id)
            else:
                truncated = True
            continue

        try:
            _validate_edge_binding(
                parent_id=parent_id,
                parent_record=parent_record,
                child_network=norm_network,
                child_contract_id=norm_contract_id,
            )
        except LineageValidationError as exc:
            if len(rejected_edges) < limit:
                rejected_edges.append({"parentProofId": parent_id, "reason": str(exc)})
            else:
                truncated = True
        else:
            if len(valid_branches) < limit:
                valid_branches.append(parent_id)
            else:
                truncated = True

    return {
        "valid_branches": valid_branches,
        "rejected_edges": rejected_edges,
        "total_evaluated": len(parent_proof_ids),
        "truncated": truncated,
    }
