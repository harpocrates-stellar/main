from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from strkey import validate_contract_id

SUPPORTED_OPERATIONS = {"crop", "transcode", "blur", "redact", "compose"}
MAX_LINEAGE_DEPTH = 4
MAX_LINEAGE_FANOUT = 4
MAX_LINEAGE_PAYLOAD_BYTES = 4096
MAX_NETWORK_REPORT_NODES = 64
MAX_NETWORK_REPORT_EDGES = 128

_STELLAR_NETWORK_ALIASES: dict[str, str] = {
    "testnet": "testnet",
    "test sdf network ; september 2015": "testnet",
    "mainnet": "mainnet",
    "pubnet": "mainnet",
    "public": "mainnet",
    "public global stellar network ; september 2015": "mainnet",
    "futurenet": "futurenet",
    "test sdf future network ; october 2022": "futurenet",
    "standalone": "standalone",
    "local": "standalone",
    "standalone network ; february 2017": "standalone",
}


class LineageValidationError(ValueError):
    pass


class LineageNetworkMismatchError(LineageValidationError):
    """Raised when a lineage edge mixes incompatible network or contract bindings."""

    def __init__(self, reason: str, *, parent_id: str | None = None, child_id: str | None = None) -> None:
        self.reason = reason
        self.parent_id = parent_id
        self.child_id = child_id
        super().__init__(f"incompatible lineage endpoint binding: {reason}")


@dataclass(frozen=True)
class LineageNetworkBindingReport:
    """Bounded graph evaluation preserving valid branches while rejecting incompatible edges."""

    all_valid: bool
    valid_nodes: tuple[dict[str, Any], ...]
    valid_edges: tuple[dict[str, Any], ...]
    rejected_edges: tuple[dict[str, Any], ...]
    rejected_nodes: tuple[dict[str, Any], ...]
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "all_valid": self.all_valid,
            "valid_nodes": [dict(n) for n in self.valid_nodes],
            "valid_edges": [dict(e) for e in self.valid_edges],
            "rejected_edges": [dict(e) for e in self.rejected_edges],
            "rejected_nodes": [dict(n) for n in self.rejected_nodes],
            "truncated": self.truncated,
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
    raw_contract = manifest.get("contractId") if "contractId" in manifest else manifest.get("contract_id")
    if raw_contract is not None:
        normalized["contractId"] = normalize_contract_binding(raw_contract, required=True)
    return json.dumps(normalized, separators=(",", ":"), sort_keys=True)


def lineage_manifest_digest(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_lineage_manifest(manifest).encode("utf-8")).hexdigest()


def validate_lineage_graph(
    parent_proof_ids: list[str],
    depth: int,
    actor_address: str,
    output_digest: str | None = None,
    get_lineage_fn: Any = None,
    *,
    network: str | None = None,
    contract_id: str | None = None,
) -> None:
    """Validate lineage graph constraints.
    
    Args:
        parent_proof_ids: List of parent proof IDs
        depth: Current depth in the lineage tree
        actor_address: Address of the actor submitting the lineage
        output_digest: Output digest of the current lineage record (for cycle detection)
        get_lineage_fn: Optional function to query lineage records (for cycle detection)
        network: Optional child network identity to validate against resolved parents
        contract_id: Optional child Soroban contract ID to validate against resolved parents
    
    Raises:
        LineageValidationError: If validation fails
    """
    if depth > MAX_LINEAGE_DEPTH:
        raise LineageValidationError("lineage depth exceeds limit")
    if len(parent_proof_ids) > MAX_LINEAGE_FANOUT:
        raise LineageValidationError("lineage fan-out exceeds limit")
    if not actor_address:
        raise LineageValidationError("actorAddress is required")

    norm_child_net = normalize_network_identity(network) if network is not None else None
    norm_child_contract = (
        normalize_contract_binding(contract_id, required=True)
        if contract_id is not None
        else None
    )
    
    # Cycle detection: check if output_digest appears in parents
    if output_digest and output_digest in parent_proof_ids:
        raise LineageValidationError("lineage cycle detected: output digest appears in parents")
    
    # Transitive cycle detection & endpoint network/contract compatibility
    if get_lineage_fn:
        for parent_id in parent_proof_ids:
            if output_digest and _contains_in_ancestry(parent_id, output_digest, get_lineage_fn):
                raise LineageValidationError("lineage cycle detected: would create circular dependency")
            parent_rec = get_lineage_fn(parent_id)
            if isinstance(parent_rec, dict) and (
                norm_child_net is not None or norm_child_contract is not None
            ):
                p_manifest = (
                    parent_rec.get("manifest")
                    if isinstance(parent_rec.get("manifest"), dict)
                    else parent_rec
                )
                p_net_raw = p_manifest.get("network") or parent_rec.get("network")
                p_contract_raw = (
                    p_manifest.get("contractId")
                    or p_manifest.get("contract_id")
                    or parent_rec.get("contractId")
                    or parent_rec.get("contract_id")
                )
                if norm_child_net is not None and p_net_raw is not None:
                    p_net = normalize_network_identity(p_net_raw)
                    if p_net != norm_child_net:
                        raise LineageNetworkMismatchError(
                            "network_mismatch",
                            parent_id=parent_id,
                            child_id=output_digest,
                        )
                if norm_child_contract is not None or p_contract_raw is not None:
                    if norm_child_contract is None or p_contract_raw is None:
                        raise LineageNetworkMismatchError(
                            "missing_contract_binding",
                            parent_id=parent_id,
                            child_id=output_digest,
                        )
                    p_contract = normalize_contract_binding(p_contract_raw, required=True)
                    if p_contract != norm_child_contract:
                        raise LineageNetworkMismatchError(
                            "contract_mismatch",
                            parent_id=parent_id,
                            child_id=output_digest,
                        )


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


def normalize_network_identity(network: Any) -> str:
    """Normalize a Stellar network identifier or passphrase to its canonical slug."""
    if not isinstance(network, str) or not network.strip():
        raise LineageValidationError("network must be a non-empty string")
    cleaned = " ".join(network.strip().lower().split())
    return _STELLAR_NETWORK_ALIASES.get(cleaned, cleaned)


def normalize_contract_binding(
    contract_id: Any,
    *,
    required: bool = True,
) -> str | None:
    """Validate and normalize a Soroban C-contract ID binding."""
    if contract_id is None:
        if required:
            raise LineageValidationError("contractId binding is required")
        return None
    if not isinstance(contract_id, str) or not contract_id.strip():
        raise LineageValidationError("contractId must be a valid Stellar C-contract ID")
    try:
        validated = validate_contract_id(contract_id)
    except ValueError as exc:
        raise LineageValidationError("contractId must be a valid Stellar C-contract ID") from exc
    if not validated:
        raise LineageValidationError("contractId must be a valid Stellar C-contract ID")
    return validated


def _extract_endpoint_identity(endpoint: dict[str, Any]) -> tuple[str, str, str]:
    """Return ``(node_id, canonical_network, canonical_contract_id)`` for one endpoint."""
    if not isinstance(endpoint, dict):
        raise LineageValidationError("endpoint must be a JSON object")
    src = endpoint.get("manifest") if isinstance(endpoint.get("manifest"), dict) else endpoint
    raw_id = (
        src.get("outputDigest")
        or src.get("output_digest")
        or src.get("proof_id")
        or src.get("proofId")
        or src.get("node_id")
        or src.get("nodeId")
    )
    if not isinstance(raw_id, str) or not _is_hex_32(raw_id):
        raise LineageValidationError("endpoint requires a 32-byte hex identifier")
    node_id = raw_id.lower()

    raw_net = src.get("network") if "network" in src else endpoint.get("network")
    norm_net = normalize_network_identity(raw_net)

    raw_contract = (
        src.get("contractId")
        or src.get("contract_id")
        or endpoint.get("contractId")
        or endpoint.get("contract_id")
    )
    norm_contract = normalize_contract_binding(raw_contract, required=True)
    assert norm_contract is not None
    return node_id, norm_net, norm_contract


def validate_lineage_edge_binding(
    parent_endpoint: dict[str, Any],
    child_endpoint: dict[str, Any],
) -> dict[str, str]:
    """Validate that parent and child lineage endpoints share network and contract bindings."""
    p_id, p_net, p_contract = _extract_endpoint_identity(parent_endpoint)
    c_id, c_net, c_contract = _extract_endpoint_identity(child_endpoint)

    if p_net != c_net:
        raise LineageNetworkMismatchError(
            "network_mismatch",
            parent_id=p_id,
            child_id=c_id,
        )
    if p_contract != c_contract:
        raise LineageNetworkMismatchError(
            "contract_mismatch",
            parent_id=p_id,
            child_id=c_id,
        )

    return {
        "parent_id": p_id,
        "child_id": c_id,
        "network": c_net,
        "contract_id": c_contract,
    }


def evaluate_lineage_network_bindings(
    lineage_nodes: list[dict[str, Any]],
    *,
    root_endpoints: list[dict[str, Any]] | dict[str, dict[str, Any]] | None = None,
    max_nodes: int = MAX_NETWORK_REPORT_NODES,
    max_edges: int = MAX_NETWORK_REPORT_EDGES,
) -> LineageNetworkBindingReport:
    """Evaluate network and contract compatibility across a multi-branch lineage graph.

    Incompatible edges (and their downstream dependent derivatives) are rejected
    explicitly while valid unrelated branches are preserved in a bounded report.
    """
    if not isinstance(lineage_nodes, list):
        raise LineageValidationError("lineage_nodes must be a list")

    truncated = False
    bounded_nodes = lineage_nodes
    if len(lineage_nodes) > max_nodes:
        bounded_nodes = lineage_nodes[:max_nodes]
        truncated = True

    roots_by_id: dict[str, tuple[str | None, str | None, str | None]] = {}
    raw_roots: list[dict[str, Any]] = []
    if isinstance(root_endpoints, dict):
        for k, v in root_endpoints.items():
            if isinstance(v, dict):
                raw_roots.append({"node_id": k, **v})
    elif isinstance(root_endpoints, list):
        raw_roots = [r for r in root_endpoints if isinstance(r, dict)]

    for root in raw_roots:
        rid_raw = (
            root.get("node_id")
            or root.get("nodeId")
            or root.get("proof_id")
            or root.get("proofId")
            or root.get("outputDigest")
        )
        if not isinstance(rid_raw, str) or not _is_hex_32(rid_raw):
            continue
        rid = rid_raw.lower()
        try:
            _, r_net, r_contract = _extract_endpoint_identity({**root, "node_id": rid})
            roots_by_id[rid] = (r_net, r_contract, None)
        except LineageValidationError as exc:
            err_msg = str(exc)
            reason = (
                "invalid_contract_binding"
                if "contractId" in err_msg
                else "invalid_network_binding"
            )
            roots_by_id[rid] = (None, None, reason)

    derivatives_raw: dict[str, dict[str, Any]] = {}
    rejected_nodes: list[dict[str, Any]] = []
    rejected_edges: list[dict[str, Any]] = []
    valid_nodes: list[dict[str, Any]] = []
    valid_edges: list[dict[str, Any]] = []

    for rec in bounded_nodes:
        if not isinstance(rec, dict):
            continue
        m_src = rec.get("manifest") if isinstance(rec.get("manifest"), dict) else rec
        out_raw = m_src.get("outputDigest") or rec.get("output_digest")
        if not isinstance(out_raw, str) or not _is_hex_32(out_raw):
            continue
        derivatives_raw[out_raw.lower()] = rec

    memo_state: dict[str, tuple[bool, str | None, str | None]] = {}
    visiting: set[str] = set()

    def _record_rejected_edge(parent_id: str, child_id: str, reason: str) -> None:
        nonlocal truncated
        if len(rejected_edges) >= max_edges:
            truncated = True
            return
        rejected_edges.append(
            {
                "parent_id": parent_id,
                "child_id": child_id,
                "reason": reason,
            }
        )

    def _evaluate_node(node_id: str) -> tuple[bool, str | None, str | None]:
        if node_id in memo_state:
            return memo_state[node_id]
        if node_id in visiting:
            rejected_nodes.append({"node_id": node_id, "reason": "cycle_detected"})
            memo_state[node_id] = (False, None, None)
            return memo_state[node_id]

        visiting.add(node_id)
        rec = derivatives_raw[node_id]
        m_src = rec.get("manifest") if isinstance(rec.get("manifest"), dict) else rec

        try:
            canonical_lineage_manifest(m_src)
            _, c_net, c_contract = _extract_endpoint_identity(rec)
        except LineageValidationError as exc:
            msg = str(exc)
            reason = (
                "invalid_contract_binding"
                if "contractId" in msg
                else "invalid_endpoint_manifest"
            )
            rejected_nodes.append({"node_id": node_id, "reason": reason})
            visiting.remove(node_id)
            memo_state[node_id] = (False, None, None)
            return memo_state[node_id]

        parents = [str(p).lower() for p in m_src.get("parentProofIds", [])]
        node_ok = True
        local_valid_edges: list[dict[str, Any]] = []

        for pid in parents:
            if pid == node_id:
                _record_rejected_edge(pid, node_id, "cycle_detected")
                node_ok = False
                continue

            if pid in derivatives_raw:
                p_ok, p_net, p_contract = _evaluate_node(pid)
                if not p_ok or p_net is None or p_contract is None:
                    _record_rejected_edge(pid, node_id, "tainted_parent_branch")
                    node_ok = False
                    continue
            elif pid in roots_by_id:
                p_net, p_contract, r_err = roots_by_id[pid]
                if r_err is not None or p_net is None or p_contract is None:
                    _record_rejected_edge(pid, node_id, r_err or "invalid_parent_binding")
                    node_ok = False
                    continue
            else:
                _record_rejected_edge(pid, node_id, "missing_parent_binding")
                node_ok = False
                continue

            if p_net != c_net:
                _record_rejected_edge(pid, node_id, "network_mismatch")
                node_ok = False
            elif p_contract != c_contract:
                _record_rejected_edge(pid, node_id, "contract_mismatch")
                node_ok = False
            else:
                local_valid_edges.append(
                    {
                        "parent_id": pid,
                        "child_id": node_id,
                        "network": c_net,
                        "contract_id": c_contract,
                    }
                )

        visiting.remove(node_id)
        if node_ok:
            valid_nodes.append(
                {
                    "node_id": node_id,
                    "network": c_net,
                    "contract_id": c_contract,
                }
            )
            for edge in local_valid_edges:
                if len(valid_edges) < max_edges:
                    valid_edges.append(edge)
                else:
                    truncated = True
            memo_state[node_id] = (True, c_net, c_contract)
        else:
            rejected_nodes.append(
                {
                    "node_id": node_id,
                    "reason": "incompatible_or_invalid_edge",
                }
            )
            memo_state[node_id] = (False, None, None)

        return memo_state[node_id]

    for nid in sorted(derivatives_raw.keys()):
        _evaluate_node(nid)

    valid_nodes_sorted = sorted(valid_nodes, key=lambda x: x["node_id"])
    valid_edges_sorted = sorted(valid_edges, key=lambda x: (x["child_id"], x["parent_id"]))
    rejected_nodes_sorted = sorted(rejected_nodes, key=lambda x: x["node_id"])
    rejected_edges_sorted = sorted(
        rejected_edges, key=lambda x: (x["child_id"], x["parent_id"], x["reason"])
    )

    return LineageNetworkBindingReport(
        all_valid=len(rejected_nodes_sorted) == 0 and len(rejected_edges_sorted) == 0 and not truncated,
        valid_nodes=tuple(valid_nodes_sorted),
        valid_edges=tuple(valid_edges_sorted),
        rejected_edges=tuple(rejected_edges_sorted),
        rejected_nodes=tuple(rejected_nodes_sorted),
        truncated=truncated,
    )
