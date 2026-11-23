from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

SUPPORTED_OPERATIONS = {"crop", "transcode", "blur", "redact", "compose"}
MAX_LINEAGE_DEPTH = 4
MAX_LINEAGE_FANOUT = 4
MAX_LINEAGE_PAYLOAD_BYTES = 4096
MAX_LINEAGE_REPORT_ENTRIES = 50

LINEAGE_BUNDLE_VERSION = 1
LINEAGE_COMPARISON_REPORT_VERSION = 1
MAX_BUNDLE_BYTES = 128 * 1024
MAX_BUNDLE_NODES = 64
MAX_BUNDLE_TRUST_REFS = 64
ALLOWED_TIERS = frozenset({"silent", "source", "seal"})
ALLOWED_TRUST_ANCHOR_TYPES = frozenset({"onchain_proof", "c2pa_binding"})

_URL_SCHEME_RE = re.compile(r"\b(?:https?|ftp|file|ws|wss|data)://|^data:", re.IGNORECASE)
_FORBIDDEN_URL_KEYS = frozenset({"url", "uri", "href", "endpoint", "fetchUrl", "remoteUrl"})


class LineageValidationError(ValueError):
    pass


class LineageBundleError(LineageValidationError):
    """Structured, privacy-safe error raised for invalid lineage verification bundles.

    Error payloads expose only stable reason codes and optional field names,
    never raw digests, media hashes, or actor identifiers.
    """

    def __init__(self, reason: str, field: str | None = None) -> None:
        self.reason = reason
        self.field = field
        super().__init__(reason if field is None else f"{reason}: {field}")

    def to_dict(self) -> dict[str, str | None]:
        return {"reason": self.reason, "field": self.field}


class LineageRecordError(RuntimeError):
    pass


class LineageVerificationStatus(str, Enum):
    """Explicit verification verdict for a portable lineage bundle.

    ``INCOMPLETE`` is a distinct status from ``VERIFIED`` so callers never
    present a partial or unanchored lineage graph as a fully verified original.
    """

    VERIFIED = "verified"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True)
class LineageVerifiedEdge:
    """A verified directed edge from a derived statement to a known parent."""

    child_digest: str
    parent_id: str
    parent_kind: str  # "statement" | "trust_reference"
    operation_type: str
    statement_digest: str

    def to_dict(self) -> dict[str, str]:
        return {
            "childDigest": self.child_digest,
            "parentId": self.parent_id,
            "parentKind": self.parent_kind,
            "operationType": self.operation_type,
            "statementDigest": self.statement_digest,
        }


@dataclass(frozen=True)
class LineageMissingDependency:
    """An explicit missing parent dependency encountered during lineage traversal."""

    parent_id: str
    referenced_by: tuple[str, ...]
    reason: str = "missing_parent"

    def to_dict(self) -> dict[str, Any]:
        return {
            "parentId": self.parent_id,
            "referencedBy": list(self.referenced_by),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class LineageBundleVerificationResult:
    """Verified summary of a portable lineage verification bundle."""

    valid: bool
    bundle_digest: str
    target_digest: str
    network: str
    statement_count: int
    root_proof_ids: tuple[str, ...]
    max_depth_observed: int
    tiers: tuple[str, ...]
    trust_anchor_types: tuple[str, ...]
    status: LineageVerificationStatus = LineageVerificationStatus.VERIFIED
    complete: bool = True
    verified_edges: tuple[LineageVerifiedEdge, ...] = ()
    missing_dependencies: tuple[LineageMissingDependency, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "status": self.status.value,
            "complete": self.complete,
            "bundleDigest": self.bundle_digest,
            "targetDigest": self.target_digest,
            "network": self.network,
            "statementCount": self.statement_count,
            "rootProofIds": list(self.root_proof_ids),
            "maxDepthObserved": self.max_depth_observed,
            "tiers": list(self.tiers),
            "trustAnchorTypes": list(self.trust_anchor_types),
            "verifiedEdges": [edge.to_dict() for edge in self.verified_edges],
            "missingDependencies": [dep.to_dict() for dep in self.missing_dependencies],
        }


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


# ---------------------------------------------------------------------------
# Portable lineage verification bundle with bounded graph closure
# ---------------------------------------------------------------------------


def _reject_if_url(value: Any, field: str) -> None:
    """Fail closed if a string looks like a remote or local URL."""
    if isinstance(value, str) and _URL_SCHEME_RE.search(value.strip()):
        raise LineageBundleError("external_url_forbidden", field)


def _reject_url_keys(obj: dict[str, Any], prefix: str) -> None:
    for key, val in obj.items():
        if key in _FORBIDDEN_URL_KEYS:
            raise LineageBundleError("external_url_forbidden", f"{prefix}.{key}")
        if isinstance(val, str):
            _reject_if_url(val, f"{prefix}.{key}")


def _normalize_trust_reference(ref: Any, idx: int) -> dict[str, Any]:
    prefix = f"trustReferences[{idx}]"
    if not isinstance(ref, dict):
        raise LineageBundleError("invalid_trust_reference", prefix)

    _reject_url_keys(ref, prefix)

    proof_id = ref.get("proofId")
    if not isinstance(proof_id, str) or not _is_hex_32(proof_id):
        raise LineageBundleError("invalid_trust_reference", f"{prefix}.proofId")

    network = ref.get("network")
    if not isinstance(network, str) or not network.strip():
        raise LineageBundleError("invalid_trust_reference", f"{prefix}.network")
    _reject_if_url(network, f"{prefix}.network")

    contract_id = ref.get("contractId")
    if not isinstance(contract_id, str) or not contract_id.strip():
        raise LineageBundleError("invalid_trust_reference", f"{prefix}.contractId")
    _reject_if_url(contract_id, f"{prefix}.contractId")

    tier = ref.get("tier")
    if not isinstance(tier, str) or tier not in ALLOWED_TIERS:
        raise LineageBundleError("invalid_trust_reference", f"{prefix}.tier")

    anchor_type = ref.get("trustAnchorType", "onchain_proof")
    if not isinstance(anchor_type, str) or anchor_type not in ALLOWED_TRUST_ANCHOR_TYPES:
        raise LineageBundleError("invalid_trust_reference", f"{prefix}.trustAnchorType")

    normalized: dict[str, Any] = {
        "proofId": proof_id.lower(),
        "network": network.strip(),
        "contractId": contract_id.strip(),
        "tier": tier,
        "trustAnchorType": anchor_type,
    }

    for opt_hex in ("c2paDigest", "videoHash", "metadataHash"):
        if opt_hex in ref and ref[opt_hex] is not None:
            val = ref[opt_hex]
            if not isinstance(val, str) or not _is_hex_32(val):
                raise LineageBundleError("invalid_trust_reference", f"{prefix}.{opt_hex}")
            normalized[opt_hex] = val.lower()

    return normalized


def _normalize_bundle_statement(stmt: Any, idx: int) -> dict[str, Any]:
    prefix = f"statements[{idx}]"
    if not isinstance(stmt, dict):
        raise LineageBundleError("invalid_statement", prefix)

    _reject_url_keys(stmt, prefix)

    try:
        canonical_str = canonical_lineage_manifest(stmt)
    except LineageValidationError as exc:
        raise LineageBundleError("invalid_statement", prefix) from exc

    parsed_manifest = json.loads(canonical_str)
    # Normalize hex digests to lowercase for canonical bundle identity
    output_digest = parsed_manifest["outputDigest"]
    if not _is_hex_32(output_digest):
        raise LineageBundleError("invalid_statement", f"{prefix}.outputDigest")

    expected_digest = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
    supplied_digest = stmt.get("manifestDigest")
    if supplied_digest is not None:
        if not isinstance(supplied_digest, str) or supplied_digest.lower() != expected_digest:
            raise LineageBundleError("statement_digest_mismatch", f"{prefix}.manifestDigest")

    parsed_manifest["manifestDigest"] = expected_digest
    return parsed_manifest


def trust_reference_from_c2pa_binding(
    binding: Any,
    *,
    c2pa_digest: str | None = None,
) -> dict[str, Any]:
    """Build a portable trust reference dict from a ``C2paHarpocratesBinding``.

    Explicitly marks ``trustAnchorType`` as ``"c2pa_binding"`` so C2PA trust is
    never conflated with on-chain / ZK proof verification.
    """
    ref: dict[str, Any] = {
        "proofId": binding.proof_id.lower(),
        "network": binding.network.strip(),
        "contractId": binding.contract_id.strip(),
        "tier": binding.tier,
        "trustAnchorType": "c2pa_binding",
        "videoHash": binding.video_hash.lower(),
        "metadataHash": binding.metadata_hash.lower(),
    }
    if c2pa_digest is not None:
        if not isinstance(c2pa_digest, str) or not _is_hex_32(c2pa_digest):
            raise LineageBundleError("invalid_trust_reference", "c2paDigest")
        ref["c2paDigest"] = c2pa_digest.lower()
    return ref


def canonical_lineage_bundle(bundle: dict[str, Any]) -> str:
    """Return the canonical compact JSON encoding of a bundle (excluding ``bundleDigest``)."""
    if not isinstance(bundle, dict):
        raise LineageBundleError("invalid_bundle", "bundle")
    payload = {k: v for k, v in bundle.items() if k != "bundleDigest"}
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def lineage_bundle_digest(bundle: dict[str, Any]) -> str:
    """Return the SHA-256 hex digest of the canonical lineage verification bundle."""
    return hashlib.sha256(canonical_lineage_bundle(bundle).encode("utf-8")).hexdigest()


def build_lineage_verification_bundle(
    *,
    target_digest: str,
    network: str,
    statements: list[dict[str, Any]],
    trust_references: list[dict[str, Any]],
    max_depth: int = MAX_LINEAGE_DEPTH,
    max_nodes: int = MAX_BUNDLE_NODES,
) -> dict[str, Any]:
    """Package canonical ancestry statements and trust references into a portable bundle.

    Validates the bounded graph closure before returning. Raises
    ``LineageBundleError`` on any missing parent, cycle, contradictory root,
    external URL, or bound violation.
    """
    if not isinstance(target_digest, str) or not _is_hex_32(target_digest):
        raise LineageBundleError("invalid_target_digest", "targetDigest")
    if not isinstance(network, str) or not network.strip():
        raise LineageBundleError("invalid_network", "network")
    _reject_if_url(network, "network")

    if not isinstance(statements, list) or not statements:
        raise LineageBundleError("empty_statements", "statements")
    if len(statements) > max_nodes:
        raise LineageBundleError("node_limit_exceeded", "statements")

    if not isinstance(trust_references, list) or not trust_references:
        raise LineageBundleError("empty_trust_references", "trustReferences")
    if len(trust_references) > MAX_BUNDLE_TRUST_REFS:
        raise LineageBundleError("trust_reference_limit_exceeded", "trustReferences")

    norm_statements = [
        _normalize_bundle_statement(stmt, idx) for idx, stmt in enumerate(statements)
    ]
    norm_statements.sort(key=lambda item: item["outputDigest"].lower())

    norm_refs = [
        _normalize_trust_reference(ref, idx) for idx, ref in enumerate(trust_references)
    ]
    norm_refs.sort(key=lambda item: item["proofId"])

    bundle: dict[str, Any] = {
        "protocol": "harpocrates",
        "bundleVersion": LINEAGE_BUNDLE_VERSION,
        "targetDigest": target_digest.lower(),
        "network": network.strip(),
        "statements": norm_statements,
        "trustReferences": norm_refs,
    }
    bundle["bundleDigest"] = lineage_bundle_digest(bundle)

    # Verify fail-closed closure before returning the packaged bundle.
    verify_lineage_verification_bundle(bundle, max_depth=max_depth, max_nodes=max_nodes)
    return bundle


def _parse_and_verify_bundle_graph(
    bundle: dict[str, Any] | str | bytes,
    *,
    max_depth: int = MAX_LINEAGE_DEPTH,
    max_nodes: int = MAX_BUNDLE_NODES,
    allow_incomplete: bool = False,
) -> LineageBundleVerificationResult:
    """Verify a portable lineage verification bundle completely offline.

    Enforces:
    - Bounded payload size, node count, fan-out, and graph depth.
    - No external URLs or network resolution.
    - Canonical statement digests and network consistency.
    - No cycles, no contradictory roots, and no orphaned nodes.
    - By default (``allow_incomplete=False``), fails closed with
      ``LineageBundleError("missing_parent", ...)`` if any parent dependency is
      absent. When ``allow_incomplete=True``, returns a distinct
      ``LineageVerificationStatus.INCOMPLETE`` result (``valid=False``,
      ``complete=False``) containing all known ``verified_edges`` and explicit
      ``missing_dependencies`` without presenting the graph as fully verified.
    """
    if isinstance(bundle, str):
        raw_bytes = bundle.encode("utf-8")
        if len(raw_bytes) > MAX_BUNDLE_BYTES:
            raise LineageBundleError("bundle_too_large")
        try:
            data = json.loads(bundle)
        except json.JSONDecodeError as exc:
            raise LineageBundleError("invalid_json") from exc
    elif isinstance(bundle, bytes):
        if len(bundle) > MAX_BUNDLE_BYTES:
            raise LineageBundleError("bundle_too_large")
        try:
            data = json.loads(bundle.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LineageBundleError("invalid_json") from exc
    elif isinstance(bundle, dict):
        try:
            encoded = json.dumps(bundle, separators=(",", ":"), sort_keys=True).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise LineageBundleError("invalid_bundle") from exc
        if len(encoded) > MAX_BUNDLE_BYTES:
            raise LineageBundleError("bundle_too_large")
        data = bundle
    else:
        raise LineageBundleError("invalid_bundle")

    if not isinstance(data, dict):
        raise LineageBundleError("invalid_bundle")

    _reject_url_keys(data, "bundle")

    if data.get("protocol") != "harpocrates":
        raise LineageBundleError("invalid_protocol", "protocol")
    if data.get("bundleVersion") != LINEAGE_BUNDLE_VERSION:
        raise LineageBundleError("unsupported_bundle_version", "bundleVersion")

    target_digest = data.get("targetDigest")
    if not isinstance(target_digest, str) or not _is_hex_32(target_digest):
        raise LineageBundleError("invalid_target_digest", "targetDigest")
    target_key = target_digest.lower()

    network = data.get("network")
    if not isinstance(network, str) or not network.strip():
        raise LineageBundleError("invalid_network", "network")
    _reject_if_url(network, "network")
    bundle_network = network.strip()

    statements_raw = data.get("statements")
    if not isinstance(statements_raw, list) or not statements_raw:
        raise LineageBundleError("empty_statements", "statements")
    if len(statements_raw) > max_nodes:
        raise LineageBundleError("node_limit_exceeded", "statements")

    trust_refs_raw = data.get("trustReferences")
    if not isinstance(trust_refs_raw, list) or (not allow_incomplete and not trust_refs_raw):
        raise LineageBundleError("empty_trust_references", "trustReferences")
    if len(trust_refs_raw) > MAX_BUNDLE_TRUST_REFS:
        raise LineageBundleError("trust_reference_limit_exceeded", "trustReferences")

    # Verify optional bundleDigest if present.
    computed_digest = lineage_bundle_digest(data)
    supplied_bundle_digest = data.get("bundleDigest")
    if supplied_bundle_digest is not None:
        if (
            not isinstance(supplied_bundle_digest, str)
            or supplied_bundle_digest.lower() != computed_digest
        ):
            raise LineageBundleError("bundle_digest_mismatch", "bundleDigest")

    # Index and validate statements.
    statements_by_output: dict[str, dict[str, Any]] = {}
    statement_order: list[str] = []
    for idx, stmt in enumerate(statements_raw):
        norm = _normalize_bundle_statement(stmt, idx)
        if norm["network"].strip() != bundle_network:
            raise LineageBundleError("network_mismatch", f"statements[{idx}].network")
        out_key = norm["outputDigest"].lower()
        if out_key in statements_by_output:
            raise LineageBundleError("duplicate_statement", f"statements[{idx}].outputDigest")
        statements_by_output[out_key] = norm
        statement_order.append(out_key)

    # Index and validate trust references (roots).
    trust_by_id: dict[str, dict[str, Any]] = {}
    trust_order: list[str] = []
    for idx, ref in enumerate(trust_refs_raw):
        norm_ref = _normalize_trust_reference(ref, idx)
        if norm_ref["network"] != bundle_network:
            raise LineageBundleError("contradictory_root", f"trustReferences[{idx}].network")
        pid = norm_ref["proofId"]
        if pid in trust_by_id:
            raise LineageBundleError("contradictory_root", f"trustReferences[{idx}].proofId")
        if pid in statements_by_output:
            raise LineageBundleError("contradictory_root", f"trustReferences[{idx}].proofId")
        trust_by_id[pid] = norm_ref
        trust_order.append(pid)

    if target_key not in statements_by_output:
        raise LineageBundleError("missing_target_statement", "targetDigest")

    # Bounded graph closure traversal from targetDigest.
    visited_statements: set[str] = set()
    used_roots: set[str] = set()
    visiting: set[str] = set()
    verified_edges_set: set[LineageVerifiedEdge] = set()
    missing_refs_by_parent: dict[str, set[str]] = {}
    max_depth_observed = 0

    def _visit(node_id: str, depth: int) -> None:
        nonlocal max_depth_observed
        if depth > max_depth:
            raise LineageBundleError("depth_exceeded", "statements")
        if depth > max_depth_observed:
            max_depth_observed = depth

        visiting.add(node_id)
        visited_statements.add(node_id)
        if len(visited_statements) > max_nodes:
            raise LineageBundleError("node_limit_exceeded", "statements")

        stmt = statements_by_output[node_id]
        for raw_parent in stmt["parentProofIds"]:
            parent_key = raw_parent.lower()
            if parent_key in visiting:
                raise LineageBundleError("cycle_detected", "parentProofIds")
            if parent_key in statements_by_output:
                verified_edges_set.add(
                    LineageVerifiedEdge(
                        child_digest=node_id,
                        parent_id=parent_key,
                        parent_kind="statement",
                        operation_type=stmt["operationType"],
                        statement_digest=stmt["manifestDigest"],
                    )
                )
                if parent_key not in visited_statements:
                    _visit(parent_key, depth + 1)
                else:
                    # Re-check depth bound on DAG diamond paths.
                    if depth + 1 > max_depth:
                        raise LineageBundleError("depth_exceeded", "statements")
                    if depth + 1 > max_depth_observed:
                        max_depth_observed = depth + 1
            elif parent_key in trust_by_id:
                used_roots.add(parent_key)
                verified_edges_set.add(
                    LineageVerifiedEdge(
                        child_digest=node_id,
                        parent_id=parent_key,
                        parent_kind="trust_reference",
                        operation_type=stmt["operationType"],
                        statement_digest=stmt["manifestDigest"],
                    )
                )
            else:
                if not allow_incomplete:
                    raise LineageBundleError("missing_parent", "parentProofIds")
                missing_refs_by_parent.setdefault(parent_key, set()).add(node_id)

        visiting.remove(node_id)

    _visit(target_key, 1)

    if len(visited_statements) != len(statements_by_output):
        raise LineageBundleError("disconnected_statement", "statements")
    if len(used_roots) != len(trust_by_id):
        raise LineageBundleError("unused_trust_reference", "trustReferences")

    tiers = tuple(sorted({trust_by_id[rid]["tier"] for rid in used_roots}))
    anchor_types = tuple(sorted({trust_by_id[rid]["trustAnchorType"] for rid in used_roots}))
    verified_edges = tuple(
        sorted(
            verified_edges_set,
            key=lambda edge: (edge.child_digest, edge.parent_id, edge.parent_kind),
        )
    )
    missing_dependencies = tuple(
        LineageMissingDependency(
            parent_id=parent_id,
            referenced_by=tuple(sorted(children)),
        )
        for parent_id, children in sorted(missing_refs_by_parent.items())
    )
    is_complete = len(missing_dependencies) == 0

    return LineageBundleVerificationResult(
        valid=is_complete,
        bundle_digest=computed_digest,
        target_digest=target_key,
        network=bundle_network,
        statement_count=len(visited_statements),
        root_proof_ids=tuple(sorted(used_roots)),
        max_depth_observed=max_depth_observed,
        tiers=tiers,
        trust_anchor_types=anchor_types,
        status=(
            LineageVerificationStatus.VERIFIED
            if is_complete
            else LineageVerificationStatus.INCOMPLETE
        ),
        complete=is_complete,
        verified_edges=verified_edges,
        missing_dependencies=missing_dependencies,
    )
    return result, statements_by_output, trust_by_id, statement_order, trust_order


def verify_lineage_verification_bundle(
    bundle: dict[str, Any] | str | bytes,
    *,
    max_depth: int = MAX_LINEAGE_DEPTH,
    max_nodes: int = MAX_BUNDLE_NODES,
) -> LineageBundleVerificationResult:
    """Verify a portable lineage verification bundle completely offline.

    Enforces:
    - Bounded payload size, node count, fan-out, and graph depth.
    - No external URLs or network resolution.
    - Canonical statement digests and network consistency.
    - No missing parents, no cycles, no contradictory roots, and no orphaned nodes.
    """
    result, _, _, _, _ = _parse_and_verify_bundle_graph(
        bundle, max_depth=max_depth, max_nodes=max_nodes
    )
    return result


# ---------------------------------------------------------------------------
# Deterministic lineage graph comparison report
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LineageAssertionEntry:
    """An added or removed assertion in a lineage graph comparison."""

    kind: str  # "statement" | "trust_reference"
    assertion_id: str
    canonical_digest: str
    provenance_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "assertionId": self.assertion_id,
            "canonicalDigest": self.canonical_digest,
            "provenanceDigest": self.provenance_digest,
        }


@dataclass(frozen=True)
class LineageAssertionChange:
    """A provenance-level change to an assertion present in both lineage graphs."""

    kind: str  # "statement" | "trust_reference"
    assertion_id: str
    before_digest: str
    after_digest: str
    before_provenance_digest: str
    after_provenance_digest: str
    changed_fields: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "assertionId": self.assertion_id,
            "beforeDigest": self.before_digest,
            "afterDigest": self.after_digest,
            "beforeProvenanceDigest": self.before_provenance_digest,
            "afterProvenanceDigest": self.after_provenance_digest,
            "changedFields": list(self.changed_fields),
        }


@dataclass(frozen=True)
class LineageOrderingDifference:
    """A pure ordering difference that does not alter provenance semantics."""

    scope: str  # "statements" | "trust_references" | "statement_parents"
    assertion_id: str | None
    before_digest: str
    after_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "assertionId": self.assertion_id,
            "beforeDigest": self.before_digest,
            "afterDigest": self.after_digest,
        }


@dataclass(frozen=True)
class LineageGraphComparisonReport:
    """Deterministic comparison report between two verified lineage graphs."""

    before_bundle_digest: str
    after_bundle_digest: str
    before_target_digest: str
    after_target_digest: str
    before_network: str
    after_network: str
    target_changed: bool
    network_changed: bool
    added_assertions: tuple[LineageAssertionEntry, ...]
    removed_assertions: tuple[LineageAssertionEntry, ...]
    changed_assertions: tuple[LineageAssertionChange, ...]
    unchanged_assertion_count: int
    ordering_differences: tuple[LineageOrderingDifference, ...]
    has_provenance_changes: bool
    has_ordering_differences: bool
    equivalent_provenance: bool
    report_digest: str
    protocol: str = "harpocrates"
    report_version: int = LINEAGE_COMPARISON_REPORT_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "reportVersion": self.report_version,
            "beforeBundleDigest": self.before_bundle_digest,
            "afterBundleDigest": self.after_bundle_digest,
            "beforeTargetDigest": self.before_target_digest,
            "afterTargetDigest": self.after_target_digest,
            "beforeNetwork": self.before_network,
            "afterNetwork": self.after_network,
            "targetChanged": self.target_changed,
            "networkChanged": self.network_changed,
            "addedAssertions": [entry.to_dict() for entry in self.added_assertions],
            "removedAssertions": [entry.to_dict() for entry in self.removed_assertions],
            "changedAssertions": [entry.to_dict() for entry in self.changed_assertions],
            "unchangedAssertionCount": self.unchanged_assertion_count,
            "orderingDifferences": [diff.to_dict() for diff in self.ordering_differences],
            "hasProvenanceChanges": self.has_provenance_changes,
            "hasOrderingDifferences": self.has_ordering_differences,
            "equivalentProvenance": self.equivalent_provenance,
            "reportDigest": self.report_digest,
        }


def _statement_provenance_payload(stmt: dict[str, Any]) -> dict[str, Any]:
    """Return an order-independent canonical representation of a normalized statement."""
    return {
        "protocol": stmt["protocol"],
        "version": stmt["version"],
        "parentProofIds": sorted(p.lower() for p in stmt["parentProofIds"]),
        "operationType": stmt["operationType"],
        "parametersDigest": stmt["parametersDigest"],
        "toolIdentity": stmt["toolIdentity"],
        "toolVersion": stmt["toolVersion"],
        "outputDigest": stmt["outputDigest"].lower(),
        "network": stmt["network"],
        "actorAddress": stmt["actorAddress"],
    }


def _statement_provenance_digest(stmt: dict[str, Any]) -> str:
    payload = _statement_provenance_payload(stmt)
    return hashlib.sha256(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def _trust_reference_digest(ref: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(ref, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def canonical_lineage_comparison_report(
    report: LineageGraphComparisonReport | dict[str, Any],
) -> str:
    """Return the canonical compact JSON encoding of a comparison report (excluding ``reportDigest``)."""
    raw = report.to_dict() if isinstance(report, LineageGraphComparisonReport) else report
    if not isinstance(raw, dict):
        raise LineageBundleError("invalid_comparison_report", "report")
    payload = {k: v for k, v in raw.items() if k != "reportDigest"}
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def lineage_comparison_report_digest(
    report: LineageGraphComparisonReport | dict[str, Any],
) -> str:
    """Return the SHA-256 hex digest of the canonical lineage comparison report."""
    return hashlib.sha256(
        canonical_lineage_comparison_report(report).encode("utf-8")
    ).hexdigest()


def compare_lineage_graphs(
    before: dict[str, Any] | str | bytes,
    after: dict[str, Any] | str | bytes,
    *,
    max_depth: int = MAX_LINEAGE_DEPTH,
    max_nodes: int = MAX_BUNDLE_NODES,
) -> LineageGraphComparisonReport:
    """Produce a deterministic comparison report between two lineage verification bundles.

    Both ``before`` and ``after`` are verified offline (fail-closed) before comparison.
    Assertions (statements and root trust references) are compared by canonical digest,
    while separating genuine provenance changes from pure ordering differences (bundle
    list order or ``parentProofIds`` permutation).
    """
    (
        before_res,
        before_stmts,
        before_trust,
        before_stmt_order,
        before_trust_order,
    ) = _parse_and_verify_bundle_graph(before, max_depth=max_depth, max_nodes=max_nodes)
    (
        after_res,
        after_stmts,
        after_trust,
        after_stmt_order,
        after_trust_order,
    ) = _parse_and_verify_bundle_graph(after, max_depth=max_depth, max_nodes=max_nodes)

    added: list[LineageAssertionEntry] = []
    removed: list[LineageAssertionEntry] = []
    changed: list[LineageAssertionChange] = []
    ordering_diffs: list[LineageOrderingDifference] = []
    unchanged_count = 0

    # 1. Compare lineage statements keyed by canonical outputDigest.
    all_stmt_ids = sorted(set(before_stmts) | set(after_stmts))
    for oid in all_stmt_ids:
        b_stmt = before_stmts.get(oid)
        a_stmt = after_stmts.get(oid)
        if b_stmt is None and a_stmt is not None:
            added.append(
                LineageAssertionEntry(
                    kind="statement",
                    assertion_id=oid,
                    canonical_digest=a_stmt["manifestDigest"],
                    provenance_digest=_statement_provenance_digest(a_stmt),
                )
            )
        elif a_stmt is None and b_stmt is not None:
            removed.append(
                LineageAssertionEntry(
                    kind="statement",
                    assertion_id=oid,
                    canonical_digest=b_stmt["manifestDigest"],
                    provenance_digest=_statement_provenance_digest(b_stmt),
                )
            )
        elif b_stmt is not None and a_stmt is not None:
            b_digest = b_stmt["manifestDigest"]
            a_digest = a_stmt["manifestDigest"]
            b_prov = _statement_provenance_digest(b_stmt)
            a_prov = _statement_provenance_digest(a_stmt)
            if b_digest == a_digest:
                unchanged_count += 1
            elif b_prov == a_prov:
                unchanged_count += 1
                ordering_diffs.append(
                    LineageOrderingDifference(
                        scope="statement_parents",
                        assertion_id=oid,
                        before_digest=b_digest,
                        after_digest=a_digest,
                    )
                )
            else:
                b_payload = _statement_provenance_payload(b_stmt)
                a_payload = _statement_provenance_payload(a_stmt)
                diff_fields = tuple(
                    sorted(
                        k
                        for k in (set(b_payload) | set(a_payload))
                        if b_payload.get(k) != a_payload.get(k)
                    )
                )
                changed.append(
                    LineageAssertionChange(
                        kind="statement",
                        assertion_id=oid,
                        before_digest=b_digest,
                        after_digest=a_digest,
                        before_provenance_digest=b_prov,
                        after_provenance_digest=a_prov,
                        changed_fields=diff_fields,
                    )
                )

    # 2. Compare root trust references keyed by canonical proofId.
    all_trust_ids = sorted(set(before_trust) | set(after_trust))
    for pid in all_trust_ids:
        b_ref = before_trust.get(pid)
        a_ref = after_trust.get(pid)
        if b_ref is None and a_ref is not None:
            a_digest = _trust_reference_digest(a_ref)
            added.append(
                LineageAssertionEntry(
                    kind="trust_reference",
                    assertion_id=pid,
                    canonical_digest=a_digest,
                    provenance_digest=a_digest,
                )
            )
        elif a_ref is None and b_ref is not None:
            b_digest = _trust_reference_digest(b_ref)
            removed.append(
                LineageAssertionEntry(
                    kind="trust_reference",
                    assertion_id=pid,
                    canonical_digest=b_digest,
                    provenance_digest=b_digest,
                )
            )
        elif b_ref is not None and a_ref is not None:
            b_digest = _trust_reference_digest(b_ref)
            a_digest = _trust_reference_digest(a_ref)
            if b_digest == a_digest:
                unchanged_count += 1
            else:
                diff_fields = tuple(
                    sorted(
                        k
                        for k in (set(b_ref) | set(a_ref))
                        if b_ref.get(k) != a_ref.get(k)
                    )
                )
                changed.append(
                    LineageAssertionChange(
                        kind="trust_reference",
                        assertion_id=pid,
                        before_digest=b_digest,
                        after_digest=a_digest,
                        before_provenance_digest=b_digest,
                        after_provenance_digest=a_digest,
                        changed_fields=diff_fields,
                    )
                )

    # 3. Detect bundle-level list ordering differences among shared assertions.
    shared_stmt_before = [oid for oid in before_stmt_order if oid in after_stmts]
    shared_stmt_after = [oid for oid in after_stmt_order if oid in before_stmts]
    if shared_stmt_before != shared_stmt_after:
        ordering_diffs.append(
            LineageOrderingDifference(
                scope="statements",
                assertion_id=None,
                before_digest=before_res.bundle_digest,
                after_digest=after_res.bundle_digest,
            )
        )

    shared_trust_before = [pid for pid in before_trust_order if pid in after_trust]
    shared_trust_after = [pid for pid in after_trust_order if pid in before_trust]
    if shared_trust_before != shared_trust_after:
        ordering_diffs.append(
            LineageOrderingDifference(
                scope="trust_references",
                assertion_id=None,
                before_digest=before_res.bundle_digest,
                after_digest=after_res.bundle_digest,
            )
        )

    # Deterministic sorting of all report collections.
    added_tuple = tuple(sorted(added, key=lambda e: (e.kind, e.assertion_id)))
    removed_tuple = tuple(sorted(removed, key=lambda e: (e.kind, e.assertion_id)))
    changed_tuple = tuple(sorted(changed, key=lambda c: (c.kind, c.assertion_id)))
    ordering_tuple = tuple(
        sorted(ordering_diffs, key=lambda d: (d.scope, d.assertion_id or ""))
    )

    target_changed = before_res.target_digest != after_res.target_digest
    network_changed = before_res.network != after_res.network
    has_provenance_changes = bool(
        target_changed
        or network_changed
        or added_tuple
        or removed_tuple
        or changed_tuple
    )
    has_ordering_differences = bool(ordering_tuple)

    draft = LineageGraphComparisonReport(
        before_bundle_digest=before_res.bundle_digest,
        after_bundle_digest=after_res.bundle_digest,
        before_target_digest=before_res.target_digest,
        after_target_digest=after_res.target_digest,
        before_network=before_res.network,
        after_network=after_res.network,
        target_changed=target_changed,
        network_changed=network_changed,
        added_assertions=added_tuple,
        removed_assertions=removed_tuple,
        changed_assertions=changed_tuple,
        unchanged_assertion_count=unchanged_count,
        ordering_differences=ordering_tuple,
        has_provenance_changes=has_provenance_changes,
        has_ordering_differences=has_ordering_differences,
        equivalent_provenance=not has_provenance_changes,
        report_digest="",
    )
    digest = lineage_comparison_report_digest(draft)
    return LineageGraphComparisonReport(
        before_bundle_digest=draft.before_bundle_digest,
        after_bundle_digest=draft.after_bundle_digest,
        before_target_digest=draft.before_target_digest,
        after_target_digest=draft.after_target_digest,
        before_network=draft.before_network,
        after_network=draft.after_network,
        target_changed=draft.target_changed,
        network_changed=draft.network_changed,
        added_assertions=draft.added_assertions,
        removed_assertions=draft.removed_assertions,
        changed_assertions=draft.changed_assertions,
        unchanged_assertion_count=draft.unchanged_assertion_count,
        ordering_differences=draft.ordering_differences,
        has_provenance_changes=draft.has_provenance_changes,
        has_ordering_differences=draft.has_ordering_differences,
        equivalent_provenance=draft.equivalent_provenance,
        report_digest=digest,
    )
