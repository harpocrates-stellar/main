from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

SUPPORTED_OPERATIONS = {"crop", "transcode", "blur", "redact", "compose"}
MAX_LINEAGE_DEPTH = 4
MAX_LINEAGE_FANOUT = 4
MAX_LINEAGE_PAYLOAD_BYTES = 4096

LINEAGE_BUNDLE_VERSION = 1
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
    if not isinstance(trust_refs_raw, list) or not trust_refs_raw:
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
    for idx, stmt in enumerate(statements_raw):
        norm = _normalize_bundle_statement(stmt, idx)
        if norm["network"].strip() != bundle_network:
            raise LineageBundleError("network_mismatch", f"statements[{idx}].network")
        out_key = norm["outputDigest"].lower()
        if out_key in statements_by_output:
            raise LineageBundleError("duplicate_statement", f"statements[{idx}].outputDigest")
        statements_by_output[out_key] = norm

    # Index and validate trust references (roots).
    trust_by_id: dict[str, dict[str, Any]] = {}
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

    if target_key not in statements_by_output:
        raise LineageBundleError("missing_target_statement", "targetDigest")

    # Bounded graph closure traversal from targetDigest.
    visited_statements: set[str] = set()
    used_roots: set[str] = set()
    visiting: set[str] = set()
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
            else:
                raise LineageBundleError("missing_parent", "parentProofIds")

        visiting.remove(node_id)

    _visit(target_key, 1)

    if len(visited_statements) != len(statements_by_output):
        raise LineageBundleError("disconnected_statement", "statements")
    if len(used_roots) != len(trust_by_id):
        raise LineageBundleError("unused_trust_reference", "trustReferences")

    tiers = tuple(sorted({trust_by_id[rid]["tier"] for rid in used_roots}))
    anchor_types = tuple(sorted({trust_by_id[rid]["trustAnchorType"] for rid in used_roots}))

    return LineageBundleVerificationResult(
        valid=True,
        bundle_digest=computed_digest,
        target_digest=target_key,
        network=bundle_network,
        statement_count=len(visited_statements),
        root_proof_ids=tuple(sorted(used_roots)),
        max_depth_observed=max_depth_observed,
        tiers=tiers,
        trust_anchor_types=anchor_types,
    )
