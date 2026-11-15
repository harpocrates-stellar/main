from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from typing import Any

from c2pa import (
    C2paParseError,
    C2paPortableTrustReference,
    C2paTrustStatus,
    extract_c2pa_portable_trust_reference,
)

SUPPORTED_OPERATIONS = {"crop", "transcode", "blur", "redact", "compose"}
MAX_LINEAGE_DEPTH = 4
MAX_LINEAGE_FANOUT = 4
MAX_LINEAGE_PAYLOAD_BYTES = 4096

PORTABLE_LINEAGE_BUNDLE_SCHEMA = "harpocrates.lineage.bundle/v1"
PORTABLE_LINEAGE_BUNDLE_VERSION = 1
MAX_PORTABLE_BUNDLE_NODES = 32
MAX_PORTABLE_BUNDLE_BYTES = 128 * 1024
MAX_PORTABLE_JSON_DEPTH = 16
PARENT_COMMITMENT_DOMAIN = b"harp_lin_pc"
_ALLOWED_ROOT_TIERS = frozenset({"silent", "source", "seal"})
_ALLOWED_TRUST_KINDS = frozenset({"soroban_registry", "c2pa_manifest"})

_BUNDLE_PROHIBITED_URL_SCHEMES: tuple[str, ...] = (
    "http://",
    "https://",
    "ftp://",
    "ftps://",
    "ws://",
    "wss://",
    "file://",
    "ipfs://",
    "data:",
)

_BUNDLE_PROHIBITED_URL_KEYS: frozenset[str] = frozenset(
    {
        "url",
        "uri",
        "href",
        "manifest_url",
        "manifestUrl",
        "remote_url",
        "remoteUrl",
        "trust_url",
        "trustUrl",
        "fetch_url",
        "fetchUrl",
        "ingredient_url",
        "ingredientUrl",
        "active_manifest_uri",
        "claim_uri",
    }
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


@dataclass(frozen=True)
class PortableBundleVerificationReport:
    """Deterministic verification summary for an offline portable lineage bundle."""

    valid: bool
    target_id: str
    bundle_digest: str
    is_derivative: bool
    max_depth: int
    node_count: int
    root_proof_ids: tuple[str, ...]
    ancestry_output_digests: tuple[str, ...]
    network: str
    contract_id: str | None
    trust_reference_count: int
    c2pa_trust_statuses: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "target_id": self.target_id,
            "bundle_digest": self.bundle_digest,
            "is_derivative": self.is_derivative,
            "max_depth": self.max_depth,
            "node_count": self.node_count,
            "root_proof_ids": list(self.root_proof_ids),
            "ancestry_output_digests": list(self.ancestry_output_digests),
            "network": self.network,
            "contract_id": self.contract_id,
            "trust_reference_count": self.trust_reference_count,
            "c2pa_trust_statuses": list(self.c2pa_trust_statuses),
        }


def compute_parent_commitment(binding_a: str, binding_b: str) -> str:
    """
    Compute the canonical parent commitment ``SHA-256("harp_lin_pc" || a || b)``.

    - Root proof parent: ``(video_hash, metadata_hash)``
    - Lineage derivative parent: ``(manifest_digest, output_digest)``
    """
    if not isinstance(binding_a, str) or not _is_hex_32(binding_a):
        raise LineageValidationError("binding_a must be a 32-byte hex string")
    if not isinstance(binding_b, str) or not _is_hex_32(binding_b):
        raise LineageValidationError("binding_b must be a 32-byte hex string")
    hasher = hashlib.sha256()
    hasher.update(PARENT_COMMITMENT_DOMAIN)
    hasher.update(bytes.fromhex(binding_a.lower()))
    hasher.update(bytes.fromhex(binding_b.lower()))
    return hasher.hexdigest()


def build_portable_lineage_bundle(
    target_id: str,
    *,
    lineage_records: dict[str, dict[str, Any]] | list[dict[str, Any]] | Any = None,
    root_statements: dict[str, dict[str, Any]] | list[dict[str, Any]] | Any = None,
    trust_references: list[dict[str, Any]] | None = None,
    c2pa_manifests: list[Any] | None = None,
    max_nodes: int = MAX_PORTABLE_BUNDLE_NODES,
    max_bytes: int = MAX_PORTABLE_BUNDLE_BYTES,
) -> dict[str, Any]:
    """
    Package canonical ancestry statements and offline trust references for
    ``target_id`` into a self-contained, bounded portable verification bundle.

    Enforces bounded graph closure (``MAX_LINEAGE_DEPTH``, ``MAX_LINEAGE_FANOUT``,
    ``max_nodes``, ``max_bytes``) and fails closed on missing parents, cycles,
    contradictory roots, tier-privacy violations, or any external URL / remote
    reference without performing network I/O.
    """
    if not isinstance(target_id, str) or not _is_hex_32(target_id):
        raise LineageValidationError("target_id must be a 32-byte hex string")
    if not isinstance(max_nodes, int) or max_nodes < 1 or max_nodes > MAX_PORTABLE_BUNDLE_NODES:
        raise LineageValidationError("max_nodes must be between 1 and 32")
    if not isinstance(max_bytes, int) or max_bytes < 256 or max_bytes > MAX_PORTABLE_BUNDLE_BYTES:
        raise LineageValidationError("max_bytes exceeds portable bundle limit")

    target_norm = target_id.lower()

    if not callable(lineage_records) and lineage_records is not None:
        _reject_bundle_urls(lineage_records)
    if not callable(root_statements) and root_statements is not None:
        _reject_bundle_urls(root_statements)
    if trust_references is not None:
        if not isinstance(trust_references, list):
            raise LineageValidationError("trust_references must be a list")
        _reject_bundle_urls(trust_references)

    lineage_index = _index_lineage_records_input(lineage_records)
    root_by_proof, root_by_video = _index_root_statements_input(root_statements)

    for digest_key in set(root_by_proof.keys()) | set(root_by_video.keys()):
        if _resolve_lineage_entry(digest_key, lineage_index, lineage_records) is not None:
            raise LineageValidationError(
                "contradictory root and derivative statement for digest"
            )

    closure_ancestry_raw: dict[str, tuple[dict[str, Any], str, list[str]]] = {}
    closure_roots: dict[str, dict[str, Any]] = {}
    parent_resolution: dict[str, tuple[str, str]] = {}

    def _lookup_root(digest_hex: str) -> dict[str, Any] | None:
        by_p = root_by_proof.get(digest_hex)
        by_v = root_by_video.get(digest_hex)
        if by_p is not None and by_v is not None and by_p != by_v:
            raise LineageValidationError("contradictory root statements detected")
        found = by_p if by_p is not None else by_v
        if found is None and callable(root_statements):
            fetched = root_statements(digest_hex)
            if fetched is not None:
                _reject_bundle_urls(fetched)
                found = _normalize_root_statement(fetched)
                existing_p = root_by_proof.get(found["proof_id"])
                if existing_p is not None and existing_p != found:
                    raise LineageValidationError("contradictory root statements detected")
                existing_v = root_by_video.get(found["video_hash"])
                if existing_v is not None and existing_v != found:
                    raise LineageValidationError("contradictory root statements detected")
                root_by_proof[found["proof_id"]] = found
                root_by_video[found["video_hash"]] = found
        return found

    def _lookup_lineage(digest_hex: str) -> tuple[dict[str, Any], str, list[str]] | None:
        entry = _resolve_lineage_entry(digest_hex, lineage_index, lineage_records)
        if entry is None:
            return None
        _reject_bundle_urls(entry)
        return _normalize_ancestry_record(digest_hex, entry)

    def _collect_closure(node_id: str, hop_depth: int, path_stack: frozenset[str]) -> int:
        lin_item = _lookup_lineage(node_id)
        root_item = _lookup_root(node_id)

        if lin_item is not None and root_item is not None:
            raise LineageValidationError(
                "contradictory root and derivative statement for digest"
            )

        if lin_item is None:
            if root_item is None:
                if hop_depth == 0:
                    raise LineageValidationError(
                        "target statement not found in bundle closure"
                    )
                raise LineageValidationError(
                    "missing parent statement in portable bundle closure"
                )
            closure_roots[root_item["proof_id"]] = root_item
            parent_resolution[node_id] = ("root", root_item["proof_id"])
            if len(closure_ancestry_raw) + len(closure_roots) > max_nodes:
                raise LineageValidationError("portable bundle node count exceeds limit")
            return 0

        if hop_depth >= MAX_LINEAGE_DEPTH:
            raise LineageValidationError("lineage depth exceeds limit")

        normalized_manifest, manifest_digest, parents_norm = lin_item
        closure_ancestry_raw[node_id] = lin_item
        parent_resolution[node_id] = ("ancestry", node_id)
        if len(closure_ancestry_raw) + len(closure_roots) > max_nodes:
            raise LineageValidationError("portable bundle node count exceeds limit")

        max_parent_depth = 0
        for parent_id in parents_norm:
            if parent_id in path_stack:
                raise LineageValidationError(
                    "lineage cycle detected in portable bundle closure"
                )
            p_depth = _collect_closure(
                parent_id, hop_depth + 1, path_stack | {parent_id}
            )
            if p_depth > max_parent_depth:
                max_parent_depth = p_depth

        derived_depth = 1 + max_parent_depth
        if derived_depth > MAX_LINEAGE_DEPTH:
            raise LineageValidationError("lineage depth exceeds limit")
        return derived_depth

    _collect_closure(target_norm, 0, frozenset({target_norm}))

    derived_depths: dict[str, int] = {}

    def _compute_depth(node_id: str) -> int:
        if node_id in derived_depths:
            return derived_depths[node_id]
        _, _, parents_norm = closure_ancestry_raw[node_id]
        best = 0
        for parent_id in parents_norm:
            kind, resolved_key = parent_resolution[parent_id]
            if kind == "ancestry":
                d = _compute_depth(resolved_key)
                if d > best:
                    best = d
        depth_val = 1 + best
        if depth_val > MAX_LINEAGE_DEPTH:
            raise LineageValidationError("lineage depth exceeds limit")
        derived_depths[node_id] = depth_val
        return depth_val

    ancestry_statements: list[dict[str, Any]] = []
    for out_digest in sorted(closure_ancestry_raw.keys()):
        norm_manifest, m_digest, parents_norm = closure_ancestry_raw[out_digest]
        depth_val = _compute_depth(out_digest)
        commitments: list[str] = []
        for parent_id in parents_norm:
            kind, resolved_key = parent_resolution[parent_id]
            if kind == "root":
                root_stmt = closure_roots[resolved_key]
                commitments.append(
                    compute_parent_commitment(
                        root_stmt["video_hash"], root_stmt["metadata_hash"]
                    )
                )
            else:
                _, parent_m_digest, _ = closure_ancestry_raw[resolved_key]
                commitments.append(
                    compute_parent_commitment(parent_m_digest, resolved_key)
                )
        ancestry_statements.append(
            {
                "output_digest": out_digest,
                "manifest_digest": m_digest,
                "depth": depth_val,
                "parent_commitments": commitments,
                "manifest": norm_manifest,
            }
        )

    ancestry_statements.sort(key=lambda s: (s["depth"], s["output_digest"]))
    sorted_roots = [closure_roots[k] for k in sorted(closure_roots.keys())]

    _validate_closure_domain_consistency(sorted_roots, ancestry_statements)

    valid_subjects: set[str] = set(closure_ancestry_raw.keys()) | set(
        closure_roots.keys()
    )
    normalized_refs: list[dict[str, Any]] = []

    if trust_references:
        for raw_ref in trust_references:
            norm_ref = _normalize_trust_reference(raw_ref)
            if norm_ref["subject_id"] in closure_roots:
                _check_ref_matches_root(norm_ref, closure_roots[norm_ref["subject_id"]])
                normalized_refs.append(norm_ref)
            elif norm_ref["subject_id"] in closure_ancestry_raw:
                _check_ref_matches_ancestry(
                    norm_ref,
                    closure_ancestry_raw[norm_ref["subject_id"]][0],
                    sorted_roots,
                )
                normalized_refs.append(norm_ref)

    if c2pa_manifests:
        if not isinstance(c2pa_manifests, list):
            raise LineageValidationError("c2pa_manifests must be a list")
        for c2pa_item in c2pa_manifests:
            try:
                c2pa_ref = extract_c2pa_portable_trust_reference(c2pa_item)
            except C2paParseError as exc:
                if exc.reason == "remote_reference_prohibited":
                    raise LineageValidationError(
                        "external URL references are not permitted in portable lineage bundles"
                    ) from exc
                raise LineageValidationError(
                    f"invalid C2PA manifest in portable bundle: {exc.reason}"
                ) from exc

            matched_subject = _match_c2pa_ref_to_closure(
                c2pa_ref, closure_roots, closure_ancestry_raw, sorted_roots
            )
            if matched_subject is not None and matched_subject in valid_subjects:
                normalized_refs.append(
                    _make_canonical_trust_reference(
                        kind="c2pa_manifest",
                        subject_id=matched_subject,
                        network=c2pa_ref.network,
                        contract_id=c2pa_ref.contract_id,
                        anchor_digest=c2pa_ref.manifest_digest,
                        c2pa_trust_status=c2pa_ref.c2pa_trust_status,
                    )
                )

    dedup_refs = {
        (r["subject_id"], r["kind"], r["reference_digest"]): r for r in normalized_refs
    }
    sorted_refs = [dedup_refs[k] for k in sorted(dedup_refs.keys())]

    bundle_body: dict[str, Any] = {
        "schema": PORTABLE_LINEAGE_BUNDLE_SCHEMA,
        "version": PORTABLE_LINEAGE_BUNDLE_VERSION,
        "target_id": target_norm,
        "root_statements": sorted_roots,
        "ancestry_statements": ancestry_statements,
        "trust_references": sorted_refs,
    }
    bundle_digest = hashlib.sha256(_canonical_json_bytes(bundle_body)).hexdigest()
    full_bundle = dict(bundle_body)
    full_bundle["bundle_digest"] = bundle_digest

    encoded = _canonical_json_bytes(full_bundle)
    if len(encoded) > max_bytes:
        raise LineageValidationError("portable lineage bundle exceeds size limit")

    verify_portable_lineage_bundle(full_bundle, max_nodes=max_nodes, max_bytes=max_bytes)
    return full_bundle


def verify_portable_lineage_bundle(
    bundle: dict[str, Any] | bytes | str,
    *,
    max_nodes: int = MAX_PORTABLE_BUNDLE_NODES,
    max_bytes: int = MAX_PORTABLE_BUNDLE_BYTES,
) -> PortableBundleVerificationReport:
    """
    Verify a portable lineage verification bundle completely offline.

    Rejects oversized payloads, external URL or remote-fetch references,
    tampered digests, missing parents, direct/transitive cycles, understated or
    overstated depths, tier-privacy leaks, unreferenced orphan statements, and
    contradictory roots without performing network I/O.
    """
    if not isinstance(max_nodes, int) or max_nodes < 1 or max_nodes > MAX_PORTABLE_BUNDLE_NODES:
        raise LineageValidationError("max_nodes must be between 1 and 32")
    if not isinstance(max_bytes, int) or max_bytes < 256 or max_bytes > MAX_PORTABLE_BUNDLE_BYTES:
        raise LineageValidationError("max_bytes exceeds portable bundle limit")

    if isinstance(bundle, (bytes, str)):
        raw_bytes = bundle.encode("utf-8") if isinstance(bundle, str) else bundle
        if len(raw_bytes) > max_bytes:
            raise LineageValidationError("portable lineage bundle exceeds size limit")
        try:
            data = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LineageValidationError("portable bundle must be valid UTF-8 JSON") from exc
    elif isinstance(bundle, dict):
        _check_bundle_json_depth(bundle, limit=MAX_PORTABLE_JSON_DEPTH)
        try:
            raw_bytes = _canonical_json_bytes(bundle)
        except (TypeError, ValueError) as exc:
            raise LineageValidationError("portable bundle must be JSON serializable") from exc
        if len(raw_bytes) > max_bytes:
            raise LineageValidationError("portable lineage bundle exceeds size limit")
        data = bundle
    else:
        raise LineageValidationError("portable bundle must be a JSON object or string")

    _check_bundle_json_depth(data, limit=MAX_PORTABLE_JSON_DEPTH)
    _reject_bundle_urls(data)

    if not isinstance(data, dict):
        raise LineageValidationError("portable bundle must be a JSON object")

    if data.get("schema") != PORTABLE_LINEAGE_BUNDLE_SCHEMA:
        raise LineageValidationError("unsupported portable bundle schema")
    if data.get("version") != PORTABLE_LINEAGE_BUNDLE_VERSION:
        raise LineageValidationError("unsupported portable bundle version")

    target_id = data.get("target_id")
    if not isinstance(target_id, str) or not _is_hex_32(target_id):
        raise LineageValidationError("target_id must be a 32-byte hex string")
    target_norm = target_id.lower()
    if target_id != target_norm:
        raise LineageValidationError("target_id must be canonical lowercase hex")

    bundle_digest = data.get("bundle_digest")
    if not isinstance(bundle_digest, str) or not _is_hex_32(bundle_digest):
        raise LineageValidationError("bundle_digest must be a 32-byte hex string")

    raw_roots = data.get("root_statements")
    raw_ancestry = data.get("ancestry_statements")
    raw_refs = data.get("trust_references")

    if not isinstance(raw_roots, list):
        raise LineageValidationError("root_statements must be a list")
    if not isinstance(raw_ancestry, list):
        raise LineageValidationError("ancestry_statements must be a list")
    if not isinstance(raw_refs, list):
        raise LineageValidationError("trust_references must be a list")

    total_nodes = len(raw_roots) + len(raw_ancestry)
    if total_nodes == 0:
        raise LineageValidationError("portable bundle cannot be empty")
    if total_nodes > max_nodes:
        raise LineageValidationError("portable bundle node count exceeds limit")

    roots_by_proof: dict[str, dict[str, Any]] = {}
    roots_by_video: dict[str, dict[str, Any]] = {}
    validated_roots: list[dict[str, Any]] = []

    for root_entry in raw_roots:
        norm_root = _validate_serialized_root_statement(root_entry)
        pid = norm_root["proof_id"]
        vh = norm_root["video_hash"]
        if pid in roots_by_proof:
            if roots_by_proof[pid] != norm_root:
                raise LineageValidationError("contradictory root statements detected")
            raise LineageValidationError("duplicate root statement in portable bundle")
        if vh in roots_by_video:
            if roots_by_video[vh] != norm_root:
                raise LineageValidationError("contradictory root statements detected")
            raise LineageValidationError("duplicate root statement in portable bundle")
        roots_by_proof[pid] = norm_root
        roots_by_video[vh] = norm_root
        validated_roots.append(norm_root)

    ancestry_by_out: dict[str, dict[str, Any]] = {}
    validated_ancestry: list[dict[str, Any]] = []

    for anc_entry in raw_ancestry:
        norm_anc = _validate_serialized_ancestry_statement(anc_entry)
        out_id = norm_anc["output_digest"]
        if out_id in ancestry_by_out:
            raise LineageValidationError("duplicate ancestry statement in portable bundle")
        if out_id in roots_by_proof or out_id in roots_by_video:
            raise LineageValidationError(
                "contradictory root and derivative statement for digest"
            )
        ancestry_by_out[out_id] = norm_anc
        validated_ancestry.append(norm_anc)

    _validate_closure_domain_consistency(validated_roots, validated_ancestry)

    visited_ancestry: set[str] = set()
    visited_roots: set[str] = set()
    computed_depths: dict[str, int] = {}

    def _verify_node(node_ref: str, hop_depth: int, path_stack: frozenset[str]) -> tuple[str, str, int]:
        anc = ancestry_by_out.get(node_ref)
        r_by_p = roots_by_proof.get(node_ref)
        r_by_v = roots_by_video.get(node_ref)
        if r_by_p is not None and r_by_v is not None and r_by_p != r_by_v:
            raise LineageValidationError("contradictory root statements detected")
        root_stmt = r_by_p if r_by_p is not None else r_by_v

        if anc is not None and root_stmt is not None:
            raise LineageValidationError(
                "contradictory root and derivative statement for digest"
            )

        if anc is None:
            if root_stmt is None:
                if hop_depth == 0:
                    raise LineageValidationError(
                        "target statement not found in portable bundle"
                    )
                raise LineageValidationError(
                    "missing parent statement in portable bundle closure"
                )
            visited_roots.add(root_stmt["proof_id"])
            return ("root", root_stmt["proof_id"], 0)

        if hop_depth >= MAX_LINEAGE_DEPTH:
            raise LineageValidationError("lineage depth exceeds limit")

        visited_ancestry.add(anc["output_digest"])
        parents = [str(p).lower() for p in anc["manifest"]["parentProofIds"]]
        expected_commitments: list[str] = []
        max_parent_depth = 0

        for parent_id in parents:
            if parent_id in path_stack:
                raise LineageValidationError(
                    "lineage cycle detected in portable bundle closure"
                )
            p_kind, p_key, p_depth = _verify_node(
                parent_id, hop_depth + 1, path_stack | {parent_id}
            )
            if p_depth > max_parent_depth:
                max_parent_depth = p_depth
            if p_kind == "root":
                p_root = roots_by_proof[p_key]
                expected_commitments.append(
                    compute_parent_commitment(
                        p_root["video_hash"], p_root["metadata_hash"]
                    )
                )
            else:
                p_anc = ancestry_by_out[p_key]
                expected_commitments.append(
                    compute_parent_commitment(
                        p_anc["manifest_digest"], p_anc["output_digest"]
                    )
                )

        derived_depth = 1 + max_parent_depth
        if derived_depth > MAX_LINEAGE_DEPTH:
            raise LineageValidationError("lineage depth exceeds limit")
        if anc["depth"] != derived_depth:
            raise LineageValidationError("ancestry depth mismatch in portable bundle")
        if anc["parent_commitments"] != expected_commitments:
            raise LineageValidationError(
                "parent commitments mismatch in portable bundle"
            )
        computed_depths[anc["output_digest"]] = derived_depth
        return ("ancestry", anc["output_digest"], derived_depth)

    target_kind, _, target_depth = _verify_node(
        target_norm, 0, frozenset({target_norm})
    )

    if len(visited_roots) != len(validated_roots) or len(visited_ancestry) != len(
        validated_ancestry
    ):
        raise LineageValidationError(
            "portable bundle contains unreferenced statements outside graph closure"
        )

    valid_subjects = visited_roots | visited_ancestry
    seen_ref_keys: set[tuple[str, str, str]] = set()
    c2pa_statuses: set[str] = set()
    validated_refs: list[dict[str, Any]] = []

    for ref_entry in raw_refs:
        norm_ref = _validate_serialized_trust_reference(ref_entry)
        subj = norm_ref["subject_id"]
        if subj not in valid_subjects:
            raise LineageValidationError(
                "unreferenced trust anchor in portable bundle"
            )
        if subj in roots_by_proof:
            _check_ref_matches_root(norm_ref, roots_by_proof[subj])
        else:
            _check_ref_matches_ancestry(
                norm_ref, ancestry_by_out[subj]["manifest"], validated_roots
            )
        ref_key = (subj, norm_ref["kind"], norm_ref["reference_digest"])
        if ref_key in seen_ref_keys:
            raise LineageValidationError("duplicate trust reference in portable bundle")
        seen_ref_keys.add(ref_key)
        if norm_ref["c2pa_trust_status"] is not None:
            c2pa_statuses.add(norm_ref["c2pa_trust_status"])
        validated_refs.append(norm_ref)

    expected_body = {
        "schema": PORTABLE_LINEAGE_BUNDLE_SCHEMA,
        "version": PORTABLE_LINEAGE_BUNDLE_VERSION,
        "target_id": target_norm,
        "root_statements": raw_roots,
        "ancestry_statements": raw_ancestry,
        "trust_references": raw_refs,
    }
    expected_bundle_digest = hashlib.sha256(
        _canonical_json_bytes(expected_body)
    ).hexdigest()
    if bundle_digest.lower() != expected_bundle_digest:
        raise LineageValidationError("bundle_digest mismatch")

    extra_keys = set(data.keys()) - (set(expected_body.keys()) | {"bundle_digest"})
    if extra_keys:
        raise LineageValidationError("unexpected top-level field in portable bundle")

    closure_network = validated_roots[0]["network"]
    closure_contract = validated_roots[0]["contract_id"]

    return PortableBundleVerificationReport(
        valid=True,
        target_id=target_norm,
        bundle_digest=expected_bundle_digest,
        is_derivative=(target_kind == "ancestry"),
        max_depth=target_depth,
        node_count=total_nodes,
        root_proof_ids=tuple(sorted(visited_roots)),
        ancestry_output_digests=tuple(sorted(visited_ancestry)),
        network=closure_network,
        contract_id=closure_contract,
        trust_reference_count=len(validated_refs),
        c2pa_trust_statuses=tuple(sorted(c2pa_statuses)),
    )


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _check_bundle_json_depth(obj: Any, *, limit: int, _current: int = 0) -> None:
    if _current > limit:
        raise LineageValidationError("portable bundle JSON nesting depth exceeds limit")
    if isinstance(obj, dict):
        for val in obj.values():
            _check_bundle_json_depth(val, limit=limit, _current=_current + 1)
    elif isinstance(obj, list):
        for item in obj:
            _check_bundle_json_depth(item, limit=limit, _current=_current + 1)


def _reject_bundle_urls(obj: Any) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k) in _BUNDLE_PROHIBITED_URL_KEYS:
                raise LineageValidationError(
                    "external URL references are not permitted in portable lineage bundles"
                )
            _reject_bundle_urls(v)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _reject_bundle_urls(item)
    elif isinstance(obj, str):
        lowered = obj.strip().lower()
        if any(
            lowered.startswith(scheme) for scheme in _BUNDLE_PROHIBITED_URL_SCHEMES
        ):
            raise LineageValidationError(
                "external URL references are not permitted in portable lineage bundles"
            )


def _canonical_root_statement_digest(
    *,
    proof_id: str,
    video_hash: str,
    metadata_hash: str,
    tier: str,
    network: str,
    contract_id: str,
) -> str:
    payload = {
        "protocol": "harpocrates.root/v1",
        "proof_id": proof_id,
        "video_hash": video_hash,
        "metadata_hash": metadata_hash,
        "tier": tier,
        "network": network,
        "contract_id": contract_id,
    }
    return hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()


def _normalize_root_statement(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise LineageValidationError("root statement must be a JSON object")

    if (
        raw.get("revoked") is True
        or str(raw.get("event_type", "")).lower() == "revoke"
        or str(raw.get("tx_status", "")).lower() in ("revoked", "failed")
        or str(raw.get("status", "")).lower() in ("revoked", "failed")
    ):
        raise LineageValidationError(
            "revoked or failed root statement cannot anchor a portable bundle"
        )

    proof_id = raw.get("proof_id") if "proof_id" in raw else raw.get("proofId")
    video_hash = raw.get("video_hash") if "video_hash" in raw else raw.get("videoHash")
    metadata_hash = (
        raw.get("metadata_hash") if "metadata_hash" in raw else raw.get("metadataHash")
    )
    tier = raw.get("tier")
    network = raw.get("network")
    contract_id = (
        raw.get("contract_id") if "contract_id" in raw else raw.get("contractId")
    )

    for field_name, val in (
        ("proof_id", proof_id),
        ("video_hash", video_hash),
        ("metadata_hash", metadata_hash),
    ):
        if not isinstance(val, str) or not _is_hex_32(val):
            raise LineageValidationError(
                f"root statement {field_name} must be a 32-byte hex string"
            )

    if not isinstance(tier, str) or tier not in _ALLOWED_ROOT_TIERS:
        raise LineageValidationError(
            "root statement tier must be silent, source, or seal"
        )

    if tier == "silent":
        for addr_key in (
            "source_address",
            "sourceAddress",
            "actor_address",
            "actorAddress",
        ):
            addr_val = raw.get(addr_key)
            if isinstance(addr_val, str) and addr_val.strip():
                raise LineageValidationError(
                    "silent tier root statement cannot carry an actor identity"
                )

    if not isinstance(network, str) or not network.strip():
        raise LineageValidationError("root statement network is required")
    if not isinstance(contract_id, str) or not contract_id.strip():
        raise LineageValidationError("root statement contract_id is required")

    pid_norm = proof_id.lower()
    vh_norm = video_hash.lower()
    mh_norm = metadata_hash.lower()
    net_norm = network.strip()
    cid_norm = contract_id.strip()

    expected_digest = _canonical_root_statement_digest(
        proof_id=pid_norm,
        video_hash=vh_norm,
        metadata_hash=mh_norm,
        tier=tier,
        network=net_norm,
        contract_id=cid_norm,
    )
    supplied_digest = raw.get("statement_digest") or raw.get("statementDigest")
    if supplied_digest is not None:
        if (
            not isinstance(supplied_digest, str)
            or supplied_digest.lower() != expected_digest
        ):
            raise LineageValidationError("root statement_digest mismatch")

    return {
        "proof_id": pid_norm,
        "video_hash": vh_norm,
        "metadata_hash": mh_norm,
        "tier": tier,
        "network": net_norm,
        "contract_id": cid_norm,
        "statement_digest": expected_digest,
    }


def _validate_serialized_root_statement(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise LineageValidationError("root statement must be a JSON object")
    required_keys = {
        "proof_id",
        "video_hash",
        "metadata_hash",
        "tier",
        "network",
        "contract_id",
        "statement_digest",
    }
    if set(raw.keys()) != required_keys:
        raise LineageValidationError("root statement has invalid key set")
    norm = _normalize_root_statement(raw)
    if norm != raw:
        raise LineageValidationError("root statement is not canonically normalized")
    return norm


def _index_root_statements_input(
    root_statements: Any,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_proof: dict[str, dict[str, Any]] = {}
    by_video: dict[str, dict[str, Any]] = {}
    if root_statements is None or callable(root_statements):
        return by_proof, by_video

    items: list[Any]
    if isinstance(root_statements, dict):
        items = list(root_statements.values())
    elif isinstance(root_statements, list):
        items = root_statements
    else:
        raise LineageValidationError("root_statements must be a dict, list, or callable")

    for entry in items:
        norm = _normalize_root_statement(entry)
        pid = norm["proof_id"]
        vh = norm["video_hash"]
        if pid in by_proof and by_proof[pid] != norm:
            raise LineageValidationError("contradictory root statements detected")
        if vh in by_video and by_video[vh] != norm:
            raise LineageValidationError("contradictory root statements detected")
        by_proof[pid] = norm
        by_video[vh] = norm

    return by_proof, by_video


def _index_lineage_records_input(lineage_records: Any) -> dict[str, Any]:
    index: dict[str, Any] = {}
    if lineage_records is None or callable(lineage_records):
        return index

    if isinstance(lineage_records, dict):
        for k, v in lineage_records.items():
            if not isinstance(k, str) or not _is_hex_32(k):
                raise LineageValidationError(
                    "lineage_records keys must be 32-byte hex strings"
                )
            key_norm = k.lower()
            if key_norm in index and index[key_norm] != v:
                raise LineageValidationError(
                    "contradictory lineage statements detected"
                )
            index[key_norm] = v
        return index

    if isinstance(lineage_records, list):
        for item in lineage_records:
            if not isinstance(item, dict):
                raise LineageValidationError("lineage record must be a JSON object")
            m_obj = item.get("manifest") if "manifest" in item else item
            if not isinstance(m_obj, dict):
                raise LineageValidationError("lineage manifest must be a JSON object")
            out_val = m_obj.get("outputDigest")
            if not isinstance(out_val, str) or not _is_hex_32(out_val):
                raise LineageValidationError(
                    "lineage outputDigest must be a 32-byte hex string"
                )
            out_norm = out_val.lower()
            if out_norm in index:
                _, prev_digest, _ = _normalize_ancestry_record(out_norm, index[out_norm])
                _, curr_digest, _ = _normalize_ancestry_record(out_norm, item)
                if prev_digest != curr_digest:
                    raise LineageValidationError(
                        "contradictory lineage statements detected"
                    )
            index[out_norm] = item
        return index

    raise LineageValidationError("lineage_records must be a dict, list, or callable")


def _resolve_lineage_entry(
    digest_hex: str, index: dict[str, Any], raw_source: Any
) -> Any:
    if digest_hex in index:
        return index[digest_hex]
    if callable(raw_source):
        found = raw_source(digest_hex)
        if found is None:
            found = raw_source(digest_hex.upper())
        return found
    return None


def _normalize_ancestry_record(
    expected_output: str, record: Any
) -> tuple[dict[str, Any], str, list[str]]:
    if not isinstance(record, dict):
        raise LineageValidationError("lineage record must be a JSON object")
    manifest_in = record.get("manifest") if "manifest" in record else record
    if not isinstance(manifest_in, dict):
        raise LineageValidationError("lineage manifest must be a JSON object")

    output_raw = manifest_in.get("outputDigest")
    params_raw = manifest_in.get("parametersDigest")
    parents_raw = manifest_in.get("parentProofIds")
    actor_raw = manifest_in.get("actorAddress")

    if not isinstance(output_raw, str) or not _is_hex_32(output_raw):
        raise LineageValidationError("outputDigest must be a 32-byte hex string")
    if output_raw.lower() != expected_output:
        raise LineageValidationError("lineage record outputDigest mismatch")
    if not isinstance(params_raw, str) or not _is_hex_32(params_raw):
        raise LineageValidationError("parametersDigest must be a 32-byte hex string")
    if not isinstance(actor_raw, str) or not actor_raw.strip():
        raise LineageValidationError("actorAddress is required")
    if not isinstance(parents_raw, list) or not parents_raw:
        raise LineageValidationError("parentProofIds must be a non-empty array")

    lower_manifest_in = dict(manifest_in)
    lower_manifest_in["outputDigest"] = output_raw.lower()
    lower_manifest_in["parametersDigest"] = params_raw.lower()
    lower_manifest_in["parentProofIds"] = [
        p.lower() if isinstance(p, str) else p for p in parents_raw
    ]
    lower_manifest_in["network"] = str(manifest_in.get("network", "")).strip()
    if not lower_manifest_in["network"]:
        raise LineageValidationError("lineage network is required")

    canonical_str = canonical_lineage_manifest(lower_manifest_in)
    normalized_manifest = json.loads(canonical_str)
    parents_norm = [str(p).lower() for p in normalized_manifest["parentProofIds"]]
    if len(set(parents_norm)) != len(parents_norm):
        raise LineageValidationError("duplicate parentProofIds are not permitted")
    if expected_output in parents_norm:
        raise LineageValidationError(
            "lineage cycle detected in portable bundle closure"
        )

    expected_digest = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
    stored_digest = record.get("manifest_digest") or record.get("manifestDigest")
    if stored_digest is not None:
        orig_digest = lineage_manifest_digest(manifest_in)
        if not isinstance(stored_digest, str) or stored_digest.lower() not in (
            expected_digest,
            orig_digest,
        ):
            raise LineageValidationError("lineage manifest_digest mismatch")

    return normalized_manifest, expected_digest, parents_norm


def _validate_serialized_ancestry_statement(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise LineageValidationError("ancestry statement must be a JSON object")
    required_keys = {
        "output_digest",
        "manifest_digest",
        "depth",
        "parent_commitments",
        "manifest",
    }
    if set(raw.keys()) != required_keys:
        raise LineageValidationError("ancestry statement has invalid key set")

    out_digest = raw.get("output_digest")
    if not isinstance(out_digest, str) or not _is_hex_32(out_digest):
        raise LineageValidationError("ancestry output_digest must be 32-byte hex")
    if out_digest != out_digest.lower():
        raise LineageValidationError(
            "ancestry output_digest must be canonical lowercase hex"
        )

    depth = raw.get("depth")
    if not isinstance(depth, int) or isinstance(depth, bool) or depth < 1 or depth > MAX_LINEAGE_DEPTH:
        raise LineageValidationError("ancestry depth exceeds bounds")

    commitments = raw.get("parent_commitments")
    if not isinstance(commitments, list) or not commitments:
        raise LineageValidationError("parent_commitments must be a non-empty list")
    for c in commitments:
        if not isinstance(c, str) or not _is_hex_32(c) or c != c.lower():
            raise LineageValidationError(
                "parent_commitments must contain canonical 32-byte lowercase hex"
            )

    norm_manifest, expected_digest, parents_norm = _normalize_ancestry_record(
        out_digest, raw
    )
    if raw.get("manifest") != norm_manifest:
        raise LineageValidationError("ancestry manifest is not canonically normalized")
    if raw.get("manifest_digest") != expected_digest:
        raise LineageValidationError("ancestry manifest_digest mismatch")
    if len(commitments) != len(parents_norm):
        raise LineageValidationError("parent_commitments count mismatch")

    return raw


def _validate_closure_domain_consistency(
    roots: list[dict[str, Any]], ancestry: list[dict[str, Any]]
) -> None:
    if not roots:
        raise LineageValidationError("portable bundle requires at least one root statement")

    networks = {r["network"] for r in roots}
    contracts = {r["contract_id"] for r in roots}
    if len(networks) > 1 or len(contracts) > 1:
        raise LineageValidationError(
            "contradictory root network or contract binding in bundle closure"
        )

    expected_net = roots[0]["network"]
    for anc in ancestry:
        manifest_obj = anc["manifest"]
        if manifest_obj.get("network") != expected_net:
            raise LineageValidationError(
                "lineage edge network contradicts root statement network"
            )


def _make_canonical_trust_reference(
    *,
    kind: str,
    subject_id: str,
    network: str,
    contract_id: str,
    anchor_digest: str,
    c2pa_trust_status: str | None,
) -> dict[str, Any]:
    core = {
        "protocol": "harpocrates.trust_ref/v1",
        "kind": kind,
        "subject_id": subject_id,
        "network": network,
        "contract_id": contract_id,
        "anchor_digest": anchor_digest,
        "c2pa_trust_status": c2pa_trust_status,
    }
    ref_digest = hashlib.sha256(_canonical_json_bytes(core)).hexdigest()
    return {
        "kind": kind,
        "subject_id": subject_id,
        "network": network,
        "contract_id": contract_id,
        "anchor_digest": anchor_digest,
        "c2pa_trust_status": c2pa_trust_status,
        "reference_digest": ref_digest,
    }


def _normalize_trust_reference(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise LineageValidationError("trust reference must be a JSON object")
    kind = raw.get("kind")
    if not isinstance(kind, str) or kind not in _ALLOWED_TRUST_KINDS:
        raise LineageValidationError("unsupported trust reference kind")

    subject_id = raw.get("subject_id") if "subject_id" in raw else raw.get("subjectId")
    anchor_digest = (
        raw.get("anchor_digest") if "anchor_digest" in raw else raw.get("anchorDigest")
    )
    network = raw.get("network")
    contract_id = (
        raw.get("contract_id") if "contract_id" in raw else raw.get("contractId")
    )

    if not isinstance(subject_id, str) or not _is_hex_32(subject_id):
        raise LineageValidationError("trust reference subject_id must be 32-byte hex")
    if not isinstance(anchor_digest, str) or not _is_hex_32(anchor_digest):
        raise LineageValidationError(
            "trust reference anchor_digest must be 32-byte hex"
        )
    if not isinstance(network, str) or not network.strip():
        raise LineageValidationError("trust reference network is required")
    if not isinstance(contract_id, str) or not contract_id.strip():
        raise LineageValidationError("trust reference contract_id is required")

    c2pa_status = raw.get("c2pa_trust_status")
    if kind == "c2pa_manifest":
        if c2pa_status is None:
            c2pa_status = C2paTrustStatus.SIGNATURE_NOT_CHECKED.value
        if c2pa_status != C2paTrustStatus.SIGNATURE_NOT_CHECKED.value:
            raise LineageValidationError(
                "c2pa_manifest trust reference must preserve signature_not_checked status"
            )
    else:
        if c2pa_status is not None:
            raise LineageValidationError(
                "non-C2PA trust reference cannot set c2pa_trust_status"
            )

    built = _make_canonical_trust_reference(
        kind=kind,
        subject_id=subject_id.lower(),
        network=network.strip(),
        contract_id=contract_id.strip(),
        anchor_digest=anchor_digest.lower(),
        c2pa_trust_status=c2pa_status,
    )
    supplied_ref_digest = raw.get("reference_digest")
    if supplied_ref_digest is not None:
        if (
            not isinstance(supplied_ref_digest, str)
            or supplied_ref_digest.lower() != built["reference_digest"]
        ):
            raise LineageValidationError("trust reference_digest mismatch")
    return built


def _validate_serialized_trust_reference(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise LineageValidationError("trust reference must be a JSON object")
    required_keys = {
        "kind",
        "subject_id",
        "network",
        "contract_id",
        "anchor_digest",
        "c2pa_trust_status",
        "reference_digest",
    }
    if set(raw.keys()) != required_keys:
        raise LineageValidationError("trust reference has invalid key set")
    norm = _normalize_trust_reference(raw)
    if norm != raw:
        raise LineageValidationError("trust reference is not canonically normalized")
    return norm


def _check_ref_matches_root(ref: dict[str, Any], root: dict[str, Any]) -> None:
    if ref["network"] != root["network"] or ref["contract_id"] != root["contract_id"]:
        raise LineageValidationError(
            "contradictory trust reference for root statement"
        )


def _check_ref_matches_ancestry(
    ref: dict[str, Any],
    manifest_obj: dict[str, Any],
    roots: list[dict[str, Any]],
) -> None:
    expected_contract = roots[0]["contract_id"] if roots else None
    if ref["network"] != manifest_obj.get("network"):
        raise LineageValidationError(
            "contradictory trust reference network for ancestry statement"
        )
    if expected_contract is not None and ref["contract_id"] != expected_contract:
        raise LineageValidationError(
            "contradictory trust reference contract_id for ancestry statement"
        )


def _match_c2pa_ref_to_closure(
    c2pa_ref: C2paPortableTrustReference,
    closure_roots: dict[str, dict[str, Any]],
    closure_ancestry: dict[str, tuple[dict[str, Any], str, list[str]]],
    sorted_roots: list[dict[str, Any]],
) -> str | None:
    if c2pa_ref.subject_id in closure_roots:
        root = closure_roots[c2pa_ref.subject_id]
        if (
            c2pa_ref.video_hash != root["video_hash"]
            or c2pa_ref.metadata_hash != root["metadata_hash"]
            or c2pa_ref.tier != root["tier"]
            or c2pa_ref.network != root["network"]
            or c2pa_ref.contract_id != root["contract_id"]
        ):
            raise LineageValidationError(
                "contradictory C2PA binding for root statement"
            )
        return c2pa_ref.subject_id

    for pid, root in closure_roots.items():
        if c2pa_ref.video_hash == root["video_hash"]:
            raise LineageValidationError(
                "contradictory C2PA binding for root statement"
            )

    for candidate in (c2pa_ref.subject_id, c2pa_ref.video_hash):
        if candidate in closure_ancestry:
            manifest_obj = closure_ancestry[candidate][0]
            expected_contract = sorted_roots[0]["contract_id"] if sorted_roots else None
            if c2pa_ref.network != manifest_obj.get("network"):
                raise LineageValidationError(
                    "contradictory C2PA binding network for ancestry statement"
                )
            if expected_contract is not None and c2pa_ref.contract_id != expected_contract:
                raise LineageValidationError(
                    "contradictory C2PA binding contract_id for ancestry statement"
                )
            return candidate

    return None
