from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from typing import Any

from c2pa import (
    C2paIngredientDependency,
    C2paParseError,
    C2paTrustStatus,
    parse_c2pa_with_dependencies,
)

SUPPORTED_OPERATIONS = {"crop", "transcode", "blur", "redact", "compose"}
MAX_LINEAGE_DEPTH = 4
MAX_LINEAGE_FANOUT = 4
MAX_LINEAGE_PAYLOAD_BYTES = 4096


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


class LineageVerificationStatus(str, Enum):
    """
    Distinct verification verdicts for lineage completeness inspection.

    ``INCOMPLETE_LINEAGE`` is strictly separated from ``VERIFIED_ORIGINAL`` and
    ``VERIFIED_DERIVATIVE`` so callers never mistake a partially resolved
    provenance graph or an uncovered C2PA ingredient claim for a verified
    original evidence record.
    """

    VERIFIED_ORIGINAL = "verified_original"
    VERIFIED_DERIVATIVE = "verified_derivative"
    INCOMPLETE_LINEAGE = "incomplete_lineage"
    UNVERIFIED = "unverified"
    INVALID_LINEAGE = "invalid_lineage"


@dataclass(frozen=True)
class VerifiedLineageEdge:
    """A canonically verified transformation edge whose endpoints both resolved."""

    parent_id: str
    child_id: str
    operation_type: str
    manifest_digest: str
    depth: int
    parent_kind: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "parent_id": self.parent_id,
            "child_id": self.child_id,
            "operation_type": self.operation_type,
            "manifest_digest": self.manifest_digest,
            "depth": self.depth,
            "parent_kind": self.parent_kind,
        }


@dataclass(frozen=True)
class MissingLineageDependency:
    """An explicit unresolved or unconfirmed provenance dependency."""

    dependency_id: str | None
    referenced_by: str
    depth: int
    reason: str
    source: str = "lineage_manifest"

    def to_dict(self) -> dict[str, Any]:
        return {
            "dependency_id": self.dependency_id,
            "referenced_by": self.referenced_by,
            "depth": self.depth,
            "reason": self.reason,
            "source": self.source,
        }


@dataclass(frozen=True)
class LineageVerificationResult:
    """
    Structured result of ``verify_lineage_completeness``.

    Invariants:
    - ``is_verified`` is ``True`` ONLY for ``VERIFIED_ORIGINAL`` and
      ``VERIFIED_DERIVATIVE``.
    - ``is_original`` is ``True`` ONLY for ``VERIFIED_ORIGINAL``.
    - ``INCOMPLETE_LINEAGE`` always sets ``is_verified=False``,
      ``is_original=False``, and ``is_complete=False`` while preserving both
      ``verified_edges`` and ``missing_dependencies``.
    """

    target_id: str
    status: LineageVerificationStatus
    is_verified: bool
    is_original: bool
    is_complete: bool
    verified_edges: tuple[VerifiedLineageEdge, ...] = ()
    missing_dependencies: tuple[MissingLineageDependency, ...] = ()
    verified_roots: tuple[str, ...] = ()
    c2pa_trust_status: str | None = None
    error_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "target_id": self.target_id,
            "status": self.status.value,
            "is_verified": self.is_verified,
            "is_original": self.is_original,
            "is_complete": self.is_complete,
            "verified_edges": [edge.to_dict() for edge in self.verified_edges],
            "missing_dependencies": [dep.to_dict() for dep in self.missing_dependencies],
            "verified_roots": list(self.verified_roots),
            "c2pa_trust_status": self.c2pa_trust_status,
            "error_reason": self.error_reason,
        }
        return payload


class _InvalidGraphError(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def verify_lineage_completeness(
    target_id: str,
    *,
    get_lineage_fn: Any = None,
    get_proof_fn: Any = None,
    c2pa_manifest: Any = None,
) -> LineageVerificationResult:
    """
    Inspect the bounded provenance graph of ``target_id`` and return an explicit
    completeness verdict without conflating incomplete graphs with verified
    originals.

    Args:
        target_id: 32-byte hex digest of the target output or root proof.
        get_lineage_fn: Optional lookup ``(digest: str) -> dict | None`` for
            lineage transformation records.
        get_proof_fn: Optional lookup ``(digest: str) -> bool | dict | list | None``
            for registered root proof records.
        c2pa_manifest: Optional ``C2paParsedManifest``, JSON dict, or UTF-8 JSON
            bytes/str whose declared ingredient claims must be covered by
            verified Harpocrates lineage edges.
    """
    if not isinstance(target_id, str) or not _is_hex_32(target_id):
        return LineageVerificationResult(
            target_id="",
            status=LineageVerificationStatus.INVALID_LINEAGE,
            is_verified=False,
            is_original=False,
            is_complete=False,
            error_reason="invalid_target_id",
        )

    target_norm = target_id.lower()
    c2pa_deps: tuple[C2paIngredientDependency, ...] = ()
    c2pa_trust: str | None = None

    if c2pa_manifest is not None:
        try:
            parsed_c2pa, c2pa_deps = parse_c2pa_with_dependencies(c2pa_manifest)
        except C2paParseError as exc:
            return LineageVerificationResult(
                target_id=target_norm,
                status=LineageVerificationStatus.INVALID_LINEAGE,
                is_verified=False,
                is_original=False,
                is_complete=False,
                c2pa_trust_status=C2paTrustStatus.PARSE_FAILED.value,
                error_reason=f"c2pa_{exc.reason}",
            )

        if target_norm not in (
            parsed_c2pa.binding.proof_id,
            parsed_c2pa.binding.video_hash,
        ):
            return LineageVerificationResult(
                target_id=target_norm,
                status=LineageVerificationStatus.INVALID_LINEAGE,
                is_verified=False,
                is_original=False,
                is_complete=False,
                c2pa_trust_status=C2paTrustStatus.BINDING_MISMATCH.value,
                error_reason="c2pa_binding_target_mismatch",
            )
        c2pa_trust = parsed_c2pa.trust_status.value

    root_record = _lookup_lineage_record(target_norm, get_lineage_fn)
    target_proof_state, metadata_parents = _inspect_proof_lookup(
        target_norm, get_proof_fn
    )

    if target_proof_state == "revoked":
        return LineageVerificationResult(
            target_id=target_norm,
            status=LineageVerificationStatus.INVALID_LINEAGE,
            is_verified=False,
            is_original=False,
            is_complete=False,
            c2pa_trust_status=c2pa_trust,
            error_reason="revoked_target_proof",
        )

    if root_record is None:
        uncovered_missing: list[MissingLineageDependency] = []
        for dep in c2pa_deps:
            uncovered_missing.append(
                MissingLineageDependency(
                    dependency_id=dep.dependency_id,
                    referenced_by=target_norm,
                    depth=1,
                    reason=(
                        "unverified_c2pa_ingredient"
                        if dep.dependency_id is None
                        else "missing_lineage_edge"
                    ),
                    source="c2pa_ingredient",
                )
            )
        for parent_hex in metadata_parents:
            uncovered_missing.append(
                MissingLineageDependency(
                    dependency_id=parent_hex,
                    referenced_by=target_norm,
                    depth=1,
                    reason="missing_lineage_edge",
                    source="proof_metadata",
                )
            )

        if uncovered_missing:
            if target_proof_state != "verified":
                uncovered_missing.append(
                    MissingLineageDependency(
                        dependency_id=target_norm,
                        referenced_by=target_norm,
                        depth=0,
                        reason=(
                            "unconfirmed_target_proof"
                            if target_proof_state == "unconfirmed"
                            else "target_not_found"
                        ),
                        source="target_lookup",
                    )
                )
            return LineageVerificationResult(
                target_id=target_norm,
                status=LineageVerificationStatus.INCOMPLETE_LINEAGE,
                is_verified=False,
                is_original=False,
                is_complete=False,
                verified_edges=(),
                missing_dependencies=_sort_missing_dependencies(uncovered_missing),
                verified_roots=(),
                c2pa_trust_status=c2pa_trust,
            )

        if target_proof_state == "verified":
            return LineageVerificationResult(
                target_id=target_norm,
                status=LineageVerificationStatus.VERIFIED_ORIGINAL,
                is_verified=True,
                is_original=True,
                is_complete=True,
                verified_edges=(),
                missing_dependencies=(),
                verified_roots=(target_norm,),
                c2pa_trust_status=c2pa_trust,
            )

        return LineageVerificationResult(
            target_id=target_norm,
            status=LineageVerificationStatus.UNVERIFIED,
            is_verified=False,
            is_original=False,
            is_complete=False,
            verified_edges=(),
            missing_dependencies=(
                MissingLineageDependency(
                    dependency_id=target_norm,
                    referenced_by=target_norm,
                    depth=0,
                    reason=(
                        "unconfirmed_target_proof"
                        if target_proof_state == "unconfirmed"
                        else "target_not_found"
                    ),
                    source="target_lookup",
                ),
            ),
            verified_roots=(),
            c2pa_trust_status=c2pa_trust,
        )

    edge_map: dict[tuple[str, str, str], VerifiedLineageEdge] = {}
    missing_map: dict[tuple[str | None, str, str, str], MissingLineageDependency] = {}
    verified_roots: set[str] = set()
    validated_cache: dict[str, tuple[dict[str, Any], str, list[str]]] = {}

    def _validate_node_record(
        node_id: str, record: Any
    ) -> tuple[dict[str, Any], str, list[str]]:
        if node_id in validated_cache:
            return validated_cache[node_id]

        if not isinstance(record, dict):
            raise _InvalidGraphError("malformed_lineage_record")

        manifest_obj = record.get("manifest") if "manifest" in record else record
        if not isinstance(manifest_obj, dict):
            raise _InvalidGraphError("malformed_lineage_manifest")

        try:
            canonical_str = canonical_lineage_manifest(manifest_obj)
        except LineageValidationError as exc:
            msg = str(exc).lower()
            if "fan-out" in msg:
                raise _InvalidGraphError("fanout_exceeded") from exc
            if "too large" in msg:
                raise _InvalidGraphError("manifest_too_large") from exc
            if "unsupported" in msg:
                raise _InvalidGraphError("unsupported_operation") from exc
            raise _InvalidGraphError("malformed_lineage_manifest") from exc

        normalized_manifest = json.loads(canonical_str)
        output_hex = str(normalized_manifest["outputDigest"]).lower()
        if not _is_hex_32(output_hex) or output_hex != node_id:
            raise _InvalidGraphError("output_digest_mismatch")

        actor = str(normalized_manifest.get("actorAddress", "")).strip()
        if not actor:
            raise _InvalidGraphError("missing_actor_address")

        if not _is_hex_32(str(normalized_manifest.get("parametersDigest", ""))):
            raise _InvalidGraphError("invalid_parameters_digest")

        expected_digest = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
        stored_digest = record.get("manifest_digest") or record.get("manifestDigest")
        if stored_digest is not None:
            if (
                not isinstance(stored_digest, str)
                or stored_digest.lower() != expected_digest
            ):
                raise _InvalidGraphError("manifest_digest_mismatch")

        parents_norm = [str(p).lower() for p in normalized_manifest["parentProofIds"]]
        if len(set(parents_norm)) != len(parents_norm):
            raise _InvalidGraphError("duplicate_parent_id")

        if "parent_proof_ids" in record and record["parent_proof_ids"] is not None:
            raw_row_parents = record["parent_proof_ids"]
            if not isinstance(raw_row_parents, list):
                raise _InvalidGraphError("parent_list_mismatch")
            row_parents_norm = [str(p).lower() for p in raw_row_parents]
            if row_parents_norm != parents_norm:
                raise _InvalidGraphError("parent_list_mismatch")

        result_tuple = (normalized_manifest, expected_digest, parents_norm)
        validated_cache[node_id] = result_tuple
        return result_tuple

    def _record_edge(edge: VerifiedLineageEdge) -> None:
        key = (edge.parent_id, edge.child_id, edge.manifest_digest)
        existing = edge_map.get(key)
        if existing is None or edge.depth > existing.depth:
            edge_map[key] = edge

    def _record_missing(dep: MissingLineageDependency) -> None:
        key = (dep.dependency_id, dep.referenced_by, dep.reason, dep.source)
        existing = missing_map.get(key)
        if existing is None or dep.depth > existing.depth:
            missing_map[key] = dep

    def _walk(node_id: str, record: Any, edge_depth: int, path_stack: frozenset[str]) -> None:
        if edge_depth > MAX_LINEAGE_DEPTH:
            raise _InvalidGraphError("max_depth_exceeded")

        normalized_manifest, expected_digest, parents_norm = _validate_node_record(
            node_id, record
        )
        op_type = str(normalized_manifest["operationType"])

        for parent_id in parents_norm:
            if parent_id in path_stack:
                raise _InvalidGraphError("cycle_detected")

            parent_lineage = _lookup_lineage_record(parent_id, get_lineage_fn)
            parent_proof_state, _ = _inspect_proof_lookup(parent_id, get_proof_fn)
            if parent_proof_state == "revoked":
                raise _InvalidGraphError("revoked_parent_proof")

            if parent_lineage is not None:
                _walk(
                    parent_id,
                    parent_lineage,
                    edge_depth + 1,
                    path_stack | {parent_id},
                )
                _record_edge(
                    VerifiedLineageEdge(
                        parent_id=parent_id,
                        child_id=node_id,
                        operation_type=op_type,
                        manifest_digest=expected_digest,
                        depth=edge_depth,
                        parent_kind="lineage_record",
                    )
                )
            else:
                if parent_proof_state == "verified":
                    verified_roots.add(parent_id)
                    _record_edge(
                        VerifiedLineageEdge(
                            parent_id=parent_id,
                            child_id=node_id,
                            operation_type=op_type,
                            manifest_digest=expected_digest,
                            depth=edge_depth,
                            parent_kind="root_proof",
                        )
                    )
                elif parent_proof_state == "unconfirmed":
                    _record_missing(
                        MissingLineageDependency(
                            dependency_id=parent_id,
                            referenced_by=node_id,
                            depth=edge_depth,
                            reason="unconfirmed_parent_proof",
                            source="lineage_manifest",
                        )
                    )
                else:
                    _record_missing(
                        MissingLineageDependency(
                            dependency_id=parent_id,
                            referenced_by=node_id,
                            depth=edge_depth,
                            reason="missing_parent_proof",
                            source="lineage_manifest",
                        )
                    )

    try:
        _walk(target_norm, root_record, 1, frozenset({target_norm}))
    except _InvalidGraphError as exc:
        return LineageVerificationResult(
            target_id=target_norm,
            status=LineageVerificationStatus.INVALID_LINEAGE,
            is_verified=False,
            is_original=False,
            is_complete=False,
            c2pa_trust_status=c2pa_trust,
            error_reason=exc.reason,
        )

    _, _, root_parents_norm = validated_cache[target_norm]
    covered_direct_parents = set(root_parents_norm)

    for dep in c2pa_deps:
        if dep.dependency_id is None:
            _record_missing(
                MissingLineageDependency(
                    dependency_id=None,
                    referenced_by=target_norm,
                    depth=1,
                    reason="unverified_c2pa_ingredient",
                    source="c2pa_ingredient",
                )
            )
        elif dep.dependency_id not in covered_direct_parents:
            _record_missing(
                MissingLineageDependency(
                    dependency_id=dep.dependency_id,
                    referenced_by=target_norm,
                    depth=1,
                    reason="missing_lineage_edge",
                    source="c2pa_ingredient",
                )
            )

    for parent_hex in metadata_parents:
        if parent_hex not in covered_direct_parents:
            _record_missing(
                MissingLineageDependency(
                    dependency_id=parent_hex,
                    referenced_by=target_norm,
                    depth=1,
                    reason="missing_lineage_edge",
                    source="proof_metadata",
                )
            )

    sorted_edges = _sort_verified_edges(list(edge_map.values()))
    sorted_missing = _sort_missing_dependencies(list(missing_map.values()))
    sorted_roots = tuple(sorted(verified_roots))

    if sorted_missing:
        return LineageVerificationResult(
            target_id=target_norm,
            status=LineageVerificationStatus.INCOMPLETE_LINEAGE,
            is_verified=False,
            is_original=False,
            is_complete=False,
            verified_edges=sorted_edges,
            missing_dependencies=sorted_missing,
            verified_roots=sorted_roots,
            c2pa_trust_status=c2pa_trust,
        )

    return LineageVerificationResult(
        target_id=target_norm,
        status=LineageVerificationStatus.VERIFIED_DERIVATIVE,
        is_verified=True,
        is_original=False,
        is_complete=True,
        verified_edges=sorted_edges,
        missing_dependencies=(),
        verified_roots=sorted_roots,
        c2pa_trust_status=c2pa_trust,
    )


def _lookup_lineage_record(digest_lower: str, get_lineage_fn: Any) -> Any:
    if get_lineage_fn is None:
        return None
    record = get_lineage_fn(digest_lower)
    if record is None:
        record = get_lineage_fn(digest_lower.upper())
    return record


def _inspect_proof_lookup(
    digest_lower: str, get_proof_fn: Any
) -> tuple[str, tuple[str, ...]]:
    """
    Classify the result of ``get_proof_fn(digest)`` into one of:
    ``("verified" | "unconfirmed" | "revoked" | "missing", declared_parents)``.
    """
    if get_proof_fn is None:
        return "missing", ()

    raw = get_proof_fn(digest_lower)
    if raw is None or raw is False or raw == []:
        raw_upper = get_proof_fn(digest_lower.upper())
        if raw_upper is not None and raw_upper is not False and raw_upper != []:
            raw = raw_upper

    if raw is None or raw is False:
        return "missing", ()
    if raw is True:
        return "verified", ()

    if isinstance(raw, dict):
        events = [raw]
    elif isinstance(raw, (list, tuple)):
        events = [item for item in raw if isinstance(item, dict)]
        if not events:
            return "missing", ()
    else:
        return "missing", ()

    declared_parents: set[str] = set()
    for ev in events:
        meta = ev.get("metadata")
        if isinstance(meta, dict):
            for key in ("parentProofIds", "parent_proof_ids", "lineageParentIds"):
                vals = meta.get(key)
                if isinstance(vals, list):
                    for candidate in vals:
                        if isinstance(candidate, str) and _is_hex_32(candidate):
                            declared_parents.add(candidate.lower())

    for ev in events:
        if (
            ev.get("revoked") is True
            or str(ev.get("event_type", "")).lower() == "revoke"
            or str(ev.get("tx_status", "")).lower() == "revoked"
            or str(ev.get("status", "")).lower() == "revoked"
        ):
            return "revoked", tuple(sorted(declared_parents))

    has_verified = False
    for ev in events:
        if ev.get("verified") is False or ev.get("confirmed") is False:
            continue
        has_status_key = "tx_status" in ev or "status" in ev
        tx_st = str(ev.get("tx_status") or "").lower()
        st = str(ev.get("status") or "").lower()
        if not has_status_key:
            has_verified = True
            break
        if tx_st in ("confirmed", "verified") or st in ("confirmed", "verified"):
            has_verified = True
            break

    if has_verified:
        return "verified", tuple(sorted(declared_parents))
    return "unconfirmed", tuple(sorted(declared_parents))


def _sort_verified_edges(
    edges: list[VerifiedLineageEdge],
) -> tuple[VerifiedLineageEdge, ...]:
    return tuple(
        sorted(
            edges,
            key=lambda e: (e.depth, e.child_id, e.parent_id, e.manifest_digest),
        )
    )


def _sort_missing_dependencies(
    deps: list[MissingLineageDependency],
) -> tuple[MissingLineageDependency, ...]:
    return tuple(
        sorted(
            deps,
            key=lambda d: (
                d.depth,
                d.referenced_by,
                d.dependency_id or "~",
                d.reason,
                d.source,
            ),
        )
    )
