from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Callable

SUPPORTED_OPERATIONS = {"crop", "transcode", "blur", "redact", "compose"}
MAX_LINEAGE_DEPTH = 4
MAX_LINEAGE_FANOUT = 4
MAX_LINEAGE_PAYLOAD_BYTES = 4096
LINEAGE_AUDIT_SCHEMA = "harpocrates.lineage.audit/v1"
LINEAGE_AUDIT_VERSION = 1
MAX_AUDIT_EXPORT_NODES = 64
PARENT_COMMITMENT_DOMAIN = b"harp_lin_pc"

_LOCATION_FIELD_NAMES = frozenset(
    {
        "sourcelocation",
        "source_location",
        "sourceuri",
        "source_uri",
        "gps",
        "gpscoordinates",
        "gps_coordinates",
        "latitude",
        "longitude",
        "lat",
        "lon",
        "lng",
        "location",
        "capturelocation",
        "capture_location",
        "geo",
        "geotag",
    }
)

_FILENAME_FIELD_NAMES = frozenset(
    {
        "filename",
        "file_name",
        "uploadfilename",
        "upload_filename",
        "originalfilename",
        "original_filename",
        "inputpath",
        "input_path",
        "outputpath",
        "output_path",
        "filepath",
        "file_path",
        "localpath",
        "local_path",
        "storagepath",
        "storage_path",
        "sourcepath",
        "source_path",
        "sourcefile",
        "source_file",
    }
)

_SAFE_TOOL_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:@+-]{1,128}$")


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


def _looks_like_private_path_or_uri(value: str) -> tuple[bool, bool]:
    """Return ``(is_location_uri, is_file_path)`` heuristics for a string value."""
    stripped = value.strip()
    lower = stripped.lower()
    is_loc = lower.startswith(("geo:", "file://", "s3://", "gs://"))
    is_path = (
        lower.startswith("file://")
        or "\\" in stripped
        or stripped.startswith("/")
        or bool(re.match(r"^[a-zA-Z]:[/\\]", stripped))
        or bool(
            re.search(
                r"\.(mp4|mov|avi|mkv|webm|wav|mp3|jpg|jpeg|png|json)$",
                lower,
            )
        )
    )
    return is_loc, is_path


def redact_lineage_private_fields(payload: Any) -> tuple[Any, dict[str, Any]]:
    """Strip private source locations and upload filenames from nested lineage inputs."""
    flags = {"source_location": False, "upload_filename": False}

    def _walk(item: Any) -> Any:
        if isinstance(item, dict):
            cleaned: dict[str, Any] = {}
            for raw_k, raw_v in item.items():
                norm_k = str(raw_k).strip().lower().replace("-", "")
                norm_k_plain = norm_k.replace("_", "")
                if norm_k in _LOCATION_FIELD_NAMES or norm_k_plain in _LOCATION_FIELD_NAMES:
                    flags["source_location"] = True
                    continue
                if norm_k in _FILENAME_FIELD_NAMES or norm_k_plain in _FILENAME_FIELD_NAMES:
                    flags["upload_filename"] = True
                    continue
                cleaned[raw_k] = _walk(raw_v)
            return cleaned
        if isinstance(item, list):
            return [_walk(v) for v in item]
        if isinstance(item, str):
            is_loc, is_path = _looks_like_private_path_or_uri(item)
            if is_loc:
                flags["source_location"] = True
            if is_path:
                flags["upload_filename"] = True
            if is_loc or is_path:
                return "[REDACTED]"
        return item

    sanitized = _walk(payload)
    categories = sorted(cat for cat, active in flags.items() if active)
    summary = {
        "redacted_source_location": flags["source_location"],
        "redacted_upload_filename": flags["upload_filename"],
        "redacted_field_categories": categories,
    }
    return sanitized, summary


def compute_parent_commitment(binding_a_hex: str, binding_b_hex: str) -> str:
    """Compute canonical ``SHA-256('harp_lin_pc' || binding_a || binding_b)`` digest."""
    if not isinstance(binding_a_hex, str) or not _is_hex_32(binding_a_hex):
        raise LineageValidationError("binding_a must be a 32-byte hex value")
    if not isinstance(binding_b_hex, str) or not _is_hex_32(binding_b_hex):
        raise LineageValidationError("binding_b must be a 32-byte hex value")
    hasher = hashlib.sha256()
    hasher.update(PARENT_COMMITMENT_DOMAIN)
    hasher.update(bytes.fromhex(binding_a_hex))
    hasher.update(bytes.fromhex(binding_b_hex))
    return hasher.hexdigest()


def compute_proof_statement_digest(statement: dict[str, Any]) -> str:
    """Compute or validate a deterministic SHA-256 digest for a public proof statement."""
    if not isinstance(statement, dict):
        raise LineageValidationError("proof statement must be a JSON object")

    proof_id = statement.get("proof_id") or statement.get("proofId")
    if not isinstance(proof_id, str) or not _is_hex_32(proof_id):
        raise LineageValidationError("proof statement requires a 32-byte hex proof_id")

    explicit_digest = statement.get("statement_digest") or statement.get("statementDigest")
    if explicit_digest is not None:
        if not isinstance(explicit_digest, str) or not _is_hex_32(explicit_digest):
            raise LineageValidationError("statement_digest must be a 32-byte hex value")

    video_hash = statement.get("video_hash") or statement.get("videoHash")
    metadata_hash = statement.get("metadata_hash") or statement.get("metadataHash")

    if video_hash is None and metadata_hash is None and explicit_digest is not None:
        return explicit_digest.lower()

    if not isinstance(video_hash, str) or not _is_hex_32(video_hash):
        raise LineageValidationError("proof statement requires a 32-byte hex video_hash")
    if not isinstance(metadata_hash, str) or not _is_hex_32(metadata_hash):
        raise LineageValidationError("proof statement requires a 32-byte hex metadata_hash")

    canonical_payload: dict[str, Any] = {
        "protocol": "harpocrates",
        "statement_version": 1,
        "proof_id": proof_id.lower(),
        "video_hash": video_hash.lower(),
        "metadata_hash": metadata_hash.lower(),
        "tier": str(statement.get("tier") or "source").strip(),
        "network": str(statement.get("network") or "").strip(),
    }
    contract_id = statement.get("contract_id") or statement.get("contractId")
    if isinstance(contract_id, str) and contract_id.strip():
        canonical_payload["contract_id"] = contract_id.strip()

    computed = hashlib.sha256(
        json.dumps(canonical_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()

    if explicit_digest is not None and explicit_digest.lower() != computed:
        raise LineageValidationError("statement_digest does not match canonical proof statement")

    return computed


def export_lineage_audit_trail(
    target_output_digest: str,
    lineage_records: list[dict[str, Any]] | Callable[[str], dict[str, Any] | None],
    *,
    source_proofs: (
        dict[str, dict[str, Any]]
        | list[dict[str, Any]]
        | Callable[[str], dict[str, Any] | None]
        | None
    ) = None,
    require_verified_ancestry: bool = True,
) -> dict[str, Any]:
    """Export a deterministic, privacy-redacted source-to-derivative lineage audit trail."""
    if not isinstance(target_output_digest, str) or not _is_hex_32(target_output_digest):
        raise LineageValidationError("target_output_digest must be a 32-byte hex value")
    target_id = target_output_digest.lower()

    redacted_loc = False
    redacted_fn = False

    def _merge_redaction(raw_obj: Any) -> None:
        nonlocal redacted_loc, redacted_fn
        _, summary = redact_lineage_private_fields(raw_obj)
        if summary["redacted_source_location"]:
            redacted_loc = True
        if summary["redacted_upload_filename"]:
            redacted_fn = True

    lineage_map: dict[str, dict[str, Any]] = {}
    if isinstance(lineage_records, list):
        if len(lineage_records) > MAX_AUDIT_EXPORT_NODES:
            raise LineageValidationError("lineage_records exceeds audit export node limit")
        for rec in lineage_records:
            if not isinstance(rec, dict):
                raise LineageValidationError("each lineage record must be a JSON object")
            _merge_redaction(rec)
            manifest_obj = rec.get("manifest") if isinstance(rec.get("manifest"), dict) else rec
            out_dig = manifest_obj.get("outputDigest") or rec.get("output_digest")
            if not isinstance(out_dig, str) or not _is_hex_32(out_dig):
                raise LineageValidationError("lineage record missing valid outputDigest")
            lineage_map[out_dig.lower()] = rec

        def _get_lineage(output_hex: str) -> dict[str, Any] | None:
            return lineage_map.get(output_hex.lower())
    elif callable(lineage_records):
        def _get_lineage(output_hex: str) -> dict[str, Any] | None:
            found = lineage_records(output_hex.lower()) or lineage_records(output_hex)
            if isinstance(found, dict):
                _merge_redaction(found)
            return found
    else:
        raise LineageValidationError("lineage_records must be a list or lookup callable")

    proof_map: dict[str, dict[str, Any]] = {}
    if isinstance(source_proofs, dict):
        for k, v in source_proofs.items():
            if isinstance(v, dict):
                _merge_redaction(v)
                proof_map[str(k).lower()] = v
    elif isinstance(source_proofs, list):
        for item in source_proofs:
            if isinstance(item, dict):
                _merge_redaction(item)
                pid = item.get("proof_id") or item.get("proofId")
                if isinstance(pid, str) and _is_hex_32(pid):
                    proof_map[pid.lower()] = item

    def _get_proof(proof_hex: str) -> dict[str, Any] | None:
        key = proof_hex.lower()
        if key in proof_map:
            return proof_map[key]
        if callable(source_proofs):
            found = source_proofs(key) or source_proofs(proof_hex)
            if isinstance(found, dict):
                _merge_redaction(found)
                return found
        return None

    target_record = _get_lineage(target_id)
    if not isinstance(target_record, dict):
        raise LineageValidationError("target lineage record not found")

    verified_derivatives: dict[str, dict[str, Any]] = {}
    resolved_proofs: dict[str, dict[str, Any]] = {}
    active_stack: set[str] = set()

    def _resolve_derivative(node_hex: str, visit_depth: int) -> int:
        """Return topological depth >= 1 (1 for children of source proofs)."""
        if visit_depth > MAX_LINEAGE_DEPTH:
            raise LineageValidationError("lineage depth exceeds limit")
        if node_hex in active_stack:
            raise LineageValidationError("lineage cycle detected during audit export")
        if node_hex in verified_derivatives:
            return int(verified_derivatives[node_hex]["depth"])

        if len(verified_derivatives) >= MAX_AUDIT_EXPORT_NODES:
            raise LineageValidationError("audit export exceeded maximum node limit")

        raw_rec = _get_lineage(node_hex)
        if not isinstance(raw_rec, dict):
            raise LineageValidationError(f"missing derivative record: {node_hex}")

        active_stack.add(node_hex)
        manifest_obj = raw_rec.get("manifest") if isinstance(raw_rec.get("manifest"), dict) else raw_rec
        canonical_str = canonical_lineage_manifest(manifest_obj)
        canonical_manifest = json.loads(canonical_str)
        computed_manifest_digest = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        if str(canonical_manifest["outputDigest"]).lower() != node_hex:
            raise LineageValidationError("lineage manifest outputDigest does not match target key")

        declared_md = raw_rec.get("manifest_digest") or raw_rec.get("manifestDigest")
        if declared_md is not None:
            if not isinstance(declared_md, str) or declared_md.lower() != computed_manifest_digest:
                raise LineageValidationError("stored manifest_digest does not match canonical manifest")

        parents = [str(p).lower() for p in canonical_manifest["parentProofIds"]]
        if node_hex in parents:
            raise LineageValidationError("lineage cycle detected: output digest appears in parents")

        max_parent_depth = 0
        parent_links_meta: list[dict[str, Any]] = []

        for parent_hex in parents:
            parent_deriv = _get_lineage(parent_hex)
            if isinstance(parent_deriv, dict) or parent_hex in verified_derivatives:
                p_depth = _resolve_derivative(parent_hex, visit_depth + 1)
                max_parent_depth = max(max_parent_depth, p_depth)
                p_entry = verified_derivatives[parent_hex]
                parent_links_meta.append(
                    {
                        "parent_id": parent_hex,
                        "parent_kind": "derivative",
                        "parent_statement_digest": p_entry["manifest_digest"],
                        "parent_commitment": compute_parent_commitment(
                            p_entry["manifest_digest"],
                            parent_hex,
                        ),
                    }
                )
            else:
                proof_rec = _get_proof(parent_hex)
                if proof_rec is None:
                    if require_verified_ancestry:
                        raise LineageValidationError("unverified parent proof statement in lineage")
                    parent_links_meta.append(
                        {
                            "parent_id": parent_hex,
                            "parent_kind": "unverified_reference",
                            "parent_statement_digest": None,
                            "parent_commitment": None,
                        }
                    )
                else:
                    stmt_digest = compute_proof_statement_digest(
                        {**proof_rec, "proof_id": parent_hex}
                    )
                    vh = proof_rec.get("video_hash") or proof_rec.get("videoHash")
                    mh = proof_rec.get("metadata_hash") or proof_rec.get("metadataHash")
                    p_comm = (
                        compute_parent_commitment(str(vh).lower(), str(mh).lower())
                        if isinstance(vh, str)
                        and _is_hex_32(vh)
                        and isinstance(mh, str)
                        and _is_hex_32(mh)
                        else None
                    )
                    public_stmt: dict[str, Any] = {
                        "proof_id": parent_hex,
                        "statement_digest": stmt_digest,
                        "tier": str(proof_rec.get("tier") or "source").strip(),
                        "network": str(proof_rec.get("network") or "").strip(),
                    }
                    if isinstance(vh, str) and _is_hex_32(vh):
                        public_stmt["video_hash"] = vh.lower()
                    if isinstance(mh, str) and _is_hex_32(mh):
                        public_stmt["metadata_hash"] = mh.lower()
                    if "c2pa_trust_status" in proof_rec and isinstance(
                        proof_rec["c2pa_trust_status"], str
                    ):
                        public_stmt["c2pa_trust_status"] = proof_rec["c2pa_trust_status"]
                    resolved_proofs[parent_hex] = public_stmt
                    parent_links_meta.append(
                        {
                            "parent_id": parent_hex,
                            "parent_kind": "source_proof",
                            "parent_statement_digest": stmt_digest,
                            "parent_commitment": p_comm,
                        }
                    )

        derived_depth = max_parent_depth + 1
        if derived_depth > MAX_LINEAGE_DEPTH:
            raise LineageValidationError("lineage depth exceeds limit")

        raw_tool_id = str(canonical_manifest["toolIdentity"])
        is_loc, is_path = _looks_like_private_path_or_uri(raw_tool_id)
        if is_loc or is_path or not _SAFE_TOOL_TOKEN_RE.match(raw_tool_id):
            if is_loc:
                redacted_loc = True
            redacted_fn = True
            safe_tool_id = "[REDACTED_TOOL_PATH]"
        else:
            safe_tool_id = raw_tool_id

        verified_derivatives[node_hex] = {
            "output_digest": node_hex,
            "manifest_digest": computed_manifest_digest,
            "depth": derived_depth,
            "operation_type": str(canonical_manifest["operationType"]),
            "parameters_digest": str(canonical_manifest["parametersDigest"]).lower()
            if _is_hex_32(str(canonical_manifest["parametersDigest"]))
            else str(canonical_manifest["parametersDigest"]),
            "tool_identity": safe_tool_id,
            "tool_version": str(canonical_manifest["toolVersion"]),
            "network": str(canonical_manifest["network"]),
            "actor_address": str(canonical_manifest["actorAddress"]),
            "parent_links": parent_links_meta,
        }
        active_stack.remove(node_hex)
        return derived_depth

    _resolve_derivative(target_id, 1)

    ordered_proof_statements = [
        resolved_proofs[pid] for pid in sorted(resolved_proofs.keys())
    ]

    ordered_derivatives = sorted(
        verified_derivatives.values(),
        key=lambda item: (item["depth"], item["output_digest"]),
    )

    transformation_links: list[dict[str, Any]] = []
    for deriv in ordered_derivatives:
        for p_link in deriv["parent_links"]:
            transformation_links.append(
                {
                    "link_index": len(transformation_links),
                    "depth": deriv["depth"],
                    "parent_id": p_link["parent_id"],
                    "parent_kind": p_link["parent_kind"],
                    "parent_statement_digest": p_link["parent_statement_digest"],
                    "parent_commitment": p_link["parent_commitment"],
                    "child_output_digest": deriv["output_digest"],
                    "manifest_digest": deriv["manifest_digest"],
                    "operation_type": deriv["operation_type"],
                    "parameters_digest": deriv["parameters_digest"],
                    "tool_identity": deriv["tool_identity"],
                    "tool_version": deriv["tool_version"],
                    "network": deriv["network"],
                    "actor_address": deriv["actor_address"],
                    "verified": p_link["parent_kind"] != "unverified_reference",
                }
            )

    redacted_categories: list[str] = []
    if redacted_loc:
        redacted_categories.append("source_location")
    if redacted_fn:
        redacted_categories.append("upload_filename")

    export_body: dict[str, Any] = {
        "schema": LINEAGE_AUDIT_SCHEMA,
        "version": LINEAGE_AUDIT_VERSION,
        "target_output_digest": target_id,
        "proof_statements": ordered_proof_statements,
        "transformation_links": transformation_links,
        "redaction_summary": {
            "redacted_source_location": redacted_loc,
            "redacted_upload_filename": redacted_fn,
            "redacted_field_categories": redacted_categories,
        },
    }
    audit_digest = hashlib.sha256(
        json.dumps(export_body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    export_body["audit_digest"] = audit_digest
    return export_body
