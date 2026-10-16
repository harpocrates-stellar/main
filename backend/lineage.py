from __future__ import annotations

import hashlib
import json
import os
from typing import Any

# Protocol version for redacted derivative ancestry proofs.
# v1: legacy lineage manifests without redaction commitments.
# v2: adds optional redactionCommitment and redactionPolicy fields.
# v3: requires redaction commitments for redact/blur operations.
PROTOCOL_VERSION = 3
MIN_SUPPORTED_PROTOCOL_VERSION = 1
MAX_SUPPORTED_PROTOCOL_VERSION = 3

REDACTION_OPERATIONS = {"blur", "redact"}
REDACTION_POLICIES = {"none", "deterministic", "commitment"}

SUPPORTED_OPERATIONS = {"crop", "transcode", "blur", "redact", "compose"}
MAX_LINEAGE_DEPTH = 4
MAX_LINEAGE_FANOUT = 4
MAX_LINEAGE_PAYLOAD_BYTES = 4096


class LineageValidationError(ValueError):
    pass


class LineageRecordError(RuntimeError):
    pass


def _normalize_redaction_commitment(manifest: dict[str, Any]) -> dict[str, Any]:
    """Normalize and validate redaction commitment fields.

    Returns a normalized dict containing only the redaction commitment fields
    that are present. Raises LineageValidationError on malformed input.
    """
    normalized: dict[str, Any] = {}

    commitment = manifest.get("redactionCommitment")
    if commitment is not None:
        if not isinstance(commitment, str) or not _is_hex_32(commitment):
            raise LineageValidationError(
                "redactionCommitment must be a 32-byte hex value"
            )
        normalized["redactionCommitment"] = commitment.lower()

    policy = manifest.get("redactionPolicy")
    if policy is not None:
        if not isinstance(policy, str) or policy not in REDACTION_POLICIES:
            raise LineageValidationError("Unsupported redaction policy")
        normalized["redactionPolicy"] = policy

    attestation = manifest.get("redactionAttestation")
    if attestation is not None:
        if not isinstance(attestation, str) or not _is_hex_32(attestation):
            raise LineageValidationError(
                "redactionAttestation must be a 32-byte hex value"
            )
        normalized["redactionAttestation"] = attestation.lower()

    return normalized


def _resolve_protocol_version(manifest: dict[str, Any]) -> int:
    """Resolve the protocol version for a manifest.

    Absent version implies the legacy v1 manifest format. Explicit versions
    must be within the supported range.
    """
    raw_version = manifest.get("version")
    if raw_version is None:
        return 1
    if not isinstance(raw_version, int) or isinstance(raw_version, bool):
        raise LineageValidationError("unsupported lineage protocol version")
    if raw_version < MIN_SUPPORTED_PROTOCOL_VERSION or raw_version > MAX_SUPPORTED_PROTOCOL_VERSION:
        raise LineageValidationError("unsupported lineage protocol version")
    return raw_version


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

    protocol_version = _resolve_protocol_version(manifest)
    redaction_fields = _normalize_redaction_commitment(manifest)

    if protocol_version >= 3 and operation_type in REDACTION_OPERATIONS:
        if "redactionCommitment" not in redaction_fields:
            raise LineageValidationError(
                "redactionCommitment is required for redaction operations"
            )
        if "redactionPolicy" not in redaction_fields:
            raise LineageValidationError(
                "redactionPolicy is required for redaction operations"
            )

    normalized = {
        "protocol": "harpocrates",
        "version": protocol_version,
        "parentProofIds": [str(parent) for parent in parent_proofs],
        "operationType": operation_type,
        "parametersDigest": str(manifest["parametersDigest"]),
        "toolIdentity": str(manifest["toolIdentity"]),
        "toolVersion": str(manifest["toolVersion"]),
        "outputDigest": str(manifest["outputDigest"]),
        "network": str(manifest["network"]),
        "actorAddress": str(manifest["actorAddress"]),
    }
    normalized.update(redaction_fields)
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
    if not isinstance(depth, int) or isinstance(depth, bool):
        raise LineageValidationError("depth must be an integer")
    if depth < 0:
        raise LineageValidationError("depth must be non-negative")
    if depth > MAX_LINEAGE_DEPTH:
        raise LineageValidationError("lineage depth exceeds limit")
    if not isinstance(parent_proof_ids, list):
        raise LineageValidationError("parent_proof_ids must be a list")
    if len(parent_proof_ids) > MAX_LINEAGE_FANOUT:
        raise LineageValidationError("lineage fan-out exceeds limit")
    if not actor_address:
        raise LineageValidationError("actorAddress is required")

    for parent_id in parent_proof_ids:
        if not isinstance(parent_id, str) or not _is_hex_32(parent_id):
            raise LineageValidationError(
                "parent_proof_ids must contain 32-byte hex values"
            )

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
    parents = record.get("parent_proof_ids", $)
    for parent_id in parents:
        if _contains_in_ancestry(parent_id, target, get_lineage_fn, visited):
            return True

    return False


def _is_hex_32(value: str) -> bool:
    return len(value) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in value)
