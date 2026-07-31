from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from verifier_inputs import (
    BN254_SCALAR_FIELD_MODULUS,
    REDACTION_PUBLIC_INPUTS_LEN,
    SCHEMA_REDACTION_WITNESS,
    VerifierInputError,
    check_proof_bounds,
    decode_hex,
    parse_redaction_witness_inputs,
)

SUPPORTED_OPERATIONS = {"crop", "transcode", "blur", "redact", "compose"}
MAX_LINEAGE_DEPTH = 4
MAX_LINEAGE_FANOUT = 4
MAX_LINEAGE_PAYLOAD_BYTES = 4096
REDACTION_OPERATION_CODES = {
    "crop": 1,
    "transcode": 2,
    "blur": 3,
    "redact": 4,
    "compose": 5,
}
REDACTION_REPLAY_DOMAIN = b"harpocrates:redaction-lineage:v1:"


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


def redaction_replay_binding(manifest: dict[str, Any]) -> bytes:
    """Derive the canonical field binding for a lineage claim.

    The circuit receives only this fixed-width field.  The full canonical
    manifest is never made public to the proof system and private parameters
    therefore cannot leak through verifier inputs.
    """
    digest = hashlib.sha256(
        REDACTION_REPLAY_DOMAIN + canonical_lineage_manifest(manifest).encode("utf-8")
    ).digest()
    return (int.from_bytes(digest, "big") % BN254_SCALAR_FIELD_MODULUS).to_bytes(32, "big")


def validate_redaction_witness_binding(manifest: dict[str, Any], witness: Any) -> None:
    """Validate a redaction proof's public frame against a lineage manifest.

    This intentionally validates *only* the canonical wire frame and its
    manifest binding. Cryptographic proof verification must be performed by a
    pinned UltraHonk verification key in the browser or registry; callers must
    never treat this boundary check as proof verification.
    """
    if not isinstance(witness, dict):
        raise LineageValidationError("redactionWitness must be an object")
    if witness.get("schema") != SCHEMA_REDACTION_WITNESS:
        raise LineageValidationError("redactionWitness schema is invalid")
    try:
        public_inputs = decode_hex(witness.get("publicInputs"), field="public_inputs")
        proof = decode_hex(witness.get("proof"), field="proof")
        if len(public_inputs) != REDACTION_PUBLIC_INPUTS_LEN:
            raise LineageValidationError("redactionWitness public inputs have invalid length")
        parsed = parse_redaction_witness_inputs(public_inputs)
        check_proof_bounds(proof)
    except VerifierInputError as exc:
        raise LineageValidationError(f"redactionWitness rejected: {exc.code.value}") from None

    expected_operation = REDACTION_OPERATION_CODES[manifest["operationType"]]
    if int.from_bytes(parsed.operation_type, "big") != expected_operation:
        raise LineageValidationError("redactionWitness operation does not match lineage manifest")
    if parsed.replay_binding != redaction_replay_binding(manifest):
        raise LineageValidationError("redactionWitness replay binding does not match lineage manifest")


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
