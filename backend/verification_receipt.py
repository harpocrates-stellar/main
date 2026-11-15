"""Validation for the canonical verification-receipt input contract.

The frontend owns receipt versioning and signing. The backend validates
canonical evidence and parent-child derivative bindings fail-closed and emits
only the 12-field unsigned input shape, so there is one protocol contract and
no backend-owned signing or envelope versioning.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Literal, Mapping, Sequence, TypedDict

from lineage import (
    MAX_LINEAGE_FANOUT,
    canonical_lineage_manifest,
    lineage_manifest_digest,
)
from time_attestation import (
    TimeAttestation,
    decode_time_attestation,
    validate_attestation_evidence_binding,
)

PARENT_CHILD_BINDING_DOMAIN = "harpocrates:receipt-parent-child:v1"
FRONTEND_OWNED_ENVELOPE_FIELDS = frozenset(
    {
        "protocol",
        "version",
        "signer",
        "signature",
        "privateKey",
        "signingKey",
    }
)


class ReceiptBindingConflictError(ValueError):
    """Raised when evidence, parent, or derivative identifiers conflict."""


class VerificationReceiptInput(TypedDict):
    """Unsigned fields consumed by the frontend receipt signer."""

    result: Literal["verified", "unverified"]
    verifiedAt: str
    proofId: str
    videoHash: str
    metadataHash: str
    tier: Literal["silent", "source", "seal"]
    networkPassphrase: str
    contractId: str
    ledgerSequence: int | None
    transactionHash: str | None
    circuitVersion: str
    verifierVersion: str


def compute_parent_child_statement_digest(
    *,
    parent_proof_ids: Sequence[str],
    child_proof_id: str,
    child_video_hash: str,
    network_passphrase: str,
    lineage_manifest_digest_hex: str | None = None,
) -> str:
    """Compute a deterministic domain-separated SHA-256 over parent-child receipt bindings."""
    normalized_parents = _validate_parent_proof_ids(
        list(parent_proof_ids),
        child_proof_id=child_proof_id,
    )
    normalized_child_proof = _hex32(child_proof_id, "childProofId")
    normalized_child_video = _hex32(child_video_hash, "childVideoHash")
    normalized_network = _text(network_passphrase, "networkPassphrase")
    normalized_manifest_digest = (
        _hex32(lineage_manifest_digest_hex, "lineageManifestDigest")
        if lineage_manifest_digest_hex is not None
        else None
    )

    statement = {
        "domain": PARENT_CHILD_BINDING_DOMAIN,
        "parentProofIds": normalized_parents,
        "childProofId": normalized_child_proof,
        "childVideoHash": normalized_child_video,
        "networkPassphrase": normalized_network,
        "lineageManifestDigest": normalized_manifest_digest,
    }
    canonical = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def validate_receipt_statement_binding(
    context: Mapping[str, object],
    *,
    proof_id: str,
    video_hash: str,
    network_passphrase: str,
    transaction_hash: str | None,
) -> None:
    """Reject conflicting evidence, derivative, or parent-child statement fields."""
    forbidden = FRONTEND_OWNED_ENVELOPE_FIELDS.intersection(context.keys())
    if forbidden:
        field_list = ", ".join(sorted(forbidden))
        raise ReceiptBindingConflictError(
            f"frontend owns receipt signing and envelope versioning; forbidden field(s): {field_list}"
        )

    # 1. Direct evidence / derivative alias consistency against canonical proofId & videoHash
    if "evidenceDigest" in context and context.get("evidenceDigest") is not None:
        evidence_digest = _hex32(context.get("evidenceDigest"), "evidenceDigest")
        if evidence_digest != video_hash:
            raise ReceiptBindingConflictError(
                "conflicting evidence identifiers: evidenceDigest does not match videoHash"
            )

    if "derivativeProofId" in context and context.get("derivativeProofId") is not None:
        derivative_proof_id = _hex32(context.get("derivativeProofId"), "derivativeProofId")
        if derivative_proof_id != proof_id:
            raise ReceiptBindingConflictError(
                "conflicting derivative identifiers: derivativeProofId does not match proofId"
            )

    explicit_output_digest: str | None = None
    for alias in ("outputDigest", "derivativeVideoHash"):
        if alias in context and context.get(alias) is not None:
            alias_digest = _hex32(context.get(alias), alias)
            if alias_digest != video_hash:
                raise ReceiptBindingConflictError(
                    f"conflicting evidence and derivative identifiers: {alias} does not match videoHash"
                )
            explicit_output_digest = alias_digest

    # 2. Parent proof / statement consistency
    parent_ids: list[str] = []
    if "parentProofId" in context and context.get("parentProofId") is not None:
        single_parent = _hex32(context.get("parentProofId"), "parentProofId")
        parent_ids.append(single_parent)

    if "parentProofIds" in context and context.get("parentProofIds") is not None:
        raw_parents = context.get("parentProofIds")
        if not isinstance(raw_parents, list) or not raw_parents:
            raise ValueError("parentProofIds must be a non-empty array")
        listed_parents = [_hex32(item, "parentProofIds") for item in raw_parents]
        if parent_ids and parent_ids[0] not in listed_parents:
            raise ReceiptBindingConflictError(
                "conflicting parent identifiers: parentProofId is absent from parentProofIds"
            )
        parent_ids = listed_parents

    if "parentStatement" in context and context.get("parentStatement") is not None:
        parent_stmt = context.get("parentStatement")
        if not isinstance(parent_stmt, Mapping):
            raise ValueError("parentStatement must be a JSON object")
        stmt_proof_id = _hex32(parent_stmt.get("proofId"), "parentStatement.proofId")
        if stmt_proof_id == proof_id:
            raise ReceiptBindingConflictError(
                "conflicting parent-child identifiers: parentStatement.proofId equals child proofId"
            )
        if parent_ids and stmt_proof_id not in parent_ids:
            raise ReceiptBindingConflictError(
                "conflicting parent identifiers: parentStatement.proofId is absent from parentProofIds"
            )
        if not parent_ids:
            parent_ids = [stmt_proof_id]

        if parent_stmt.get("videoHash") is not None:
            stmt_video_hash = _hex32(parent_stmt.get("videoHash"), "parentStatement.videoHash")
            if stmt_video_hash == video_hash:
                raise ReceiptBindingConflictError(
                    "conflicting evidence and derivative identifiers: parentStatement.videoHash equals derivative videoHash"
                )
        if parent_stmt.get("networkPassphrase") is not None:
            stmt_network = _text(
                parent_stmt.get("networkPassphrase"),
                "parentStatement.networkPassphrase",
            )
            if stmt_network != network_passphrase:
                raise ReceiptBindingConflictError(
                    "conflicting parent-child networkPassphrase"
                )

    # 3. Canonical lineage manifest validation when derivative manifest is present
    computed_manifest_digest: str | None = None
    if "lineageManifest" in context and context.get("lineageManifest") is not None:
        raw_manifest = context.get("lineageManifest")
        if not isinstance(raw_manifest, dict):
            raise ValueError("lineageManifest must be a JSON object")
        # Validates operationType, fan-out <= 4, 32-byte parentProofIds, required fields, size cap
        canonical_lineage_manifest(raw_manifest)
        manifest_output = _hex32(raw_manifest.get("outputDigest"), "lineageManifest.outputDigest")
        if manifest_output != video_hash:
            raise ReceiptBindingConflictError(
                "conflicting evidence and derivative identifiers: lineageManifest.outputDigest does not match videoHash"
            )
        manifest_network = _text(raw_manifest.get("network"), "lineageManifest.network")
        if manifest_network != network_passphrase:
            raise ReceiptBindingConflictError(
                "conflicting network between lineageManifest and receipt context"
            )
        manifest_parents = [
            _hex32(parent, "lineageManifest.parentProofIds")
            for parent in raw_manifest["parentProofIds"]
        ]
        if parent_ids and [p.lower() for p in parent_ids] != manifest_parents:
            # Check set/sequence compatibility: if single parentProofId was supplied, ensure membership; if list was supplied, must match exact canonical order
            if "parentProofIds" in context:
                raise ReceiptBindingConflictError(
                    "conflicting parent identifiers: parentProofIds does not match lineageManifest.parentProofIds"
                )
            if parent_ids[0] not in manifest_parents:
                raise ReceiptBindingConflictError(
                    "conflicting parent identifiers: parentProofId is absent from lineageManifest.parentProofIds"
                )
        parent_ids = manifest_parents
        computed_manifest_digest = lineage_manifest_digest(raw_manifest)

    if "lineageManifestDigest" in context and context.get("lineageManifestDigest") is not None:
        declared_manifest_digest = _hex32(
            context.get("lineageManifestDigest"),
            "lineageManifestDigest",
        )
        if computed_manifest_digest is not None and declared_manifest_digest != computed_manifest_digest:
            raise ReceiptBindingConflictError(
                "conflicting derivative digest: lineageManifestDigest does not match canonical lineageManifest"
            )
        computed_manifest_digest = declared_manifest_digest

    if parent_ids:
        _validate_parent_proof_ids(parent_ids, child_proof_id=proof_id)

    if (
        "parentChildStatementDigest" in context
        and context.get("parentChildStatementDigest") is not None
    ):
        if not parent_ids:
            raise ReceiptBindingConflictError(
                "parentChildStatementDigest supplied without parent proof identifiers"
            )
        declared_binding = _hex32(
            context.get("parentChildStatementDigest"),
            "parentChildStatementDigest",
        )
        expected_binding = compute_parent_child_statement_digest(
            parent_proof_ids=parent_ids,
            child_proof_id=proof_id,
            child_video_hash=video_hash,
            network_passphrase=network_passphrase,
            lineage_manifest_digest_hex=computed_manifest_digest,
        )
        if declared_binding != expected_binding:
            raise ReceiptBindingConflictError(
                "canonical parent-child statement binding digest mismatch"
            )

    # 4. Time attestation cross-check when provided
    if "timeAttestation" in context and context.get("timeAttestation") is not None:
        raw_att = context.get("timeAttestation")
        if isinstance(raw_att, TimeAttestation):
            att = raw_att
        elif isinstance(raw_att, dict):
            att = decode_time_attestation(raw_att)
        else:
            raise ValueError("timeAttestation must be a JSON object")
        validate_attestation_evidence_binding(
            att,
            video_hash=video_hash,
            output_digest=explicit_output_digest,
            transaction_hash=transaction_hash,
            network_passphrase=network_passphrase,
        )


def build_verification_receipt(
    context: Mapping[str, object],
    *,
    result: Literal["verified", "unverified"] = "unverified",
) -> VerificationReceiptInput:
    """Validate canonical statement bindings and build the unsigned receipt input.

    A receipt is only emitted when the caller supplies a non-conflicting
    canonical evidence context. Frontend retains exclusive ownership of signing
    and envelope versioning.
    """
    if not isinstance(context, Mapping):
        raise ValueError("receipt context must be a mapping")

    proof_id = _hex32(context.get("proofId"), "proofId")
    video_hash = _hex32(context.get("videoHash"), "videoHash")
    metadata_hash = _hex32(context.get("metadataHash"), "metadataHash")
    tier: Literal["silent", "source", "seal"] = _choice(
        context.get("tier"),
        "tier",
        ("silent", "source", "seal"),
    )  # type: ignore[assignment]
    network_passphrase = _text(context.get("networkPassphrase"), "networkPassphrase")
    contract_id = _text(context.get("contractId"), "contractId")
    ledger_sequence = _optional_int(context.get("ledgerSequence"), "ledgerSequence")
    transaction_hash = _optional_hex32(context.get("transactionHash"), "transactionHash")
    circuit_version = _text(context.get("circuitVersion"), "circuitVersion")
    verifier_version = _text(context.get("verifierVersion"), "verifierVersion")

    validate_receipt_statement_binding(
        context,
        proof_id=proof_id,
        video_hash=video_hash,
        network_passphrase=network_passphrase,
        transaction_hash=transaction_hash,
    )

    return {
        "result": result,
        "verifiedAt": datetime.now(timezone.utc).isoformat(),
        "proofId": proof_id,
        "videoHash": video_hash,
        "metadataHash": metadata_hash,
        "tier": tier,
        "networkPassphrase": network_passphrase,
        "contractId": contract_id,
        "ledgerSequence": ledger_sequence,
        "transactionHash": transaction_hash,
        "circuitVersion": circuit_version,
        "verifierVersion": verifier_version,
    }


def _validate_parent_proof_ids(
    parent_proof_ids: list[str],
    *,
    child_proof_id: str,
) -> list[str]:
    if not parent_proof_ids:
        raise ValueError("parentProofIds must be non-empty")
    if len(parent_proof_ids) > MAX_LINEAGE_FANOUT:
        raise ValueError(f"parentProofIds exceeds maximum fan-out of {MAX_LINEAGE_FANOUT}")

    normalized_child = _hex32(child_proof_id, "proofId")
    normalized_parents: list[str] = []
    seen: set[str] = set()
    for raw_parent in parent_proof_ids:
        parent = _hex32(raw_parent, "parentProofIds")
        if parent == normalized_child:
            raise ReceiptBindingConflictError(
                "conflicting parent-child identifiers: proofId cannot appear in parentProofIds"
            )
        if parent in seen:
            raise ReceiptBindingConflictError(
                "duplicate parent proof identifier in parentProofIds"
            )
        seen.add(parent)
        normalized_parents.append(parent)
    return normalized_parents


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _hex32(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{field} must be a 32-byte hex string")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{field} must be a 32-byte hex string") from exc
    return value.lower()


def _optional_hex32(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _hex32(value, field)


def _optional_int(value: object, field: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer or null")
    return value


def _choice(value: object, field: str, choices: tuple[str, ...]) -> str:
    if value not in choices:
        raise ValueError(f"{field} must be one of: {', '.join(choices)}")
    return value
