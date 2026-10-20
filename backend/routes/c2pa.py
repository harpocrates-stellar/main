"""C2PA manifest export and import routes."""

from __future__ import annotations

import json

from flask import Blueprint, request

from c2pa import (
    C2paParseError,
    C2paTrustStatus,
    corroborate_binding,
    export_c2pa_manifest,
    parse_c2pa_manifest,
)
from errors import VALIDATION_ERROR, error_response, ok_response

bp = Blueprint("c2pa", __name__)


@bp.post("/api/c2pa/export")
def c2pa_export():
    """Export a C2PA-compatible authenticity manifest from Harpocrates evidence digests."""
    if not request.is_json:
        return error_response(
            code=VALIDATION_ERROR,
            message="JSON body is required",
            status=400,
        )
    body = request.get_json(silent=True) or {}

    required_fields = (
        "video_hash",
        "metadata_hash",
        "proof_id",
        "tier",
        "network",
        "contract_id",
    )
    for field_name in required_fields:
        if field_name not in body:
            return error_response(
                code=VALIDATION_ERROR,
                message=f"missing required field: {field_name}",
                status=400,
            )

    try:
        exported = export_c2pa_manifest(
            video_hash=body["video_hash"],
            metadata_hash=body["metadata_hash"],
            proof_id=body["proof_id"],
            tier=body["tier"],
            network=body["network"],
            contract_id=body["contract_id"],
            claim_generator=body.get("claim_generator"),
        )
    except ValueError as exc:
        return error_response(
            code=VALIDATION_ERROR,
            message=str(exc),
            status=400,
        )

    return ok_response(
        {
            "manifest": exported.manifest,
            "digest": exported.digest,
            "trust_status": C2paTrustStatus.SIGNATURE_NOT_CHECKED.value,
            "note": (
                "C2PA trust status is independent of Harpocrates on-chain and ZK "
                "verification. Do not treat this manifest as a Harpocrates proof."
            ),
        }
    )


@bp.post("/api/c2pa/import")
def c2pa_import():
    """Parse, validate, and corroborate a C2PA-compatible authenticity manifest."""
    if not request.is_json:
        return error_response(
            code=VALIDATION_ERROR,
            message="JSON body is required",
            status=400,
        )
    body = request.get_json(silent=True) or {}

    if "manifest" not in body:
        return error_response(
            code=VALIDATION_ERROR,
            message="missing required field: manifest",
            status=400,
        )

    manifest_raw = body["manifest"]
    if isinstance(manifest_raw, dict):
        try:
            manifest_bytes = json.dumps(
                manifest_raw, separators=(",", ":")
            ).encode("utf-8")
        except (TypeError, ValueError):
            return error_response(
                code=VALIDATION_ERROR,
                message="manifest object could not be serialised",
                status=400,
            )
    elif isinstance(manifest_raw, str):
        manifest_bytes = manifest_raw.encode("utf-8")
    else:
        return error_response(
            code=VALIDATION_ERROR,
            message="manifest must be a JSON object or string",
            status=400,
        )

    try:
        parsed = parse_c2pa_manifest(manifest_bytes)
    except C2paParseError as exc:
        err_payload = exc.to_dict()
        return error_response(
            code=VALIDATION_ERROR,
            message=f"C2PA manifest parse failed: {err_payload['reason']}"
            + (
                f" (field: {err_payload['field']})"
                if err_payload.get("field")
                else ""
            ),
            status=400,
        )

    binding = parsed.binding

    expected = body.get("expected")
    if expected is not None and not isinstance(expected, dict):
        return error_response(
            code=VALIDATION_ERROR,
            message="expected must be a JSON object of submitted hashes",
            status=400,
        )

    corroboration = None
    if expected is not None:
        try:
            corroboration = corroborate_binding(
                parsed,
                video_hash=expected.get("video_hash"),
                metadata_hash=expected.get("metadata_hash"),
                proof_id=expected.get("proof_id"),
                tier=expected.get("tier"),
                network=expected.get("network"),
                contract_id=expected.get("contract_id"),
            )
        except ValueError as exc:
            return error_response(
                code=VALIDATION_ERROR,
                message=str(exc),
                status=400,
            )

        if not corroboration.ok:
            return error_response(
                code=VALIDATION_ERROR,
                message=(
                    "submitted hashes do not match the embedded C2PA binding: "
                    + ", ".join(corroboration.mismatches)
                ),
                status=400,
                field=corroboration.mismatches[0],
            )

    unknown = [
        {
            "label": ua.label,
            "unsupported_semantics": ua.unsupported_semantics,
        }
        for ua in parsed.unknown_assertions
    ]

    return ok_response(
        {
            "binding": {
                "mapping_version": binding.mapping_version,
                "video_hash": binding.video_hash,
                "metadata_hash": binding.metadata_hash,
                "proof_id": binding.proof_id,
                "tier": binding.tier,
                "network": binding.network,
                "contract_id": binding.contract_id,
            },
            "trust_status": parsed.trust_status.value,
            "hashes_verified": bool(corroboration is not None and corroboration.ok),
            "hashes_compared": (
                list(corroboration.compared_fields) if corroboration else []
            ),
            "unknown_assertions": unknown,
            "note": (
                "C2PA trust status is independent of Harpocrates on-chain and ZK "
                "verification. A matching 'expected' block is integrity "
                "corroboration only. Corroborate this binding against on-chain "
                "records before making any trust decision."
            ),
        }
    )
