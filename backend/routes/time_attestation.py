"""Time attestation and capture attestation verification routes."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from capture_attestation import (
    canonical_attestation_hash,
    decode_attestation,
    verify_device_commitment,
)
from errors import (
    MALFORMED_INPUT,
    VALIDATION_ERROR,
    error_response,
    ok_response,
)
from routes import dynamic_limit, enforce_json_size, get_config, is_hex_32

bp = Blueprint("time_attestation", __name__)


@bp.post("/api/time-attestation/create")
def create_time_attestation_endpoint():
    """Create a new time attestation envelope."""
    config = get_config()
    if enforce_json_size() > config.max_json_bytes:
        return jsonify({"error": "JSON payload exceeds size limit"}), 413

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required"}), 400

    evidence_digest = payload.get("evidenceDigest")
    if not is_hex_32(evidence_digest):
        return (
            jsonify({"error": "evidenceDigest must be a 32-byte hex string"}),
            400,
        )

    from time_attestation import (
        check_backdating_risk,
        create_time_attestation,
        encode_time_attestation,
    )

    claimed_time_ms = payload.get("claimedTimeMs")
    claimed_source_label = payload.get("claimedSourceLabel", "device_clock")
    uncertainty_ms = payload.get("uncertaintyMs", 0)

    try:
        attestation = create_time_attestation(
            evidence_digest=evidence_digest,
            claimed_time_ms=claimed_time_ms,
            claimed_source_label=claimed_source_label,
            uncertainty_ms=uncertainty_ms,
        )

        encoded = encode_time_attestation(attestation)
        risk_assessment = check_backdating_risk(attestation)

        return jsonify(
            {
                "ok": True,
                "timeAttestation": encoded,
                "riskAssessment": risk_assessment,
            }
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@bp.post("/api/time-attestation/anchor")
def anchor_time_attestation():
    """Add anchors to an existing time attestation."""
    config = get_config()
    if enforce_json_size() > config.max_json_bytes:
        return jsonify({"error": "JSON payload exceeds size limit"}), 413

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required"}), 400

    from time_attestation import (
        add_rfc3161_anchor,
        add_stellar_anchor,
        check_backdating_risk,
        decode_time_attestation,
        encode_time_attestation,
    )

    try:
        attestation = decode_time_attestation(payload.get("timeAttestation", {}))
    except (ValueError, TypeError) as exc:
        return (
            jsonify({"error": f"Invalid time attestation: {str(exc)}"}),
            400,
        )

    if "stellarAnchor" in payload:
        stellar = payload["stellarAnchor"]
        try:
            attestation = add_stellar_anchor(
                attestation,
                ledger_sequence=stellar["ledgerSequence"],
                ledger_timestamp=stellar["ledgerTimestamp"],
                transaction_hash=stellar["transactionHash"],
                network_passphrase=stellar["networkPassphrase"],
            )
        except (ValueError, KeyError) as exc:
            return (
                jsonify({"error": f"Invalid Stellar anchor: {str(exc)}"}),
                400,
            )

    if "rfc3161Anchor" in payload:
        rfc3161 = payload["rfc3161Anchor"]
        try:
            attestation = add_rfc3161_anchor(
                attestation,
                token_bytes=rfc3161["tokenBytes"],
                tsa_url=rfc3161["tsaUrl"],
                gen_time=rfc3161["genTime"],
                policy_oid=rfc3161.get("policyOid"),
                cert_fingerprint=rfc3161.get("certFingerprint"),
                verification_status=rfc3161.get("verificationStatus", "unverified"),
                verification_error=rfc3161.get("verificationError"),
            )
        except (ValueError, KeyError) as exc:
            return (
                jsonify({"error": f"Invalid RFC 3161 anchor: {str(exc)}"}),
                400,
            )

    encoded = encode_time_attestation(attestation)
    risk_assessment = check_backdating_risk(attestation)

    return jsonify(
        {
            "ok": True,
            "timeAttestation": encoded,
            "riskAssessment": risk_assessment,
        }
    )


@bp.post("/api/time-attestation/validate")
def validate_time_attestation_endpoint():
    """Validate a time attestation envelope."""
    config = get_config()
    if enforce_json_size() > config.max_json_bytes:
        return jsonify({"error": "JSON payload exceeds size limit"}), 413

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required"}), 400

    evidence_digest = payload.get("evidenceDigest")
    if not is_hex_32(evidence_digest):
        return (
            jsonify({"error": "evidenceDigest must be a 32-byte hex string"}),
            400,
        )

    from time_attestation import (
        check_backdating_risk,
        decode_time_attestation,
        validate_time_attestation,
    )

    try:
        attestation = decode_time_attestation(payload.get("timeAttestation", {}))
        errors = validate_time_attestation(attestation, evidence_digest)
        risk_assessment = check_backdating_risk(attestation)

        return jsonify(
            {
                "ok": len(errors) == 0,
                "errors": errors,
                "riskAssessment": risk_assessment,
            }
        )
    except (ValueError, TypeError) as exc:
        return (
            jsonify({"error": f"Invalid time attestation: {str(exc)}"}),
            400,
        )


@bp.post("/api/capture-attestation/verify")
@dynamic_limit("ratelimit_verify")
def verify_capture_attestation():
    config = get_config()
    if enforce_json_size() > config.max_json_bytes:
        return jsonify({"error": "JSON payload exceeds size limit"}), 413

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return error_response(
            code=VALIDATION_ERROR,
            message="JSON body is required",
            status=400,
            cli_code=MALFORMED_INPUT,
        )

    if "attestation" not in payload or payload["attestation"] is None:
        return error_response(
            code=VALIDATION_ERROR,
            message="attestation is required",
            status=400,
            cli_code=MALFORMED_INPUT,
        )

    attestation_raw = payload["attestation"]
    if not isinstance(attestation_raw, dict):
        return error_response(
            code=VALIDATION_ERROR,
            message="attestation must be a JSON object",
            status=400,
            cli_code=MALFORMED_INPUT,
        )

    evidence_digest = payload.get("evidence_digest")
    if evidence_digest is None:
        evidence_digest = payload.get("evidenceDigest")

    if evidence_digest is None:
        return error_response(
            code=VALIDATION_ERROR,
            message="evidence_digest is required",
            status=400,
            cli_code=MALFORMED_INPUT,
        )

    if not is_hex_32(evidence_digest):
        return error_response(
            code=VALIDATION_ERROR,
            message="evidence_digest must be a 32-byte hex string",
            status=400,
            cli_code=MALFORMED_INPUT,
        )

    device_key = payload.get("device_key")
    if device_key is None:
        device_key = payload.get("deviceKey")

    if device_key is not None and not is_hex_32(device_key):
        return error_response(
            code=VALIDATION_ERROR,
            message="device_key must be a 32-byte hex string",
            status=400,
            cli_code=MALFORMED_INPUT,
        )

    try:
        decoded = decode_attestation(attestation_raw)
    except (ValueError, TypeError, KeyError, AttributeError):
        return error_response(
            code=VALIDATION_ERROR,
            message="malformed attestation payload",
            status=400,
            cli_code=MALFORMED_INPUT,
        )

    try:
        attestation_hash = canonical_attestation_hash(decoded)
    except (ValueError, TypeError):
        return error_response(
            code=VALIDATION_ERROR,
            message="malformed attestation payload",
            status=400,
            cli_code=MALFORMED_INPUT,
        )

    evidence_binding_valid = (
        decoded.evidence_digest_binding.lower() == evidence_digest.lower()
    )
    checks: dict[str, bool] = {
        "evidence_binding": evidence_binding_valid,
    }

    if device_key is not None:
        try:
            checks["device_commitment"] = verify_device_commitment(
                decoded, bytes.fromhex(device_key)
            )
        except (ValueError, TypeError):
            checks["device_commitment"] = False

    valid = all(checks.values())

    return ok_response(
        {
            "valid": valid,
            "attestation_hash": attestation_hash,
            "checks": checks,
        }
    )
