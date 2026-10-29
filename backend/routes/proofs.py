"""Proof listing, registration, batch verification, reconciliation, and history routes."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from flask import Blueprint, g, jsonify, request

import register_auth
from db import (
    ConflictError,
    decode_proof_events_cursor,
    enqueue_job,
    find_proof_events_by_proof_id,
    find_proof_events_by_video,
    find_proof_owner,
    insert_proof_history_event,
    list_proof_events,
    list_proof_history_events,
    make_idempotency_key,
    upsert_register_event,
)
from envelope import ALLOWED_TIERS
from errors import (
    DEPENDENCY_UNAVAILABLE,
    FORBIDDEN,
    MALFORMED_INPUT,
    OVERSIZED_INPUT,
    PAYLOAD_TOO_LARGE,
    UNSUPPORTED_INPUT,
    VALIDATION_ERROR,
    classify_cli_error,
    error_response,
    ok_response,
)
from idempotency import idempotent
from logging_utils import log_structured
try:
    from registration_reconcile import (
        clamp_reconcile_limit,
        default_min_confirmations,
        reconcile_pending_registrations,
        reconcile_registration,
    )
except ImportError:
    clamp_reconcile_limit = None
    default_min_confirmations = None
    reconcile_pending_registrations = None
    reconcile_registration = None
from routes import (
    LOGGER,
    app_attr,
    dynamic_limit,
    enforce_json_size,
    get_config,
    get_verifier_cache,
    is_hex_32,
    normalize_filename,
    normalize_tx_hash,
    normalize_tx_status,
    redact_metadata,
    require_app_capacity,
    require_register_auth,
    request_id,
)
from strkey import validate_contract_id, validate_source_address
from webhook import queue_webhook_deliveries

bp = Blueprint("proofs", __name__)


@bp.get("/api/proofs")
def proofs():
    limit = request.args.get("limit", "25")
    cursor_token = request.args.get("cursor")
    try:
        parsed_limit = int(limit)
    except ValueError:
        return error_response(
            code=VALIDATION_ERROR,
            message="limit must be an integer",
            status=400,
        )

    cursor_id = None
    if cursor_token is not None and cursor_token != "":
        try:
            cursor_id = decode_proof_events_cursor(cursor_token)
        except ValueError:
            return jsonify({"error": "invalid cursor"}), 400

    list_fn = app_attr("list_proof_events", list_proof_events)
    events, next_cursor = list_fn(parsed_limit, cursor_id=cursor_id)
    return jsonify({"ok": True, "events": events, "nextCursor": next_cursor})


@bp.get("/api/proofs/by-video/<video_hash>")
def proof_by_video(video_hash: str):
    if not is_hex_32(video_hash):
        return error_response(
            code=VALIDATION_ERROR,
            message="video_hash must be a 32-byte hex string",
            status=400,
        )

    limit = request.args.get("limit", "25")
    cursor_token = request.args.get("cursor")
    try:
        parsed_limit = int(limit)
    except ValueError:
        return error_response(
            code=VALIDATION_ERROR,
            message="limit must be an integer",
            status=400,
        )

    cursor_id = None
    if cursor_token is not None and cursor_token != "":
        try:
            cursor_id = decode_proof_events_cursor(cursor_token)
        except ValueError:
            return jsonify({"error": "invalid cursor"}), 400

    find_fn = app_attr("find_proof_events_by_video", find_proof_events_by_video)
    events, next_cursor = find_fn(video_hash, parsed_limit, cursor_id=cursor_id)
    return ok_response({"events": events, "nextCursor": next_cursor})


@bp.post("/api/proofs/verify-batch")
@require_app_capacity
def verify_batch():
    config = get_config()
    if enforce_json_size() > config.max_json_bytes:
        return jsonify({"error": "JSON payload exceeds size limit"}), 413

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("proofs"), list):
        return jsonify({"error": "JSON body with a 'proofs' array is required"}), 400

    proof_items = payload["proofs"]
    if len(proof_items) > config.max_batch_size:
        return (
            jsonify({"error": f"batch size exceeds limit of {config.max_batch_size}"}),
            413,
        )

    find_by_video_fn = app_attr("find_proof_events_by_video", find_proof_events_by_video)

    results = []
    for idx, item in enumerate(proof_items):
        if not isinstance(item, dict):
            results.append(
                {
                    "status": "malformed",
                    "error": "item must be a JSON object",
                    "index": idx,
                }
            )
            continue

        video_hash = item.get("videoHash")
        proof_id = item.get("proofId")

        if video_hash is not None and not is_hex_32(video_hash):
            results.append(
                {
                    "videoHash": video_hash,
                    "proofId": proof_id,
                    "status": "malformed",
                    "error": "invalid videoHash",
                    "index": idx,
                }
            )
            continue
        if proof_id is not None and not is_hex_32(proof_id):
            results.append(
                {
                    "videoHash": video_hash,
                    "proofId": proof_id,
                    "status": "malformed",
                    "error": "invalid proofId",
                    "index": idx,
                }
            )
            continue
        if not video_hash and not proof_id:
            results.append(
                {
                    "status": "malformed",
                    "error": "must provide videoHash or proofId",
                    "index": idx,
                }
            )
            continue

        try:
            events = []
            if video_hash:
                events, _ = find_by_video_fn(video_hash)
                if proof_id:
                    events = [e for e in events if e.get("proof_id") == proof_id]
            else:
                find_by_proof_fn = app_attr(
                    "find_proof_events_by_proof_id", find_proof_events_by_proof_id
                )
                events = find_by_proof_fn(proof_id)

            if not events:
                results.append(
                    {
                        "videoHash": video_hash,
                        "proofId": proof_id,
                        "status": "not_found",
                        "events": [],
                        "index": idx,
                    }
                )
            else:
                has_confirmed = any(
                    e.get("tx_status") == "confirmed" for e in events
                )
                has_failed = any(e.get("tx_status") == "failed" for e in events)
                has_revoked = any(
                    e.get("tx_status") == "revoked" or e.get("event_type") == "revoke"
                    for e in events
                )

                if has_revoked:
                    status = "revoked"
                elif has_confirmed:
                    status = "verified"
                elif has_failed:
                    status = "failed"
                else:
                    status = "pending"

                results.append(
                    {
                        "videoHash": video_hash,
                        "proofId": proof_id,
                        "status": status,
                        "events": events,
                        "index": idx,
                    }
                )
        except Exception as e:
            results.append(
                {
                    "videoHash": video_hash,
                    "proofId": proof_id,
                    "status": "dependency_failure",
                    "error": str(e),
                    "index": idx,
                }
            )

    return jsonify({"ok": True, "results": results})


@bp.post("/api/proofs/register")
@dynamic_limit("ratelimit_register")
@require_register_auth
@idempotent("register")
def register_proof_event():
    config = get_config()
    if enforce_json_size() > config.max_json_bytes:
        return jsonify({"error": "JSON payload exceeds size limit"}), 413
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return error_response(
            code=VALIDATION_ERROR,
            message="JSON body is required",
            status=400,
        )
    if (
        len(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        > config.max_metadata_bytes
    ):
        return error_response(
            code=PAYLOAD_TOO_LARGE,
            message="registration payload is too large",
            status=413,
            cli_code=OVERSIZED_INPUT,
        )

    video_hash = payload.get("videoHash")
    metadata_hash = payload.get("metadataHash")
    proof_id = payload.get("proofId")
    tx_hash = payload.get("txHash")
    tx_status = payload.get("txStatus")

    for name, value in (
        ("videoHash", video_hash),
        ("metadataHash", metadata_hash),
        ("proofId", proof_id),
    ):
        if not is_hex_32(value):
            return error_response(
                code=VALIDATION_ERROR,
                message=f"{name} must be a 32-byte hex string",
                status=400,
                cli_code=MALFORMED_INPUT,
            )

    tier = payload.get("tier")
    if tier not in ALLOWED_TIERS:
        return error_response(
            code=VALIDATION_ERROR,
            message="tier must be one of: silent, source, seal",
            status=400,
            cli_code=UNSUPPORTED_INPUT,
        )

    try:
        normalized_tx_hash = normalize_tx_hash(tx_hash)
        normalized_tx_status = normalize_tx_status(tx_status)
        if normalized_tx_hash:
            normalized_tx_status = "pending"
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    try:
        validated_source_address = validate_source_address(payload.get("sourceAddress"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        validated_contract_id = validate_contract_id(payload.get("contractId"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    principal = g.get("register_principal")
    if principal is not None and principal.is_scoped:
        find_owner_fn = app_attr("find_proof_owner", find_proof_owner)
        try:
            existing_owner = find_owner_fn(proof_id)
        except Exception:
            log_structured(
                LOGGER,
                logging.ERROR,
                {"event": "register_owner_lookup_failed", "request_id": request_id()},
            )
            return error_response(
                code=DEPENDENCY_UNAVAILABLE,
                message="ownership check unavailable; registration was not applied",
                status=503,
            )
        if existing_owner is not None and existing_owner != validated_source_address:
            log_structured(
                LOGGER,
                logging.WARNING,
                {
                    "event": "register_auth_rejected",
                    "reason": register_auth.REASON_OWNER_CONFLICT,
                    "request_id": request_id(),
                },
            )
            return error_response(
                code=FORBIDDEN,
                message="proof is registered to a different owner",
                status=403,
                field="proofId",
            )

    time_attestation_data = None
    claimed_capture_time = None
    if "timeAttestation" in payload:
        from time_attestation import (
            decode_time_attestation,
            encode_time_attestation,
            validate_time_attestation,
        )

        try:
            time_att = decode_time_attestation(payload["timeAttestation"])
            errors = validate_time_attestation(time_att, video_hash)
            if errors:
                return error_response(
                    code=VALIDATION_ERROR,
                    message="Invalid time attestation",
                    status=400,
                    cli_code=classify_cli_error("time attestation is invalid"),
                )
            time_attestation_data = encode_time_attestation(time_att)
            if time_att.claimed_time:
                claimed_capture_time = datetime.fromtimestamp(
                    time_att.claimed_time.unix_ms / 1000, tz=timezone.utc
                ).isoformat()
        except (ValueError, TypeError) as exc:
            return error_response(
                code=VALIDATION_ERROR,
                message=f"Time attestation error: {str(exc)}",
                status=400,
                cli_code=classify_cli_error(str(exc)),
            )

    idempotency_key = make_idempotency_key(video_hash, proof_id, normalized_tx_hash)

    retention_class = payload.get("retentionClass", "default")
    if retention_class not in config.retention_classes:
        return error_response(
            code=VALIDATION_ERROR,
            message=f"invalid retention class: {retention_class}",
            status=400,
            cli_code=UNSUPPORTED_INPUT,
        )
    retention_days = config.retention_classes[retention_class]
    expires_at = None
    if retention_days >= 0:
        expires_at = datetime.now(timezone.utc) + timedelta(days=retention_days)

    upsert_fn = app_attr("upsert_register_event", upsert_register_event)
    queue_webhooks_fn = app_attr("queue_webhook_deliveries", queue_webhook_deliveries)
    enqueue_job_fn = app_attr("enqueue_job", enqueue_job)

    try:
        db_event, created = upsert_fn(
            idempotency_key=idempotency_key,
            file_name=normalize_filename(payload.get("fileName")),
            video_hash=video_hash,
            metadata_hash=metadata_hash,
            proof_id=proof_id,
            tier=tier,
            tx_hash=normalized_tx_hash,
            tx_status=normalized_tx_status,
            source_address=validated_source_address,
            contract_id=validated_contract_id,
            retention_class=retention_class,
            expires_at=expires_at,
            metadata=redact_metadata(payload),
            time_attestation=time_attestation_data,
            claimed_capture_time=claimed_capture_time,
        )
    except ConflictError as exc:
        return (
            jsonify(
                {
                    "error": "idempotency key reused with conflicting payload",
                    "conflict_field": exc.field,
                }
            ),
            409,
        )

    if db_event and db_event.get("id") and created:
        get_verifier_cache().invalidate_proof(proof_id)
        queue_webhooks_fn(db_event["id"])
        if normalized_tx_hash:
            enqueue_job_fn(
                "verify_tx",
                {
                    "proof_id": proof_id,
                    "tx_hash": normalized_tx_hash,
                    "contract_id": validated_contract_id,
                },
            )

    status = 201 if created else 200
    return jsonify({"ok": True, "db_event": db_event, "created": created}), status


@bp.post("/api/proofs/reconcile")
def reconcile_registration_confirmations():
    """Reconcile pending registration tx hashes against on-chain Horizon state."""
    config = get_config()
    if enforce_json_size() > config.max_json_bytes:
        return jsonify({"error": "JSON payload exceeds size limit"}), 413

    payload = request.get_json(silent=True)
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        return error_response(
            code=VALIDATION_ERROR,
            message="JSON body must be an object",
            status=400,
        )

    if (
        len(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        > config.max_metadata_bytes
    ):
        return jsonify({"error": "reconcile payload is too large"}), 413

    force = bool(payload.get("force", False))
    min_confirmations = payload.get("minConfirmations")
    if min_confirmations is None:
        min_confirmations = default_min_confirmations()
    else:
        try:
            min_confirmations = int(min_confirmations)
        except (TypeError, ValueError):
            return error_response(
                code=VALIDATION_ERROR,
                message="minConfirmations must be an integer >= 1",
                status=400,
            )
        if min_confirmations < 1:
            return error_response(
                code=VALIDATION_ERROR,
                message="minConfirmations must be an integer >= 1",
                status=400,
            )

    tx_hash = payload.get("txHash")
    if tx_hash is not None:
        reconcile_one_fn = app_attr("reconcile_registration", reconcile_registration)
        try:
            result = reconcile_one_fn(
                tx_hash,
                previous_status=None if force else "pending",
                min_confirmations=min_confirmations,
                force=force,
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        if result.get("error") == "malformed_tx_hash":
            return error_response(
                code=VALIDATION_ERROR,
                message="txHash must be a 32-byte hex string",
                status=400,
            )
        if result.get("status") == "error":
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "horizon_dependency_failure",
                        "result": result,
                    }
                ),
                503,
            )
        return jsonify({"ok": True, "result": result})

    try:
        limit = clamp_reconcile_limit(payload.get("limit", 50))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    reconcile_batch_fn = app_attr(
        "reconcile_pending_registrations", reconcile_pending_registrations
    )
    try:
        report = reconcile_batch_fn(
            limit=limit,
            min_confirmations=min_confirmations,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(report)


@bp.get("/api/proofs/history/<proof_id>")
def proof_history(proof_id: str):
    if not is_hex_32(proof_id):
        return jsonify({"error": "proof_id must be a 32-byte hex string"}), 400

    limit = request.args.get("limit", "50")
    offset = request.args.get("offset", "0")
    try:
        parsed_limit = int(limit)
        parsed_offset = int(offset)
    except ValueError:
        return jsonify({"error": "limit and offset must be integers"}), 400

    list_history_fn = app_attr("list_proof_history_events", list_proof_history_events)
    return jsonify(
        {
            "ok": True,
            "events": list_history_fn(proof_id, parsed_limit, parsed_offset),
        }
    )


@bp.post("/api/proofs/history")
def register_proof_history_event():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required"}), 400

    proof_id = payload.get("proofId")
    action = payload.get("action")
    actor = payload.get("actor")
    reason_code = payload.get("reasonCode")
    contract_id = payload.get("contractId")
    tx_hash = payload.get("txHash")

    if not is_hex_32(proof_id):
        return jsonify({"error": "proofId must be a 32-byte hex string"}), 400
    if not isinstance(action, str) or not action:
        return jsonify({"error": "action is required"}), 400
    if reason_code is None or not isinstance(reason_code, int):
        return jsonify({"error": "reasonCode is required"}), 400

    insert_history_fn = app_attr(
        "insert_proof_history_event", insert_proof_history_event
    )
    db_event = insert_history_fn(
        proof_id=proof_id,
        action=action,
        actor=actor,
        reason_code=reason_code,
        contract_id=contract_id,
        tx_hash=tx_hash,
    )

    return ok_response({"db_event": db_event})
