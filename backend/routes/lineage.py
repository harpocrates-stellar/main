"""Lineage event registration and lookup routes."""

from __future__ import annotations

import json

from flask import Blueprint, jsonify, request

from db import (
    find_lineage_by_actor,
    find_lineage_by_output_digest,
    insert_lineage_event,
    list_lineage_events,
)
from errors import NOT_FOUND, VALIDATION_ERROR, error_response, ok_response
from lineage import (
    LineageValidationError,
    canonical_lineage_manifest,
    lineage_manifest_digest,
    validate_lineage_graph,
)
from routes import (
    app_attr,
    clamp_lineage_limit,
    enforce_json_size,
    get_config,
    is_hex_32,
)
from strkey import validate_source_address

bp = Blueprint("lineage", __name__)


@bp.get("/api/proofs/lineage")
def lineage_events():
    limit = request.args.get("limit", "25")
    try:
        parsed_limit = clamp_lineage_limit(limit)
    except (TypeError, ValueError):
        return error_response(
            code=VALIDATION_ERROR,
            message="limit must be a positive integer",
            status=400,
        )
    list_fn = app_attr("list_lineage_events", list_lineage_events)
    return jsonify({"ok": True, "events": list_fn(parsed_limit)})


@bp.get("/api/lineage/by-actor/<actor_address>")
def lineage_by_actor(actor_address: str):
    limit = request.args.get("limit", "25")
    try:
        parsed_limit = clamp_lineage_limit(limit)
    except (TypeError, ValueError):
        return error_response(
            code=VALIDATION_ERROR,
            message="limit must be a positive integer",
            status=400,
        )

    try:
        validated_actor_address = validate_source_address(actor_address)
        if not validated_actor_address:
            raise ValueError("actor_address must be a valid Stellar G-address")
    except ValueError:
        return error_response(
            code=VALIDATION_ERROR,
            message="actor_address must be a valid Stellar G-address",
            status=400,
        )

    find_fn = app_attr("find_lineage_by_actor", find_lineage_by_actor)
    return jsonify({"ok": True, "events": find_fn(validated_actor_address, parsed_limit)})


@bp.get("/api/lineage/<output_digest>")
def lineage_by_output_digest(output_digest: str):
    if not is_hex_32(output_digest):
        return error_response(
            code=VALIDATION_ERROR,
            message="output_digest must be a 32-byte hex string",
            status=400,
        )

    find_fn = app_attr("find_lineage_by_output_digest", find_lineage_by_output_digest)
    record = find_fn(output_digest)
    if not record:
        return error_response(
            code=NOT_FOUND,
            message="lineage record not found",
            status=404,
        )

    return ok_response({"record": record})


@bp.post("/api/proofs/lineage")
def register_lineage_event():
    config = get_config()
    if enforce_json_size() > config.max_json_bytes:
        return jsonify({"error": "JSON payload exceeds size limit"}), 413

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required"}), 400

    output_digest = payload.get("outputDigest")
    if not output_digest:
        return jsonify({"error": "outputDigest is required"}), 400
    if not is_hex_32(output_digest):
        return jsonify({"error": "outputDigest must be a 32-byte hex string"}), 400

    find_fn = app_attr("find_lineage_by_output_digest", find_lineage_by_output_digest)
    insert_fn = app_attr("insert_lineage_event", insert_lineage_event)

    try:
        manifest_canonical = canonical_lineage_manifest(payload)
        manifest_digest = lineage_manifest_digest(payload)
        parent_ids = payload.get("parentProofIds", [])
        actor_address = str(payload.get("actorAddress", ""))

        validate_lineage_graph(
            parent_ids,
            depth=1,
            actor_address=actor_address,
            output_digest=output_digest,
            get_lineage_fn=find_fn,
        )
    except LineageValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    existing = find_fn(output_digest)
    if existing:
        return (
            jsonify({"error": "lineage already registered for this output digest"}),
            409,
        )

    db_event = insert_fn(
        manifest_digest=manifest_digest,
        manifest=json.loads(manifest_canonical),
        actor_address=actor_address,
        parent_proof_ids=[str(parent) for parent in parent_ids],
    )

    if not db_event:
        return jsonify({"error": "failed to record lineage event"}), 500

    return jsonify(
        {"ok": True, "manifestDigest": manifest_digest, "db_event": db_event}
    )
