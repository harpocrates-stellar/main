"""Schema discovery and selective disclosure verification routes."""

from __future__ import annotations

import hashlib

from flask import Blueprint, current_app, jsonify, request

from routes import app_attr, enforce_json_size, get_config, is_hex_32
from schema import (
    discover_schemas,
    resolve_schema,
    validate_selective_disclosure_input,
)
from verification_receipt import build_verification_receipt

bp = Blueprint("schemas", __name__)


@bp.get("/api/schemas")
def list_schemas():
    discover_fn = app_attr("discover_schemas", discover_schemas)
    schemas = discover_fn()
    hashes = sorted(
        s.get("schemaHash", "")
        for s in schemas
        if isinstance(s, dict) and s.get("schemaHash")
    )
    etag = '"' + hashlib.sha256("".join(hashes).encode()).hexdigest() + '"'
    if request.headers.get("If-None-Match") == etag:
        return "", 304
    response = jsonify({"ok": True, "schemas": schemas})
    response.headers["ETag"] = etag
    return response


@bp.get("/api/schemas/<schema_hash>")
def get_schema(schema_hash: str):
    if not is_hex_32(schema_hash):
        return jsonify({"error": "schemaHash must be a 32-byte hex string"}), 400
    resolve_fn = app_attr("resolve_schema", resolve_schema)
    schema = resolve_fn(schema_hash)
    if schema is None:
        return jsonify({"error": "schema not found"}), 404
    etag = '"' + schema_hash.lower() + '"'
    if request.headers.get("If-None-Match") == etag:
        resp = current_app.response_class("", status=304)
        resp.headers["ETag"] = etag
        resp.headers["Cache-Control"] = "public, max-age=86400, immutable"
        return resp
    response = jsonify({"ok": True, "schema": schema})
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "public, max-age=86400, immutable"
    return response


@bp.post("/api/verify/selective-disclosure")
def verify_selective_disclosure():
    config = get_config()
    if enforce_json_size() > config.max_json_bytes:
        return jsonify({"error": "JSON payload exceeds size limit"}), 413

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required"}), 400

    err = validate_selective_disclosure_input(payload)
    if err is not None:
        return jsonify({"error": err}), 400

    response = {
        "ok": True,
        "message": "Selective disclosure proof submission accepted.",
        "note": "On-chain verification must be performed via verify_selective_disclosure on the registry contract.",
    }
    receipt_context = payload.get("receiptContext")
    if receipt_context is not None:
        if not isinstance(receipt_context, dict):
            return jsonify({"error": "receiptContext must be a JSON object"}), 400
        try:
            response["verificationReceipt"] = build_verification_receipt(
                receipt_context
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
    return jsonify(response)
