"""Background job status, download, cancellation, and Noir worker routes."""

from __future__ import annotations

import logging

from flask import Blueprint, current_app, jsonify, request, send_file

from db import cancel_job, get_job
from errors import (
    GONE,
    INTERNAL_ERROR,
    NOT_FOUND,
    VALIDATION_ERROR,
    error_response,
)
from idempotency import idempotent
from logging_utils import log_structured
from noir import generate_aggregated_proof, generate_silent_witness
from routes import (
    LOGGER,
    MAX_AGGREGATION_SIZE,
    app_attr,
    dynamic_limit,
    enforce_json_size,
    get_config,
    is_field_decimal,
    is_hex_32,
    require_app_capacity,
    request_id,
)
from stego import sha256_file
from storage import get_job_output_path

bp = Blueprint("jobs", __name__)


@bp.post("/api/noir/silent-witness")
@dynamic_limit("ratelimit_silent_witness")
@require_app_capacity
@idempotent("silent-witness")
def silent_witness_proof():
    config = get_config()
    if enforce_json_size() > config.max_json_bytes:
        return jsonify({"error": "JSON payload exceeds size limit"}), 413
    if not config.noir_worker_enabled:
        return error_response(
            code=NOT_FOUND,
            message="local Noir worker is disabled",
            status=404,
        )

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return error_response(
            code=VALIDATION_ERROR,
            message="JSON body is required",
            status=400,
        )

    video_hash = payload.get("videoHash")
    if not is_hex_32(video_hash):
        return error_response(
            code=VALIDATION_ERROR,
            message="videoHash must be a 32-byte hex string",
            status=400,
        )
    credential_secret = payload.get("credentialSecret")
    nullifier_secret = payload.get("nullifierSecret")
    if not is_field_decimal(credential_secret):
        return error_response(
            code=VALIDATION_ERROR,
            message="credentialSecret must be a decimal field string",
            status=400,
        )
    if not is_field_decimal(nullifier_secret):
        return error_response(
            code=VALIDATION_ERROR,
            message="nullifierSecret must be a decimal field string",
            status=400,
        )

    verifier_scope = payload.get("verifierScope", "0")
    if not is_field_decimal(verifier_scope):
        return jsonify({"error": "verifierScope must be a decimal field string"}), 400
    epoch = payload.get("epoch", 0)
    if not isinstance(epoch, int) or epoch < 0:
        return jsonify({"error": "epoch must be a non-negative integer"}), 400

    gen_fn = app_attr("generate_silent_witness", generate_silent_witness)
    try:
        proof = gen_fn(  # noqa: F841
            video_hash,
            credential_secret,
            nullifier_secret,
            verifier_scope,
            epoch,
        )
    except RuntimeError as exc:
        current_app.logger.error("Noir proof generation failed: %s", exc, exc_info=True)
        return error_response(
            code=INTERNAL_ERROR,
            message="Noir proof generation failed",
            status=500,
        )

    return jsonify({"job_id": job_id, "status": "pending"}), 202  # noqa: F821


@bp.get("/api/jobs/<int:job_id>")
def get_job_status(job_id: int):
    get_job_fn = app_attr("get_job", get_job)
    job = get_job_fn(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    public_job = {key: value for key, value in job.items() if key != "_trace_context"}
    return jsonify({"ok": True, "job": public_job})


@bp.get("/api/jobs/<int:job_id>/download")
def download_job_result(job_id: int):
    get_job_fn = app_attr("get_job", get_job)
    job = get_job_fn(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job.get("purged"):
        return error_response(
            code=GONE,
            message="Job output has been purged",
            status=410,
        )
    if job["type"] != "embed" or job["status"] != "completed":
        return jsonify({"error": "No output available for download"}), 400

    get_path_fn = app_attr("get_job_output_path", get_job_output_path)
    output_path = get_path_fn(job_id)
    if not output_path.exists():
        return error_response(
            code=GONE,
            message="Job output has been purged",
            status=410,
        )

    result = job.get("result", {})
    etag = result.get("embedded_hash")
    if not etag:
        etag = sha256_file(output_path)

    response = send_file(
        output_path,
        mimetype="video/mp4",
        as_attachment=True,
        download_name="harpocrates-evidence.mp4",
        conditional=True,
        etag=etag,
    )
    if result.get("source_hash"):
        response.headers["X-Harpocrates-Source-Hash"] = result["source_hash"]
    if result.get("embedded_hash"):
        response.headers["X-Harpocrates-Embedded-Hash"] = result["embedded_hash"]
    if result.get("metadata_hash"):
        response.headers["X-Harpocrates-Metadata-Hash"] = result["metadata_hash"]
    if result.get("db_event"):
        response.headers["X-Harpocrates-Db-Event"] = str(result["db_event"])

    return response


@bp.post("/api/jobs/<int:job_id>/cancel")
def cancel_job_endpoint(job_id: int):
    cancel_fn = app_attr("cancel_job", cancel_job)
    if cancel_fn(job_id):
        return jsonify({"ok": True, "message": "Job cancelled"})
    return jsonify({"error": "Job cannot be cancelled or not found"}), 400


@bp.post("/api/noir/silent-witness/aggregate")
def silent_witness_aggregate():
    """Generate a bounded aggregated proof for multiple video hashes."""
    config = get_config()
    if enforce_json_size() > config.max_json_bytes:
        return jsonify({"error": "JSON payload exceeds size limit"}), 413
    if not config.noir_worker_enabled:
        return jsonify({"error": "local Noir worker is disabled"}), 404

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required"}), 400

    video_hashes = payload.get("videoHashes")
    if not isinstance(video_hashes, list) or len(video_hashes) == 0:
        return jsonify({"error": "videoHashes must be a non-empty array"}), 400

    if len(video_hashes) > MAX_AGGREGATION_SIZE:
        return (
            jsonify(
                {
                    "error": f"videoHashes exceeds maximum aggregation size ({MAX_AGGREGATION_SIZE})"
                }
            ),
            400,
        )

    for i, video_hash in enumerate(video_hashes):
        if not is_hex_32(video_hash):
            return (
                jsonify(
                    {"error": f"videoHashes[{i}] must be a 32-byte hex string"}
                ),
                400,
            )

    credential_secret = payload.get("credentialSecret")
    nullifier_secret = payload.get("nullifierSecret")
    if not is_field_decimal(credential_secret):
        return jsonify({"error": "credentialSecret must be a decimal field string"}), 400
    if not is_field_decimal(nullifier_secret):
        return jsonify({"error": "nullifierSecret must be a decimal field string"}), 400

    safe_fields = {
        "event": "aggregate_proof_request",
        "request_id": request_id(),
        "batch_size": len(video_hashes),
    }
    log_structured(LOGGER, logging.INFO, safe_fields)

    gen_agg_fn = app_attr("generate_aggregated_proof", generate_aggregated_proof)
    try:
        proof = gen_agg_fn(
            video_hashes,
            credential_secret,
            nullifier_secret,
        )
    except (ValueError, RuntimeError) as exc:
        return jsonify({"error": str(exc)}), 500

    return jsonify({"ok": True, "proof": proof})
