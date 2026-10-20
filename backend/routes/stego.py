"""Steganography embed, extract, and chunked upload session routes."""

from __future__ import annotations

import base64
import json
import shutil
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Blueprint, Response, g, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

from db import insert_proof_event
from envelope import validate_v2 as validate_embed_metadata
from errors import UNSUPPORTED_MEDIA_TYPE, error_response
from idempotency import idempotent
from metadata_errors import (
    METADATA_MALFORMED,
    METADATA_OVERSIZED,
    MetadataError,
    classify_validation_error,
    metadata_error_response,
)
from quarantine import QuarantineError, isolate_upload, sniff_media_type_path
from routes import (
    app_attr,
    dynamic_limit,
    enable_streaming_for_large_uploads,
    enforce_video_size,
    get_config,
    normalize_filename,
    redact_metadata,
    require_app_capacity,
    validate_video_upload,
)
from stego import canonical_metadata_hash, embed_metadata, extract_metadata, sha256_file
from streaming_upload import create_streaming_file_storage, hash_paths_concat
from webhook import queue_webhook_deliveries
from workspace import EncryptedWorkspace

bp = Blueprint("stego", __name__)


@bp.post("/api/stego/embed")
@dynamic_limit("ratelimit_embed")
@require_app_capacity
@idempotent("embed")
def embed():
    config = get_config()
    enable_streaming_for_large_uploads()

    video = request.files.get("video")
    metadata_raw = request.form.get("metadata")
    if video is None or metadata_raw is None:
        return jsonify({"error": "video and metadata are required"}), 400
    if not enforce_video_size(video):
        return jsonify({"error": "video payload exceeds size limit"}), 413
    validate_video_upload(video)
    if len(metadata_raw.encode("utf-8")) > config.max_metadata_bytes:
        return metadata_error_response(
            MetadataError(METADATA_OVERSIZED, "metadata is too large")
        )

    try:
        metadata = json.loads(metadata_raw)
    except json.JSONDecodeError:
        return metadata_error_response(
            MetadataError(METADATA_MALFORMED, "metadata must be valid JSON")
        )
    try:
        validate_embed_metadata(metadata)
    except MetadataError as exc:
        return metadata_error_response(exc)
    except ValueError as exc:
        return metadata_error_response(classify_validation_error(exc))

    normalized_name = normalize_filename(video.filename)
    workspace_cls = app_attr("EncryptedWorkspace", EncryptedWorkspace)
    embed_fn = app_attr("embed_metadata", embed_metadata)
    insert_event_fn = app_attr("insert_proof_event", insert_proof_event)
    queue_webhooks_fn = app_attr("queue_webhook_deliveries", queue_webhook_deliveries)

    try:
        quarantine_context = isolate_upload(
            video,
            filename=normalized_name,
            content_type=video.content_type,
        )
        with quarantine_context as quarantined_path, workspace_cls() as workspace:
            source_url = workspace.get_url("source.video")
            output_url = workspace.get_url("embedded.mp4")
            with quarantined_path.open("rb") as quarantined:
                workspace.write_encrypted(
                    "source.video",
                    quarantined,
                    size=quarantined_path.stat().st_size,
                )

            embed_fn(source_url, output_url, metadata)
            output_bytes = workspace.read_decrypted("embedded.mp4")
            source_hash = workspace.sha256("source.video")
            embedded_hash = workspace.sha256("embedded.mp4")
            metadata_hash = canonical_metadata_hash(metadata)
    except QuarantineError as exc:
        return error_response(
            code=UNSUPPORTED_MEDIA_TYPE,
            message=str(exc),
            status=400,
        )

    db_event = insert_event_fn(
        event_type="embed",
        file_name=normalized_name,
        video_hash=embedded_hash,
        metadata_hash=metadata_hash,
        proof_id=metadata.get("proofId"),
        tier=metadata.get("tier"),
        embedded_hash=embedded_hash,
        metadata=redact_metadata(metadata),
    )

    if db_event and db_event.get("id"):
        queue_webhooks_fn(db_event["id"])

    response = Response(output_bytes, mimetype="video/mp4")
    response.headers["Content-Disposition"] = 'attachment; filename="harpocrates-evidence.mp4"'
    response.headers["X-Harpocrates-Source-Hash"] = source_hash
    response.headers["X-Harpocrates-Embedded-Hash"] = embedded_hash
    response.headers["X-Harpocrates-Metadata-Hash"] = metadata_hash
    response.headers["X-Harpocrates-Db-Event"] = str(db_event)
    if config.expose_metadata_header:
        response.headers["X-Harpocrates-Metadata"] = base64.b64encode(
            json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).decode("ascii")
    return response


@bp.post("/api/stego/upload-session")
@dynamic_limit("ratelimit_upload_session")
def create_upload_session():
    session_id = str(uuid.uuid4())
    session_dir = Path(tempfile.gettempdir()) / f"harpocrates-session-{session_id}"
    session_dir.mkdir(parents=True, exist_ok=True)
    return jsonify({"sessionId": session_id})


@bp.put("/api/stego/upload-session/<session_id>/chunk/<int:chunk_index>")
@dynamic_limit("ratelimit_upload_chunk")
def upload_chunk(session_id: str, chunk_index: int):
    config = get_config()
    session_dir = Path(tempfile.gettempdir()) / f"harpocrates-session-{session_id}"
    if not session_dir.exists():
        return jsonify({"error": "session not found"}), 404

    chunk = request.files.get("chunk")
    if chunk is None:
        return jsonify({"error": "chunk is required"}), 400
    if chunk_index < 0:
        return jsonify({"error": "chunk_index must be non-negative"}), 400

    g.upload_config = config
    streaming_factory = app_attr(
        "create_streaming_file_storage", create_streaming_file_storage
    )
    streaming_chunk = streaming_factory(chunk)
    chunk_path = session_dir / f"chunk-{chunk_index}"
    try:
        streaming_chunk.save(str(chunk_path))
    except RequestEntityTooLarge:
        return jsonify({"error": "chunk exceeds size limit"}), 413
    return jsonify(
        {
            "ok": True,
            "bytes": streaming_chunk.bytes_written,
            "sha256": streaming_chunk.computed_hash,
        }
    )


@bp.post("/api/stego/upload-session/<session_id>/commit")
@dynamic_limit("ratelimit_upload_session")
@require_app_capacity
def commit_upload_session(session_id: str):
    config = get_config()
    session_dir = Path(tempfile.gettempdir()) / f"harpocrates-session-{session_id}"
    if not session_dir.exists():
        return jsonify({"error": "session not found"}), 404

    metadata_raw = request.form.get("metadata")
    if metadata_raw is None:
        return jsonify({"error": "metadata is required"}), 400

    try:
        metadata = json.loads(metadata_raw)
    except json.JSONDecodeError:
        return metadata_error_response(
            MetadataError(METADATA_MALFORMED, "metadata must be valid JSON")
        )
    try:
        validate_embed_metadata(metadata)
    except MetadataError as exc:
        return metadata_error_response(exc)
    except ValueError as exc:
        return metadata_error_response(classify_validation_error(exc))

    combined_path = session_dir / "combined.video"
    chunk_files = sorted(
        [f for f in session_dir.iterdir() if f.name.startswith("chunk-")],
        key=lambda f: int(f.name.split("-")[1]),
    )
    if not chunk_files:
        return jsonify({"error": "session has no chunks"}), 400

    source_hash, _written = hash_paths_concat(
        chunk_files,
        combined_path,
        chunk_size=getattr(config, "upload_chunk_bytes", None),
        max_size=getattr(config, "upload_max_bytes", config.max_video_bytes),
    )

    try:
        sniff_media_type_path(combined_path)
    except QuarantineError as exc:
        return error_response(
            code=UNSUPPORTED_MEDIA_TYPE,
            message=str(exc),
            status=400,
        )

    embed_fn = app_attr("embed_metadata", embed_metadata)
    insert_event_fn = app_attr("insert_proof_event", insert_proof_event)

    with tempfile.TemporaryDirectory(prefix="harpocrates-") as tmp_dir:
        output_path = Path(tmp_dir) / "embedded.mp4"
        embed_fn(combined_path, output_path, metadata)
        output_bytes = output_path.read_bytes()
        embedded_hash = sha256_file(output_path)
        metadata_hash = canonical_metadata_hash(metadata)

    retention_class = request.headers.get("X-Harpocrates-Retention-Class") or metadata.get(
        "retentionClass", "default"
    )
    if retention_class not in config.retention_classes:
        return jsonify({"error": f"invalid retention class: {retention_class}"}), 400
    retention_days = config.retention_classes[retention_class]
    expires_at = None
    if retention_days >= 0:
        expires_at = datetime.now(timezone.utc) + timedelta(days=retention_days)

    db_event = insert_event_fn(
        event_type="embed",
        file_name=normalize_filename(metadata.get("fileName", "unknown.mp4")),
        video_hash=embedded_hash,
        metadata_hash=metadata_hash,
        proof_id=metadata.get("proofId"),
        tier=metadata.get("tier"),
        embedded_hash=embedded_hash,
        retention_class=retention_class,
        expires_at=expires_at,
        metadata=redact_metadata(metadata),
    )

    response = Response(output_bytes, mimetype="video/mp4")
    response.headers["Content-Disposition"] = 'attachment; filename="harpocrates-evidence.mp4"'
    response.headers["X-Harpocrates-Source-Hash"] = source_hash
    response.headers["X-Harpocrates-Embedded-Hash"] = embedded_hash
    response.headers["X-Harpocrates-Metadata-Hash"] = metadata_hash
    response.headers["X-Harpocrates-Db-Event"] = str(db_event)
    response.headers["X-Harpocrates-Retention-Class"] = retention_class
    if config.expose_metadata_header:
        response.headers["X-Harpocrates-Metadata"] = base64.b64encode(
            json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).decode("ascii")

    shutil.rmtree(session_dir, ignore_errors=True)

    return response


@bp.post("/api/stego/extract")
@dynamic_limit("ratelimit_extract")
@require_app_capacity
@idempotent("extract")
def extract():
    config = get_config()
    enable_streaming_for_large_uploads()

    video = request.files.get("video")
    if video is None:
        return jsonify({"error": "video is required"}), 400
    if not enforce_video_size(video):
        return jsonify({"error": "video payload exceeds size limit"}), 413
    validate_video_upload(video)

    normalized_name = normalize_filename(video.filename)
    workspace_cls = app_attr("EncryptedWorkspace", EncryptedWorkspace)
    extract_fn = app_attr("extract_metadata", extract_metadata)
    insert_event_fn = app_attr("insert_proof_event", insert_proof_event)
    queue_webhooks_fn = app_attr("queue_webhook_deliveries", queue_webhook_deliveries)

    try:
        quarantine_context = isolate_upload(
            video,
            filename=normalized_name,
            content_type=video.content_type,
        )
        with quarantine_context as quarantined_path, workspace_cls() as workspace:
            source_url = workspace.get_url("source.video")
            with quarantined_path.open("rb") as quarantined:
                workspace.write_encrypted(
                    "source.video",
                    quarantined,
                    size=quarantined_path.stat().st_size,
                )
            metadata = extract_fn(source_url)
            video_hash = workspace.sha256("source.video")
            metadata_hash = canonical_metadata_hash(metadata) if metadata else None
    except QuarantineError as exc:
        return error_response(
            code=UNSUPPORTED_MEDIA_TYPE,
            message=str(exc),
            status=400,
        )

    retention_class = request.headers.get("X-Harpocrates-Retention-Class") or (
        metadata.get("retentionClass", "default") if metadata else "default"
    )
    if retention_class not in config.retention_classes:
        return jsonify({"error": f"invalid retention class: {retention_class}"}), 400
    retention_days = config.retention_classes[retention_class]
    expires_at = None
    if retention_days >= 0:
        expires_at = datetime.now(timezone.utc) + timedelta(days=retention_days)

    db_event = insert_event_fn(
        event_type="extract",
        file_name=normalized_name,
        video_hash=video_hash,
        metadata_hash=metadata_hash,
        proof_id=metadata.get("proofId") if metadata else None,
        tier=metadata.get("tier") if metadata else None,
        retention_class=retention_class,
        expires_at=expires_at,
        metadata=redact_metadata(metadata),
    )

    if db_event and db_event.get("id"):
        queue_webhooks_fn(db_event["id"])

    return jsonify(
        {
            "video_hash": video_hash,
            "metadata_hash": metadata_hash,
            "metadata": metadata,
            "db_event": db_event,
        }
    )
