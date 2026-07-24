from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path

from flask import Flask, Response, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from config import load_config
from db import (
    check_db,
    find_proof_events_by_video,
    init_db,
    insert_proof_event,
    insert_proof_history_event,
    list_proof_events,
    list_proof_history_events,
)
from noir import generate_silent_witness
from stego import canonical_metadata_hash, embed_metadata, extract_metadata, sha256_file


ALLOWED_TIERS = {"silent", "source", "seal"}
REDACTED_METADATA_KEYS = {"credentialSecret", "nullifierSecret", "proof", "publicInputs"}
REQUIRED_EMBED_METADATA = {"protocol", "version", "tier", "sourceHash", "proofId", "timestamp"}


def create_app() -> Flask:
    load_dotenv()
    config = load_config()
    app = Flask(__name__)
    CORS(app, origins=config.cors_origins)
    app.config["MAX_CONTENT_LENGTH"] = config.max_content_length
    init_db()

    @app.after_request
    def add_security_headers(response: Response):
        if config.security_headers_enabled:
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            response.headers.setdefault("Referrer-Policy", "no-referrer")
            response.headers.setdefault("Cross-Origin-Resource-Policy", "same-site")
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error: RequestEntityTooLarge):
        return jsonify({"error": "request body is too large"}), 413

    @app.errorhandler(ValueError)
    def bad_request(error: ValueError):
        return jsonify({"error": str(error)}), 400

    @app.errorhandler(RuntimeError)
    def runtime_error(error: RuntimeError):
        return jsonify({"error": str(error)}), 500

    @app.get("/health")
    def health():
        return jsonify({"ok": True, "service": "harpocrates-stego"})

    @app.get("/ready")
    def ready():
        database_ready = check_db()
        video_tools_ready = video_tooling_ready()
        return jsonify(
            {
                "ok": database_ready and video_tools_ready,
                "service": "harpocrates-stego",
                "database": "connected" if database_ready else "not_configured",
                "video_tools": "available" if video_tools_ready else "missing",
                "noir_worker": "enabled" if config.noir_worker_enabled else "disabled",
            }
        ), 200 if database_ready and video_tools_ready else 503

    @app.post("/api/stego/embed")
    def embed():
        video = request.files.get("video")
        metadata_raw = request.form.get("metadata")

        if video is None or metadata_raw is None:
            return jsonify({"error": "video and metadata are required"}), 400
        validate_video_upload(video)
        if len(metadata_raw.encode("utf-8")) > config.max_metadata_bytes:
            return jsonify({"error": "metadata is too large"}), 400

        try:
            metadata = json.loads(metadata_raw)
        except json.JSONDecodeError:
            return jsonify({"error": "metadata must be valid JSON"}), 400
        try:
            validate_embed_metadata(metadata)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        with tempfile.TemporaryDirectory(prefix="harpocrates-") as tmp_dir:
            source_path = Path(tmp_dir) / "source.video"
            output_path = Path(tmp_dir) / "embedded.mp4"
            video.save(source_path)

            embed_metadata(source_path, output_path, metadata)
            output_bytes = output_path.read_bytes()
            source_hash = sha256_file(source_path)
            embedded_hash = sha256_file(output_path)
            metadata_hash = canonical_metadata_hash(metadata)

        db_event = insert_proof_event(
            event_type="embed",
            file_name=safe_filename(video.filename),
            video_hash=embedded_hash,
            metadata_hash=metadata_hash,
            proof_id=metadata.get("proofId"),
            tier=metadata.get("tier"),
            embedded_hash=embedded_hash,
            metadata=redact_metadata(metadata),
        )

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

    @app.post("/api/stego/extract")
    def extract():
        video = request.files.get("video")

        if video is None:
            return jsonify({"error": "video is required"}), 400
        validate_video_upload(video)

        with tempfile.TemporaryDirectory(prefix="harpocrates-") as tmp_dir:
            source_path = Path(tmp_dir) / "source.video"
            video.save(source_path)
            metadata = extract_metadata(source_path)
            video_hash = sha256_file(source_path)
            metadata_hash = canonical_metadata_hash(metadata) if metadata else None

        db_event = insert_proof_event(
            event_type="extract",
            file_name=safe_filename(video.filename),
            video_hash=video_hash,
            metadata_hash=metadata_hash,
            proof_id=metadata.get("proofId") if metadata else None,
            tier=metadata.get("tier") if metadata else None,
            metadata=redact_metadata(metadata),
        )

        return jsonify(
            {
                "ok": True,
                "video_hash": video_hash,
                "metadata_hash": metadata_hash,
                "metadata": metadata,
                "db_event": db_event,
            }
        )

    @app.get("/api/proofs")
    def proofs():
        limit = request.args.get("limit", "25")
        try:
            parsed_limit = int(limit)
        except ValueError:
            return jsonify({"error": "limit must be an integer"}), 400

        return jsonify({"ok": True, "events": list_proof_events(parsed_limit)})

    @app.get("/api/proofs/by-video/<video_hash>")
    def proof_by_video(video_hash: str):
        if not is_hex_32(video_hash):
            return jsonify({"error": "video_hash must be a 32-byte hex string"}), 400

        return jsonify({"ok": True, "events": find_proof_events_by_video(video_hash)})

    @app.post("/api/proofs/register")
    def register_proof_event():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON body is required"}), 400
        if len(json.dumps(payload, separators=(",", ":")).encode("utf-8")) > config.max_metadata_bytes:
            return jsonify({"error": "registration payload is too large"}), 400

        video_hash = payload.get("videoHash")
        metadata_hash = payload.get("metadataHash")
        proof_id = payload.get("proofId")
        tx_hash = payload.get("txHash")

        for name, value in (
            ("videoHash", video_hash),
            ("metadataHash", metadata_hash),
            ("proofId", proof_id),
        ):
            if not is_hex_32(value):
                return jsonify({"error": f"{name} must be a 32-byte hex string"}), 400

        db_event = insert_proof_event(
            event_type="register",
            file_name=safe_filename(payload.get("fileName")),
            video_hash=video_hash,
            metadata_hash=metadata_hash,
            proof_id=proof_id,
            tier=payload.get("tier"),
            tx_hash=tx_hash,
            tx_status=payload.get("txStatus"),
            source_address=payload.get("sourceAddress"),
            contract_id=payload.get("contractId"),
            metadata=redact_metadata(payload),
        )

        return jsonify({"ok": True, "db_event": db_event})

    @app.get("/api/proofs/history/<proof_id>")
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

        return jsonify(
            {"ok": True, "events": list_proof_history_events(proof_id, parsed_limit, parsed_offset)}
        )

    @app.post("/api/proofs/history")
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

        db_event = insert_proof_history_event(
            proof_id=proof_id,
            action=action,
            actor=actor,
            reason_code=reason_code,
            contract_id=contract_id,
            tx_hash=tx_hash,
        )

        return jsonify({"ok": True, "db_event": db_event})

    @app.post("/api/noir/silent-witness")
    def silent_witness_proof():
        if not config.noir_worker_enabled:
            return jsonify({"error": "local Noir worker is disabled"}), 404

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON body is required"}), 400

        video_hash = payload.get("videoHash")
        if not is_hex_32(video_hash):
            return jsonify({"error": "videoHash must be a 32-byte hex string"}), 400
        credential_secret = payload.get("credentialSecret")
        nullifier_secret = payload.get("nullifierSecret")
        if not is_field_decimal(credential_secret):
            return jsonify({"error": "credentialSecret must be a decimal field string"}), 400
        if not is_field_decimal(nullifier_secret):
            return jsonify({"error": "nullifierSecret must be a decimal field string"}), 400

        try:
            proof = generate_silent_witness(
                video_hash,
                credential_secret,
                nullifier_secret,
            )
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 500

        return jsonify({"ok": True, "proof": proof})

    return app


def is_hex_32(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def is_field_decimal(value: object) -> bool:
    if not isinstance(value, str) or not value or not value.isdecimal():
        return False
    field_modulus = (
        21888242871839275222246405745257275088548364400416034343698204186575808495617
    )
    return 0 < int(value) < field_modulus


def validate_video_upload(video) -> None:
    if not video.filename:
        raise ValueError("video filename is required")
    content_type = (video.content_type or "").lower()
    if content_type and not content_type.startswith("video/") and content_type != "application/octet-stream":
        raise ValueError("video upload must use a video content type")


def validate_embed_metadata(metadata: object) -> None:
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be a JSON object")
    missing = REQUIRED_EMBED_METADATA - set(metadata.keys())
    if missing:
        raise ValueError(f"metadata missing required field: {sorted(missing)[0]}")
    if metadata.get("protocol") != "harpocrates":
        raise ValueError("metadata protocol must be harpocrates")
    if metadata.get("tier") not in ALLOWED_TIERS:
        raise ValueError("metadata tier is invalid")
    if not is_hex_32(metadata.get("sourceHash")):
        raise ValueError("metadata sourceHash must be a 32-byte hex string")
    if not is_hex_32(metadata.get("proofId")):
        raise ValueError("metadata proofId must be a 32-byte hex string")


def safe_filename(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    sanitized = secure_filename(value)
    return sanitized[:160] if sanitized else None


def redact_metadata(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    redacted = {}
    for key, item in value.items():
        if key in REDACTED_METADATA_KEYS:
            redacted[key] = "[redacted]"
        elif isinstance(item, dict):
            redacted[key] = redact_metadata(item)
        else:
            redacted[key] = item
    return redacted


def video_tooling_ready() -> bool:
    try:
        from stego import _require

        _require("ffmpeg")
        _require("ffprobe")
    except RuntimeError:
        return False
    return True


app = create_app()


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5050")), debug=debug)
