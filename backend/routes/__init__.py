"""Shared helpers, context accessors, and validation utilities for backend routes."""

from __future__ import annotations

import functools
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from flask import current_app, g, jsonify, request
from werkzeug.datastructures import ImmutableMultiDict
from werkzeug.utils import secure_filename

import register_auth
from admission import AdmissionController, require_capacity
from config import AppConfig
from errors import FORBIDDEN, error_response
from logging_utils import log_structured, redact_sensitive
from quarantine import QuarantineError, sniff_media_type_stream
from streaming_upload import (
    StreamingFileStorage,
    create_streaming_file_storage,
)
from strkey import validate_source_address
from trace_fields import build_trace_fields, merge_trace_into_event
from verifier_cache import VerifierCache

# ---------------------------------------------------------------------------
# Bounded aggregation constants
# ---------------------------------------------------------------------------
# These MUST match the values in the Noir circuit and the Soroban contract.
MAX_AGGREGATION_SIZE = 8
AGGREGATION_ELEMENT_COST = 128  # bytes per aggregated public-input element

# ---------------------------------------------------------------------------
# Declared upload-body budget
# ---------------------------------------------------------------------------
UPLOAD_MULTIPART_OVERHEAD_BYTES = 1_048_576

LOGGER = logging.getLogger("harpocrates.requests")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = False


@dataclass
class AppContext:
    """Shared application state stored in ``app.extensions['harpocrates']``."""

    config: AppConfig
    limiter: Any
    admission_controller: AdmissionController
    verifier_cache: VerifierCache


def get_app_context() -> AppContext:
    return current_app.extensions["harpocrates"]


def get_config() -> AppConfig:
    ctx = current_app.extensions.get("harpocrates")
    if ctx is not None:
        return ctx.config
    return current_app.extensions["config"]


def get_limiter():
    ctx = current_app.extensions.get("harpocrates")
    if ctx is not None:
        return ctx.limiter
    return current_app.extensions["limiter"]


def get_admission_controller() -> AdmissionController:
    ctx = current_app.extensions.get("harpocrates")
    if ctx is not None:
        return ctx.admission_controller
    return current_app.extensions["admission_controller"]


def get_verifier_cache() -> VerifierCache:
    if "verifier_cache" in current_app.extensions:
        return current_app.extensions["verifier_cache"]
    return current_app.extensions["harpocrates"].verifier_cache


def app_attr(name: str, default: Any):
    """Look up ``name`` on the ``app`` module first so ``patch.object(app, ...)`` works."""
    import sys

    app_mod = sys.modules.get("app")
    if app_mod is not None and hasattr(app_mod, name):
        return getattr(app_mod, name)
    return default


def dynamic_limit(config_attr: str):
    """Apply a Flask-Limiter limit dynamically resolved from the current app's config."""

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            limiter = get_limiter()
            config = get_config()
            limit_str = getattr(config, config_attr)
            decorated = getattr(fn, "_rate_limited_view", None)
            if decorated is None or getattr(fn, "_rate_limited_owner", None) is not limiter:
                decorated = limiter.limit(limit_str)(fn)
                setattr(fn, "_rate_limited_view", decorated)
                setattr(fn, "_rate_limited_owner", limiter)
            return decorated(*args, **kwargs)

        return wrapper

    return decorator


def require_app_capacity(fn):
    """Enforce admission control using the current app's ``AdmissionController``."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        controller = get_admission_controller()
        return require_capacity(controller)(fn)(*args, **kwargs)

    return wrapper


def require_register_auth(fn):
    """Decorator that enforces ownership-scoped auth on proof registration."""

    def reject(reason: str, message: str):
        log_structured(
            LOGGER,
            logging.WARNING,
            {"event": "register_auth_rejected", "reason": reason, "request_id": request_id()},
        )
        return jsonify({"error": message}), 401

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        config = get_config()
        legacy_key = config.register_api_key
        scoped_keys = config.register_scoped_keys
        if legacy_key is None and not scoped_keys:
            return fn(*args, **kwargs)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return reject(
                register_auth.REASON_MISSING,
                "Authorization header with Bearer token is required",
            )

        token = auth_header[len("Bearer ") :].strip()
        now = datetime.now(tz=timezone.utc)

        principal = register_auth.authenticate(
            token,
            legacy_key=legacy_key,
            scoped_keys=scoped_keys,
        )
        previous_key = config.register_api_key_previous
        previous_principal = (
            register_auth.authenticate(token, legacy_key=previous_key, scoped_keys=())
            if previous_key
            else None
        )
        expires = config.register_api_key_expires
        primary_expired = expires is not None and now >= expires
        previous_expires = config.register_api_key_previous_expires
        if primary_expired:
            principal = None
        if (
            principal is None
            and previous_principal is not None
            and (previous_expires is None or now < previous_expires)
        ):
            principal = previous_principal
        if principal is None:
            if primary_expired:
                return reject(register_auth.REASON_EXPIRED, "API key has expired")
            return reject(register_auth.REASON_INVALID, "Invalid API key")

        if principal.is_scoped:
            if (request.content_length or 0) > config.max_json_bytes:
                return jsonify({"error": "JSON payload exceeds size limit"}), 413
            payload = request.get_json(silent=True)
            if isinstance(payload, dict):
                try:
                    claimed_owner = validate_source_address(payload.get("sourceAddress"))
                except ValueError as exc:
                    return jsonify({"error": str(exc)}), 400
                if not register_auth.scope_allows(principal, claimed_owner):
                    log_structured(
                        LOGGER,
                        logging.WARNING,
                        {
                            "event": "register_auth_rejected",
                            "reason": register_auth.REASON_SCOPE,
                            "request_id": request_id(),
                        },
                    )
                    return error_response(
                        code=FORBIDDEN,
                        message="credential is not authorized for this sourceAddress",
                        status=403,
                        field="sourceAddress",
                    )

        g.register_principal = principal
        return fn(*args, **kwargs)

    return wrapper


def declared_upload_limit_bytes(config) -> int:
    """Return the largest acceptable declared ``Content-Length`` for an upload."""
    per_file = int(getattr(config, "upload_max_bytes", 0) or config.max_video_bytes)
    limit = per_file + UPLOAD_MULTIPART_OVERHEAD_BYTES
    global_cap = int(getattr(config, "max_content_length", 0) or 0)
    if global_cap and limit > global_cap:
        limit = global_cap
    return limit


def enforce_video_size(video) -> bool:
    config = get_config()
    if isinstance(video, StreamingFileStorage):
        if video.bytes_written > 0:
            return video.bytes_written <= config.max_video_bytes
        if request.content_length is not None:
            return request.content_length <= config.max_content_length
        return True
    video.seek(0, 2)
    size = video.tell()
    video.seek(0)
    return size <= config.max_video_bytes


def enable_streaming_for_large_uploads() -> None:
    """Wrap large multipart uploads with bounded-chunk stream hashing."""
    config = get_config()
    threshold = getattr(config, "upload_stream_threshold_bytes", 1_048_576)
    if not request.content_length or request.content_length <= threshold:
        return
    if not request.files:
        return

    g.upload_config = config
    current = request.files
    streaming_factory = app_attr(
        "create_streaming_file_storage", create_streaming_file_storage
    )
    new_items = []
    for field_name, field_storage in current.items(multi=True):
        new_items.append((field_name, streaming_factory(field_storage)))
    request.__dict__["files"] = ImmutableMultiDict(new_items)


def enforce_json_size() -> int:
    raw = request.get_data()
    return len(raw) if raw else 0


def request_id() -> str:
    return getattr(g, "request_id", "unknown")


def request_route() -> str:
    return request.url_rule.rule if request.url_rule else request.path


def request_duration_ms() -> float:
    started_at = getattr(g, "request_started_at", None)
    if started_at is None:
        return 0.0
    return round((time.perf_counter() - started_at) * 1000, 2)


def log_error_response(status: int) -> None:
    log_structured(
        LOGGER,
        logging.ERROR,
        merge_trace_into_event(
            {
                "event": "error",
                "request_id": request_id(),
                "method": request.method,
                "route": request_route(),
                "path": request.path,
                "status": status,
                "duration_ms": request_duration_ms(),
            },
            current_trace_fields(),
        ),
    )


def current_trace_fields() -> dict:
    fields = getattr(g, "trace_fields", None)
    if isinstance(fields, dict):
        return fields
    return build_trace_fields(
        getattr(request, "headers", None),
        request_id=request_id(),
        method=getattr(request, "method", None),
        route=request_route() if request else None,
        path=getattr(request, "path", None),
    )


def is_hex_32(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def normalize_tx_hash(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("txHash must be a 32-byte hex string")

    normalized = value.strip().lower()
    if not is_hex_32(normalized):
        raise ValueError("txHash must be a 32-byte hex string")
    return normalized


def normalize_tx_status(value: object) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError("txStatus must be one of: pending, confirmed, failed, missing")

    normalized = value.strip().lower()
    if normalized in {"pending", "confirmed", "failed", "missing"}:
        return normalized
    if normalized in {"success", "successful", "succeeded"}:
        return "confirmed"
    if normalized in {"failure", "failed", "error", "errored"}:
        return "failed"
    if normalized in {"not_found", "notfound"}:
        return "missing"
    raise ValueError("txStatus must be one of: pending, confirmed, failed, missing")


def is_field_decimal(value: object) -> bool:
    if not isinstance(value, str) or not value or not value.isdecimal():
        return False
    field_modulus = (
        21888242871839275222246405745257275088548364400416034343698204186575808495617
    )
    return 0 < int(value) < field_modulus


def validate_video_upload(video) -> None:
    """Validate an uploaded video *before* it is saved to disk or handed to ffmpeg."""
    if not video.filename:
        raise ValueError("video filename is required")

    content_type = (video.content_type or "").lower()
    if (
        content_type
        and not content_type.startswith("video/")
        and content_type != "application/octet-stream"
    ):
        raise QuarantineError(
            "video upload must use a video/* or application/octet-stream content type"
        )

    stream = getattr(video, "stream", None)
    if stream is None:
        stream = video
    sniff_media_type_stream(
        stream,
        filename=video.filename,
        content_type=video.content_type,
    )


def normalize_filename(value: object) -> str | None:
    """Return a normalized, filesystem-safe version of an uploaded filename."""
    if not isinstance(value, str) or not value.strip():
        return None

    sanitized = secure_filename(value)
    if not sanitized:
        return None

    sanitized = sanitized.lower()

    if "." in sanitized:
        dot = sanitized.rfind(".")
        stem, ext = sanitized[:dot], sanitized[dot:]
    else:
        stem, ext = sanitized, ""

    stem = re.sub(r"[\s_\-]+", "_", stem).strip("_-")
    if not stem:
        return None

    normalized = stem + ext
    return normalized[:160]


safe_filename = normalize_filename


def redact_metadata(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    return redact_sensitive(value)


def video_tooling_ready() -> bool:
    try:
        from stego import _require

        _require("ffmpeg")
        _require("ffprobe")
    except RuntimeError:
        return False
    return True
