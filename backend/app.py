from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import time
import uuid

from dotenv import load_dotenv
from flask import Flask, Response, g, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import RequestEntityTooLarge

from admission import AdmissionController, require_capacity  # noqa: F401
from config import load_config
from db import (  # noqa: F401
    ConflictError,
    cancel_job,
    check_db,
    database_url,
    decode_proof_events_cursor,
    enqueue_job,
    find_lineage_by_actor,
    find_lineage_by_output_digest,
    find_proof_events_by_proof_id,
    find_proof_events_by_video,
    find_proof_owner,
    get_job,
    init_db,
    insert_lineage_event,
    insert_proof_event,
    insert_proof_history_event,
    list_lineage_events,
    list_proof_events,
    list_proof_history_events,
    make_idempotency_key,
    set_legal_hold,
    upsert_register_event,
)
try:
    from registration_reconcile import (  # noqa: F401
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
from errors import (  # noqa: F401
    DEPENDENCY_UNAVAILABLE,
    FORBIDDEN,
    FORBIDDEN_ORIGIN,
    GONE,
    INTERNAL_ERROR,
    MALFORMED_INPUT,
    NOT_FOUND,
    OVERSIZED_INPUT,
    PAYLOAD_TOO_LARGE,
    RATE_LIMITED,
    STEGO_LIMIT_EXCEEDED,
    UNSUPPORTED_INPUT,
    UNSUPPORTED_MEDIA_TYPE,
    VALIDATION_ERROR,
    classify_cli_error,
    error_response,
    ok_response,
    register_request_id_propagation,
)
from http_security import (
    CORS_EXEMPT_PATHS,
    apply_security_headers,
    cors_kwargs,
    is_origin_allowed,
)
from logging_utils import log_structured, redact_sensitive  # noqa: F401
from metadata_errors import MetadataError, metadata_error_response
from metrics import collector as metrics_collector
try:
    from noir import generate_aggregated_proof, generate_silent_witness  # noqa: F401
except ImportError:
    generate_silent_witness = None
    generate_aggregated_proof = None
from readiness import ReadinessManager
from retention import init_retention_worker
from routes import (
    AGGREGATION_ELEMENT_COST,  # noqa: F401
    JOB_PRIVATE_FIELDS,  # noqa: F401
    LOGGER,
    MAX_AGGREGATION_SIZE,
    UPLOAD_MULTIPART_OVERHEAD_BYTES,  # noqa: F401
    AppContext,
    _detect_worker_count,
    clamp_lineage_limit,  # noqa: F401
    current_trace_fields,
    declared_upload_limit_bytes,  # noqa: F401
    get_ratelimit_storage_kind,
    is_field_decimal,  # noqa: F401
    is_hex_32,  # noqa: F401
    log_error_response,
    normalize_filename,  # noqa: F401
    normalize_tx_hash,  # noqa: F401
    normalize_tx_status,  # noqa: F401
    public_job_view,  # noqa: F401
    redact_metadata,  # noqa: F401
    request_duration_ms,
    request_id,
    request_route,
    safe_filename,  # noqa: F401
    validate_video_upload,  # noqa: F401
    video_tooling_ready,
)
from routes.c2pa import bp as c2pa_bp
from routes.jobs import bp as jobs_bp
from routes.lineage import bp as lineage_bp
from routes.proofs import bp as proofs_bp
from routes.schemas import bp as schemas_bp
from routes.stego import bp as stego_bp
from routes.time_attestation import bp as time_attestation_bp
from schema import discover_schemas, resolve_schema  # noqa: F401
from stego import (  # noqa: F401
    StegoLimitExceededError,
    canonical_metadata_hash,
    embed_metadata,
    extract_metadata,
    sha256_file,
)
from storage import get_job_output_path  # noqa: F401
from streaming_upload import (  # noqa: F401
    StreamingFileStorage,
    create_streaming_file_storage,
    hash_paths_concat,
)
from trace_fields import (
    build_trace_fields,
    format_traceparent,
    merge_trace_into_event,
)
from tracing import (
    begin_request_span,
    configure_tracing,
    finish_request_span,
)
from verifier_cache import VerifierCache
from webhook import WebhookWorker, queue_webhook_deliveries  # noqa: F401
from workspace import EncryptedWorkspace  # noqa: F401


def _make_key_func(config):
    """Return a rate-limit key function that uses the real client IP."""
    trusted = set()
    for entry in config.trusted_proxies:
        try:
            trusted.add(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            pass

    def _key_func() -> str:
        if not trusted:
            return get_remote_address()

        xff = request.headers.get("X-Forwarded-For", "")
        addrs = [a.strip() for a in xff.split(",") if a.strip()]
        addrs.append(request.remote_addr or "127.0.0.1")

        for addr in reversed(addrs):
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if not any(ip in net for net in trusted):
                return str(ip)

        return get_remote_address()

    return _key_func


def create_app() -> Flask:
    load_dotenv()
    config = load_config()
    configure_tracing(
        enabled=config.tracing_enabled,
        service_name=config.tracing_service_name,
        endpoint=config.tracing_endpoint,
        sample_ratio=config.tracing_sample_ratio,
        export_timeout_seconds=config.tracing_export_timeout_seconds,
        service_version=config.release_id,
    )
    app = Flask(__name__)
    verifier_cache = VerifierCache(
        max_size=config.verifier_cache_max_size,
        positive_ttl_seconds=config.verifier_cache_positive_ttl_seconds,
        negative_ttl_seconds=config.verifier_cache_negative_ttl_seconds,
    )
    app.extensions["verifier_cache"] = verifier_cache

    LOGGER.info("App started with config summary")
    log_structured(
        LOGGER,
        logging.INFO,
        {"event": "app_start", "config": config.redacted_summary()},
    )
    CORS(app, **cors_kwargs(config.cors_origins))
    app.config["MAX_CONTENT_LENGTH"] = config.max_content_length
    register_request_id_propagation(app)

    storage_uri = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    storage_kind = get_ratelimit_storage_kind(storage_uri)
    worker_count = _detect_worker_count()

    if config.ratelimit_enabled and storage_kind == "memory" and worker_count > 1:
        log_structured(
            LOGGER,
            logging.WARNING,
            {
                "event": "ratelimit_unshared_storage",
                "message": (
                    "Rate limits are stored in memory and not shared across workers; "
                    "limits will multiply with concurrency. Configure RATELIMIT_STORAGE_URI."
                ),
                "storage_kind": storage_kind,
                "workers": worker_count,
            },
        )

    try:
        limiter = Limiter(
            key_func=_make_key_func(config),
            app=app,
            enabled=config.ratelimit_enabled,
            storage_uri=storage_uri,
            default_limits=[],
            headers_enabled=True,
            swallow_errors=True,
        )
    except Exception:
        limiter = Limiter(
            key_func=_make_key_func(config),
            app=app,
            enabled=config.ratelimit_enabled,
            storage_uri="memory://",
            default_limits=[],
            headers_enabled=True,
            swallow_errors=True,
        )

    @limiter.request_filter
    def _health_exempt():
        """Health and readiness probes must never be rate-limited."""
        return request.path in {"/health", "/ready"}

    init_db()
    init_retention_worker()

    readiness_manager = ReadinessManager(timeout_seconds=1.0, cache_ttl_seconds=5.0)
    readiness_manager.add_dependency(
        "database",
        check_db,
        critical=True,
        ok_status="connected",
        fail_status="not_configured",
    )
    readiness_manager.add_dependency(
        "video_tools",
        video_tooling_ready,
        critical=True,
        ok_status="available",
        fail_status="missing",
    )

    admission_controller = AdmissionController(
        max_concurrent=config.max_concurrent_requests,
        max_queue=config.max_queue_size,
        max_per_identity=config.max_concurrent_per_identity,
        timeout_seconds=config.admission_timeout_seconds,
    )

    app.extensions["config"] = config
    app.extensions["limiter"] = limiter
    app.extensions["admission_controller"] = admission_controller
    app.extensions["harpocrates"] = AppContext(
        config=config,
        limiter=limiter,
        admission_controller=admission_controller,
        verifier_cache=verifier_cache,
    )

    @app.before_request
    def start_request_context():
        g.start_time = time.perf_counter()
        g.request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        g.request_started_at = time.perf_counter()

    @app.before_request
    def initialize_trace_context():
        g.trace_fields = build_trace_fields(
            request.headers,
            request_id=g.request_id,
            method=request.method,
            route=request.url_rule.rule if request.url_rule else request.path,
            path=request.path,
        )
        g.request_id = g.trace_fields["request_id"]
        g.otel_request_span = begin_request_span(
            request.headers,
            method=request.method,
            route=(
                request.url_rule.rule
                if request.url_rule
                else g.trace_fields["endpoint_pattern"]
            ),
            request_id=g.request_id,
        )
        span_context = g.otel_request_span.span.get_span_context()
        if span_context.is_valid:
            g.trace_fields["trace_id"] = f"{span_context.trace_id:032x}"
            g.trace_fields["span_id"] = f"{span_context.span_id:016x}"
            g.trace_fields["trace_flags"] = f"{int(span_context.trace_flags):02x}"

    @app.before_request
    def enforce_cors_origins():
        """Reject browser requests whose Origin is not on the configured allow-list."""
        origin = request.headers.get("Origin")
        if origin is None or request.path in CORS_EXEMPT_PATHS:
            return None
        if is_origin_allowed(origin, config.cors_origins):
            return None
        metrics_collector.record_rejection(
            "cors_origin_not_allowed",
            request.url_rule.rule if request.url_rule else request.path,
        )
        log_structured(
            LOGGER,
            logging.INFO,
            {
                "event": "cors_origin_rejected",
                "request_id": request_id(),
                "method": request.method,
                "path": request.path,
            },
        )
        return error_response(
            code=FORBIDDEN_ORIGIN,
            message="request origin is not allowed",
            status=403,
        )

    @app.after_request
    def process_response(response: Response):
        trace = current_trace_fields()
        if trace.get("trace_id"):
            response.headers["X-Trace-ID"] = str(trace["trace_id"])
        if trace.get("correlation_id"):
            response.headers["X-Correlation-ID"] = str(trace["correlation_id"])
        if trace.get("span_id"):
            response.headers["X-Span-ID"] = str(trace["span_id"])
        traceparent = format_traceparent(trace)
        if traceparent:
            response.headers["traceparent"] = traceparent
        apply_security_headers(
            response.headers,
            enabled=config.security_headers_enabled,
        )
        response.headers.setdefault("X-Harpocrates-Release", config.release_id)
        response.headers.setdefault("X-Harpocrates-Network", config.release_network)

        if config.metrics_enabled and request.path != config.metrics_path:
            start_time = getattr(g, "start_time", None)
            duration = (
                time.perf_counter() - start_time if start_time is not None else 0.0
            )
            endpoint_rule = (
                request.url_rule.rule if request.url_rule else "unmatched"
            )
            metrics_collector.record_request(
                method=request.method,
                endpoint=endpoint_rule,
                status=response.status_code,
                duration_seconds=duration,
                upload_bytes=request.content_length,
            )

        if response.status_code >= 400:
            log_error_response(response.status_code)
        log_structured(
            LOGGER,
            logging.INFO,
            merge_trace_into_event(
                {
                    "event": "request",
                    "request_id": request_id(),
                    "method": request.method,
                    "route": request_route(),
                    "path": request.path,
                    "status": response.status_code,
                    "duration_ms": request_duration_ms(),
                },
                trace,
            ),
        )
        finish_request_span(
            getattr(g, "otel_request_span", None),
            status_code=response.status_code,
        )
        return response

    @app.teardown_request
    def finish_unhandled_request_span(error: BaseException | None):
        if getattr(g, "otel_request_span", None) is not None:
            finish_request_span(
                g.otel_request_span,
                status_code=500 if error is not None else 200,
                error=error,
            )

    @app.errorhandler(StegoLimitExceededError)
    def stego_limit_exceeded(error: StegoLimitExceededError):
        app.logger.warning("Steganography resource limit exceeded: %s", error)
        return error_response(
            code=STEGO_LIMIT_EXCEEDED,
            message="steganography resource limit exceeded",
            status=413,
            cli_code=OVERSIZED_INPUT,
        )

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error: RequestEntityTooLarge):
        return error_response(
            code=PAYLOAD_TOO_LARGE,
            message="request body is too large",
            status=413,
        )

    @app.errorhandler(ValueError)
    def bad_request(error: ValueError):
        if isinstance(error, MetadataError):
            return metadata_error_response(error)
        return error_response(
            code=VALIDATION_ERROR,
            message=str(error),
            status=400,
        )

    @app.errorhandler(RuntimeError)
    def runtime_error(error: RuntimeError):
        app.logger.error("Unhandled runtime error: %s", error, exc_info=True)
        return error_response(
            code=INTERNAL_ERROR,
            message="internal server error",
            status=500,
        )

    @app.errorhandler(429)
    def rate_limit_exceeded(_error: Exception):
        """Stable, privacy-safe envelope for per-client throttle responses."""
        response, status = error_response(
            code=RATE_LIMITED,
            message="rate limit exceeded",
            status=429,
        )
        response.headers.setdefault("Retry-After", "60")
        return response, status

    @app.get(config.metrics_path)
    def metrics():
        if not config.metrics_enabled:
            return jsonify({"error": "metrics service disabled"}), 404

        if config.metrics_token:
            auth_header = request.headers.get("Authorization", "")
            token = (
                auth_header[7:].strip()
                if auth_header.startswith("Bearer ")
                else ""
            )
            custom_token = request.headers.get("X-Metrics-Token", "").strip()
            expected_token = config.metrics_token.encode("utf-8")
            bearer_ok = hmac.compare_digest(token.encode("utf-8"), expected_token)
            header_ok = hmac.compare_digest(
                custom_token.encode("utf-8"), expected_token
            )
            if not (bearer_ok or header_ok):
                return jsonify({"error": "unauthorized metrics access"}), 401

        output = metrics_collector.generate_prometheus_metrics()
        return Response(output, mimetype="text/plain; version=0.0.4; charset=utf-8")

    @app.get("/health")
    def health():
        trace = current_trace_fields()
        return jsonify(
            {
                "ok": True,
                "service": "harpocrates-stego",
                "release_id": config.release_id,
                "network": config.release_network,
                "request_id": request_id(),
                "trace_id": trace.get("trace_id"),
                "correlation_id": trace.get("correlation_id"),
            }
        )

    @app.get("/ready")
    def ready():
        status = readiness_manager.check()
        for dependency in readiness_manager.deps:
            metrics_collector.record_dependency_status(
                dependency.name,
                status.get(dependency.name, "unknown"),
                dependency.critical,
            )
        trace = current_trace_fields()
        return (
            jsonify(
                {
                    "ok": status["ok"],
                    "service": "harpocrates-stego",
                    "database": status.get("database", "not_configured"),
                    "video_tools": status.get("video_tools", "missing"),
                    "noir_worker": (
                        "enabled" if config.noir_worker_enabled else "disabled"
                    ),
                    "aggregation": (
                        "enabled" if config.noir_worker_enabled else "disabled"
                    ),
                    "max_aggregation_size": MAX_AGGREGATION_SIZE,
                    "ratelimit_storage": storage_kind,
                    "storage_kind": storage_kind,
                    "request_id": request_id(),
                    "trace_id": trace.get("trace_id"),
                    "correlation_id": trace.get("correlation_id"),
                }
            ),
            200 if status["ok"] else 503,
        )

    for blueprint in (
        stego_bp,
        proofs_bp,
        lineage_bp,
        time_attestation_bp,
        jobs_bp,
        schemas_bp,
        c2pa_bp,
    ):
        app.register_blueprint(blueprint)

    if database_url():
        webhook_worker = WebhookWorker()
        webhook_worker.start()
        app.webhook_worker = webhook_worker

    return app


app = create_app()


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5050")),
        debug=debug,
    )
