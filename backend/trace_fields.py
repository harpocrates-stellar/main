"""Privacy-safe backend trace fields for request correlation.

Trust boundary
--------------
Trace fields are emitted at the Flask request/response boundary for log
correlation only. They may include opaque identifiers and sanitized route
patterns. They must never include real media bytes, secrets, witness values,
private keys, raw client IPs, or raw user-agent strings.

Schema / migration
------------------
``TRACE_FIELDS_SCHEMA_VERSION`` is additive. Existing ``request_id`` logging
and response headers remain compatible. Rollback is removing
``build_trace_fields`` / ``merge_trace_into_event`` usage; callers keep the
previous ``request_id``-only shape.

Malformed / oversized / unsupported inputs
------------------------------------------
Incoming trace headers that are empty, oversized, or contain disallowed
characters are ignored and replaced with generated opaque IDs. Partial
W3C ``traceparent`` values are rejected as a whole (no half-parsed IDs).
"""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from typing import Any, Mapping

TRACE_FIELDS_SCHEMA_VERSION = "harpocrates-trace-v1"
MAX_OPAQUE_ID_BYTES = 128
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9._:@+/-]{1,128}$")
_TRACEPARENT_RE = re.compile(
    r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$",
    re.IGNORECASE,
)
_UUID_SEG_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_LONG_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_DIGITS_LONG_RE = re.compile(r"^[0-9]{7,}$")
_B64_LONG_RE = re.compile(r"^[A-Za-z0-9+/\-_]{41,}={0,3}$")
_SAFE_ENDPOINT_WORDS = {
    "proof",
    "video",
    "embed",
    "extract",
    "upload",
    "api",
    "health",
    "metrics",
    "ready",
    "readiness",
    "stego",
    "noir",
    "schemas",
    "verify",
    "register",
    "aggregate",
    "internal",
    "public",
    "status",
    "version",
    "webhook",
    "workspace",
    "lineage",
    "events",
}


def versioned_domain_tag(value: object) -> str:
    """Return a stable, non-reversible ``v1:<16 hex>`` tag for opaque correlation."""
    if isinstance(value, bytes):
        data = value
    elif isinstance(value, str):
        data = value.encode("utf-8", "replace")
    else:
        data = str(value).encode("utf-8", "replace")
    digest = hashlib.sha256(data).hexdigest()
    return f"v1:{digest[:16]}"


def normalize_opaque_id(value: object, *, max_bytes: int = MAX_OPAQUE_ID_BYTES) -> str | None:
    """Accept a caller-supplied opaque ID or return ``None`` if unsafe/malformed."""
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    encoded = candidate.encode("utf-8", "replace")
    if len(encoded) > max_bytes:
        return None
    if not _OPAQUE_ID_RE.match(candidate):
        return None
    # Reject values that look like secrets / JWTs / PEMs rather than IDs.
    lowered = candidate.lower()
    if lowered.startswith("eyj") or "begin " in lowered or "private" in lowered:
        return None
    return candidate


def parse_traceparent(header: object) -> dict[str, str] | None:
    """Parse W3C ``traceparent``; reject malformed/unsupported versions."""
    if not isinstance(header, str):
        return None
    raw = header.strip()
    if not raw or len(raw.encode("utf-8", "replace")) > MAX_OPAQUE_ID_BYTES:
        return None
    match = _TRACEPARENT_RE.match(raw)
    if match is None:
        return None
    version, trace_id, span_id, flags = match.groups()
    version = version.lower()
    trace_id = trace_id.lower()
    span_id = span_id.lower()
    flags = flags.lower()
    if version != "00":
        return None
    if trace_id == "0" * 32 or span_id == "0" * 16:
        return None
    return {
        "version": version,
        "trace_id": trace_id,
        "span_id": span_id,
        "trace_flags": flags,
    }


def generate_trace_id() -> str:
    return secrets.token_hex(16)


def generate_span_id() -> str:
    return secrets.token_hex(8)


def sanitize_endpoint_pattern(path: object) -> str:
    """Replace identifier-like path segments with ``{id}`` for safe logging."""
    if not isinstance(path, str) or not path:
        return "/"
    cleaned = path.split("?", 1)[0].split("#", 1)[0]
    if cleaned == "":
        return "/"
    segments = cleaned.split("/")
    is_absolute = bool(segments) and segments[0] == ""
    if is_absolute:
        segments = segments[1:]

    processed: list[str] = []
    for seg in segments:
        if seg == "":
            continue
        lower = seg.lower()
        if (
            _UUID_SEG_RE.match(seg)
            or _HEX_LONG_RE.match(seg)
            or _DIGITS_LONG_RE.match(seg)
            or _B64_LONG_RE.match(seg)
            or (len(seg) >= 16 and seg.isalnum() and lower not in _SAFE_ENDPOINT_WORDS)
        ):
            if processed and processed[-1] == "{id}":
                continue
            processed.append("{id}")
            continue
        processed.append(seg)

    if is_absolute:
        return "/" + "/".join(processed) if processed else "/"
    return "/".join(processed) if processed else "/"


def _header_get(headers: Mapping[str, Any] | None, *names: str) -> str | None:
    if headers is None:
        return None
    # Flask headers are case-insensitive; plain dicts may not be.
    lower_map = {str(k).lower(): v for k, v in headers.items()}
    for name in names:
        value = lower_map.get(name.lower())
        if value is not None:
            return value if isinstance(value, str) else str(value)
    return None


def build_trace_fields(
    headers: Mapping[str, Any] | None,
    *,
    request_id: str | None = None,
    method: str | None = None,
    route: str | None = None,
    path: str | None = None,
) -> dict[str, Any]:
    """Build the privacy-safe trace context stored on ``g`` for this request."""
    rid = normalize_opaque_id(request_id) or str(uuid.uuid4())

    traceparent = parse_traceparent(_header_get(headers, "traceparent"))
    x_trace = normalize_opaque_id(_header_get(headers, "X-Trace-ID", "X-Trace-Id"))
    x_span = normalize_opaque_id(_header_get(headers, "X-Span-ID", "X-Span-Id"))
    x_corr = normalize_opaque_id(
        _header_get(headers, "X-Correlation-ID", "X-Correlation-Id", "X-Correlation-Id")
    )

    if traceparent is not None:
        trace_id = traceparent["trace_id"]
        parent_span_id = traceparent["span_id"]
        trace_flags = traceparent["trace_flags"]
        # Child span for this service hop.
        span_id = generate_span_id()
    else:
        parent_span_id = None
        trace_flags = "01"
        if x_trace and re.fullmatch(r"[0-9a-fA-F]{32}", x_trace):
            trace_id = x_trace.lower()
        elif x_trace:
            trace_id = hashlib.sha256(x_trace.encode("utf-8")).hexdigest()[:32]
        else:
            trace_id = hashlib.sha256(rid.encode("utf-8")).hexdigest()[:32]
        if x_span and re.fullmatch(r"[0-9a-fA-F]{16}", x_span):
            span_id = x_span.lower()
        else:
            span_id = generate_span_id()

    correlation_id = x_corr or rid
    endpoint_pattern = sanitize_endpoint_pattern(path or route or "/")

    fields: dict[str, Any] = {
        "trace_schema": TRACE_FIELDS_SCHEMA_VERSION,
        "request_id": rid,
        "trace_id": trace_id.lower() if isinstance(trace_id, str) else trace_id,
        "span_id": span_id.lower() if isinstance(span_id, str) else span_id,
        "correlation_id": correlation_id,
        "correlation_id_tag": versioned_domain_tag(correlation_id),
        "request_id_tag": versioned_domain_tag(rid),
        "endpoint_pattern": endpoint_pattern,
        "trace_flags": trace_flags,
    }
    if parent_span_id:
        fields["parent_span_id"] = parent_span_id
    if method:
        fields["method"] = method
    if route:
        fields["route"] = route
    return fields


def format_traceparent(trace_fields: Mapping[str, Any]) -> str | None:
    """Serialize current hop as W3C ``traceparent`` (version 00)."""
    trace_id = trace_fields.get("trace_id")
    span_id = trace_fields.get("span_id")
    flags = trace_fields.get("trace_flags") or "01"
    if not isinstance(trace_id, str) or not isinstance(span_id, str):
        return None
    if not re.fullmatch(r"[0-9a-f]{32}", trace_id):
        return None
    if not re.fullmatch(r"[0-9a-f]{16}", span_id):
        return None
    if not re.fullmatch(r"[0-9a-f]{2}", str(flags)):
        flags = "01"
    return f"00-{trace_id}-{span_id}-{flags}"


def merge_trace_into_event(
    event: Mapping[str, Any],
    trace_fields: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Merge privacy-safe trace fields into a structured log event.

    Existing event keys win over trace defaults so callers can override
    ``event`` / ``status`` / ``duration_ms`` without losing correlation IDs.
    Sensitive keys that somehow appear in ``event`` should still be redacted
    by ``log_structured`` / ``redact_sensitive``.
    """
    merged: dict[str, Any] = {}
    if trace_fields:
        for key in (
            "trace_schema",
            "request_id",
            "trace_id",
            "span_id",
            "parent_span_id",
            "correlation_id",
            "correlation_id_tag",
            "request_id_tag",
            "endpoint_pattern",
            "trace_flags",
            "method",
            "route",
        ):
            if key in trace_fields and trace_fields[key] is not None:
                merged[key] = trace_fields[key]
    merged.update(dict(event))
    # Prefer sanitized endpoint pattern over raw path when present.
    if "endpoint_pattern" in merged and "path" in merged:
        # Keep path only when it matches the sanitized pattern; otherwise drop
        # identifier-bearing paths from the durable log event.
        if merged["path"] != merged["endpoint_pattern"]:
            merged.pop("path", None)
    return merged


def assert_trace_fields_privacy_safe(fields: Mapping[str, Any]) -> None:
    """Raise ``ValueError`` if forbidden categories appear in trace field keys/values."""
    allowed = {
        "trace_schema",
        "request_id",
        "trace_id",
        "span_id",
        "parent_span_id",
        "correlation_id",
        "correlation_id_tag",
        "request_id_tag",
        "endpoint_pattern",
        "trace_flags",
        "method",
        "route",
        "status",
        "duration_ms",
        "event",
        "path",
    }
    for key, value in fields.items():
        if key not in allowed:
            raise ValueError(f"non-allowlisted trace field key: {key}")
        if isinstance(value, (bytes, bytearray)):
            raise ValueError("trace fields must not contain raw bytes")
        if isinstance(value, str) and value.lstrip().startswith("-----BEGIN"):
            raise ValueError("trace fields must not contain PEM material")
