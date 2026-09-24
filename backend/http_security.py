"""CORS policy and security-header helpers for Harpocrates public boundaries.

Extracted so unit tests can assert allow-lists, header maps, and enable/disable
behavior without standing up the full Flask stack or relying on opaque
flask-cors internals.
"""

from __future__ import annotations

from typing import Mapping, MutableMapping

# Methods and headers the public API actually uses. Keep this the single source
# of truth for both create_app() and focused CORS tests.
CORS_METHODS: tuple[str, ...] = ("GET", "POST", "OPTIONS")

# Server-side endpoints exempt from strict Origin enforcement. Server-to-server
# callers (health probes, metrics scrapers, contract/webhook workers) legitimately
# send no ``Origin`` header at all — a missing Origin is not a cross-origin
# browser request and must never be rejected.
CORS_EXEMPT_PATHS: frozenset[str] = frozenset({"/health", "/ready", "/metrics"})

# Request headers the public API accepts from browser clients. The trace /
# correlation headers are emitted by the request middleware in ``app.py``
# (``trace_fields.build_trace_fields``); they must be allowed here so a
# cross-origin client can supply them and have its request IDs propagated.
CORS_ALLOW_HEADERS: tuple[str, ...] = (
    "Content-Type",
    "Authorization",
    "X-Request-ID",
    "X-Trace-ID",
    "X-Correlation-ID",
    "X-Span-ID",
    "traceparent",
    "X-Metrics-Token",
    "X-Harpocrates-Retention-Class",
)

# Response headers a cross-origin browser client is allowed to read. The
# request middleware echoes the correlation IDs on every response, so they must
# be exposed as well or the browser silently hides them.
CORS_EXPOSE_HEADERS: tuple[str, ...] = (
    "Content-Disposition",
    "X-Request-ID",
    "X-Trace-ID",
    "X-Correlation-ID",
    "X-Span-ID",
    "traceparent",
    "X-Harpocrates-Source-Hash",
    "X-Harpocrates-Embedded-Hash",
    "X-Harpocrates-Metadata-Hash",
    "X-Harpocrates-Db-Event",
    "X-Harpocrates-Metadata",
    "X-Harpocrates-Retention-Class",
)

# Canonical scheme://host pairs the backend treats as trusted. Configuration
# remains authoritative for anything beyond these defaults.
CANONICAL_CORS_ORIGINS: tuple[str, ...] = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
)

# Privacy-preserving defaults applied on every response when enabled.
SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-site",
    "Cache-Control": "no-store",
}


def cors_kwargs(origins: list[str]) -> dict[str, object]:
    """Build keyword arguments for ``flask_cors.CORS`` from configured origins."""
    return {
        "origins": list(origins),
        "methods": list(CORS_METHODS),
        "allow_headers": list(CORS_ALLOW_HEADERS),
        "expose_headers": list(CORS_EXPOSE_HEADERS),
    }


def normalize_origin(origin: str | None) -> str | None:
    """Return a canonical ``scheme://host[:port]`` form of *origin*, else None.

    Normalization is deliberately narrow: surrounding whitespace is stripped and
    the value is lowercased (schemes and hosts are case-insensitive). Path,
    query, and fragment components are rejected because a CORS origin never
    carries them — an Origin such as ``https://app.example.com/evil`` is not the
    trusted origin ``https://app.example.com`` and must not match it.
    Returns ``None`` for anything empty, malformed, or path-bearing so strict
    allow-list matching can reject it.
    """
    if not origin:
        return None
    candidate = origin.strip().lower()
    if not candidate or any(c in candidate for c in "?#"):
        return None
    # A well-formed origin has exactly one "://" separating scheme and host.
    if candidate.count("://") != 1:
        return None
    scheme, _, host = candidate.partition("://")
    if not scheme or not host:
        return None
    # Path/query/fragment components never belong to an origin; reject values
    # such as "https://app.example.com/evil" outright.
    if any(c in host for c in "/?#"):
        return None
    # Reject credentials smuggled into the authority (user:pass@host).
    if "@" in host:
        return None
    # Reject a missing or malformed port (":", "abc:", ":port", "1:2:3").
    if ":" in host:
        _, _, port = host.rpartition(":")
        if not port or not port.isdigit() or not 1 <= int(port) <= 65535:
            return None
    return candidate


def is_origin_allowed(origin: str | None, allowed_origins: list[str]) -> bool:
    """Strictly decide whether *origin* is permitted by the configured allow-list.

    Both sides are normalized first, so case or whitespace variations of a
    configured origin cannot smuggle a match, while path/query-bearing values
    are rejected outright. A wildcard entry (``*``) is honored only because
    ``load_config`` already gates it behind ``ALLOW_WILDCARD_CORS=true`` and
    forbids it in production.
    """
    if "*" in allowed_origins:
        return True
    canonical = normalize_origin(origin)
    if canonical is None:
        return False
    return canonical in {normalize_origin(entry) for entry in allowed_origins}


def is_cors_method_allowed(method: str | None) -> bool:
    if not method:
        return False
    return method.upper() in CORS_METHODS


def is_cors_request_header_allowed(header_name: str | None) -> bool:
    if not header_name:
        return False
    # Preflight may send a comma-separated list; callers should split first.
    normalized = header_name.strip().lower()
    allowed = {h.lower() for h in CORS_ALLOW_HEADERS}
    return normalized in allowed


def apply_security_headers(
    headers: MutableMapping[str, str],
    *,
    enabled: bool,
) -> MutableMapping[str, str]:
    """Apply (or skip) the standard security header map onto a response header mapping.

    Uses setdefault semantics so handlers that already set a header keep their value.
    When *enabled* is False, existing headers are left untouched — callers can assert
    the toggle without depending on Flask's Response object.
    """
    if not enabled:
        return headers
    for name, value in SECURITY_HEADERS.items():
        # Mapping-like objects (werkzeug Headers) support setdefault.
        if hasattr(headers, "setdefault"):
            headers.setdefault(name, value)
        elif name not in headers:
            headers[name] = value
    return headers


def security_headers_enabled_from_mapping(config: Mapping[str, object]) -> bool:
    """Read a boolean enable flag from a config-like mapping (tests / adapters)."""
    value = config.get("security_headers_enabled", True)
    return bool(value)
