"""Structured privacy-safe audit records for the Harpocrates backend.

Audit records capture security- and operations-relevant events at public
boundaries without embedding real media, secrets, witness values, or private
keys. Records are versioned, size-bounded, and safe to persist to Neon or emit
as structured logs.

Schema version: harpocrates-audit-record-v1

Trust boundary
--------------
- Inputs may include attacker-controlled keys/values from request metadata.
- Outputs are allowlisted fields plus a sanitized ``details`` object.
- Persistence failures never raise into request handlers (dependency-failure
  outcome is recorded in-memory / logged instead).

Migration / rollback
--------------------
- Neon table ``audit_records`` is created by migration id=11.
- Rollback: stop writing new records; the table is additive and unused by
  protocol evidence paths. Existing proof/metadata artifacts are untouched.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

from logging_utils import REDACTED_VALUE, log_structured, redact_sensitive

AUDIT_RECORD_SCHEMA_VERSION = "harpocrates-audit-record-v1"
AUDIT_RECORD_MAX_DETAILS_BYTES = 4096
AUDIT_RECORD_MAX_DETAIL_DEPTH = 8
AUDIT_RECORD_RING_SIZE = 256

LOGGER = logging.getLogger("harpocrates.audit")

# Stable outcome codes for malformed / oversized / expired / revoked /
# unsupported / dependency-failure inputs (acceptance criteria).
OUTCOME_OK = "ok"
OUTCOME_MALFORMED = "malformed"
OUTCOME_OVERSIZED = "oversized"
OUTCOME_EXPIRED = "expired"
OUTCOME_REVOKED = "revoked"
OUTCOME_UNSUPPORTED = "unsupported"
OUTCOME_DEPENDENCY_FAILURE = "dependency_failure"
OUTCOME_DENIED = "denied"

OUTCOMES = frozenset(
    {
        OUTCOME_OK,
        OUTCOME_MALFORMED,
        OUTCOME_OVERSIZED,
        OUTCOME_EXPIRED,
        OUTCOME_REVOKED,
        OUTCOME_UNSUPPORTED,
        OUTCOME_DEPENDENCY_FAILURE,
        OUTCOME_DENIED,
    }
)

# Allowlisted actions — only these may appear on durable audit records.
ALLOWED_ACTIONS = frozenset(
    {
        "http.request",
        "http.error",
        "auth.denied",
        "auth.expired_key",
        "proof.register",
        "proof.verify",
        "proof.history",
        "media.embed",
        "media.extract",
        "metadata.validate",
        "lineage.register",
        "admin.legal_hold",
        "system.dependency_failure",
        "system.startup",
        "audit.write",
        "audit.query",
    }
)

# Extra sensitive key fragments beyond logging_utils.SENSITIVE_KEYS.
_EXTRA_SENSITIVE_FRAGMENTS = frozenset(
    {
        "secret",
        "password",
        "passwd",
        "token",
        "apikey",
        "privatekey",
        "privkey",
        "mnemonic",
        "seed",
        "witness",
        "video",
        "media",
        "upload",
        "blob",
        "rawbytes",
        "filecontent",
        "credential",
        "nullifier",
        "authorization",
        "bearer",
        "cookie",
        "session",
    }
)


@dataclass
class AuditRecord:
    """Canonical privacy-safe audit record."""

    schema_version: str
    audit_id: str
    action: str
    outcome: str
    timestamp_unix: float
    request_id: str | None = None
    actor: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    route: str | None = None
    method: str | None = None
    status: int | None = None
    details: dict[str, Any] = field(default_factory=dict)
    details_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuditRecordError(ValueError):
    """Stable validation error for audit record construction."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


_lock = threading.Lock()
_ring: list[AuditRecord] = []


def _normalize_key(key: object) -> str:
    return "".join(c for c in str(key).lower() if c.isalnum())


def _is_sensitive_key(key: object) -> bool:
    """Return True when a details key must be redacted.

    Public digests / ids such as ``video_hash`` and ``proof_id`` are kept.
    """
    normalized = _normalize_key(key)
    if not normalized:
        return False

    # Public correlation / digest fields stay (unless they are secret carriers).
    safe_exact = {
        "requestid",
        "auditid",
        "proofid",
        "route",
        "path",
        "method",
        "status",
        "tier",
        "outcome",
        "action",
        "durationms",
        "count",
        "errorcode",
        "errormessage",
        "errortype",
        "dependency",
    }
    if normalized in safe_exact:
        return False
    if normalized.endswith(("hash", "digest", "id")) and not any(
        normalized.startswith(prefix)
        for prefix in ("password", "secret", "private", "mnemonic", "credential", "token", "cookie", "bearer")
    ):
        return False

    if "witness" in normalized:
        return True
    for frag in _EXTRA_SENSITIVE_FRAGMENTS:
        if frag in normalized:
            return True
    return False


def sanitize_audit_details(
    value: Any,
    *,
    depth: int = 0,
    max_depth: int = AUDIT_RECORD_MAX_DETAIL_DEPTH,
    max_bytes: int = AUDIT_RECORD_MAX_DETAILS_BYTES,
    _scalar_limit: int = 256,
) -> dict[str, Any]:
    """Return a privacy-safe details object.

    - Drops/redacts sensitive keys (secrets, media, witness, private keys).
    - Caps nesting depth and serialized size.
    - Always returns a dict (wraps non-dicts).
    """
    if depth > max_depth:
        return {"_truncated": "max_depth"}

    # Pre-check raw payload size so oversized inputs cannot bypass via scalar caps.
    if depth == 0:
        try:
            raw = json.dumps(value, default=str)
        except Exception:
            raw = str(value)
        if len(raw.encode("utf-8", "replace")) > max_bytes:
            digest = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()
            return {
                "_truncated": "oversized",
                "_original_bytes": len(raw.encode("utf-8", "replace")),
                "_digest": digest,
            }

    if value is None:
        cleaned: Any = {}
    elif isinstance(value, Mapping):
        cleaned = {}
        for key, item in value.items():
            if _is_sensitive_key(key):
                cleaned[str(key)] = REDACTED_VALUE
            elif isinstance(item, (Mapping, list, tuple)):
                if isinstance(item, Mapping):
                    cleaned[str(key)] = sanitize_audit_details(
                        item,
                        depth=depth + 1,
                        max_depth=max_depth,
                        max_bytes=max_bytes,
                        _scalar_limit=_scalar_limit,
                    )
                else:
                    cleaned[str(key)] = [
                        (
                            sanitize_audit_details(
                                el,
                                depth=depth + 1,
                                max_depth=max_depth,
                                max_bytes=max_bytes,
                                _scalar_limit=_scalar_limit,
                            )
                            if isinstance(el, Mapping)
                            else (
                                REDACTED_VALUE
                                if _looks_like_secret_value(el)
                                else _cap_scalar(el, _scalar_limit)
                            )
                        )
                        for el in list(item)[:32]
                    ]
            else:
                cleaned[str(key)] = (
                    REDACTED_VALUE
                    if _looks_like_secret_value(item)
                    else _cap_scalar(item, _scalar_limit)
                )
    else:
        cleaned = {
            "value": REDACTED_VALUE
            if _looks_like_secret_value(value)
            else _cap_scalar(value, _scalar_limit)
        }

    # Apply logging_utils redaction as a second pass for known sensitive keys.
    cleaned = redact_sensitive(cleaned)
    if not isinstance(cleaned, dict):
        cleaned = {"value": cleaned}

    serialized = json.dumps(cleaned, separators=(",", ":"), sort_keys=True, default=str)
    if len(serialized.encode("utf-8")) > max_bytes:
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return {
            "_truncated": "oversized",
            "_original_bytes": len(serialized.encode("utf-8")),
            "_digest": digest,
        }
    return cleaned


def _cap_scalar(value: Any, limit: int = 256) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value
    text = str(value)
    if len(text) > limit:
        return text[:limit] + "…[truncated]"
    return text


def _looks_like_secret_value(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if text.startswith("-----BEGIN") and "PRIVATE KEY" in text:
        return True
    if text.startswith("eyJ") and text.count(".") >= 2:  # JWT-ish
        return True
    if len(text) >= 64 and all(c in "0123456789abcdefABCDEF" for c in text):
        # Long hex blobs (proofs / hashes of secrets) — keep only digest form
        # via caller; treat as sensitive when key already flagged. Here only
        # PEM/JWT auto-redact to avoid nuking public video_hash fields when
        # passed under safe keys.
        return False
    return False


def _details_digest(details: Mapping[str, Any]) -> str:
    raw = json.dumps(details, separators=(",", ":"), sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_audit_record(
    *,
    action: str,
    outcome: str = OUTCOME_OK,
    request_id: str | None = None,
    actor: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    route: str | None = None,
    method: str | None = None,
    status: int | None = None,
    details: Mapping[str, Any] | None = None,
    audit_id: str | None = None,
    timestamp_unix: float | None = None,
) -> AuditRecord:
    """Validate and build a structured audit record.

    Raises AuditRecordError with a stable ``code`` for malformed / unsupported
    / oversized inputs. Callers that must not raise should use ``record_audit``.
    """
    if not isinstance(action, str) or not action.strip():
        raise AuditRecordError(OUTCOME_MALFORMED, "action is required")
    action = action.strip()
    if action not in ALLOWED_ACTIONS:
        raise AuditRecordError(OUTCOME_UNSUPPORTED, f"unsupported action: {action}")

    if not isinstance(outcome, str) or outcome not in OUTCOMES:
        raise AuditRecordError(OUTCOME_MALFORMED, f"invalid outcome: {outcome}")

    safe_details = sanitize_audit_details(dict(details or {}))
    # Oversized details are replaced with a digest stub by sanitize_audit_details.
    # Surface OVERSIZED as the outcome when the caller still claimed OK.
    if safe_details.get("_truncated") == "oversized" and outcome == OUTCOME_OK:
        outcome = OUTCOME_OVERSIZED

    if actor is not None:
        actor = _cap_scalar(actor, 128)
        if _is_sensitive_key("actor") or _looks_like_secret_value(actor):
            actor = REDACTED_VALUE

    if resource_id is not None:
        resource_id = _cap_scalar(resource_id, 128)

    record = AuditRecord(
        schema_version=AUDIT_RECORD_SCHEMA_VERSION,
        audit_id=audit_id or str(uuid.uuid4()),
        action=action,
        outcome=outcome,
        timestamp_unix=float(timestamp_unix if timestamp_unix is not None else time.time()),
        request_id=_cap_scalar(request_id, 128) if request_id else None,
        actor=actor,
        resource_type=_cap_scalar(resource_type, 64) if resource_type else None,
        resource_id=resource_id,
        route=_cap_scalar(route, 256) if route else None,
        method=_cap_scalar(method, 16) if method else None,
        status=int(status) if status is not None else None,
        details=safe_details,
        details_digest=_details_digest(safe_details),
    )
    return record


def _ring_append(record: AuditRecord) -> None:
    with _lock:
        _ring.append(record)
        if len(_ring) > AUDIT_RECORD_RING_SIZE:
            del _ring[: len(_ring) - AUDIT_RECORD_RING_SIZE]


def recent_audit_records(limit: int = 50) -> list[dict[str, Any]]:
    """Return recent in-memory audit records (newest last)."""
    limit = max(1, min(int(limit), AUDIT_RECORD_RING_SIZE))
    with _lock:
        return [r.to_dict() for r in _ring[-limit:]]


def clear_audit_ring() -> None:
    """Test helper: clear the in-memory ring buffer."""
    with _lock:
        _ring.clear()


def record_audit(
    *,
    action: str,
    outcome: str = OUTCOME_OK,
    request_id: str | None = None,
    actor: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    route: str | None = None,
    method: str | None = None,
    status: int | None = None,
    details: Mapping[str, Any] | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """Build, log, optionally persist, and return an audit record dict.

    Never raises for caller-supplied bad input or DB failures — returns a
    stable privacy-safe record describing the failure outcome instead.
    """
    try:
        record = build_audit_record(
            action=action,
            outcome=outcome,
            request_id=request_id,
            actor=actor,
            resource_type=resource_type,
            resource_id=resource_id,
            route=route,
            method=method,
            status=status,
            details=details,
        )
    except AuditRecordError as exc:
        # Stable failure record — still privacy-safe.
        fallback_details = sanitize_audit_details(
            {"error_code": exc.code, "error_message": exc.message, **dict(details or {})}
        )
        record = AuditRecord(
            schema_version=AUDIT_RECORD_SCHEMA_VERSION,
            audit_id=str(uuid.uuid4()),
            action=action if action in ALLOWED_ACTIONS else "audit.write",
            outcome=exc.code if exc.code in OUTCOMES else OUTCOME_MALFORMED,
            timestamp_unix=time.time(),
            request_id=request_id,
            route=route,
            method=method,
            status=status,
            details=fallback_details,
            details_digest=_details_digest(fallback_details),
        )

    _ring_append(record)
    payload = record.to_dict()
    log_structured(
        LOGGER,
        logging.INFO,
        {"event": "audit_record", **{k: v for k, v in payload.items() if k != "details"}, "details": payload.get("details")},
    )

    if persist:
        try:
            from db import insert_audit_record

            insert_audit_record(payload)
        except Exception as exc:  # noqa: BLE001 — dependency failure must be soft
            dep = build_audit_record(
                action="system.dependency_failure",
                outcome=OUTCOME_DEPENDENCY_FAILURE,
                request_id=request_id,
                details={
                    "dependency": "neon_audit_records",
                    "error_type": type(exc).__name__,
                },
            )
            _ring_append(dep)
            log_structured(
                LOGGER,
                logging.WARNING,
                {
                    "event": "audit_persist_failed",
                    "request_id": request_id,
                    "error_type": type(exc).__name__,
                },
            )

    return payload


def outcome_from_http_status(status: int) -> str:
    """Map an HTTP status code to a stable audit outcome."""
    if status < 400:
        return OUTCOME_OK
    if status == 401:
        return OUTCOME_DENIED
    if status == 403:
        return OUTCOME_DENIED
    if status == 404:
        return OUTCOME_UNSUPPORTED
    if status == 413:
        return OUTCOME_OVERSIZED
    if status == 415:
        return OUTCOME_UNSUPPORTED
    if status == 422:
        return OUTCOME_MALFORMED
    if status >= 500:
        return OUTCOME_DEPENDENCY_FAILURE
    return OUTCOME_MALFORMED


def action_from_route(method: str, route: str) -> str:
    """Best-effort map of Flask route → allowlisted audit action."""
    path = (route or "").lower()
    method_u = (method or "GET").upper()
    if "register" in path and "lineage" in path:
        return "lineage.register"
    if "register" in path or path.endswith("/api/proofs"):
        return "proof.register"
    if "history" in path:
        return "proof.history"
    if "verify" in path:
        return "proof.verify"
    if "embed" in path:
        return "media.embed"
    if "extract" in path:
        return "media.extract"
    if "legal" in path or "hold" in path:
        return "admin.legal_hold"
    if "audit" in path:
        return "audit.query" if method_u == "GET" else "audit.write"
    if method_u in {"POST", "PUT", "PATCH", "DELETE"}:
        return "http.request"
    return "http.request"
