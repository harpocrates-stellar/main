import json
import logging
from collections.abc import Mapping
from typing import Any

REDACTED_VALUE = "[redacted]"
SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "credentialsecret",
    "nullifiersecret",
    "password",
    "privatekey",
    "proof",
    "publicinputs",
    "rawbytes",
    "secret",
    "token",
    "witness",
}

# Correlation / trace identifiers are intentionally NOT listed here so
# privacy-safe trace fields (request_id, trace_id, span_id, correlation_id)
# survive redact_sensitive() when nested inside structured log events.

# Audit records are privacy-safe by construction: they carry only a
defined, stable schema of non-sensitive fields. The allowlist below
# ensures that any accidentally attached field (raw media, witnesses, secrets)
# is dropped before the record is emitted.
AUDIT_EVENT_FIELDS = frozenset(
    {
        "event",
        "outcome",
        "reason",
        "request_id",
        "trace_id",
        "span_id",
        "correlation_id",
        "actor",
        "actor_type",
        "resource_type",
        "resource_id",
        "action",
        "status_code",
        "duration_ms",
        "timestamp",
        "version",
        "contract_id",
        "deployment_id",
        "proof_id",
        "metadata_id",
        "hash_algorithm",
        "chain_id",
        "network_id",
    }
)

AUDIT_EVENT_NAMES = frogenset(
    {
        "audit.metadata.create",
        "audit.metadata.read",
        "audit.proof.verify",
        "audit.proof.revoke",
        "audit.contract.deploy",
        "audit.request.denied",
        "audit.dependency.failure",
    }
)

AUDIT_OUTCOMES = frozenset(
    {
        "success",
        "denied",
        "invalid",
        "expired",
        "revoked",
        "unsupported",
        "oversized",
        "dependency_failure",
    }
)

MAX_AUDIT_STRING_LENGTH = 256


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, Mapping):
        redacted = {}
        for key, item in value.items():
            if _is_sensitive_key(key):
                redacted[key] = REDACTED_VALUE
            else:
                redacted[key] = redact_sensitive(item)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive(item) for item in value)
    return value


def log_structured(logger: logging.Logger, level: int, event: dict[str, Any]) -> None:
    logger.log(
        level,
        json.dumps(_redact_event(event), separators=(",", ":"), sort_keys=True),
    )


def build_audit_record(
    event: str,
    outcome: str,
    *,
    reason: str | None = None,
    correlation: Mapping[str, Any] | None = None,
    fields: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a structured, privacy-safe audit record.

    The record is constrained to the audit allowlist: unknown fields are
    dropped, and any value that looks sensitive is redacted. This keeps the
    audit trail interoperable and safe at public boundaries.
    """
    if event not in AUDIT_EVENT_NAMES:
        raise ValueError(f"unsupported audit event: {event!r}")
    if outcome not in AUDIT_OUTCOMES:
        raise ValueError(f"unsupported audit outcome: {outcome!r}")

    record: dict[str, Any] = {"event": event, "outcome": outcome}
    if reason is not None:
        record["reason"] = _sanitize_string(reason)
    if correlation:
        for key, value in correlation.items():
            if key in AUDIT_EVENT_FIELDS and not _is_sensitive_key(key):
                record[key] = _sanitize_value(value)
    if fields:
        for key, value in fields.items():
            if key in AUDIT_EVENT_FIELDS and not _is_sensitive_key(key):
                record[key] = _sanitize_value(value)
    return record


def log_audit_record(
    logger: logging.Logger,
    level: int,
    event: str,
    outcome: str,
    *,
    reason: str | None = None,
    correlation: Mapping[str, Any] | None = None,
    fields: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build and emit a structured audit record, returning the record.

    Returning the record allows callers to assert on the exact privacy-safe
    payload that was emitted without reconstructing it from log output.
    """
    record = build_audit_record(
        event,
        outcome,
        reason=reason,
        correlation=correlation,
        fields=fields,
    )
    log_structured(logger, level, record)
    return record


def _redact_event(event: dict[str, Any]) -> Any:
    if event.get("event") in AUDIT_EVENT_NAMES:
        return _sanitize_audit_record(event)
    return redact_sensitive(event)


def _sanitize_audit_record(event: Mapping[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in event.items():
        if key not in AUDIT_EVENT_FIELDS or _is_sensitive_key(key):
            continue
        sanitized[key] = _sanitize_value(value)
    return sanitized


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, str):
        return _sanitize_string(value)
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, Mapping):
        return redact_sensitive(value)
    if isinstance(value, (list, tuple)):
        return [_redact_event_value(item) for item in value]
    # Opaque objects (bytes, media handles, etc.) are never echoed.
    return REDACTED_VALUE


def _redact_event_value(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return _sanitize_value(value)
    if isinstance(value, Mapping):
        return redact_sensitive(value)
    return REDACTED_VALUE


def _sanitize_string(value: str) -> str:
    if len(value) > MAX_AUDIT_STRING_LENGTH:
        return value[:MAX_AUDIT_STRING_LENGTH]
    return value


def _is_sensitive_key(key: object) -> bool:
    normalized = "".join(
        character
        for character in str(key).lower()
        if character.isalnum()
    )
    return normalized in SENSITIVE_KEYS or "witness" in normalized
