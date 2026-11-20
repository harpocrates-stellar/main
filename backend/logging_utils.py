import json
import logging
import re
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

DIAGNOSTIC_MAX_BYTES = 2048
DIAGNOSTIC_MAX_FRAMES = 20

_PATH_PATTERN = re.compile(r"(?:[A-Za-z]:\\|/)(?:[^\s'\"/\\:]+[/\\])+[^\s'\"/\\:]*")
_SECRET_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|private[_-]?key|witness)"
    r"(\s*[=:]\s*)(\S+)"
)
_BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+")


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


def sanitize_diagnostic_text(text: object, max_bytes: int = DIAGNOSTIC_MAX_BYTES) -> str:
    """Redact private paths and secret-shaped values, then cap the byte size."""
    value = str(text)
    value = _BEARER_PATTERN.sub("Bearer " + REDACTED_VALUE, value)
    value = _SECRET_PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED_VALUE}", value)
    value = _PATH_PATTERN.sub("[path]", value)
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) > max_bytes:
        suffix = "...[truncated]"
        budget = max(0, max_bytes - len(suffix.encode("utf-8")))
        value = encoded[:budget].decode("utf-8", errors="ignore") + suffix
    return value


def sanitize_traceback_frames(
    frames: list[str],
    max_frames: int = DIAGNOSTIC_MAX_FRAMES,
    max_bytes: int = DIAGNOSTIC_MAX_BYTES,
) -> list[str]:
    """Sanitize formatted traceback frames, keeping the most recent ones."""
    kept = frames[-max_frames:] if max_frames > 0 else []
    sanitized = [sanitize_diagnostic_text(frame, max_bytes) for frame in kept]
    if len(frames) > len(kept):
        sanitized.insert(0, f"[{len(frames) - len(kept)} frames omitted]")
    return sanitized


def sanitize_exception(exc: BaseException) -> dict[str, Any]:
    """Return a bounded, redacted description of an exception for logs and storage."""
    import traceback

    frames = [
        line.rstrip("\n")
        for line in traceback.format_exception(type(exc), exc, exc.__traceback__)
    ]
    frames = [line for chunk in frames for line in chunk.splitlines()]
    return {
        "type": type(exc).__name__,
        "message": sanitize_diagnostic_text(exc),
        "traceback": sanitize_traceback_frames(frames),
    }


def log_structured(logger: logging.Logger, level: int, event: dict[str, Any]) -> None:
    logger.log(
        level,
        json.dumps(redact_sensitive(event), separators=(",", ":"), sort_keys=True),
    )


def _is_sensitive_key(key: object) -> bool:
    normalized = "".join(
        character
        for character in str(key).lower()
        if character.isalnum()
    )
    return normalized in SENSITIVE_KEYS or "witness" in normalized
