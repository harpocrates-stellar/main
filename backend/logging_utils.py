import json
import logging
from collections.abc import Mapping
from typing import Any

REDACTED_VALUE = "[redacted]"
SENSITIVE_KEYS = {
    "authorization",
    "credentialsecret",
    "nullifiersecret",
    "proof",
    "publicinputs",
}


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
        json.dumps(redact_sensitive(event), separators=(",", ":"), sort_keys=True),
    )


def _is_sensitive_key(key: object) -> bool:
    normalized = "".join(
        character
        for character in str(key).lower()
        if character.isalnum()
    )
    return normalized in SENSITIVE_KEYS or "witness" in normalized
