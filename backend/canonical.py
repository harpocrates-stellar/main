"""Canonical JSON and hex validation helpers shared across backend modules."""

from __future__ import annotations

import json
from typing import Any


def canonical_json_bytes(obj: Any) -> bytes:
    """Return deterministic, canonical UTF-8 encoded JSON bytes for `obj`.

    Keys are recursively sorted and compact separators (',', ':') are used
    without extra whitespace, ensuring identical serialization regardless of
    initial dictionary key order. Non-ASCII characters are preserved in UTF-8
    (ensure_ascii=False).
    """
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def is_hex(value: Any, length: int | None = None) -> bool:
    """Return True if `value` is a valid hexadecimal string.

    Optionally checks if the string has exact length `length` characters.
    Case-insensitive (accepts both uppercase and lowercase hex digits).
    Does not allow leading/trailing whitespace, signs (+/-), or prefixes (0x).
    """
    if not isinstance(value, str):
        return False
    if length is not None and len(value) != length:
        return False
    if not value:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value)
