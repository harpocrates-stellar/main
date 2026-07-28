import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict


MAX_METADATA_BYTES = 16384  # Default fallback if config isn't available

class SchemaValidationError(ValueError):
    pass


def is_hex_32(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _validate_timestamp(value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise SchemaValidationError("metadata timestamp must be a string")
    ts = value.strip().replace("Z", "+00:00").replace("z", "+00:00")
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        raise SchemaValidationError("metadata timestamp must be a timezone-aware ISO-8601 string")
    if dt.tzinfo is None:
        raise SchemaValidationError("metadata timestamp must be timezone-aware")
    if dt > datetime.now(timezone.utc) + timedelta(seconds=300):
        raise SchemaValidationError("metadata timestamp is unreasonably far in the future")


def validate_v1(metadata: Dict[str, Any]) -> None:
    required = {"protocol", "version", "tier", "sourceHash", "proofId", "timestamp"}
    missing = required - set(metadata.keys())
    if missing:
        raise SchemaValidationError(f"metadata missing required field: {sorted(missing)[0]}")
    
    if metadata.get("protocol") != "harpocrates":
        raise SchemaValidationError("metadata protocol must be harpocrates")
    if metadata.get("version") != 1:
        raise SchemaValidationError("metadata version must be 1")
    if metadata.get("tier") not in {"silent", "source", "seal"}:
        raise SchemaValidationError("metadata tier is invalid")
    if not is_hex_32(metadata.get("sourceHash")):
        raise SchemaValidationError("metadata sourceHash must be a 32-byte hex string")
    if not is_hex_32(metadata.get("proofId")):
        raise SchemaValidationError("metadata proofId must be a 32-byte hex string")
    
    _validate_timestamp(metadata.get("timestamp"))


def validate(metadata: object) -> None:
    if not isinstance(metadata, dict):
        raise SchemaValidationError("metadata must be a JSON object")
    
    version = metadata.get("version")
    if version == 1:
        validate_v1(metadata)
    else:
        raise SchemaValidationError(f"unsupported metadata version: {version}")


def canonical_encode(metadata: Dict[str, Any]) -> bytes:
    validate(metadata)
    encoded = json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(encoded) > MAX_METADATA_BYTES:
        raise SchemaValidationError("metadata is too large")
    return encoded


def canonical_decode(payload: bytes) -> Dict[str, Any]:
    try:
        metadata = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SchemaValidationError("payload is not valid JSON")
    
    validate(metadata)
    return metadata
