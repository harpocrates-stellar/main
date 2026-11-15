"""Validation for the canonical verification-receipt input contract.

The frontend owns receipt versioning and signing. The backend only returns the
same unsigned input shape, so there is one protocol contract and no second
backend-specific receipt envelope.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
from typing import Any, Literal, Mapping, NotRequired, TypedDict

SUPPORTED_CRITICAL_RECEIPT_EXTENSIONS: frozenset[str] = frozenset(
    {
        "timeAttestationDigest",
        "revocationEpochBinding",
    }
)
MAX_RECEIPT_EXTENSIONS = 16
MAX_EXTENSION_KEY_LENGTH = 64
MAX_EXTENSIONS_JSON_BYTES = 2_048

_FORBIDDEN_EXTENSION_KEY_TOKENS = (
    "witness",
    "secret",
    "seed",
    "privatekey",
    "nonce",
    "rawmedia",
    "videobytes",
)


class VerificationReceiptInput(TypedDict):
    """Unsigned fields consumed by the frontend receipt signer."""

    result: Literal["verified", "unverified"]
    verifiedAt: str
    proofId: str
    videoHash: str
    metadataHash: str
    tier: Literal["silent", "source", "seal"]
    networkPassphrase: str
    contractId: str
    ledgerSequence: int | None
    transactionHash: str | None
    circuitVersion: str
    verifierVersion: str
    extensions: NotRequired[dict[str, Any]]
    criticalExtensions: NotRequired[list[str]]


def build_verification_receipt(
    context: Mapping[str, object],
    *,
    result: Literal["verified", "unverified"] = "unverified",
    supported_critical_extensions: frozenset[str] = SUPPORTED_CRITICAL_RECEIPT_EXTENSIONS,
) -> VerificationReceiptInput:
    """Validate and build the canonical unsigned receipt input.

    A receipt is only emitted when the caller supplies the complete canonical
    evidence context. This prevents the selective-disclosure endpoint from
    inventing proof IDs or hashes from unrelated request fields.
    """

    receipt: VerificationReceiptInput = {
        "result": _choice(result, "result", ("verified", "unverified")),  # type: ignore[typeddict-item]
        "verifiedAt": (
            _iso_timestamp(context["verifiedAt"])
            if "verifiedAt" in context and context.get("verifiedAt") is not None
            else datetime.now(timezone.utc).isoformat()
        ),
        "proofId": _hex32(context.get("proofId"), "proofId"),
        "videoHash": _hex32(context.get("videoHash"), "videoHash"),
        "metadataHash": _hex32(context.get("metadataHash"), "metadataHash"),
        "tier": _choice(context.get("tier"), "tier", ("silent", "source", "seal")),  # type: ignore[typeddict-item]
        "networkPassphrase": _text(context.get("networkPassphrase"), "networkPassphrase"),
        "contractId": _text(context.get("contractId"), "contractId"),
        "ledgerSequence": _optional_int(context.get("ledgerSequence"), "ledgerSequence"),
        "transactionHash": _optional_hex32(context.get("transactionHash"), "transactionHash"),
        "circuitVersion": _text(context.get("circuitVersion"), "circuitVersion"),
        "verifierVersion": _text(context.get("verifierVersion"), "verifierVersion"),
    }

    has_ext = "extensions" in context and context.get("extensions") is not None
    has_crit = "criticalExtensions" in context and context.get("criticalExtensions") is not None
    if has_ext or has_crit:
        normalized_exts, normalized_crit = validate_receipt_extensions(
            context.get("extensions"),
            context.get("criticalExtensions"),
            supported_critical_extensions=supported_critical_extensions,
        )
        if has_ext or normalized_exts:
            receipt["extensions"] = normalized_exts
        if has_crit or normalized_crit:
            receipt["criticalExtensions"] = normalized_crit

    return receipt


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _hex32(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{field} must be a 32-byte hex string")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{field} must be a 32-byte hex string") from exc
    return value.lower()


def _optional_hex32(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _hex32(value, field)


def _optional_int(value: object, field: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer or null")
    return value


def _choice(value: object, field: str, choices: tuple[str, ...]) -> str:
    if value not in choices:
        raise ValueError(f"{field} must be one of: {', '.join(choices)}")
    return value


def _iso_timestamp(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("verifiedAt must be a valid ISO-8601 timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("verifiedAt must be a valid ISO-8601 timestamp") from exc
    return value


def _assert_safe_json_value(value: object, *, depth: int = 0) -> None:
    if depth > 6:
        raise ValueError("receipt extension nesting exceeds maximum depth")
    if value is None or isinstance(value, (bool, int, float, str)):
        return
    if isinstance(value, list):
        for item in value:
            _assert_safe_json_value(item, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        for k, v in value.items():
            if not isinstance(k, str) or not k.strip() or len(k) > MAX_EXTENSION_KEY_LENGTH:
                raise ValueError("receipt extension keys must be bounded non-empty strings")
            lowered = k.lower().replace("_", "").replace("-", "")
            if any(tok in lowered for tok in _FORBIDDEN_EXTENSION_KEY_TOKENS):
                raise ValueError("receipt extensions must not carry private witness or secret fields")
            _assert_safe_json_value(v, depth=depth + 1)
        return
    raise ValueError("receipt extension values must be JSON-compatible")


def _validate_supported_critical_semantics(name: str, raw_val: object) -> Any:
    # Unwrap inline {"critical": bool, "value": ...} wrapper when used
    is_wrapped = (
        isinstance(raw_val, Mapping)
        and set(raw_val.keys()) <= {"critical", "value"}
        and "value" in raw_val
    )
    inner = raw_val["value"] if is_wrapped else raw_val

    if name == "timeAttestationDigest":
        checked = _hex32(inner, "extensions.timeAttestationDigest")
        return {"critical": True, "value": checked} if is_wrapped else checked

    if name == "revocationEpochBinding":
        if not isinstance(inner, Mapping) or set(inner.keys()) != {"epoch", "rootHash"}:
            raise ValueError(
                "extensions.revocationEpochBinding must define epoch and rootHash"
            )
        epoch = _optional_int(inner.get("epoch"), "extensions.revocationEpochBinding.epoch")
        if epoch is None:
            raise ValueError("extensions.revocationEpochBinding.epoch is required")
        root_hash = _hex32(
            inner.get("rootHash"),
            "extensions.revocationEpochBinding.rootHash",
        )
        normalized_binding = {"epoch": epoch, "rootHash": root_hash}
        return {"critical": True, "value": normalized_binding} if is_wrapped else normalized_binding

    raise ValueError(f"unsupported critical receipt extension: {name}")


def validate_receipt_extensions(
    extensions: object,
    critical_extensions: object = None,
    *,
    supported_critical_extensions: frozenset[str] = SUPPORTED_CRITICAL_RECEIPT_EXTENSIONS,
) -> tuple[dict[str, Any], list[str]]:
    """Validate receipt metadata extensions fail-closed on unsupported critical semantics."""
    if extensions is None:
        ext_map: dict[str, Any] = {}
    elif isinstance(extensions, Mapping):
        ext_map = {str(k): copy.deepcopy(v) for k, v in extensions.items()}
    else:
        raise ValueError("extensions must be a JSON object")

    if len(ext_map) > MAX_RECEIPT_EXTENSIONS:
        raise ValueError(f"extensions count exceeds maximum of {MAX_RECEIPT_EXTENSIONS}")
    _assert_safe_json_value(ext_map)

    declared_critical: list[str] = []
    if critical_extensions is not None:
        if not isinstance(critical_extensions, (list, tuple)):
            raise ValueError("criticalExtensions must be a list of extension names")
        if len(critical_extensions) > MAX_RECEIPT_EXTENSIONS:
            raise ValueError("criticalExtensions exceeds maximum bound")
        seen_crit: set[str] = set()
        for item in critical_extensions:
            if not isinstance(item, str) or not item.strip() or len(item) > MAX_EXTENSION_KEY_LENGTH:
                raise ValueError("criticalExtensions entries must be bounded non-empty strings")
            if item in seen_crit:
                raise ValueError(f"duplicate critical receipt extension: {item}")
            seen_crit.add(item)
            declared_critical.append(item)

    # Also detect inline {"critical": True} declarations inside extensions
    for ext_name, ext_val in ext_map.items():
        if isinstance(ext_val, Mapping) and "critical" in ext_val:
            crit_flag = ext_val.get("critical")
            if not isinstance(crit_flag, bool):
                raise ValueError(f"extensions.{ext_name}.critical must be a boolean")
            if crit_flag and ext_name not in declared_critical:
                declared_critical.append(ext_name)

    for crit_name in declared_critical:
        if crit_name not in supported_critical_extensions:
            raise ValueError(f"unsupported critical receipt extension: {crit_name}")
        if crit_name not in ext_map:
            raise ValueError(
                f"critical receipt extension '{crit_name}' is missing from extensions"
            )
        ext_map[crit_name] = _validate_supported_critical_semantics(
            crit_name, ext_map[crit_name]
        )

    encoded = json.dumps(ext_map, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode(
        "utf-8"
    )
    if len(encoded) > MAX_EXTENSIONS_JSON_BYTES:
        raise ValueError("receipt extensions exceed byte size bound")

    return ext_map, sorted(declared_critical)


def serialize_receipt_metadata(
    receipt: Mapping[str, object],
    *,
    supported_critical_extensions: frozenset[str] = SUPPORTED_CRITICAL_RECEIPT_EXTENSIONS,
) -> str:
    """Validate and canonically serialize receipt metadata preserving optional extensions."""
    validated = parse_receipt_metadata(
        receipt,
        supported_critical_extensions=supported_critical_extensions,
    )
    return json.dumps(validated, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def parse_receipt_metadata(
    raw: str | bytes | Mapping[str, object],
    *,
    supported_critical_extensions: frozenset[str] = SUPPORTED_CRITICAL_RECEIPT_EXTENSIONS,
) -> VerificationReceiptInput:
    """Parse and validate receipt metadata fail-closed on unsupported critical extensions."""
    if isinstance(raw, (str, bytes)):
        raw_text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError("malformed receipt metadata JSON") from exc
    else:
        parsed = raw

    if not isinstance(parsed, Mapping):
        raise ValueError("receipt metadata must be a JSON object")

    allowed_top_fields = {
        "result",
        "verifiedAt",
        "proofId",
        "videoHash",
        "metadataHash",
        "tier",
        "networkPassphrase",
        "contractId",
        "ledgerSequence",
        "transactionHash",
        "circuitVersion",
        "verifierVersion",
        "extensions",
        "criticalExtensions",
    }
    unknown_top = sorted(set(parsed.keys()) - allowed_top_fields)
    if unknown_top:
        raise ValueError(f"unknown top-level receipt fields: {', '.join(unknown_top)}")

    res_val = _choice(parsed.get("result"), "result", ("verified", "unverified"))
    return build_verification_receipt(
        parsed,
        result=res_val,  # type: ignore[arg-type]
        supported_critical_extensions=supported_critical_extensions,
    )

