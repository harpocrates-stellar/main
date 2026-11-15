"""Validation and public signing-key history for the verification-receipt protocol.

The frontend owns receipt versioning and signing. The backend never loads,
stores, or accepts private signing keys: it only validates unsigned receipt
inputs and serves bounded, read-only public ECDSA P-256 JWK history and
validity intervals in the existing ``harpocrates-verification-receipt`` protocol.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from typing import Any, Literal, Mapping, TypedDict

RECEIPT_PROTOCOL: Literal["harpocrates-verification-receipt"] = (
    "harpocrates-verification-receipt"
)
RECEIPT_VERSION: Literal[1] = 1
RECEIPT_SIGNING_ALGORITHM: Literal["ECDSA_P256_SHA256"] = "ECDSA_P256_SHA256"
MAX_RECEIPT_SIGNING_KEYS = 32
MAX_PUBLIC_KEY_DIRECTORY_BYTES = 32_768
MAX_KEY_ID_LENGTH = 128

ReceiptKeyStatus = Literal["active", "rotated", "retired", "revoked"]
ALLOWED_KEY_STATUSES: tuple[ReceiptKeyStatus, ...] = (
    "active",
    "rotated",
    "retired",
    "revoked",
)

FORBIDDEN_PRIVATE_JWK_FIELDS = frozenset(
    {
        "d",
        "p",
        "q",
        "dp",
        "dq",
        "qi",
        "oth",
        "k",
        "privateKey",
        "private_key",
        "secretKey",
        "secret_key",
        "signingKey",
        "signing_key",
        "seed",
    }
)
FORBIDDEN_PRIVATE_ENV_VARS = (
    "RECEIPT_SIGNING_PRIVATE_KEY",
    "RECEIPT_PRIVATE_KEY",
    "RECEIPT_SIGNING_SEED",
)


class PrivateSigningKeyRejectedError(ValueError):
    """Raised fail-closed whenever private signing material reaches the backend."""


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


class PublicEcP256Jwk(TypedDict):
    """Sanitized public-only ECDSA P-256 JWK compatible with WebCrypto verify."""

    kty: Literal["EC"]
    crv: Literal["P-256"]
    x: str
    y: str
    key_ops: list[Literal["verify"]]


class ReceiptKeyValidityWindow(TypedDict, total=False):
    """Validity interval consumed by ``verifyVerificationReceipt``."""

    notBefore: str
    notAfter: str


class PublicReceiptSigningKeyEntry(TypedDict):
    """Read-only public receipt signing-key history record."""

    keyId: str
    algorithm: Literal["ECDSA_P256_SHA256"]
    status: ReceiptKeyStatus
    publicKeyJwk: PublicEcP256Jwk
    publicKeyThumbprint: str
    notBefore: str
    notAfter: str | None


class PublicReceiptSigningKeyHistory(TypedDict):
    """Protocol-aligned public key history payload."""

    protocol: Literal["harpocrates-verification-receipt"]
    version: Literal[1]
    algorithm: Literal["ECDSA_P256_SHA256"]
    signingOwnership: Literal["frontend"]
    totalEntries: int
    entries: list[PublicReceiptSigningKeyEntry]
    keys: dict[str, PublicEcP256Jwk]
    keyValidity: dict[str, ReceiptKeyValidityWindow]


def build_verification_receipt(
    context: Mapping[str, object],
    *,
    result: Literal["verified", "unverified"] = "unverified",
) -> VerificationReceiptInput:
    """Validate and build the canonical unsigned receipt input.

    A receipt is only emitted when the caller supplies the complete canonical
    evidence context. This prevents the selective-disclosure endpoint from
    inventing proof IDs or hashes from unrelated request fields.
    """

    return {
        "result": result,
        "verifiedAt": datetime.now(timezone.utc).isoformat(),
        "proofId": _hex32(context.get("proofId"), "proofId"),
        "videoHash": _hex32(context.get("videoHash"), "videoHash"),
        "metadataHash": _hex32(context.get("metadataHash"), "metadataHash"),
        "tier": _choice(context.get("tier"), "tier", ("silent", "source", "seal")),
        "networkPassphrase": _text(context.get("networkPassphrase"), "networkPassphrase"),
        "contractId": _text(context.get("contractId"), "contractId"),
        "ledgerSequence": _optional_int(context.get("ledgerSequence"), "ledgerSequence"),
        "transactionHash": _optional_hex32(context.get("transactionHash"), "transactionHash"),
        "circuitVersion": _text(context.get("circuitVersion"), "circuitVersion"),
        "verifierVersion": _text(context.get("verifierVersion"), "verifierVersion"),
    }


def sanitize_public_ec_p256_jwk(raw_jwk: Mapping[str, object]) -> tuple[PublicEcP256Jwk, str]:
    """Validate an EC P-256 public JWK and compute its RFC 7638 SHA-256 thumbprint.

    Any private scalar (``d``) or signing capability (``sign`` in ``key_ops``)
    is rejected fail-closed so private signing material never enters memory.
    """
    if not isinstance(raw_jwk, Mapping):
        raise ValueError("publicKeyJwk must be a JSON object")

    leaked_fields = FORBIDDEN_PRIVATE_JWK_FIELDS.intersection(raw_jwk.keys())
    if leaked_fields:
        raise PrivateSigningKeyRejectedError(
            "private signing key material is prohibited on the backend"
        )

    key_ops = raw_jwk.get("key_ops")
    if key_ops is not None:
        if not isinstance(key_ops, list) or any(not isinstance(op, str) for op in key_ops):
            raise ValueError("publicKeyJwk.key_ops must be an array of strings")
        if any(op != "verify" for op in key_ops):
            raise PrivateSigningKeyRejectedError(
                "publicKeyJwk.key_ops may only declare 'verify'"
            )

    use = raw_jwk.get("use")
    if use is not None and use != "sig":
        raise ValueError("publicKeyJwk.use must be 'sig' when provided")

    if raw_jwk.get("kty") != "EC" or raw_jwk.get("crv") != "P-256":
        raise ValueError("publicKeyJwk must declare kty='EC' and crv='P-256'")

    x = _decode_p256_coord(raw_jwk.get("x"), "publicKeyJwk.x")
    y = _decode_p256_coord(raw_jwk.get("y"), "publicKeyJwk.y")

    thumbprint_input = json.dumps(
        {"crv": "P-256", "kty": "EC", "x": x, "y": y},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    thumbprint = hashlib.sha256(thumbprint_input).hexdigest()

    sanitized: PublicEcP256Jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "key_ops": ["verify"],
    }
    return sanitized, thumbprint


def parse_public_receipt_signing_key_entries(
    raw_entries: object,
) -> list[PublicReceiptSigningKeyEntry]:
    """Validate bounded public receipt signing-key entries and their validity windows."""
    if raw_entries is None:
        return []
    if not isinstance(raw_entries, list):
        raise ValueError("receipt signing-key history must be a JSON array")
    if len(raw_entries) > MAX_RECEIPT_SIGNING_KEYS:
        raise ValueError(
            f"receipt signing-key history exceeds maximum of {MAX_RECEIPT_SIGNING_KEYS} entries"
        )

    seen_ids: set[str] = set()
    normalized: list[PublicReceiptSigningKeyEntry] = []

    for entry in raw_entries:
        if not isinstance(entry, Mapping):
            raise ValueError("each signing-key entry must be a JSON object")

        leaked_top = FORBIDDEN_PRIVATE_JWK_FIELDS.intersection(entry.keys())
        if leaked_top:
            raise PrivateSigningKeyRejectedError(
                "private signing key material is prohibited on the backend"
            )

        key_id = _text(entry.get("keyId"), "keyId").strip()
        if len(key_id) > MAX_KEY_ID_LENGTH:
            raise ValueError(f"keyId exceeds maximum length of {MAX_KEY_ID_LENGTH}")
        if key_id in seen_ids:
            raise ValueError("duplicate keyId in receipt signing-key history")
        seen_ids.add(key_id)

        algorithm = entry.get("algorithm", RECEIPT_SIGNING_ALGORITHM)
        if algorithm != RECEIPT_SIGNING_ALGORITHM:
            raise ValueError(f"algorithm must be {RECEIPT_SIGNING_ALGORITHM}")

        raw_status = entry.get("status", "active")
        status: ReceiptKeyStatus = _choice(
            raw_status,
            "status",
            ALLOWED_KEY_STATUSES,
        )  # type: ignore[assignment]

        raw_jwk = entry.get("publicKeyJwk")
        if not isinstance(raw_jwk, Mapping):
            raise ValueError("publicKeyJwk must be a JSON object")
        sanitized_jwk, thumbprint = sanitize_public_ec_p256_jwk(raw_jwk)

        not_before_dt, not_before_iso = _parse_utc_timestamp(
            entry.get("notBefore"),
            "notBefore",
        )
        raw_not_after = entry.get("notAfter")
        not_after_iso: str | None = None
        if raw_not_after is not None:
            not_after_dt, not_after_iso = _parse_utc_timestamp(
                raw_not_after,
                "notAfter",
            )
            if not_after_dt <= not_before_dt:
                raise ValueError("notAfter must be strictly after notBefore")

        normalized.append(
            {
                "keyId": key_id,
                "algorithm": RECEIPT_SIGNING_ALGORITHM,
                "status": status,
                "publicKeyJwk": sanitized_jwk,
                "publicKeyThumbprint": thumbprint,
                "notBefore": not_before_iso,
                "notAfter": not_after_iso,
            }
        )

    normalized.sort(key=lambda item: (item["notBefore"], item["keyId"]), reverse=True)
    return normalized


def load_public_receipt_signing_keys_from_env(
    environ: Mapping[str, str] | None = None,
) -> list[PublicReceiptSigningKeyEntry]:
    """Load public-only receipt signing-key history from environment configuration."""
    env = os.environ if environ is None else environ
    for forbidden_var in FORBIDDEN_PRIVATE_ENV_VARS:
        if env.get(forbidden_var, "").strip():
            raise PrivateSigningKeyRejectedError(
                f"{forbidden_var} is prohibited: frontend retains receipt signing ownership"
            )

    raw_json = env.get("RECEIPT_PUBLIC_SIGNING_KEYS_JSON", "").strip()
    if not raw_json:
        return []
    if len(raw_json.encode("utf-8")) > MAX_PUBLIC_KEY_DIRECTORY_BYTES:
        raise ValueError("RECEIPT_PUBLIC_SIGNING_KEYS_JSON exceeds size bound")

    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise ValueError("RECEIPT_PUBLIC_SIGNING_KEYS_JSON is not valid JSON") from exc

    if isinstance(parsed, Mapping) and "entries" in parsed:
        leaked = FORBIDDEN_PRIVATE_JWK_FIELDS.intersection(parsed.keys())
        if leaked:
            raise PrivateSigningKeyRejectedError(
                "private signing key material is prohibited on the backend"
            )
        parsed = parsed["entries"]

    return parse_public_receipt_signing_key_entries(parsed)


def clamp_signing_key_history_limit(raw_limit: object) -> int:
    """Validate and clamp the ``limit`` query parameter into ``[1, MAX_RECEIPT_SIGNING_KEYS]``."""
    if raw_limit is None:
        return MAX_RECEIPT_SIGNING_KEYS
    if isinstance(raw_limit, bool):
        raise ValueError("limit must be an integer")
    try:
        parsed = int(str(raw_limit).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer") from exc
    if parsed < 1:
        return 1
    if parsed > MAX_RECEIPT_SIGNING_KEYS:
        return MAX_RECEIPT_SIGNING_KEYS
    return parsed


def build_public_receipt_signing_key_history(
    entries: list[PublicReceiptSigningKeyEntry],
    *,
    limit: int = MAX_RECEIPT_SIGNING_KEYS,
    status_filter: str | None = None,
    key_id_filter: str | None = None,
) -> PublicReceiptSigningKeyHistory:
    """Build the bounded protocol-compatible public key history response."""
    if status_filter is not None and status_filter not in ALLOWED_KEY_STATUSES:
        raise ValueError(
            f"status must be one of: {', '.join(ALLOWED_KEY_STATUSES)}"
        )
    if key_id_filter is not None:
        key_id_filter = key_id_filter.strip()
        if not key_id_filter or len(key_id_filter) > MAX_KEY_ID_LENGTH:
            raise ValueError("keyId filter must be a non-empty bounded string")

    clamped_limit = clamp_signing_key_history_limit(limit)

    filtered = [
        entry
        for entry in entries
        if (status_filter is None or entry["status"] == status_filter)
        and (key_id_filter is None or entry["keyId"] == key_id_filter)
    ]
    bounded = filtered[:clamped_limit]

    keys_map: dict[str, PublicEcP256Jwk] = {}
    validity_map: dict[str, ReceiptKeyValidityWindow] = {}
    for entry in bounded:
        kid = entry["keyId"]
        keys_map[kid] = entry["publicKeyJwk"]
        window: ReceiptKeyValidityWindow = {"notBefore": entry["notBefore"]}
        if entry["notAfter"] is not None:
            window["notAfter"] = entry["notAfter"]
        validity_map[kid] = window

    return {
        "protocol": RECEIPT_PROTOCOL,
        "version": RECEIPT_VERSION,
        "algorithm": RECEIPT_SIGNING_ALGORITHM,
        "signingOwnership": "frontend",
        "totalEntries": len(filtered),
        "entries": bounded,
        "keys": keys_map,
        "keyValidity": validity_map,
    }


def _decode_p256_coord(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a base64url-encoded 32-byte coordinate")
    trimmed = value.strip().rstrip("=")
    if not all(ch.isalnum() or ch in "-_" for ch in trimmed):
        raise ValueError(f"{field} contains invalid base64url characters")
    padded = trimmed + ("=" * ((4 - len(trimmed) % 4) % 4))
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise ValueError(f"{field} could not be decoded as base64url") from exc
    if len(raw) != 32:
        raise ValueError(f"{field} must decode to exactly 32 bytes")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _parse_utc_timestamp(value: object, field: str) -> tuple[datetime, str]:
    if isinstance(value, bool) or value is None:
        raise ValueError(f"{field} must be a UTC timestamp")
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"{field} must be non-negative")
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
        return dt, dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, str) and value.strip():
        raw = value.strip()
        iso_candidate = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
        try:
            dt = datetime.fromisoformat(iso_candidate)
        except ValueError as exc:
            raise ValueError(f"{field} must be a valid ISO-8601 timestamp") from exc
        if dt.tzinfo is None or dt.utcoffset() is None:
            raise ValueError(f"{field} must include an explicit timezone offset")
        utc_dt = dt.astimezone(timezone.utc)
        if utc_dt.microsecond == 0:
            return utc_dt, utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        millis = utc_dt.microsecond // 1000
        return utc_dt, f"{utc_dt.strftime('%Y-%m-%dT%H:%M:%S')}.{millis:03d}Z"
    raise ValueError(f"{field} must be an ISO-8601 UTC string or Unix seconds integer")


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
