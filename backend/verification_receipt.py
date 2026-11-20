"""Validation and offline verification for the canonical verification-receipt contract.

The frontend and CLI own receipt signing. The backend returns the same unsigned
input shape and provides deterministic canonicalization and offline verification
helpers so backend and CLI share one protocol contract.
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from typing import Literal, Mapping, TypedDict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

RECEIPT_PROTOCOL = "harpocrates-verification-receipt"
RECEIPT_VERSION = 1
RECEIPT_ALGORITHM = "ECDSA_P256_SHA256"
MAX_RECEIPT_BYTES = 8_192
MAX_QR_PAYLOAD_BYTES = 4_096

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_HEX32_RE = re.compile(r"^[0-9a-fA-F]{64}$")


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


def build_verification_receipt(
    context: Mapping[str, object],
    *,
    result: Literal["verified", "unverified"] = "unverified",
    verified_at: str | None = None,
) -> VerificationReceiptInput:
    """Validate and build the canonical unsigned receipt input.

    A receipt is only emitted when the caller supplies the complete canonical
    evidence context. This prevents the selective-disclosure endpoint from
    inventing proof IDs or hashes from unrelated request fields.
    """

    timestamp = _iso_timestamp(verified_at, "verifiedAt") if verified_at is not None else datetime.now(timezone.utc).isoformat()
    return {
        "result": result,
        "verifiedAt": timestamp,
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


def canonicalize_receipt(value: object) -> str:
    """Encode a receipt or payload as deterministic canonical JSON.

    Matches the CLI/frontend recursive sorted-key JSON serialization with no
    insignificant whitespace.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def serialize_verification_receipt(receipt: Mapping[str, object]) -> str:
    """Encode a signed receipt as portable canonical JSON."""
    _assert_receipt_size(receipt, MAX_RECEIPT_BYTES)
    return canonicalize_receipt(receipt)


def encode_receipt_for_qr(receipt: Mapping[str, object]) -> str:
    """Encode a signed receipt as a compact, URL-safe base64url QR payload."""
    encoded = _base64url_encode(serialize_verification_receipt(receipt).encode("utf-8"))
    if len(encoded) > MAX_QR_PAYLOAD_BYTES:
        raise ValueError("receipt exceeds the QR payload size limit")
    return encoded


def decode_receipt_from_qr(encoded: str) -> dict[str, object]:
    """Decode a base64url QR payload back into a signed receipt mapping."""
    if not isinstance(encoded, str) or len(encoded) > MAX_QR_PAYLOAD_BYTES:
        raise ValueError("receipt exceeds the QR payload size limit")
    try:
        raw = _base64url_decode(encoded)
        receipt = json.loads(raw.decode("utf-8"))
        if not isinstance(receipt, dict):
            raise ValueError("receipt must be a JSON object")
        _assert_receipt_size(receipt, MAX_RECEIPT_BYTES)
        return receipt
    except Exception as exc:
        raise ValueError(f"invalid receipt encoding: {exc}") from exc


def verify_verification_receipt(
    receipt: Mapping[str, object],
    *,
    keys: Mapping[str, Mapping[str, object]],
    expected_network_passphrase: str | None = None,
    expected_proof_id: str | None = None,
    now: datetime | None = None,
    key_validity: Mapping[str, Mapping[str, str]] | None = None,
) -> dict[str, object]:
    """Verify a signed verification receipt offline (fail-closed).

    Returns ``{"valid": True, "receipt": dict(receipt)}`` on success, or
    ``{"valid": False, "reason": "..."}`` on any validation or signature failure.
    """
    try:
        if not isinstance(receipt, Mapping):
            raise ValueError("receipt must be a mapping")
        _assert_receipt_size(receipt, MAX_RECEIPT_BYTES)
        _assert_payload(receipt)

        signature = receipt.get("signature")
        if not isinstance(signature, str) or not signature:
            raise ValueError("missing signature")

        if expected_network_passphrase and receipt.get("networkPassphrase") != expected_network_passphrase:
            raise ValueError("receipt network does not match the expected network")
        if expected_proof_id and receipt.get("proofId") != expected_proof_id:
            raise ValueError("receipt proof does not match the expected proof")

        signer = receipt["signer"]
        assert isinstance(signer, Mapping)
        key_id = str(signer["keyId"])

        validity = key_validity.get(key_id) if key_validity else None
        _assert_key_validity(receipt, validity, now or datetime.now(timezone.utc))

        jwk = keys.get(key_id)
        if not jwk:
            raise ValueError("signer key is unknown")

        public_key = _import_p256_jwk(jwk)
        raw_sig = _base64url_decode(signature)
        if len(raw_sig) != 64:
            raise ValueError("receipt signature is invalid")

        r = int.from_bytes(raw_sig[:32], "big")
        s = int.from_bytes(raw_sig[32:], "big")
        der_sig = encode_dss_signature(r, s)

        unsigned_payload = {k: v for k, v in receipt.items() if k != "signature"}
        message = canonicalize_receipt(unsigned_payload).encode("utf-8")
        try:
            public_key.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return {"valid": False, "reason": "receipt signature is invalid"}

        return {"valid": True, "receipt": dict(receipt)}
    except Exception as exc:
        return {"valid": False, "reason": str(exc) or "invalid receipt"}


def _assert_payload(payload: Mapping[str, object]) -> None:
    if payload.get("protocol") != RECEIPT_PROTOCOL or payload.get("version") != RECEIPT_VERSION:
        raise ValueError("unsupported receipt version")
    if payload.get("result") not in ("verified", "unverified"):
        raise ValueError("receipt result is invalid")
    if not (
        _is_hex32(payload.get("proofId"))
        and _is_hex32(payload.get("videoHash"))
        and _is_hex32(payload.get("metadataHash"))
    ):
        raise ValueError("receipt digests must be 32-byte hex strings")
    if payload.get("tier") not in ("silent", "source", "seal"):
        raise ValueError("receipt tier is invalid")
    if not (
        _is_non_empty_str(payload.get("networkPassphrase"))
        and _is_non_empty_str(payload.get("contractId"))
        and _is_non_empty_str(payload.get("circuitVersion"))
        and _is_non_empty_str(payload.get("verifierVersion"))
    ):
        raise ValueError("receipt metadata is incomplete")

    signer = payload.get("signer")
    if (
        not isinstance(signer, Mapping)
        or not _is_non_empty_str(signer.get("keyId"))
        or signer.get("algorithm") != RECEIPT_ALGORITHM
    ):
        raise ValueError("receipt signer is invalid")

    ledger_seq = payload.get("ledgerSequence")
    if ledger_seq is not None and (not isinstance(ledger_seq, int) or isinstance(ledger_seq, bool)):
        raise ValueError("receipt ledger sequence is invalid")

    tx_hash = payload.get("transactionHash")
    if tx_hash is not None and not _is_hex32(tx_hash):
        raise ValueError("receipt transaction hash is invalid")

    _iso_timestamp(payload.get("verifiedAt"), "receipt verification time")


def _assert_key_validity(
    receipt: Mapping[str, object],
    validity: Mapping[str, str] | None,
    now: datetime,
) -> None:
    if not validity:
        return
    verified_at = _parse_iso_datetime(str(receipt["verifiedAt"]))
    not_before = _parse_iso_datetime(validity["notBefore"]) if validity.get("notBefore") else None
    not_after = _parse_iso_datetime(validity["notAfter"]) if validity.get("notAfter") else None
    now_utc = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    if (
        (not_before is not None and verified_at < not_before)
        or (not_after is not None and verified_at > not_after)
        or (not_after is not None and now_utc > not_after)
    ):
        raise ValueError("receipt signer key is stale or was not valid at verification time")


def _assert_receipt_size(value: object, limit: int) -> None:
    if len(canonicalize_receipt(value).encode("utf-8")) > limit:
        raise ValueError("receipt exceeds the size limit")


def _import_p256_jwk(jwk: Mapping[str, object]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("unsupported signer key type")
    x_raw = _base64url_decode(str(jwk.get("x", "")))
    y_raw = _base64url_decode(str(jwk.get("y", "")))
    if len(x_raw) != 32 or len(y_raw) != 32:
        raise ValueError("invalid P-256 public key coordinates")
    x = int.from_bytes(x_raw, "big")
    y = int.from_bytes(y_raw, "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not _BASE64URL_RE.match(value):
        raise ValueError("invalid base64url data")
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _parse_iso_datetime(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    dt = datetime.fromisoformat(normalized)
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _iso_timestamp(value: object, field: str) -> str:
    if not _is_non_empty_str(value):
        raise ValueError(f"{field} is invalid")
    try:
        _parse_iso_datetime(value)
    except ValueError as exc:
        raise ValueError(f"{field} is invalid") from exc
    return value


def _is_hex32(value: object) -> bool:
    return isinstance(value, str) and bool(_HEX32_RE.match(value))


def _is_non_empty_str(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


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
