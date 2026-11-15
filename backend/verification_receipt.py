"""Validation for the canonical verification-receipt input contract.

The frontend owns receipt versioning and signing. The backend only returns the
same unsigned input shape, so there is one protocol contract and no second
backend-specific receipt envelope.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
from typing import Any, Literal, Mapping, TypedDict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

RECEIPT_PROTOCOL = "harpocrates-verification-receipt"
RECEIPT_VERSION = 1
RECEIPT_ALGORITHM = "ECDSA_P256_SHA256"
MAX_RECEIPT_BYTES = 8_192
MAX_QR_PAYLOAD_BYTES = 4_096

_UNSIGNED_RECEIPT_FIELDS = frozenset(
    {
        "protocol",
        "version",
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
        "signer",
    }
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


def canonicalize_receipt_json(value: object) -> str:
    """Deterministic sorted-key JSON matching CLI/frontend receipt canonicalization."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def _base64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _base64url_decode(encoded: str) -> bytes:
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("invalid base64url data")
    for ch in encoded:
        if not (ch.isalnum() or ch in "-_"):
            raise ValueError("invalid base64url data")
    padding = "=" * ((4 - len(encoded) % 4) % 4)
    return base64.urlsafe_b64decode(encoded + padding)


def _parse_iso_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("receipt verification time is invalid")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("receipt verification time is invalid") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _assert_receipt_size(value: object, limit: int = MAX_RECEIPT_BYTES) -> None:
    if len(canonicalize_receipt_json(value).encode("utf-8")) > limit:
        raise ValueError("receipt exceeds the size limit")


def _assert_unsigned_payload(payload: Mapping[str, object]) -> None:
    if set(payload.keys()) != _UNSIGNED_RECEIPT_FIELDS:
        extra = sorted(set(payload.keys()) - _UNSIGNED_RECEIPT_FIELDS)
        if extra:
            raise ValueError(f"unsupported receipt fields: {', '.join(extra)}")
        raise ValueError("receipt metadata is incomplete")

    ver = payload.get("version")
    if payload.get("protocol") != RECEIPT_PROTOCOL or isinstance(ver, bool) or ver != RECEIPT_VERSION:
        raise ValueError("unsupported receipt version")
    if payload.get("result") not in ("verified", "unverified"):
        raise ValueError("receipt result is invalid")
    for digest_field in ("proofId", "videoHash", "metadataHash"):
        try:
            _hex32(payload.get(digest_field), digest_field)
        except ValueError as exc:
            raise ValueError("receipt digests must be 32-byte hex strings") from exc
    if payload.get("tier") not in ("silent", "source", "seal"):
        raise ValueError("receipt tier is invalid")
    for str_field in ("networkPassphrase", "contractId", "circuitVersion", "verifierVersion"):
        val = payload.get(str_field)
        if not isinstance(val, str) or not val.strip():
            raise ValueError("receipt metadata is incomplete")

    signer = payload.get("signer")
    if not isinstance(signer, Mapping) or set(signer.keys()) != {"keyId", "algorithm"}:
        raise ValueError("receipt signer is invalid")
    key_id = signer.get("keyId")
    if not isinstance(key_id, str) or not key_id.strip() or signer.get("algorithm") != RECEIPT_ALGORITHM:
        raise ValueError("receipt signer is invalid")

    ledger_seq = payload.get("ledgerSequence")
    if ledger_seq is not None and (isinstance(ledger_seq, bool) or not isinstance(ledger_seq, int) or ledger_seq < 0):
        raise ValueError("receipt ledger sequence is invalid")
    tx_hash = payload.get("transactionHash")
    if tx_hash is not None:
        try:
            _hex32(tx_hash, "transactionHash")
        except ValueError as exc:
            raise ValueError("receipt transaction hash is invalid") from exc

    _parse_iso_timestamp(payload.get("verifiedAt"))


def build_unsigned_receipt_payload(
    input_data: Mapping[str, object],
    *,
    key_id: str,
) -> dict[str, Any]:
    """Build the canonical unsigned receipt payload matching CLI/frontend signers."""
    payload: dict[str, Any] = {
        "protocol": RECEIPT_PROTOCOL,
        "version": RECEIPT_VERSION,
        "result": input_data.get("result"),
        "verifiedAt": input_data.get("verifiedAt"),
        "proofId": _hex32(input_data.get("proofId"), "proofId"),
        "videoHash": _hex32(input_data.get("videoHash"), "videoHash"),
        "metadataHash": _hex32(input_data.get("metadataHash"), "metadataHash"),
        "tier": input_data.get("tier"),
        "networkPassphrase": input_data.get("networkPassphrase"),
        "contractId": input_data.get("contractId"),
        "ledgerSequence": input_data.get("ledgerSequence"),
        "transactionHash": (
            _hex32(input_data.get("transactionHash"), "transactionHash")
            if input_data.get("transactionHash") is not None
            else None
        ),
        "circuitVersion": input_data.get("circuitVersion"),
        "verifierVersion": input_data.get("verifierVersion"),
        "signer": {"keyId": key_id, "algorithm": RECEIPT_ALGORITHM},
    }
    _assert_unsigned_payload(payload)
    return payload


def sign_verification_receipt(
    input_data: Mapping[str, object],
    *,
    key_id: str,
    private_key: ec.EllipticCurvePrivateKey,
) -> dict[str, Any]:
    """Sign a canonical receipt using ECDSA P-256 SHA-256 (IEEE P1363 raw format)."""
    payload = build_unsigned_receipt_payload(input_data, key_id=key_id)
    canonical_bytes = canonicalize_receipt_json(payload).encode("utf-8")
    der_sig = private_key.sign(canonical_bytes, ec.ECDSA(hashes.SHA256()))
    r_val, s_val = decode_dss_signature(der_sig)
    raw_sig = r_val.to_bytes(32, "big") + s_val.to_bytes(32, "big")
    signed = {**payload, "signature": _base64url_encode(raw_sig)}
    _assert_receipt_size(signed, MAX_RECEIPT_BYTES)
    return signed


def serialize_signed_receipt(receipt: Mapping[str, object]) -> str:
    """Serialize a signed receipt to canonical JSON matching CLI output."""
    _assert_receipt_size(receipt, MAX_RECEIPT_BYTES)
    return canonicalize_receipt_json(receipt)


def encode_receipt_for_qr(receipt: Mapping[str, object]) -> str:
    encoded = _base64url_encode(serialize_signed_receipt(receipt).encode("utf-8"))
    if len(encoded) > MAX_QR_PAYLOAD_BYTES:
        raise ValueError("receipt exceeds the QR payload size limit")
    return encoded


def decode_receipt_from_qr(encoded: str) -> dict[str, Any]:
    if not isinstance(encoded, str) or len(encoded) > MAX_QR_PAYLOAD_BYTES:
        raise ValueError("receipt exceeds the QR payload size limit")
    try:
        decoded_bytes = _base64url_decode(encoded)
        parsed = json.loads(decoded_bytes.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("decoded QR receipt must be a JSON object")
        _assert_receipt_size(parsed, MAX_RECEIPT_BYTES)
        return parsed
    except Exception as exc:
        raise ValueError(f"invalid receipt encoding: {exc}") from exc


def _public_key_from_jwk(jwk: Mapping[str, object]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("unsupported JWK key type or curve")
    x_raw = _base64url_decode(str(jwk["x"]))
    y_raw = _base64url_decode(str(jwk["y"]))
    if len(x_raw) != 32 or len(y_raw) != 32:
        raise ValueError("invalid P-256 JWK coordinate length")
    nums = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x_raw, "big"),
        int.from_bytes(y_raw, "big"),
        ec.SECP256R1(),
    )
    return nums.public_key()


def verify_signed_verification_receipt(
    receipt: Mapping[str, object],
    *,
    keys: Mapping[str, Mapping[str, object]],
    expected_network_passphrase: str | None = None,
    expected_proof_id: str | None = None,
    now: datetime | None = None,
    key_validity: Mapping[str, Mapping[str, str]] | None = None,
) -> dict[str, Any]:
    """Verify a signed receipt offline using the CLI/frontend wire contract."""
    try:
        if not isinstance(receipt, Mapping):
            raise ValueError("invalid receipt")
        _assert_receipt_size(receipt, MAX_RECEIPT_BYTES)
        sig_str = receipt.get("signature")
        if not isinstance(sig_str, str) or not sig_str:
            raise ValueError("missing signature")
        unsigned = {k: v for k, v in receipt.items() if k != "signature"}
        _assert_unsigned_payload(unsigned)

        if expected_network_passphrase and unsigned["networkPassphrase"] != expected_network_passphrase:
            raise ValueError("receipt network does not match the expected network")
        if expected_proof_id and str(unsigned["proofId"]).lower() != expected_proof_id.lower():
            raise ValueError("receipt proof does not match the expected proof")

        signer = unsigned["signer"]
        assert isinstance(signer, Mapping)
        key_id = str(signer["keyId"])
        eval_now = now if now is not None else datetime.now(timezone.utc)
        if eval_now.tzinfo is None:
            eval_now = eval_now.replace(tzinfo=timezone.utc)

        if key_validity and key_id in key_validity:
            win = key_validity[key_id]
            verified_at = _parse_iso_timestamp(unsigned["verifiedAt"])
            not_before = _parse_iso_timestamp(win["notBefore"]) if win.get("notBefore") else None
            not_after = _parse_iso_timestamp(win["notAfter"]) if win.get("notAfter") else None
            if (
                (not_before and verified_at < not_before)
                or (not_after and verified_at > not_after)
                or (not_after and eval_now > not_after)
            ):
                raise ValueError("receipt signer key is stale or was not valid at verification time")

        jwk = keys.get(key_id)
        if jwk is None:
            raise ValueError("signer key is unknown")
        pub_key = _public_key_from_jwk(jwk)

        raw_sig = _base64url_decode(sig_str)
        if len(raw_sig) != 64:
            return {"valid": False, "reason": "receipt signature is invalid"}
        r_val = int.from_bytes(raw_sig[:32], "big")
        s_val = int.from_bytes(raw_sig[32:], "big")
        der_sig = encode_dss_signature(r_val, s_val)
        canonical_bytes = canonicalize_receipt_json(unsigned).encode("utf-8")
        try:
            pub_key.verify(der_sig, canonical_bytes, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return {"valid": False, "reason": "receipt signature is invalid"}

        return {"valid": True, "receipt": dict(receipt)}
    except ValueError as exc:
        return {"valid": False, "reason": str(exc)}

