"""Validation, signature verification, and orthogonal freshness evaluation for receipts.

The frontend owns receipt versioning and signing. When evaluating signed
``harpocrates-verification-receipt`` payloads, cryptographic signature validity
is separated from observation and verification freshness so an old signed
receipt is reported as a historical snapshot rather than current chain truth.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import math
from typing import Any, Literal, Mapping, TypedDict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from time_attestation import (
    MAX_FUTURE_DRIFT_SECONDS,
    TimeAttestation,
    decode_time_attestation,
    extract_observation_timestamp_ms,
)

RECEIPT_PROTOCOL = "harpocrates-verification-receipt"
RECEIPT_VERSION = 1
RECEIPT_ALGORITHM = "ECDSA_P256_SHA256"
MAX_RECEIPT_BYTES = 8_192
DEFAULT_RECEIPT_FRESHNESS_SECONDS = 3_600

SignatureStatus = Literal[
    "valid",
    "invalid_signature",
    "unknown_signer",
    "key_invalid_at_signing",
    "malformed_receipt",
]
FreshnessStatus = Literal[
    "fresh",
    "stale_verification",
    "stale_observation",
    "future_skew",
    "unanchored_observation",
    "unverified_signature",
]
ChainTruthStanding = Literal[
    "current_verified",
    "historical_signed_snapshot",
    "unverified_result",
    "rejected",
]


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


class ReceiptSignatureValidity(TypedDict):
    """Cryptographic validity of a signed verification receipt."""

    valid: bool
    status: SignatureStatus
    reasonCode: str
    keyId: str | None


class ReceiptFreshnessReport(TypedDict):
    """Temporal freshness separating observation time from verification run time."""

    fresh: bool
    status: FreshnessStatus
    reasonCode: str
    evidenceObservedAt: str | None
    evidenceObservedAtSource: str | None
    verifiedAt: str | None
    evaluatedAt: str
    verificationAgeSeconds: float | None
    observationAgeSeconds: float | None
    maxVerificationAgeSeconds: int
    maxObservationAgeSeconds: int | None


class SignedReceiptEvaluation(TypedDict):
    """Orthogonal receipt signature validity and freshness assessment."""

    signatureValidity: ReceiptSignatureValidity
    receiptFreshness: ReceiptFreshnessReport
    isCurrentChainTruth: bool
    chainTruthStanding: ChainTruthStanding


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


def canonicalize_receipt_object(value: Any) -> str:
    """Match ``frontend/src/verificationReceipt.ts`` canonical JSON serialization."""
    if value is None or not isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize_receipt_object(item) for item in value) + "]"
    parts = [
        f"{json.dumps(str(key), ensure_ascii=False)}:{canonicalize_receipt_object(value[key])}"
        for key in sorted(value.keys())
    ]
    return "{" + ",".join(parts) + "}"


def verify_receipt_signature_only(
    receipt: Mapping[str, object],
    *,
    keys: Mapping[str, Mapping[str, object]],
    key_validity: Mapping[str, Mapping[str, object]] | None = None,
) -> ReceiptSignatureValidity:
    """Verify ECDSA P-256 signature and historical key window at ``verifiedAt``.

    Unlike conflated checks, rotating or retiring a key *after* ``verifiedAt``
    or evaluating an older receipt does NOT invalidate its signature.
    """
    try:
        encoded_full = canonicalize_receipt_object(dict(receipt)).encode("utf-8")
        if len(encoded_full) > MAX_RECEIPT_BYTES:
            return {
                "valid": False,
                "status": "malformed_receipt",
                "reasonCode": "RECEIPT_OVERSIZED",
                "keyId": None,
            }
        _validate_signed_receipt_shape(receipt)
    except ValueError:
        return {
            "valid": False,
            "status": "malformed_receipt",
            "reasonCode": "MALFORMED_RECEIPT",
            "keyId": None,
        }

    signer = receipt["signer"]
    assert isinstance(signer, Mapping)
    key_id = str(signer["keyId"])
    verified_at_ms, _ = _parse_utc_ms(receipt["verifiedAt"], "verifiedAt")

    if key_validity and key_id in key_validity:
        window = key_validity[key_id]
        if window.get("notBefore") is not None:
            nb_ms, _ = _parse_utc_ms(window["notBefore"], "notBefore")
            if verified_at_ms < nb_ms:
                return {
                    "valid": False,
                    "status": "key_invalid_at_signing",
                    "reasonCode": "KEY_NOT_YET_VALID_AT_SIGNING",
                    "keyId": key_id,
                }
        if window.get("notAfter") is not None:
            na_ms, _ = _parse_utc_ms(window["notAfter"], "notAfter")
            if verified_at_ms > na_ms:
                return {
                    "valid": False,
                    "status": "key_invalid_at_signing",
                    "reasonCode": "KEY_EXPIRED_AT_SIGNING",
                    "keyId": key_id,
                }

    jwk = keys.get(key_id)
    if jwk is None:
        return {
            "valid": False,
            "status": "unknown_signer",
            "reasonCode": "UNKNOWN_SIGNER_KEY",
            "keyId": key_id,
        }

    try:
        pub_key = _load_ec_p256_public_key_from_jwk(jwk)
        der_sig = _decode_ecdsa_p256_signature_to_der(str(receipt["signature"]))
        unsigned_copy = {k: v for k, v in receipt.items() if k != "signature"}
        unsigned_bytes = canonicalize_receipt_object(unsigned_copy).encode("utf-8")
        pub_key.verify(der_sig, unsigned_bytes, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return {
            "valid": False,
            "status": "invalid_signature",
            "reasonCode": "SIGNATURE_MISMATCH",
            "keyId": key_id,
        }

    return {
        "valid": True,
        "status": "valid",
        "reasonCode": "SIGNATURE_VERIFIED",
        "keyId": key_id,
    }


def evaluate_signed_receipt(
    receipt: Mapping[str, object],
    *,
    keys: Mapping[str, Mapping[str, object]],
    key_validity: Mapping[str, Mapping[str, object]] | None = None,
    evidence_observed_at: object = None,
    time_attestation: Mapping[str, object] | TimeAttestation | None = None,
    now: object = None,
    max_verification_age_seconds: int = DEFAULT_RECEIPT_FRESHNESS_SECONDS,
    max_observation_age_seconds: int | None = None,
) -> SignedReceiptEvaluation:
    """Evaluate receipt signature validity orthogonally from receipt freshness.

    An authentic old receipt yields ``signatureValidity.valid == True``,
    ``receiptFreshness.fresh == False``, ``isCurrentChainTruth == False``, and
    ``chainTruthStanding == 'historical_signed_snapshot'``.
    """
    if (
        isinstance(max_verification_age_seconds, bool)
        or not isinstance(max_verification_age_seconds, int)
        or max_verification_age_seconds <= 0
    ):
        raise ValueError("max_verification_age_seconds must be a positive integer")
    if max_observation_age_seconds is not None and (
        isinstance(max_observation_age_seconds, bool)
        or not isinstance(max_observation_age_seconds, int)
        or max_observation_age_seconds <= 0
    ):
        raise ValueError("max_observation_age_seconds must be a positive integer or null")

    eval_source = datetime.now(timezone.utc) if now is None else now
    evaluated_ms, evaluated_iso = _parse_utc_ms(eval_source, "now")

    sig_validity = verify_receipt_signature_only(
        receipt,
        keys=keys,
        key_validity=key_validity,
    )

    observed_ms, observed_iso, observed_source = _resolve_evidence_observation(
        receipt=receipt,
        explicit_observed_at=evidence_observed_at,
        time_attestation=time_attestation,
    )

    if not sig_validity["valid"]:
        raw_verified_iso: str | None = None
        try:
            _, raw_verified_iso = _parse_utc_ms(receipt.get("verifiedAt"), "verifiedAt")
        except ValueError:
            raw_verified_iso = None
        return {
            "signatureValidity": sig_validity,
            "receiptFreshness": {
                "fresh": False,
                "status": "unverified_signature",
                "reasonCode": "SIGNATURE_NOT_VALID",
                "evidenceObservedAt": observed_iso,
                "evidenceObservedAtSource": observed_source,
                "verifiedAt": raw_verified_iso,
                "evaluatedAt": evaluated_iso,
                "verificationAgeSeconds": None,
                "observationAgeSeconds": None,
                "maxVerificationAgeSeconds": max_verification_age_seconds,
                "maxObservationAgeSeconds": max_observation_age_seconds,
            },
            "isCurrentChainTruth": False,
            "chainTruthStanding": "rejected",
        }

    verified_ms, verified_iso = _parse_utc_ms(receipt["verifiedAt"], "verifiedAt")
    max_skew_ms = MAX_FUTURE_DRIFT_SECONDS * 1000

    verification_age_sec = round((evaluated_ms - verified_ms) / 1000.0, 3)
    observation_age_sec = (
        round((evaluated_ms - observed_ms) / 1000.0, 3)
        if observed_ms is not None
        else None
    )

    fresh: bool
    freshness_status: FreshnessStatus
    reason_code: str

    if verified_ms > evaluated_ms + max_skew_ms or (
        observed_ms is not None and observed_ms > evaluated_ms + max_skew_ms
    ):
        fresh = False
        freshness_status = "future_skew"
        reason_code = "TIMESTAMP_EXCEEDS_FUTURE_DRIFT"
    elif observed_ms is not None and verified_ms + max_skew_ms < observed_ms:
        fresh = False
        freshness_status = "future_skew"
        reason_code = "VERIFICATION_PREDATES_OBSERVATION"
    elif evaluated_ms - verified_ms > max_verification_age_seconds * 1000:
        fresh = False
        freshness_status = "stale_verification"
        reason_code = "VERIFICATION_RESULT_STALE"
    elif max_observation_age_seconds is not None and observed_ms is None:
        fresh = False
        freshness_status = "unanchored_observation"
        reason_code = "EVIDENCE_OBSERVATION_MISSING"
    elif (
        max_observation_age_seconds is not None
        and observed_ms is not None
        and evaluated_ms - observed_ms > max_observation_age_seconds * 1000
    ):
        fresh = False
        freshness_status = "stale_observation"
        reason_code = "EVIDENCE_OBSERVATION_STALE"
    else:
        fresh = True
        freshness_status = "fresh"
        reason_code = "RECEIPT_FRESH"

    freshness_report: ReceiptFreshnessReport = {
        "fresh": fresh,
        "status": freshness_status,
        "reasonCode": reason_code,
        "evidenceObservedAt": observed_iso,
        "evidenceObservedAtSource": observed_source,
        "verifiedAt": verified_iso,
        "evaluatedAt": evaluated_iso,
        "verificationAgeSeconds": verification_age_sec,
        "observationAgeSeconds": observation_age_sec,
        "maxVerificationAgeSeconds": max_verification_age_seconds,
        "maxObservationAgeSeconds": max_observation_age_seconds,
    }

    if receipt.get("result") != "verified":
        standing: ChainTruthStanding = "unverified_result"
        is_current = False
    elif fresh:
        standing = "current_verified"
        is_current = True
    else:
        standing = "historical_signed_snapshot"
        is_current = False

    return {
        "signatureValidity": sig_validity,
        "receiptFreshness": freshness_report,
        "isCurrentChainTruth": is_current,
        "chainTruthStanding": standing,
    }


def _resolve_evidence_observation(
    *,
    receipt: Mapping[str, object],
    explicit_observed_at: object,
    time_attestation: Mapping[str, object] | TimeAttestation | None,
) -> tuple[int | None, str | None, str | None]:
    if time_attestation is not None:
        att = (
            time_attestation
            if isinstance(time_attestation, TimeAttestation)
            else decode_time_attestation(dict(time_attestation))
        )
        video_hash = receipt.get("videoHash")
        if isinstance(video_hash, str) and att.evidence_digest.lower() != video_hash.lower():
            raise ValueError(
                "timeAttestation.evidenceDigest does not match receipt.videoHash"
            )
        extracted = extract_observation_timestamp_ms(att)
        if extracted is not None:
            obs_ms, source = extracted
            return obs_ms, _format_utc_ms(obs_ms), source

    candidate = (
        explicit_observed_at
        if explicit_observed_at is not None
        else receipt.get("evidenceObservedAt")
    )
    if candidate is not None:
        obs_ms, obs_iso = _parse_utc_ms(candidate, "evidenceObservedAt")
        return obs_ms, obs_iso, "explicit"

    return None, None, None


def _validate_signed_receipt_shape(receipt: Mapping[str, object]) -> None:
    if receipt.get("protocol") != RECEIPT_PROTOCOL or receipt.get("version") != RECEIPT_VERSION:
        raise ValueError("unsupported receipt version")
    if receipt.get("result") not in ("verified", "unverified"):
        raise ValueError("receipt result is invalid")
    _hex32(receipt.get("proofId"), "proofId")
    _hex32(receipt.get("videoHash"), "videoHash")
    _hex32(receipt.get("metadataHash"), "metadataHash")
    _choice(receipt.get("tier"), "tier", ("silent", "source", "seal"))
    _text(receipt.get("networkPassphrase"), "networkPassphrase")
    _text(receipt.get("contractId"), "contractId")
    _optional_int(receipt.get("ledgerSequence"), "ledgerSequence")
    _optional_hex32(receipt.get("transactionHash"), "transactionHash")
    _text(receipt.get("circuitVersion"), "circuitVersion")
    _text(receipt.get("verifierVersion"), "verifierVersion")
    _parse_utc_ms(receipt.get("verifiedAt"), "verifiedAt")

    signer = receipt.get("signer")
    if not isinstance(signer, Mapping):
        raise ValueError("receipt signer is invalid")
    _text(signer.get("keyId"), "signer.keyId")
    if signer.get("algorithm") != RECEIPT_ALGORITHM:
        raise ValueError("receipt signer algorithm is invalid")
    _text(receipt.get("signature"), "signature")


def _load_ec_p256_public_key_from_jwk(jwk: Mapping[str, object]) -> ec.EllipticCurvePublicKey:
    if "d" in jwk or "privateKey" in jwk:
        raise ValueError("private JWK fields are not permitted")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("JWK must be EC P-256")
    x_bytes = _b64url_decode(str(jwk.get("x", "")))
    y_bytes = _b64url_decode(str(jwk.get("y", "")))
    if len(x_bytes) != 32 or len(y_bytes) != 32:
        raise ValueError("P-256 coordinates must be 32 bytes")
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x_bytes, "big"),
        int.from_bytes(y_bytes, "big"),
        ec.SECP256R1(),
    )
    return numbers.public_key()


def _decode_ecdsa_p256_signature_to_der(encoded_sig: str) -> bytes:
    raw = _b64url_decode(encoded_sig)
    if len(raw) == 64:
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:], "big")
        return encode_dss_signature(r, s)
    if len(raw) >= 8 and raw[0] == 0x30:
        return raw
    raise ValueError("invalid ECDSA P-256 signature encoding")


def _b64url_decode(value: str) -> bytes:
    trimmed = value.strip()
    if not trimmed or not all(ch.isalnum() or ch in "-_" for ch in trimmed.rstrip("=")):
        raise ValueError("invalid base64url string")
    unpadded = trimmed.rstrip("=")
    padded = unpadded + ("=" * ((4 - len(unpadded) % 4) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _format_utc_ms(unix_ms: int) -> str:
    seconds, millis = divmod(unix_ms, 1000)
    dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    if millis == 0:
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{millis:03d}Z"


def _parse_utc_ms(value: object, field: str) -> tuple[int, str]:
    if isinstance(value, bool) or value is None:
        raise ValueError(f"{field} must be a valid UTC timestamp")
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{field} must include a timezone offset")
        ms = round(value.astimezone(timezone.utc).timestamp() * 1000)
        if ms < 0:
            raise ValueError(f"{field} must be non-negative")
        return ms, _format_utc_ms(ms)
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"{field} must be non-negative")
        ms = value * 1000
        return ms, _format_utc_ms(ms)
    if isinstance(value, float):
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"{field} must be finite and non-negative")
        ms = round(value * 1000)
        return ms, _format_utc_ms(ms)
    if isinstance(value, str) and value.strip():
        raw = value.strip()
        iso_str = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
        try:
            dt = datetime.fromisoformat(iso_str)
        except ValueError as exc:
            raise ValueError(f"{field} must be a valid ISO-8601 timestamp") from exc
        if dt.tzinfo is None or dt.utcoffset() is None:
            raise ValueError(f"{field} must include an explicit timezone offset")
        ms = round(dt.astimezone(timezone.utc).timestamp() * 1000)
        if ms < 0:
            raise ValueError(f"{field} must be non-negative")
        return ms, _format_utc_ms(ms)
    raise ValueError(f"{field} must be an ISO-8601 UTC string or epoch seconds")


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
