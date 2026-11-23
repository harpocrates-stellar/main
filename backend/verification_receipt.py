"""Validation and offline verification for the canonical verification-receipt contract.

The frontend owns receipt versioning and signing. The backend only returns the
same unsigned input shape, so there is one protocol contract and no second
backend-specific receipt envelope.

Public signing-key history is served as read-only metadata: each entry carries a
key identifier, the public key, and a validity interval. Private signing keys
are never loaded or handled by the backend.
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Literal, Mapping, TypedDict

try:
    from time_attestation import (
        TimeAttestation,
        check_backdating_risk,
        decode_time_attestation,
        encode_time_attestation,
    )
except ImportError:  # pragma: no cover - package layout fallback
    from backend.time_attestation import (  # type: ignore[no-redef]
        TimeAttestation,
        check_backdating_risk,
        decode_time_attestation,
        encode_time_attestation,
    )

# Upper bound on how many key-history entries a single response may carry.
MAX_KEY_HISTORY_ENTRIES = 100


DiffCategory = Literal["evidence", "trust", "revocation", "chain", "presentation"]


class ReceiptDiffItem(TypedDict):
    """Single categorized difference between two verification runs."""

    field: str
    category: DiffCategory
    before: Any
    after: Any
    explanation: str


class ReceiptComparisonReport(TypedDict):
    """Structured comparison report for two verification runs."""

    identical: bool
    equivalentEvidence: bool
    presentationOnly: bool
    summary: str
    evidenceChanges: list[ReceiptDiffItem]
    trustChanges: list[ReceiptDiffItem]
    revocationChanges: list[ReceiptDiffItem]
    chainChanges: list[ReceiptDiffItem]
    presentationChanges: list[ReceiptDiffItem]
    explanations: list[str]

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


class SigningKeyRecord(TypedDict):
    """Public metadata for one historical receipt signing key."""

    keyId: str
    publicKey: str
    validFrom: str
    validUntil: str | None


class SigningKeyHistory(TypedDict):
    """Bounded, read-only public signing-key history response."""

    keys: list[SigningKeyRecord]
    truncated: bool


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

    Any metadata extensions present in ``context['extensions']`` are checked:
    unknown critical extensions are rejected, while optional extensions are
    preserved in the returned mapping under ``extensions``.

    Canonical parent-child statement binding is validated before the unsigned
    receipt input is returned; conflicting evidence or derivative identifiers
    are rejected fail-closed.
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
    _validate_statement_binding(receipt, context)
    extensions = _extensions(context.get("extensions"))
    if extensions:
        receipt["extensions"] = extensions  # type: ignore[typeddict-unknown-key]
    return receipt


def _validate_statement_binding(
    receipt: VerificationReceiptInput,
    context: Mapping[str, object],
) -> None:
    """Reject receipt inputs whose evidence and derivative identifiers conflict.

    The receipt's ``proofId`` is a derivative identifier: it must bind the same
    canonical evidence (``videoHash`` and ``metadataHash``) as the parent
    statement. If the caller supplies a parent statement, its evidence digests
    and proof identifier must match the receipt exactly. Any mismatch is a
    conflicting-evidence error and the receipt is not emitted.
    """

    parent = context.get("parentStatement")
    if parent is None:
        return
    if not isinstance(parent, Mapping):
        raise ValueError("parentStatement must be a mapping or null")

    parent_video = _hex32(parent.get("videoHash"), "parentStatement.videoHash")
    parent_metadata = _hex32(
        parent.get("metadataHash"), "parentStatement.metadataHash"
    )
    parent_proof = _hex32(parent.get("proofId"), "parentStatement.proofId")

    if parent_video != receipt["videoHash"]:
        raise ValueError(
            "conflicting evidence: parentStatement.videoHash does not match videoHash"
        )
    if parent_metadata != receipt["metadataHash"]:
        raise ValueError(
            "conflicting evidence: parentStatement.metadataHash does not match metadataHash"
        )
    if parent_proof != receipt["proofId"]:
        raise ValueError(
            "conflicting derivative identifier: parentStatement.proofId does not match proofId"
        )

    parent_tier = parent.get("tier")
    if parent_tier is not None:
        parent_tier_norm = _choice(
            parent_tier, "parentStatement.tier", ("silent", "source", "seal")
        )
        if parent_tier_norm != receipt["tier"]:
            raise ValueError(
                "conflicting evidence: parentStatement.tier does not match tier"
            )


def _extensions(value: object) -> dict[str, object]:
    """Validate receipt metadata extensions, failing closed on unknown critical ones."""

    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("extensions must be a mapping or null")
    preserved: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError("extension names must be non-empty strings")
        if key.startswith(CRITICAL_EXTENSION_PREFIX):
            if key not in SUPPORTED_CRITICAL_EXTENSIONS:
                raise ValueError(f"unsupported critical extension: {key}")
        preserved[key] = item
    return preserved


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


def build_signing_key_history(
    records: Iterable[Mapping[str, object]],
    *,
    limit: int = MAX_KEY_HISTORY_ENTRIES,
) -> SigningKeyHistory:
    """Build a bounded public signing-key history from public key metadata.

    Each record must provide ``keyId``, ``publicKey`` and ``validFrom``, and may
    provide ``validUntil`` (``None`` means still valid). Records with a validity
    interval whose end precedes its start are rejected. Output is sorted by
    ``validFrom`` ascending and capped at ``limit`` entries; ``truncated`` is set
    when additional entries were dropped.
    """

    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer")

    parsed: list[SigningKeyRecord] = []
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            raise ValueError(f"signing key record {index} must be a mapping")
        valid_from = _timestamp(record.get("validFrom"), "validFrom")
        valid_until_raw = record.get("validUntil")
        valid_until = (
            None if valid_until_raw is None else _timestamp(valid_until_raw, "validUntil")
        )
        if valid_until is not None and valid_until < valid_from:
            raise ValueError("validUntil must not precede validFrom")
        parsed.append(
            {
                "keyId": _text(record.get("keyId"), "keyId"),
                "publicKey": _text(record.get("publicKey"), "publicKey"),
                "validFrom": valid_from.isoformat(),
                "validUntil": None if valid_until is None else valid_until.isoformat(),
            }
        )

    parsed.sort(key=lambda entry: entry["validFrom"])
    truncated = len(parsed) > limit
    return {"keys": parsed[:limit], "truncated": truncated}


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be an ISO 8601 timestamp string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO 8601 timestamp string") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


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


_PRESENTATION_ENVELOPE_FIELDS: tuple[str, ...] = (
    "protocol",
    "version",
    "signature",
    "signedAt",
    "format",
)

_HEX_FIELDS: tuple[str, ...] = (
    "proofId",
    "videoHash",
    "metadataHash",
    "transactionHash",
)

_DERIVATIVE_IDENTIFIER_FIELDS: tuple[str, ...] = ("proofId",)


def _validate_receipt_for_comparison(
    receipt: Mapping[str, object],
    label: str,
) -> VerificationReceiptInput:
    """Fail-closed validation of canonical receipt fields prior to comparison."""

    if not isinstance(receipt, Mapping):
        raise ValueError(f"{label} receipt must be a mapping")

    try:
        return {
            "result": _choice(receipt.get("result"), "result", ("verified", "unverified")),
            "verifiedAt": _text(receipt.get("verifiedAt"), "verifiedAt"),
            "proofId": _hex32(receipt.get("proofId"), "proofId"),
            "videoHash": _hex32(receipt.get("videoHash"), "videoHash"),
            "metadataHash": _hex32(receipt.get("metadataHash"), "metadataHash"),
            "tier": _choice(receipt.get("tier"), "tier", ("silent", "source", "seal")),
            "networkPassphrase": _text(
                receipt.get("networkPassphrase"), "networkPassphrase"
            ),
            "contractId": _text(receipt.get("contractId"), "contractId"),
            "ledgerSequence": _optional_int(
                receipt.get("ledgerSequence"), "ledgerSequence"
            ),
            "transactionHash": _optional_hex32(
                receipt.get("transactionHash"), "transactionHash"
            ),
            "circuitVersion": _text(receipt.get("circuitVersion"), "circuitVersion"),
            "verifierVersion": _text(receipt.get("verifierVersion"), "verifierVersion"),
        }
    except ValueError as exc:
        raise ValueError(f"{label} receipt invalid: {exc}") from exc


def _validate_receipt_binding(
    receipt: Mapping[str, object],
    label: str,
) -> None:
    """Reject receipts whose derivative identifiers conflict with evidence."""

    parent = receipt.get("parentStatement")
    if parent is None:
        return
    if not isinstance(parent, Mapping):
        raise ValueError(
            f"{label} receipt invalid: parentStatement must be a mapping or null"
        )
    try:
        _validate_statement_binding(
            _validate_receipt_for_comparison(receipt, label),
            {"parentStatement": parent},
        )
    except ValueError as exc:
        raise ValueError(f"{label} receipt invalid: {exc}") from exc


def _optional_mapping(
    receipt: Mapping[str, object],
    field: str,
    label: str,
) -> Mapping[str, object] | None:
    value = receipt.get(field)
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} receipt invalid: {field} must be a mapping or null")
    return value


def _optional_time_attestation(
    receipt: Mapping[str, object],
    label: str,
) -> TimeAttestation | None:
    value = receipt.get("timeAttestation")
    if value is None:
        return None
    if isinstance(value, TimeAttestation):
        # Validate canonical encoding bounds fail-closed
        encode_time_attestation(value)
        return value
    if isinstance(value, Mapping):
        try:
            return decode_time_attestation(dict(value))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(
                f"{label} receipt invalid: timeAttestation malformed: {exc}"
            ) from exc
    raise ValueError(
        f"{label} receipt invalid: timeAttestation must be a TimeAttestation, mapping, or null"
    )


def _record_diff(
    buckets: dict[DiffCategory, list[ReceiptDiffItem]],
    *,
    field: str,
    category: DiffCategory,
    before: Any,
    after: Any,
    explanation: str,
) -> None:
    buckets[category].append(
        {
            "field": field,
            "category": category,
            "before": before,
            "after": after,
            "explanation": explanation,
        }
    )


def _compare_optional_section(
    buckets: dict[DiffCategory, list[ReceiptDiffItem]],
    *,
    section: str,
    category: DiffCategory,
    before: Mapping[str, object] | None,
    after: Mapping[str, object] | None,
) -> None:
    if before is None and after is None:
        return
    before_map = dict(before) if before is not None else {}
    after_map = dict(after) if after is not None else {}
    for key in sorted(set(before_map.keys()) | set(after_map.keys())):
        b_val = before_map.get(key)
        a_val = after_map.get(key)
        if b_val != a_val:
            _record_diff(
                buckets,
                field=f"{section}.{key}",
                category=category,
                before=b_val,
                after=a_val,
                explanation=(
                    f"{category.capitalize()} observation '{section}.{key}' "
                    f"changed from {b_val!r} to {a_val!r}."
                ),
            )


def _compare_time_attestations(
    buckets: dict[DiffCategory, list[ReceiptDiffItem]],
    before: TimeAttestation | None,
    after: TimeAttestation | None,
) -> None:
    if before is None and after is None:
        return

    if before is None or after is None:
        state = "added" if before is None else "removed"
        _record_diff(
            buckets,
            field="timeAttestation",
            category="trust",
            before=encode_time_attestation(before) if before else None,
            after=encode_time_attestation(after) if after else None,
            explanation=f"Time attestation was {state} between verification runs.",
        )
        return

    if before.evidence_digest != after.evidence_digest:
        _record_diff(
            buckets,
            field="timeAttestation.evidenceDigest",
            category="evidence",
            before=before.evidence_digest,
            after=after.evidence_digest,
            explanation=(
                "Time attestation evidence digest changed, indicating the "
                "attestations bind different evidence payloads."
            ),
        )

    before_stellar = [
        (a.network_passphrase, a.ledger_sequence, a.ledger_timestamp, a.transaction_hash)
        for a in before.stellar_anchors
    ]
    after_stellar = [
        (a.network_passphrase, a.ledger_sequence, a.ledger_timestamp, a.transaction_hash)
        for a in after.stellar_anchors
    ]
    if before_stellar != after_stellar:
        _record_diff(
            buckets,
            field="timeAttestation.stellarAnchors",
            category="chain",
            before=len(before.stellar_anchors),
            after=len(after.stellar_anchors),
            explanation=(
                "Stellar ledger time anchors changed "
                f"({len(before.stellar_anchors)} -> {len(after.stellar_anchors)})."
            ),
        )

    before_tsa = [
        (a.tsa_url, a.gen_time, a.verification_status, a.cert_fingerprint)
        for a in before.rfc3161_anchors
    ]
    after_tsa = [
        (a.tsa_url, a.gen_time, a.verification_status, a.cert_fingerprint)
        for a in after.rfc3161_anchors
    ]
    if before_tsa != after_tsa:
        _record_diff(
            buckets,
            field="timeAttestation.rfc3161Anchors",
            category="trust",
            before=[a.verification_status for a in before.rfc3161_anchors],
            after=[a.verification_status for a in after.rfc3161_anchors],
            explanation=(
                "RFC 3161 TSA time anchor trust or verification status changed."
            ),
        )

    before_risk = check_backdating_risk(before)["risk_level"]
    after_risk = check_backdating_risk(after)["risk_level"]
    if before_risk != after_risk:
        _record_diff(
            buckets,
            field="timeAttestation.backdatingRisk",
            category="trust",
            before=before_risk,
            after=after_risk,
            explanation=(
                f"Time attestation backdating risk changed from '{before_risk}' "
                f"to '{after_risk}'."
            ),
        )


def compare_verification_receipts(
    baseline: Mapping[str, object],
    candidate: Mapping[str, object],
) -> ReceiptComparisonReport:
    """Compare two verification runs and categorize every difference.

    Distinguishes evidence changes, trust/revocation/chain observations, and
    presentation-only differences while validating canonical fields fail-closed.
    """

    base_norm = _validate_receipt_for_comparison(baseline, "baseline")
    cand_norm = _validate_receipt_for_comparison(candidate, "candidate")
    _validate_receipt_binding(baseline, "baseline")
    _validate_receipt_binding(candidate, "candidate")

    base_trust = _optional_mapping(baseline, "trust", "baseline")
    cand_trust = _optional_mapping(candidate, "trust", "candidate")
    base_rev = _optional_mapping(baseline, "revocation", "baseline")
    cand_rev = _optional_mapping(candidate, "revocation", "candidate")
    base_ta = _optional_time_attestation(baseline, "baseline")
    cand_ta = _optional_time_attestation(candidate, "candidate")

    buckets: dict[DiffCategory, list[ReceiptDiffItem]] = {
        "evidence": [],
        "trust": [],
        "revocation": [],
        "chain": [],
        "presentation": [],
    }

    # 1. Evidence fields (canonicalized)
    evidence_explanations = {
        "videoHash": "Evidence media digest (videoHash) changed between runs.",
        "metadataHash": "Evidence metadata digest (metadataHash) changed between runs.",
        "proofId": "Proof identifier (proofId) changed between runs.",
        "tier": (
            f"Identity tier changed from '{base_norm['tier']}' to '{cand_norm['tier']}'."
        ),
        "circuitVersion": (
            f"ZK circuit version changed from '{base_norm['circuitVersion']}' "
            f"to '{cand_norm['circuitVersion']}'."
        ),
    }
    for field, explanation in evidence_explanations.items():
        if base_norm[field] != cand_norm[field]:  # type: ignore[literal-required]
            _record_diff(
                buckets,
                field=field,
                category="evidence",
                before=base_norm[field],  # type: ignore[literal-required]
                after=cand_norm[field],  # type: ignore[literal-required]
                explanation=explanation,
            )

    # 2. Trust outcome & optional trust observations
    if base_norm["result"] != cand_norm["result"]:
        _record_diff(
            buckets,
            field="result",
            category="trust",
            before=base_norm["result"],
            after=cand_norm["result"],
            explanation=(
                f"Verification outcome changed from '{base_norm['result']}' "
                f"to '{cand_norm['result']}'."
            ),
        )
    _compare_optional_section(
        buckets,
        section="trust",
        category="trust",
        before=base_trust,
        after=cand_trust,
    )

    # 3. Revocation observations
    _compare_optional_section(
        buckets,
        section="revocation",
        category="revocation",
        before=base_rev,
        after=cand_rev,
    )

    # 4. Chain observations
    chain_explanations = {
        "networkPassphrase": (
            f"Stellar network changed from '{base_norm['networkPassphrase']}' "
            f"to '{cand_norm['networkPassphrase']}'."
        ),
        "contractId": (
            f"Verifier contract changed from '{base_norm['contractId']}' "
            f"to '{cand_norm['contractId']}'."
        ),
        "ledgerSequence": (
            f"Observed ledger sequence changed from {base_norm['ledgerSequence']!r} "
            f"to {cand_norm['ledgerSequence']!r}."
        ),
        "transactionHash": (
            "Observed anchor transaction hash changed between runs."
        ),
    }
    for field, explanation in chain_explanations.items():
        if base_norm[field] != cand_norm[field]:  # type: ignore[literal-required]
            _record_diff(
                buckets,
                field=field,
                category="chain",
                before=base_norm[field],  # type: ignore[literal-required]
                after=cand_norm[field],  # type: ignore[literal-required]
                explanation=explanation,
            )

    # 5. Time attestation observations (evidence, chain, and trust)
    _compare_time_attestations(buckets, base_ta, cand_ta)

    # 6. Presentation-only differences
    if base_norm["verifiedAt"] != cand_norm["verifiedAt"]:
        _record_diff(
            buckets,
            field="verifiedAt",
            category="presentation",
            before=base_norm["verifiedAt"],
            after=cand_norm["verifiedAt"],
            explanation=(
                "Verification timestamp (verifiedAt) changed; evidence and "
                "verification observations are unaffected."
            ),
        )
    if base_norm["verifierVersion"] != cand_norm["verifierVersion"]:
        _record_diff(
            buckets,
            field="verifierVersion",
            category="presentation",
            before=base_norm["verifierVersion"],
            after=cand_norm["verifierVersion"],
            explanation=(
                f"Verifier software version changed from '{base_norm['verifierVersion']}' "
                f"to '{cand_norm['verifierVersion']}'."
            ),
        )

    # Detect non-canonical hex casing differences when canonical values match
    for field in _HEX_FIELDS:
        raw_base = baseline.get(field)
        raw_cand = candidate.get(field)
        if (
            base_norm[field] == cand_norm[field]  # type: ignore[literal-required]
            and raw_base != raw_cand
        ):
            _record_diff(
                buckets,
                field=f"{field}.casing",
                category="presentation",
                before=raw_base,
                after=raw_cand,
                explanation=(
                    f"Hex casing for '{field}' differed, but canonical lowercase "
                    "digests are identical."
                ),
            )

    # Optional presentation/envelope metadata fields
    for field in _PRESENTATION_ENVELOPE_FIELDS:
        if field in baseline or field in candidate:
            raw_base = baseline.get(field)
            raw_cand = candidate.get(field)
            if raw_base != raw_cand:
                _record_diff(
                    buckets,
                    field=field,
                    category="presentation",
                    before=raw_base,
                    after=raw_cand,
                    explanation=(
                        f"Presentation/envelope field '{field}' changed without "
                        "altering evidence or verification observations."
                    ),
                )

    substantive_categories = [
        cat
        for cat in ("evidence", "trust", "revocation", "chain")
        if buckets[cat]
    ]
    has_presentation = bool(buckets["presentation"])
    identical = not substantive_categories and not has_presentation
    equivalent_evidence = not buckets["evidence"]
    presentation_only = not substantive_categories and has_presentation

    if identical:
        summary = "Receipts are identical."
    elif presentation_only:
        fields = ", ".join(item["field"] for item in buckets["presentation"])
        summary = f"Only presentation differences detected ({fields})."
    else:
        cats = ", ".join(substantive_categories)
        summary = f"Substantive differences detected in: {cats}."

    explanations = [
        item["explanation"]
        for cat in ("evidence", "trust", "revocation", "chain", "presentation")
        for item in buckets[cat]
    ]

    return {
        "identical": identical,
        "equivalentEvidence": equivalent_evidence,
        "presentationOnly": presentation_only,
        "summary": summary,
        "evidenceChanges": buckets["evidence"],
        "trustChanges": buckets["trust"],
        "revocationChanges": buckets["revocation"],
        "chainChanges": buckets["chain"],
        "presentationChanges": buckets["presentation"],
        "explanations": explanations,
    }


TrustDependency = Literal["stellar_anchor", "rfc3161_anchor", "backdating_risk"]
TrustOutcome = Literal["trusted", "invalid_signature", "unavailable", "not_present"]


class TimestampChainDependency(TypedDict):
    """One time-attestation dependency and its bounded trust result."""

    dependency: TrustDependency
    source: str
    outcome: TrustOutcome
    explanation: str


class TimestampChainReport(TypedDict):
    """Offline timestamp-chain validation report for one receipt."""

    valid: bool
    dependencies: list[TimestampChainDependency]
    invalidSignatures: list[str]
    unavailableTrust: list[str]
    summary: str


def build_timestamp_chain_report(
    receipt: Mapping[str, object],
) -> TimestampChainReport:
    """Enumerate time-attestation dependencies with bounded, offline trust results.

    Invalid signatures (a TSA or anchor that reports a failed verification) are
    reported separately from unavailable trust material (a missing, unreachable
    or unknown verification status). Nothing is fetched over the network.
    """

    ta = _optional_time_attestation(receipt, "candidate")
    dependencies: list[TimestampChainDependency] = []
    invalid: list[str] = []
    unavailable: list[str] = []

    if ta is None:
        summary = "No time attestation present; no timestamp chain to validate."
        return {
            "valid": True,
            "dependencies": [],
            "invalidSignatures": [],
            "unavailableTrust": [],
            "summary": summary,
        }

    for anchor in ta.stellar_anchors:
        source = f"stellar:{anchor.network_passphrase}@{anchor.ledger_sequence}"
        dependencies.append(
            {
                "dependency": "stellar_anchor",
                "source": source,
                "outcome": "trusted",
                "explanation": "Stellar ledger anchor is present for offline cross-check.",
            }
        )

    for anchor in ta.rfc3161_anchors:
        status = anchor.verification_status
        source = f"rfc3161:{anchor.tsa_url}"
        if status == "verified":
            outcome: TrustOutcome = "trusted"
            explanation = "RFC 3161 token signature verified against held trust material."
        elif status in ("invalid", "failed", "bad_signature"):
            outcome = "invalid_signature"
            explanation = f"RFC 3161 token signature is invalid ({status})."
            invalid.append(source)
        else:
            outcome = "unavailable"
            explanation = (
                f"RFC 3161 trust material unavailable or unknown ({status!r})."
            )
            unavailable.append(source)
        dependencies.append(
            {
                "dependency": "rfc3161_anchor",
                "source": source,
                "outcome": outcome,
                "explanation": explanation,
            }
        )

    risk = check_backdating_risk(ta)["risk_level"]
    dependencies.append(
        {
            "dependency": "backdating_risk",
            "source": "time_attestation",
            "outcome": "trusted" if risk == "low" else "unavailable",
            "explanation": f"Backdating risk assessed as '{risk}' from local anchors.",
        }
    )
    if risk != "low":
        unavailable.append("time_attestation:backdating_risk")

    valid = not invalid and not unavailable
    if invalid:
        summary = f"Invalid signatures detected in {len(invalid)} anchor(s)."
    elif unavailable:
        summary = f"Trust material unavailable for {len(unavailable)} dependency(ies)."
    else:
        summary = "All time-attestation dependencies validated offline."

    return {
        "valid": valid,
        "dependencies": dependencies,
        "invalidSignatures": invalid,
        "unavailableTrust": unavailable,
        "summary": summary,
    }


def format_receipt_comparison_report(report: ReceiptComparisonReport) -> str:
    """Render a deterministic human-readable receipt comparison report."""

    lines = [
        "Verification Receipt Comparison Report",
        f"Summary: {report['summary']}",
        f"Equivalent evidence: {'yes' if report['equivalentEvidence'] else 'no'}",
        f"Presentation only: {'yes' if report['presentationOnly'] else 'no'}",
    ]
    sections: tuple[tuple[str, list[ReceiptDiffItem]], ...] = (
        ("Evidence Changes", report["evidenceChanges"]),
        ("Trust Observations", report["trustChanges"]),
        ("Revocation Observations", report["revocationChanges"]),
        ("Chain Observations", report["chainChanges"]),
        ("Presentation Differences", report["presentationChanges"]),
    )
    for title, items in sections:
        if not items:
            continue
        lines.append(f"\n{title}:")
        for item in items:
            lines.append(f"  - [{item['field']}] {item['explanation']}")
    return "\n".join(lines)