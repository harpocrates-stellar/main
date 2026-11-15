"""Validation and time-bound export helpers for verification receipts.

The frontend owns receipt versioning and signing. The backend only returns the
same unsigned input shape for ``build_verification_receipt``, while portable
receipt exports attach explicit half-open ``[validFromInclusive, validUntilExclusive)``
UTC bounds so APIs and offline tools interpret exact boundary instants identically.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Mapping, TypedDict

from time_attestation import normalize_timestamp_ms

TIME_BOUNDS_SEMANTICS: Literal["[inclusive, exclusive)"] = "[inclusive, exclusive)"
TimeBoundStatus = Literal["valid", "not_yet_valid", "expired"]


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


class ReceiptTimeBounds(TypedDict):
    """Explicit half-open UTC validity interval ``[validFromInclusive, validUntilExclusive)``."""

    semantics: Literal["[inclusive, exclusive)"]
    validFromInclusive: str
    validFromInclusiveUnixMs: int
    validUntilExclusive: str | None
    validUntilExclusiveUnixMs: int | None


class ReceiptTimeBoundEvaluation(TypedDict):
    """Deterministic evaluation of a fixed clock instant against receipt bounds."""

    valid: bool
    status: TimeBoundStatus
    evaluatedAt: str
    evaluatedAtUnixMs: int
    semantics: Literal["[inclusive, exclusive)"]


class VerificationReceiptExport(TypedDict):
    """Unsigned receipt export paired with explicit inclusive/exclusive time bounds."""

    receipt: VerificationReceiptInput
    timeBounds: ReceiptTimeBounds
    boundEvaluation: ReceiptTimeBoundEvaluation


def build_verification_receipt(
    context: Mapping[str, object],
    *,
    result: Literal["verified", "unverified"] = "unverified",
    now: object = None,
    numeric_unit: Literal["s", "ms"] = "s",
) -> VerificationReceiptInput:
    """Validate and build the canonical unsigned receipt input.

    A receipt is only emitted when the caller supplies the complete canonical
    evidence context. This prevents the selective-disclosure endpoint from
    inventing proof IDs or hashes from unrelated request fields.
    """
    if result not in ("verified", "unverified"):
        raise ValueError("result must be one of: verified, unverified")

    clock_source = datetime.now(timezone.utc) if now is None else now
    _, verified_at_iso = normalize_timestamp_ms(
        clock_source,
        field="verifiedAt",
        numeric_unit=numeric_unit,
    )

    return {
        "result": result,
        "verifiedAt": verified_at_iso,
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


def build_receipt_time_bounds(
    *,
    valid_from: object,
    valid_until: object = None,
    from_unit: Literal["s", "ms"] = "s",
    until_unit: Literal["s", "ms"] = "s",
    zero_means_unbounded: bool = True,
) -> ReceiptTimeBounds:
    """Construct canonical ``[validFromInclusive, validUntilExclusive)`` receipt bounds.

    Soroban ``ProofRecord.expires_at == 0`` represents a non-expiring record and
    maps to ``validUntilExclusive = None`` when ``zero_means_unbounded`` is True.
    """
    from_ms, from_iso = normalize_timestamp_ms(
        valid_from,
        field="validFromInclusive",
        numeric_unit=from_unit,
    )

    if valid_until is None or (
        zero_means_unbounded
        and isinstance(valid_until, int)
        and not isinstance(valid_until, bool)
        and valid_until == 0
    ):
        return {
            "semantics": TIME_BOUNDS_SEMANTICS,
            "validFromInclusive": from_iso,
            "validFromInclusiveUnixMs": from_ms,
            "validUntilExclusive": None,
            "validUntilExclusiveUnixMs": None,
        }

    until_ms, until_iso = normalize_timestamp_ms(
        valid_until,
        field="validUntilExclusive",
        numeric_unit=until_unit,
    )
    if until_ms <= from_ms:
        raise ValueError(
            "validUntilExclusive must be strictly greater than validFromInclusive"
        )

    return {
        "semantics": TIME_BOUNDS_SEMANTICS,
        "validFromInclusive": from_iso,
        "validFromInclusiveUnixMs": from_ms,
        "validUntilExclusive": until_iso,
        "validUntilExclusiveUnixMs": until_ms,
    }


def evaluate_receipt_time_bounds(
    bounds: Mapping[str, object],
    *,
    at: object,
    numeric_unit: Literal["s", "ms"] = "s",
) -> ReceiptTimeBoundEvaluation:
    """Evaluate ``at`` against ``[validFromInclusive, validUntilExclusive)``.

    Exact boundary rules:
    * ``at < validFromInclusive``  -> ``not_yet_valid`` (invalid)
    * ``at == validFromInclusive`` -> ``valid`` (inclusive lower bound)
    * ``at == validUntilExclusive`` -> ``expired`` (exclusive upper bound)
    * ``at > validUntilExclusive``  -> ``expired`` (invalid)
    """
    if not isinstance(bounds, Mapping):
        raise ValueError("bounds must be a mapping")
    if bounds.get("semantics") != TIME_BOUNDS_SEMANTICS:
        raise ValueError(f"bounds semantics must equal {TIME_BOUNDS_SEMANTICS!r}")

    from_ms, _ = normalize_timestamp_ms(
        bounds.get("validFromInclusive"),
        field="validFromInclusive",
        numeric_unit="ms",
    )
    declared_from_ms = bounds.get("validFromInclusiveUnixMs")
    if declared_from_ms is not None:
        if (
            isinstance(declared_from_ms, bool)
            or not isinstance(declared_from_ms, int)
            or declared_from_ms != from_ms
        ):
            raise ValueError(
                "validFromInclusiveUnixMs does not match validFromInclusive"
            )

    raw_until = bounds.get("validUntilExclusive")
    declared_until_ms = bounds.get("validUntilExclusiveUnixMs")
    until_ms: int | None
    if raw_until is None:
        if declared_until_ms is not None:
            raise ValueError(
                "validUntilExclusiveUnixMs must be null when validUntilExclusive is null"
            )
        until_ms = None
    else:
        until_ms, _ = normalize_timestamp_ms(
            raw_until,
            field="validUntilExclusive",
            numeric_unit="ms",
        )
        if declared_until_ms is not None:
            if (
                isinstance(declared_until_ms, bool)
                or not isinstance(declared_until_ms, int)
                or declared_until_ms != until_ms
            ):
                raise ValueError(
                    "validUntilExclusiveUnixMs does not match validUntilExclusive"
                )
        if until_ms <= from_ms:
            raise ValueError(
                "validUntilExclusive must be strictly greater than validFromInclusive"
            )

    at_ms, at_iso = normalize_timestamp_ms(
        at,
        field="at",
        numeric_unit=numeric_unit,
    )

    if at_ms < from_ms:
        return {
            "valid": False,
            "status": "not_yet_valid",
            "evaluatedAt": at_iso,
            "evaluatedAtUnixMs": at_ms,
            "semantics": TIME_BOUNDS_SEMANTICS,
        }

    if until_ms is not None and at_ms >= until_ms:
        return {
            "valid": False,
            "status": "expired",
            "evaluatedAt": at_iso,
            "evaluatedAtUnixMs": at_ms,
            "semantics": TIME_BOUNDS_SEMANTICS,
        }

    return {
        "valid": True,
        "status": "valid",
        "evaluatedAt": at_iso,
        "evaluatedAtUnixMs": at_ms,
        "semantics": TIME_BOUNDS_SEMANTICS,
    }


def export_verification_receipt(
    context: Mapping[str, object],
    *,
    result: Literal["verified", "unverified"] = "unverified",
    now: object = None,
    valid_from: object = None,
    valid_until: object = None,
    numeric_unit: Literal["s", "ms"] = "s",
) -> VerificationReceiptExport:
    """Export an unsigned verification receipt with explicit ``[inclusive, exclusive)`` bounds."""
    receipt = build_verification_receipt(
        context,
        result=result,
        now=now,
        numeric_unit=numeric_unit,
    )

    effective_from = (
        valid_from
        if valid_from is not None
        else context.get("validFromInclusive", context.get("observedAt", receipt["verifiedAt"]))
    )
    effective_until = (
        valid_until
        if valid_until is not None
        else context.get("validUntilExclusive", context.get("expiresAt"))
    )

    time_bounds = build_receipt_time_bounds(
        valid_from=effective_from,
        valid_until=effective_until,
        from_unit=numeric_unit,
        until_unit=numeric_unit,
    )
    evaluation = evaluate_receipt_time_bounds(
        time_bounds,
        at=receipt["verifiedAt"],
        numeric_unit=numeric_unit,
    )

    return {
        "receipt": receipt,
        "timeBounds": time_bounds,
        "boundEvaluation": evaluation,
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
