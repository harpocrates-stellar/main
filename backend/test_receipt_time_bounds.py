from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import app as app_module
from time_attestation import (
    MAX_FUTURE_DRIFT_SECONDS,
    create_time_attestation,
    format_utc_iso8601_ms,
    normalize_timestamp_ms,
    validate_time_attestation,
)
from verification_receipt import (
    TIME_BOUNDS_SEMANTICS,
    build_receipt_time_bounds,
    build_verification_receipt,
    evaluate_receipt_time_bounds,
    export_verification_receipt,
)


def _base_context() -> dict[str, object]:
    return {
        "proofId": "11" * 32,
        "videoHash": "22" * 32,
        "metadataHash": "33" * 32,
        "tier": "source",
        "networkPassphrase": "Test SDF Network ; September 2015",
        "contractId": "C" + "A" * 55,
        "ledgerSequence": 108,
        "transactionHash": "44" * 32,
        "circuitVersion": "1",
        "verifierVersion": "2026.11",
    }


def test_normalize_timestamp_ms_unifies_iso_offsets_and_numeric_epochs():
    fixed_sec = 1_800_000_000
    fixed_ms = fixed_sec * 1000
    tz_plus2 = timezone(timedelta(hours=2))
    dt_plus2 = datetime.fromtimestamp(fixed_sec, tz=timezone.utc).astimezone(tz_plus2)

    from_sec = normalize_timestamp_ms(fixed_sec, numeric_unit="s")
    from_ms = normalize_timestamp_ms(fixed_ms, numeric_unit="ms")
    from_z = normalize_timestamp_ms("2027-01-15T08:00:00Z")
    from_offset = normalize_timestamp_ms(dt_plus2.isoformat())
    from_dt = normalize_timestamp_ms(dt_plus2)

    assert from_sec == (fixed_ms, "2027-01-15T08:00:00Z")
    assert from_ms == from_sec
    assert from_z == from_sec
    assert from_offset == from_sec
    assert from_dt == from_sec
    assert format_utc_iso8601_ms(fixed_ms + 45) == "2027-01-15T08:00:00.045Z"


@pytest.mark.parametrize(
    "bad_value",
    [
        None,
        True,
        False,
        -1,
        -0.5,
        float("nan"),
        float("inf"),
        "",
        "2027-01-15T08:00:00",  # missing timezone offset
        datetime(2027, 1, 15, 8, 0, 0),  # naive datetime
        {"unix": 123},
    ],
)
def test_normalize_timestamp_ms_rejects_ambiguous_or_invalid_inputs(bad_value: object):
    with pytest.raises(ValueError):
        normalize_timestamp_ms(bad_value, field="testTimestamp")


def test_exact_inclusive_lower_and_exclusive_upper_boundaries_with_fixed_clock():
    start_sec = 1_800_000_000
    end_sec = 1_800_003_600
    bounds = build_receipt_time_bounds(
        valid_from=start_sec,
        valid_until=end_sec,
        from_unit="s",
        until_unit="s",
    )

    assert bounds == {
        "semantics": TIME_BOUNDS_SEMANTICS,
        "validFromInclusive": "2027-01-15T08:00:00Z",
        "validFromInclusiveUnixMs": start_sec * 1000,
        "validUntilExclusive": "2027-01-15T09:00:00Z",
        "validUntilExclusiveUnixMs": end_sec * 1000,
    }

    # 1 ms before start -> not_yet_valid
    before_start = evaluate_receipt_time_bounds(
        bounds,
        at=(start_sec * 1000) - 1,
        numeric_unit="ms",
    )
    assert before_start["valid"] is False
    assert before_start["status"] == "not_yet_valid"

    # Exact lower bound t == validFromInclusive -> valid (inclusive)
    at_start = evaluate_receipt_time_bounds(
        bounds,
        at=start_sec * 1000,
        numeric_unit="ms",
    )
    assert at_start["valid"] is True
    assert at_start["status"] == "valid"

    # 1 ms before end -> valid
    just_before_end = evaluate_receipt_time_bounds(
        bounds,
        at=(end_sec * 1000) - 1,
        numeric_unit="ms",
    )
    assert just_before_end["valid"] is True
    assert just_before_end["status"] == "valid"

    # Exact upper bound t == validUntilExclusive -> expired (exclusive)
    at_end = evaluate_receipt_time_bounds(
        bounds,
        at=end_sec * 1000,
        numeric_unit="ms",
    )
    assert at_end["valid"] is False
    assert at_end["status"] == "expired"


def test_soroban_zero_expiry_maps_to_unbounded_and_inverted_bounds_fail_closed():
    unbounded = build_receipt_time_bounds(valid_from=1_800_000_000, valid_until=0)
    assert unbounded["validUntilExclusive"] is None
    assert unbounded["validUntilExclusiveUnixMs"] is None
    far_future = evaluate_receipt_time_bounds(unbounded, at=2_500_000_000)
    assert far_future["valid"] is True

    with pytest.raises(ValueError, match="strictly greater"):
        build_receipt_time_bounds(valid_from=1_800_000_000, valid_until=1_800_000_000)

    with pytest.raises(ValueError, match="validFromInclusiveUnixMs"):
        evaluate_receipt_time_bounds(
            {**unbounded, "validFromInclusiveUnixMs": 999},
            at=1_800_000_000,
        )


def test_export_verification_receipt_and_fixed_clock_time_attestation_boundaries():
    ctx = {
        **_base_context(),
        "validFromInclusive": "2027-01-15T08:00:00Z",
        "validUntilExclusive": "2027-01-15T09:00:00Z",
    }
    exported_valid = export_verification_receipt(
        ctx,
        result="verified",
        now="2027-01-15T08:00:00Z",
    )
    assert exported_valid["receipt"]["verifiedAt"] == "2027-01-15T08:00:00Z"
    assert exported_valid["boundEvaluation"]["valid"] is True
    assert exported_valid["boundEvaluation"]["status"] == "valid"

    exported_at_expiry = export_verification_receipt(
        ctx,
        result="verified",
        now="2027-01-15T09:00:00Z",
    )
    assert exported_at_expiry["boundEvaluation"]["valid"] is False
    assert exported_at_expiry["boundEvaluation"]["status"] == "expired"

    # Legacy build_verification_receipt stays untouched in shape
    unsigned = build_verification_receipt(_base_context(), now=1_800_000_000)
    assert unsigned["verifiedAt"] == "2027-01-15T08:00:00Z"
    assert "timeBounds" not in unsigned

    # Fixed-clock time_attestation boundary check
    fixed_now_ms = 1_800_000_000_000
    max_skew_ms = MAX_FUTURE_DRIFT_SECONDS * 1000
    att_exact = create_time_attestation(
        "22" * 32,
        claimed_time_ms=fixed_now_ms + max_skew_ms,
        now_ms=fixed_now_ms,
    )
    assert validate_time_attestation(att_exact, "22" * 32, now_ms=fixed_now_ms) == []

    att_over = create_time_attestation(
        "22" * 32,
        claimed_time_ms=fixed_now_ms + max_skew_ms + 1,
        now_ms=fixed_now_ms,
    )
    errs = validate_time_attestation(att_over, "22" * 32, now_ms=fixed_now_ms)
    assert any("too far in the future" in err for err in errs)


def test_selective_disclosure_endpoint_emits_explicit_receipt_time_bounds():
    client = app_module.create_app().test_client()
    payload = {
        "proof": "ab" * 64,
        "publicInputs": "01" * 352,
        "schemaHash": "cd" * 32,
        "receiptContext": {
            **_base_context(),
            "validFromInclusive": "2027-01-15T08:00:00Z",
            "validUntilExclusive": "2027-01-15T09:00:00Z",
            "now": "2027-01-15T09:00:00Z",
        },
    }
    resp = client.post("/api/verify/selective-disclosure", json=payload)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["receiptTimeBounds"]["semantics"] == "[inclusive, exclusive)"
    assert body["receiptBoundEvaluation"]["status"] == "expired"
    assert body["receiptBoundEvaluation"]["valid"] is False

    # Legacy receiptContext without time bounds keeps exact backward-compatible response keys
    legacy_resp = client.post(
        "/api/verify/selective-disclosure",
        json={
            "proof": "ab" * 64,
            "publicInputs": "01" * 352,
            "schemaHash": "cd" * 32,
            "receiptContext": _base_context(),
        },
    )
    assert legacy_resp.status_code == 200
    legacy_body = legacy_resp.get_json()
    assert "verificationReceipt" in legacy_body
    assert "receiptTimeBounds" not in legacy_body
