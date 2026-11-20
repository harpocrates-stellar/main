import pytest

from verification_receipt import build_verification_receipt


def context() -> dict[str, object]:
    return {
        "proofId": "a" * 64,
        "videoHash": "b" * 64,
        "metadataHash": "c" * 64,
        "tier": "source",
        "networkPassphrase": "Test SDF Network ; September 2015",
        "contractId": "C" + "d" * 55,
        "ledgerSequence": 42,
        "transactionHash": "e" * 64,
        "circuitVersion": "1",
        "verifierVersion": "2026.09",
    }


def test_receipt_matches_the_frontend_unsigned_model():
    receipt = build_verification_receipt(context())

    assert receipt["result"] == "unverified"
    assert receipt["proofId"] == "a" * 64
    assert receipt["videoHash"] == "b" * 64
    assert receipt["metadataHash"] == "c" * 64
    assert receipt["ledgerSequence"] == 42
    assert "protocol" not in receipt
    assert "signature" not in receipt
    assert "proof" not in receipt


@pytest.mark.parametrize(
    ("field", "value"),
    [("proofId", "short"), ("transactionHash", "not-hex")],
)
def test_rejects_invalid_digest_fields(field: str, value: str):
    invalid = context()
    invalid[field] = value

    with pytest.raises(ValueError, match=field):
        build_verification_receipt(invalid)


def test_rejects_incomplete_context_without_inventing_receipt_fields():
    with pytest.raises(ValueError, match="videoHash"):
        build_verification_receipt({"proofId": "a" * 64})


def test_receipt_includes_index_freshness_and_coverage():
    receipt = build_verification_receipt(context())

    assert receipt["indexFreshness"]["lastTrustedLedger"] == 42
    assert receipt["indexFreshness"]["knownGaps"] == []


def test_stale_index_does_not_imply_invalid_proof():
    stale = context()
    stale["indexLastTrustedLedger"] = 10
    stale["ledgerSequence"] = 42
    receipt = build_verification_receipt(stale)

    assert receipt["result"] == "unverified"
    assert receipt["indexFreshness"]["stale"] is True
    assert receipt["indexFreshness"]["lastTrustedLedger"] == 10


def test_known_gaps_are_reported_in_coverage():
    gapped = context()
    gapped["indexKnownGaps"] = [[11, 20]]
    receipt = build_verification_receipt(gapped)

    assert receipt["indexFreshness"]["knownGaps"] == [[11, 20]]
