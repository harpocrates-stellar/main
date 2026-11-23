import copy
import pytest

from time_attestation import (
    RFC3161Anchor,
    StellarAnchor,
    TimeAttestation,
    PROFILE_ID,
    create_time_attestation,
    encode_time_attestation,
    add_stellar_anchor,
)
from verification_receipt import (
    build_verification_receipt,
    compare_verification_receipts,
    format_receipt_comparison_report,
    validate_receipt_input,
)


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


def _receipt(**overrides: object) -> dict[str, object]:
    base = dict(build_verification_receipt(context(), result="verified"))
    base["verifiedAt"] = "2026-10-01T12:00:00+00:00"
    base.update(overrides)
    return base



def test_compare_identical_receipts():
    run_a = _receipt()
    run_b = _receipt()

    report = compare_verification_receipts(run_a, run_b)

    assert report["identical"] is True
    assert report["equivalentEvidence"] is True
    assert report["presentationOnly"] is False
    assert report["summary"] == "Receipts are identical."
    assert report["evidenceChanges"] == []
    assert report["trustChanges"] == []
    assert report["revocationChanges"] == []
    assert report["chainChanges"] == []
    assert report["presentationChanges"] == []
    assert report["explanations"] == []



def test_compare_distinguishes_presentation_only_differences():
    run_a = _receipt(
        verifiedAt="2026-10-01T12:00:00+00:00",
        verifierVersion="2026.09",
        videoHash="b" * 64,
        signature="sig-aaa",
    )
    run_b = _receipt(
        verifiedAt="2026-10-02T15:30:00+00:00",
        verifierVersion="2026.10",
        videoHash="B" * 64,
        signature="sig-bbb",
    )

    report = compare_verification_receipts(run_a, run_b)

    assert report["identical"] is False
    assert report["equivalentEvidence"] is True
    assert report["presentationOnly"] is True
    assert report["evidenceChanges"] == []
    assert report["trustChanges"] == []
    assert report["revocationChanges"] == []
    assert report["chainChanges"] == []

    fields = [item["field"] for item in report["presentationChanges"]]
    assert fields == ["verifiedAt", "verifierVersion", "videoHash.casing", "signature"]
    assert "Only presentation differences detected" in report["summary"]



def test_compare_detects_evidence_changes_and_tier_separation():
    run_a = _receipt(tier="silent", videoHash="1" * 64, metadataHash="2" * 64)
    run_b = _receipt(tier="seal", videoHash="3" * 64, metadataHash="2" * 64)

    report = compare_verification_receipts(run_a, run_b)

    assert report["identical"] is False
    assert report["equivalentEvidence"] is False
    assert report["presentationOnly"] is False
    fields = [item["field"] for item in report["evidenceChanges"]]
    assert fields == ["videoHash", "tier"]
    assert any("Identity tier changed from 'silent' to 'seal'" in e for e in report["explanations"])



def test_compare_explains_trust_revocation_and_chain_observations():
    run_a = _receipt(
        result="verified",
        ledgerSequence=42,
        transactionHash="e" * 64,
        trust={"status": "trusted", "issuerId": "issuer-1"},
        revocation={"status": "active", "revocationRoot": "1" * 64},
    )
    run_b = _receipt(
        result="unverified",
        ledgerSequence=99,
        transactionHash="f" * 64,
        trust={"status": "untrusted", "issuerId": "issuer-1"},
        revocation={"status": "revoked", "revocationRoot": "9" * 64},
    )

    report = compare_verification_receipts(run_a, run_b)

    assert report["equivalentEvidence"] is True
    assert report["presentationOnly"] is False
    assert [i["field"] for i in report["trustChanges"]] == ["result", "trust.status"]
    assert [i["field"] for i in report["revocationChanges"]] == [
        "revocation.revocationRoot",
        "revocation.status",
    ]
    assert [i["field"] for i in report["chainChanges"]] == [
        "ledgerSequence",
        "transactionHash",
    ]
    assert "trust, revocation, chain" in report["summary"]

    rendered = format_receipt_comparison_report(report)
    assert "Verification Receipt Comparison Report" in rendered
    assert "Trust Observations:" in rendered
    assert "Revocation Observations:" in rendered
    assert "Chain Observations:" in rendered



def test_compare_explains_time_attestation_chain_and_trust_changes():
    digest = "a" * 64
    ta_before = create_time_attestation(evidence_digest=digest)
    ta_after = TimeAttestation(
        version=1,
        protocol=PROFILE_ID,
        evidence_digest=digest,
        observed_time=ta_before.observed_time,
        stellar_anchors=[
            StellarAnchor(
                ledger_sequence=100,
                ledger_timestamp=1700000000,
                transaction_hash="d" * 64,
                network_passphrase="Test SDF Network ; September 2015",
            )
        ],
        rfc3161_anchors=[
            RFC3161Anchor(
                token_bytes="dGVzdA==",
                tsa_url="https://tsa.example.org",
                gen_time=1700000000000,
                verification_status="valid",
            )
        ],
    )

    run_a = _receipt(timeAttestation=encode_time_attestation(ta_before))
    run_b = _receipt(timeAttestation=ta_after)

    report = compare_verification_receipts(run_a, run_b)

    assert report["equivalentEvidence"] is True
    assert [i["field"] for i in report["chainChanges"]] == ["timeAttestation.stellarAnchors"]
    assert [i["field"] for i in report["trustChanges"]] == [
        "timeAttestation.rfc3161Anchors",
        "timeAttestation.backdatingRisk",
    ]



def test_compare_fails_closed_on_invalid_receipt_or_observations():
    valid = _receipt()
    bad_hex = _receipt(proofId="not-a-hex-digest")

    with pytest.raises(ValueError, match="candidate receipt invalid: proofId"):
        compare_verification_receipts(valid, bad_hex)

    with pytest.raises(ValueError, match="baseline receipt must be a mapping"):
        compare_verification_receipts("not-a-dict", valid)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="revocation must be a mapping"):
        compare_verification_receipts(valid, _receipt(revocation="revoked"))

    with pytest.raises(ValueError, match="timeAttestation malformed"):
        compare_verification_receipts(valid, _receipt(timeAttestation={"version": 99}))



# ── Time bounds in receipt comparison ────────────────────────────────────────

def test_compare_time_attestation_with_time_bounds():
    """Receipt comparison includes time bounds in time attestation diff."""
    digest = "a" * 64
    fixed_time = 1700000000000
    
    # Create two attestations with same time sources but different anchor counts
    ta_before = create_time_attestation(evidence_digest=digest, claimed_time_ms=fixed_time)
    ta_after = TimeAttestation(
        version=1,
        protocol=PROFILE_ID,
        evidence_digest=digest,
        claimed_time=ta_before.claimed_time,
        observed_time=ta_before.observed_time,
        stellar_anchors=[
            StellarAnchor(
                ledger_sequence=100,
                ledger_timestamp=fixed_time // 1000,
                transaction_hash="d" * 64,
                network_passphrase="Test SDF Network ; September 2015",
            )
        ],
        rfc3161_anchors=[],
    )
    
    run_a = _receipt(timeAttestation=encode_time_attestation(ta_before))
    run_b = _receipt(timeAttestation=ta_after)
    
    report = compare_verification_receipts(run_a, run_b)
    
    # Time bounds should be present in both encoded attestations
    encoded_before = encode_time_attestation(ta_before)
    encoded_after = encode_time_attestation(ta_after)
    assert "timeBounds" in encoded_before
    assert "timeBounds" in encoded_after
    assert encoded_before["timeBounds"]["claimedTime"] == "inclusive"
    assert encoded_after["timeBounds"]["stellarAnchors"] == "inclusive"



def test_compare_fixed_clock_exact_boundary_match():
    """Receipt comparison with fixed clock at exact boundary."""
    digest = "b" * 64
    fixed_time = 1700000000000
    
    # Both runs have identical time attestation with exact boundary match
    ta = create_time_attestation(evidence_digest=digest, claimed_time_ms=fixed_time)
    # Add stellar anchor at exact same timestamp
    ta_with_anchor = add_stellar_anchor(
        ta,
        ledger_sequence=100,
        ledger_timestamp=fixed_time // 1000,
        transaction_hash="c" * 64,
        network_passphrase="Test SDF Network ; September 2015",
    )
    
    run_a = _receipt(timeAttestation=encode_time_attestation(ta_with_anchor))
    run_b = _receipt(timeAttestation=ta_with_anchor)
    
    report = compare_verification_receipts(run_a, run_b)
    
    # Should be identical including time bounds
    assert report["identical"] is True
    assert report["equivalentEvidence"] is True
    assert report["presentationOnly"] is False



def test_compare_time_bounds_presentation_only_difference():
    """Time bounds differences are presentation-only if time sources match."""
    digest = "c" * 64
    fixed_time = 1700000000000
    
    ta = create_time_attestation(evidence_digest=digest, claimed_time_ms=fixed_time)
    ta_with_stellar = add_stellar_anchor(
        ta,
        ledger_sequence=100,
        ledger_timestamp=fixed_time // 1000,
        transaction_hash="d" * 64,
        network_passphrase="Test SDF Network ; September 2015",
    )
    
    # Both have same time sources, time bounds should match
    run_a = _receipt(timeAttestation=encode_time_attestation(ta_with_stellar))
    run_b = _receipt(timeAttestation=ta_with_stellar)
    
    report = compare_verification_receipts(run_a, run_b)
    
    assert report["identical"] is True
    # Time bounds are derived from time source types, so identical sources = identical bounds