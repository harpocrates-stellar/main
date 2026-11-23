from datetime import datetime, timezone
import json
from pathlib import Path
import re

import pytest

from verification_receipt import (
    MAX_QR_PAYLOAD_BYTES,
    build_verification_receipt,
    canonicalize_receipt,
    decode_receipt_from_qr,
    encode_receipt_for_qr,
    serialize_verification_receipt,
    verify_verification_receipt,
)

INTEROP_FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent
    / "devx"
    / "fixtures"
    / "receipt-interop"
    / "vectors.json"
)
INTEROP_FIXTURE = json.loads(INTEROP_FIXTURE_PATH.read_text(encoding="utf-8"))


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


def test_receipt_remains_unsigned_when_key_history_is_requested():
    # Public signing-key history is served by a separate read-only endpoint.
    # The unsigned receipt model must not embed key material or signatures.
    receipt = build_verification_receipt(context())

    assert "signingKeys" not in receipt
    assert "keyHistory" not in receipt
    assert "signature" not in receipt


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
    assert built == unsigned_input

    signed = vector["signedReceipt"]
    unsigned_payload = {k: v for k, v in signed.items() if k != "signature"}
    assert canonicalize_receipt(unsigned_payload) == vector["canonicalPayload"]
    assert serialize_verification_receipt(signed) == vector["serializedReceipt"]

    qr = encode_receipt_for_qr(signed)
    assert qr == vector["qrPayload"]
    assert decode_receipt_from_qr(qr) == signed

    now = datetime.fromisoformat(INTEROP_FIXTURE["verificationNow"].replace("Z", "+00:00"))
    result = verify_verification_receipt(
        signed,
        keys=INTEROP_FIXTURE["keys"],
        expected_network_passphrase=unsigned_input["networkPassphrase"],
        expected_proof_id=unsigned_input["proofId"],
        now=now,
        key_validity=INTEROP_FIXTURE["keyValidity"],
    )
    assert result == {"valid": True, "receipt": signed}


@pytest.mark.parametrize(
    "case",
    INTEROP_FIXTURE["mutatedStatements"],
    ids=lambda c: c["name"],
)
def test_interop_mutated_statements_are_explicitly_rejected(case: dict):
    now = datetime.fromisoformat(INTEROP_FIXTURE["verificationNow"].replace("Z", "+00:00"))
    result = verify_verification_receipt(
        case["receipt"],
        keys=INTEROP_FIXTURE["keys"],
        now=now,
        key_validity=INTEROP_FIXTURE["keyValidity"],
    )
    assert result["valid"] is False
    assert re.search(case["expectedReasonPattern"], str(result["reason"]), re.IGNORECASE)


def test_interop_rejects_stale_key_wrong_network_wrong_proof_and_oversized_qr():
    signed = INTEROP_FIXTURE["validVectors"][0]["signedReceipt"]
    keys = INTEROP_FIXTURE["keys"]

    wrong_proof = verify_verification_receipt(
        signed,
        keys=keys,
        expected_proof_id="f" * 64,
    )
    assert wrong_proof["valid"] is False
    assert "proof" in str(wrong_proof["reason"])

    wrong_network = verify_verification_receipt(
        signed,
        keys=keys,
        expected_network_passphrase="Public Global Stellar Network ; September 2015",
    )
    assert wrong_network["valid"] is False
    assert "network" in str(wrong_network["reason"])

    stale_key = verify_verification_receipt(
        signed,
        keys=keys,
        now=datetime(2026, 8, 2, 0, 0, tzinfo=timezone.utc),
        key_validity=INTEROP_FIXTURE["keyValidity"],
    )
    assert stale_key["valid"] is False
    assert "stale" in str(stale_key["reason"])


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