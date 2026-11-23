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


@pytest.mark.parametrize(
    "vector",
    INTEROP_FIXTURE["validVectors"],
    ids=lambda v: v["name"],
)
def test_interop_valid_vectors_parse_canonicalize_and_verify(vector: dict):
    unsigned_input = vector["unsignedInput"]
    built = build_verification_receipt(
        unsigned_input,
        result=unsigned_input["result"],
        verified_at=unsigned_input["verifiedAt"],
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

    with pytest.raises(ValueError, match="QR payload size limit"):
        decode_receipt_from_qr("A" * (MAX_QR_PAYLOAD_BYTES + 1))
