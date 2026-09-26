from verification_receipt import build_verification_receipt


def test_receipt_has_stable_public_shape():
    receipt = build_verification_receipt(evidence_digest="a" * 64, schema_hash="b" * 64, request_id="req-123")
    assert receipt["protocol"] == "harpocrates-verification-receipt"
    assert receipt["version"] == 1
    assert receipt["status"] == "accepted"
    assert receipt["verification_method"] == "selective_disclosure"
    assert "proof" not in receipt
    assert "public_inputs" not in receipt


def test_receipt_can_explain_an_unverified_result():
    receipt = build_verification_receipt(evidence_digest="a" * 64, schema_hash=None, request_id="req-456", status="unverified", reason_code="SCHEMA_NOT_FOUND")
    assert receipt["schema_hash"] is None
    assert receipt["reason_code"] == "SCHEMA_NOT_FOUND"
