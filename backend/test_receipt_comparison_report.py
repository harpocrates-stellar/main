"""Focused tests for verification receipt comparison reports across two runs (#1079)."""

from __future__ import annotations

import pytest

from verification_receipt import (
    RECEIPT_COMPARISON_REPORT_SCHEMA,
    RunObservationContext,
    compare_verification_receipts,
)


def _base_receipt() -> dict[str, object]:
    return {
        "protocol": "harpocrates-verification-receipt",
        "version": 1,
        "result": "verified",
        "verifiedAt": "2026-07-26T12:00:00Z",
        "proofId": "a" * 64,
        "videoHash": "b" * 64,
        "metadataHash": "c" * 64,
        "tier": "source",
        "networkPassphrase": "Test SDF Network ; September 2015",
        "contractId": "C" + "d" * 55,
        "ledgerSequence": 100,
        "transactionHash": "e" * 64,
        "circuitVersion": "silent-witness-v1",
        "verifierVersion": "registry-v1",
        "signer": {"keyId": "verifier-2026-07", "algorithm": "ECDSA_P256_SHA256"},
        "signature": "sig_run_1",
    }


def test_distinguishes_presentation_only_differences_from_evidence_changes() -> None:
    run1 = _base_receipt()
    identical = compare_verification_receipts(run1, dict(run1))
    assert identical.overall_status == "identical"
    assert identical.same_evidence is True
    assert identical.has_substantive_changes is False
    assert identical.to_dict()["schema"] == RECEIPT_COMPARISON_REPORT_SCHEMA

    # Presentation-only: later verifiedAt, +00:00 formatting, uppercase hex, fresh signature bytes
    run2_presentation = {
        **run1,
        "verifiedAt": "2026-07-26T12:15:00+00:00",
        "videoHash": "B" * 64,
        "signature": "sig_run_2_re_signed",
    }
    pres_report = compare_verification_receipts(run1, run2_presentation)
    assert pres_report.overall_status == "presentation_only_differences"
    assert pres_report.same_evidence is True
    assert pres_report.has_substantive_changes is False
    assert pres_report.has_presentation_differences is True
    assert {d.category for d in pres_report.differences} == {"presentation_only"}

    # Substantive evidence change: videoHash digest and identity tier changed
    run2_tampered_evidence = {
        **run1,
        "videoHash": "f" + ("b" * 63),
        "tier": "seal",
    }
    ev_report = compare_verification_receipts(run1, run2_tampered_evidence)
    assert ev_report.overall_status == "different_evidence"
    assert ev_report.same_evidence is False
    assert ev_report.has_substantive_changes is True
    ev_fields = {d.field for d in ev_report.differences if d.category == "evidence_change"}
    assert ev_fields == {"videoHash", "tier"}


def test_explains_changed_trust_revocation_and_chain_observations() -> None:
    unanchored_run = {
        **_base_receipt(),
        "result": "verified",
        "ledgerSequence": None,
        "transactionHash": None,
    }
    later_revoked_run = {
        **_base_receipt(),
        "result": "unverified",
        "ledgerSequence": 54321,
        "transactionHash": "e" * 64,
        "verifiedAt": "2026-07-27T09:00:00Z",
    }

    report = compare_verification_receipts(
        unanchored_run,
        later_revoked_run,
        first_observation=RunObservationContext(
            trust_status="trusted",
            revocation_status="active",
            tsa_verification_status="unverified",
        ),
        second_observation=RunObservationContext(
            trust_status="compromised",
            revocation_status="revoked",
            tsa_verification_status="valid",
        ),
    )

    assert report.overall_status == "observation_or_trust_changed"
    assert report.same_evidence is True
    assert report.has_substantive_changes is True

    by_field = {d.field: d for d in report.differences}
    assert by_field["result"].category == "trust_or_revocation_change"
    assert by_field["revocationStatus"].reason_code == "revocation_status_changed"
    assert by_field["trustStatus"].reason_code == "issuer_or_signer_trust_changed"
    assert by_field["tsaVerificationStatus"].reason_code == "tsa_chain_status_changed"
    assert by_field["ledgerSequence"].category == "chain_observation_change"
    assert by_field["ledgerSequence"].reason_code == "chain_anchor_confirmed"
    assert by_field["transactionHash"].category == "chain_observation_change"
    assert any("revoked" in expl for expl in report.explanations)

    with pytest.raises(ValueError, match="videoHash"):
        compare_verification_receipts(unanchored_run, {**unanchored_run, "videoHash": "invalid"})
