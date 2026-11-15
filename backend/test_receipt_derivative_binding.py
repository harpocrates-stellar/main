from __future__ import annotations

import pytest

import app as app_module
from lineage import lineage_manifest_digest
from time_attestation import add_stellar_anchor, create_time_attestation, encode_time_attestation
from verification_receipt import (
    ReceiptBindingConflictError,
    build_verification_receipt,
    compute_parent_child_statement_digest,
)


def _base_context() -> dict[str, object]:
    return {
        "proofId": "11" * 32,
        "videoHash": "22" * 32,
        "metadataHash": "33" * 32,
        "tier": "source",
        "networkPassphrase": "Test SDF Network ; September 2015",
        "contractId": "C" + "A" * 55,
        "ledgerSequence": 77,
        "transactionHash": "44" * 32,
        "circuitVersion": "1",
        "verifierVersion": "2026.11",
    }


def _valid_lineage_manifest() -> dict[str, object]:
    return {
        "operationType": "redact",
        "parentProofIds": ["99" * 32],
        "parametersDigest": "55" * 32,
        "toolIdentity": "harpocrates-studio",
        "toolVersion": "1.0.0",
        "outputDigest": "22" * 32,
        "network": "Test SDF Network ; September 2015",
        "actorAddress": "G" + "B" * 55,
    }


def test_accepts_canonical_parent_child_binding_and_emits_only_unsigned_fields():
    manifest = _valid_lineage_manifest()
    manifest_digest = lineage_manifest_digest(manifest)
    statement_digest = compute_parent_child_statement_digest(
        parent_proof_ids=["99" * 32],
        child_proof_id="11" * 32,
        child_video_hash="22" * 32,
        network_passphrase="Test SDF Network ; September 2015",
        lineage_manifest_digest_hex=manifest_digest,
    )

    att = add_stellar_anchor(
        create_time_attestation("22" * 32),
        ledger_sequence=77,
        ledger_timestamp=1_800_000_000,
        transaction_hash="44" * 32,
        network_passphrase="Test SDF Network ; September 2015",
    )

    ctx = {
        **_base_context(),
        "evidenceDigest": "22" * 32,
        "outputDigest": "22" * 32,
        "derivativeProofId": "11" * 32,
        "parentProofIds": ["99" * 32],
        "parentStatement": {
            "proofId": "99" * 32,
            "videoHash": "88" * 32,
            "networkPassphrase": "Test SDF Network ; September 2015",
        },
        "lineageManifest": manifest,
        "lineageManifestDigest": manifest_digest,
        "parentChildStatementDigest": statement_digest,
        "timeAttestation": encode_time_attestation(att),
    }

    receipt = build_verification_receipt(ctx, result="verified")
    assert receipt["result"] == "verified"
    assert receipt["proofId"] == "11" * 32
    assert receipt["videoHash"] == "22" * 32
    # Frontend retains exclusive ownership of versioning and signing
    assert set(receipt.keys()) == {
        "result",
        "verifiedAt",
        "proofId",
        "videoHash",
        "metadataHash",
        "tier",
        "networkPassphrase",
        "contractId",
        "ledgerSequence",
        "transactionHash",
        "circuitVersion",
        "verifierVersion",
    }


@pytest.mark.parametrize(
    ("override", "match_pattern"),
    [
        ({"evidenceDigest": "ff" * 32}, "evidenceDigest does not match videoHash"),
        ({"outputDigest": "ee" * 32}, "outputDigest does not match videoHash"),
        ({"derivativeVideoHash": "dd" * 32}, "derivativeVideoHash does not match videoHash"),
        ({"derivativeProofId": "cc" * 32}, "derivativeProofId does not match proofId"),
        ({"parentProofIds": ["11" * 32]}, "proofId cannot appear in parentProofIds"),
        ({"parentProofIds": ["99" * 32, "99" * 32]}, "duplicate parent proof identifier"),
        (
            {"parentStatement": {"proofId": "99" * 32, "videoHash": "22" * 32}},
            "equals derivative videoHash",
        ),
        (
            {
                "lineageManifest": {
                    **_valid_lineage_manifest(),
                    "outputDigest": "aa" * 32,
                }
            },
            "lineageManifest.outputDigest does not match videoHash",
        ),
        (
            {
                "lineageManifest": _valid_lineage_manifest(),
                "lineageManifestDigest": "00" * 32,
            },
            "lineageManifestDigest does not match",
        ),
        (
            {
                "parentProofIds": ["99" * 32],
                "parentChildStatementDigest": "ff" * 32,
            },
            "parent-child statement binding digest mismatch",
        ),
        ({"protocol": "harpocrates-verification-receipt"}, "frontend owns receipt signing"),
        ({"version": 1}, "frontend owns receipt signing"),
        ({"signature": "deadbeef"}, "frontend owns receipt signing"),
    ],
)
def test_rejects_conflicting_evidence_and_derivative_identifiers(
    override: dict[str, object],
    match_pattern: str,
):
    bad_ctx = {**_base_context(), **override}
    with pytest.raises(ReceiptBindingConflictError, match=match_pattern):
        build_verification_receipt(bad_ctx)


def test_rejects_conflicting_time_attestation_and_endpoint_returns_400():
    conflicting_att = create_time_attestation("77" * 32)
    with pytest.raises(ValueError, match="timeAttestation.evidenceDigest does not match videoHash"):
        build_verification_receipt(
            {
                **_base_context(),
                "timeAttestation": encode_time_attestation(conflicting_att),
            }
        )

    client = app_module.create_app().test_client()
    resp = client.post(
        "/api/verify/selective-disclosure",
        json={
            "proof": "ab" * 64,
            "publicInputs": "01" * 352,
            "schemaHash": "cd" * 32,
            "receiptContext": {
                **_base_context(),
                "outputDigest": "ef" * 32,
            },
        },
    )
    assert resp.status_code == 400
    assert "outputDigest does not match videoHash" in resp.get_json()["error"]
