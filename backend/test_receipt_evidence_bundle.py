from __future__ import annotations

import base64
import copy

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from app import create_app
from time_attestation import (
    ClaimedTime,
    ObservedTime,
    PROFILE_ID,
    StellarAnchor,
    TimeAttestation,
    encode_time_attestation,
)
from verification_receipt import (
    EVIDENCE_BUNDLE_PROTOCOL,
    EVIDENCE_BUNDLE_VERSION,
    RECEIPT_ALGORITHM,
    RECEIPT_PROTOCOL,
    RECEIPT_VERSION,
    build_receipt_evidence_bundle,
    build_verification_receipt,
    canonicalize_json,
    serialize_receipt_evidence_bundle,
    verify_receipt_evidence_bundle,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _generate_p256_keypair() -> tuple[ec.EllipticCurvePrivateKey, dict[str, object]]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
        "ext": True,
        "key_ops": ["verify"],
    }
    return private_key, jwk


def _sign_receipt(
    unsigned_input: dict[str, object],
    *,
    key_id: str,
    private_key: ec.EllipticCurvePrivateKey,
) -> dict[str, object]:
    payload = {
        **unsigned_input,
        "protocol": RECEIPT_PROTOCOL,
        "version": RECEIPT_VERSION,
        "signer": {"keyId": key_id, "algorithm": RECEIPT_ALGORITHM},
    }
    der_sig = private_key.sign(
        canonicalize_json(payload).encode("utf-8"),
        ec.ECDSA(hashes.SHA256()),
    )
    r_int, s_int = utils.decode_dss_signature(der_sig)
    raw_sig = r_int.to_bytes(32, "big") + s_int.to_bytes(32, "big")
    return {**payload, "signature": _b64url(raw_sig)}


def _sample_fixture() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    private_key, public_jwk = _generate_p256_keypair()
    proof_id = "11" * 32
    video_hash = "22" * 32
    metadata_hash = "33" * 32
    tx_hash = "44" * 32
    network = "Test SDF Network ; September 2015"
    contract_id = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"

    unsigned = {
        "result": "verified",
        "verifiedAt": "2026-06-15T12:05:00Z",
        "proofId": proof_id,
        "videoHash": video_hash,
        "metadataHash": metadata_hash,
        "tier": "seal",
        "networkPassphrase": network,
        "contractId": contract_id,
        "ledgerSequence": 900123,
        "transactionHash": tx_hash,
        "circuitVersion": "seal-v1",
        "verifierVersion": "ultrahonk-v1",
    }
    signed_receipt = _sign_receipt(unsigned, key_id="portal-2026-q2", private_key=private_key)

    trust_snapshot = {
        "capturedAt": "2026-06-15T12:00:00Z",
        "policyVersion": "trust-policy-v1",
        "keys": {"portal-2026-q2": public_jwk},
        "keyValidity": {
            "portal-2026-q2": {
                "notBefore": "2026-04-01T00:00:00Z",
                "notAfter": "2026-07-01T00:00:00Z",
                "status": "retired",
            }
        },
    }

    attestation = TimeAttestation(
        version=1,
        protocol=PROFILE_ID,
        evidence_digest=video_hash,
        claimed_time=ClaimedTime(unix_ms=1781524800000, source_label="device_clock"),
        observed_time=ObservedTime(unix_ms=1781524900000, source_label="backend_ntp_synced"),
        stellar_anchors=[
            StellarAnchor(
                ledger_sequence=900123,
                ledger_timestamp=1781524950,
                transaction_hash=tx_hash,
                network_passphrase=network,
            )
        ],
    )

    chain_observation = {
        "proofId": proof_id,
        "videoHash": video_hash,
        "metadataHash": metadata_hash,
        "tier": "seal",
        "networkPassphrase": network,
        "contractId": contract_id,
        "ledgerSequence": 900123,
        "transactionHash": tx_hash,
        "status": "confirmed",
        "observedAt": "2026-06-15T12:03:00Z",
        "timeAttestation": encode_time_attestation(attestation),
    }

    return signed_receipt, trust_snapshot, chain_observation


def test_build_and_verify_bundle_offline_roundtrip() -> None:
    signed_receipt, trust_snapshot, chain_observation = _sample_fixture()
    bundle = build_receipt_evidence_bundle(
        receipt=signed_receipt,
        trust_snapshot=trust_snapshot,
        chain_observation=chain_observation,
        bundled_at="2026-06-15T12:10:00Z",
    )

    assert bundle["protocol"] == EVIDENCE_BUNDLE_PROTOCOL
    assert bundle["version"] == EVIDENCE_BUNDLE_VERSION

    serialized = serialize_receipt_evidence_bundle(bundle)
    # Offline archival verification succeeds years later without API tokens or media
    result = verify_receipt_evidence_bundle(
        serialized,
        expected_network_passphrase="Test SDF Network ; September 2015",
        expected_proof_id="11" * 32,
        trusted_snapshot_digest=bundle["bindings"]["trustSnapshotDigest"],
        now="2028-01-01T00:00:00Z",
    )
    assert result["valid"] is True
    assert result["code"] == "VALID"
    assert result["offline"] is True
    assert result["bindings"] == bundle["bindings"]


def test_bundle_detects_digest_and_component_tampering() -> None:
    signed_receipt, trust_snapshot, chain_observation = _sample_fixture()
    bundle = build_receipt_evidence_bundle(
        receipt=signed_receipt,
        trust_snapshot=trust_snapshot,
        chain_observation=chain_observation,
        bundled_at="2026-06-15T12:10:00Z",
    )

    tampered_obs = copy.deepcopy(bundle)
    tampered_obs["chainObservation"]["observedAt"] = "2026-06-15T12:04:00Z"
    res_obs = verify_receipt_evidence_bundle(tampered_obs)
    assert res_obs["valid"] is False
    assert res_obs["code"] == "DIGEST_MISMATCH"

    wrong_pinned_snapshot = verify_receipt_evidence_bundle(
        bundle,
        trusted_snapshot_digest="ff" * 32,
    )
    assert wrong_pinned_snapshot["valid"] is False
    assert wrong_pinned_snapshot["code"] == "UNTRUSTED_SNAPSHOT"

    unsupported_version = copy.deepcopy(bundle)
    unsupported_version["version"] = 2
    res_ver = verify_receipt_evidence_bundle(unsupported_version)
    assert res_ver["valid"] is False
    assert res_ver["code"] == "UNSUPPORTED_BUNDLE_VERSION"


def test_bundle_rejects_statement_mismatch_revoked_keys_and_anchor_mismatch() -> None:
    signed_receipt, trust_snapshot, chain_observation = _sample_fixture()

    bad_obs = copy.deepcopy(chain_observation)
    bad_obs["metadataHash"] = "99" * 32
    with pytest.raises(ValueError, match="STATEMENT_MISMATCH"):
        build_receipt_evidence_bundle(
            receipt=signed_receipt,
            trust_snapshot=trust_snapshot,
            chain_observation=bad_obs,
        )

    revoked_snapshot = copy.deepcopy(trust_snapshot)
    revoked_snapshot["keyValidity"]["portal-2026-q2"]["status"] = "revoked"
    with pytest.raises(ValueError, match="SIGNER_KEY_REVOKED"):
        build_receipt_evidence_bundle(
            receipt=signed_receipt,
            trust_snapshot=revoked_snapshot,
            chain_observation=chain_observation,
        )

    bad_anchor_obs = copy.deepcopy(chain_observation)
    bad_anchor_obs["timeAttestation"]["stellarAnchors"][0]["transactionHash"] = "88" * 32
    with pytest.raises(ValueError, match="INVALID_TIME_ATTESTATION"):
        build_receipt_evidence_bundle(
            receipt=signed_receipt,
            trust_snapshot=trust_snapshot,
            chain_observation=bad_anchor_obs,
        )


def test_bundle_rejects_api_tokens_private_keys_and_sensitive_media() -> None:
    signed_receipt, trust_snapshot, chain_observation = _sample_fixture()
    bundle = build_receipt_evidence_bundle(
        receipt=signed_receipt,
        trust_snapshot=trust_snapshot,
        chain_observation=chain_observation,
        bundled_at="2026-06-15T12:10:00Z",
    )

    for forbidden_patch in (
        {"apiToken": "secret-token-123"},
        {"mediaBytes": "AAAA"},
        {"witness": {"nullifier": "01" * 32}},
    ):
        contaminated = {**copy.deepcopy(bundle), **forbidden_patch}
        check = verify_receipt_evidence_bundle(contaminated)
        assert check["valid"] is False
        assert check["code"] == "SENSITIVE_MATERIAL_REJECTED"

    private_jwk_snapshot = copy.deepcopy(trust_snapshot)
    private_jwk_snapshot["keys"]["portal-2026-q2"]["d"] = _b64url(b"\x01" * 32)
    with pytest.raises(ValueError, match="forbidden sensitive or credential"):
        build_receipt_evidence_bundle(
            receipt=signed_receipt,
            trust_snapshot=private_jwk_snapshot,
            chain_observation=chain_observation,
        )


def test_http_endpoints_verify_bundle_without_api_token_and_preserve_unsigned_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NOIR_WORKER_ENABLED", "false")
    unsigned = build_verification_receipt(
        {
            "proofId": "aa" * 32,
            "videoHash": "bb" * 32,
            "metadataHash": "cc" * 32,
            "tier": "silent",
            "networkPassphrase": "Test SDF Network ; September 2015",
            "contractId": "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
            "ledgerSequence": 12,
            "transactionHash": "dd" * 32,
            "circuitVersion": "silent-v1",
            "verifierVersion": "ultrahonk-v1",
        },
        result="verified",
    )
    assert "protocol" not in unsigned
    assert "signature" not in unsigned

    signed_receipt, trust_snapshot, chain_observation = _sample_fixture()
    app = create_app()
    client = app.test_client()

    create_resp = client.post(
        "/api/receipts/evidence-bundle",
        json={
            "receipt": signed_receipt,
            "trustSnapshot": trust_snapshot,
            "chainObservation": chain_observation,
            "bundledAt": "2026-06-15T12:10:00Z",
        },
    )
    assert create_resp.status_code == 200
    bundle = create_resp.get_json()["bundle"]

    verify_resp = client.post(
        "/api/receipts/evidence-bundle/verify",
        json={"bundle": bundle},
    )
    assert verify_resp.status_code == 200
    verification = verify_resp.get_json()["verification"]
    assert verification["valid"] is True
    assert verification["offline"] is True

    token_rejected = client.post(
        "/api/receipts/evidence-bundle/verify",
        headers={"Authorization": "Bearer should-not-be-sent"},
        json={"bundle": bundle},
    )
    assert token_rejected.status_code == 400
    assert token_rejected.get_json()["error"]["code"] == "VALIDATION_ERROR"
