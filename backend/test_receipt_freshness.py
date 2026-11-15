from __future__ import annotations

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import app as app_module
from time_attestation import (
    ClaimedTime,
    TimeAttestation,
    add_stellar_anchor,
    create_time_attestation,
    encode_time_attestation,
    extract_observation_timestamp_ms,
)
from verification_receipt import (
    RECEIPT_ALGORITHM,
    RECEIPT_PROTOCOL,
    RECEIPT_VERSION,
    canonicalize_receipt_object,
    evaluate_signed_receipt,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _generate_p256_keypair_and_jwk() -> tuple[ec.EllipticCurvePrivateKey, dict[str, object]]:
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    jwk: dict[str, object] = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(nums.x.to_bytes(32, "big")),
        "y": _b64url(nums.y.to_bytes(32, "big")),
    }
    return priv, jwk


def _sign_webcrypto_receipt(
    priv: ec.EllipticCurvePrivateKey,
    *,
    key_id: str = "portal-key-1",
    verified_at: str = "2027-01-15T08:05:00Z",
    result: str = "verified",
    video_hash: str = "22" * 32,
) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "protocol": RECEIPT_PROTOCOL,
        "version": RECEIPT_VERSION,
        "result": result,
        "verifiedAt": verified_at,
        "proofId": "11" * 32,
        "videoHash": video_hash,
        "metadataHash": "33" * 32,
        "tier": "seal",
        "networkPassphrase": "Test SDF Network ; September 2015",
        "contractId": "C" + "A" * 55,
        "ledgerSequence": 100,
        "transactionHash": "44" * 32,
        "circuitVersion": "1",
        "verifierVersion": "2026.11",
        "signer": {"keyId": key_id, "algorithm": RECEIPT_ALGORITHM},
    }
    der_sig = priv.sign(
        canonicalize_receipt_object(unsigned).encode("utf-8"),
        ec.ECDSA(hashes.SHA256()),
    )
    r, s = decode_dss_signature(der_sig)
    raw_p1363 = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return {**unsigned, "signature": _b64url(raw_p1363)}


def test_fresh_valid_receipt_reports_current_chain_truth_and_observation_times():
    priv, pub_jwk = _generate_p256_keypair_and_jwk()
    receipt = _sign_webcrypto_receipt(priv, verified_at="2027-01-15T08:05:00Z")

    att = add_stellar_anchor(
        create_time_attestation("22" * 32),
        ledger_sequence=100,
        ledger_timestamp=1_800_000_000,  # 2027-01-15T08:00:00Z
        transaction_hash="44" * 32,
        network_passphrase="Test SDF Network ; September 2015",
    )

    evaluated = evaluate_signed_receipt(
        receipt,
        keys={"portal-key-1": pub_jwk},
        time_attestation=att,
        now="2027-01-15T08:15:00Z",
        max_verification_age_seconds=3_600,
        max_observation_age_seconds=7_200,
    )

    assert evaluated["signatureValidity"]["valid"] is True
    assert evaluated["signatureValidity"]["status"] == "valid"
    assert evaluated["receiptFreshness"]["fresh"] is True
    assert evaluated["receiptFreshness"]["status"] == "fresh"
    assert evaluated["receiptFreshness"]["evidenceObservedAt"] == "2027-01-15T08:00:00Z"
    assert evaluated["receiptFreshness"]["evidenceObservedAtSource"] == "stellar_ledger"
    assert evaluated["receiptFreshness"]["verifiedAt"] == "2027-01-15T08:05:00Z"
    assert evaluated["receiptFreshness"]["verificationAgeSeconds"] == 600.0
    assert evaluated["receiptFreshness"]["observationAgeSeconds"] == 900.0
    assert evaluated["isCurrentChainTruth"] is True
    assert evaluated["chainTruthStanding"] == "current_verified"


def test_old_validly_signed_receipt_keeps_valid_signature_without_claiming_current_chain_truth():
    priv, pub_jwk = _generate_p256_keypair_and_jwk()
    receipt = _sign_webcrypto_receipt(priv, verified_at="2027-01-01T00:00:00Z")

    # Even after the signer key rotated on 2027-01-10, the historical signature remains valid,
    # while freshness is stale and isCurrentChainTruth is strictly False.
    evaluated = evaluate_signed_receipt(
        receipt,
        keys={"portal-key-1": pub_jwk},
        key_validity={
            "portal-key-1": {
                "notBefore": "2026-12-01T00:00:00Z",
                "notAfter": "2027-01-10T00:00:00Z",
            }
        },
        evidence_observed_at="2026-12-31T23:55:00Z",
        now="2027-01-20T00:00:00Z",
        max_verification_age_seconds=3_600,
    )

    assert evaluated["signatureValidity"]["valid"] is True
    assert evaluated["signatureValidity"]["status"] == "valid"
    assert evaluated["receiptFreshness"]["fresh"] is False
    assert evaluated["receiptFreshness"]["status"] == "stale_verification"
    assert evaluated["isCurrentChainTruth"] is False
    assert evaluated["chainTruthStanding"] == "historical_signed_snapshot"


def test_tampered_signature_and_stale_observation_and_claimed_only_attestation():
    priv, pub_jwk = _generate_p256_keypair_and_jwk()
    receipt = _sign_webcrypto_receipt(priv, verified_at="2027-01-15T08:05:00Z")

    # Tamper verified result after signing -> signature invalid, rejected
    tampered = {**receipt, "videoHash": "99" * 32}
    rejected = evaluate_signed_receipt(
        tampered,
        keys={"portal-key-1": pub_jwk},
        now="2027-01-15T08:06:00Z",
    )
    assert rejected["signatureValidity"]["valid"] is False
    assert rejected["signatureValidity"]["status"] == "invalid_signature"
    assert rejected["isCurrentChainTruth"] is False
    assert rejected["chainTruthStanding"] == "rejected"

    # Device claimed_time alone does not count as an independent observation
    claimed_only = TimeAttestation(
        version=1,
        protocol="harpocrates-time-attestation/v1",
        evidence_digest="22" * 32,
        claimed_time=ClaimedTime(unix_ms=1_800_000_000_000, source_label="device_clock"),
    )
    assert extract_observation_timestamp_ms(claimed_only) is None

    unanchored = evaluate_signed_receipt(
        receipt,
        keys={"portal-key-1": pub_jwk},
        time_attestation=claimed_only,
        now="2027-01-15T08:06:00Z",
        max_verification_age_seconds=3_600,
        max_observation_age_seconds=1_800,
    )
    assert unanchored["signatureValidity"]["valid"] is True
    assert unanchored["receiptFreshness"]["fresh"] is False
    assert unanchored["receiptFreshness"]["status"] == "unanchored_observation"
    assert unanchored["chainTruthStanding"] == "historical_signed_snapshot"


def test_http_receipt_evaluate_endpoint_separates_signature_and_freshness():
    priv, pub_jwk = _generate_p256_keypair_and_jwk()
    receipt = _sign_webcrypto_receipt(priv, verified_at="2027-01-15T08:00:00Z")
    att = encode_time_attestation(
        add_stellar_anchor(
            create_time_attestation("22" * 32),
            ledger_sequence=100,
            ledger_timestamp=1_799_999_900,
            transaction_hash="44" * 32,
            network_passphrase="Test SDF Network ; September 2015",
        )
    )

    client = app_module.create_app().test_client()
    resp = client.post(
        "/api/receipts/evaluate",
        json={
            "receipt": receipt,
            "keys": {"portal-key-1": pub_jwk},
            "timeAttestation": att,
            "now": "2027-01-15T12:00:00Z",
            "maxVerificationAgeSeconds": 1800,
        },
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    assert body["signatureValidity"]["valid"] is True
    assert body["receiptFreshness"]["fresh"] is False
    assert body["receiptFreshness"]["status"] == "stale_verification"
    assert body["isCurrentChainTruth"] is False
    assert body["chainTruthStanding"] == "historical_signed_snapshot"
