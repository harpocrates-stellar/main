"""Focused tests for offline timestamp-chain validation reports (#1081)."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from rfc3161_chain import trust_store_from_b64_roots
from time_attestation import (
    OFFLINE_TIMESTAMP_CHAIN_REPORT_SCHEMA,
    add_rfc3161_anchor,
    add_stellar_anchor,
    build_offline_timestamp_chain_report,
    create_time_attestation,
)

DIGEST = "a" * 64
TX_HASH = "b" * 64
NETWORK = "Test SDF Network ; September 2015"


def _b64_der(cert: x509.Certificate) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _make_certs():
    base_dt = datetime(2026, 7, 1, tzinfo=UTC)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("Harpocrates Offline TSA Root"))
        .issuer_name(_name("Harpocrates Offline TSA Root"))
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(base_dt - timedelta(days=30))
        .not_valid_after(base_dt + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    valid_leaf = (
        x509.CertificateBuilder()
        .subject_name(_name("Harpocrates Offline TSA Signer"))
        .issuer_name(root_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(base_dt - timedelta(days=1))
        .not_valid_after(base_dt + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    # Forged leaf claims root_cert.subject as issuer, but is signed by attacker_key!
    forged_leaf = (
        x509.CertificateBuilder()
        .subject_name(_name("Harpocrates Forged TSA Signer"))
        .issuer_name(root_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(3)
        .not_valid_before(base_dt - timedelta(days=1))
        .not_valid_after(base_dt + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(attacker_key, hashes.SHA256())
    )

    gen_time_ms = int((base_dt + timedelta(days=2)).timestamp() * 1000)
    return _b64_der(root_cert), _b64_der(valid_leaf), _b64_der(forged_leaf), gen_time_ms


def test_lists_each_dependency_and_verifies_trusted_offline_chains() -> None:
    root_b64, valid_leaf_b64, _, gen_ms = _make_certs()
    store = trust_store_from_b64_roots([root_b64])

    att = create_time_attestation(DIGEST, claimed_time_ms=gen_ms - 2_000)
    att = add_stellar_anchor(att, 500, gen_ms // 1000, TX_HASH, NETWORK)
    att = add_rfc3161_anchor(
        att,
        token_bytes="VE9LRU4=",
        tsa_url="https://tsa.example.org/tsr",
        gen_time=gen_ms,
        certificate_chain=[valid_leaf_b64, root_b64],
    )

    report = build_offline_timestamp_chain_report(
        att,
        expected_evidence_digest=DIGEST,
        trust_store=store,
        offline_stellar_snapshots={
            TX_HASH: {
                "ledgerSequence": 500,
                "ledgerTimestamp": gen_ms // 1000,
                "networkPassphrase": NETWORK,
                "signatureValid": True,
            }
        },
        now_unix_ms=max(gen_ms + 5_000, att.observed_time.unix_ms + 1_000),  # type: ignore[union-attr]
    )
    doc = report.to_dict()

    assert doc["schema"] == OFFLINE_TIMESTAMP_CHAIN_REPORT_SCHEMA
    assert report.overall_assurance == "verified_independent_anchor"
    assert report.has_invalid_signatures is False
    assert report.has_unavailable_trust_material is False

    by_id = {d.dependency_id: d for d in report.dependencies}
    assert by_id["claimed_time"].trust_result == "self_asserted_bounded"
    assert by_id["observed_time"].trust_result == "self_asserted_bounded"
    assert by_id["stellar_anchor[0]"].trust_result == "verified_trusted"
    assert by_id["rfc3161_anchor[0]"].trust_result == "verified_trusted"
    assert by_id["rfc3161_anchor[0]"].root_fingerprint is not None


def test_cleanly_separates_invalid_signatures_from_unavailable_trust_material() -> None:
    root_b64, valid_leaf_b64, forged_leaf_b64, gen_ms = _make_certs()
    store = trust_store_from_b64_roots([root_b64])

    # Case A: Unavailable trust material (no cert chain, empty trust store, missing ledger snapshot)
    att_missing_material = create_time_attestation(DIGEST, claimed_time_ms=gen_ms - 1_000)
    att_missing_material = add_stellar_anchor(
        att_missing_material, 500, gen_ms // 1000, TX_HASH, NETWORK
    )
    att_missing_material = add_rfc3161_anchor(
        att_missing_material,
        token_bytes="VE9LRU4=",
        tsa_url="https://tsa.example.org/tsr",
        gen_time=gen_ms,
        certificate_chain=None,
    )
    att_missing_material = add_rfc3161_anchor(
        att_missing_material,
        token_bytes="VE9LRU4y",
        tsa_url="https://tsa2.example.org/tsr",
        gen_time=gen_ms,
        certificate_chain=[valid_leaf_b64],
    )

    now_ms = max(gen_ms + 5_000, att_missing_material.observed_time.unix_ms + 1_000)  # type: ignore[union-attr]
    unavail_report = build_offline_timestamp_chain_report(
        att_missing_material,
        expected_evidence_digest=DIGEST,
        trust_roots_b64=[],
        offline_stellar_snapshots=None,
        now_unix_ms=now_ms,
    )
    assert unavail_report.has_unavailable_trust_material is True
    assert unavail_report.has_invalid_signatures is False
    assert unavail_report.overall_assurance == "bounded_unverified_material"
    assert set(unavail_report.unavailable_trust_material_dependencies) == {
        "stellar_anchor[0]",
        "rfc3161_anchor[0]",
        "rfc3161_anchor[1]",
    }

    # Case B: Invalid cryptographic signatures (both 2-cert [forged_leaf, root] and 1-cert [forged_leaf] against store)
    att_bad_sig = create_time_attestation(DIGEST, claimed_time_ms=gen_ms - 1_000)
    att_bad_sig = add_rfc3161_anchor(
        att_bad_sig,
        token_bytes="VE9LRU4=",
        tsa_url="https://tsa.example.org/tsr",
        gen_time=gen_ms,
        certificate_chain=[forged_leaf_b64, root_b64],
    )
    att_bad_sig = add_rfc3161_anchor(
        att_bad_sig,
        token_bytes="VE9LRU4y",
        tsa_url="https://tsa.example.org/tsr",
        gen_time=gen_ms,
        certificate_chain=[forged_leaf_b64],
    )
    now_ms_2 = max(gen_ms + 5_000, att_bad_sig.observed_time.unix_ms + 1_000)  # type: ignore[union-attr]
    bad_sig_report = build_offline_timestamp_chain_report(
        att_bad_sig,
        expected_evidence_digest=DIGEST,
        trust_store=store,
        now_unix_ms=now_ms_2,
    )
    assert bad_sig_report.has_invalid_signatures is True
    assert bad_sig_report.has_unavailable_trust_material is False
    assert bad_sig_report.overall_assurance == "failed_validation"
    assert bad_sig_report.invalid_signature_dependencies == (
        "rfc3161_anchor[0]",
        "rfc3161_anchor[1]",
    )
