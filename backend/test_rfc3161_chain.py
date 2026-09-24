"""Tests for RFC 3161 TSA certificate-chain validation."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from rfc3161_chain import (
    ChainErrorCode,
    TrustStore,
    trust_store_from_b64_roots,
    validate_chain_document,
    validate_rfc3161_certificate_chain,
)


def _b64(der: bytes) -> str:
    return base64.b64encode(der).decode("ascii")


def _name(common: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build_cert(
    *,
    subject: str,
    issuer_name: x509.Name,
    issuer_key: rsa.RSAPrivateKey,
    subject_key: rsa.RSAPrivateKey,
    not_before: datetime,
    not_after: datetime,
    serial: int,
    is_ca: bool,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    return builder.sign(issuer_key, hashes.SHA256())


@pytest.fixture
def chain_bundle():
    """Leaf <- Intermediate <- Root (all RSA-SHA256)."""
    now = datetime(2024, 6, 1, tzinfo=timezone.utc)
    root_key = _key()
    int_key = _key()
    leaf_key = _key()

    root = _build_cert(
        subject="Harpocrates Test Root",
        issuer_name=_name("Harpocrates Test Root"),
        issuer_key=root_key,
        subject_key=root_key,
        not_before=now - timedelta(days=365),
        not_after=now + timedelta(days=3650),
        serial=1,
        is_ca=True,
    )
    intermediate = _build_cert(
        subject="Harpocrates Test TSA Intermediate",
        issuer_name=root.subject,
        issuer_key=root_key,
        subject_key=int_key,
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=365),
        serial=2,
        is_ca=True,
    )
    leaf = _build_cert(
        subject="Harpocrates Test TSA",
        issuer_name=intermediate.subject,
        issuer_key=int_key,
        subject_key=leaf_key,
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=180),
        serial=3,
        is_ca=False,
    )

    root_der = root.public_bytes(serialization.Encoding.DER)
    int_der = intermediate.public_bytes(serialization.Encoding.DER)
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)

    return {
        "now": now,
        "root_der": root_der,
        "int_der": int_der,
        "leaf_der": leaf_der,
        "root_b64": _b64(root_der),
        "int_b64": _b64(int_der),
        "leaf_b64": _b64(leaf_der),
        "leaf_serial_hex": format(leaf.serial_number, "x"),
        "expired_leaf": _build_cert(
            subject="Harpocrates Expired TSA",
            issuer_name=intermediate.subject,
            issuer_key=int_key,
            subject_key=leaf_key,
            not_before=now - timedelta(days=400),
            not_after=now - timedelta(days=10),
            serial=99,
            is_ca=False,
        ),
    }


def test_valid_chain_with_root_included(chain_bundle):
    store = TrustStore(root_der_list=[chain_bundle["root_der"]])
    result = validate_rfc3161_certificate_chain(
        [chain_bundle["leaf_b64"], chain_bundle["int_b64"], chain_bundle["root_b64"]],
        trust_store=store,
        at_time=chain_bundle["now"],
    )
    assert result.ok is True
    assert result.status == "valid"
    assert result.error_code is None
    assert result.leaf_fingerprint is not None
    assert result.root_fingerprint is not None
    assert result.depth == 3


def test_valid_chain_without_root_in_chain(chain_bundle):
    store = TrustStore(root_der_list=[chain_bundle["root_der"]])
    result = validate_rfc3161_certificate_chain(
        [chain_bundle["leaf_b64"], chain_bundle["int_b64"]],
        trust_store=store,
        at_time=chain_bundle["now"],
    )
    assert result.ok is True
    assert result.status == "valid"


def test_untrusted_root(chain_bundle):
    other_root_key = _key()
    now = chain_bundle["now"]
    other_root = _build_cert(
        subject="Other Root",
        issuer_name=_name("Other Root"),
        issuer_key=other_root_key,
        subject_key=other_root_key,
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=365),
        serial=50,
        is_ca=True,
    )
    store = TrustStore(root_der_list=[other_root.public_bytes(serialization.Encoding.DER)])
    result = validate_rfc3161_certificate_chain(
        [chain_bundle["leaf_b64"], chain_bundle["int_b64"]],
        trust_store=store,
        at_time=now,
    )
    assert result.ok is False
    assert result.status == "untrusted"
    assert result.error_code == ChainErrorCode.UNTRUSTED_ROOT.value


def test_expired_certificate(chain_bundle):
    store = TrustStore(root_der_list=[chain_bundle["root_der"]])
    expired_b64 = _b64(chain_bundle["expired_leaf"].public_bytes(serialization.Encoding.DER))
    result = validate_rfc3161_certificate_chain(
        [expired_b64, chain_bundle["int_b64"]],
        trust_store=store,
        at_time=chain_bundle["now"],
    )
    assert result.ok is False
    assert result.status == "expired"
    assert result.error_code == ChainErrorCode.EXPIRED_CERTIFICATE.value


def test_revoked_certificate(chain_bundle):
    store = TrustStore(
        root_der_list=[chain_bundle["root_der"]],
        revoked_serials_hex={chain_bundle["leaf_serial_hex"]},
    )
    result = validate_rfc3161_certificate_chain(
        [chain_bundle["leaf_b64"], chain_bundle["int_b64"]],
        trust_store=store,
        at_time=chain_bundle["now"],
    )
    assert result.ok is False
    assert result.status == "invalid"
    assert result.error_code == ChainErrorCode.REVOKED_CERTIFICATE.value


def test_broken_chain_order(chain_bundle):
    store = TrustStore(root_der_list=[chain_bundle["root_der"]])
    # Swap leaf and intermediate → issuer/subject mismatch
    result = validate_rfc3161_certificate_chain(
        [chain_bundle["int_b64"], chain_bundle["leaf_b64"]],
        trust_store=store,
        at_time=chain_bundle["now"],
    )
    assert result.ok is False
    assert result.error_code == ChainErrorCode.CHAIN_ORDER_INVALID.value


def test_malformed_base64(chain_bundle):
    store = TrustStore(root_der_list=[chain_bundle["root_der"]])
    result = validate_rfc3161_certificate_chain(
        ["%%%not-base64%%%"],
        trust_store=store,
        at_time=chain_bundle["now"],
    )
    assert result.ok is False
    assert result.error_code == ChainErrorCode.MALFORMED_CERTIFICATE.value


def test_empty_chain(chain_bundle):
    store = TrustStore(root_der_list=[chain_bundle["root_der"]])
    result = validate_rfc3161_certificate_chain([], trust_store=store, at_time=chain_bundle["now"])
    assert result.ok is False
    assert result.error_code == ChainErrorCode.EMPTY_CHAIN.value


def test_oversized_chain(chain_bundle):
    store = TrustStore(root_der_list=[chain_bundle["root_der"]])
    huge = [chain_bundle["leaf_b64"]] * 20
    result = validate_rfc3161_certificate_chain(huge, trust_store=store, at_time=chain_bundle["now"])
    assert result.ok is False
    assert result.error_code == ChainErrorCode.OVERSIZED_CHAIN.value


def test_result_never_embeds_der(chain_bundle):
    store = TrustStore(root_der_list=[chain_bundle["root_der"]])
    result = validate_rfc3161_certificate_chain(
        [chain_bundle["leaf_b64"], chain_bundle["int_b64"]],
        trust_store=store,
        at_time=chain_bundle["now"],
    )
    blob = str(result.to_dict())
    assert "BEGIN CERTIFICATE" not in blob
    assert chain_bundle["leaf_b64"][:40] not in blob


def test_validate_chain_document_roundtrip(chain_bundle):
    doc = {
        "schemaVersion": 1,
        "atTime": "2024-06-01T00:00:00Z",
        "chain": [chain_bundle["leaf_b64"], chain_bundle["int_b64"]],
        "trustRoots": [chain_bundle["root_b64"]],
        "revokedSerials": [],
    }
    result = validate_chain_document(doc)
    assert result.ok is True
    assert result.status == "valid"


def test_trust_store_from_b64_roots(chain_bundle):
    store = trust_store_from_b64_roots([chain_bundle["root_b64"]], ["0xABC"])
    assert len(store.root_der_list) == 1
    assert "abc" in store.revoked_serials_hex
