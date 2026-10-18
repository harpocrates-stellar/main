"""RFC 3161 TSA certificate-chain validation for Harpocrates.

Validates X.509 chains that accompany RFC 3161 timestamp tokens against a
configured trust store. Designed for offline / CI use without contacting a live
TSA, CRL, or OCSP endpoint.

Privacy / safety:
- Failure responses use stable machine codes only.
- Never logs PEM/DER material, serial numbers in cleartext beyond truncated
  fingerprints, witness values, or private keys.
- Resource bounds prevent oversized chain inputs.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Sequence

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    _CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover - exercised via dependency-failure path
    x509 = None  # type: ignore[assignment]
    InvalidSignature = Exception  # type: ignore[misc, assignment]
    _CRYPTO_AVAILABLE = False


# ── Bounds / constants ─────────────────────────────────────────────────────

MAX_CERTS_PER_CHAIN = 8
MAX_CERT_DER_BYTES = 8_192
MAX_CHAIN_TOTAL_BYTES = 32_768
MAX_TRUST_STORE_ROOTS = 64
FINGERPRINT_HEX_LEN = 64  # SHA-256

SUPPORTED_HASH_OIDS = {
    "1.2.840.113549.1.1.11",  # sha256WithRSAEncryption
    "1.2.840.113549.1.1.12",  # sha384WithRSAEncryption
    "1.2.840.113549.1.1.13",  # sha512WithRSAEncryption
    "1.2.840.10045.4.3.2",    # ecdsa-with-SHA256
    "1.2.840.10045.4.3.3",    # ecdsa-with-SHA384
    "1.2.840.10045.4.3.4",    # ecdsa-with-SHA512
}


class ChainErrorCode(str, Enum):
    """Stable, privacy-safe chain validation failure codes."""

    DEPENDENCY_FAILURE = "dependency_failure"
    EMPTY_CHAIN = "empty_chain"
    OVERSIZED_CHAIN = "oversized_chain"
    MALFORMED_CERTIFICATE = "malformed_certificate"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
    CHAIN_ORDER_INVALID = "chain_order_invalid"
    EXPIRED_CERTIFICATE = "expired_certificate"
    NOT_YET_VALID = "not_yet_valid"
    REVOKED_CERTIFICATE = "revoked_certificate"
    UNTRUSTED_ROOT = "untrusted_root"
    SIGNATURE_INVALID = "signature_invalid"


@dataclass(frozen=True)
class ChainValidationResult:
    """Outcome of validating one TSA certificate chain."""

    ok: bool
    status: str  # mirrors VerificationStatus: valid|invalid|unverified|expired|untrusted
    error_code: str | None = None
    error_message: str | None = None
    leaf_fingerprint: str | None = None
    root_fingerprint: str | None = None
    depth: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status,
            "errorCode": self.error_code,
            "errorMessage": self.error_message,
            "leafFingerprint": self.leaf_fingerprint,
            "rootFingerprint": self.root_fingerprint,
            "depth": self.depth,
        }


@dataclass
class TrustStore:
    """Configured trust roots and optional revocation serials (hex lowercase)."""

    root_der_list: list[bytes] = field(default_factory=list)
    revoked_serials_hex: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if len(self.root_der_list) > MAX_TRUST_STORE_ROOTS:
            raise ValueError("trust store exceeds maximum root count")

    @property
    def root_fingerprints(self) -> set[str]:
        return {_fingerprint_der(der) for der in self.root_der_list}

    def root_by_fingerprint(self) -> dict[str, bytes]:
        return {_fingerprint_der(der): der for der in self.root_der_list}


def _fingerprint_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _fail(
    status: str,
    code: ChainErrorCode,
    message: str,
    *,
    leaf_fp: str | None = None,
    root_fp: str | None = None,
    depth: int = 0,
) -> ChainValidationResult:
    return ChainValidationResult(
        ok=False,
        status=status,
        error_code=code.value,
        error_message=message,
        leaf_fingerprint=leaf_fp,
        root_fingerprint=root_fp,
        depth=depth,
    )


def _decode_cert_entries(entries: Sequence[str]) -> tuple[list[bytes] | None, ChainValidationResult | None]:
    if not entries:
        return None, _fail("invalid", ChainErrorCode.EMPTY_CHAIN, "certificate chain is empty")

    if len(entries) > MAX_CERTS_PER_CHAIN:
        return None, _fail(
            "invalid",
            ChainErrorCode.OVERSIZED_CHAIN,
            f"certificate chain exceeds {MAX_CERTS_PER_CHAIN} certificates",
        )

    ders: list[bytes] = []
    total = 0
    for raw in entries:
        if not isinstance(raw, str) or not raw:
            return None, _fail(
                "invalid",
                ChainErrorCode.MALFORMED_CERTIFICATE,
                "certificate entry must be a non-empty base64 string",
            )
        try:
            der = base64.b64decode(raw, validate=True)
        except Exception:
            return None, _fail(
                "invalid",
                ChainErrorCode.MALFORMED_CERTIFICATE,
                "certificate entry is not valid base64",
            )
        if len(der) > MAX_CERT_DER_BYTES:
            return None, _fail(
                "invalid",
                ChainErrorCode.OVERSIZED_CHAIN,
                f"certificate exceeds {MAX_CERT_DER_BYTES} bytes",
            )
        total += len(der)
        if total > MAX_CHAIN_TOTAL_BYTES:
            return None, _fail(
                "invalid",
                ChainErrorCode.OVERSIZED_CHAIN,
                f"certificate chain exceeds {MAX_CHAIN_TOTAL_BYTES} bytes total",
            )
        ders.append(der)
    return ders, None


def _load_cert(der: bytes) -> tuple[Any | None, ChainValidationResult | None]:
    assert x509 is not None
    try:
        return x509.load_der_x509_certificate(der), None
    except Exception:
        return None, _fail(
            "invalid",
            ChainErrorCode.MALFORMED_CERTIFICATE,
            "certificate DER could not be parsed",
        )


def _check_algorithm(cert: Any) -> ChainValidationResult | None:
    oid = cert.signature_algorithm_oid.dotted_string
    if oid not in SUPPORTED_HASH_OIDS:
        return _fail(
            "untrusted",
            ChainErrorCode.UNSUPPORTED_ALGORITHM,
            "certificate uses an unsupported signature algorithm",
        )
    return None


def _cert_der(cert: Any) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding

    return cert.public_bytes(Encoding.DER)


def _verify_signature(issuer: Any, subject: Any) -> bool:
    pub = issuer.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                subject.signature,
                subject.tbs_certificate_bytes,
                padding.PKCS1v15(),
                subject.signature_hash_algorithm,
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(
                subject.signature,
                subject.tbs_certificate_bytes,
                ec.ECDSA(subject.signature_hash_algorithm),
            )
        else:
            return False
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def _validity_at(cert: Any, at_time: datetime) -> ChainValidationResult | None:
    # cryptography 42+ uses aware UTC properties; fall back for older APIs.
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # pragma: no cover
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    if at_time < not_before:
        return _fail(
            "invalid",
            ChainErrorCode.NOT_YET_VALID,
            "certificate is not yet valid at evaluation time",
        )
    if at_time > not_after:
        return _fail(
            "expired",
            ChainErrorCode.EXPIRED_CERTIFICATE,
            "certificate expired at evaluation time",
        )
    return None


def validate_rfc3161_certificate_chain(
    chain_b64: Sequence[str],
    *,
    trust_store: TrustStore,
    at_time: datetime | None = None,
) -> ChainValidationResult:
    """Validate a leaf-first X.509 chain against the trust store.

    ``chain_b64`` is base64-encoded DER certificates, leaf first, optionally
    including the trust anchor as the final element.

    ``at_time`` defaults to current UTC and should be the RFC 3161 genTime when
    verifying a timestamp token (expiry is evaluated at timestamp generation).
    """
    if not _CRYPTO_AVAILABLE:
        return _fail(
            "unverified",
            ChainErrorCode.DEPENDENCY_FAILURE,
            "cryptography dependency unavailable for chain validation",
        )

    if at_time is None:
        at_time = datetime.now(timezone.utc)
    elif at_time.tzinfo is None:
        at_time = at_time.replace(tzinfo=timezone.utc)

    ders, err = _decode_cert_entries(chain_b64)
    if err is not None:
        return err
    assert ders is not None

    certs: list[Any] = []
    for der in ders:
        cert, cerr = _load_cert(der)
        if cerr is not None:
            return cerr
        assert cert is not None
        alg_err = _check_algorithm(cert)
        if alg_err is not None:
            # attach fingerprint for leaf when possible
            leaf_fp = _fingerprint_der(ders[0]) if ders else None
            return ChainValidationResult(
                ok=False,
                status=alg_err.status,
                error_code=alg_err.error_code,
                error_message=alg_err.error_message,
                leaf_fingerprint=leaf_fp,
                depth=len(certs),
            )
        certs.append(cert)

    leaf_fp = _fingerprint_der(ders[0])
    depth = len(certs)

    # Validity windows at evaluation time
    for cert in certs:
        verr = _validity_at(cert, at_time)
        if verr is not None:
            return ChainValidationResult(
                ok=False,
                status=verr.status,
                error_code=verr.error_code,
                error_message=verr.error_message,
                leaf_fingerprint=leaf_fp,
                depth=depth,
            )

    # Revocation (offline serial list standing in for CRL/OCSP)
    for cert in certs:
        serial_hex = format(cert.serial_number, "x")
        if serial_hex in trust_store.revoked_serials_hex:
            return _fail(
                "invalid",
                ChainErrorCode.REVOKED_CERTIFICATE,
                "certificate serial is present in revocation set",
                leaf_fp=leaf_fp,
                depth=depth,
            )

    # Chain order: each subject must be signed by the next issuer (or self for root)
    for i in range(len(certs) - 1):
        subject = certs[i]
        issuer = certs[i + 1]
        if subject.issuer != issuer.subject:
            return _fail(
                "invalid",
                ChainErrorCode.CHAIN_ORDER_INVALID,
                "certificate issuer/subject linkage is broken",
                leaf_fp=leaf_fp,
                depth=depth,
            )
        if not _verify_signature(issuer, subject):
            return _fail(
                "invalid",
                ChainErrorCode.SIGNATURE_INVALID,
                "certificate signature verification failed",
                leaf_fp=leaf_fp,
                depth=depth,
            )

    # Resolve trust anchor: last cert may be a trusted root, or its issuer must be
    root_candidates = trust_store.root_by_fingerprint()
    last = certs[-1]
    last_der = ders[-1]
    last_fp = _fingerprint_der(last_der)

    matched_root_fp: str | None = None

    if last_fp in root_candidates:
        # Chain includes the trust anchor
        if last.issuer == last.subject:
            if not _verify_signature(last, last):
                return _fail(
                    "invalid",
                    ChainErrorCode.SIGNATURE_INVALID,
                    "trust anchor self-signature verification failed",
                    leaf_fp=leaf_fp,
                    root_fp=last_fp,
                    depth=depth,
                )
        matched_root_fp = last_fp
    else:
        # Find a trusted root that issued the last certificate
        found = False
        for root_fp, root_der in root_candidates.items():
            root_cert, rerr = _load_cert(root_der)
            if rerr is not None or root_cert is None:
                continue
            if last.issuer != root_cert.subject:
                continue
            if not _verify_signature(root_cert, last):
                continue
            # Root validity at evaluation time
            rvalid = _validity_at(root_cert, at_time)
            if rvalid is not None:
                return ChainValidationResult(
                    ok=False,
                    status=rvalid.status,
                    error_code=rvalid.error_code,
                    error_message=rvalid.error_message,
                    leaf_fingerprint=leaf_fp,
                    root_fingerprint=root_fp,
                    depth=depth,
                )
            matched_root_fp = root_fp
            found = True
            break
        if not found:
            return _fail(
                "untrusted",
                ChainErrorCode.UNTRUSTED_ROOT,
                "certificate chain does not terminate at a configured trust root",
                leaf_fp=leaf_fp,
                depth=depth,
            )

    return ChainValidationResult(
        ok=True,
        status="valid",
        error_code=None,
        error_message=None,
        leaf_fingerprint=leaf_fp,
        root_fingerprint=matched_root_fp,
        depth=depth,
    )


def trust_store_from_b64_roots(
    roots_b64: Iterable[str],
    revoked_serials_hex: Iterable[str] | None = None,
) -> TrustStore:
    """Build a TrustStore from base64 DER roots and optional revoked serials."""
    ders: list[bytes] = []
    for raw in roots_b64:
        if not isinstance(raw, str) or not raw:
            raise ValueError("trust root must be a non-empty base64 string")
        der = base64.b64decode(raw, validate=True)
        if len(der) > MAX_CERT_DER_BYTES:
            raise ValueError("trust root exceeds maximum certificate size")
        ders.append(der)
    revoked = {s.lower().lstrip("0x") for s in (revoked_serials_hex or []) if s}
    return TrustStore(root_der_list=ders, revoked_serials_hex=revoked)


def validate_chain_document(doc: dict[str, Any]) -> ChainValidationResult:
    """Validate a JSON chain document used by fixtures / CI.

    Expected shape (no secrets / media)::

        {
          "schemaVersion": 1,
          "atTime": "2024-01-01T00:00:00Z",   # optional ISO-8601
          "chain": ["base64-der-leaf", "..."],
          "trustRoots": ["base64-der-root", ...],
          "revokedSerials": ["abc123", ...]     # optional
        }
    """
    if not isinstance(doc, dict):
        return _fail("invalid", ChainErrorCode.MALFORMED_CERTIFICATE, "document must be a JSON object")

    if doc.get("schemaVersion") != 1:
        return _fail(
            "invalid",
            ChainErrorCode.MALFORMED_CERTIFICATE,
            "schemaVersion must be 1",
        )

    chain = doc.get("chain")
    roots = doc.get("trustRoots")
    if not isinstance(chain, list) or not isinstance(roots, list):
        return _fail(
            "invalid",
            ChainErrorCode.MALFORMED_CERTIFICATE,
            "chain and trustRoots must be arrays",
        )

    at_time = None
    raw_at = doc.get("atTime")
    if raw_at is not None:
        if not isinstance(raw_at, str):
            return _fail("invalid", ChainErrorCode.MALFORMED_CERTIFICATE, "atTime must be an ISO-8601 string")
        try:
            at_time = datetime.fromisoformat(raw_at.replace("Z", "+00:00"))
        except ValueError:
            return _fail("invalid", ChainErrorCode.MALFORMED_CERTIFICATE, "atTime is not valid ISO-8601")

    try:
        store = trust_store_from_b64_roots(roots, doc.get("revokedSerials") or [])
    except Exception:
        return _fail(
            "invalid",
            ChainErrorCode.MALFORMED_CERTIFICATE,
            "trustRoots could not be decoded",
        )

    return validate_rfc3161_certificate_chain(chain, trust_store=store, at_time=at_time)
