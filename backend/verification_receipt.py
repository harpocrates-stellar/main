"""Validation for the canonical verification-receipt contract and offline evidence bundles.

The frontend owns receipt signing (`harpocrates-verification-receipt` v1). The
backend builds canonical unsigned receipt inputs and also supports versioned
offline-verifiable receipt evidence bundles (`harpocrates-receipt-evidence-bundle`
v1) binding a signed receipt, a public trust snapshot, and a chain observation
digest without requiring API tokens or sensitive media.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Literal, Mapping, TypedDict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from time_attestation import (
    compute_chain_observation_digest,
    decode_time_attestation,
    normalize_chain_observation,
    validate_time_attestation_at,
    verify_rfc3161_anchors,
)

RECEIPT_PROTOCOL = "harpocrates-verification-receipt"
RECEIPT_VERSION = 1
RECEIPT_ALGORITHM = "ECDSA_P256_SHA256"
MAX_RECEIPT_BYTES = 8_192

EVIDENCE_BUNDLE_PROTOCOL = "harpocrates-receipt-evidence-bundle"
EVIDENCE_BUNDLE_VERSION = 1
SUPPORTED_EVIDENCE_BUNDLE_VERSIONS = frozenset({1})
MAX_EVIDENCE_BUNDLE_BYTES = 65_536

RECEIPT_DIGEST_DOMAIN = "harpocrates-signed-receipt/v1"
TRUST_SNAPSHOT_DOMAIN = "harpocrates-trust-snapshot/v1"
EVIDENCE_BUNDLE_DOMAIN = "harpocrates-receipt-evidence-bundle/v1"

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_FORBIDDEN_KEY_NAMES = frozenset(
    {
        "apitoken",
        "api_token",
        "apikey",
        "api_key",
        "authorization",
        "bearer",
        "bearer_token",
        "access_token",
        "metrics_token",
        "secret",
        "secret_key",
        "private_key",
        "privatekey",
        "d",
        "media",
        "mediabytes",
        "media_bytes",
        "videobytes",
        "video_bytes",
        "rawmedia",
        "raw_media",
        "filepath",
        "file_path",
        "witness",
        "privateinputs",
        "private_inputs",
    }
)
_FORBIDDEN_VALUE_MARKERS = (
    "-----BEGIN " + "PRIVATE KEY-----",
    "-----BEGIN EC " + "PRIVATE KEY-----",
    "data:video/",
    "data:image/",
    "data:audio/",
    "data:application/octet-stream",
)


class VerificationReceiptInput(TypedDict):
    """Unsigned fields consumed by the frontend receipt signer."""

    result: Literal["verified", "unverified"]
    verifiedAt: str
    proofId: str
    videoHash: str
    metadataHash: str
    tier: Literal["silent", "source", "seal"]
    networkPassphrase: str
    contractId: str
    ledgerSequence: int | None
    transactionHash: str | None
    circuitVersion: str
    verifierVersion: str


class EvidenceBundleBindings(TypedDict):
    """Domain-separated cryptographic digests binding bundle components."""

    receiptDigest: str
    trustSnapshotDigest: str
    chainObservationDigest: str
    bundleDigest: str


def build_verification_receipt(
    context: Mapping[str, object],
    *,
    result: Literal["verified", "unverified"] = "unverified",
) -> VerificationReceiptInput:
    """Validate and build the canonical unsigned receipt input.

    A receipt is only emitted when the caller supplies the complete canonical
    evidence context. This prevents the selective-disclosure endpoint from
    inventing proof IDs or hashes from unrelated request fields.
    """

    return {
        "result": result,
        "verifiedAt": datetime.now(timezone.utc).isoformat(),
        "proofId": _hex32(context.get("proofId"), "proofId"),
        "videoHash": _hex32(context.get("videoHash"), "videoHash"),
        "metadataHash": _hex32(context.get("metadataHash"), "metadataHash"),
        "tier": _choice(context.get("tier"), "tier", ("silent", "source", "seal")),
        "networkPassphrase": _text(context.get("networkPassphrase"), "networkPassphrase"),
        "contractId": _text(context.get("contractId"), "contractId"),
        "ledgerSequence": _optional_int(context.get("ledgerSequence"), "ledgerSequence"),
        "transactionHash": _optional_hex32(context.get("transactionHash"), "transactionHash"),
        "circuitVersion": _text(context.get("circuitVersion"), "circuitVersion"),
        "verifierVersion": _text(context.get("verifierVersion"), "verifierVersion"),
    }


def canonicalize_json(value: Any) -> str:
    """Serialize JSON values deterministically with lexicographically sorted keys."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def compute_signed_receipt_digest(receipt: Mapping[str, object]) -> str:
    """Compute domain-separated SHA-256 digest of a signed verification receipt."""
    normalized = _normalize_signed_receipt(receipt)
    payload = RECEIPT_DIGEST_DOMAIN.encode("utf-8") + b":" + canonicalize_json(normalized).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def normalize_trust_snapshot(trust_snapshot: Mapping[str, object]) -> dict[str, Any]:
    """Validate and normalize a public-only trust snapshot for offline verification."""
    if not isinstance(trust_snapshot, Mapping):
        raise ValueError("trustSnapshot must be an object")
    _assert_no_sensitive_material(trust_snapshot, path="trustSnapshot")

    captured_at_raw = trust_snapshot.get("capturedAt")
    captured_dt = _parse_utc_iso(captured_at_raw, "trustSnapshot.capturedAt")
    captured_at = captured_dt.isoformat().replace("+00:00", "Z")

    keys_raw = trust_snapshot.get("keys")
    if not isinstance(keys_raw, Mapping) or len(keys_raw) == 0:
        raise ValueError("trustSnapshot.keys must be a non-empty map of public JWKs")

    normalized_keys: dict[str, dict[str, Any]] = {}
    for key_id, jwk in sorted(keys_raw.items(), key=lambda item: str(item[0])):
        key_name = _text(key_id, "trustSnapshot.keys.keyId")
        if not isinstance(jwk, Mapping):
            raise ValueError(f"trustSnapshot.keys[{key_name}] must be a JWK object")
        _assert_no_sensitive_material(jwk, path=f"trustSnapshot.keys[{key_name}]")
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            raise ValueError(f"trustSnapshot.keys[{key_name}] must be an EC P-256 public JWK")
        x_b64 = _text(jwk.get("x"), f"trustSnapshot.keys[{key_name}].x")
        y_b64 = _text(jwk.get("y"), f"trustSnapshot.keys[{key_name}].y")
        x_bytes = _b64url_decode(x_b64, f"trustSnapshot.keys[{key_name}].x")
        y_bytes = _b64url_decode(y_b64, f"trustSnapshot.keys[{key_name}].y")
        if len(x_bytes) != 32 or len(y_bytes) != 32:
            raise ValueError(f"trustSnapshot.keys[{key_name}] coordinates must be 32 bytes")
        # Confirm valid P-256 curve point
        ec.EllipticCurvePublicNumbers(
            int.from_bytes(x_bytes, "big"),
            int.from_bytes(y_bytes, "big"),
            ec.SECP256R1(),
        ).public_key()
        normalized_jwk: dict[str, Any] = {
            "crv": "P-256",
            "kty": "EC",
            "x": x_b64,
            "y": y_b64,
        }
        if "ext" in jwk and isinstance(jwk["ext"], bool):
            normalized_jwk["ext"] = jwk["ext"]
        if "key_ops" in jwk and isinstance(jwk["key_ops"], list):
            if any(op != "verify" for op in jwk["key_ops"]):
                raise ValueError(
                    f"trustSnapshot.keys[{key_name}].key_ops may only include 'verify'"
                )
            normalized_jwk["key_ops"] = ["verify"]
        normalized_keys[key_name] = normalized_jwk

    normalized_validity: dict[str, dict[str, str]] = {}
    validity_raw = trust_snapshot.get("keyValidity")
    if validity_raw is not None:
        if not isinstance(validity_raw, Mapping):
            raise ValueError("trustSnapshot.keyValidity must be an object when provided")
        for key_id, window in sorted(validity_raw.items(), key=lambda item: str(item[0])):
            key_name = _text(key_id, "trustSnapshot.keyValidity.keyId")
            if not isinstance(window, Mapping):
                raise ValueError(f"trustSnapshot.keyValidity[{key_name}] must be an object")
            entry: dict[str, str] = {}
            if window.get("notBefore") is not None:
                nb_dt = _parse_utc_iso(
                    window.get("notBefore"),
                    f"trustSnapshot.keyValidity[{key_name}].notBefore",
                )
                entry["notBefore"] = nb_dt.isoformat().replace("+00:00", "Z")
            if window.get("notAfter") is not None:
                na_dt = _parse_utc_iso(
                    window.get("notAfter"),
                    f"trustSnapshot.keyValidity[{key_name}].notAfter",
                )
                entry["notAfter"] = na_dt.isoformat().replace("+00:00", "Z")
            if "notBefore" in entry and "notAfter" in entry:
                if _parse_utc_iso(entry["notBefore"], "notBefore") > _parse_utc_iso(
                    entry["notAfter"], "notAfter"
                ):
                    raise ValueError(
                        f"trustSnapshot.keyValidity[{key_name}] has notBefore after notAfter"
                    )
            if window.get("status") is not None:
                entry["status"] = _choice(
                    window.get("status"),
                    f"trustSnapshot.keyValidity[{key_name}].status",
                    ("active", "retired", "revoked"),
                )
            normalized_validity[key_name] = entry

    normalized: dict[str, Any] = {
        "capturedAt": captured_at,
        "keys": normalized_keys,
    }
    if normalized_validity:
        normalized["keyValidity"] = normalized_validity

    policy_version = trust_snapshot.get("policyVersion")
    if policy_version is not None:
        normalized["policyVersion"] = _text(policy_version, "trustSnapshot.policyVersion")

    tsa_roots = trust_snapshot.get("tsaTrustRootsB64")
    if tsa_roots is not None:
        if not isinstance(tsa_roots, list) or not all(
            isinstance(item, str) and bool(item.strip()) for item in tsa_roots
        ):
            raise ValueError("trustSnapshot.tsaTrustRootsB64 must be a list of base64 strings")
        normalized["tsaTrustRootsB64"] = list(tsa_roots)

    revoked_tsa_serials = trust_snapshot.get("revokedTsaSerialsHex")
    if revoked_tsa_serials is not None:
        if not isinstance(revoked_tsa_serials, list) or not all(
            isinstance(item, str) and bool(item.strip()) for item in revoked_tsa_serials
        ):
            raise ValueError("trustSnapshot.revokedTsaSerialsHex must be a list of hex strings")
        normalized["revokedTsaSerialsHex"] = [item.lower() for item in revoked_tsa_serials]

    return normalized


def compute_trust_snapshot_digest(trust_snapshot: Mapping[str, object]) -> str:
    """Compute domain-separated SHA-256 digest of a normalized trust snapshot."""
    normalized = normalize_trust_snapshot(trust_snapshot)
    payload = TRUST_SNAPSHOT_DOMAIN.encode("utf-8") + b":" + canonicalize_json(normalized).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def compute_evidence_bundle_digest(
    *,
    protocol: str,
    version: int,
    bundled_at: str,
    receipt_digest: str,
    trust_snapshot_digest: str,
    chain_observation_digest: str,
) -> str:
    """Compute domain-separated SHA-256 digest binding receipt, trust snapshot, and chain observation."""
    envelope = {
        "protocol": protocol,
        "version": version,
        "bundledAt": bundled_at,
        "receiptDigest": _hex32(receipt_digest, "receiptDigest"),
        "trustSnapshotDigest": _hex32(trust_snapshot_digest, "trustSnapshotDigest"),
        "chainObservationDigest": _hex32(chain_observation_digest, "chainObservationDigest"),
    }
    payload = EVIDENCE_BUNDLE_DOMAIN.encode("utf-8") + b":" + canonicalize_json(envelope).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def verify_signed_verification_receipt(
    receipt: Mapping[str, object],
    *,
    keys: Mapping[str, Mapping[str, object]],
    key_validity: Mapping[str, Mapping[str, object]] | None = None,
    expected_network_passphrase: str | None = None,
    expected_proof_id: str | None = None,
    now: datetime | str | None = None,
    enforce_active_key_at_now: bool = False,
) -> dict[str, Any]:
    """Verify a signed verification receipt offline against public ECDSA P-256 JWKs."""
    try:
        _assert_no_sensitive_material(receipt, path="receipt")
        canonical_bytes = canonicalize_json(receipt).encode("utf-8")
        if len(canonical_bytes) > MAX_RECEIPT_BYTES:
            return {"valid": False, "code": "RECEIPT_OVERSIZED", "reason": "receipt exceeds the size limit"}

        normalized = _normalize_signed_receipt(receipt)
        if (
            expected_network_passphrase is not None
            and normalized["networkPassphrase"] != expected_network_passphrase
        ):
            return {
                "valid": False,
                "code": "NETWORK_MISMATCH",
                "reason": "receipt network does not match the expected network",
            }
        if expected_proof_id is not None and normalized["proofId"] != expected_proof_id.lower():
            return {
                "valid": False,
                "code": "PROOF_MISMATCH",
                "reason": "receipt proof does not match the expected proof",
            }

        key_id = normalized["signer"]["keyId"]
        jwk = keys.get(key_id)
        if not isinstance(jwk, Mapping):
            return {"valid": False, "code": "UNKNOWN_SIGNER_KEY", "reason": "signer key is unknown"}

        verified_at_dt = _parse_utc_iso(normalized["verifiedAt"], "receipt.verifiedAt")
        if key_validity is not None and key_id in key_validity:
            window = key_validity[key_id]
            if window.get("status") == "revoked":
                return {
                    "valid": False,
                    "code": "SIGNER_KEY_REVOKED",
                    "reason": "receipt signer key is revoked in trust snapshot",
                }
            if window.get("notBefore") is not None:
                nb_dt = _parse_utc_iso(window["notBefore"], "notBefore")
                if verified_at_dt < nb_dt:
                    return {
                        "valid": False,
                        "code": "SIGNER_KEY_WINDOW_INVALID",
                        "reason": "receipt signer key was not yet valid at verification time",
                    }
            if window.get("notAfter") is not None:
                na_dt = _parse_utc_iso(window["notAfter"], "notAfter")
                if verified_at_dt > na_dt:
                    return {
                        "valid": False,
                        "code": "SIGNER_KEY_WINDOW_INVALID",
                        "reason": "receipt signer key had expired before verification time",
                    }
                if enforce_active_key_at_now and now is not None:
                    now_dt = (
                        now.astimezone(timezone.utc)
                        if isinstance(now, datetime)
                        else _parse_utc_iso(now, "now")
                    )
                    if now_dt > na_dt:
                        return {
                            "valid": False,
                            "code": "SIGNER_KEY_WINDOW_INVALID",
                            "reason": "receipt signer key is stale at evaluation time",
                        }

        x_bytes = _b64url_decode(_text(jwk.get("x"), "jwk.x"), "jwk.x")
        y_bytes = _b64url_decode(_text(jwk.get("y"), "jwk.y"), "jwk.y")
        if len(x_bytes) != 32 or len(y_bytes) != 32:
            return {"valid": False, "code": "INVALID_SIGNER_KEY", "reason": "signer public key is malformed"}
        public_key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x_bytes, "big"),
            int.from_bytes(y_bytes, "big"),
            ec.SECP256R1(),
        ).public_key()

        sig_bytes = _b64url_decode(normalized["signature"], "receipt.signature")
        if len(sig_bytes) != 64:
            return {"valid": False, "code": "INVALID_SIGNATURE", "reason": "receipt signature is invalid"}
        r_int = int.from_bytes(sig_bytes[:32], "big")
        s_int = int.from_bytes(sig_bytes[32:], "big")
        der_sig = utils.encode_dss_signature(r_int, s_int)

        unsigned_payload = dict(normalized)
        unsigned_payload.pop("signature", None)
        unsigned_bytes = canonicalize_json(unsigned_payload).encode("utf-8")

        public_key.verify(der_sig, unsigned_bytes, ec.ECDSA(hashes.SHA256()))
        return {"valid": True, "code": "VALID", "reason": None, "receipt": normalized}
    except InvalidSignature:
        return {"valid": False, "code": "INVALID_SIGNATURE", "reason": "receipt signature is invalid"}
    except ValueError as exc:
        code = "SENSITIVE_MATERIAL_REJECTED" if "sensitive or credential" in str(exc) else "MALFORMED_RECEIPT"
        return {"valid": False, "code": code, "reason": str(exc)}


def build_receipt_evidence_bundle(
    *,
    receipt: Mapping[str, object],
    trust_snapshot: Mapping[str, object],
    chain_observation: Mapping[str, object],
    bundled_at: str | None = None,
) -> dict[str, Any]:
    """Build a versioned verification receipt evidence bundle ready for offline verification."""
    _assert_no_sensitive_material(receipt, path="receipt")
    _assert_no_sensitive_material(trust_snapshot, path="trustSnapshot")
    _assert_no_sensitive_material(chain_observation, path="chainObservation")

    normalized_receipt = _normalize_signed_receipt(receipt)
    normalized_snapshot = normalize_trust_snapshot(trust_snapshot)
    normalized_observation = normalize_chain_observation(chain_observation)

    bundled_dt = (
        datetime.now(timezone.utc)
        if bundled_at is None
        else _parse_utc_iso(bundled_at, "bundledAt")
    )
    normalized_bundled_at = bundled_dt.isoformat().replace("+00:00", "Z")

    receipt_digest = compute_signed_receipt_digest(normalized_receipt)
    trust_snapshot_digest = compute_trust_snapshot_digest(normalized_snapshot)
    chain_observation_digest = compute_chain_observation_digest(normalized_observation)
    bundle_digest = compute_evidence_bundle_digest(
        protocol=EVIDENCE_BUNDLE_PROTOCOL,
        version=EVIDENCE_BUNDLE_VERSION,
        bundled_at=normalized_bundled_at,
        receipt_digest=receipt_digest,
        trust_snapshot_digest=trust_snapshot_digest,
        chain_observation_digest=chain_observation_digest,
    )

    bundle: dict[str, Any] = {
        "protocol": EVIDENCE_BUNDLE_PROTOCOL,
        "version": EVIDENCE_BUNDLE_VERSION,
        "bundledAt": normalized_bundled_at,
        "receipt": normalized_receipt,
        "trustSnapshot": normalized_snapshot,
        "chainObservation": normalized_observation,
        "bindings": {
            "receiptDigest": receipt_digest,
            "trustSnapshotDigest": trust_snapshot_digest,
            "chainObservationDigest": chain_observation_digest,
            "bundleDigest": bundle_digest,
        },
    }

    verification = verify_receipt_evidence_bundle(bundle)
    if not verification["valid"]:
        raise ValueError(
            f"Cannot build invalid receipt evidence bundle ({verification['code']}): {verification['reason']}"
        )
    return bundle


def serialize_receipt_evidence_bundle(bundle: Mapping[str, object]) -> str:
    """Serialize a verified receipt evidence bundle to canonical JSON."""
    verification = verify_receipt_evidence_bundle(bundle)
    if not verification["valid"]:
        raise ValueError(
            f"Cannot serialize invalid receipt evidence bundle ({verification['code']}): {verification['reason']}"
        )
    serialized = canonicalize_json(bundle)
    if len(serialized.encode("utf-8")) > MAX_EVIDENCE_BUNDLE_BYTES:
        raise ValueError("evidence bundle exceeds the size limit")
    return serialized


def verify_receipt_evidence_bundle(
    bundle: Mapping[str, object] | str | bytes,
    *,
    expected_network_passphrase: str | None = None,
    expected_proof_id: str | None = None,
    trusted_snapshot_digest: str | None = None,
    now: datetime | str | None = None,
    enforce_active_key_at_now: bool = False,
) -> dict[str, Any]:
    """Verify a versioned receipt evidence bundle completely offline.

    Requires zero API tokens, zero network calls, zero database connections,
    and zero media bytes. Rejects any bundle carrying credentials, private keys,
    witness data, or sensitive media fail-closed.
    """
    try:
        if isinstance(bundle, bytes):
            if len(bundle) > MAX_EVIDENCE_BUNDLE_BYTES:
                return _invalid_bundle("BUNDLE_OVERSIZED", "evidence bundle exceeds the size limit")
            parsed = json.loads(bundle.decode("utf-8"))
        elif isinstance(bundle, str):
            if len(bundle.encode("utf-8")) > MAX_EVIDENCE_BUNDLE_BYTES:
                return _invalid_bundle("BUNDLE_OVERSIZED", "evidence bundle exceeds the size limit")
            parsed = json.loads(bundle)
        elif isinstance(bundle, Mapping):
            parsed = dict(bundle)
        else:
            return _invalid_bundle("MALFORMED_BUNDLE", "evidence bundle must be a JSON object")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _invalid_bundle("MALFORMED_BUNDLE", f"invalid evidence bundle JSON: {exc}")

    if not isinstance(parsed, Mapping):
        return _invalid_bundle("MALFORMED_BUNDLE", "evidence bundle must be a JSON object")

    try:
        _assert_no_sensitive_material(parsed, path="bundle")
    except ValueError as exc:
        return _invalid_bundle("SENSITIVE_MATERIAL_REJECTED", str(exc))

    try:
        serialized_len = len(canonicalize_json(parsed).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        return _invalid_bundle("MALFORMED_BUNDLE", f"bundle contains non-JSON values: {exc}")
    if serialized_len > MAX_EVIDENCE_BUNDLE_BYTES:
        return _invalid_bundle("BUNDLE_OVERSIZED", "evidence bundle exceeds the size limit")

    protocol = parsed.get("protocol")
    version = parsed.get("version")
    if (
        protocol != EVIDENCE_BUNDLE_PROTOCOL
        or isinstance(version, bool)
        or not isinstance(version, int)
        or version not in SUPPORTED_EVIDENCE_BUNDLE_VERSIONS
    ):
        return _invalid_bundle(
            "UNSUPPORTED_BUNDLE_VERSION",
            f"unsupported evidence bundle protocol or version: {protocol!r} v{version!r}",
        )

    try:
        bundled_dt = _parse_utc_iso(parsed.get("bundledAt"), "bundledAt")
        normalized_bundled_at = bundled_dt.isoformat().replace("+00:00", "Z")
    except ValueError as exc:
        return _invalid_bundle("MALFORMED_BUNDLE", str(exc))

    bindings_raw = parsed.get("bindings")
    if not isinstance(bindings_raw, Mapping):
        return _invalid_bundle("MALFORMED_BUNDLE", "bindings must be an object")

    try:
        claimed_receipt_digest = _hex32(bindings_raw.get("receiptDigest"), "bindings.receiptDigest")
        claimed_snapshot_digest = _hex32(
            bindings_raw.get("trustSnapshotDigest"), "bindings.trustSnapshotDigest"
        )
        claimed_observation_digest = _hex32(
            bindings_raw.get("chainObservationDigest"), "bindings.chainObservationDigest"
        )
        claimed_bundle_digest = _hex32(bindings_raw.get("bundleDigest"), "bindings.bundleDigest")
    except ValueError as exc:
        return _invalid_bundle("MALFORMED_BUNDLE", str(exc))

    receipt_raw = parsed.get("receipt")
    snapshot_raw = parsed.get("trustSnapshot")
    observation_raw = parsed.get("chainObservation")
    if not isinstance(receipt_raw, Mapping):
        return _invalid_bundle("MALFORMED_BUNDLE", "receipt must be an object")
    if not isinstance(snapshot_raw, Mapping):
        return _invalid_bundle("MALFORMED_BUNDLE", "trustSnapshot must be an object")
    if not isinstance(observation_raw, Mapping):
        return _invalid_bundle("MALFORMED_BUNDLE", "chainObservation must be an object")

    try:
        normalized_receipt = _normalize_signed_receipt(receipt_raw)
        normalized_snapshot = normalize_trust_snapshot(snapshot_raw)
        normalized_observation = normalize_chain_observation(observation_raw)
    except ValueError as exc:
        return _invalid_bundle("MALFORMED_BUNDLE", str(exc))

    actual_receipt_digest = compute_signed_receipt_digest(normalized_receipt)
    actual_snapshot_digest = compute_trust_snapshot_digest(normalized_snapshot)
    actual_observation_digest = compute_chain_observation_digest(normalized_observation)
    actual_bundle_digest = compute_evidence_bundle_digest(
        protocol=EVIDENCE_BUNDLE_PROTOCOL,
        version=version,
        bundled_at=normalized_bundled_at,
        receipt_digest=actual_receipt_digest,
        trust_snapshot_digest=actual_snapshot_digest,
        chain_observation_digest=actual_observation_digest,
    )

    if not hmac.compare_digest(actual_receipt_digest, claimed_receipt_digest):
        return _invalid_bundle(
            "DIGEST_MISMATCH",
            "receiptDigest does not match canonical signed receipt",
        )
    if not hmac.compare_digest(actual_snapshot_digest, claimed_snapshot_digest):
        return _invalid_bundle(
            "DIGEST_MISMATCH",
            "trustSnapshotDigest does not match canonical trust snapshot",
        )
    if not hmac.compare_digest(actual_observation_digest, claimed_observation_digest):
        return _invalid_bundle(
            "DIGEST_MISMATCH",
            "chainObservationDigest does not match canonical chain observation",
        )
    if not hmac.compare_digest(actual_bundle_digest, claimed_bundle_digest):
        return _invalid_bundle(
            "DIGEST_MISMATCH",
            "bundleDigest does not match bound component digests",
        )

    if trusted_snapshot_digest is not None:
        try:
            expected_snap = _hex32(trusted_snapshot_digest, "trustedSnapshotDigest")
        except ValueError as exc:
            return _invalid_bundle("UNTRUSTED_SNAPSHOT", str(exc))
        if not hmac.compare_digest(actual_snapshot_digest, expected_snap):
            return _invalid_bundle(
                "UNTRUSTED_SNAPSHOT",
                "trustSnapshotDigest does not match caller pinned trust snapshot digest",
            )

    # Cross-bind receipt fields and chain observation fields
    for shared_field in (
        "proofId",
        "videoHash",
        "metadataHash",
        "tier",
        "networkPassphrase",
        "contractId",
        "ledgerSequence",
        "transactionHash",
    ):
        if normalized_receipt[shared_field] != normalized_observation[shared_field]:
            return _invalid_bundle(
                "STATEMENT_MISMATCH",
                f"receipt.{shared_field} does not match chainObservation.{shared_field}",
            )

    if normalized_receipt["result"] == "verified":
        if normalized_observation["status"] != "confirmed":
            return _invalid_bundle(
                "STATEMENT_MISMATCH",
                "verified receipt requires a confirmed chainObservation status",
            )
        if (
            normalized_observation["ledgerSequence"] is None
            or normalized_observation["transactionHash"] is None
        ):
            return _invalid_bundle(
                "STATEMENT_MISMATCH",
                "verified receipt requires non-null ledgerSequence and transactionHash",
            )

    # Offline time-attestation validation if present
    if "timeAttestation" in normalized_observation:
        decoded_att = decode_time_attestation(normalized_observation["timeAttestation"])
        obs_dt = _parse_utc_iso(normalized_observation["observedAt"], "chainObservation.observedAt")
        reference_ms = max(
            int(obs_dt.timestamp() * 1000),
            int(bundled_dt.timestamp() * 1000),
        )
        if now is not None:
            now_dt = (
                now.astimezone(timezone.utc)
                if isinstance(now, datetime)
                else _parse_utc_iso(now, "now")
            )
            reference_ms = int(now_dt.timestamp() * 1000)

        att_errors = validate_time_attestation_at(
            decoded_att,
            normalized_observation["videoHash"],
            reference_time_ms=reference_ms,
        )
        if att_errors:
            return _invalid_bundle(
                "INVALID_TIME_ATTESTATION",
                "; ".join(att_errors),
            )

        for anchor in decoded_att.stellar_anchors:
            if anchor.network_passphrase != normalized_observation["networkPassphrase"]:
                return _invalid_bundle(
                    "INVALID_TIME_ATTESTATION",
                    "Stellar anchor networkPassphrase does not match chainObservation",
                )
        if (
            decoded_att.stellar_anchors
            and normalized_observation["transactionHash"] is not None
            and normalized_observation["ledgerSequence"] is not None
        ):
            matching_anchor = any(
                anchor.transaction_hash.lower() == normalized_observation["transactionHash"]
                and anchor.ledger_sequence == normalized_observation["ledgerSequence"]
                for anchor in decoded_att.stellar_anchors
            )
            if not matching_anchor:
                return _invalid_bundle(
                    "INVALID_TIME_ATTESTATION",
                    "Stellar anchor does not match chainObservation transactionHash and ledgerSequence",
                )

        if decoded_att.rfc3161_anchors and normalized_snapshot.get("tsaTrustRootsB64"):
            chain_checked = verify_rfc3161_anchors(
                decoded_att,
                trust_roots_b64=normalized_snapshot.get("tsaTrustRootsB64"),
                revoked_serials_hex=normalized_snapshot.get("revokedTsaSerialsHex"),
            )
            for idx, checked_anchor in enumerate(chain_checked.rfc3161_anchors):
                if checked_anchor.certificate_chain and checked_anchor.verification_status != "valid":
                    return _invalid_bundle(
                        "INVALID_TIME_ATTESTATION",
                        f"RFC 3161 anchor {idx} failed offline chain verification: {checked_anchor.verification_status}",
                    )

    sig_check = verify_signed_verification_receipt(
        normalized_receipt,
        keys=normalized_snapshot["keys"],
        key_validity=normalized_snapshot.get("keyValidity"),
        expected_network_passphrase=expected_network_passphrase,
        expected_proof_id=expected_proof_id,
        now=now,
        enforce_active_key_at_now=enforce_active_key_at_now,
    )
    if not sig_check["valid"]:
        return _invalid_bundle(sig_check["code"], sig_check["reason"])

    return {
        "valid": True,
        "code": "VALID",
        "reason": None,
        "offline": True,
        "protocol": EVIDENCE_BUNDLE_PROTOCOL,
        "version": version,
        "proofId": normalized_receipt["proofId"],
        "result": normalized_receipt["result"],
        "tier": normalized_receipt["tier"],
        "networkPassphrase": normalized_receipt["networkPassphrase"],
        "signerKeyId": normalized_receipt["signer"]["keyId"],
        "chainStatus": normalized_observation["status"],
        "bindings": {
            "receiptDigest": actual_receipt_digest,
            "trustSnapshotDigest": actual_snapshot_digest,
            "chainObservationDigest": actual_observation_digest,
            "bundleDigest": actual_bundle_digest,
        },
    }


def _invalid_bundle(code: str, reason: str | None) -> dict[str, Any]:
    return {
        "valid": False,
        "code": code,
        "reason": reason or "invalid receipt evidence bundle",
        "offline": True,
    }


def _normalize_signed_receipt(receipt: Mapping[str, object]) -> dict[str, Any]:
    if not isinstance(receipt, Mapping):
        raise ValueError("receipt must be an object")
    if receipt.get("protocol") != RECEIPT_PROTOCOL or receipt.get("version") != RECEIPT_VERSION:
        raise ValueError("unsupported receipt version")

    result = _choice(receipt.get("result"), "receipt.result", ("verified", "unverified"))
    verified_at_raw = _text(receipt.get("verifiedAt"), "receipt.verifiedAt")
    # Validate ISO timestamp while preserving exact signed string for signature verification
    _parse_utc_iso(verified_at_raw, "receipt.verifiedAt")

    signer_raw = receipt.get("signer")
    if not isinstance(signer_raw, Mapping):
        raise ValueError("receipt signer is invalid")
    key_id = _text(signer_raw.get("keyId"), "receipt.signer.keyId")
    algorithm = signer_raw.get("algorithm")
    if algorithm != RECEIPT_ALGORITHM:
        raise ValueError("receipt signer is invalid")

    signature = _text(receipt.get("signature"), "receipt.signature")
    _b64url_decode(signature, "receipt.signature")

    return {
        "protocol": RECEIPT_PROTOCOL,
        "version": RECEIPT_VERSION,
        "result": result,
        "verifiedAt": verified_at_raw,
        "proofId": _hex32(receipt.get("proofId"), "receipt.proofId"),
        "videoHash": _hex32(receipt.get("videoHash"), "receipt.videoHash"),
        "metadataHash": _hex32(receipt.get("metadataHash"), "receipt.metadataHash"),
        "tier": _choice(receipt.get("tier"), "receipt.tier", ("silent", "source", "seal")),
        "networkPassphrase": _text(receipt.get("networkPassphrase"), "receipt.networkPassphrase"),
        "contractId": _text(receipt.get("contractId"), "receipt.contractId"),
        "ledgerSequence": _optional_int(receipt.get("ledgerSequence"), "receipt.ledgerSequence"),
        "transactionHash": _optional_hex32(receipt.get("transactionHash"), "receipt.transactionHash"),
        "circuitVersion": _text(receipt.get("circuitVersion"), "receipt.circuitVersion"),
        "verifierVersion": _text(receipt.get("verifierVersion"), "receipt.verifierVersion"),
        "signer": {
            "keyId": key_id,
            "algorithm": RECEIPT_ALGORITHM,
        },
        "signature": signature,
    }


def _assert_no_sensitive_material(value: object, *, path: str) -> None:
    if isinstance(value, Mapping):
        for raw_key, nested in value.items():
            key_str = str(raw_key)
            normalized_key = key_str.strip().lower()
            if normalized_key in _FORBIDDEN_KEY_NAMES:
                raise ValueError(
                    f"{path}.{key_str} contains forbidden sensitive or credential material"
                )
            _assert_no_sensitive_material(nested, path=f"{path}.{key_str}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _assert_no_sensitive_material(nested, path=f"{path}[{index}]")
    elif isinstance(value, str):
        for marker in _FORBIDDEN_VALUE_MARKERS:
            if marker in value:
                raise ValueError(
                    f"{path} contains forbidden sensitive or credential material"
                )


def _parse_utc_iso(value: object, field: str) -> datetime:
    text = _text(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include an explicit timezone")
    return parsed.astimezone(timezone.utc)


def _b64url_decode(value: str, field: str) -> bytes:
    if not value or not _BASE64URL_RE.match(value):
        raise ValueError(f"{field} must be base64url encoded")
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise ValueError(f"{field} must be base64url encoded") from exc


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _hex32(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{field} must be a 32-byte hex string")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{field} must be a 32-byte hex string") from exc
    return value.lower()


def _optional_hex32(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _hex32(value, field)


def _optional_int(value: object, field: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer or null")
    return value


def _choice(value: object, field: str, choices: tuple[str, ...]) -> str:
    if value not in choices:
        raise ValueError(f"{field} must be one of: {', '.join(choices)}")
    return value
