"""
Capture-device attestation canonical encoding for Harpocrates.

Implements the protocol defined in docs/capture-attestation-profile.md.
Provides encoding, validation, and verification of capture-session
attestation objects without exposing stable device identifiers.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any

try:
    from issuer_key_transparency import (
        DirectoryCache,
        IssuerCertificationAssessment,
        IssuerDirectory,
        classify_issuer_certification,
    )
except ImportError:  # pragma: no cover - package import fallback
    from backend.issuer_key_transparency import (
        DirectoryCache,
        IssuerCertificationAssessment,
        IssuerDirectory,
        classify_issuer_certification,
    )


# ── Constants ──────────────────────────────────────────────────────────────

PROFILE_ID = "harpocrates-capture-attestation/v1"
SUPPORTED_VERSIONS = {1}

VALID_TRUST_LEVELS = {0, 1, 2, 3, 4}
TRUST_LEVEL_LABELS: dict[int, str] = {
    0: "unattested",
    1: "software_attested",
    2: "hardware_backed",
    3: "rooted_or_emulated",
    4: "unverifiable",
}

VALID_TIME_SOURCES = {"hardware_clock", "ntp_synchronized", "platform_clock"}
VALID_PRIVACY_SCOPES = {"per_session", "per_relying_party", "per_device_group"}
VALID_INTEGRITY_CLAIMS = {"raw_sensor", "processed", "screen_capture", "unknown"}


# ── Data model ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AppIdentity:
    """Application and build identity claims (no device identifiers)."""

    package_name: str
    version_code: str
    build_fingerprint: str | None = None
    signing_digest: str | None = None  # 32-byte hex


@dataclass(frozen=True)
class SecureTime:
    """Independently verifiable time evidence."""

    unix_ms: int
    source: str  # hardware_clock | ntp_synchronized | platform_clock
    drift_ms: int


@dataclass(frozen=True)
class CameraPipeline:
    """Claims about the camera capture pipeline."""

    sensor_orientation: int | None = None
    has_watermark: bool = False
    claimed_integrity: str | None = None


@dataclass(frozen=True)
class CaptureAttestation:
    """Privacy-preserving capture-device attestation."""

    version: int
    trust_level: int
    capture_nonce: str  # 32-byte hex
    app_identity: AppIdentity
    device_commitment: str  # 32-byte hex; HMAC-SHA256(nonce, perSessionDeviceKey)
    privacy_scope: str
    evidence_digest_binding: str  # 32-byte hex; SHA-256 of evidence payload

    secure_time: SecureTime | None = None
    camera_pipeline: CameraPipeline | None = None
    platform_claims: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_attestation(self)


# ── Public API ─────────────────────────────────────────────────────────────


def encode_attestation(attestation: CaptureAttestation) -> dict[str, Any]:
    """Encode a ``CaptureAttestation`` to its canonical JSON-safe dictionary."""
    _validate_attestation(attestation)

    obj: dict[str, Any] = {
        "version": attestation.version,
        "profile": PROFILE_ID,
        "trustLevel": attestation.trust_level,
        "captureNonce": attestation.capture_nonce.lower(),
        "appIdentity": {
            "packageName": attestation.app_identity.package_name,
            "versionCode": attestation.app_identity.version_code,
        },
        "deviceCommitment": attestation.device_commitment.lower(),
        "privacyScope": attestation.privacy_scope,
        "evidenceDigestBinding": attestation.evidence_digest_binding.lower(),
    }

    if attestation.app_identity.build_fingerprint:
        obj["appIdentity"]["buildFingerprint"] = attestation.app_identity.build_fingerprint
    if attestation.app_identity.signing_digest:
        obj["appIdentity"]["signingDigest"] = attestation.app_identity.signing_digest.lower()

    if attestation.secure_time is not None:
        obj["secureTime"] = {
            "unixMs": attestation.secure_time.unix_ms,
            "source": attestation.secure_time.source,
            "driftMs": attestation.secure_time.drift_ms,
        }

    if attestation.camera_pipeline is not None:
        cam: dict[str, Any] = {}
        if attestation.camera_pipeline.sensor_orientation is not None:
            cam["sensorOrientation"] = attestation.camera_pipeline.sensor_orientation
        cam["hasWatermark"] = attestation.camera_pipeline.has_watermark
        if attestation.camera_pipeline.claimed_integrity is not None:
            cam["claimedIntegrity"] = attestation.camera_pipeline.claimed_integrity
        if cam:
            obj["cameraPipeline"] = cam

    if attestation.platform_claims:
        obj["platformClaims"] = attestation.platform_claims

    return obj


def decode_attestation(obj: dict[str, Any]) -> CaptureAttestation:
    """Decode and validate a canonical attestation dictionary.

    Raises ``ValueError`` or ``TypeError`` on invalid input.
    """
    _validate_attestation_obj(obj)

    return CaptureAttestation(
        version=obj["version"],
        trust_level=obj["trustLevel"],
        capture_nonce=obj["captureNonce"],
        app_identity=AppIdentity(
            package_name=obj["appIdentity"]["packageName"],
            version_code=obj["appIdentity"]["versionCode"],
            build_fingerprint=obj["appIdentity"].get("buildFingerprint"),
            signing_digest=obj["appIdentity"].get("signingDigest"),
        ),
        device_commitment=obj["deviceCommitment"],
        privacy_scope=obj["privacyScope"],
        evidence_digest_binding=obj["evidenceDigestBinding"],
        secure_time=_decode_secure_time(obj.get("secureTime")),
        camera_pipeline=_decode_camera_pipeline(obj.get("cameraPipeline")),
        platform_claims=obj.get("platformClaims", {}),
    )


def canonical_attestation_hash(attestation: CaptureAttestation) -> str:
    """Compute the canonical SHA-256 hash of an attestation object."""
    encoded = encode_attestation(attestation)
    canonical = _canonical_json(encoded)
    return hashlib.sha256(canonical).hexdigest()


def verify_evidence_binding(
    attestation: CaptureAttestation,
    evidence_payload: bytes,
) -> bool:
    """Verify that the attestation's evidence digest binding matches the actual evidence."""
    expected = hashlib.sha256(evidence_payload).hexdigest()
    return attestation.evidence_digest_binding == expected


def verify_device_commitment(
    attestation: CaptureAttestation,
    per_session_device_key: bytes,
) -> bool:
    """Verify the device commitment using the per-session device key."""
    expected = hmac.new(
        per_session_device_key,
        bytes.fromhex(attestation.capture_nonce),
        hashlib.sha256,
    ).hexdigest()
    return attestation.device_commitment == expected


def make_device_commitment(capture_nonce: str, per_session_device_key: bytes) -> str:
    """Create a device commitment for a given nonce and per-session key."""
    return hmac.new(
        per_session_device_key,
        bytes.fromhex(capture_nonce),
        hashlib.sha256,
    ).hexdigest()


# ── Internal helpers ───────────────────────────────────────────────────────


def _is_hex32(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _canonical_json(obj: object) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _validate_attestation(attestation: CaptureAttestation) -> None:
    if attestation.version not in SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported attestation version: {attestation.version}")
    if attestation.trust_level not in VALID_TRUST_LEVELS:
        raise ValueError(f"Invalid trust level: {attestation.trust_level}")
    if not _is_hex32(attestation.capture_nonce):
        raise ValueError("capture_nonce must be a 32-byte hex string")
    if not _is_hex32(attestation.device_commitment):
        raise ValueError("device_commitment must be a 32-byte hex string")
    if not _is_hex32(attestation.evidence_digest_binding):
        raise ValueError("evidence_digest_binding must be a 32-byte hex string")
    if attestation.privacy_scope not in VALID_PRIVACY_SCOPES:
        raise ValueError(f"Invalid privacy scope: {attestation.privacy_scope}")
    if attestation.secure_time is not None:
        if attestation.secure_time.source not in VALID_TIME_SOURCES:
            raise ValueError(f"Invalid time source: {attestation.secure_time.source}")


def _validate_attestation_obj(obj: dict[str, Any]) -> None:
    if not isinstance(obj, dict):
        raise TypeError("attestation object must be a JSON object")

    if obj.get("profile") != PROFILE_ID:
        raise ValueError(f"attestation profile must be {PROFILE_ID}")

    version = obj.get("version")
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported attestation version: {version}")

    required = [
        "trustLevel",
        "captureNonce",
        "appIdentity",
        "deviceCommitment",
        "privacyScope",
        "evidenceDigestBinding",
    ]
    for field in required:
        if field not in obj:
            raise ValueError(f"attestation missing required field: {field}")

    if not isinstance(obj["appIdentity"], dict):
        raise ValueError("appIdentity must be a JSON object")
    if "packageName" not in obj["appIdentity"]:
        raise ValueError("appIdentity.packageName is required")
    if "versionCode" not in obj["appIdentity"]:
        raise ValueError("appIdentity.versionCode is required")


def _decode_secure_time(data: object) -> SecureTime | None:
    if data is None:
        return None
    if not isinstance(data, dict):
        raise ValueError("secureTime must be a JSON object")
    return SecureTime(
        unix_ms=data["unixMs"],
        source=data["source"],
        drift_ms=data["driftMs"],
    )


def _decode_camera_pipeline(data: object) -> CameraPipeline | None:
    if data is None:
        return None
    if not isinstance(data, dict):
        return None
    return CameraPipeline(
        sensor_orientation=data.get("sensorOrientation"),
        has_watermark=bool(data.get("hasWatermark", False)),
        claimed_integrity=data.get("claimedIntegrity"),
    )


# ── Stable capture-attestation assurance schema ────────────────────────────

CAPTURE_ASSURANCE_SCHEMA = "harpocrates-capture-assurance/v1"
CAPTURE_ASSURANCE_VERSION = 1

ASSURANCE_LEVELS: tuple[str, ...] = (
    "rejected_invalid_binding",
    "degraded_or_unverifiable",
    "unverified_claim",
    "device_software_verified",
    "device_hardware_verified",
    "institutional_certified",
    "institutional_high_assurance",
)


@dataclass(frozen=True)
class DeviceClaimSummary:
    """Self-reported device and capture-pipeline claims (not independently verified)."""

    trust_level: int
    trust_level_label: str
    device_tier: str
    privacy_scope: str
    claimed_time_source: str | None
    claimed_pipeline_integrity: str | None
    has_watermark: bool | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority": "device_self_claim",
            "claimedPipelineIntegrity": self.claimed_pipeline_integrity,
            "claimedTimeSource": self.claimed_time_source,
            "deviceTier": self.device_tier,
            "hasWatermark": self.has_watermark,
            "privacyScope": self.privacy_scope,
            "trustLevel": self.trust_level,
            "trustLevelLabel": self.trust_level_label,
        }


@dataclass(frozen=True)
class VerifiedCaptureProperties:
    """Cryptographically checked capture properties (distinct from self-claims)."""

    evidence_binding_verified: bool | None
    device_commitment_verified: bool | None

    @property
    def has_cryptographic_failure(self) -> bool:
        return (
            self.evidence_binding_verified is False
            or self.device_commitment_verified is False
        )

    def to_dict(self) -> dict[str, Any]:
        verified_props: list[str] = []
        if self.evidence_binding_verified is True:
            verified_props.append("evidence_digest_binding")
        if self.device_commitment_verified is True:
            verified_props.append("per_session_device_commitment")
        return {
            "deviceCommitmentVerified": self.device_commitment_verified,
            "evidenceBindingVerified": self.evidence_binding_verified,
            "hasCryptographicFailure": self.has_cryptographic_failure,
            "verifiedProperties": verified_props,
        }


@dataclass(frozen=True)
class CaptureAssuranceRecord:
    """Stable assurance schema separating device claims, issuer seal, and verified bindings."""

    attestation_hash: str
    overall_assurance_level: str
    institutional_trust_granted: bool
    elevation_blocked_reasons: tuple[str, ...]
    device_claims: DeviceClaimSummary
    issuer_certification: IssuerCertificationAssessment
    verified_capture_properties: VerifiedCaptureProperties

    def to_dict(self) -> dict[str, Any]:
        return {
            "attestationHash": self.attestation_hash,
            "deviceClaims": self.device_claims.to_dict(),
            "elevationBlockedReasons": list(self.elevation_blocked_reasons),
            "institutionalTrustGranted": self.institutional_trust_granted,
            "issuerCertification": self.issuer_certification.to_dict(),
            "overallAssuranceLevel": self.overall_assurance_level,
            "schema": CAPTURE_ASSURANCE_SCHEMA,
            "version": CAPTURE_ASSURANCE_VERSION,
            "verifiedCaptureProperties": self.verified_capture_properties.to_dict(),
        }


def evaluate_capture_assurance(
    attestation: CaptureAttestation,
    *,
    evidence_payload: bytes | None = None,
    evidence_digest: str | None = None,
    per_session_device_key: bytes | None = None,
    issuer_directory: IssuerDirectory | None = None,
    issuer_key_id: str | None = None,
    signature_timestamp: int | None = None,
    directory_cache: DirectoryCache | None = None,
    now: int | None = None,
) -> CaptureAssuranceRecord:
    """Evaluate capture-attestation assurance without elevating unsupported attestations."""
    _validate_attestation(attestation)
    if evidence_payload is not None and evidence_digest is not None:
        raise ValueError("pass at most one of evidence_payload or evidence_digest")

    ev_verified: bool | None = None
    if evidence_payload is not None:
        ev_verified = verify_evidence_binding(attestation, evidence_payload)
    elif evidence_digest is not None:
        normalized_digest = evidence_digest.lower()
        if not _is_hex32(normalized_digest):
            raise ValueError("evidence_digest must be a 32-byte hex string")
        ev_verified = attestation.evidence_digest_binding.lower() == normalized_digest

    dev_verified: bool | None = None
    if per_session_device_key is not None:
        if not isinstance(per_session_device_key, (bytes, bytearray)) or len(per_session_device_key) != 32:
            raise ValueError("per_session_device_key must be 32 bytes")
        dev_verified = verify_device_commitment(attestation, bytes(per_session_device_key))

    if attestation.trust_level == 2:
        device_tier = "hardware_backed"
    elif attestation.trust_level == 1:
        device_tier = "software_attested"
    elif attestation.trust_level == 0:
        device_tier = "unattested"
    else:
        device_tier = "degraded_environment"

    device_claims = DeviceClaimSummary(
        trust_level=attestation.trust_level,
        trust_level_label=TRUST_LEVEL_LABELS[attestation.trust_level],
        device_tier=device_tier,
        privacy_scope=attestation.privacy_scope,
        claimed_time_source=attestation.secure_time.source if attestation.secure_time else None,
        claimed_pipeline_integrity=(
            attestation.camera_pipeline.claimed_integrity
            if attestation.camera_pipeline
            else None
        ),
        has_watermark=(
            attestation.camera_pipeline.has_watermark if attestation.camera_pipeline else None
        ),
    )

    verified_props = VerifiedCaptureProperties(
        evidence_binding_verified=ev_verified,
        device_commitment_verified=dev_verified,
    )

    issuer_cert = classify_issuer_certification(
        issuer_directory,
        issuer_key_id,
        signature_timestamp,
        directory_cache=directory_cache,
        now=now,
    )

    blocked: list[str] = []
    if verified_props.has_cryptographic_failure:
        blocked.append("cryptographic_binding_mismatch")
        overall = "rejected_invalid_binding"
    elif attestation.trust_level in (3, 4):
        blocked.append("unsupported_or_degraded_device_trust_level")
        overall = "degraded_or_unverifiable"
    elif ev_verified is not True:
        blocked.append("evidence_binding_unverified")
        overall = "unverified_claim"
    elif attestation.trust_level == 0:
        blocked.append("unattested_device_cannot_reach_institutional_trust")
        overall = "unverified_claim"
    elif issuer_cert.certified:
        if (
            attestation.trust_level == 2
            and dev_verified is True
            and issuer_cert.high_assurance_eligible
            and issuer_cert.status != "historical_pre_compromise_warning"
        ):
            overall = "institutional_high_assurance"
        else:
            if attestation.trust_level != 2:
                blocked.append("software_device_capped_below_high_assurance")
            if dev_verified is not True:
                blocked.append("device_commitment_unverified_for_high_assurance")
            if not issuer_cert.high_assurance_eligible:
                blocked.append("fresh_high_assurance_checkpoint_required")
            overall = "institutional_certified"
    else:
        blocked.extend(issuer_cert.reasons)
        overall = (
            "device_hardware_verified"
            if attestation.trust_level == 2
            else "device_software_verified"
        )

    institutional_granted = overall in (
        "institutional_certified",
        "institutional_high_assurance",
    )

    return CaptureAssuranceRecord(
        attestation_hash=canonical_attestation_hash(attestation),
        overall_assurance_level=overall,
        institutional_trust_granted=institutional_granted,
        elevation_blocked_reasons=tuple(dict.fromkeys(blocked)),
        device_claims=device_claims,
        issuer_certification=issuer_cert,
        verified_capture_properties=verified_props,
    )
