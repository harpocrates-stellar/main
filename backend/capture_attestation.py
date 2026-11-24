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
from typing import Any, Callable


# ── Constants ──────────────────────────────────────────────────────────────

PROFILE_ID = "harpocrates-capture-attestation/v1"
ASSURANCE_SCHEMA_ID = "harpocrates-capture-assurance/v1"
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

REQUIRED_ATTESTATION_FIELDS = frozenset(
    {
        "profile",
        "version",
        "trustLevel",
        "captureNonce",
        "appIdentity",
        "deviceCommitment",
        "privacyScope",
        "evidenceDigestBinding",
    }
)
KNOWN_OPTIONAL_ATTESTATION_FIELDS = frozenset(
    {
        "secureTime",
        "cameraPipeline",
        "platformClaims",
        "criticalFields",
        "criticalExtensions",
        "optionalMetadata",
    }
)
KNOWN_ATTESTATION_FIELDS = REQUIRED_ATTESTATION_FIELDS | KNOWN_OPTIONAL_ATTESTATION_FIELDS

# A profile may declare a field as required only if this verifier understands it.
KNOWN_DECLARABLE_CRITICAL_FIELDS = REQUIRED_ATTESTATION_FIELDS | frozenset(
    {"secureTime", "cameraPipeline", "platformClaims"}
)
KNOWN_APP_IDENTITY_FIELDS = frozenset(
    {"packageName", "versionCode", "buildFingerprint", "signingDigest"}
)
KNOWN_SECURE_TIME_FIELDS = frozenset({"unixMs", "source", "driftMs"})
KNOWN_CAMERA_PIPELINE_FIELDS = frozenset(
    {"sensorOrientation", "hasWatermark", "claimedIntegrity"}
)

# These identifiers have verifier semantics; a profile must not silently require
# a critical extension whose semantics this version cannot enforce.
SUPPORTED_CRITICAL_EXTENSIONS = frozenset(
    {
        "harpocrates.evidence-binding/v1",
        "harpocrates.per-session-commitment/v1",
    }
)

# Optional metadata is preserved for display and policy input, never treated as
# proof of a higher trust level.
KNOWN_OPTIONAL_METADATA_KEYS = frozenset(
    {
        "attestationBackend",
        "captureMode",
        "lensProfile",
        "osPatchLevel",
        "sensorModelClass",
    }
)
MAX_OPTIONAL_METADATA_STR_LEN = 128


class AttestationProfileValidationError(ValueError):
    """Raised when a profile declaration or metadata field is not understood."""


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
    critical_fields: tuple[str, ...] = ()
    critical_extensions: tuple[str, ...] = ()
    optional_metadata: dict[str, Any] = field(default_factory=dict)

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
        obj["platformClaims"] = dict(attestation.platform_claims)
    if attestation.critical_fields:
        obj["criticalFields"] = sorted(set(attestation.critical_fields))
    if attestation.critical_extensions:
        obj["criticalExtensions"] = sorted(set(attestation.critical_extensions))
    if attestation.optional_metadata:
        obj["optionalMetadata"] = dict(attestation.optional_metadata)

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
        platform_claims=dict(obj.get("platformClaims") or {}),
        critical_fields=tuple(obj.get("criticalFields", ())),
        critical_extensions=tuple(obj.get("criticalExtensions", ())),
        optional_metadata=dict(obj.get("optionalMetadata") or {}),
    )


def inspect_attestation_profile_metadata(attestation: CaptureAttestation) -> dict[str, Any]:
    """Describe profile declarations without promoting untrusted metadata to trust."""
    _validate_attestation(attestation)
    return {
        "broadTrustAssumed": False,
        "criticalExtensions": list(attestation.critical_extensions),
        "criticalFields": list(attestation.critical_fields),
        "optionalMetadata": dict(attestation.optional_metadata),
        "optionalMetadataVerified": False,
        "platformClaimKeys": sorted(attestation.platform_claims.keys()),
        "profile": PROFILE_ID,
        "trustLevel": attestation.trust_level,
        "trustLevelLabel": TRUST_LEVEL_LABELS[attestation.trust_level],
        "version": attestation.version,
    }


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


def build_assurance_schema(
    attestation: CaptureAttestation,
    checks: dict[str, bool],
) -> dict[str, Any]:
    """Describe device claims, issuer status, and only the capture checks run."""
    verified: list[str] = []
    failed: list[str] = []
    not_evaluated: list[str] = []

    check_properties = (
        ("evidence_binding", "attested_digest_matches_request"),
        ("device_commitment", "device_commitment_matches_supplied_key"),
    )
    for check_name, property_name in check_properties:
        if check_name not in checks:
            not_evaluated.append(property_name)
        elif checks[check_name]:
            verified.append(property_name)
        else:
            failed.append(property_name)

    not_evaluated.extend(
        (
            "evidence_content_digest",
            "secure_time",
            "camera_pipeline_integrity",
            "platform_claims",
        )
    )
    claimed_integrity = (
        attestation.camera_pipeline.claimed_integrity
        if attestation.camera_pipeline is not None
        else None
    )

    return {
        "schema": ASSURANCE_SCHEMA_ID,
        "deviceClaims": {
            "status": "reported",
            "trustLevel": {
                "code": attestation.trust_level,
                "label": TRUST_LEVEL_LABELS[attestation.trust_level],
            },
            "claimedIntegrity": claimed_integrity,
        },
        "issuerCertification": {
            "status": "not_evaluated",
            "reasonCode": "issuer_transparency_not_checked",
        },
        "captureVerification": {
            "verifiedProperties": verified,
            "failedProperties": failed,
            "notEvaluatedProperties": not_evaluated,
        },
    }


def make_device_commitment(capture_nonce: str, per_session_device_key: bytes) -> str:
    """Create a device commitment for a given nonce and per-session key."""
    return hmac.new(
        per_session_device_key,
        bytes.fromhex(capture_nonce),
        hashlib.sha256,
    ).hexdigest()


# ── Internal helpers ───────────────────────────────────────────────────────

_DATACLASS_FIELD_NAMES = {
    "trustLevel": "trust_level",
    "captureNonce": "capture_nonce",
    "appIdentity": "app_identity",
    "deviceCommitment": "device_commitment",
    "privacyScope": "privacy_scope",
    "evidenceDigestBinding": "evidence_digest_binding",
    "secureTime": "secure_time",
    "cameraPipeline": "camera_pipeline",
    "platformClaims": "platform_claims",
}


def _attestation_field_value(attestation: CaptureAttestation, field_name: str) -> Any:
    if field_name == "profile":
        return PROFILE_ID
    return getattr(attestation, _DATACLASS_FIELD_NAMES.get(field_name, field_name), None)


def _is_hex32(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _canonical_json(obj: object) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _validate_optional_metadata(meta: object) -> None:
    if not isinstance(meta, dict):
        raise AttestationProfileValidationError("optionalMetadata must be a JSON object")
    for key, value in meta.items():
        if not isinstance(key, str) or key not in KNOWN_OPTIONAL_METADATA_KEYS:
            raise AttestationProfileValidationError(
                "optionalMetadata contains an unknown metadata field"
            )
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            continue
        if isinstance(value, str) and len(value) <= MAX_OPTIONAL_METADATA_STR_LEN:
            continue
        raise AttestationProfileValidationError(
            "optionalMetadata values must be bounded scalar strings, booleans, or integers"
        )


def _validate_platform_claims(claims: object) -> None:
    if not isinstance(claims, dict):
        raise AttestationProfileValidationError("platformClaims must be a JSON object")
    for key, value in claims.items():
        if not isinstance(key, str) or not 1 <= len(key) <= 64:
            raise AttestationProfileValidationError(
                "platformClaims keys must be bounded strings"
            )
        if isinstance(value, dict) and any(
            marker in value and value[marker] not in (None, False)
            for marker in ("critical", "required")
        ):
            raise AttestationProfileValidationError(
                "platformClaims cannot declare unrecognised critical or required extensions"
            )


def _validate_critical_declarations(
    critical_fields: object,
    critical_extensions: object,
) -> None:
    if not isinstance(critical_fields, (tuple, list)):
        raise AttestationProfileValidationError(
            "criticalFields must be a list of field names"
        )
    for field_name in critical_fields:
        if not isinstance(field_name, str) or field_name not in KNOWN_DECLARABLE_CRITICAL_FIELDS:
            raise AttestationProfileValidationError(
                "attestation declares an unknown required field"
            )

    if not isinstance(critical_extensions, (tuple, list)):
        raise AttestationProfileValidationError(
            "criticalExtensions must be a list of extension identifiers"
        )
    for extension in critical_extensions:
        if not isinstance(extension, str) or extension not in SUPPORTED_CRITICAL_EXTENSIONS:
            raise AttestationProfileValidationError(
                "attestation declares an unsupported critical extension"
            )


def _validate_declared_critical_present(
    critical_fields: tuple[str, ...] | list[Any],
    get_value: Callable[[str], Any],
) -> None:
    for field_name in critical_fields:
        value = get_value(field_name)
        if value is None or (
            isinstance(value, (str, dict, list, tuple)) and not value
        ):
            raise AttestationProfileValidationError(
                f"attestation omits a field declared in criticalFields: {field_name}"
            )


def _validate_attestation(attestation: CaptureAttestation) -> None:
    if isinstance(attestation.version, bool) or not isinstance(attestation.version, int):
        raise ValueError(f"Unsupported attestation version: {attestation.version}")
    if attestation.version not in SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported attestation version: {attestation.version}")
    if isinstance(attestation.trust_level, bool) or not isinstance(attestation.trust_level, int):
        raise ValueError(f"Invalid trust level: {attestation.trust_level}")
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
    _validate_critical_declarations(
        attestation.critical_fields,
        attestation.critical_extensions,
    )
    _validate_optional_metadata(attestation.optional_metadata)
    _validate_platform_claims(attestation.platform_claims)
    _validate_declared_critical_present(
        attestation.critical_fields,
        lambda field_name: _attestation_field_value(attestation, field_name),
    )


def _validate_attestation_obj(obj: dict[str, Any]) -> None:
    if not isinstance(obj, dict):
        raise TypeError("attestation object must be a JSON object")

    version = obj.get("version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise ValueError(f"Unsupported attestation version: {version}")
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported attestation version: {version}")
    expected_profile = f"harpocrates-capture-attestation/v{version}"
    if obj.get("profile") != expected_profile:
        raise AttestationProfileValidationError(
            f"attestation profile must be {expected_profile} "
            "(profile identifier conflicts with version)"
        )

    unknown_top_level = set(obj.keys()) - KNOWN_ATTESTATION_FIELDS
    if unknown_top_level:
        raise AttestationProfileValidationError(
            "attestation profile contains unknown top-level fields"
        )

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
    if set(obj["appIdentity"].keys()) - KNOWN_APP_IDENTITY_FIELDS:
        raise AttestationProfileValidationError("appIdentity contains unknown fields")

    if obj.get("secureTime") is not None:
        if not isinstance(obj["secureTime"], dict):
            raise ValueError("secureTime must be a JSON object")
        if set(obj["secureTime"].keys()) - KNOWN_SECURE_TIME_FIELDS:
            raise AttestationProfileValidationError("secureTime contains unknown fields")
        if any(field not in obj["secureTime"] for field in KNOWN_SECURE_TIME_FIELDS):
            raise ValueError("secureTime missing required fields")

    if obj.get("cameraPipeline") is not None:
        if not isinstance(obj["cameraPipeline"], dict):
            raise AttestationProfileValidationError(
                "cameraPipeline must be a JSON object"
            )
        if set(obj["cameraPipeline"].keys()) - KNOWN_CAMERA_PIPELINE_FIELDS:
            raise AttestationProfileValidationError(
                "cameraPipeline contains unknown fields"
            )

    critical_fields = obj.get("criticalFields", [])
    critical_extensions = obj.get("criticalExtensions", [])
    _validate_critical_declarations(critical_fields, critical_extensions)
    _validate_declared_critical_present(
        critical_fields,
        lambda field_name: obj.get(field_name),
    )

    if "optionalMetadata" in obj:
        _validate_optional_metadata(obj["optionalMetadata"])
    if "platformClaims" in obj:
        _validate_platform_claims(obj["platformClaims"])


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
