"""Focused tests for rejecting device attestation profiles with unknown required fields (#1092)."""

from __future__ import annotations

import hashlib

import pytest

from app import create_app
from capture_attestation import (
    AppIdentity,
    AttestationProfileValidationError,
    CameraPipeline,
    CaptureAttestation,
    SecureTime,
    decode_attestation,
    encode_attestation,
    inspect_attestation_profile_metadata,
    make_device_commitment,
)
from issuer_key_transparency import IssuerKey, IssuerManifest, TransparencyError


def _valid_encoded_attestation() -> tuple[dict, str]:
    nonce = hashlib.sha256(b"nonce-1092").hexdigest()
    key = hashlib.sha256(b"device-key-1092").digest()
    ev_digest = hashlib.sha256(b"synthetic-evidence-1092").hexdigest()
    att = CaptureAttestation(
        version=1,
        trust_level=1,
        capture_nonce=nonce,
        app_identity=AppIdentity(
            package_name="com.harpocrates.camera",
            version_code="12",
            build_fingerprint="harpocrates/synth:14",
        ),
        device_commitment=make_device_commitment(nonce, key),
        privacy_scope="per_session",
        evidence_digest_binding=ev_digest,
        secure_time=SecureTime(unix_ms=1_721_971_200_000, source="ntp_synchronized", drift_ms=25),
        camera_pipeline=CameraPipeline(
            sensor_orientation=90,
            has_watermark=False,
            claimed_integrity="raw_sensor",
        ),
        platform_claims={"bootloaderLocked": True},
        critical_fields=("secureTime", "cameraPipeline"),
        critical_extensions=("harpocrates.evidence-binding/v1",),
        optional_metadata={
            "lensProfile": "wide-24mm",
            "osPatchLevel": "2026-10-01",
            "captureMode": "still_burst",
        },
    )
    return encode_attestation(att), ev_digest


def test_preserves_known_optional_metadata_and_supported_critical_declarations_without_broad_trust() -> None:
    encoded, _ = _valid_encoded_attestation()
    decoded = decode_attestation(encoded)

    assert decoded.optional_metadata == {
        "lensProfile": "wide-24mm",
        "osPatchLevel": "2026-10-01",
        "captureMode": "still_burst",
    }
    assert set(decoded.critical_fields) == {"secureTime", "cameraPipeline"}
    assert decoded.critical_extensions == ("harpocrates.evidence-binding/v1",)
    assert decoded.platform_claims == {"bootloaderLocked": True}
    # Optional metadata never elevates software_attested (1) to hardware_backed (2)
    assert decoded.trust_level == 1

    meta_report = inspect_attestation_profile_metadata(decoded)
    assert meta_report["optionalMetadataVerified"] is False
    assert meta_report["broadTrustAssumed"] is False
    assert meta_report["trustLevelLabel"] == "software_attested"


def test_rejects_unknown_required_fields_and_unsupported_critical_extensions() -> None:
    base, _ = _valid_encoded_attestation()

    unknown_top = {**base, "quantumHardwareSeal": {"required": True}}
    with pytest.raises(AttestationProfileValidationError, match="unknown top-level"):
        decode_attestation(unknown_top)

    unknown_crit_field = {**base, "criticalFields": ["secureTime", "biometricLivenessGate"]}
    with pytest.raises(AttestationProfileValidationError, match="unknown required field"):
        decode_attestation(unknown_crit_field)

    missing_declared_crit = {k: v for k, v in base.items() if k != "secureTime"}
    missing_declared_crit["criticalFields"] = ["secureTime"]
    with pytest.raises(AttestationProfileValidationError, match="omits a field"):
        decode_attestation(missing_declared_crit)

    unsupported_ext = {**base, "criticalExtensions": ["vendor.proprietary.enclave/v2"]}
    with pytest.raises(AttestationProfileValidationError, match="unsupported critical extension"):
        decode_attestation(unsupported_ext)

    critical_platform_claim = {
        **base,
        "platformClaims": {"customGate": {"critical": True, "value": "enforced"}},
    }
    with pytest.raises(AttestationProfileValidationError, match="platformClaims"):
        decode_attestation(critical_platform_claim)

    unknown_optional_meta = {**base, "optionalMetadata": {"imeiNumber": "000000000000000"}}
    with pytest.raises(AttestationProfileValidationError, match="unknown metadata field"):
        decode_attestation(unknown_optional_meta)

    unknown_sub = {**base, "appIdentity": {**base["appIdentity"], "unknownRequiredSub": "x"}}
    with pytest.raises(AttestationProfileValidationError, match="appIdentity"):
        decode_attestation(unknown_sub)


def test_rejects_boolean_version_coercion_and_manifest_critical_extensions() -> None:
    base, _ = _valid_encoded_attestation()
    bool_version = {**base, "version": True}
    with pytest.raises(ValueError, match="Unsupported attestation version"):
        decode_attestation(bool_version)

    manifest = IssuerManifest(
        organization_identity_hash="a" * 64,
        issuer_address="GTESTISSUERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        active_keys=[IssuerKey("k1", "c" * 64, "ed25519", 1_000)],
        policy_hash="b" * 64,
        valid_from=1_000,
    ).to_dict()
    with pytest.raises(TransparencyError, match="unsupported critical extension"):
        IssuerManifest.from_dict({**manifest, "criticalExtensions": ["unknown.manifest.ext/v1"]})
    with pytest.raises(TransparencyError, match="version"):
        IssuerManifest.from_dict({**manifest, "version": True})


def test_verify_route_rejects_unknown_critical_extension_without_echoing_secret() -> None:
    encoded, ev_digest = _valid_encoded_attestation()
    secret_marker = "SECRET_EXTENSION_TOKEN_9911"
    tampered = {**encoded, "criticalExtensions": [secret_marker]}

    client = create_app().test_client()
    res = client.post(
        "/api/capture-attestation/verify",
        json={"attestation": tampered, "evidence_digest": ev_digest},
    )
    assert res.status_code == 400
    body = res.get_data(as_text=True)
    assert secret_marker not in body
    assert res.get_json()["error"]["code"] == "VALIDATION_ERROR"
