"""Focused tests for the stable capture-attestation assurance schema (#1091)."""

from __future__ import annotations

import hashlib
import json

import pytest

from capture_attestation import (
    ASSURANCE_LEVELS,
    CAPTURE_ASSURANCE_SCHEMA,
    AppIdentity,
    CameraPipeline,
    CaptureAttestation,
    SecureTime,
    evaluate_capture_assurance,
    make_device_commitment,
)
from issuer_key_transparency import (
    DirectoryCache,
    DirectoryEvent,
    EventType,
    IssuerKey,
    IssuerManifest,
    create_activation_event,
    event_hash,
    rebuild_directory,
)

ORG = "a" * 64
POLICY = "b" * 64
KEY_A = "c" * 64
SIG = "f" * 64


def _build_fixture(trust_level: int = 2) -> tuple[CaptureAttestation, bytes, bytes]:
    nonce = hashlib.sha256(f"nonce-{trust_level}".encode()).hexdigest()
    device_key = hashlib.sha256(f"dev-key-{trust_level}".encode()).digest()
    evidence = f"synthetic-media-{trust_level}".encode()
    att = CaptureAttestation(
        version=1,
        trust_level=trust_level,
        capture_nonce=nonce,
        app_identity=AppIdentity(
            package_name="com.harpocrates.camera",
            version_code="7",
            build_fingerprint="PRIVATE_FINGERPRINT_DO_NOT_LEAK",
        ),
        device_commitment=make_device_commitment(nonce, device_key),
        privacy_scope="per_session",
        evidence_digest_binding=hashlib.sha256(evidence).hexdigest(),
        secure_time=SecureTime(unix_ms=1_721_971_200_000, source="hardware_clock", drift_ms=10),
        camera_pipeline=CameraPipeline(
            sensor_orientation=0,
            has_watermark=False,
            claimed_integrity="raw_sensor",
        ),
    )
    return att, evidence, device_key


def _issuer_setup(*, compromised_at: int | None = None):
    e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1_000)
    events = [e0]
    if compromised_at is not None:
        events.append(
            DirectoryEvent(
                event_type=EventType.COMPROMISE,
                sequence=1,
                timestamp=compromised_at,
                organization_identity_hash=ORG,
                key_id="k1",
                public_key_hash=KEY_A,
                previous_event_hash=event_hash(e0),
                reason_hash="9" * 64,
            )
        )
    directory = rebuild_directory(ORG, events)
    directory.publish_manifest(
        IssuerManifest(
            organization_identity_hash=ORG,
            issuer_address="GTESTISSUERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            active_keys=[IssuerKey("k1", KEY_A, "ed25519", 1_000)],
            policy_hash=POLICY,
            valid_from=1_000,
            signature_hash=SIG,
        )
    )
    cp = directory.make_checkpoint(timestamp=2_000, signature_hash=SIG)
    return directory, cp


def test_distinguishes_device_claims_issuer_certification_and_verified_properties() -> None:
    att, evidence, device_key = _build_fixture(trust_level=2)
    directory, cp = _issuer_setup()
    fresh_cache = DirectoryCache(checkpoint=cp, fetched_at=10_000)

    # Hardware-backed + verified bindings + fresh institutional seal -> institutional_high_assurance
    high = evaluate_capture_assurance(
        att,
        evidence_payload=evidence,
        per_session_device_key=device_key,
        issuer_directory=directory,
        issuer_key_id="k1",
        signature_timestamp=1_500,
        directory_cache=fresh_cache,
        now=10_500,
    ).to_dict()

    assert high["schema"] == CAPTURE_ASSURANCE_SCHEMA
    assert high["overallAssuranceLevel"] == "institutional_high_assurance"
    assert high["overallAssuranceLevel"] in ASSURANCE_LEVELS
    assert high["institutionalTrustGranted"] is True
    assert high["deviceClaims"]["authority"] == "device_self_claim"
    assert high["deviceClaims"]["claimedPipelineIntegrity"] == "raw_sensor"
    assert high["issuerCertification"]["status"] == "active_institutional_seal"
    assert high["verifiedCaptureProperties"]["verifiedProperties"] == [
        "evidence_digest_binding",
        "per_session_device_commitment",
    ]
    assert "PRIVATE_FINGERPRINT_DO_NOT_LEAK" not in json.dumps(high)

    # Hardware-backed + verified binding WITHOUT issuer directory -> capped at device_hardware_verified
    device_only = evaluate_capture_assurance(
        att,
        evidence_payload=evidence,
        per_session_device_key=device_key,
    ).to_dict()
    assert device_only["overallAssuranceLevel"] == "device_hardware_verified"
    assert device_only["institutionalTrustGranted"] is False
    assert device_only["issuerCertification"]["status"] == "not_provided"


def test_never_elevates_unsupported_degraded_unverified_or_compromised_attestations() -> None:
    directory, cp = _issuer_setup()
    fresh_cache = DirectoryCache(checkpoint=cp, fetched_at=10_000)

    # Rooted/emulated (3) and unverifiable (4) stay degraded even WITH valid active issuer seal!
    for degraded_level in (3, 4):
        att, evidence, device_key = _build_fixture(trust_level=degraded_level)
        rec = evaluate_capture_assurance(
            att,
            evidence_payload=evidence,
            per_session_device_key=device_key,
            issuer_directory=directory,
            issuer_key_id="k1",
            signature_timestamp=1_500,
            directory_cache=fresh_cache,
            now=10_100,
        )
        assert rec.overall_assurance_level == "degraded_or_unverifiable"
        assert rec.institutional_trust_granted is False
        assert "unsupported_or_degraded_device_trust_level" in rec.elevation_blocked_reasons

    # Unattested (0) cannot be elevated to institutional trust even if signed by an issuer
    unattested, ev0, key0 = _build_fixture(trust_level=0)
    rec0 = evaluate_capture_assurance(
        unattested,
        evidence_payload=ev0,
        per_session_device_key=key0,
        issuer_directory=directory,
        issuer_key_id="k1",
        signature_timestamp=1_500,
        directory_cache=fresh_cache,
        now=10_100,
    )
    assert rec0.overall_assurance_level == "unverified_claim"
    assert rec0.institutional_trust_granted is False

    # Unchecked evidence binding stays unverified_claim even for trust_level=2 + active issuer
    hw_att, hw_ev, hw_key = _build_fixture(trust_level=2)
    unchecked = evaluate_capture_assurance(
        hw_att,
        issuer_directory=directory,
        issuer_key_id="k1",
        signature_timestamp=1_500,
        directory_cache=fresh_cache,
        now=10_100,
    )
    assert unchecked.overall_assurance_level == "unverified_claim"
    assert unchecked.institutional_trust_granted is False

    # Tampered evidence payload -> rejected_invalid_binding
    tampered = evaluate_capture_assurance(
        hw_att,
        evidence_payload=b"tampered-bytes",
        per_session_device_key=hw_key,
        issuer_directory=directory,
        issuer_key_id="k1",
        signature_timestamp=1_500,
        directory_cache=fresh_cache,
        now=10_100,
    )
    assert tampered.overall_assurance_level == "rejected_invalid_binding"
    assert tampered.institutional_trust_granted is False

    # Post-compromise issuer signature -> rejected from institutional trust
    comp_dir, comp_cp = _issuer_setup(compromised_at=1_800)
    comp_cache = DirectoryCache(checkpoint=comp_cp, fetched_at=10_000)
    post_comp = evaluate_capture_assurance(
        hw_att,
        evidence_payload=hw_ev,
        per_session_device_key=hw_key,
        issuer_directory=comp_dir,
        issuer_key_id="k1",
        signature_timestamp=1_900,
        directory_cache=comp_cache,
        now=10_100,
    )
    assert post_comp.overall_assurance_level == "device_hardware_verified"
    assert post_comp.institutional_trust_granted is False
    assert post_comp.issuer_certification.status == "compromised_rejected"


def test_boundary_validation_for_assurance_inputs() -> None:
    att, evidence, _ = _build_fixture(trust_level=1)
    with pytest.raises(ValueError, match="at most one"):
        evaluate_capture_assurance(
            att,
            evidence_payload=evidence,
            evidence_digest=hashlib.sha256(evidence).hexdigest(),
        )
    with pytest.raises(ValueError, match="32-byte hex"):
        evaluate_capture_assurance(att, evidence_digest="bad-hex")
    with pytest.raises(ValueError, match="32 bytes"):
        evaluate_capture_assurance(att, evidence_payload=evidence, per_session_device_key=b"short")
