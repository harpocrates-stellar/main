"""Focused tests for trust-policy simulation reports over captured evidence (#1093)."""

from __future__ import annotations

import hashlib
import json

import pytest

from capture_attestation import (
    MAX_SIMULATION_SAMPLES,
    SIMULATION_REPORT_SCHEMA,
    ActiveTrustPolicyRegistry,
    AppIdentity,
    CameraPipeline,
    CaptureAttestation,
    EvidenceTrustPolicy,
    SecureTime,
    SyntheticEvidenceSample,
    evaluate_evidence_trust_policy,
    make_device_commitment,
    simulate_trust_policy_transition,
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
POLICY_DIGEST = "b" * 64
KEY_A = "c" * 64
SIG = "f" * 64


def _make_attestation(
    tag: str,
    *,
    trust_level: int = 2,
    source: str = "hardware_clock",
    drift_ms: int = 40,
    integrity: str = "raw_sensor",
    has_watermark: bool = False,
) -> CaptureAttestation:
    nonce = hashlib.sha256(f"nonce-{tag}".encode()).hexdigest()
    device_key = hashlib.sha256(f"key-{tag}".encode()).digest()
    evidence = hashlib.sha256(f"evidence-{tag}".encode()).hexdigest()
    return CaptureAttestation(
        version=1,
        trust_level=trust_level,
        capture_nonce=nonce,
        app_identity=AppIdentity(
            package_name="org.harpocrates.synthetic",
            version_code="1",
            build_fingerprint=f"PRIVATE_BUILD_{tag}",
        ),
        device_commitment=make_device_commitment(nonce, device_key),
        privacy_scope="per_session",
        evidence_digest_binding=evidence,
        secure_time=SecureTime(unix_ms=1_721_971_200_000, source=source, drift_ms=drift_ms),
        camera_pipeline=CameraPipeline(
            sensor_orientation=0,
            has_watermark=has_watermark,
            claimed_integrity=integrity,
        ),
    )


def _make_issuer_directory(*, compromised: bool = False):
    e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1_000)
    events = [e0]
    if compromised:
        events.append(
            DirectoryEvent(
                event_type=EventType.COMPROMISE,
                sequence=1,
                timestamp=1_800,
                organization_identity_hash=ORG,
                key_id="k1",
                public_key_hash=KEY_A,
                previous_event_hash=event_hash(e0),
                reason_hash="1" * 64,
            )
        )
    directory = rebuild_directory(ORG, events)
    directory.publish_manifest(
        IssuerManifest(
            organization_identity_hash=ORG,
            issuer_address="GTESTISSUERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            active_keys=[IssuerKey("k1", KEY_A, "ed25519", 1_000)],
            policy_hash=POLICY_DIGEST,
            valid_from=1_000,
            signature_hash=SIG,
        )
    )
    checkpoint = directory.make_checkpoint(timestamp=2_000, signature_hash=SIG)
    return directory, checkpoint


def test_simulation_compares_two_policies_without_modifying_active_policy() -> None:
    directory, checkpoint = _make_issuer_directory()
    cache = DirectoryCache(checkpoint=checkpoint, fetched_at=10_000)

    policy_v1 = EvidenceTrustPolicy(
        policy_version="2026.01-standard",
        minimum_trust_level=1,
        require_secure_time=True,
        allowed_time_sources=("hardware_clock", "ntp_synchronized", "platform_clock"),
        max_clock_drift_ms=500,
        allowed_integrity_claims=("raw_sensor", "processed"),
        require_valid_issuer_key=True,
        high_assurance_freshness=False,
    )
    policy_v2 = EvidenceTrustPolicy(
        policy_version="2026.02-strict-hardware",
        minimum_trust_level=2,
        require_secure_time=True,
        allowed_time_sources=("hardware_clock",),
        max_clock_drift_ms=100,
        allowed_integrity_claims=("raw_sensor",),
        disallow_watermarked=True,
        require_valid_issuer_key=True,
        high_assurance_freshness=True,
    )

    registry = ActiveTrustPolicyRegistry(policy_v1)
    active_hash_before = registry.active_policy.policy_hash()

    samples = [
        SyntheticEvidenceSample(
            sample_id="hw-raw-fresh",
            attestation=_make_attestation("hw-raw", trust_level=2, source="hardware_clock"),
            issuer_key_id="k1",
            signature_timestamp=1_500,
            directory=directory,
            directory_cache=cache,
            evaluation_now=10_600,
        ),
        SyntheticEvidenceSample(
            sample_id="sw-ntp-captured",
            attestation=_make_attestation(
                "sw-ntp",
                trust_level=1,
                source="ntp_synchronized",
                integrity="processed",
            ),
            issuer_key_id="k1",
            signature_timestamp=1_500,
            directory=directory,
            directory_cache=cache,
            evaluation_now=10_600,
        ),
        SyntheticEvidenceSample(
            sample_id="hw-stale-high-assurance",
            attestation=_make_attestation("hw-stale", trust_level=2, source="hardware_clock"),
            issuer_key_id="k1",
            signature_timestamp=1_500,
            directory=directory,
            directory_cache=cache,
            evaluation_now=15_000,  # >1h high-assurance window, <24h standard window
        ),
        SyntheticEvidenceSample(
            sample_id="rooted-device",
            attestation=_make_attestation("rooted", trust_level=3, integrity="screen_capture"),
            issuer_key_id="k1",
            signature_timestamp=1_500,
            directory=directory,
            directory_cache=cache,
            evaluation_now=10_600,
        ),
    ]

    report = simulate_trust_policy_transition(
        samples,
        policy_v1,
        policy_v2,
        active_registry=registry,
    )
    payload = report.to_dict()

    assert payload["schema"] == SIMULATION_REPORT_SCHEMA
    assert payload["activePolicyVersion"] == "2026.01-standard"
    assert payload["activePolicyMutated"] is False
    assert registry.active_policy is policy_v1
    assert registry.active_policy.policy_hash() == active_hash_before

    # Active policy continues to accept software-attested NTP sample after simulation
    sw_live = evaluate_evidence_trust_policy(samples[1], registry.active_policy)
    assert sw_live.accepted is True

    by_id = {item["sampleId"]: item for item in payload["results"]}
    assert by_id["hw-raw-fresh"]["transition"] == "unchanged_accepted"
    assert by_id["hw-raw-fresh"]["changed"] is False

    assert by_id["sw-ntp-captured"]["transition"] == "newly_rejected"
    assert by_id["sw-ntp-captured"]["changed"] is True
    assert set(by_id["sw-ntp-captured"]["addedReasons"]) == {
        "insufficient_trust_level",
        "disallowed_time_source",
        "disallowed_integrity_claim",
    }

    assert by_id["hw-stale-high-assurance"]["transition"] == "newly_rejected"
    assert by_id["hw-stale-high-assurance"]["addedReasons"] == ["stale_directory_checkpoint"]

    assert by_id["rooted-device"]["transition"] == "unchanged_rejected"
    assert "degraded_trust_level" in by_id["rooted-device"]["baseline"]["reasons"]

    assert payload["summary"] == {
        "changedCount": 2,
        "newlyAcceptedCount": 0,
        "newlyRejectedCount": 2,
        "reasonShiftCount": 0,
        "totalSamples": 4,
        "unchangedCount": 2,
    }
    assert payload["changedSampleIds"] == ["sw-ntp-captured", "hw-stale-high-assurance"]


def test_simulation_detects_newly_accepted_and_reason_shifts_and_preserves_privacy() -> None:
    compromised_dir, cp = _make_issuer_directory(compromised=True)
    cache = DirectoryCache(checkpoint=cp, fetched_at=10_000)

    strict_policy = EvidenceTrustPolicy(
        policy_version="strict-v1",
        minimum_trust_level=2,
        disallow_watermarked=True,
        require_valid_issuer_key=True,
        reject_compromised_issuer_key=True,
    )
    relaxed_historical_policy = EvidenceTrustPolicy(
        policy_version="historical-audit-v2",
        minimum_trust_level=1,
        disallow_watermarked=False,
        require_valid_issuer_key=True,
        reject_compromised_issuer_key=False,
    )

    sample_pre_compromise = SyntheticEvidenceSample(
        sample_id="pre-compromise-seal",
        attestation=_make_attestation("pre-comp", trust_level=1, has_watermark=True),
        issuer_key_id="k1",
        signature_timestamp=1_500,
        directory=compromised_dir,
        directory_cache=cache,
        evaluation_now=10_100,
    )
    sample_post_compromise = SyntheticEvidenceSample(
        sample_id="post-compromise-seal",
        attestation=_make_attestation("post-comp", trust_level=1, has_watermark=True),
        issuer_key_id="k1",
        signature_timestamp=1_900,
        directory=compromised_dir,
        directory_cache=cache,
        evaluation_now=10_100,
    )

    report = simulate_trust_policy_transition(
        [sample_pre_compromise, sample_post_compromise],
        strict_policy,
        relaxed_historical_policy,
    )
    serialized = json.dumps(report.to_dict(), sort_keys=True)

    assert report.newly_accepted_count == 1
    assert report.reason_shift_count == 1
    assert report.results[0].transition == "newly_accepted"
    assert report.results[1].transition == "rejection_reasons_changed"
    assert report.results[1].candidate.reasons == ("invalid_issuer_key_at_signature_time",)

    # Privacy guarantee: private build fingerprints, nonces, commitments, and media digests never appear
    for sample in (sample_pre_compromise, sample_post_compromise):
        assert sample.attestation.capture_nonce not in serialized
        assert sample.attestation.device_commitment not in serialized
        assert sample.attestation.evidence_digest_binding not in serialized
        assert "PRIVATE_BUILD_" not in serialized


def test_simulation_rejects_empty_duplicate_and_oversized_batches_and_bad_policy() -> None:
    policy = EvidenceTrustPolicy(policy_version="v1")
    att = _make_attestation("boundary")
    sample = SyntheticEvidenceSample(sample_id="s1", attestation=att)

    with pytest.raises(ValueError, match="must not be empty"):
        simulate_trust_policy_transition([], policy, policy)

    with pytest.raises(ValueError, match="duplicate sample_id"):
        simulate_trust_policy_transition([sample, sample], policy, policy)

    oversized = [
        SyntheticEvidenceSample(sample_id=f"s-{idx}", attestation=att)
        for idx in range(MAX_SIMULATION_SAMPLES + 1)
    ]
    with pytest.raises(ValueError, match="exceeds maximum bound"):
        simulate_trust_policy_transition(oversized, policy, policy)

    with pytest.raises(ValueError, match="minimum_trust_level"):
        EvidenceTrustPolicy(policy_version="bad-trust", minimum_trust_level=3)

    with pytest.raises(ValueError, match="policy_version"):
        EvidenceTrustPolicy(policy_version="   ")
