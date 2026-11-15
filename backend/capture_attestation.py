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
        IssuerDirectory,
        evaluate_issuer_signing_standing,
    )
except ImportError:  # pragma: no cover - package import fallback
    from backend.issuer_key_transparency import (
        DirectoryCache,
        IssuerDirectory,
        evaluate_issuer_signing_standing,
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


# ── Trust-policy simulation for captured evidence ──────────────────────────

SIMULATION_REPORT_SCHEMA = "harpocrates-trust-policy-simulation/v1"
MAX_SIMULATION_SAMPLES = 256
_ASSURANCE_ORDERED_TRUST_LEVELS = {0, 1, 2}
_DEGRADED_TRUST_LEVELS = {3, 4}


@dataclass(frozen=True)
class EvidenceTrustPolicy:
    """Immutable trust policy version for evaluating captured evidence."""

    policy_version: str
    minimum_trust_level: int = 1
    allow_degraded_trust_levels: frozenset[int] = field(default_factory=frozenset)
    require_secure_time: bool = False
    allowed_time_sources: tuple[str, ...] = (
        "hardware_clock",
        "ntp_synchronized",
        "platform_clock",
    )
    max_clock_drift_ms: int | None = None
    allowed_privacy_scopes: tuple[str, ...] = (
        "per_session",
        "per_relying_party",
        "per_device_group",
    )
    allowed_integrity_claims: tuple[str, ...] | None = None
    disallow_watermarked: bool = False
    require_valid_issuer_key: bool = False
    reject_compromised_issuer_key: bool = True
    high_assurance_freshness: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.policy_version, str) or not (
            1 <= len(self.policy_version.strip()) <= 64
        ):
            raise ValueError("policy_version must be a non-empty string up to 64 chars")
        if (
            isinstance(self.minimum_trust_level, bool)
            or self.minimum_trust_level not in _ASSURANCE_ORDERED_TRUST_LEVELS
        ):
            raise ValueError("minimum_trust_level must be 0, 1, or 2")
        if any(level not in _DEGRADED_TRUST_LEVELS for level in self.allow_degraded_trust_levels):
            raise ValueError("allow_degraded_trust_levels may only contain 3 or 4")
        if any(src not in VALID_TIME_SOURCES for src in self.allowed_time_sources):
            raise ValueError("allowed_time_sources contains an unsupported time source")
        if self.max_clock_drift_ms is not None and (
            isinstance(self.max_clock_drift_ms, bool)
            or not isinstance(self.max_clock_drift_ms, int)
            or self.max_clock_drift_ms < 0
        ):
            raise ValueError("max_clock_drift_ms must be a non-negative integer")
        if any(scope not in VALID_PRIVACY_SCOPES for scope in self.allowed_privacy_scopes):
            raise ValueError("allowed_privacy_scopes contains an unsupported privacy scope")
        if self.allowed_integrity_claims is not None and any(
            claim not in VALID_INTEGRITY_CLAIMS for claim in self.allowed_integrity_claims
        ):
            raise ValueError("allowed_integrity_claims contains an unsupported integrity claim")

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowDegradedTrustLevels": sorted(self.allow_degraded_trust_levels),
            "allowedIntegrityClaims": (
                sorted(self.allowed_integrity_claims)
                if self.allowed_integrity_claims is not None
                else None
            ),
            "allowedPrivacyScopes": sorted(self.allowed_privacy_scopes),
            "allowedTimeSources": sorted(self.allowed_time_sources),
            "disallowWatermarked": self.disallow_watermarked,
            "highAssuranceFreshness": self.high_assurance_freshness,
            "maxClockDriftMs": self.max_clock_drift_ms,
            "minimumTrustLevel": self.minimum_trust_level,
            "policyVersion": self.policy_version.strip(),
            "rejectCompromisedIssuerKey": self.reject_compromised_issuer_key,
            "requireSecureTime": self.require_secure_time,
            "requireValidIssuerKey": self.require_valid_issuer_key,
        }

    def policy_hash(self) -> str:
        return hashlib.sha256(_canonical_json(self.to_dict())).hexdigest()


class ActiveTrustPolicyRegistry:
    """Holds the active production trust policy; simulations must never mutate it."""

    def __init__(self, active_policy: EvidenceTrustPolicy) -> None:
        if not isinstance(active_policy, EvidenceTrustPolicy):
            raise TypeError("active_policy must be an EvidenceTrustPolicy")
        self._active_policy = active_policy

    @property
    def active_policy(self) -> EvidenceTrustPolicy:
        return self._active_policy


@dataclass(frozen=True)
class SyntheticEvidenceSample:
    """Synthetic evidence input for offline policy simulation."""

    sample_id: str
    attestation: CaptureAttestation
    issuer_key_id: str | None = None
    signature_timestamp: int | None = None
    directory: IssuerDirectory | None = None
    directory_cache: DirectoryCache | None = None
    evaluation_now: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.sample_id, str) or not (1 <= len(self.sample_id.strip()) <= 64):
            raise ValueError("sample_id must be a non-empty string up to 64 chars")
        if not isinstance(self.attestation, CaptureAttestation):
            raise TypeError("attestation must be a CaptureAttestation")


@dataclass(frozen=True)
class PolicyEvaluationOutcome:
    """Outcome of evaluating one synthetic sample against one policy version."""

    policy_version: str
    policy_hash: str
    accepted: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "outcome": "accepted" if self.accepted else "rejected",
            "policyHash": self.policy_hash,
            "policyVersion": self.policy_version,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class SampleSimulationDiff:
    """Per-sample comparison across baseline and candidate trust policies."""

    sample_id: str
    attestation_hash: str
    baseline: PolicyEvaluationOutcome
    candidate: PolicyEvaluationOutcome
    changed: bool
    transition: str
    added_reasons: tuple[str, ...]
    removed_reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "addedReasons": list(self.added_reasons),
            "attestationHash": self.attestation_hash,
            "baseline": self.baseline.to_dict(),
            "candidate": self.candidate.to_dict(),
            "changed": self.changed,
            "removedReasons": list(self.removed_reasons),
            "sampleId": self.sample_id,
            "transition": self.transition,
        }


@dataclass(frozen=True)
class TrustPolicySimulationReport:
    """Read-only simulation report comparing two policy versions on synthetic samples."""

    baseline_policy_version: str
    baseline_policy_hash: str
    candidate_policy_version: str
    candidate_policy_hash: str
    active_policy_version: str | None
    active_policy_hash: str | None
    active_policy_mutated: bool
    results: tuple[SampleSimulationDiff, ...]
    changed_sample_ids: tuple[str, ...]
    newly_accepted_count: int
    newly_rejected_count: int
    reason_shift_count: int
    unchanged_count: int

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "activePolicyHash": self.active_policy_hash,
            "activePolicyMutated": self.active_policy_mutated,
            "activePolicyVersion": self.active_policy_version,
            "baselinePolicyHash": self.baseline_policy_hash,
            "baselinePolicyVersion": self.baseline_policy_version,
            "candidatePolicyHash": self.candidate_policy_hash,
            "candidatePolicyVersion": self.candidate_policy_version,
            "changedSampleIds": list(self.changed_sample_ids),
            "results": [r.to_dict() for r in self.results],
            "schema": SIMULATION_REPORT_SCHEMA,
            "summary": {
                "changedCount": len(self.changed_sample_ids),
                "newlyAcceptedCount": self.newly_accepted_count,
                "newlyRejectedCount": self.newly_rejected_count,
                "reasonShiftCount": self.reason_shift_count,
                "totalSamples": len(self.results),
                "unchangedCount": self.unchanged_count,
            },
        }
        body["reportHash"] = hashlib.sha256(_canonical_json(body)).hexdigest()
        return body


def evaluate_evidence_trust_policy(
    sample: SyntheticEvidenceSample,
    policy: EvidenceTrustPolicy,
) -> PolicyEvaluationOutcome:
    """Evaluate a synthetic evidence sample against a trust policy without side effects."""
    reasons: list[str] = []
    att = sample.attestation

    if att.trust_level in _DEGRADED_TRUST_LEVELS:
        if att.trust_level not in policy.allow_degraded_trust_levels:
            reasons.append("degraded_trust_level")
    elif att.trust_level < policy.minimum_trust_level:
        reasons.append("insufficient_trust_level")

    if att.privacy_scope not in policy.allowed_privacy_scopes:
        reasons.append("disallowed_privacy_scope")

    if att.secure_time is None:
        if policy.require_secure_time:
            reasons.append("missing_secure_time")
    else:
        if att.secure_time.source not in policy.allowed_time_sources:
            reasons.append("disallowed_time_source")
        if (
            policy.max_clock_drift_ms is not None
            and abs(att.secure_time.drift_ms) > policy.max_clock_drift_ms
        ):
            reasons.append("excessive_clock_drift")

    if policy.disallow_watermarked and att.camera_pipeline and att.camera_pipeline.has_watermark:
        reasons.append("watermarked_pipeline_disallowed")

    if policy.allowed_integrity_claims is not None:
        claimed = att.camera_pipeline.claimed_integrity if att.camera_pipeline else None
        if claimed is None:
            reasons.append("missing_integrity_claim")
        elif claimed not in policy.allowed_integrity_claims:
            reasons.append("disallowed_integrity_claim")

    if policy.require_valid_issuer_key:
        if (
            sample.directory is None
            or sample.issuer_key_id is None
            or sample.signature_timestamp is None
        ):
            reasons.append("missing_issuer_context")
        else:
            _, issuer_reasons = evaluate_issuer_signing_standing(
                sample.directory,
                sample.issuer_key_id,
                sample.signature_timestamp,
                directory_cache=sample.directory_cache,
                high_assurance=policy.high_assurance_freshness,
                reject_compromised=policy.reject_compromised_issuer_key,
                now=sample.evaluation_now,
            )
            reasons.extend(issuer_reasons)

    deduped = tuple(dict.fromkeys(reasons))
    return PolicyEvaluationOutcome(
        policy_version=policy.policy_version.strip(),
        policy_hash=policy.policy_hash(),
        accepted=len(deduped) == 0,
        reasons=deduped,
    )


def simulate_trust_policy_transition(
    samples: list[SyntheticEvidenceSample] | tuple[SyntheticEvidenceSample, ...],
    baseline_policy: EvidenceTrustPolicy,
    candidate_policy: EvidenceTrustPolicy,
    *,
    active_registry: ActiveTrustPolicyRegistry | None = None,
) -> TrustPolicySimulationReport:
    """Simulate two policy versions over synthetic attestations without modifying active policy."""
    if not isinstance(baseline_policy, EvidenceTrustPolicy) or not isinstance(
        candidate_policy, EvidenceTrustPolicy
    ):
        raise TypeError("baseline_policy and candidate_policy must be EvidenceTrustPolicy")
    if len(samples) == 0:
        raise ValueError("samples must not be empty")
    if len(samples) > MAX_SIMULATION_SAMPLES:
        raise ValueError(f"samples exceeds maximum bound ({MAX_SIMULATION_SAMPLES})")

    active_before_version: str | None = None
    active_before_hash: str | None = None
    if active_registry is not None:
        active_before_version = active_registry.active_policy.policy_version.strip()
        active_before_hash = active_registry.active_policy.policy_hash()

    seen_ids: set[str] = set()
    diffs: list[SampleSimulationDiff] = []
    changed_ids: list[str] = []
    newly_accepted = 0
    newly_rejected = 0
    reason_shifts = 0
    unchanged = 0

    for sample in samples:
        if not isinstance(sample, SyntheticEvidenceSample):
            raise TypeError("each sample must be a SyntheticEvidenceSample")
        sid = sample.sample_id.strip()
        if sid in seen_ids:
            raise ValueError(f"duplicate sample_id in simulation: {sid}")
        seen_ids.add(sid)

        base_out = evaluate_evidence_trust_policy(sample, baseline_policy)
        cand_out = evaluate_evidence_trust_policy(sample, candidate_policy)

        added = tuple(r for r in cand_out.reasons if r not in base_out.reasons)
        removed = tuple(r for r in base_out.reasons if r not in cand_out.reasons)

        if base_out.accepted and cand_out.accepted:
            transition = "unchanged_accepted"
            changed = False
            unchanged += 1
        elif not base_out.accepted and cand_out.accepted:
            transition = "newly_accepted"
            changed = True
            newly_accepted += 1
            changed_ids.append(sid)
        elif base_out.accepted and not cand_out.accepted:
            transition = "newly_rejected"
            changed = True
            newly_rejected += 1
            changed_ids.append(sid)
        elif base_out.reasons != cand_out.reasons:
            transition = "rejection_reasons_changed"
            changed = True
            reason_shifts += 1
            changed_ids.append(sid)
        else:
            transition = "unchanged_rejected"
            changed = False
            unchanged += 1

        diffs.append(
            SampleSimulationDiff(
                sample_id=sid,
                attestation_hash=canonical_attestation_hash(sample.attestation),
                baseline=base_out,
                candidate=cand_out,
                changed=changed,
                transition=transition,
                added_reasons=added,
                removed_reasons=removed,
            )
        )

    active_mutated = False
    if active_registry is not None:
        active_mutated = (
            active_registry.active_policy.policy_version.strip() != active_before_version
            or active_registry.active_policy.policy_hash() != active_before_hash
        )

    return TrustPolicySimulationReport(
        baseline_policy_version=baseline_policy.policy_version.strip(),
        baseline_policy_hash=baseline_policy.policy_hash(),
        candidate_policy_version=candidate_policy.policy_version.strip(),
        candidate_policy_hash=candidate_policy.policy_hash(),
        active_policy_version=active_before_version,
        active_policy_hash=active_before_hash,
        active_policy_mutated=active_mutated,
        results=tuple(diffs),
        changed_sample_ids=tuple(changed_ids),
        newly_accepted_count=newly_accepted,
        newly_rejected_count=newly_rejected,
        reason_shift_count=reason_shifts,
        unchanged_count=unchanged,
    )
