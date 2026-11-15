"""
Time attestation envelope for Harpocrates evidence protocol.

Implements versioned time-attestation envelopes supporting:
- Claimed capture time (from device/user)
- Observed registration time (backend timestamp)
- Independent anchors: Stellar ledger timestamps and RFC 3161 TSA tokens

Designed to prevent backdating, detect digest substitution, and provide
graduated trust levels without breaking privacy guarantees.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Literal
from datetime import datetime, timezone

try:
    from rfc3161_chain import (
        TrustStore,
        validate_rfc3161_certificate_chain,
        trust_store_from_b64_roots,
    )
except ImportError:  # pragma: no cover - package layout / optional path
    TrustStore = None  # type: ignore[misc, assignment]
    validate_rfc3161_certificate_chain = None  # type: ignore[misc, assignment]
    trust_store_from_b64_roots = None  # type: ignore[misc, assignment]

# ── Constants ──────────────────────────────────────────────────────────────

PROFILE_ID = "harpocrates-time-attestation/v1"
SUPPORTED_VERSIONS = {1}

# Maximum allowed future drift: 5 minutes (accounts for clock skew)
MAX_FUTURE_DRIFT_SECONDS = 300

# Maximum resource consumption bounds
MAX_TIMESTAMP_TOKEN_SIZE = 10_000  # 10 KB for RFC 3161 token
MAX_ANCHOR_COUNT = 10  # Maximum independent time sources per envelope

# Time source types
TimeSourceType = Literal["claimed", "observed", "stellar_ledger", "rfc3161_tsa"]

# Verification status
VerificationStatus = Literal["valid", "invalid", "unverified", "expired", "untrusted"]


# ── Data model ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ClaimedTime:
    """Time claimed by the capture device or user."""
    
    unix_ms: int
    source_label: str  # e.g., "device_clock", "manual_entry"
    uncertainty_ms: int = 0  # Clock uncertainty estimate


@dataclass(frozen=True)
class ObservedTime:
    """Time observed by the registration backend."""
    
    unix_ms: int
    source_label: str  # e.g., "backend_ntp_synced", "backend_system_clock"


@dataclass(frozen=True)
class StellarAnchor:
    """Stellar ledger timestamp anchor."""
    
    ledger_sequence: int
    ledger_timestamp: int  # Unix seconds from Stellar ledger
    transaction_hash: str  # 64-char hex
    network_passphrase: str  # e.g., "Test SDF Network ; September 2015"


@dataclass(frozen=True)
class RFC3161Anchor:
    """RFC 3161 timestamp token anchor."""
    
    token_bytes: str  # Base64-encoded DER token
    tsa_url: str
    gen_time: int  # Unix milliseconds from parsed GeneralizedTime
    policy_oid: str | None = None
    cert_fingerprint: str | None = None  # SHA-256 of TSA signing cert
    verification_status: VerificationStatus = "unverified"
    verification_error: str | None = None
    # Optional leaf-first base64 DER TSA certificate chain for offline validation.
    # Absence keeps the historical "unverified" protocol state (lower assurance).
    certificate_chain: list[str] | None = None


@dataclass(frozen=True)
class TimeAttestation:
    """Complete time attestation envelope."""
    
    version: int
    protocol: str
    evidence_digest: str  # 64-char hex SHA-256 of canonical evidence
    
    claimed_time: ClaimedTime | None = None
    observed_time: ObservedTime | None = None
    stellar_anchors: list[StellarAnchor] = field(default_factory=list)
    rfc3161_anchors: list[RFC3161Anchor] = field(default_factory=list)


# ── Encoding ───────────────────────────────────────────────────────────────

def encode_time_attestation(attestation: TimeAttestation) -> dict[str, Any]:
    """Encode a time attestation to canonical JSON-safe dictionary."""
    
    if attestation.version not in SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported time attestation version: {attestation.version}")
    
    if attestation.protocol != PROFILE_ID:
        raise ValueError(f"Protocol mismatch: expected {PROFILE_ID}, got {attestation.protocol}")
    
    if not _is_valid_hex(attestation.evidence_digest, 64):
        raise ValueError("evidence_digest must be 64-character hex string")
    
    if len(attestation.stellar_anchors) + len(attestation.rfc3161_anchors) > MAX_ANCHOR_COUNT:
        raise ValueError(f"Total anchor count exceeds maximum of {MAX_ANCHOR_COUNT}")
    
    obj: dict[str, Any] = {
        "version": attestation.version,
        "protocol": attestation.protocol,
        "evidenceDigest": attestation.evidence_digest,
    }
    
    if attestation.claimed_time:
        obj["claimedTime"] = {
            "unixMs": attestation.claimed_time.unix_ms,
            "sourceLabel": attestation.claimed_time.source_label,
            "uncertaintyMs": attestation.claimed_time.uncertainty_ms,
        }
    
    if attestation.observed_time:
        obj["observedTime"] = {
            "unixMs": attestation.observed_time.unix_ms,
            "sourceLabel": attestation.observed_time.source_label,
        }
    
    if attestation.stellar_anchors:
        obj["stellarAnchors"] = [
            {
                "ledgerSequence": anchor.ledger_sequence,
                "ledgerTimestamp": anchor.ledger_timestamp,
                "transactionHash": anchor.transaction_hash,
                "networkPassphrase": anchor.network_passphrase,
            }
            for anchor in attestation.stellar_anchors
        ]
    
    if attestation.rfc3161_anchors:
        obj["rfc3161Anchors"] = []
        for anchor in attestation.rfc3161_anchors:
            entry = {
                "tokenBytes": anchor.token_bytes,
                "tsaUrl": anchor.tsa_url,
                "genTime": anchor.gen_time,
                "policyOid": anchor.policy_oid,
                "certFingerprint": anchor.cert_fingerprint,
                "verificationStatus": anchor.verification_status,
                "verificationError": anchor.verification_error,
            }
            if anchor.certificate_chain is not None:
                entry["certificateChain"] = list(anchor.certificate_chain)
            obj["rfc3161Anchors"].append(entry)
    
    return obj


def decode_time_attestation(obj: dict[str, Any]) -> TimeAttestation:
    """Decode and validate a time attestation dictionary."""
    
    _validate_time_attestation_obj(obj)
    
    claimed_time = None
    if "claimedTime" in obj:
        ct = obj["claimedTime"]
        claimed_time = ClaimedTime(
            unix_ms=ct["unixMs"],
            source_label=ct["sourceLabel"],
            uncertainty_ms=ct.get("uncertaintyMs", 0),
        )
    
    observed_time = None
    if "observedTime" in obj:
        ot = obj["observedTime"]
        observed_time = ObservedTime(
            unix_ms=ot["unixMs"],
            source_label=ot["sourceLabel"],
        )
    
    stellar_anchors = []
    for anchor_obj in obj.get("stellarAnchors", []):
        stellar_anchors.append(
            StellarAnchor(
                ledger_sequence=anchor_obj["ledgerSequence"],
                ledger_timestamp=anchor_obj["ledgerTimestamp"],
                transaction_hash=anchor_obj["transactionHash"],
                network_passphrase=anchor_obj["networkPassphrase"],
            )
        )
    
    rfc3161_anchors = []
    for anchor_obj in obj.get("rfc3161Anchors", []):
        rfc3161_anchors.append(
            RFC3161Anchor(
                token_bytes=anchor_obj["tokenBytes"],
                tsa_url=anchor_obj["tsaUrl"],
                gen_time=anchor_obj["genTime"],
                policy_oid=anchor_obj.get("policyOid"),
                cert_fingerprint=anchor_obj.get("certFingerprint"),
                verification_status=anchor_obj.get("verificationStatus", "unverified"),
                verification_error=anchor_obj.get("verificationError"),
                certificate_chain=anchor_obj.get("certificateChain"),
            )
        )
    
    return TimeAttestation(
        version=obj["version"],
        protocol=obj["protocol"],
        evidence_digest=obj["evidenceDigest"],
        claimed_time=claimed_time,
        observed_time=observed_time,
        stellar_anchors=stellar_anchors,
        rfc3161_anchors=rfc3161_anchors,
    )


def canonical_time_attestation_hash(attestation: TimeAttestation) -> str:
    """Compute the canonical SHA-256 hash of a time attestation."""
    encoded = encode_time_attestation(attestation)
    canonical = _canonical_json(encoded)
    return hashlib.sha256(canonical).hexdigest()


# ── Validation ─────────────────────────────────────────────────────────────

def validate_time_attestation(attestation: TimeAttestation, evidence_digest: str) -> list[str]:
    """
    Validate a time attestation envelope.
    
    Returns a list of validation errors. Empty list means valid.
    """
    errors: list[str] = []
    
    # Verify evidence digest binding
    if attestation.evidence_digest != evidence_digest:
        errors.append(
            f"Evidence digest mismatch: expected {evidence_digest}, "
            f"got {attestation.evidence_digest}"
        )
    
    current_time_ms = int(time.time() * 1000)
    
    # Validate claimed time
    if attestation.claimed_time:
        claimed_ms = attestation.claimed_time.unix_ms
        if claimed_ms > current_time_ms + (MAX_FUTURE_DRIFT_SECONDS * 1000):
            errors.append(
                f"Claimed time {claimed_ms} is too far in the future "
                f"(current: {current_time_ms})"
            )
        if claimed_ms < 0:
            errors.append(f"Claimed time {claimed_ms} is negative")
    
    # Validate observed time
    if attestation.observed_time:
        observed_ms = attestation.observed_time.unix_ms
        if observed_ms > current_time_ms + (MAX_FUTURE_DRIFT_SECONDS * 1000):
            errors.append(
                f"Observed time {observed_ms} is too far in the future "
                f"(current: {current_time_ms})"
            )
        if observed_ms < 0:
            errors.append(f"Observed time {observed_ms} is negative")
    
    # Validate Stellar anchors
    for i, anchor in enumerate(attestation.stellar_anchors):
        if not _is_valid_hex(anchor.transaction_hash, 64):
            errors.append(
                f"Stellar anchor {i}: transaction_hash must be 64-char hex"
            )
        if anchor.ledger_sequence < 0:
            errors.append(
                f"Stellar anchor {i}: ledger_sequence must be non-negative"
            )
        if anchor.ledger_timestamp < 0:
            errors.append(
                f"Stellar anchor {i}: ledger_timestamp must be non-negative"
            )
    
    # Validate RFC 3161 anchors
    for i, anchor in enumerate(attestation.rfc3161_anchors):
        if len(anchor.token_bytes) > MAX_TIMESTAMP_TOKEN_SIZE:
            errors.append(
                f"RFC 3161 anchor {i}: token exceeds {MAX_TIMESTAMP_TOKEN_SIZE} bytes"
            )
        if anchor.gen_time < 0:
            errors.append(
                f"RFC 3161 anchor {i}: genTime must be non-negative"
            )
        if anchor.gen_time > current_time_ms + (MAX_FUTURE_DRIFT_SECONDS * 1000):
            errors.append(
                f"RFC 3161 anchor {i}: genTime is too far in the future"
            )
    
    # Validate at least one time source exists
    has_time_source = (
        attestation.claimed_time is not None
        or attestation.observed_time is not None
        or attestation.stellar_anchors
        or attestation.rfc3161_anchors
    )
    if not has_time_source:
        errors.append("At least one time source is required")
    
    return errors


def check_backdating_risk(attestation: TimeAttestation) -> dict[str, Any]:
    """
    Analyze backdating risk based on available time sources.
    
    Returns a risk assessment with:
    - risk_level: "none", "low", "medium", "high"
    - reasons: list of contributing factors
    - recommendations: suggested actions
    """
    risk_level = "none"
    reasons: list[str] = []
    recommendations: list[str] = []
    
    has_independent_anchor = bool(
        attestation.stellar_anchors or attestation.rfc3161_anchors
    )
    
    if not has_independent_anchor:
        risk_level = "medium"
        reasons.append("No independent timestamp anchor (Stellar/RFC 3161)")
        recommendations.append("Add Stellar ledger timestamp from transaction")
    
    if attestation.claimed_time and attestation.observed_time:
        claimed_ms = attestation.claimed_time.unix_ms
        observed_ms = attestation.observed_time.unix_ms
        drift_seconds = abs(claimed_ms - observed_ms) / 1000
        
        if drift_seconds > 86400:  # 1 day
            if risk_level == "none":
                risk_level = "low"
            elif risk_level == "medium":
                risk_level = "high"
            reasons.append(
                f"Large drift between claimed and observed time: "
                f"{drift_seconds:.0f} seconds"
            )
        
        if claimed_ms < observed_ms - 3600000:  # Claimed > 1 hour before observed
            if risk_level in ("none", "low"):
                risk_level = "medium"
            elif risk_level == "medium":
                risk_level = "high"
            reasons.append("Claimed time significantly predates observed time")
    
    if not attestation.observed_time:
        if risk_level == "none":
            risk_level = "low"
        reasons.append("No observed registration time recorded")
    
    if not reasons:
        reasons.append("All time sources align within acceptable bounds")
    
    if not recommendations:
        recommendations.append("Time attestation appears robust")
    
    return {
        "risk_level": risk_level,
        "reasons": reasons,
        "recommendations": recommendations,
    }


# ── Factory functions ──────────────────────────────────────────────────────

def create_time_attestation(
    evidence_digest: str,
    claimed_time_ms: int | None = None,
    claimed_source_label: str = "device_clock",
    uncertainty_ms: int = 0,
) -> TimeAttestation:
    """
    Create a new time attestation with observed time.
    
    Automatically captures the current backend time as observed_time.
    Stellar and RFC 3161 anchors should be added separately after
    transaction confirmation or TSA response.
    """
    if not _is_valid_hex(evidence_digest, 64):
        raise ValueError("evidence_digest must be 64-character hex string")
    
    observed_ms = int(time.time() * 1000)
    
    claimed_time = None
    if claimed_time_ms is not None:
        claimed_time = ClaimedTime(
            unix_ms=claimed_time_ms,
            source_label=claimed_source_label,
            uncertainty_ms=uncertainty_ms,
        )
    
    observed_time = ObservedTime(
        unix_ms=observed_ms,
        source_label="backend_system_clock",
    )
    
    return TimeAttestation(
        version=1,
        protocol=PROFILE_ID,
        evidence_digest=evidence_digest,
        claimed_time=claimed_time,
        observed_time=observed_time,
    )


def add_stellar_anchor(
    attestation: TimeAttestation,
    ledger_sequence: int,
    ledger_timestamp: int,
    transaction_hash: str,
    network_passphrase: str,
) -> TimeAttestation:
    """Add a Stellar ledger timestamp anchor to an existing attestation."""
    if len(attestation.stellar_anchors) + len(attestation.rfc3161_anchors) >= MAX_ANCHOR_COUNT:
        raise ValueError(f"Maximum anchor count ({MAX_ANCHOR_COUNT}) reached")
    
    if not _is_valid_hex(transaction_hash, 64):
        raise ValueError("transaction_hash must be 64-character hex string")
    
    new_anchor = StellarAnchor(
        ledger_sequence=ledger_sequence,
        ledger_timestamp=ledger_timestamp,
        transaction_hash=transaction_hash,
        network_passphrase=network_passphrase,
    )
    
    return TimeAttestation(
        version=attestation.version,
        protocol=attestation.protocol,
        evidence_digest=attestation.evidence_digest,
        claimed_time=attestation.claimed_time,
        observed_time=attestation.observed_time,
        stellar_anchors=[*attestation.stellar_anchors, new_anchor],
        rfc3161_anchors=attestation.rfc3161_anchors,
    )


def add_rfc3161_anchor(
    attestation: TimeAttestation,
    token_bytes: str,
    tsa_url: str,
    gen_time: int,
    policy_oid: str | None = None,
    cert_fingerprint: str | None = None,
    verification_status: VerificationStatus = "unverified",
    verification_error: str | None = None,
    certificate_chain: list[str] | None = None,
) -> TimeAttestation:
    """Add an RFC 3161 timestamp token anchor to an existing attestation."""
    if len(attestation.stellar_anchors) + len(attestation.rfc3161_anchors) >= MAX_ANCHOR_COUNT:
        raise ValueError(f"Maximum anchor count ({MAX_ANCHOR_COUNT}) reached")
    
    if len(token_bytes) > MAX_TIMESTAMP_TOKEN_SIZE:
        raise ValueError(f"Timestamp token exceeds {MAX_TIMESTAMP_TOKEN_SIZE} bytes")
    
    new_anchor = RFC3161Anchor(
        token_bytes=token_bytes,
        tsa_url=tsa_url,
        gen_time=gen_time,
        policy_oid=policy_oid,
        cert_fingerprint=cert_fingerprint,
        verification_status=verification_status,
        verification_error=verification_error,
        certificate_chain=certificate_chain,
    )
    
    return TimeAttestation(
        version=attestation.version,
        protocol=attestation.protocol,
        evidence_digest=attestation.evidence_digest,
        claimed_time=attestation.claimed_time,
        observed_time=attestation.observed_time,
        stellar_anchors=attestation.stellar_anchors,
        rfc3161_anchors=[*attestation.rfc3161_anchors, new_anchor],
    )



def verify_rfc3161_anchor_chain(
    anchor: RFC3161Anchor,
    trust_store: "TrustStore | None" = None,
    trust_roots_b64: list[str] | None = None,
    revoked_serials_hex: list[str] | None = None,
) -> RFC3161Anchor:
    """Validate the TSA certificate chain for an RFC 3161 anchor.

    When no certificate_chain is present, returns the anchor unchanged with
    status "unverified" (valid protocol state, lower assurance).

    Failure statuses are stable and privacy-safe (no PEM/DER in error text).
    """
    if not anchor.certificate_chain:
        if anchor.verification_status == "unverified":
            return anchor
        return RFC3161Anchor(
            token_bytes=anchor.token_bytes,
            tsa_url=anchor.tsa_url,
            gen_time=anchor.gen_time,
            policy_oid=anchor.policy_oid,
            cert_fingerprint=anchor.cert_fingerprint,
            verification_status="unverified",
            verification_error=anchor.verification_error or "certificate chain not provided",
            certificate_chain=anchor.certificate_chain,
        )

    if validate_rfc3161_certificate_chain is None or TrustStore is None:
        return RFC3161Anchor(
            token_bytes=anchor.token_bytes,
            tsa_url=anchor.tsa_url,
            gen_time=anchor.gen_time,
            policy_oid=anchor.policy_oid,
            cert_fingerprint=anchor.cert_fingerprint,
            verification_status="unverified",
            verification_error="dependency_failure",
            certificate_chain=anchor.certificate_chain,
        )

    store = trust_store
    if store is None:
        assert trust_store_from_b64_roots is not None
        store = trust_store_from_b64_roots(trust_roots_b64 or [], revoked_serials_hex or [])

    at_time = datetime.fromtimestamp(anchor.gen_time / 1000.0, tz=timezone.utc)
    result = validate_rfc3161_certificate_chain(
        anchor.certificate_chain,
        trust_store=store,
        at_time=at_time,
    )

    status: VerificationStatus
    if result.status in ("valid", "invalid", "unverified", "expired", "untrusted"):
        status = result.status  # type: ignore[assignment]
    else:
        status = "invalid"

    return RFC3161Anchor(
        token_bytes=anchor.token_bytes,
        tsa_url=anchor.tsa_url,
        gen_time=anchor.gen_time,
        policy_oid=anchor.policy_oid,
        cert_fingerprint=result.leaf_fingerprint or anchor.cert_fingerprint,
        verification_status=status,
        verification_error=None if result.ok else (result.error_code or result.error_message),
        certificate_chain=anchor.certificate_chain,
    )


def verify_rfc3161_anchors(
    attestation: TimeAttestation,
    trust_store: "TrustStore | None" = None,
    trust_roots_b64: list[str] | None = None,
    revoked_serials_hex: list[str] | None = None,
) -> TimeAttestation:
    """Return a copy of attestation with RFC 3161 anchors chain-verified."""
    if not attestation.rfc3161_anchors:
        return attestation

    verified = [
        verify_rfc3161_anchor_chain(
            anchor,
            trust_store=trust_store,
            trust_roots_b64=trust_roots_b64,
            revoked_serials_hex=revoked_serials_hex,
        )
        for anchor in attestation.rfc3161_anchors
    ]
    return TimeAttestation(
        version=attestation.version,
        protocol=attestation.protocol,
        evidence_digest=attestation.evidence_digest,
        claimed_time=attestation.claimed_time,
        observed_time=attestation.observed_time,
        stellar_anchors=attestation.stellar_anchors,
        rfc3161_anchors=verified,
    )


# ── Internal helpers ───────────────────────────────────────────────────────

def _canonical_json(obj: dict[str, Any]) -> bytes:
    """Encode dictionary to canonical JSON bytes."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _is_valid_hex(value: str, expected_length: int) -> bool:
    """Check if value is a valid hex string of expected length."""
    if len(value) != expected_length:
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def _validate_time_attestation_obj(obj: dict[str, Any]) -> None:
    """Validate structure of time attestation dictionary."""
    if not isinstance(obj, dict):
        raise TypeError("Time attestation must be a dictionary")
    
    required_fields = ["version", "protocol", "evidenceDigest"]
    for field in required_fields:
        if field not in obj:
            raise ValueError(f"Missing required field: {field}")
    
    if obj["version"] not in SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported version: {obj['version']}")
    
    if obj["protocol"] != PROFILE_ID:
        raise ValueError(f"Protocol mismatch: expected {PROFILE_ID}, got {obj['protocol']}")
    
    if not isinstance(obj["evidenceDigest"], str):
        raise TypeError("evidenceDigest must be a string")
    
    if not _is_valid_hex(obj["evidenceDigest"], 64):
        raise ValueError("evidenceDigest must be 64-character hex string")


# ── Offline timestamp-chain validation report ──────────────────────────────

OFFLINE_TIMESTAMP_CHAIN_REPORT_SCHEMA = "harpocrates-offline-timestamp-chain-report/v1"

BoundedDependencyTrustResult = Literal[
    "verified_trusted",
    "self_asserted_bounded",
    "trust_material_unavailable",
    "signature_or_chain_invalid",
    "untrusted_anchor",
]

DependencyFailureClassification = Literal[
    "none",
    "invalid_signature",
    "invalid_chain_or_policy",
    "unavailable_trust_material",
]

OverallTimestampAssurance = Literal[
    "verified_independent_anchor",
    "bounded_unverified_material",
    "self_asserted_only",
    "failed_validation",
]


@dataclass(frozen=True)
class TimestampDependencyEntry:
    """Per-dependency bounded offline validation result."""

    dependency_id: str
    source_type: TimeSourceType
    trust_result: BoundedDependencyTrustResult
    failure_classification: DependencyFailureClassification
    reason_code: str
    timestamp_unix_ms: int
    leaf_fingerprint: str | None = None
    root_fingerprint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "dependencyId": self.dependency_id,
            "failureClassification": self.failure_classification,
            "reasonCode": self.reason_code,
            "sourceType": self.source_type,
            "timestampUnixMs": self.timestamp_unix_ms,
            "trustResult": self.trust_result,
        }
        if self.leaf_fingerprint is not None:
            d["leafFingerprint"] = self.leaf_fingerprint
        if self.root_fingerprint is not None:
            d["rootFingerprint"] = self.root_fingerprint
        return d


@dataclass(frozen=True)
class OfflineTimestampChainReport:
    """Structured offline validation report over all attestation dependencies."""

    evidence_digest: str
    evidence_digest_matches: bool
    overall_assurance: OverallTimestampAssurance
    has_invalid_signatures: bool
    has_unavailable_trust_material: bool
    dependencies: tuple[TimestampDependencyEntry, ...]
    invalid_signature_dependencies: tuple[str, ...]
    unavailable_trust_material_dependencies: tuple[str, ...]
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "dependencies": [dep.to_dict() for dep in self.dependencies],
            "errors": list(self.errors),
            "evidenceDigest": self.evidence_digest,
            "evidenceDigestMatches": self.evidence_digest_matches,
            "hasInvalidSignatures": self.has_invalid_signatures,
            "hasUnavailableTrustMaterial": self.has_unavailable_trust_material,
            "invalidSignatureDependencies": list(self.invalid_signature_dependencies),
            "overallAssurance": self.overall_assurance,
            "schema": OFFLINE_TIMESTAMP_CHAIN_REPORT_SCHEMA,
            "unavailableTrustMaterialDependencies": list(
                self.unavailable_trust_material_dependencies
            ),
        }


def _has_matching_issuer_subject_in_store(
    chain_b64: list[str],
    store: "TrustStore",
) -> bool:
    """Detect when a configured root matches ``last.issuer`` so signature failure is not misreported as untrusted."""
    try:
        import base64 as _b64

        from cryptography import x509 as _x509

        last_cert = _x509.load_der_x509_certificate(_b64.b64decode(chain_b64[-1], validate=True))
        for root_der in store.root_der_list:
            root_cert = _x509.load_der_x509_certificate(root_der)
            if last_cert.issuer == root_cert.subject:
                return True
    except Exception:
        return False
    return False


def _evaluate_rfc3161_dependency(
    idx: int,
    anchor: RFC3161Anchor,
    *,
    store: "TrustStore | None",
    has_trust_roots: bool,
    eval_now_ms: int,
) -> TimestampDependencyEntry:
    dep_id = f"rfc3161_anchor[{idx}]"
    if len(anchor.token_bytes) > MAX_TIMESTAMP_TOKEN_SIZE or anchor.gen_time < 0 or (
        anchor.gen_time > eval_now_ms + (MAX_FUTURE_DRIFT_SECONDS * 1000)
    ):
        return TimestampDependencyEntry(
            dependency_id=dep_id,
            source_type="rfc3161_tsa",
            trust_result="signature_or_chain_invalid",
            failure_classification="invalid_chain_or_policy",
            reason_code="invalid_token_bounds",
            timestamp_unix_ms=anchor.gen_time,
            leaf_fingerprint=anchor.cert_fingerprint,
        )

    if not anchor.certificate_chain:
        return TimestampDependencyEntry(
            dependency_id=dep_id,
            source_type="rfc3161_tsa",
            trust_result="trust_material_unavailable",
            failure_classification="unavailable_trust_material",
            reason_code="missing_certificate_chain",
            timestamp_unix_ms=anchor.gen_time,
            leaf_fingerprint=anchor.cert_fingerprint,
        )

    if validate_rfc3161_certificate_chain is None or TrustStore is None:
        return TimestampDependencyEntry(
            dependency_id=dep_id,
            source_type="rfc3161_tsa",
            trust_result="trust_material_unavailable",
            failure_classification="unavailable_trust_material",
            reason_code="dependency_failure",
            timestamp_unix_ms=anchor.gen_time,
            leaf_fingerprint=anchor.cert_fingerprint,
        )

    assert store is not None
    at_time = datetime.fromtimestamp(anchor.gen_time / 1000.0, tz=timezone.utc)
    chain_res = validate_rfc3161_certificate_chain(
        anchor.certificate_chain,
        trust_store=store,
        at_time=at_time,
    )

    if chain_res.ok:
        return TimestampDependencyEntry(
            dependency_id=dep_id,
            source_type="rfc3161_tsa",
            trust_result="verified_trusted",
            failure_classification="none",
            reason_code="verified",
            timestamp_unix_ms=anchor.gen_time,
            leaf_fingerprint=chain_res.leaf_fingerprint or anchor.cert_fingerprint,
            root_fingerprint=chain_res.root_fingerprint,
        )

    code = chain_res.error_code or "chain_validation_failed"
    if code == "dependency_failure":
        return TimestampDependencyEntry(
            dependency_id=dep_id,
            source_type="rfc3161_tsa",
            trust_result="trust_material_unavailable",
            failure_classification="unavailable_trust_material",
            reason_code="dependency_failure",
            timestamp_unix_ms=anchor.gen_time,
            leaf_fingerprint=chain_res.leaf_fingerprint,
        )

    if code == "untrusted_root":
        if not has_trust_roots:
            return TimestampDependencyEntry(
                dependency_id=dep_id,
                source_type="rfc3161_tsa",
                trust_result="trust_material_unavailable",
                failure_classification="unavailable_trust_material",
                reason_code="missing_trust_roots",
                timestamp_unix_ms=anchor.gen_time,
                leaf_fingerprint=chain_res.leaf_fingerprint,
            )
        if _has_matching_issuer_subject_in_store(anchor.certificate_chain, store):
            return TimestampDependencyEntry(
                dependency_id=dep_id,
                source_type="rfc3161_tsa",
                trust_result="signature_or_chain_invalid",
                failure_classification="invalid_signature",
                reason_code="signature_invalid",
                timestamp_unix_ms=anchor.gen_time,
                leaf_fingerprint=chain_res.leaf_fingerprint,
            )
        return TimestampDependencyEntry(
            dependency_id=dep_id,
            source_type="rfc3161_tsa",
            trust_result="untrusted_anchor",
            failure_classification="invalid_chain_or_policy",
            reason_code="untrusted_root",
            timestamp_unix_ms=anchor.gen_time,
            leaf_fingerprint=chain_res.leaf_fingerprint,
        )

    if code == "signature_invalid":
        return TimestampDependencyEntry(
            dependency_id=dep_id,
            source_type="rfc3161_tsa",
            trust_result="signature_or_chain_invalid",
            failure_classification="invalid_signature",
            reason_code="signature_invalid",
            timestamp_unix_ms=anchor.gen_time,
            leaf_fingerprint=chain_res.leaf_fingerprint,
            root_fingerprint=chain_res.root_fingerprint,
        )

    return TimestampDependencyEntry(
        dependency_id=dep_id,
        source_type="rfc3161_tsa",
        trust_result="signature_or_chain_invalid",
        failure_classification="invalid_chain_or_policy",
        reason_code=code,
        timestamp_unix_ms=anchor.gen_time,
        leaf_fingerprint=chain_res.leaf_fingerprint,
        root_fingerprint=chain_res.root_fingerprint,
    )


def build_offline_timestamp_chain_report(
    attestation: TimeAttestation,
    *,
    expected_evidence_digest: str | None = None,
    trust_store: "TrustStore | None" = None,
    trust_roots_b64: list[str] | None = None,
    revoked_serials_hex: list[str] | None = None,
    offline_stellar_snapshots: dict[str, dict[str, Any]] | None = None,
    now_unix_ms: int | None = None,
) -> OfflineTimestampChainReport:
    """Validate every attestation dependency offline and classify bounded trust results.

    Cleanly separates cryptographic signature/chain failures from unavailable
    offline trust material (missing TSA chains, empty trust stores, or absent
    offline ledger snapshots).
    """
    eval_now_ms = int(time.time() * 1000) if now_unix_ms is None else now_unix_ms
    target_digest = (
        attestation.evidence_digest
        if expected_evidence_digest is None
        else expected_evidence_digest
    )
    digest_matches = attestation.evidence_digest == target_digest
    errors: list[str] = []
    if not digest_matches:
        errors.append("evidence_digest_mismatch")

    resolved_store = trust_store
    if resolved_store is None and TrustStore is not None and trust_store_from_b64_roots is not None:
        resolved_store = trust_store_from_b64_roots(
            trust_roots_b64 or [], revoked_serials_hex or []
        )
    has_trust_roots = bool(resolved_store is not None and len(resolved_store.root_der_list) > 0)

    deps: list[TimestampDependencyEntry] = []

    if attestation.claimed_time is not None:
        ct = attestation.claimed_time
        ct_ok = 0 <= ct.unix_ms <= eval_now_ms + (MAX_FUTURE_DRIFT_SECONDS * 1000)
        deps.append(
            TimestampDependencyEntry(
                dependency_id="claimed_time",
                source_type="claimed",
                trust_result="self_asserted_bounded" if ct_ok else "signature_or_chain_invalid",
                failure_classification="none" if ct_ok else "invalid_chain_or_policy",
                reason_code="bounded_unanchored_claim" if ct_ok else "claimed_time_out_of_bounds",
                timestamp_unix_ms=ct.unix_ms,
            )
        )

    if attestation.observed_time is not None:
        ot = attestation.observed_time
        ot_ok = 0 <= ot.unix_ms <= eval_now_ms + (MAX_FUTURE_DRIFT_SECONDS * 1000)
        deps.append(
            TimestampDependencyEntry(
                dependency_id="observed_time",
                source_type="observed",
                trust_result="self_asserted_bounded" if ot_ok else "signature_or_chain_invalid",
                failure_classification="none" if ot_ok else "invalid_chain_or_policy",
                reason_code="bounded_backend_observation" if ot_ok else "observed_time_out_of_bounds",
                timestamp_unix_ms=ot.unix_ms,
            )
        )

    for idx, s_anchor in enumerate(attestation.stellar_anchors):
        dep_id = f"stellar_anchor[{idx}]"
        tx_ms = s_anchor.ledger_timestamp * 1000
        if (
            not _is_valid_hex(s_anchor.transaction_hash, 64)
            or s_anchor.ledger_sequence < 0
            or s_anchor.ledger_timestamp < 0
        ):
            deps.append(
                TimestampDependencyEntry(
                    dependency_id=dep_id,
                    source_type="stellar_ledger",
                    trust_result="signature_or_chain_invalid",
                    failure_classification="invalid_chain_or_policy",
                    reason_code="malformed_stellar_anchor",
                    timestamp_unix_ms=tx_ms,
                )
            )
        elif offline_stellar_snapshots is None or s_anchor.transaction_hash not in offline_stellar_snapshots:
            deps.append(
                TimestampDependencyEntry(
                    dependency_id=dep_id,
                    source_type="stellar_ledger",
                    trust_result="trust_material_unavailable",
                    failure_classification="unavailable_trust_material",
                    reason_code="missing_offline_ledger_snapshot",
                    timestamp_unix_ms=tx_ms,
                )
            )
        else:
            snap = offline_stellar_snapshots[s_anchor.transaction_hash]
            snap_ok = (
                snap.get("ledgerSequence") == s_anchor.ledger_sequence
                and snap.get("ledgerTimestamp") == s_anchor.ledger_timestamp
                and snap.get("networkPassphrase") == s_anchor.network_passphrase
                and (
                    snap.get("signatureValid", True) is True
                )
            )
            if not snap.get("signatureValid", True):
                deps.append(
                    TimestampDependencyEntry(
                        dependency_id=dep_id,
                        source_type="stellar_ledger",
                        trust_result="signature_or_chain_invalid",
                        failure_classification="invalid_signature",
                        reason_code="signature_invalid",
                        timestamp_unix_ms=tx_ms,
                    )
                )
            elif not snap_ok:
                deps.append(
                    TimestampDependencyEntry(
                        dependency_id=dep_id,
                        source_type="stellar_ledger",
                        trust_result="signature_or_chain_invalid",
                        failure_classification="invalid_chain_or_policy",
                        reason_code="ledger_snapshot_mismatch",
                        timestamp_unix_ms=tx_ms,
                    )
                )
            else:
                deps.append(
                    TimestampDependencyEntry(
                        dependency_id=dep_id,
                        source_type="stellar_ledger",
                        trust_result="verified_trusted",
                        failure_classification="none",
                        reason_code="verified",
                        timestamp_unix_ms=tx_ms,
                    )
                )

    for idx, r_anchor in enumerate(attestation.rfc3161_anchors):
        deps.append(
            _evaluate_rfc3161_dependency(
                idx,
                r_anchor,
                store=resolved_store,
                has_trust_roots=has_trust_roots,
                eval_now_ms=eval_now_ms,
            )
        )

    if not deps:
        errors.append("no_time_sources")

    invalid_sig_ids = tuple(
        d.dependency_id for d in deps if d.failure_classification == "invalid_signature"
    )
    unavail_ids = tuple(
        d.dependency_id for d in deps if d.failure_classification == "unavailable_trust_material"
    )
    any_hard_failure = (
        not digest_matches
        or not deps
        or any(
            d.trust_result in ("signature_or_chain_invalid", "untrusted_anchor")
            for d in deps
        )
    )
    any_verified_anchor = any(d.trust_result == "verified_trusted" for d in deps)

    overall: OverallTimestampAssurance
    if any_hard_failure:
        overall = "failed_validation"
    elif any_verified_anchor:
        overall = "verified_independent_anchor"
    elif unavail_ids:
        overall = "bounded_unverified_material"
    else:
        overall = "self_asserted_only"

    return OfflineTimestampChainReport(
        evidence_digest=attestation.evidence_digest,
        evidence_digest_matches=digest_matches,
        overall_assurance=overall,
        has_invalid_signatures=len(invalid_sig_ids) > 0,
        has_unavailable_trust_material=len(unavail_ids) > 0,
        dependencies=tuple(deps),
        invalid_signature_dependencies=invalid_sig_ids,
        unavailable_trust_material_dependencies=unavail_ids,
        errors=tuple(errors),
    )

