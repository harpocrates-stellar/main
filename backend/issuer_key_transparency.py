"""Issuer key transparency and rotation history for Harpocrates.

Provides independently auditable institutional issuer identity and key history
with fail-closed freshness for high-assurance seals. Private organization
fields are never required in public directory artifacts — only opaque identity
hashes and key material hashes are published.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from capture_attestation import (
    VALID_INTEGRITY_CLAIMS,
    VALID_PRIVACY_SCOPES,
    VALID_TIME_SOURCES,
    VALID_TRUST_LEVELS,
    CaptureAttestation,
    canonical_attestation_hash,
)

PROTOCOL = "harpocrates-issuer-key-transparency"
VERSION = 1
SUPPORTED_VERSIONS = {1}

MAX_ACTIVE_KEYS = 8
MAX_EVENTS = 10_000
MAX_SIMULATION_ITEMS = 1_000
MAX_MANIFEST_BYTES = 8_192
MAX_CHECKPOINT_BYTES = 16_384
MAX_EXPLANATION_EVENTS = 16
MAX_EXPLANATION_BYTES = 4_096
DEFAULT_FRESHNESS_SECONDS = 86_400  # 24h
HIGH_ASSURANCE_FRESHNESS_SECONDS = 3_600  # 1h fail-closed window


class KeyStatus(str, Enum):
    ACTIVE = "active"
    ROTATED = "rotated"
    COMPROMISED = "compromised"
    RETIRED = "retired"


class EventType(str, Enum):
    ACTIVATION = "activation"
    ROTATION = "rotation"
    COMPROMISE = "compromise"
    RETIREMENT = "retirement"
    CHECKPOINT = "checkpoint"


class HistoricalValidityReason(str, Enum):
    """Stable reason codes for historical issuer-key validity explanations."""

    VALID_ACTIVE_KEY = "valid_active_key"
    VALID_BEFORE_ROTATION = "valid_before_rotation"
    VALID_BEFORE_RETIREMENT = "valid_before_retirement"
    VALID_BEFORE_COMPROMISE = "valid_before_compromise"
    UNKNOWN_KEY = "unknown_key"
    BEFORE_ACTIVATION = "before_activation"
    ROTATED_BEFORE_SIGNATURE_TIME = "rotated_before_signature_time"
    RETIRED_BEFORE_SIGNATURE_TIME = "retired_before_signature_time"
    COMPROMISED_AT_SIGNATURE_TIME = "compromised_at_signature_time"
    EXPIRED_BEFORE_SIGNATURE_TIME = "expired_before_signature_time"


class TransparencyError(ValueError):
    """Raised for protocol / consistency failures."""


class FreshnessError(TransparencyError):
    """Raised when a cached directory checkpoint is stale (fail-closed)."""


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode(
        "utf-8"
    )


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_hex(value: str, length: int = 64) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def _require_hex(name: str, value: str, length: int = 64) -> str:
    if not _is_hex(value, length):
        raise TransparencyError(f"{name} must be a {length}-char hex digest")
    return value.lower()


@dataclass(frozen=True)
class IssuerKey:
    """Public key entry in an issuer manifest (hash only — no private material)."""

    key_id: str
    public_key_hash: str
    algorithm: str
    valid_from: int
    valid_until: int | None = None
    status: KeyStatus = KeyStatus.ACTIVE

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "algorithm": self.algorithm,
            "keyId": self.key_id,
            "publicKeyHash": self.public_key_hash,
            "status": self.status.value,
            "validFrom": self.valid_from,
        }
        if self.valid_until is not None:
            d["validUntil"] = self.valid_until
        return d

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> "IssuerKey":
        status = KeyStatus(str(obj.get("status", "active")))
        return IssuerKey(
            key_id=str(obj["keyId"]),
            public_key_hash=_require_hex("publicKeyHash", str(obj["publicKeyHash"])),
            algorithm=str(obj["algorithm"]),
            valid_from=int(obj["validFrom"]),
            valid_until=int(obj["validUntil"]) if obj.get("validUntil") is not None else None,
            status=status,
        )


@dataclass
class IssuerManifest:
    """Canonical signed issuer metadata (public fields only)."""

    organization_identity_hash: str
    issuer_address: str
    active_keys: list[IssuerKey]
    policy_hash: str
    valid_from: int
    valid_until: int | None = None
    predecessor_manifest_hash: str | None = None
    successor_manifest_hash: str | None = None
    signature_hash: str | None = None  # hash of detached signature bytes
    version: int = VERSION
    protocol: str = PROTOCOL

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "activeKeys": [k.to_dict() for k in self.active_keys],
            "issuerAddress": self.issuer_address,
            "organizationIdentityHash": self.organization_identity_hash,
            "policyHash": self.policy_hash,
            "protocol": self.protocol,
            "validFrom": self.valid_from,
            "version": self.version,
        }
        if self.valid_until is not None:
            d["validUntil"] = self.valid_until
        if self.predecessor_manifest_hash:
            d["predecessorManifestHash"] = self.predecessor_manifest_hash
        if self.successor_manifest_hash:
            d["successorManifestHash"] = self.successor_manifest_hash
        if self.signature_hash:
            d["signatureHash"] = self.signature_hash
        return d

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> "IssuerManifest":
        if obj.get("protocol") != PROTOCOL:
            raise TransparencyError("unsupported issuer transparency protocol")
        raw_version = obj.get("version", 0)
        if (
            isinstance(raw_version, bool)
            or not isinstance(raw_version, int)
            or raw_version not in SUPPORTED_VERSIONS
        ):
            raise TransparencyError("unsupported issuer transparency version")
        # This manifest version understands no critical extensions. A non-empty
        # declaration must fail closed rather than being silently ignored.
        critical_extensions = obj.get("criticalExtensions")
        if critical_extensions is not None:
            if not isinstance(critical_extensions, list) or critical_extensions:
                raise TransparencyError(
                    "unsupported critical extension in issuer manifest"
                )
        keys = [IssuerKey.from_dict(k) for k in obj.get("activeKeys", [])]
        return IssuerManifest(
            organization_identity_hash=_require_hex(
                "organizationIdentityHash", str(obj["organizationIdentityHash"])
            ),
            issuer_address=str(obj["issuerAddress"]),
            active_keys=keys,
            policy_hash=_require_hex("policyHash", str(obj["policyHash"])),
            valid_from=int(obj["validFrom"]),
            valid_until=int(obj["validUntil"]) if obj.get("validUntil") is not None else None,
            predecessor_manifest_hash=(
                _require_hex("predecessorManifestHash", str(obj["predecessorManifestHash"]))
                if obj.get("predecessorManifestHash")
                else None
            ),
            successor_manifest_hash=(
                _require_hex("successorManifestHash", str(obj["successorManifestHash"]))
                if obj.get("successorManifestHash")
                else None
            ),
            signature_hash=(
                _require_hex("signatureHash", str(obj["signatureHash"]))
                if obj.get("signatureHash")
                else None
            ),
            version=int(obj["version"]),
            protocol=str(obj["protocol"]),
        )


def _validate_manifest_keys(active_keys: list[IssuerKey]) -> None:
    """Reject manifests with repeated key identifiers or conflicting key attributes."""
    seen: dict[str, IssuerKey] = {}
    for key in active_keys:
        if not key.key_id:
            raise TransparencyError("keyId is required")
        existing = seen.get(key.key_id)
        if existing is not None:
            if existing != key:
                raise TransparencyError(
                    f"conflicting attributes for repeated keyId: {key.key_id}"
                )
            raise TransparencyError(f"duplicate keyId in manifest: {key.key_id}")
        seen[key.key_id] = key


def canonicalize_manifest(manifest: IssuerManifest) -> str:
    """Deterministic JSON encoding used for hashing and signatures."""
    payload = manifest.to_dict()
    # Signature is over the unsigned body — exclude signatureHash from digest input.
    payload.pop("signatureHash", None)
    encoded = _canonical_json(payload)
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise TransparencyError("issuer manifest exceeds size bound")
    if len(manifest.active_keys) > MAX_ACTIVE_KEYS:
        raise TransparencyError("active key count exceeds bound")
    if not manifest.issuer_address:
        raise TransparencyError("issuerAddress is required")
    _validate_manifest_keys(manifest.active_keys)
    return encoded.decode("utf-8")


def manifest_hash(manifest: IssuerManifest) -> str:
    return _sha256_hex(canonicalize_manifest(manifest).encode("utf-8"))


@dataclass(frozen=True)
class DirectoryEvent:
    """Append-only key lifecycle record."""

    event_type: EventType
    sequence: int
    timestamp: int
    organization_identity_hash: str
    key_id: str
    public_key_hash: str
    previous_event_hash: str | None = None
    related_key_id: str | None = None  # predecessor on rotation
    manifest_hash: str | None = None
    reason_hash: str | None = None  # opaque; never plain private text

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "eventType": self.event_type.value,
            "keyId": self.key_id,
            "organizationIdentityHash": self.organization_identity_hash,
            "publicKeyHash": self.public_key_hash,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
        }
        if self.previous_event_hash:
            d["previousEventHash"] = self.previous_event_hash
        if self.related_key_id:
            d["relatedKeyId"] = self.related_key_id
        if self.manifest_hash:
            d["manifestHash"] = self.manifest_hash
        if self.reason_hash:
            d["reasonHash"] = self.reason_hash
        return d

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> "DirectoryEvent":
        return DirectoryEvent(
            event_type=EventType(str(obj["eventType"])),
            sequence=int(obj["sequence"]),
            timestamp=int(obj["timestamp"]),
            organization_identity_hash=_require_hex(
                "organizationIdentityHash", str(obj["organizationIdentityHash"])
            ),
            key_id=str(obj["keyId"]),
            public_key_hash=_require_hex("publicKeyHash", str(obj["publicKeyHash"])),
            previous_event_hash=(
                _require_hex("previousEventHash", str(obj["previousEventHash"]))
                if obj.get("previousEventHash")
                else None
            ),
            related_key_id=str(obj["relatedKeyId"]) if obj.get("relatedKeyId") else None,
            manifest_hash=(
                _require_hex("manifestHash", str(obj["manifestHash"]))
                if obj.get("manifestHash")
                else None
            ),
            reason_hash=(
                _require_hex("reasonHash", str(obj["reasonHash"])) if obj.get("reasonHash") else None
            ),
        )


def event_hash(event: DirectoryEvent) -> str:
    return _sha256_hex(_canonical_json(event.to_dict()))


@dataclass
class DirectoryCheckpoint:
    """Signed directory consistency checkpoint."""

    tree_head_hash: str
    event_count: int
    timestamp: int
    organization_identity_hash: str
    manifest_hash: str
    signature_hash: str | None = None
    version: int = VERSION
    protocol: str = PROTOCOL

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "eventCount": self.event_count,
            "manifestHash": self.manifest_hash,
            "organizationIdentityHash": self.organization_identity_hash,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
            "treeHeadHash": self.tree_head_hash,
            "version": self.version,
        }
        if self.signature_hash:
            d["signatureHash"] = self.signature_hash
        return d

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> "DirectoryCheckpoint":
        if obj.get("protocol") != PROTOCOL:
            raise TransparencyError("unsupported checkpoint protocol")
        return DirectoryCheckpoint(
            tree_head_hash=_require_hex("treeHeadHash", str(obj["treeHeadHash"])),
            event_count=int(obj["eventCount"]),
            timestamp=int(obj["timestamp"]),
            organization_identity_hash=_require_hex(
                "organizationIdentityHash", str(obj["organizationIdentityHash"])
            ),
            manifest_hash=_require_hex("manifestHash", str(obj["manifestHash"])),
            signature_hash=(
                _require_hex("signatureHash", str(obj["signatureHash"]))
                if obj.get("signatureHash")
                else None
            ),
            version=int(obj.get("version", VERSION)),
            protocol=str(obj.get("protocol", PROTOCOL)),
        )


def canonicalize_checkpoint(checkpoint: DirectoryCheckpoint) -> str:
    payload = checkpoint.to_dict()
    payload.pop("signatureHash", None)
    encoded = _canonical_json(payload)
    if len(encoded) > MAX_CHECKPOINT_BYTES:
        raise TransparencyError("checkpoint exceeds size bound")
    return encoded.decode("utf-8")


def checkpoint_hash(checkpoint: DirectoryCheckpoint) -> str:
    return _sha256_hex(canonicalize_checkpoint(checkpoint).encode("utf-8"))


def compute_tree_head(events: Iterable[DirectoryEvent]) -> str:
    """Deterministic Merkle-style chain head over ordered events."""
    head = "0" * 64
    for ev in events:
        head = _sha256_hex((head + event_hash(ev)).encode("utf-8"))
    return head


@dataclass
class IssuerDirectory:
    """In-memory authoritative directory rebuilt from append-only events."""

    organization_identity_hash: str
    events: list[DirectoryEvent] = field(default_factory=list)
    keys: dict[str, IssuerKey] = field(default_factory=dict)
    current_manifest: IssuerManifest | None = None
    manifests_by_hash: dict[str, IssuerManifest] = field(default_factory=dict)

    def append_event(self, event: DirectoryEvent) -> None:
        if len(self.events) >= MAX_EVENTS:
            raise TransparencyError("event log exceeds bound")
        if event.organization_identity_hash != self.organization_identity_hash:
            raise TransparencyError("event organizationIdentityHash mismatch")
        expected_seq = len(self.events)
        if event.sequence != expected_seq:
            raise TransparencyError(
                f"non-monotonic sequence: expected {expected_seq}, got {event.sequence}"
            )
        if expected_seq == 0:
            if event.previous_event_hash is not None:
                raise TransparencyError("genesis event must not set previousEventHash")
        else:
            prev = event_hash(self.events[-1])
            if event.previous_event_hash != prev:
                raise TransparencyError("broken event chain (previousEventHash mismatch)")

        if event.event_type == EventType.ACTIVATION:
            if event.key_id in self.keys and self.keys[event.key_id].status == KeyStatus.ACTIVE:
                raise TransparencyError("conflicting activation for active key")
            self.keys[event.key_id] = IssuerKey(
                key_id=event.key_id,
                public_key_hash=event.public_key_hash,
                algorithm="ed25519",
                valid_from=event.timestamp,
                status=KeyStatus.ACTIVE,
            )
        elif event.event_type == EventType.ROTATION:
            if not event.related_key_id:
                raise TransparencyError("rotation requires relatedKeyId (predecessor)")
            if event.related_key_id not in self.keys:
                raise TransparencyError("broken rotation link: unknown predecessor key")
            pred = self.keys[event.related_key_id]
            if pred.status == KeyStatus.COMPROMISED:
                raise TransparencyError("cannot rotate from compromised key without retirement")
            self.keys[event.related_key_id] = IssuerKey(
                key_id=pred.key_id,
                public_key_hash=pred.public_key_hash,
                algorithm=pred.algorithm,
                valid_from=pred.valid_from,
                valid_until=event.timestamp,
                status=KeyStatus.ROTATED,
            )
            self.keys[event.key_id] = IssuerKey(
                key_id=event.key_id,
                public_key_hash=event.public_key_hash,
                algorithm=pred.algorithm,
                valid_from=event.timestamp,
                status=KeyStatus.ACTIVE,
            )
        elif event.event_type == EventType.COMPROMISE:
            if event.key_id not in self.keys:
                raise TransparencyError("compromise of unknown key")
            k = self.keys[event.key_id]
            self.keys[event.key_id] = IssuerKey(
                key_id=k.key_id,
                public_key_hash=k.public_key_hash,
                algorithm=k.algorithm,
                valid_from=k.valid_from,
                valid_until=event.timestamp,
                status=KeyStatus.COMPROMISED,
            )
        elif event.event_type == EventType.RETIREMENT:
            if event.key_id not in self.keys:
                raise TransparencyError("retirement of unknown key")
            k = self.keys[event.key_id]
            self.keys[event.key_id] = IssuerKey(
                key_id=k.key_id,
                public_key_hash=k.public_key_hash,
                algorithm=k.algorithm,
                valid_from=k.valid_from,
                valid_until=event.timestamp,
                status=KeyStatus.RETIRED,
            )
        elif event.event_type == EventType.CHECKPOINT:
            pass
        else:
            raise TransparencyError(f"unsupported event type: {event.event_type}")

        self.events.append(event)

    def publish_manifest(self, manifest: IssuerManifest) -> str:
        if manifest.organization_identity_hash != self.organization_identity_hash:
            raise TransparencyError("manifest organizationIdentityHash mismatch")
        h = manifest_hash(manifest)
        if self.current_manifest is not None:
            prev_h = manifest_hash(self.current_manifest)
            if manifest.predecessor_manifest_hash != prev_h:
                raise TransparencyError("broken rotation link: predecessorManifestHash mismatch")
            # Link prior manifest forward for history (does not mutate digest of prior).
            linked = IssuerManifest(
                organization_identity_hash=self.current_manifest.organization_identity_hash,
                issuer_address=self.current_manifest.issuer_address,
                active_keys=list(self.current_manifest.active_keys),
                policy_hash=self.current_manifest.policy_hash,
                valid_from=self.current_manifest.valid_from,
                valid_until=self.current_manifest.valid_until,
                predecessor_manifest_hash=self.current_manifest.predecessor_manifest_hash,
                successor_manifest_hash=h,
                signature_hash=self.current_manifest.signature_hash,
                version=self.current_manifest.version,
                protocol=self.current_manifest.protocol,
            )
            self.manifests_by_hash[prev_h] = linked
        self.manifests_by_hash[h] = manifest
        self.current_manifest = manifest
        return h

    def tree_head(self) -> str:
        return compute_tree_head(self.events)

    def make_checkpoint(self, timestamp: int | None = None, signature_hash: str | None = None) -> DirectoryCheckpoint:
        if self.current_manifest is None:
            raise TransparencyError("cannot checkpoint without a published manifest")
        ts = int(time.time()) if timestamp is None else timestamp
        return DirectoryCheckpoint(
            tree_head_hash=self.tree_head(),
            event_count=len(self.events),
            timestamp=ts,
            organization_identity_hash=self.organization_identity_hash,
            manifest_hash=manifest_hash(self.current_manifest),
            signature_hash=signature_hash,
        )


def rebuild_directory(
    organization_identity_hash: str,
    events: list[DirectoryEvent],
    manifests: list[IssuerManifest] | None = None,
) -> IssuerDirectory:
    """Deterministically rebuild directory state from authoritative events."""
    directory = IssuerDirectory(organization_identity_hash=organization_identity_hash)
    for event in events:
        directory.append_event(event)
    for manifest in manifests or []:
        directory.publish_manifest(manifest)
    return directory


def verify_checkpoint_consistency(
    directory: IssuerDirectory,
    checkpoint: DirectoryCheckpoint,
) -> list[str]:
    """Return consistency errors (empty = consistent). Detects split views / rollback."""
    errors: list[str] = []
    if checkpoint.organization_identity_hash != directory.organization_identity_hash:
        errors.append("organizationIdentityHash mismatch")
    if checkpoint.event_count > len(directory.events):
        errors.append("checkpoint eventCount exceeds local log (possible split view)")
    if checkpoint.event_count < len(directory.events):
        # Local is ahead — ok if prefix matches; detect rollback of published head.
        prefix_head = compute_tree_head(directory.events[: checkpoint.event_count])
        if checkpoint.tree_head_hash != prefix_head:
            errors.append("checkpoint tree head diverges from local prefix (split view)")
    else:
        if checkpoint.tree_head_hash != directory.tree_head():
            errors.append("checkpoint tree head mismatch (split view or tampering)")
    if directory.current_manifest is not None:
        local_mh = manifest_hash(directory.current_manifest)
        if checkpoint.event_count == len(directory.events) and checkpoint.manifest_hash != local_mh:
            errors.append("conflicting manifests at same tree head")
    # Rollback: a previously observed higher sequence must not shrink with different head
    return errors


def detect_rollback(
    previously_seen: DirectoryCheckpoint,
    candidate: DirectoryCheckpoint,
) -> list[str]:
    """Detect checkpoint rollback / equivocation against a previously observed head."""
    errors: list[str] = []
    if candidate.organization_identity_hash != previously_seen.organization_identity_hash:
        errors.append("organizationIdentityHash changed across checkpoints")
    if candidate.event_count < previously_seen.event_count:
        errors.append("checkpoint rollback: eventCount decreased")
    if (
        candidate.event_count == previously_seen.event_count
        and candidate.tree_head_hash != previously_seen.tree_head_hash
    ):
        errors.append("equivocating checkpoints at same eventCount (split view)")
    if (
        candidate.event_count == previously_seen.event_count
        and candidate.manifest_hash != previously_seen.manifest_hash
    ):
        errors.append("conflicting manifests at same eventCount")
    return errors


@dataclass
class DirectoryCache:
    """Client/backend cache with freshness rules."""

    checkpoint: DirectoryCheckpoint
    fetched_at: int
    max_age_seconds: int = DEFAULT_FRESHNESS_SECONDS

    def age_seconds(self, now: int | None = None) -> int:
        ts = int(time.time()) if now is None else now
        return max(0, ts - self.fetched_at)

    def is_fresh(self, now: int | None = None, max_age: int | None = None) -> bool:
        limit = self.max_age_seconds if max_age is None else max_age
        return self.age_seconds(now) <= limit


def require_fresh_checkpoint(
    cache: DirectoryCache,
    *,
    high_assurance: bool = False,
    now: int | None = None,
) -> DirectoryCheckpoint:
    """Fail-closed freshness gate for high-assurance seals."""
    max_age = HIGH_ASSURANCE_FRESHNESS_SECONDS if high_assurance else cache.max_age_seconds
    if not cache.is_fresh(now=now, max_age=max_age):
        raise FreshnessError(
            "stale directory checkpoint"
            + (" (high-assurance fail-closed)" if high_assurance else "")
        )
    return cache.checkpoint


def key_valid_for_historical_signature(
    directory: IssuerDirectory,
    key_id: str,
    signature_timestamp: int,
) -> bool:
    """Rotation must not invalidate signatures made while the key was valid.

    A key is acceptable for a historical signature if the signature timestamp
    falls within [valid_from, valid_until) (or open-ended if still active),
    regardless of later rotation/retirement. Compromised keys remain valid for
    pre-compromise signatures but callers should surface compromise status.
    """
    key = directory.keys.get(key_id)
    if key is None:
        return False
    if signature_timestamp < key.valid_from:
        return False
    if key.valid_until is not None and signature_timestamp >= key.valid_until:
        return False
    return True


def key_was_compromised_at(directory: IssuerDirectory, key_id: str, at: int) -> bool:
    key = directory.keys.get(key_id)
    if key is None or key.status != KeyStatus.COMPROMISED:
        return False
    # Compromised at valid_until boundary.
    return key.valid_until is not None and at >= key.valid_until


@dataclass(frozen=True)
class LifecycleEventRef:
    """Public, bounded reference to a key lifecycle event."""

    event_type: EventType
    sequence: int
    timestamp: int
    event_hash: str
    key_id: str
    related_key_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "eventHash": self.event_hash,
            "eventType": self.event_type.value,
            "keyId": self.key_id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
        }
        if self.related_key_id:
            d["relatedKeyId"] = self.related_key_id
        return d

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> "LifecycleEventRef":
        return LifecycleEventRef(
            event_type=EventType(str(obj["eventType"])),
            sequence=int(obj["sequence"]),
            timestamp=int(obj["timestamp"]),
            event_hash=_require_hex("eventHash", str(obj["eventHash"])),
            key_id=str(obj["keyId"]),
            related_key_id=str(obj["relatedKeyId"]) if obj.get("relatedKeyId") else None,
        )


@dataclass(frozen=True)
class HistoricalKeyValidityExplanation:
    """Bounded, privacy-preserving explanation of historical issuer-key validity.

    Contains only public directory metadata, stable reason codes, and bounded
    public lifecycle event references. Never includes private evidence
    identifiers, media digests, or raw organization/user fields.
    """

    organization_identity_hash: str
    key_id: str
    signature_timestamp: int
    valid: bool
    reason_code: HistoricalValidityReason
    key_status: KeyStatus | None
    valid_from: int | None
    valid_until: int | None
    compromised_at_signature_time: bool
    compromised_later: bool
    lifecycle_events: tuple[LifecycleEventRef, ...] = ()
    events_truncated: bool = False
    version: int = VERSION
    protocol: str = PROTOCOL

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "compromisedAtSignatureTime": self.compromised_at_signature_time,
            "compromisedLater": self.compromised_later,
            "eventsTruncated": self.events_truncated,
            "keyId": self.key_id,
            "lifecycleEvents": [ref.to_dict() for ref in self.lifecycle_events],
            "organizationIdentityHash": self.organization_identity_hash,
            "protocol": self.protocol,
            "reasonCode": self.reason_code.value,
            "signatureTimestamp": self.signature_timestamp,
            "valid": self.valid,
            "version": self.version,
        }
        if self.key_status is not None:
            d["keyStatus"] = self.key_status.value
        if self.valid_from is not None:
            d["validFrom"] = self.valid_from
        if self.valid_until is not None:
            d["validUntil"] = self.valid_until
        return d

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> "HistoricalKeyValidityExplanation":
        if obj.get("protocol") != PROTOCOL:
            raise TransparencyError("unsupported issuer transparency protocol")
        if int(obj.get("version", 0)) not in SUPPORTED_VERSIONS:
            raise TransparencyError("unsupported issuer transparency version")
        raw_events = obj.get("lifecycleEvents", [])
        if len(raw_events) > MAX_EXPLANATION_EVENTS:
            raise TransparencyError("explanation lifecycleEvents exceeds bound")
        return HistoricalKeyValidityExplanation(
            organization_identity_hash=_require_hex(
                "organizationIdentityHash", str(obj["organizationIdentityHash"])
            ),
            key_id=str(obj["keyId"]),
            signature_timestamp=int(obj["signatureTimestamp"]),
            valid=bool(obj["valid"]),
            reason_code=HistoricalValidityReason(str(obj["reasonCode"])),
            key_status=KeyStatus(str(obj["keyStatus"])) if obj.get("keyStatus") is not None else None,
            valid_from=int(obj["validFrom"]) if obj.get("validFrom") is not None else None,
            valid_until=int(obj["validUntil"]) if obj.get("validUntil") is not None else None,
            compromised_at_signature_time=bool(obj["compromisedAtSignatureTime"]),
            compromised_later=bool(obj["compromisedLater"]),
            lifecycle_events=tuple(LifecycleEventRef.from_dict(e) for e in raw_events),
            events_truncated=bool(obj.get("eventsTruncated", False)),
            version=int(obj["version"]),
            protocol=str(obj["protocol"]),
        )


def canonicalize_validity_explanation(explanation: HistoricalKeyValidityExplanation) -> str:
    """Deterministic bounded JSON encoding of a historical validity explanation."""
    if len(explanation.lifecycle_events) > MAX_EXPLANATION_EVENTS:
        raise TransparencyError("explanation lifecycleEvents exceeds bound")
    encoded = _canonical_json(explanation.to_dict())
    if len(encoded) > MAX_EXPLANATION_BYTES:
        raise TransparencyError("validity explanation exceeds size bound")
    return encoded.decode("utf-8")


def explain_historical_key_validity(
    directory: IssuerDirectory,
    key_id: str,
    signature_timestamp: int,
    *,
    max_events: int = MAX_EXPLANATION_EVENTS,
) -> HistoricalKeyValidityExplanation:
    """Explain historical issuer-key validity as a bounded public record.

    Reuses ``key_valid_for_historical_signature`` and ``key_was_compromised_at``
    for the underlying validity decision, attaches a stable reason code, and
    includes bounded public lifecycle event references without private evidence
    identifiers.
    """
    if max_events < 1 or max_events > MAX_EXPLANATION_EVENTS:
        raise TransparencyError(
            f"max_events must be between 1 and {MAX_EXPLANATION_EVENTS}"
        )

    valid = key_valid_for_historical_signature(directory, key_id, signature_timestamp)
    compromised_at = key_was_compromised_at(directory, key_id, signature_timestamp)
    key = directory.keys.get(key_id)

    if key is None:
        reason = HistoricalValidityReason.UNKNOWN_KEY
        compromised_later = False
    elif valid:
        compromised_later = key.status == KeyStatus.COMPROMISED and not compromised_at
        if key.status == KeyStatus.ACTIVE:
            reason = HistoricalValidityReason.VALID_ACTIVE_KEY
        elif key.status == KeyStatus.ROTATED:
            reason = HistoricalValidityReason.VALID_BEFORE_ROTATION
        elif key.status == KeyStatus.RETIRED:
            reason = HistoricalValidityReason.VALID_BEFORE_RETIREMENT
        else:
            reason = HistoricalValidityReason.VALID_BEFORE_COMPROMISE
    else:
        compromised_later = False
        if signature_timestamp < key.valid_from:
            reason = HistoricalValidityReason.BEFORE_ACTIVATION
        elif compromised_at:
            reason = HistoricalValidityReason.COMPROMISED_AT_SIGNATURE_TIME
        elif key.status == KeyStatus.ROTATED:
            reason = HistoricalValidityReason.ROTATED_BEFORE_SIGNATURE_TIME
        elif key.status == KeyStatus.RETIRED:
            reason = HistoricalValidityReason.RETIRED_BEFORE_SIGNATURE_TIME
        else:
            reason = HistoricalValidityReason.EXPIRED_BEFORE_SIGNATURE_TIME

    matching_refs = [
        LifecycleEventRef(
            event_type=ev.event_type,
            sequence=ev.sequence,
            timestamp=ev.timestamp,
            event_hash=event_hash(ev),
            key_id=ev.key_id,
            related_key_id=ev.related_key_id,
        )
        for ev in directory.events
        if ev.event_type != EventType.CHECKPOINT
        and (ev.key_id == key_id or ev.related_key_id == key_id)
    ]
    truncated = len(matching_refs) > max_events
    bounded_refs = tuple(matching_refs[:max_events])

    explanation = HistoricalKeyValidityExplanation(
        organization_identity_hash=directory.organization_identity_hash,
        key_id=key_id,
        signature_timestamp=signature_timestamp,
        valid=valid,
        reason_code=reason,
        key_status=key.status if key is not None else None,
        valid_from=key.valid_from if key is not None else None,
        valid_until=key.valid_until if key is not None else None,
        compromised_at_signature_time=compromised_at,
        compromised_later=compromised_later,
        lifecycle_events=bounded_refs,
        events_truncated=truncated,
    )
    # Enforce canonical byte-size bound fail-closed.
    canonicalize_validity_explanation(explanation)
    return explanation


def create_activation_event(
    organization_identity_hash: str,
    key_id: str,
    public_key_hash: str,
    sequence: int,
    timestamp: int,
    previous_event_hash: str | None = None,
    manifest_hash_value: str | None = None,
) -> DirectoryEvent:
    return DirectoryEvent(
        event_type=EventType.ACTIVATION,
        sequence=sequence,
        timestamp=timestamp,
        organization_identity_hash=_require_hex(
            "organizationIdentityHash", organization_identity_hash
        ),
        key_id=key_id,
        public_key_hash=_require_hex("publicKeyHash", public_key_hash),
        previous_event_hash=previous_event_hash,
        manifest_hash=manifest_hash_value,
    )


def create_rotation_event(
    organization_identity_hash: str,
    new_key_id: str,
    new_public_key_hash: str,
    predecessor_key_id: str,
    sequence: int,
    timestamp: int,
    previous_event_hash: str,
    manifest_hash_value: str | None = None,
) -> DirectoryEvent:
    return DirectoryEvent(
        event_type=EventType.ROTATION,
        sequence=sequence,
        timestamp=timestamp,
        organization_identity_hash=_require_hex(
            "organizationIdentityHash", organization_identity_hash
        ),
        key_id=new_key_id,
        public_key_hash=_require_hex("publicKeyHash", new_public_key_hash),
        previous_event_hash=previous_event_hash,
        related_key_id=predecessor_key_id,
        manifest_hash=manifest_hash_value,
    )


# ── Trust-policy simulation for captured evidence ──────────────────────────


@dataclass(frozen=True)
class TrustPolicy:
    """Immutable trust policy version for evaluating captured evidence."""

    policy_version: str
    allowed_trust_levels: frozenset[int] = frozenset({1, 2})
    allowed_privacy_scopes: frozenset[str] = frozenset(VALID_PRIVACY_SCOPES)
    require_secure_time: bool = False
    allowed_time_sources: frozenset[str] = frozenset(VALID_TIME_SOURCES)
    max_time_drift_ms: int | None = None
    allowed_integrity_claims: frozenset[str] | None = None
    require_signing_digest: bool = False
    allow_compromised_pre_compromise_key: bool = True
    allow_rotated_key: bool = True
    max_checkpoint_age_seconds: int = DEFAULT_FRESHNESS_SECONDS
    high_assurance_max_checkpoint_age_seconds: int = HIGH_ASSURANCE_FRESHNESS_SECONDS

    def __post_init__(self) -> None:
        if not isinstance(self.policy_version, str) or not self.policy_version.strip():
            raise TransparencyError("policy_version must be a non-empty string")
        if not self.allowed_trust_levels or not self.allowed_trust_levels.issubset(
            VALID_TRUST_LEVELS
        ):
            raise TransparencyError("allowed_trust_levels must be a non-empty subset of valid trust levels")
        if not self.allowed_privacy_scopes or not self.allowed_privacy_scopes.issubset(
            VALID_PRIVACY_SCOPES
        ):
            raise TransparencyError("allowed_privacy_scopes must be a non-empty subset of valid privacy scopes")
        if not self.allowed_time_sources or not self.allowed_time_sources.issubset(
            VALID_TIME_SOURCES
        ):
            raise TransparencyError("allowed_time_sources must be a non-empty subset of valid time sources")
        if self.max_time_drift_ms is not None and self.max_time_drift_ms < 0:
            raise TransparencyError("max_time_drift_ms must be non-negative")
        if self.allowed_integrity_claims is not None and (
            not self.allowed_integrity_claims
            or not self.allowed_integrity_claims.issubset(VALID_INTEGRITY_CLAIMS)
        ):
            raise TransparencyError(
                "allowed_integrity_claims must be a non-empty subset of valid integrity claims"
            )
        if self.max_checkpoint_age_seconds < 0:
            raise TransparencyError("max_checkpoint_age_seconds must be non-negative")
        if self.high_assurance_max_checkpoint_age_seconds < 0:
            raise TransparencyError("high_assurance_max_checkpoint_age_seconds must be non-negative")

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "allowCompromisedPreCompromiseKey": self.allow_compromised_pre_compromise_key,
            "allowRotatedKey": self.allow_rotated_key,
            "allowedPrivacyScopes": sorted(self.allowed_privacy_scopes),
            "allowedTimeSources": sorted(self.allowed_time_sources),
            "allowedTrustLevels": sorted(self.allowed_trust_levels),
            "highAssuranceMaxCheckpointAgeSeconds": self.high_assurance_max_checkpoint_age_seconds,
            "maxCheckpointAgeSeconds": self.max_checkpoint_age_seconds,
            "policyVersion": self.policy_version,
            "requireSecureTime": self.require_secure_time,
            "requireSigningDigest": self.require_signing_digest,
        }
        if self.max_time_drift_ms is not None:
            d["maxTimeDriftMs"] = self.max_time_drift_ms
        if self.allowed_integrity_claims is not None:
            d["allowedIntegrityClaims"] = sorted(self.allowed_integrity_claims)
        return d


def trust_policy_hash(policy: TrustPolicy) -> str:
    """Deterministic SHA-256 digest of a canonical trust policy."""
    return _sha256_hex(_canonical_json(policy.to_dict()))


@dataclass(frozen=True)
class CapturedEvidenceSample:
    """Synthetic or captured evidence attestation bound to optional issuer key context."""

    evidence_id: str
    attestation: CaptureAttestation
    key_id: str | None = None
    signature_timestamp: int | None = None
    high_assurance: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_id, str) or not self.evidence_id.strip():
            raise TransparencyError("evidence_id must be a non-empty string")


@dataclass(frozen=True)
class PolicyEvaluationOutcome:
    """Privacy-preserving evaluation result for a single evidence sample."""

    evidence_id: str
    attestation_hash: str
    policy_version: str
    policy_hash: str
    accepted: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "attestationHash": self.attestation_hash,
            "evidenceId": self.evidence_id,
            "policyHash": self.policy_hash,
            "policyVersion": self.policy_version,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class PolicyOutcomeDiff:
    """Changed evaluation outcome between baseline and candidate trust policies."""

    evidence_id: str
    attestation_hash: str
    change_type: str  # newly_rejected | newly_accepted | reasons_changed
    baseline_accepted: bool
    candidate_accepted: bool
    baseline_reasons: tuple[str, ...]
    candidate_reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "attestationHash": self.attestation_hash,
            "baselineAccepted": self.baseline_accepted,
            "baselineReasons": list(self.baseline_reasons),
            "candidateAccepted": self.candidate_accepted,
            "candidateReasons": list(self.candidate_reasons),
            "changeType": self.change_type,
            "evidenceId": self.evidence_id,
        }


@dataclass(frozen=True)
class PolicySimulationReport:
    """Non-mutating comparison report across two trust policy versions."""

    baseline_policy_version: str
    baseline_policy_hash: str
    candidate_policy_version: str
    candidate_policy_hash: str
    total_evaluated: int
    unchanged_count: int
    changed_count: int
    newly_rejected_count: int
    newly_accepted_count: int
    reason_changed_count: int
    changes: tuple[PolicyOutcomeDiff, ...]
    active_policy_mutated: bool = False
    version: int = VERSION
    protocol: str = PROTOCOL

    def to_dict(self) -> dict[str, Any]:
        return {
            "activePolicyMutated": self.active_policy_mutated,
            "baselinePolicyHash": self.baseline_policy_hash,
            "baselinePolicyVersion": self.baseline_policy_version,
            "candidatePolicyHash": self.candidate_policy_hash,
            "candidatePolicyVersion": self.candidate_policy_version,
            "changedCount": self.changed_count,
            "changes": [c.to_dict() for c in self.changes],
            "newlyAcceptedCount": self.newly_accepted_count,
            "newlyRejectedCount": self.newly_rejected_count,
            "protocol": self.protocol,
            "reasonChangedCount": self.reason_changed_count,
            "totalEvaluated": self.total_evaluated,
            "unchangedCount": self.unchanged_count,
            "version": self.version,
        }


def evaluate_captured_evidence(
    sample: CapturedEvidenceSample,
    policy: TrustPolicy,
    *,
    directory: IssuerDirectory | None = None,
    cache: DirectoryCache | None = None,
    now: int | None = None,
) -> PolicyEvaluationOutcome:
    """Evaluate a single captured evidence sample under a trust policy (fail-closed)."""
    att = sample.attestation
    reasons: list[str] = []

    if att.trust_level not in policy.allowed_trust_levels:
        reasons.append("trust_level_not_allowed")
    if att.privacy_scope not in policy.allowed_privacy_scopes:
        reasons.append("privacy_scope_not_allowed")
    if policy.require_signing_digest and not att.app_identity.signing_digest:
        reasons.append("missing_app_signing_digest")

    if policy.require_secure_time and att.secure_time is None:
        reasons.append("missing_secure_time")
    if att.secure_time is not None:
        if att.secure_time.source not in policy.allowed_time_sources:
            reasons.append("time_source_not_allowed")
        if (
            policy.max_time_drift_ms is not None
            and abs(att.secure_time.drift_ms) > policy.max_time_drift_ms
        ):
            reasons.append("time_drift_exceeded")

    if policy.allowed_integrity_claims is not None:
        claimed = att.camera_pipeline.claimed_integrity if att.camera_pipeline else None
        if claimed not in policy.allowed_integrity_claims:
            reasons.append("camera_integrity_not_allowed")

    if sample.key_id is not None:
        if directory is None:
            reasons.append("missing_issuer_directory")
        elif sample.signature_timestamp is None:
            reasons.append("missing_signature_timestamp")
        else:
            if not key_valid_for_historical_signature(
                directory, sample.key_id, sample.signature_timestamp
            ):
                reasons.append("key_invalid_at_signature_time")
            key = directory.keys.get(sample.key_id)
            if key is not None:
                if (
                    key.status == KeyStatus.COMPROMISED
                    and not policy.allow_compromised_pre_compromise_key
                ):
                    reasons.append("key_compromised_disallowed")
                if key.status == KeyStatus.ROTATED and not policy.allow_rotated_key:
                    reasons.append("rotated_key_disallowed")
                if key_was_compromised_at(directory, sample.key_id, sample.signature_timestamp):
                    reasons.append("key_compromised_at_signature_time")

    if cache is not None:
        max_age = (
            policy.high_assurance_max_checkpoint_age_seconds
            if sample.high_assurance
            else policy.max_checkpoint_age_seconds
        )
        if not cache.is_fresh(now=now, max_age=max_age):
            reasons.append("stale_directory_checkpoint")

    sorted_reasons = tuple(sorted(set(reasons)))
    return PolicyEvaluationOutcome(
        evidence_id=sample.evidence_id,
        attestation_hash=canonical_attestation_hash(att),
        policy_version=policy.policy_version,
        policy_hash=trust_policy_hash(policy),
        accepted=len(sorted_reasons) == 0,
        reasons=sorted_reasons,
    )


def simulate_trust_policy(
    samples: Iterable[CapturedEvidenceSample],
    baseline_policy: TrustPolicy,
    candidate_policy: TrustPolicy,
    *,
    directory: IssuerDirectory | None = None,
    cache: DirectoryCache | None = None,
    now: int | None = None,
) -> PolicySimulationReport:
    """Simulate a candidate trust policy against a baseline without modifying active policy.

    Evaluates each synthetic or captured attestation under both policies and
    returns a canonical report containing only the changed outcomes and summary
    counts. Both policies, the directory, and the cache are treated as read-only.
    """
    sample_list = list(samples)
    if len(sample_list) > MAX_SIMULATION_ITEMS:
        raise TransparencyError(
            f"simulation batch exceeds bound ({len(sample_list)} > {MAX_SIMULATION_ITEMS})"
        )

    seen_ids: set[str] = set()
    for s in sample_list:
        if s.evidence_id in seen_ids:
            raise TransparencyError(f"duplicate evidence_id in simulation batch: {s.evidence_id}")
        seen_ids.add(s.evidence_id)

    changes: list[PolicyOutcomeDiff] = []
    unchanged_count = 0
    newly_rejected_count = 0
    newly_accepted_count = 0
    reason_changed_count = 0

    for sample in sample_list:
        base_out = evaluate_captured_evidence(
            sample, baseline_policy, directory=directory, cache=cache, now=now
        )
        cand_out = evaluate_captured_evidence(
            sample, candidate_policy, directory=directory, cache=cache, now=now
        )

        if base_out.accepted == cand_out.accepted and base_out.reasons == cand_out.reasons:
            unchanged_count += 1
            continue

        if base_out.accepted and not cand_out.accepted:
            change_type = "newly_rejected"
            newly_rejected_count += 1
        elif not base_out.accepted and cand_out.accepted:
            change_type = "newly_accepted"
            newly_accepted_count += 1
        else:
            change_type = "reasons_changed"
            reason_changed_count += 1

        changes.append(
            PolicyOutcomeDiff(
                evidence_id=sample.evidence_id,
                attestation_hash=base_out.attestation_hash,
                change_type=change_type,
                baseline_accepted=base_out.accepted,
                candidate_accepted=cand_out.accepted,
                baseline_reasons=base_out.reasons,
                candidate_reasons=cand_out.reasons,
            )
        )

    return PolicySimulationReport(
        baseline_policy_version=baseline_policy.policy_version,
        baseline_policy_hash=trust_policy_hash(baseline_policy),
        candidate_policy_version=candidate_policy.policy_version,
        candidate_policy_hash=trust_policy_hash(candidate_policy),
        total_evaluated=len(sample_list),
        unchanged_count=unchanged_count,
        changed_count=len(changes),
        newly_rejected_count=newly_rejected_count,
        newly_accepted_count=newly_accepted_count,
        reason_changed_count=reason_changed_count,
        changes=tuple(changes),
        active_policy_mutated=False,
    )


def canonicalize_simulation_report(report: PolicySimulationReport) -> str:
    """Deterministic JSON encoding for a trust-policy simulation report."""
    return _canonical_json(report.to_dict()).decode("utf-8")


def simulation_report_hash(report: PolicySimulationReport) -> str:
    """Deterministic SHA-256 digest of a canonical trust-policy simulation report."""
    return _sha256_hex(canonicalize_simulation_report(report).encode("utf-8"))
