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

PROTOCOL = "harpocrates-issuer-key-transparency"
VERSION = 1
SUPPORTED_VERSIONS = {1}

MAX_ACTIVE_KEYS = 8
MAX_EVENTS = 10_000
MAX_MANIFEST_BYTES = 8_192
MAX_CHECKPOINT_BYTES = 16_384
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
        if int(obj.get("version", 0)) not in SUPPORTED_VERSIONS:
            raise TransparencyError("unsupported issuer transparency version")
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


# ── Historical issuer-key validity explanation record ──────────────────────

HISTORICAL_VALIDITY_EXPLANATION_SCHEMA = "harpocrates-historical-key-validity-explanation/v1"
DEFAULT_EXPLANATION_EVENT_REFS = 8
MAX_EXPLANATION_EVENT_REFS = 16

_PRIVATE_EVIDENCE_KEY_TOKENS = (
    "evidence",
    "video",
    "nonce",
    "device",
    "witness",
    "nullifier",
    "secret",
    "fingerprint",
    "proofid",
    "session",
    "email",
    "phone",
    "legalname",
)


def _reject_private_evidence_keys(obj: Any) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            normalized = str(k).lower().replace("_", "")
            if any(tok in normalized for tok in _PRIVATE_EVIDENCE_KEY_TOKENS):
                raise TransparencyError(
                    "historical validity explanation must not contain private evidence identifiers"
                )
            _reject_private_evidence_keys(v)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _reject_private_evidence_keys(item)


class HistoricalKeyValidityReason(str, Enum):
    VALID_ACTIVE_KEY = "valid_active_key"
    VALID_HISTORICAL_ROTATED_KEY = "valid_historical_rotated_key"
    VALID_HISTORICAL_RETIRED_KEY = "valid_historical_retired_key"
    VALID_PRE_COMPROMISE_WARNING = "valid_pre_compromise_warning"
    INVALID_UNKNOWN_KEY = "invalid_unknown_key"
    INVALID_BEFORE_ACTIVATION = "invalid_before_activation"
    INVALID_AT_OR_AFTER_ROTATION = "invalid_at_or_after_rotation"
    INVALID_AT_OR_AFTER_RETIREMENT = "invalid_at_or_after_retirement"
    INVALID_AT_OR_AFTER_COMPROMISE = "invalid_at_or_after_compromise"
    INVALID_EXPIRED_WINDOW = "invalid_expired_window"


@dataclass(frozen=True)
class PublicLifecycleEventReference:
    """Bounded public directory lifecycle reference (no private evidence fields)."""

    sequence: int
    event_type: EventType
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
        if self.related_key_id is not None:
            d["relatedKeyId"] = self.related_key_id
        return d

    @staticmethod
    def from_event(event: DirectoryEvent) -> PublicLifecycleEventReference:
        return PublicLifecycleEventReference(
            sequence=event.sequence,
            event_type=event.event_type,
            timestamp=event.timestamp,
            event_hash=event_hash(event),
            key_id=event.key_id,
            related_key_id=event.related_key_id,
        )

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> PublicLifecycleEventReference:
        allowed = {"eventHash", "eventType", "keyId", "relatedKeyId", "sequence", "timestamp"}
        if set(obj.keys()) - allowed:
            raise TransparencyError("unexpected field in lifecycle event reference")
        seq = obj.get("sequence")
        ts = obj.get("timestamp")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise TransparencyError("event reference sequence must be a non-negative integer")
        if isinstance(ts, bool) or not isinstance(ts, int) or ts < 0:
            raise TransparencyError("event reference timestamp must be a non-negative integer")
        return PublicLifecycleEventReference(
            sequence=seq,
            event_type=EventType(str(obj["eventType"])),
            timestamp=ts,
            event_hash=_require_hex("eventHash", str(obj["eventHash"])),
            key_id=str(obj["keyId"]),
            related_key_id=str(obj["relatedKeyId"]) if obj.get("relatedKeyId") else None,
        )


@dataclass(frozen=True)
class HistoricalKeyValidityExplanation:
    """Bounded, evidence-agnostic explanation of signature-time issuer key validity."""

    organization_identity_hash: str
    key_id: str
    signature_timestamp: int
    valid: bool
    reason_code: HistoricalKeyValidityReason
    key_status: KeyStatus | None
    valid_from: int | None
    valid_until: int | None
    compromise_warning: bool
    compromised_at_signature_time: bool
    event_references: tuple[PublicLifecycleEventReference, ...]
    total_matching_events: int
    truncated_event_references: bool

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "compromiseWarning": self.compromise_warning,
            "compromisedAtSignatureTime": self.compromised_at_signature_time,
            "eventReferences": [ref.to_dict() for ref in self.event_references],
            "keyId": self.key_id,
            "keyStatus": self.key_status.value if self.key_status is not None else None,
            "organizationIdentityHash": self.organization_identity_hash,
            "reasonCode": self.reason_code.value,
            "schema": HISTORICAL_VALIDITY_EXPLANATION_SCHEMA,
            "signatureTimestamp": self.signature_timestamp,
            "totalMatchingEvents": self.total_matching_events,
            "truncatedEventReferences": self.truncated_event_references,
            "valid": self.valid,
            "validFrom": self.valid_from,
            "validUntil": self.valid_until,
        }
        _reject_private_evidence_keys(payload)
        return payload

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> HistoricalKeyValidityExplanation:
        if not isinstance(obj, dict):
            raise TransparencyError("explanation payload must be a JSON object")
        _reject_private_evidence_keys(obj)
        allowed = {
            "compromiseWarning",
            "compromisedAtSignatureTime",
            "eventReferences",
            "keyId",
            "keyStatus",
            "organizationIdentityHash",
            "reasonCode",
            "schema",
            "signatureTimestamp",
            "totalMatchingEvents",
            "truncatedEventReferences",
            "valid",
            "validFrom",
            "validUntil",
        }
        if set(obj.keys()) - allowed:
            raise TransparencyError("unexpected field in historical validity explanation")
        if obj.get("schema") != HISTORICAL_VALIDITY_EXPLANATION_SCHEMA:
            raise TransparencyError("unsupported historical validity explanation schema")
        refs_raw = obj.get("eventReferences")
        if not isinstance(refs_raw, list) or len(refs_raw) > MAX_EXPLANATION_EVENT_REFS:
            raise TransparencyError("eventReferences exceeds bound or is malformed")
        sig_ts = obj.get("signatureTimestamp")
        total = obj.get("totalMatchingEvents")
        if isinstance(sig_ts, bool) or not isinstance(sig_ts, int) or sig_ts < 0:
            raise TransparencyError("signatureTimestamp must be a non-negative integer")
        if isinstance(total, bool) or not isinstance(total, int) or total < 0:
            raise TransparencyError("totalMatchingEvents must be a non-negative integer")
        for flag_name in ("valid", "compromiseWarning", "compromisedAtSignatureTime", "truncatedEventReferences"):
            if not isinstance(obj.get(flag_name), bool):
                raise TransparencyError(f"{flag_name} must be a boolean")
        vf = obj.get("validFrom")
        vu = obj.get("validUntil")
        if vf is not None and (isinstance(vf, bool) or not isinstance(vf, int)):
            raise TransparencyError("validFrom must be an integer or null")
        if vu is not None and (isinstance(vu, bool) or not isinstance(vu, int)):
            raise TransparencyError("validUntil must be an integer or null")
        status_raw = obj.get("keyStatus")
        return HistoricalKeyValidityExplanation(
            organization_identity_hash=_require_hex(
                "organizationIdentityHash", str(obj["organizationIdentityHash"])
            ),
            key_id=str(obj["keyId"]),
            signature_timestamp=sig_ts,
            valid=bool(obj["valid"]),
            reason_code=HistoricalKeyValidityReason(str(obj["reasonCode"])),
            key_status=KeyStatus(str(status_raw)) if status_raw is not None else None,
            valid_from=vf,
            valid_until=vu,
            compromise_warning=bool(obj["compromiseWarning"]),
            compromised_at_signature_time=bool(obj["compromisedAtSignatureTime"]),
            event_references=tuple(PublicLifecycleEventReference.from_dict(r) for r in refs_raw),
            total_matching_events=total,
            truncated_event_references=bool(obj["truncatedEventReferences"]),
        )


def _select_bounded_lifecycle_refs(
    events: list[DirectoryEvent],
    key_id: str,
    max_refs: int,
) -> tuple[tuple[PublicLifecycleEventReference, ...], int, bool]:
    matching = [ev for ev in events if ev.key_id == key_id or ev.related_key_id == key_id]
    total = len(matching)
    if total <= max_refs:
        return (
            tuple(PublicLifecycleEventReference.from_event(ev) for ev in matching),
            total,
            False,
        )
    if max_refs == 1:
        selected = [matching[-1]]
    else:
        selected = [matching[0], *matching[-(max_refs - 1) :]]
    return (
        tuple(PublicLifecycleEventReference.from_event(ev) for ev in selected),
        total,
        True,
    )


def explain_historical_issuer_key_validity(
    directory: IssuerDirectory,
    key_id: str,
    signature_timestamp: int,
    *,
    max_event_refs: int = DEFAULT_EXPLANATION_EVENT_REFS,
    evidence_context: dict[str, Any] | None = None,
) -> HistoricalKeyValidityExplanation:
    """Explain signature-time key validity with stable reason codes and public event refs.

    Reuses ``key_valid_for_historical_signature`` and ``key_was_compromised_at``
    directly while omitting any private evidence identifiers from ``evidence_context``.
    """
    if not isinstance(key_id, str) or not (1 <= len(key_id.strip()) <= 128):
        raise TransparencyError("key_id must be a non-empty bounded string")
    if isinstance(signature_timestamp, bool) or not isinstance(signature_timestamp, int) or signature_timestamp < 0:
        raise TransparencyError("signature_timestamp must be a non-negative integer")
    if (
        isinstance(max_event_refs, bool)
        or not isinstance(max_event_refs, int)
        or max_event_refs < 1
        or max_event_refs > MAX_EXPLANATION_EVENT_REFS
    ):
        raise TransparencyError(
            f"max_event_refs must be an integer in 1..{MAX_EXPLANATION_EVENT_REFS}"
        )
    # Explicitly ignore evidence_context so private evidence identifiers never enter the explanation.
    _ = evidence_context

    valid = key_valid_for_historical_signature(directory, key_id, signature_timestamp)
    compromised_at_sig = key_was_compromised_at(directory, key_id, signature_timestamp)
    key = directory.keys.get(key_id)
    refs, total_matching, truncated = _select_bounded_lifecycle_refs(
        directory.events, key_id, max_event_refs
    )

    if key is None:
        reason = HistoricalKeyValidityReason.INVALID_UNKNOWN_KEY
        compromise_warning = False
    elif valid:
        if key.status == KeyStatus.ACTIVE:
            reason = HistoricalKeyValidityReason.VALID_ACTIVE_KEY
            compromise_warning = False
        elif key.status == KeyStatus.ROTATED:
            reason = HistoricalKeyValidityReason.VALID_HISTORICAL_ROTATED_KEY
            compromise_warning = False
        elif key.status == KeyStatus.RETIRED:
            reason = HistoricalKeyValidityReason.VALID_HISTORICAL_RETIRED_KEY
            compromise_warning = False
        elif key.status == KeyStatus.COMPROMISED:
            reason = HistoricalKeyValidityReason.VALID_PRE_COMPROMISE_WARNING
            compromise_warning = True
        else:
            reason = HistoricalKeyValidityReason.VALID_ACTIVE_KEY
            compromise_warning = False
    else:
        compromise_warning = key.status == KeyStatus.COMPROMISED
        if signature_timestamp < key.valid_from:
            reason = HistoricalKeyValidityReason.INVALID_BEFORE_ACTIVATION
        elif compromised_at_sig or key.status == KeyStatus.COMPROMISED:
            reason = HistoricalKeyValidityReason.INVALID_AT_OR_AFTER_COMPROMISE
        elif key.status == KeyStatus.ROTATED:
            reason = HistoricalKeyValidityReason.INVALID_AT_OR_AFTER_ROTATION
        elif key.status == KeyStatus.RETIRED:
            reason = HistoricalKeyValidityReason.INVALID_AT_OR_AFTER_RETIREMENT
        else:
            reason = HistoricalKeyValidityReason.INVALID_EXPIRED_WINDOW

    return HistoricalKeyValidityExplanation(
        organization_identity_hash=_require_hex(
            "organizationIdentityHash", directory.organization_identity_hash
        ),
        key_id=key_id,
        signature_timestamp=signature_timestamp,
        valid=valid,
        reason_code=reason,
        key_status=key.status if key is not None else None,
        valid_from=key.valid_from if key is not None else None,
        valid_until=key.valid_until if key is not None else None,
        compromise_warning=compromise_warning,
        compromised_at_signature_time=compromised_at_sig,
        event_references=refs,
        total_matching_events=total_matching,
        truncated_event_references=truncated,
    )

