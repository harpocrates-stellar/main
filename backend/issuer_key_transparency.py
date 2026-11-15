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


# ── Offline issuer trust snapshot exports ──────────────────────────────────

OFFLINE_TRUST_SNAPSHOT_SCHEMA = "harpocrates-offline-issuer-trust-snapshot/v1"
OFFLINE_TRUST_SNAPSHOT_VERSION = 1
MAX_SNAPSHOT_ISSUERS = 128

_FORBIDDEN_PRIVATE_KEY_TOKENS = (
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


def _assert_no_private_keys(obj: Any) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            lowered = str(k).lower().replace("_", "")
            if any(tok in lowered for tok in _FORBIDDEN_PRIVATE_KEY_TOKENS):
                raise TransparencyError(
                    "offline issuer trust snapshot must not contain evidence-specific or private fields"
                )
            _assert_no_private_keys(v)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _assert_no_private_keys(item)


@dataclass(frozen=True)
class CheckpointReference:
    """Compact public reference to a verified directory checkpoint."""

    checkpoint_hash: str
    tree_head_hash: str
    event_count: int
    manifest_hash: str
    timestamp: int
    signature_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "checkpointHash": self.checkpoint_hash,
            "eventCount": self.event_count,
            "manifestHash": self.manifest_hash,
            "timestamp": self.timestamp,
            "treeHeadHash": self.tree_head_hash,
        }
        if self.signature_hash is not None:
            d["signatureHash"] = self.signature_hash
        return d

    @staticmethod
    def from_checkpoint(checkpoint: DirectoryCheckpoint) -> CheckpointReference:
        return CheckpointReference(
            checkpoint_hash=checkpoint_hash(checkpoint),
            tree_head_hash=_require_hex("treeHeadHash", checkpoint.tree_head_hash),
            event_count=int(checkpoint.event_count),
            manifest_hash=_require_hex("manifestHash", checkpoint.manifest_hash),
            timestamp=int(checkpoint.timestamp),
            signature_hash=(
                _require_hex("signatureHash", checkpoint.signature_hash)
                if checkpoint.signature_hash
                else None
            ),
        )

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> CheckpointReference:
        allowed = {
            "checkpointHash",
            "eventCount",
            "manifestHash",
            "signatureHash",
            "timestamp",
            "treeHeadHash",
        }
        if set(obj.keys()) - allowed:
            raise TransparencyError("unexpected field in checkpointReference")
        ev_count = obj.get("eventCount")
        ts = obj.get("timestamp")
        if isinstance(ev_count, bool) or not isinstance(ev_count, int) or ev_count < 0:
            raise TransparencyError("checkpointReference.eventCount must be a non-negative integer")
        if isinstance(ts, bool) or not isinstance(ts, int):
            raise TransparencyError("checkpointReference.timestamp must be an integer")
        return CheckpointReference(
            checkpoint_hash=_require_hex("checkpointHash", str(obj["checkpointHash"])),
            tree_head_hash=_require_hex("treeHeadHash", str(obj["treeHeadHash"])),
            event_count=ev_count,
            manifest_hash=_require_hex("manifestHash", str(obj["manifestHash"])),
            timestamp=ts,
            signature_hash=(
                _require_hex("signatureHash", str(obj["signatureHash"]))
                if obj.get("signatureHash")
                else None
            ),
        )


@dataclass(frozen=True)
class PolicyVersionPin:
    """Public trust-policy version metadata bundled into an offline snapshot."""

    policy_version: str
    policy_hash: str
    default_freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS
    high_assurance_freshness_seconds: int = HIGH_ASSURANCE_FRESHNESS_SECONDS

    def __post_init__(self) -> None:
        if not isinstance(self.policy_version, str) or not (
            1 <= len(self.policy_version.strip()) <= 64
        ):
            raise TransparencyError("policy_version must be a non-empty string up to 64 chars")
        _require_hex("policyHash", self.policy_hash)
        for name, val in (
            ("default_freshness_seconds", self.default_freshness_seconds),
            ("high_assurance_freshness_seconds", self.high_assurance_freshness_seconds),
        ):
            if isinstance(val, bool) or not isinstance(val, int) or val <= 0:
                raise TransparencyError(f"{name} must be a positive integer")

    def to_dict(self) -> dict[str, Any]:
        return {
            "defaultFreshnessSeconds": self.default_freshness_seconds,
            "highAssuranceFreshnessSeconds": self.high_assurance_freshness_seconds,
            "policyHash": self.policy_hash.lower(),
            "policyVersion": self.policy_version.strip(),
        }

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> PolicyVersionPin:
        allowed = {
            "defaultFreshnessSeconds",
            "highAssuranceFreshnessSeconds",
            "policyHash",
            "policyVersion",
        }
        if set(obj.keys()) - allowed:
            raise TransparencyError("unexpected field in policy pin")
        return PolicyVersionPin(
            policy_version=str(obj["policyVersion"]),
            policy_hash=_require_hex("policyHash", str(obj["policyHash"])),
            default_freshness_seconds=int(obj.get("defaultFreshnessSeconds", DEFAULT_FRESHNESS_SECONDS)),
            high_assurance_freshness_seconds=int(
                obj.get("highAssuranceFreshnessSeconds", HIGH_ASSURANCE_FRESHNESS_SECONDS)
            ),
        )


@dataclass(frozen=True)
class OfflineIssuerSnapshotEntry:
    """Single-issuer public entry in an offline trust snapshot."""

    organization_identity_hash: str
    manifests: tuple[IssuerManifest, ...]
    checkpoint_ref: CheckpointReference
    policy: PolicyVersionPin

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpointReference": self.checkpoint_ref.to_dict(),
            "manifests": [m.to_dict() for m in self.manifests],
            "organizationIdentityHash": self.organization_identity_hash,
            "policy": self.policy.to_dict(),
        }

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> OfflineIssuerSnapshotEntry:
        allowed = {"checkpointReference", "manifests", "organizationIdentityHash", "policy"}
        if set(obj.keys()) - allowed:
            raise TransparencyError("unexpected field in snapshot issuer entry")
        org = _require_hex("organizationIdentityHash", str(obj["organizationIdentityHash"]))
        raw_manifests = obj.get("manifests")
        if not isinstance(raw_manifests, list) or len(raw_manifests) == 0:
            raise TransparencyError("snapshot entry must include at least one public manifest")
        manifests = tuple(IssuerManifest.from_dict(m) for m in raw_manifests)
        for m in manifests:
            canonicalize_manifest(m)
            if m.organization_identity_hash != org:
                raise TransparencyError("snapshot manifest organizationIdentityHash mismatch")
        cp_ref = CheckpointReference.from_dict(obj["checkpointReference"])
        manifest_hashes = {manifest_hash(m) for m in manifests}
        if cp_ref.manifest_hash not in manifest_hashes:
            raise TransparencyError(
                "checkpointReference.manifestHash is not present in snapshot manifests"
            )
        policy = PolicyVersionPin.from_dict(obj["policy"])
        return OfflineIssuerSnapshotEntry(
            organization_identity_hash=org,
            manifests=manifests,
            checkpoint_ref=cp_ref,
            policy=policy,
        )


@dataclass(frozen=True)
class IssuerSnapshotSource:
    """Input source for exporting an offline issuer trust snapshot.

    Optional ``private_context`` is accepted solely so callers passing mixed
    verification bundles have all evidence-specific fields stripped deterministically.
    """

    directory: IssuerDirectory
    checkpoint: DirectoryCheckpoint
    policy_version: str
    private_context: dict[str, Any] | None = None


@dataclass(frozen=True)
class OfflineIssuerTrustSnapshot:
    """Portable, evidence-agnostic offline issuer trust snapshot."""

    exported_at: int
    entries: tuple[OfflineIssuerSnapshotEntry, ...]

    def _unsigned_dict(self) -> dict[str, Any]:
        ordered = sorted(self.entries, key=lambda e: e.organization_identity_hash)
        return {
            "exportedAt": self.exported_at,
            "issuers": [entry.to_dict() for entry in ordered],
            "schema": OFFLINE_TRUST_SNAPSHOT_SCHEMA,
            "version": OFFLINE_TRUST_SNAPSHOT_VERSION,
        }

    def snapshot_hash(self) -> str:
        return _sha256_hex(_canonical_json(self._unsigned_dict()))

    def to_dict(self) -> dict[str, Any]:
        payload = self._unsigned_dict()
        _assert_no_private_keys(payload)
        payload["snapshotHash"] = self.snapshot_hash()
        return payload

    def to_canonical_json(self) -> str:
        return _canonical_json(self.to_dict()).decode("utf-8")

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> OfflineIssuerTrustSnapshot:
        if not isinstance(obj, dict):
            raise TransparencyError("snapshot payload must be a JSON object")
        _assert_no_private_keys(obj)
        allowed = {"exportedAt", "issuers", "schema", "snapshotHash", "version"}
        if set(obj.keys()) - allowed:
            raise TransparencyError("unexpected top-level field in offline trust snapshot")
        if obj.get("schema") != OFFLINE_TRUST_SNAPSHOT_SCHEMA:
            raise TransparencyError("unsupported offline trust snapshot schema")
        ver = obj.get("version")
        if isinstance(ver, bool) or ver != OFFLINE_TRUST_SNAPSHOT_VERSION:
            raise TransparencyError("unsupported offline trust snapshot version")
        exp = obj.get("exportedAt")
        if isinstance(exp, bool) or not isinstance(exp, int) or exp < 0:
            raise TransparencyError("exportedAt must be a non-negative integer")
        raw_issuers = obj.get("issuers")
        if (
            not isinstance(raw_issuers, list)
            or len(raw_issuers) == 0
            or len(raw_issuers) > MAX_SNAPSHOT_ISSUERS
        ):
            raise TransparencyError("issuers must be a non-empty bounded list")
        entries = tuple(OfflineIssuerSnapshotEntry.from_dict(item) for item in raw_issuers)
        seen_orgs: set[str] = set()
        for entry in entries:
            if entry.organization_identity_hash in seen_orgs:
                raise TransparencyError("duplicate organizationIdentityHash in snapshot")
            seen_orgs.add(entry.organization_identity_hash)
        snap = OfflineIssuerTrustSnapshot(exported_at=exp, entries=entries)
        expected_hash = _require_hex("snapshotHash", str(obj.get("snapshotHash", "")))
        if snap.snapshot_hash() != expected_hash:
            raise TransparencyError("snapshotHash integrity mismatch")
        return snap


def export_offline_issuer_trust_snapshot(
    sources: list[IssuerSnapshotSource] | tuple[IssuerSnapshotSource, ...],
    *,
    exported_at: int | None = None,
) -> OfflineIssuerTrustSnapshot:
    """Export public manifests, checkpoint references, and policy versions only.

    Verifies checkpoint consistency before export and strips any evidence-specific
    private identifiers that may exist in surrounding caller state.
    """
    if len(sources) == 0 or len(sources) > MAX_SNAPSHOT_ISSUERS:
        raise TransparencyError(f"sources must contain 1..{MAX_SNAPSHOT_ISSUERS} issuers")
    ts = int(time.time()) if exported_at is None else exported_at
    if isinstance(ts, bool) or not isinstance(ts, int) or ts < 0:
        raise TransparencyError("exported_at must be a non-negative integer")

    entries: list[OfflineIssuerSnapshotEntry] = []
    seen_orgs: set[str] = set()

    for src in sources:
        if not isinstance(src, IssuerSnapshotSource):
            raise TransparencyError("each source must be an IssuerSnapshotSource")
        directory = src.directory
        checkpoint = src.checkpoint
        if directory.current_manifest is None:
            raise TransparencyError("cannot export snapshot without a published manifest")
        if directory.organization_identity_hash in seen_orgs:
            raise TransparencyError("duplicate issuer organizationIdentityHash in export")
        seen_orgs.add(directory.organization_identity_hash)

        errors = verify_checkpoint_consistency(directory, checkpoint)
        if errors:
            raise TransparencyError(
                f"refusing to export inconsistent issuer checkpoint: {'; '.join(errors)}"
            )

        ordered_manifests = tuple(
            sorted(
                directory.manifests_by_hash.values(),
                key=lambda m: (m.valid_from, manifest_hash(m)),
            )
        )
        for mf in ordered_manifests:
            canonicalize_manifest(mf)

        cp_ref = CheckpointReference.from_checkpoint(checkpoint)
        policy_pin = PolicyVersionPin(
            policy_version=src.policy_version,
            policy_hash=directory.current_manifest.policy_hash,
        )
        entries.append(
            OfflineIssuerSnapshotEntry(
                organization_identity_hash=directory.organization_identity_hash,
                manifests=ordered_manifests,
                checkpoint_ref=cp_ref,
                policy=policy_pin,
            )
        )

    ordered_entries = tuple(sorted(entries, key=lambda e: e.organization_identity_hash))
    snapshot = OfflineIssuerTrustSnapshot(exported_at=ts, entries=ordered_entries)
    _assert_no_private_keys(snapshot.to_dict())
    return snapshot
