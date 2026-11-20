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
SNAPSHOT_PROTOCOL = "harpocrates-issuer-trust-snapshot"
VERSION = 1
SUPPORTED_VERSIONS = {1}

MAX_ACTIVE_KEYS = 8
MAX_EVENTS = 10_000
MAX_MANIFEST_BYTES = 8_192
MAX_CHECKPOINT_BYTES = 16_384
MAX_SNAPSHOT_BYTES = 131_072
MAX_SNAPSHOT_MANIFESTS = 256
MAX_SNAPSHOT_CHECKPOINTS = 256
MAX_SNAPSHOT_POLICY_VERSIONS = 64
DEFAULT_FRESHNESS_SECONDS = 86_400  # 24h
HIGH_ASSURANCE_FRESHNESS_SECONDS = 3_600  # 1h fail-closed window

# Evidence-specific private identifiers and private org fields that must never
# appear in offline issuer trust snapshots.
FORBIDDEN_SNAPSHOT_FIELDS: frozenset[str] = frozenset(
    {
        "evidencedigestbinding",
        "capturenonce",
        "devicecommitment",
        "evidenceid",
        "evidencehash",
        "mediahash",
        "sealid",
        "proofid",
        "submissionid",
        "witnessid",
        "nullifier",
        "persessiondevicekey",
        "privatekey",
        "secret",
        "email",
        "legalname",
        "phone",
        "street",
        "employee",
    }
)


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


@dataclass(frozen=True)
class KeyLifecycleChange:
    """Proposed key lifecycle transition reported by a directory import preview."""

    key_id: str
    public_key_hash: str
    previous_status: KeyStatus | None
    proposed_status: KeyStatus
    event_types: tuple[EventType, ...]
    valid_from: int
    valid_until: int | None = None
    related_key_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "eventTypes": [et.value for et in self.event_types],
            "keyId": self.key_id,
            "previousStatus": self.previous_status.value if self.previous_status else None,
            "proposedStatus": self.proposed_status.value,
            "publicKeyHash": self.public_key_hash,
            "validFrom": self.valid_from,
        }
        if self.valid_until is not None:
            d["validUntil"] = self.valid_until
        if self.related_key_id is not None:
            d["relatedKeyId"] = self.related_key_id
        return d


@dataclass(frozen=True)
class CheckpointLineage:
    """Before/after checkpoint and manifest lineage for a directory import preview."""

    organization_identity_hash: str
    current_event_count: int
    proposed_event_count: int
    added_event_count: int
    current_tree_head_hash: str
    proposed_tree_head_hash: str
    current_manifest_hash: str | None
    proposed_manifest_hash: str | None
    manifest_chain_hashes: tuple[str, ...]
    previously_seen_checkpoint_hash: str | None = None
    incoming_checkpoint_hash: str | None = None
    incoming_checkpoint_event_count: int | None = None
    incoming_checkpoint_tree_head_hash: str | None = None
    extends_current_head: bool = True

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "addedEventCount": self.added_event_count,
            "currentEventCount": self.current_event_count,
            "currentManifestHash": self.current_manifest_hash,
            "currentTreeHeadHash": self.current_tree_head_hash,
            "extendsCurrentHead": self.extends_current_head,
            "manifestChainHashes": list(self.manifest_chain_hashes),
            "organizationIdentityHash": self.organization_identity_hash,
            "proposedEventCount": self.proposed_event_count,
            "proposedManifestHash": self.proposed_manifest_hash,
            "proposedTreeHeadHash": self.proposed_tree_head_hash,
        }
        if self.previously_seen_checkpoint_hash is not None:
            d["previouslySeenCheckpointHash"] = self.previously_seen_checkpoint_hash
        if self.incoming_checkpoint_hash is not None:
            d["incomingCheckpointHash"] = self.incoming_checkpoint_hash
        if self.incoming_checkpoint_event_count is not None:
            d["incomingCheckpointEventCount"] = self.incoming_checkpoint_event_count
        if self.incoming_checkpoint_tree_head_hash is not None:
            d["incomingCheckpointTreeHeadHash"] = self.incoming_checkpoint_tree_head_hash
        return d


@dataclass(frozen=True)
class DirectoryImportPreview:
    """Non-mutating preview of a proposed issuer directory import."""

    organization_identity_hash: str
    acceptable: bool
    errors: tuple[str, ...]
    key_changes: tuple[KeyLifecycleChange, ...]
    checkpoint_lineage: CheckpointLineage
    proposed_events: tuple[DirectoryEvent, ...]
    proposed_manifests: tuple[IssuerManifest, ...]
    incoming_checkpoint: DirectoryCheckpoint | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "acceptable": self.acceptable,
            "checkpointLineage": self.checkpoint_lineage.to_dict(),
            "errors": list(self.errors),
            "keyChanges": [c.to_dict() for c in self.key_changes],
            "organizationIdentityHash": self.organization_identity_hash,
        }


def _clone_directory(directory: IssuerDirectory) -> IssuerDirectory:
    clone = IssuerDirectory(
        organization_identity_hash=directory.organization_identity_hash,
        events=list(directory.events),
        keys=dict(directory.keys),
        current_manifest=directory.current_manifest,
        manifests_by_hash=dict(directory.manifests_by_hash),
    )
    return clone


def preview_directory_import(
    current_directory: IssuerDirectory,
    incoming_events: list[DirectoryEvent],
    *,
    incoming_manifests: list[IssuerManifest] | None = None,
    incoming_checkpoint: DirectoryCheckpoint | None = None,
    previously_seen_checkpoint: DirectoryCheckpoint | None = None,
) -> DirectoryImportPreview:
    """Preview proposed key lifecycle changes and checkpoint lineage without mutating trust state.

    Accepts either a full event log starting at sequence 0 (whose prefix must match
    `current_directory.events`) or delta events starting at `len(current_directory.events)`.
    No mutation is performed on `current_directory`; call `apply_directory_import` only
    after reviewing and accepting a valid preview.
    """
    errors: list[str] = []
    extends_current_head = True
    current_count = len(current_directory.events)
    current_head = current_directory.tree_head()
    current_mh = (
        manifest_hash(current_directory.current_manifest)
        if current_directory.current_manifest is not None
        else None
    )

    # Determine delta events while checking prefix consistency / rollback.
    delta_events: list[DirectoryEvent] = []
    if incoming_events:
        first_seq = incoming_events[0].sequence
        if current_count > 0 and first_seq == 0:
            if len(incoming_events) < current_count:
                errors.append("incoming event log shorter than current directory (rollback)")
                extends_current_head = False
            else:
                for idx in range(current_count):
                    if event_hash(incoming_events[idx]) != event_hash(current_directory.events[idx]):
                        errors.append(
                            f"incoming event log diverges from current directory at sequence {idx} (split view)"
                        )
                        extends_current_head = False
                        break
                if extends_current_head:
                    delta_events = list(incoming_events[current_count:])
        else:
            delta_events = list(incoming_events)

    # Filter out already-published manifests if a full manifest history was supplied.
    delta_manifests: list[IssuerManifest] = []
    for manifest in incoming_manifests or []:
        try:
            mh = manifest_hash(manifest)
        except TransparencyError as exc:
            errors.append(str(exc))
            continue
        if mh not in current_directory.manifests_by_hash:
            delta_manifests.append(manifest)

    candidate = _clone_directory(current_directory)
    applied_events: list[DirectoryEvent] = []
    applied_manifests: list[IssuerManifest] = []
    manifest_chain_hashes: list[str] = []

    if extends_current_head:
        for ev in delta_events:
            try:
                candidate.append_event(ev)
                applied_events.append(ev)
            except TransparencyError as exc:
                errors.append(str(exc))
                extends_current_head = False
                break

        for manifest in delta_manifests:
            try:
                mh = candidate.publish_manifest(manifest)
                applied_manifests.append(manifest)
                manifest_chain_hashes.append(mh)
            except TransparencyError as exc:
                errors.append(str(exc))
                break

    # Checkpoint lineage and rollback/equivocation checks.
    if incoming_checkpoint is not None:
        errors.extend(verify_checkpoint_consistency(candidate, incoming_checkpoint))
        if previously_seen_checkpoint is not None:
            errors.extend(detect_rollback(previously_seen_checkpoint, incoming_checkpoint))
    elif previously_seen_checkpoint is not None:
        if len(candidate.events) < previously_seen_checkpoint.event_count:
            errors.append("candidate directory shorter than previously seen checkpoint (rollback)")
            extends_current_head = False
        else:
            prefix_head = compute_tree_head(
                candidate.events[: previously_seen_checkpoint.event_count]
            )
            if prefix_head != previously_seen_checkpoint.tree_head_hash:
                errors.append(
                    "candidate directory diverges from previously seen checkpoint (split view)"
                )
                extends_current_head = False

    # Compute proposed key lifecycle changes by comparing current vs candidate state.
    events_by_key: dict[str, list[EventType]] = {}
    related_by_key: dict[str, str] = {}
    for ev in applied_events:
        if ev.event_type == EventType.CHECKPOINT:
            continue
        events_by_key.setdefault(ev.key_id, []).append(ev.event_type)
        if ev.related_key_id:
            related_by_key[ev.key_id] = ev.related_key_id
            events_by_key.setdefault(ev.related_key_id, []).append(ev.event_type)

    key_changes: list[KeyLifecycleChange] = []
    for key_id in sorted(set(current_directory.keys) | set(candidate.keys)):
        before = current_directory.keys.get(key_id)
        after = candidate.keys.get(key_id)
        if after is None:
            continue
        if before != after:
            key_changes.append(
                KeyLifecycleChange(
                    key_id=key_id,
                    public_key_hash=after.public_key_hash,
                    previous_status=before.status if before is not None else None,
                    proposed_status=after.status,
                    event_types=tuple(events_by_key.get(key_id, ())),
                    valid_from=after.valid_from,
                    valid_until=after.valid_until,
                    related_key_id=related_by_key.get(key_id),
                )
            )

    proposed_mh = (
        manifest_hash(candidate.current_manifest)
        if candidate.current_manifest is not None
        else None
    )
    lineage = CheckpointLineage(
        organization_identity_hash=current_directory.organization_identity_hash,
        current_event_count=current_count,
        proposed_event_count=len(candidate.events),
        added_event_count=len(applied_events),
        current_tree_head_hash=current_head,
        proposed_tree_head_hash=candidate.tree_head(),
        current_manifest_hash=current_mh,
        proposed_manifest_hash=proposed_mh,
        manifest_chain_hashes=tuple(manifest_chain_hashes),
        previously_seen_checkpoint_hash=(
            checkpoint_hash(previously_seen_checkpoint)
            if previously_seen_checkpoint is not None
            else None
        ),
        incoming_checkpoint_hash=(
            checkpoint_hash(incoming_checkpoint) if incoming_checkpoint is not None else None
        ),
        incoming_checkpoint_event_count=(
            incoming_checkpoint.event_count if incoming_checkpoint is not None else None
        ),
        incoming_checkpoint_tree_head_hash=(
            incoming_checkpoint.tree_head_hash if incoming_checkpoint is not None else None
        ),
        extends_current_head=extends_current_head and not errors,
    )

    return DirectoryImportPreview(
        organization_identity_hash=current_directory.organization_identity_hash,
        acceptable=len(errors) == 0,
        errors=tuple(errors),
        key_changes=tuple(key_changes),
        checkpoint_lineage=lineage,
        proposed_events=tuple(applied_events),
        proposed_manifests=tuple(applied_manifests),
        incoming_checkpoint=incoming_checkpoint,
    )


def apply_directory_import(
    directory: IssuerDirectory,
    preview: DirectoryImportPreview,
) -> IssuerDirectory:
    """Apply an accepted directory import preview to `directory` (fail-closed)."""
    if not preview.acceptable:
        raise TransparencyError(
            "cannot apply rejected directory import preview: " + "; ".join(preview.errors)
        )
    lineage = preview.checkpoint_lineage
    if directory.organization_identity_hash != preview.organization_identity_hash:
        raise TransparencyError("directory organizationIdentityHash mismatch")
    if (
        len(directory.events) != lineage.current_event_count
        or directory.tree_head() != lineage.current_tree_head_hash
    ):
        raise TransparencyError("directory state changed since preview was generated")
    current_mh = (
        manifest_hash(directory.current_manifest)
        if directory.current_manifest is not None
        else None
    )
    if current_mh != lineage.current_manifest_hash:
        raise TransparencyError("directory manifest changed since preview was generated")

    for ev in preview.proposed_events:
        directory.append_event(ev)
    for manifest in preview.proposed_manifests:
        directory.publish_manifest(manifest)
    return directory


# ── Offline issuer trust snapshot exports ──────────────────────────────────

_SNAPSHOT_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "protocol",
        "version",
        "exportedAt",
        "manifests",
        "checkpointReferences",
        "policyVersions",
    }
)
_MANIFEST_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "protocol",
        "version",
        "organizationIdentityHash",
        "issuerAddress",
        "activeKeys",
        "policyHash",
        "validFrom",
        "validUntil",
        "predecessorManifestHash",
        "successorManifestHash",
        "signatureHash",
    }
)
_KEY_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "keyId",
        "publicKeyHash",
        "algorithm",
        "validFrom",
        "validUntil",
        "status",
    }
)
_CHECKPOINT_REF_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "checkpointHash",
        "treeHeadHash",
        "eventCount",
        "timestamp",
        "organizationIdentityHash",
        "manifestHash",
        "signatureHash",
    }
)
_POLICY_VERSION_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "policyVersion",
        "policyHash",
        "effectiveFrom",
    }
)


def _reject_forbidden_and_unknown_keys(
    obj: Any,
    allowed: frozenset[str],
    context: str,
) -> None:
    if not isinstance(obj, dict):
        raise TransparencyError(f"{context} must be a JSON object")
    for key in obj:
        normalized = str(key).lower().replace("_", "")
        if normalized in FORBIDDEN_SNAPSHOT_FIELDS:
            raise TransparencyError(f"{context} contains forbidden private field: {key}")
        if key not in allowed:
            raise TransparencyError(f"{context} contains unsupported field: {key}")


@dataclass(frozen=True)
class PolicyVersion:
    """Public policy version identifier and canonical policy digest."""

    policy_version: str
    policy_hash: str
    effective_from: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.policy_version, str) or not self.policy_version.strip():
            raise TransparencyError("policyVersion must be a non-empty string")
        _require_hex("policyHash", self.policy_hash)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "policyHash": self.policy_hash.lower(),
            "policyVersion": self.policy_version,
        }
        if self.effective_from is not None:
            d["effectiveFrom"] = self.effective_from
        return d

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> "PolicyVersion":
        _reject_forbidden_and_unknown_keys(obj, _POLICY_VERSION_ALLOWED_KEYS, "policyVersion")
        if "policyVersion" not in obj or "policyHash" not in obj:
            raise TransparencyError("policyVersion and policyHash are required")
        return PolicyVersion(
            policy_version=str(obj["policyVersion"]),
            policy_hash=_require_hex("policyHash", str(obj["policyHash"])),
            effective_from=(
                int(obj["effectiveFrom"]) if obj.get("effectiveFrom") is not None else None
            ),
        )


@dataclass(frozen=True)
class CheckpointReference:
    """Public reference to a signed directory checkpoint for offline verification."""

    checkpoint_hash: str
    tree_head_hash: str
    event_count: int
    timestamp: int
    organization_identity_hash: str
    manifest_hash: str
    signature_hash: str | None = None

    def __post_init__(self) -> None:
        _require_hex("checkpointHash", self.checkpoint_hash)
        _require_hex("treeHeadHash", self.tree_head_hash)
        _require_hex("organizationIdentityHash", self.organization_identity_hash)
        _require_hex("manifestHash", self.manifest_hash)
        if self.signature_hash is not None:
            _require_hex("signatureHash", self.signature_hash)
        if self.event_count < 0:
            raise TransparencyError("checkpointReference eventCount must be non-negative")

    @staticmethod
    def from_checkpoint(checkpoint: DirectoryCheckpoint) -> "CheckpointReference":
        return CheckpointReference(
            checkpoint_hash=checkpoint_hash(checkpoint),
            tree_head_hash=checkpoint.tree_head_hash,
            event_count=checkpoint.event_count,
            timestamp=checkpoint.timestamp,
            organization_identity_hash=checkpoint.organization_identity_hash,
            manifest_hash=checkpoint.manifest_hash,
            signature_hash=checkpoint.signature_hash,
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "checkpointHash": self.checkpoint_hash.lower(),
            "eventCount": self.event_count,
            "manifestHash": self.manifest_hash.lower(),
            "organizationIdentityHash": self.organization_identity_hash.lower(),
            "timestamp": self.timestamp,
            "treeHeadHash": self.tree_head_hash.lower(),
        }
        if self.signature_hash:
            d["signatureHash"] = self.signature_hash.lower()
        return d

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> "CheckpointReference":
        _reject_forbidden_and_unknown_keys(
            obj, _CHECKPOINT_REF_ALLOWED_KEYS, "checkpointReference"
        )
        required = (
            "checkpointHash",
            "treeHeadHash",
            "eventCount",
            "timestamp",
            "organizationIdentityHash",
            "manifestHash",
        )
        for req in required:
            if req not in obj:
                raise TransparencyError(f"checkpointReference missing required field: {req}")
        return CheckpointReference(
            checkpoint_hash=_require_hex("checkpointHash", str(obj["checkpointHash"])),
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
        )


@dataclass
class IssuerTrustSnapshot:
    """Offline-exportable public issuer trust snapshot.

    Contains only public manifests, checkpoint references, and policy versions.
    Evidence-specific private identifiers are never included.
    """

    exported_at: int
    manifests: list[IssuerManifest]
    checkpoint_references: list[CheckpointReference]
    policy_versions: list[PolicyVersion]
    version: int = VERSION
    protocol: str = SNAPSHOT_PROTOCOL

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpointReferences": [c.to_dict() for c in self.checkpoint_references],
            "exportedAt": self.exported_at,
            "manifests": [m.to_dict() for m in self.manifests],
            "policyVersions": [p.to_dict() for p in self.policy_versions],
            "protocol": self.protocol,
            "version": self.version,
        }

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> "IssuerTrustSnapshot":
        _reject_forbidden_and_unknown_keys(obj, _SNAPSHOT_ALLOWED_KEYS, "trust snapshot")
        if obj.get("protocol") != SNAPSHOT_PROTOCOL:
            raise TransparencyError("unsupported issuer trust snapshot protocol")
        if int(obj.get("version", 0)) not in SUPPORTED_VERSIONS:
            raise TransparencyError("unsupported issuer trust snapshot version")
        if "exportedAt" not in obj:
            raise TransparencyError("trust snapshot missing required field: exportedAt")

        raw_manifests = obj.get("manifests")
        raw_checkpoints = obj.get("checkpointReferences")
        raw_policies = obj.get("policyVersions")
        if not isinstance(raw_manifests, list):
            raise TransparencyError("trust snapshot manifests must be a list")
        if not isinstance(raw_checkpoints, list):
            raise TransparencyError("trust snapshot checkpointReferences must be a list")
        if not isinstance(raw_policies, list):
            raise TransparencyError("trust snapshot policyVersions must be a list")

        manifests: list[IssuerManifest] = []
        for m_obj in raw_manifests:
            _reject_forbidden_and_unknown_keys(m_obj, _MANIFEST_ALLOWED_KEYS, "manifest")
            for k_obj in m_obj.get("activeKeys", []):
                _reject_forbidden_and_unknown_keys(k_obj, _KEY_ALLOWED_KEYS, "activeKey")
            manifests.append(IssuerManifest.from_dict(m_obj))

        checkpoints = [CheckpointReference.from_dict(c) for c in raw_checkpoints]
        policies = [PolicyVersion.from_dict(p) for p in raw_policies]

        return IssuerTrustSnapshot(
            exported_at=int(obj["exportedAt"]),
            manifests=manifests,
            checkpoint_references=checkpoints,
            policy_versions=policies,
            version=int(obj["version"]),
            protocol=str(obj["protocol"]),
        )


def canonicalize_trust_snapshot(snapshot: IssuerTrustSnapshot) -> str:
    """Deterministic JSON encoding for an offline issuer trust snapshot."""
    if snapshot.protocol != SNAPSHOT_PROTOCOL:
        raise TransparencyError("unsupported issuer trust snapshot protocol")
    if snapshot.version not in SUPPORTED_VERSIONS:
        raise TransparencyError("unsupported issuer trust snapshot version")
    if len(snapshot.manifests) > MAX_SNAPSHOT_MANIFESTS:
        raise TransparencyError("trust snapshot manifest count exceeds bound")
    if len(snapshot.checkpoint_references) > MAX_SNAPSHOT_CHECKPOINTS:
        raise TransparencyError("trust snapshot checkpoint count exceeds bound")
    if len(snapshot.policy_versions) > MAX_SNAPSHOT_POLICY_VERSIONS:
        raise TransparencyError("trust snapshot policy version count exceeds bound")
    for manifest in snapshot.manifests:
        canonicalize_manifest(manifest)
    encoded = _canonical_json(snapshot.to_dict())
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise TransparencyError("trust snapshot exceeds size bound")
    return encoded.decode("utf-8")


def trust_snapshot_hash(snapshot: IssuerTrustSnapshot) -> str:
    """Compute the canonical SHA-256 digest of an offline issuer trust snapshot."""
    return _sha256_hex(canonicalize_trust_snapshot(snapshot).encode("utf-8"))


def export_offline_trust_snapshot(
    directories: Iterable[IssuerDirectory],
    checkpoints: Iterable[DirectoryCheckpoint],
    policy_versions: Iterable[PolicyVersion],
    *,
    exported_at: int | None = None,
    include_historical_manifests: bool = True,
) -> IssuerTrustSnapshot:
    """Export a canonical offline issuer trust snapshot.

    Includes only public manifests, checkpoint references, and policy versions.
    Fails closed if any checkpoint is inconsistent with its directory or if
    conflicting policy versions are supplied.
    """
    dirs_by_org: dict[str, IssuerDirectory] = {}
    manifests_by_digest: dict[str, IssuerManifest] = {}

    for directory in directories:
        if directory.organization_identity_hash in dirs_by_org:
            raise TransparencyError("duplicate directory for organizationIdentityHash")
        if directory.current_manifest is None:
            raise TransparencyError(
                "cannot export trust snapshot for directory without a published manifest"
            )
        dirs_by_org[directory.organization_identity_hash] = directory
        if include_historical_manifests and directory.manifests_by_hash:
            for mh, manifest in directory.manifests_by_hash.items():
                manifests_by_digest[mh] = manifest
        else:
            mh = manifest_hash(directory.current_manifest)
            manifests_by_digest[mh] = directory.current_manifest

    checkpoint_refs_by_hash: dict[str, CheckpointReference] = {}
    for cp in checkpoints:
        directory = dirs_by_org.get(cp.organization_identity_hash)
        if directory is None:
            raise TransparencyError(
                "checkpoint references unknown organizationIdentityHash not in export"
            )
        consistency_errors = verify_checkpoint_consistency(directory, cp)
        if consistency_errors:
            raise TransparencyError(
                "inconsistent checkpoint in trust snapshot export: "
                + "; ".join(consistency_errors)
            )
        if cp.manifest_hash not in manifests_by_digest:
            raise TransparencyError(
                "checkpoint manifestHash is not present in exported manifests"
            )
        ref = CheckpointReference.from_checkpoint(cp)
        checkpoint_refs_by_hash[ref.checkpoint_hash] = ref

    policies_by_version: dict[str, PolicyVersion] = {}
    for pv in policy_versions:
        existing = policies_by_version.get(pv.policy_version)
        if existing is not None and existing.policy_hash.lower() != pv.policy_hash.lower():
            raise TransparencyError(
                f"conflicting policyHash for policyVersion {pv.policy_version}"
            )
        policies_by_version[pv.policy_version] = pv

    sorted_manifests = sorted(
        manifests_by_digest.values(),
        key=lambda m: (m.organization_identity_hash, m.valid_from, manifest_hash(m)),
    )
    sorted_checkpoints = sorted(
        checkpoint_refs_by_hash.values(),
        key=lambda c: (c.organization_identity_hash, c.event_count, c.checkpoint_hash),
    )
    sorted_policies = sorted(
        policies_by_version.values(),
        key=lambda p: (p.policy_version, p.policy_hash.lower()),
    )

    ts = int(time.time()) if exported_at is None else exported_at
    snapshot = IssuerTrustSnapshot(
        exported_at=ts,
        manifests=sorted_manifests,
        checkpoint_references=sorted_checkpoints,
        policy_versions=sorted_policies,
    )
    canonicalize_trust_snapshot(snapshot)
    return snapshot


def import_offline_trust_snapshot(
    raw: str | bytes | dict[str, Any],
) -> IssuerTrustSnapshot:
    """Decode and validate an offline issuer trust snapshot (fail-closed)."""
    if isinstance(raw, (str, bytes)):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise TransparencyError(f"invalid trust snapshot JSON: {exc}") from exc
    elif isinstance(raw, dict):
        obj = raw
    else:
        raise TransparencyError("trust snapshot input must be JSON string, bytes, or dict")

    snapshot = IssuerTrustSnapshot.from_dict(obj)
    canonicalize_trust_snapshot(snapshot)
    return snapshot


def verify_offline_trust_snapshot(snapshot: IssuerTrustSnapshot) -> list[str]:
    """Return consistency errors for an offline trust snapshot (empty = valid)."""
    errors: list[str] = []
    try:
        canonicalize_trust_snapshot(snapshot)
    except TransparencyError as exc:
        errors.append(str(exc))

    manifests_by_digest: dict[str, IssuerManifest] = {}
    for manifest in snapshot.manifests:
        try:
            mh = manifest_hash(manifest)
            manifests_by_digest[mh] = manifest
            if manifest.successor_manifest_hash is not None:
                unlinked = IssuerManifest(
                    organization_identity_hash=manifest.organization_identity_hash,
                    issuer_address=manifest.issuer_address,
                    active_keys=list(manifest.active_keys),
                    policy_hash=manifest.policy_hash,
                    valid_from=manifest.valid_from,
                    valid_until=manifest.valid_until,
                    predecessor_manifest_hash=manifest.predecessor_manifest_hash,
                    successor_manifest_hash=None,
                    signature_hash=manifest.signature_hash,
                    version=manifest.version,
                    protocol=manifest.protocol,
                )
                manifests_by_digest[manifest_hash(unlinked)] = manifest
        except TransparencyError as exc:
            errors.append(f"invalid manifest: {exc}")

    for ref in snapshot.checkpoint_references:
        manifest = manifests_by_digest.get(ref.manifest_hash)
        if manifest is None:
            errors.append(
                f"checkpoint {ref.checkpoint_hash} references missing manifest {ref.manifest_hash}"
            )
        elif manifest.organization_identity_hash != ref.organization_identity_hash:
            errors.append(
                f"checkpoint {ref.checkpoint_hash} organizationIdentityHash mismatch with manifest"
            )

    seen_policy_versions: dict[str, str] = {}
    for pv in snapshot.policy_versions:
        prev_hash = seen_policy_versions.get(pv.policy_version)
        if prev_hash is not None and prev_hash != pv.policy_hash.lower():
            errors.append(f"conflicting policyHash for policyVersion {pv.policy_version}")
        seen_policy_versions[pv.policy_version] = pv.policy_hash.lower()

    return errors
