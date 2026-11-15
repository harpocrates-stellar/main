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


# ── Portable issuer transparency consistency proof bundle ──────────────────

CONSISTENCY_PROOF_BUNDLE_SCHEMA = "harpocrates-issuer-consistency-proof-bundle/v1"
CONSISTENCY_PROOF_BUNDLE_VERSION = 1
MAX_BUNDLE_BYTES = 524_288  # 512 KiB bound for offline portable bundles


@dataclass(frozen=True)
class ConsistencyProofBundle:
    """Portable offline proof binding an earlier and later checkpoint via intervening events."""

    organization_identity_hash: str
    earlier_checkpoint: DirectoryCheckpoint
    later_checkpoint: DirectoryCheckpoint
    intervening_events: tuple[DirectoryEvent, ...]
    anchor_event_hash: str | None = None
    intervening_manifests: tuple[IssuerManifest, ...] = ()

    def _unsigned_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "anchorEventHash": self.anchor_event_hash,
            "earlierCheckpoint": self.earlier_checkpoint.to_dict(),
            "interveningEvents": [ev.to_dict() for ev in self.intervening_events],
            "interveningManifests": [mf.to_dict() for mf in self.intervening_manifests],
            "laterCheckpoint": self.later_checkpoint.to_dict(),
            "organizationIdentityHash": self.organization_identity_hash,
            "schema": CONSISTENCY_PROOF_BUNDLE_SCHEMA,
            "version": CONSISTENCY_PROOF_BUNDLE_VERSION,
        }
        return payload

    def bundle_hash(self) -> str:
        encoded = _canonical_json(self._unsigned_dict())
        if len(encoded) > MAX_BUNDLE_BYTES:
            raise TransparencyError("consistency proof bundle exceeds size bound")
        return _sha256_hex(encoded)

    def to_dict(self) -> dict[str, Any]:
        payload = self._unsigned_dict()
        payload["bundleHash"] = self.bundle_hash()
        return payload

    def to_canonical_json(self) -> str:
        encoded = _canonical_json(self.to_dict())
        if len(encoded) > MAX_BUNDLE_BYTES:
            raise TransparencyError("consistency proof bundle exceeds size bound")
        return encoded.decode("utf-8")

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> ConsistencyProofBundle:
        if not isinstance(obj, dict):
            raise TransparencyError("consistency proof bundle must be a JSON object")
        allowed = {
            "anchorEventHash",
            "bundleHash",
            "earlierCheckpoint",
            "interveningEvents",
            "interveningManifests",
            "laterCheckpoint",
            "organizationIdentityHash",
            "schema",
            "version",
        }
        if set(obj.keys()) - allowed:
            raise TransparencyError("unexpected field in consistency proof bundle")
        if obj.get("schema") != CONSISTENCY_PROOF_BUNDLE_SCHEMA:
            raise TransparencyError("unsupported consistency proof bundle schema")
        ver = obj.get("version")
        if isinstance(ver, bool) or ver != CONSISTENCY_PROOF_BUNDLE_VERSION:
            raise TransparencyError("unsupported consistency proof bundle version")
        org = _require_hex("organizationIdentityHash", str(obj["organizationIdentityHash"]))
        earlier_cp = DirectoryCheckpoint.from_dict(obj["earlierCheckpoint"])
        later_cp = DirectoryCheckpoint.from_dict(obj["laterCheckpoint"])
        raw_events = obj.get("interveningEvents")
        if not isinstance(raw_events, list) or len(raw_events) > MAX_EVENTS:
            raise TransparencyError("interveningEvents must be a bounded list")
        raw_manifests = obj.get("interveningManifests", [])
        if not isinstance(raw_manifests, list) or len(raw_manifests) > MAX_EVENTS:
            raise TransparencyError("interveningManifests must be a bounded list")
        anchor_raw = obj.get("anchorEventHash")
        anchor = (
            _require_hex("anchorEventHash", str(anchor_raw))
            if anchor_raw is not None
            else None
        )
        bundle = ConsistencyProofBundle(
            organization_identity_hash=org,
            earlier_checkpoint=earlier_cp,
            later_checkpoint=later_cp,
            intervening_events=tuple(DirectoryEvent.from_dict(e) for e in raw_events),
            anchor_event_hash=anchor,
            intervening_manifests=tuple(IssuerManifest.from_dict(m) for m in raw_manifests),
        )
        expected_hash = _require_hex("bundleHash", str(obj.get("bundleHash", "")))
        if bundle.bundle_hash() != expected_hash:
            raise TransparencyError("bundleHash integrity mismatch")
        return bundle

    @staticmethod
    def from_canonical_json(raw: str | bytes) -> ConsistencyProofBundle:
        raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
        if len(raw_bytes) > MAX_BUNDLE_BYTES:
            raise TransparencyError("consistency proof bundle exceeds size bound")
        try:
            parsed = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TransparencyError("malformed consistency proof bundle JSON") from exc
        return ConsistencyProofBundle.from_dict(parsed)


@dataclass(frozen=True)
class ConsistencyProofVerificationResult:
    """Offline verification verdict for a ``ConsistencyProofBundle``."""

    valid: bool
    errors: tuple[str, ...]
    organization_identity_hash: str
    earlier_checkpoint_hash: str
    later_checkpoint_hash: str
    verified_tree_head_hash: str
    intervening_event_count: int
    bundle_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundleHash": self.bundle_hash,
            "earlierCheckpointHash": self.earlier_checkpoint_hash,
            "errors": list(self.errors),
            "interveningEventCount": self.intervening_event_count,
            "laterCheckpointHash": self.later_checkpoint_hash,
            "organizationIdentityHash": self.organization_identity_hash,
            "valid": self.valid,
            "verifiedTreeHeadHash": self.verified_tree_head_hash,
        }


def _advance_tree_head(starting_head: str, events: Iterable[DirectoryEvent]) -> str:
    head = starting_head
    for ev in events:
        head = _sha256_hex((head + event_hash(ev)).encode("utf-8"))
    return head


def _without_successor_link(mf: IssuerManifest) -> IssuerManifest:
    if mf.successor_manifest_hash is None:
        return mf
    return IssuerManifest(
        organization_identity_hash=mf.organization_identity_hash,
        issuer_address=mf.issuer_address,
        active_keys=list(mf.active_keys),
        policy_hash=mf.policy_hash,
        valid_from=mf.valid_from,
        valid_until=mf.valid_until,
        predecessor_manifest_hash=mf.predecessor_manifest_hash,
        successor_manifest_hash=None,
        signature_hash=mf.signature_hash,
        version=mf.version,
        protocol=mf.protocol,
    )


def _publication_manifest_hash(mf: IssuerManifest) -> str:
    return manifest_hash(_without_successor_link(mf))


def build_consistency_proof_bundle(
    directory: IssuerDirectory,
    earlier_checkpoint: DirectoryCheckpoint,
    later_checkpoint: DirectoryCheckpoint,
    *,
    intervening_manifests: list[IssuerManifest] | None = None,
) -> ConsistencyProofBundle:
    """Build a portable consistency proof bundle from authoritative directory history."""
    org = _require_hex("organizationIdentityHash", directory.organization_identity_hash)
    rollback_errs = detect_rollback(earlier_checkpoint, later_checkpoint)
    if rollback_errs:
        raise TransparencyError("; ".join(rollback_errs))
    for label, cp in (("earlier", earlier_checkpoint), ("later", later_checkpoint)):
        cp_errs = verify_checkpoint_consistency(directory, cp)
        if cp_errs:
            raise TransparencyError(
                f"{label} checkpoint inconsistent with directory: {'; '.join(cp_errs)}"
            )

    start = earlier_checkpoint.event_count
    end = later_checkpoint.event_count
    slice_events = tuple(directory.events[start:end])
    anchor = event_hash(directory.events[start - 1]) if start > 0 else None

    manifests_tuple: tuple[IssuerManifest, ...] = ()
    if intervening_manifests is not None:
        manifests_tuple = tuple(intervening_manifests)
    elif earlier_checkpoint.manifest_hash != later_checkpoint.manifest_hash:
        # Walk backwards from later_checkpoint.manifest_hash to earlier_checkpoint.manifest_hash
        chain: list[IssuerManifest] = []
        cursor: str | None = later_checkpoint.manifest_hash
        visited: set[str] = set()
        while cursor is not None and cursor != earlier_checkpoint.manifest_hash:
            if cursor in visited:
                raise TransparencyError("cycle in manifest predecessor chain")
            visited.add(cursor)
            mf = directory.manifests_by_hash.get(cursor)
            if mf is None:
                raise TransparencyError(
                    "missing intervening manifest between checkpoints in directory"
                )
            unlinked = _without_successor_link(mf)
            chain.append(unlinked if manifest_hash(unlinked) == cursor else mf)
            cursor = mf.predecessor_manifest_hash
        if cursor != earlier_checkpoint.manifest_hash:
            raise TransparencyError(
                "later checkpoint manifest does not descend from earlier checkpoint manifest"
            )
        chain.reverse()
        manifests_tuple = tuple(chain)

    bundle = ConsistencyProofBundle(
        organization_identity_hash=org,
        earlier_checkpoint=earlier_checkpoint,
        later_checkpoint=later_checkpoint,
        intervening_events=slice_events,
        anchor_event_hash=anchor,
        intervening_manifests=manifests_tuple,
    )
    verdict = verify_consistency_proof_bundle(bundle)
    if not verdict.valid:
        raise TransparencyError("; ".join(verdict.errors))
    return bundle


def verify_consistency_proof_bundle(
    bundle: ConsistencyProofBundle | dict[str, Any],
    *,
    trusted_earlier_checkpoint: DirectoryCheckpoint | None = None,
    max_intervening_events: int = MAX_EVENTS,
) -> ConsistencyProofVerificationResult:
    """Verify checkpoint-to-checkpoint continuity completely offline."""
    if (
        isinstance(max_intervening_events, bool)
        or not isinstance(max_intervening_events, int)
        or max_intervening_events < 0
        or max_intervening_events > MAX_EVENTS
    ):
        raise TransparencyError(f"max_intervening_events must be in 0..{MAX_EVENTS}")

    parsed = (
        ConsistencyProofBundle.from_dict(bundle)
        if isinstance(bundle, dict)
        else bundle
    )
    canonicalize_checkpoint(parsed.earlier_checkpoint)
    canonicalize_checkpoint(parsed.later_checkpoint)

    errors: list[str] = []
    earlier = parsed.earlier_checkpoint
    later = parsed.later_checkpoint

    if earlier.organization_identity_hash != parsed.organization_identity_hash:
        errors.append("earlierCheckpoint organizationIdentityHash mismatch")
    if later.organization_identity_hash != parsed.organization_identity_hash:
        errors.append("laterCheckpoint organizationIdentityHash mismatch")

    if trusted_earlier_checkpoint is not None:
        if checkpoint_hash(earlier) != checkpoint_hash(trusted_earlier_checkpoint):
            errors.append("earlierCheckpoint does not match caller's pinned checkpoint")

    errors.extend(detect_rollback(earlier, later))

    if earlier.event_count < 0 or later.event_count < 0:
        errors.append("checkpoint eventCount must be non-negative")
    if earlier.event_count == 0 and earlier.tree_head_hash != "0" * 64:
        errors.append("genesis earlierCheckpoint must have zero treeHeadHash")
    if earlier.event_count == 0 and parsed.anchor_event_hash is not None:
        errors.append("genesis earlierCheckpoint must not set anchorEventHash")
    if (
        earlier.event_count > 0
        and len(parsed.intervening_events) > 0
        and parsed.anchor_event_hash is None
    ):
        errors.append("non-genesis consistency proof requires anchorEventHash")

    if len(parsed.intervening_events) > max_intervening_events:
        errors.append("interveningEvents exceeds max_intervening_events bound")

    expected_span = later.event_count - earlier.event_count
    if expected_span >= 0 and len(parsed.intervening_events) != expected_span:
        errors.append(
            f"interveningEvents count mismatch: expected {expected_span}, got {len(parsed.intervening_events)}"
        )

    prev_ev_hash = parsed.anchor_event_hash if earlier.event_count > 0 else None
    for offset, ev in enumerate(parsed.intervening_events):
        expected_seq = earlier.event_count + offset
        if ev.organization_identity_hash != parsed.organization_identity_hash:
            errors.append(f"event[{offset}] organizationIdentityHash mismatch")
        if ev.sequence != expected_seq:
            errors.append(
                f"event[{offset}] non-monotonic sequence: expected {expected_seq}, got {ev.sequence}"
            )
        if expected_seq == 0:
            if ev.previous_event_hash is not None:
                errors.append("genesis intervening event must not set previousEventHash")
        elif ev.previous_event_hash != prev_ev_hash:
            errors.append(f"event[{offset}] broken previousEventHash link")
        prev_ev_hash = event_hash(ev)

    computed_later_head = _advance_tree_head(
        earlier.tree_head_hash, parsed.intervening_events
    )
    if computed_later_head != later.tree_head_hash:
        errors.append("recomputed tree head does not match laterCheckpoint.treeHeadHash")

    if earlier.manifest_hash != later.manifest_hash:
        if not parsed.intervening_manifests:
            errors.append(
                "manifestHash changed across checkpoints without interveningManifests lineage"
            )
        else:
            prev_mh = earlier.manifest_hash
            for idx, mf in enumerate(parsed.intervening_manifests):
                canonicalize_manifest(mf)
                if mf.organization_identity_hash != parsed.organization_identity_hash:
                    errors.append(f"manifest[{idx}] organizationIdentityHash mismatch")
                if mf.predecessor_manifest_hash != prev_mh:
                    errors.append(f"manifest[{idx}] broken predecessorManifestHash link")
                prev_mh = _publication_manifest_hash(mf)
            if prev_mh != later.manifest_hash:
                errors.append(
                    "final intervening manifest hash does not match laterCheckpoint.manifestHash"
                )
    else:
        for idx, mf in enumerate(parsed.intervening_manifests):
            canonicalize_manifest(mf)
            if manifest_hash(mf) != later.manifest_hash:
                errors.append(
                    f"manifest[{idx}] conflicts with unchanged checkpoint manifestHash"
                )

    return ConsistencyProofVerificationResult(
        valid=len(errors) == 0,
        errors=tuple(errors),
        organization_identity_hash=parsed.organization_identity_hash,
        earlier_checkpoint_hash=checkpoint_hash(earlier),
        later_checkpoint_hash=checkpoint_hash(later),
        verified_tree_head_hash=computed_later_head,
        intervening_event_count=len(parsed.intervening_events),
        bundle_hash=parsed.bundle_hash(),
    )


def require_valid_consistency_proof_bundle(
    bundle: ConsistencyProofBundle | dict[str, Any],
    *,
    trusted_earlier_checkpoint: DirectoryCheckpoint | None = None,
    max_intervening_events: int = MAX_EVENTS,
) -> ConsistencyProofVerificationResult:
    """Fail-closed wrapper that raises ``TransparencyError`` if bundle verification fails."""
    verdict = verify_consistency_proof_bundle(
        bundle,
        trusted_earlier_checkpoint=trusted_earlier_checkpoint,
        max_intervening_events=max_intervening_events,
    )
    if not verdict.valid:
        raise TransparencyError("; ".join(verdict.errors))
    return verdict

