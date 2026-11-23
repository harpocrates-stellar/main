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
SNAPSHOT_PROTOCOL = "harpocrates-issuer-trust-snapshot"
VERSION = 1
SUPPORTED_VERSIONS = {1}

MAX_ACTIVE_KEYS = 8
MAX_EVENTS = 10_000
MAX_SIMULATION_ITEMS = 1_000
MAX_MANIFEST_BYTES = 8_192
MAX_CHECKPOINT_BYTES = 16_384
MAX_CONSISTENCY_BUNDLE_BYTES = 1_048_576
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


class TrustState(str, Enum):
    TRUSTED = "trusted"
    HISTORICALLY_VALID = "historically_valid"
    UNTRUSTED = "untrusted"
    STALE = "stale"


class TrustChangeReason(str, Enum):
    UNCHANGED = "unchanged"
    ACTIVATED = "activated"
    KEY_ROTATED = "key_rotated"
    KEY_EXPIRED = "key_expired"
    KEY_RETIRED = "key_retired"
    KEY_COMPROMISED = "key_compromised"
    STALE_DIRECTORY = "stale_directory"
    DIRECTORY_INCONSISTENT = "directory_inconsistent"
    UNKNOWN_KEY = "unknown_key"
    NOT_YET_VALID = "not_yet_valid"


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


def advance_tree_head(start_head: str, events: Iterable[DirectoryEvent]) -> str:
    """Advance a deterministic Merkle-style chain head across ordered events."""
    head = _require_hex("startHead", start_head)
    for ev in events:
        head = _sha256_hex((head + event_hash(ev)).encode("utf-8"))
    return head


def compute_tree_head(events: Iterable[DirectoryEvent]) -> str:
    """Deterministic Merkle-style chain head over ordered events."""
    return advance_tree_head("0" * 64, events)


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

    def make_consistency_proof_bundle(
        self,
        earlier_checkpoint: DirectoryCheckpoint,
        later_checkpoint: DirectoryCheckpoint,
    ) -> "ConsistencyProofBundle":
        """Build a portable consistency proof bundle between two checkpoints."""
        return build_consistency_proof_bundle(self, earlier_checkpoint, later_checkpoint)


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


@dataclass(frozen=True)
class ConsistencyProofBundle:
    """Portable, offline-verifiable consistency proof between two checkpoints.

    Binds an earlier and later ``DirectoryCheckpoint`` to the intervening
    append-only ``DirectoryEvent`` sequence so verifiers can confirm continuity
    without trusting a live directory response.
    """

    earlier_checkpoint: DirectoryCheckpoint
    later_checkpoint: DirectoryCheckpoint
    intervening_events: tuple[DirectoryEvent, ...] = ()
    version: int = VERSION
    protocol: str = PROTOCOL

    def __post_init__(self) -> None:
        if not isinstance(self.intervening_events, tuple):
            object.__setattr__(self, "intervening_events", tuple(self.intervening_events))

    def to_dict(self) -> dict[str, Any]:
        return {
            "earlierCheckpoint": self.earlier_checkpoint.to_dict(),
            "interveningEvents": [ev.to_dict() for ev in self.intervening_events],
            "laterCheckpoint": self.later_checkpoint.to_dict(),
            "protocol": self.protocol,
            "version": self.version,
        }

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> "ConsistencyProofBundle":
        if not isinstance(obj, dict):
            raise TransparencyError("consistency proof bundle must be a JSON object")
        if obj.get("protocol") != PROTOCOL:
            raise TransparencyError("unsupported consistency proof bundle protocol")
        if int(obj.get("version", 0)) not in SUPPORTED_VERSIONS:
            raise TransparencyError("unsupported consistency proof bundle version")
        raw_events = obj.get("interveningEvents")
        if not isinstance(raw_events, list):
            raise TransparencyError("interveningEvents must be a list")
        if len(raw_events) > MAX_EVENTS:
            raise TransparencyError("interveningEvents exceeds bound")
        earlier = DirectoryCheckpoint.from_dict(obj["earlierCheckpoint"])
        later = DirectoryCheckpoint.from_dict(obj["laterCheckpoint"])
        events = tuple(DirectoryEvent.from_dict(ev) for ev in raw_events)
        return ConsistencyProofBundle(
            earlier_checkpoint=earlier,
            later_checkpoint=later,
            intervening_events=events,
            version=int(obj["version"]),
            protocol=str(obj["protocol"]),
        )

    def to_json(self) -> str:
        return canonicalize_consistency_proof_bundle(self)

    @staticmethod
    def from_json(raw: str | bytes) -> "ConsistencyProofBundle":
        raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
        if len(raw_bytes) > MAX_CONSISTENCY_BUNDLE_BYTES:
            raise TransparencyError("consistency proof bundle exceeds size bound")
        try:
            parsed = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TransparencyError(f"invalid consistency proof bundle JSON: {exc}") from exc
        return ConsistencyProofBundle.from_dict(parsed)


def canonicalize_consistency_proof_bundle(bundle: ConsistencyProofBundle) -> str:
    """Deterministic JSON encoding for a consistency proof bundle."""
    if len(bundle.intervening_events) > MAX_EVENTS:
        raise TransparencyError("interveningEvents exceeds bound")
    encoded = _canonical_json(bundle.to_dict())
    if len(encoded) > MAX_CONSISTENCY_BUNDLE_BYTES:
        raise TransparencyError("consistency proof bundle exceeds size bound")
    return encoded.decode("utf-8")


def consistency_proof_bundle_hash(bundle: ConsistencyProofBundle) -> str:
    """SHA-256 digest of the canonical consistency proof bundle."""
    return _sha256_hex(canonicalize_consistency_proof_bundle(bundle).encode("utf-8"))


def build_consistency_proof_bundle(
    directory: IssuerDirectory,
    earlier_checkpoint: DirectoryCheckpoint,
    later_checkpoint: DirectoryCheckpoint,
) -> ConsistencyProofBundle:
    """Build a portable consistency proof bundle from an authoritative directory."""
    if earlier_checkpoint.event_count < 0 or later_checkpoint.event_count < 0:
        raise TransparencyError("checkpoint eventCount must be non-negative")
    earlier_errors = verify_checkpoint_consistency(directory, earlier_checkpoint)
    if earlier_errors:
        raise TransparencyError(
            "earlier checkpoint inconsistent with directory: " + "; ".join(earlier_errors)
        )
    later_errors = verify_checkpoint_consistency(directory, later_checkpoint)
    if later_errors:
        raise TransparencyError(
            "later checkpoint inconsistent with directory: " + "; ".join(later_errors)
        )
    rollback_errors = detect_rollback(earlier_checkpoint, later_checkpoint)
    if rollback_errors:
        raise TransparencyError(
            "invalid checkpoint ordering: " + "; ".join(rollback_errors)
        )
    if later_checkpoint.timestamp < earlier_checkpoint.timestamp:
        raise TransparencyError("checkpoint timestamp regressed")

    intervening = tuple(
        directory.events[earlier_checkpoint.event_count : later_checkpoint.event_count]
    )
    bundle = ConsistencyProofBundle(
        earlier_checkpoint=earlier_checkpoint,
        later_checkpoint=later_checkpoint,
        intervening_events=intervening,
    )
    require_valid_consistency_proof_bundle(bundle)
    return bundle


def verify_consistency_proof_bundle(
    bundle: ConsistencyProofBundle,
    *,
    expected_organization_identity_hash: str | None = None,
    expected_earlier_checkpoint: DirectoryCheckpoint | None = None,
) -> list[str]:
    """Verify checkpoint continuity offline without trusting a live directory.

    Returns a list of consistency errors (empty list means valid).
    """
    errors: list[str] = []
    earlier = bundle.earlier_checkpoint
    later = bundle.later_checkpoint

    if bundle.protocol != PROTOCOL:
        errors.append("unsupported consistency proof bundle protocol")
    if bundle.version not in SUPPORTED_VERSIONS:
        errors.append("unsupported consistency proof bundle version")
    if earlier.protocol != PROTOCOL or later.protocol != PROTOCOL:
        errors.append("unsupported checkpoint protocol in consistency bundle")
    if earlier.version not in SUPPORTED_VERSIONS or later.version not in SUPPORTED_VERSIONS:
        errors.append("unsupported checkpoint version in consistency bundle")

    try:
        canonicalize_consistency_proof_bundle(bundle)
    except TransparencyError as exc:
        errors.append(str(exc))

    if earlier.event_count < 0 or later.event_count < 0:
        errors.append("checkpoint eventCount must be non-negative")

    if expected_organization_identity_hash is not None:
        norm_org = expected_organization_identity_hash.lower()
        if earlier.organization_identity_hash != norm_org:
            errors.append("earlier checkpoint organizationIdentityHash mismatch")
        if later.organization_identity_hash != norm_org:
            errors.append("later checkpoint organizationIdentityHash mismatch")

    if expected_earlier_checkpoint is not None:
        if checkpoint_hash(earlier) != checkpoint_hash(expected_earlier_checkpoint):
            errors.append("earlier checkpoint does not match expected anchor")

    errors.extend(detect_rollback(earlier, later))

    if later.timestamp < earlier.timestamp:
        errors.append("checkpoint timestamp regressed")

    if earlier.event_count == 0 and earlier.tree_head_hash != "0" * 64:
        errors.append("genesis checkpoint treeHeadHash must be all zeros")

    expected_delta = later.event_count - earlier.event_count
    if expected_delta >= 0 and len(bundle.intervening_events) != expected_delta:
        errors.append(
            f"intervening event count mismatch: expected {expected_delta}, "
            f"got {len(bundle.intervening_events)}"
        )

    for idx, ev in enumerate(bundle.intervening_events):
        if ev.organization_identity_hash != earlier.organization_identity_hash:
            errors.append(
                f"intervening event {idx} organizationIdentityHash mismatch"
            )
        expected_seq = earlier.event_count + idx
        if ev.sequence != expected_seq:
            errors.append(
                f"non-monotonic sequence at intervening event {idx}: "
                f"expected {expected_seq}, got {ev.sequence}"
            )
        if ev.sequence == 0:
            if ev.previous_event_hash is not None:
                errors.append("genesis event must not set previousEventHash")
        elif idx == 0:
            if not ev.previous_event_hash or not _is_hex(ev.previous_event_hash):
                errors.append(
                    "first intervening event after non-genesis checkpoint must set previousEventHash"
                )
        else:
            prev_hash = event_hash(bundle.intervening_events[idx - 1])
            if ev.previous_event_hash != prev_hash:
                errors.append(
                    f"broken event chain at sequence {ev.sequence} (previousEventHash mismatch)"
                )

    if expected_delta >= 0 and len(bundle.intervening_events) == expected_delta:
        computed_head = advance_tree_head(earlier.tree_head_hash, bundle.intervening_events)
        if computed_head != later.tree_head_hash:
            errors.append(
                "later checkpoint treeHeadHash does not match intervening events (broken continuity)"
            )

    return errors


def require_valid_consistency_proof_bundle(
    bundle: ConsistencyProofBundle,
    *,
    expected_organization_identity_hash: str | None = None,
    expected_earlier_checkpoint: DirectoryCheckpoint | None = None,
) -> ConsistencyProofBundle:
    """Fail-closed offline verification gate for a consistency proof bundle."""
    errors = verify_consistency_proof_bundle(
        bundle,
        expected_organization_identity_hash=expected_organization_identity_hash,
        expected_earlier_checkpoint=expected_earlier_checkpoint,
    )
    if errors:
        raise TransparencyError(
            "invalid consistency proof bundle: " + "; ".join(errors)
        )
    return bundle


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


@dataclass(frozen=True)
class IssuerTrustAssessment:
    """Structured issuer trust evaluation for a single verification run."""

    key_id: str
    organization_identity_hash: str
    state: TrustState
    reason: TrustChangeReason
    verified_at: int
    signature_timestamp: int
    key_status: KeyStatus | None = None
    successor_key_id: str | None = None
    reason_hash: str | None = None
    checkpoint_event_count: int | None = None
    checkpoint_age_seconds: int | None = None
    high_assurance: bool = False
    consistency_errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "highAssurance": self.high_assurance,
            "keyId": self.key_id,
            "organizationIdentityHash": self.organization_identity_hash,
            "reason": self.reason.value,
            "signatureTimestamp": self.signature_timestamp,
            "state": self.state.value,
            "verifiedAt": self.verified_at,
        }
        if self.key_status is not None:
            d["keyStatus"] = self.key_status.value
        if self.successor_key_id is not None:
            d["successorKeyId"] = self.successor_key_id
        if self.reason_hash is not None:
            d["reasonHash"] = self.reason_hash
        if self.checkpoint_event_count is not None:
            d["checkpointEventCount"] = self.checkpoint_event_count
        if self.checkpoint_age_seconds is not None:
            d["checkpointAgeSeconds"] = self.checkpoint_age_seconds
        if self.consistency_errors:
            d["consistencyErrors"] = list(self.consistency_errors)
        return d


@dataclass(frozen=True)
class IssuerTrustChange:
    """Explains why an issuer key's trust state changed across verification runs."""

    key_id: str
    organization_identity_hash: str
    changed: bool
    previous_state: TrustState
    current_state: TrustState
    reason: TrustChangeReason
    previous_verified_at: int
    current_verified_at: int
    successor_key_id: str | None = None
    reason_hash: str | None = None
    rollback_errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "changed": self.changed,
            "currentState": self.current_state.value,
            "currentVerifiedAt": self.current_verified_at,
            "keyId": self.key_id,
            "organizationIdentityHash": self.organization_identity_hash,
            "previousState": self.previous_state.value,
            "previousVerifiedAt": self.previous_verified_at,
            "reason": self.reason.value,
        }
        if self.successor_key_id is not None:
            d["successorKeyId"] = self.successor_key_id
        if self.reason_hash is not None:
            d["reasonHash"] = self.reason_hash
        if self.rollback_errors:
            d["rollbackErrors"] = list(self.rollback_errors)
        return d


def _find_key_lifecycle_metadata(
    directory: IssuerDirectory,
    key_id: str,
) -> tuple[str | None, str | None]:
    """Return (successor_key_id, reason_hash) for a key from directory events."""
    successor_key_id: str | None = None
    reason_hash: str | None = None
    for ev in directory.events:
        if ev.event_type == EventType.ROTATION and ev.related_key_id == key_id:
            successor_key_id = ev.key_id
        if ev.key_id == key_id and ev.event_type in (EventType.COMPROMISE, EventType.RETIREMENT):
            if ev.reason_hash is not None:
                reason_hash = ev.reason_hash
    return successor_key_id, reason_hash


def _effective_key_valid_until(directory: IssuerDirectory, key: IssuerKey) -> int | None:
    """Return the tightest valid_until bound from key state or current manifest."""
    bounds: list[int] = []
    if key.valid_until is not None:
        bounds.append(key.valid_until)
    if directory.current_manifest is not None:
        for mk in directory.current_manifest.active_keys:
            if mk.key_id == key.key_id and mk.valid_until is not None:
                bounds.append(mk.valid_until)
        if directory.current_manifest.valid_until is not None:
            bounds.append(directory.current_manifest.valid_until)
    return min(bounds) if bounds else None


def assess_issuer_trust(
    directory: IssuerDirectory,
    key_id: str,
    *,
    signature_timestamp: int | None = None,
    cache: DirectoryCache | None = None,
    high_assurance: bool = False,
    now: int | None = None,
) -> IssuerTrustAssessment:
    """Evaluate issuer key trust for a verification run with an explicit reason.

    Distinguishes rotation, expiry, retirement, compromise, stale directory state,
    and directory consistency failures instead of collapsing them into a generic
    invalid-issuer outcome. Preserves fail-closed freshness for cached checkpoints.
    """
    verified_at = int(time.time()) if now is None else now
    sig_ts = verified_at if signature_timestamp is None else signature_timestamp
    cp_event_count: int | None = None
    cp_age: int | None = None

    if cache is not None:
        cp_event_count = cache.checkpoint.event_count
        cp_age = cache.age_seconds(verified_at)
        consistency_errors = verify_checkpoint_consistency(directory, cache.checkpoint)
        if consistency_errors:
            return IssuerTrustAssessment(
                key_id=key_id,
                organization_identity_hash=directory.organization_identity_hash,
                state=TrustState.UNTRUSTED,
                reason=TrustChangeReason.DIRECTORY_INCONSISTENT,
                verified_at=verified_at,
                signature_timestamp=sig_ts,
                checkpoint_event_count=cp_event_count,
                checkpoint_age_seconds=cp_age,
                high_assurance=high_assurance,
                consistency_errors=tuple(consistency_errors),
            )
        try:
            require_fresh_checkpoint(cache, high_assurance=high_assurance, now=verified_at)
        except FreshnessError:
            return IssuerTrustAssessment(
                key_id=key_id,
                organization_identity_hash=directory.organization_identity_hash,
                state=TrustState.STALE,
                reason=TrustChangeReason.STALE_DIRECTORY,
                verified_at=verified_at,
                signature_timestamp=sig_ts,
                checkpoint_event_count=cp_event_count,
                checkpoint_age_seconds=cp_age,
                high_assurance=high_assurance,
            )

    key = directory.keys.get(key_id)
    if key is None:
        return IssuerTrustAssessment(
            key_id=key_id,
            organization_identity_hash=directory.organization_identity_hash,
            state=TrustState.UNTRUSTED,
            reason=TrustChangeReason.UNKNOWN_KEY,
            verified_at=verified_at,
            signature_timestamp=sig_ts,
            checkpoint_event_count=cp_event_count,
            checkpoint_age_seconds=cp_age,
            high_assurance=high_assurance,
        )

    successor_key_id, reason_hash = _find_key_lifecycle_metadata(directory, key_id)

    if sig_ts < key.valid_from:
        return IssuerTrustAssessment(
            key_id=key_id,
            organization_identity_hash=directory.organization_identity_hash,
            state=TrustState.UNTRUSTED,
            reason=TrustChangeReason.NOT_YET_VALID,
            verified_at=verified_at,
            signature_timestamp=sig_ts,
            key_status=key.status,
            successor_key_id=successor_key_id,
            reason_hash=reason_hash,
            checkpoint_event_count=cp_event_count,
            checkpoint_age_seconds=cp_age,
            high_assurance=high_assurance,
        )

    if key.status == KeyStatus.COMPROMISED:
        state = (
            TrustState.UNTRUSTED
            if key_was_compromised_at(directory, key_id, sig_ts)
            else TrustState.HISTORICALLY_VALID
        )
        return IssuerTrustAssessment(
            key_id=key_id,
            organization_identity_hash=directory.organization_identity_hash,
            state=state,
            reason=TrustChangeReason.KEY_COMPROMISED,
            verified_at=verified_at,
            signature_timestamp=sig_ts,
            key_status=key.status,
            successor_key_id=successor_key_id,
            reason_hash=reason_hash,
            checkpoint_event_count=cp_event_count,
            checkpoint_age_seconds=cp_age,
            high_assurance=high_assurance,
        )

    if key.status == KeyStatus.ROTATED:
        state = (
            TrustState.HISTORICALLY_VALID
            if key_valid_for_historical_signature(directory, key_id, sig_ts)
            else TrustState.UNTRUSTED
        )
        return IssuerTrustAssessment(
            key_id=key_id,
            organization_identity_hash=directory.organization_identity_hash,
            state=state,
            reason=TrustChangeReason.KEY_ROTATED,
            verified_at=verified_at,
            signature_timestamp=sig_ts,
            key_status=key.status,
            successor_key_id=successor_key_id,
            reason_hash=reason_hash,
            checkpoint_event_count=cp_event_count,
            checkpoint_age_seconds=cp_age,
            high_assurance=high_assurance,
        )

    if key.status == KeyStatus.RETIRED:
        state = (
            TrustState.HISTORICALLY_VALID
            if key_valid_for_historical_signature(directory, key_id, sig_ts)
            else TrustState.UNTRUSTED
        )
        return IssuerTrustAssessment(
            key_id=key_id,
            organization_identity_hash=directory.organization_identity_hash,
            state=state,
            reason=TrustChangeReason.KEY_RETIRED,
            verified_at=verified_at,
            signature_timestamp=sig_ts,
            key_status=key.status,
            successor_key_id=successor_key_id,
            reason_hash=reason_hash,
            checkpoint_event_count=cp_event_count,
            checkpoint_age_seconds=cp_age,
            high_assurance=high_assurance,
        )

    # KeyStatus.ACTIVE — check manifest valid_from and key/manifest expiry
    if directory.current_manifest is not None and sig_ts < directory.current_manifest.valid_from:
        return IssuerTrustAssessment(
            key_id=key_id,
            organization_identity_hash=directory.organization_identity_hash,
            state=TrustState.UNTRUSTED,
            reason=TrustChangeReason.NOT_YET_VALID,
            verified_at=verified_at,
            signature_timestamp=sig_ts,
            key_status=key.status,
            checkpoint_event_count=cp_event_count,
            checkpoint_age_seconds=cp_age,
            high_assurance=high_assurance,
        )

    effective_until = _effective_key_valid_until(directory, key)
    if effective_until is not None and sig_ts >= effective_until:
        return IssuerTrustAssessment(
            key_id=key_id,
            organization_identity_hash=directory.organization_identity_hash,
            state=TrustState.UNTRUSTED,
            reason=TrustChangeReason.KEY_EXPIRED,
            verified_at=verified_at,
            signature_timestamp=sig_ts,
            key_status=key.status,
            checkpoint_event_count=cp_event_count,
            checkpoint_age_seconds=cp_age,
            high_assurance=high_assurance,
        )

    return IssuerTrustAssessment(
        key_id=key_id,
        organization_identity_hash=directory.organization_identity_hash,
        state=TrustState.TRUSTED,
        reason=TrustChangeReason.ACTIVATED,
        verified_at=verified_at,
        signature_timestamp=sig_ts,
        key_status=key.status,
        checkpoint_event_count=cp_event_count,
        checkpoint_age_seconds=cp_age,
        high_assurance=high_assurance,
    )


def compare_issuer_trust(
    previous: IssuerTrustAssessment,
    current: IssuerTrustAssessment,
    *,
    previous_checkpoint: DirectoryCheckpoint | None = None,
    current_checkpoint: DirectoryCheckpoint | None = None,
) -> IssuerTrustChange:
    """Compare two verification runs and expose the reason for any trust change."""
    if previous.organization_identity_hash != current.organization_identity_hash:
        raise TransparencyError("cannot compare trust across different organizations")
    if previous.key_id != current.key_id:
        raise TransparencyError("cannot compare trust across different keys")

    if previous_checkpoint is not None and current_checkpoint is not None:
        rollback_errors = detect_rollback(previous_checkpoint, current_checkpoint)
        if rollback_errors:
            return IssuerTrustChange(
                key_id=current.key_id,
                organization_identity_hash=current.organization_identity_hash,
                changed=True,
                previous_state=previous.state,
                current_state=TrustState.UNTRUSTED,
                reason=TrustChangeReason.DIRECTORY_INCONSISTENT,
                previous_verified_at=previous.verified_at,
                current_verified_at=current.verified_at,
                successor_key_id=current.successor_key_id,
                reason_hash=current.reason_hash,
                rollback_errors=tuple(rollback_errors),
            )

    changed = previous.state != current.state or previous.reason != current.reason
    reason = current.reason if changed else TrustChangeReason.UNCHANGED
    return IssuerTrustChange(
        key_id=current.key_id,
        organization_identity_hash=current.organization_identity_hash,
        changed=changed,
        previous_state=previous.state,
        current_state=current.state,
        reason=reason,
        previous_verified_at=previous.verified_at,
        current_verified_at=current.verified_at,
        successor_key_id=current.successor_key_id,
        reason_hash=current.reason_hash,
    )
