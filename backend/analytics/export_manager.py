from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from analytics.log_processor import LogEntry, LogProcessor, validate_log_export_safety
except Exception:
    try:
        from backend.analytics.log_processor import LogEntry, LogProcessor, validate_log_export_safety
    except Exception:
        LogEntry = None
        LogProcessor = None
        validate_log_export_safety = None


EXPORT_FORMAT_VERSION = "1.0.0"
TENANT_EXPORT_MANIFEST_VERSION = "1.0.0"
MANIFEST_DIGEST_PREFIX = "mft-v1:"
MANIFEST_DOMAIN_SEPARATOR = "harpocrates-tenant-export-manifest-v1:"
REDACTION_POLICY_DIGEST_PREFIX = "rpol-v1:"
REDACTION_POLICY_DOMAIN_SEPARATOR = "harpocrates-redaction-policy-v1:"

# Sensitive evidence and credential classes excluded from tenant exports by construction.
EXCLUDED_SENSITIVE_CLASSES: Tuple[str, ...] = (
    "credential",
    "evidence_media",
    "pii",
    "private_key",
    "proof_payload",
    "secret",
    "wallet_signature",
    "witness",
)

_SENSITIVE_CLASS_HINTS = frozenset({
    "evidence", "evidence_media", "media", "video", "audio", "image",
    "upload", "raw_bytes", "blob", "frame", "clip", "recording", "screenshot",
    "witness", "witness_data", "proof", "proof_payload", "zk_proof",
    "proving_key", "verification_key", "nullifier", "commitment", "private_inputs",
    "credential", "credentials", "secret", "secrets", "password", "passwd", "pwd",
    "token", "consent_token", "export_token", "api_key", "apikey",
    "private_key", "privkey", "mnemonic", "seed_phrase", "recovery_phrase",
    "access_key", "session_token", "bearer",
    "wallet_signature", "signature", "tx_signature", "auth_signature",
    "ed25519_signature", "signed_tx", "xdr", "transaction_envelope",
    "pii", "biometric", "passport", "ssn", "government_id",
})

_CREDENTIAL_VALUE_PATTERNS = (
    re.compile(r"\bcst-v1:[0-9a-f]{16,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"-----BEGIN\s+[A-Z0-9 ]+PRIVATE KEY-----"),
    re.compile(r"\bS[A-Z2-7]{55}\b"),
)

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_RECORD_CLASS_NORM_RE = re.compile(r"[^a-z0-9_]+")

# Sentinel values distinguishing withdrawn consent from data never collected.
CONSENT_STATE_NEVER_COLLECTED = "never_collected"
CONSENT_STATE_WITHDRAWN = "withdrawn"
CONSENT_STATE_GRANTED = "granted"

_SAFE_LABEL_RE = re.compile(r"[^A-Za-z0-9._-]")


@dataclass
class ExportPolicy:
    max_artifacts_per_export: int = 64
    max_artifact_bytes: int = 4_194_304
    compress_default: bool = False
    include_sampled_out_events: bool = False
    include_debug_fields: bool = False
    require_export_token: bool = True
    allow_unauthenticated_export_shadow_mode: bool = True
    export_id_prefix: str = "exp-v1:"
    require_safety_signature: bool = True
    safety_signature_prefix: str = "sig-v1:"


EXPORT_POLICY_DEFAULT: ExportPolicy = ExportPolicy()


@dataclass
class ExportArtifact:
    artifact_id: str
    schema_version: str = EXPORT_FORMAT_VERSION
    generated_at_epoch_seconds: float = 0.0
    entry_count: int = 0
    payload_bytes: int = 0
    compress: bool = False
    exported_by_tag: Optional[str] = None
    safety_signature: Optional[str] = None
    checksum_sha256_prefix16: Optional[str] = None
    payload_type: str = "application/json"
    rollout_phase: str = "shadow"
    redaction_version: str = "harpocrates-redaction-v1"
    encryption_at_rest: bool = False
    # Consent policy revision in effect when the underlying data was collected.
    # Entries collected under no recorded policy are reported as never_collected
    # rather than being conflated with withdrawn consent.
    consent_policy_revision: Optional[str] = None
    consent_state: str = CONSENT_STATE_NEVER_COLLECTED
    # Server-selected, filesystem-safe name. Never derived from user input.
    server_file_name: str = ""
    # Caller-requested display label. Only populated for authorized output.
    display_label: Optional[str] = None
    # Verifiable tenant data export manifest binding record classes and redaction policy.
    manifest: Optional["TenantExportManifest"] = None


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_redaction_policy_digest(
    redaction_version: str = "harpocrates-redaction-v1",
    excluded_categories: Optional[Iterable[str]] = None,
    cap_bytes: int = 256,
    max_depth: int = 16,
) -> str:
    """Compute a canonical SHA-256 digest for the active redaction policy."""
    cats = sorted(set(excluded_categories if excluded_categories is not None else EXCLUDED_SENSITIVE_CLASSES))
    canonical = _canonical_json({
        "cap_bytes": int(cap_bytes),
        "excluded_categories": cats,
        "max_depth": int(max_depth),
        "redaction_version": str(redaction_version),
    })
    digest = hashlib.sha256((REDACTION_POLICY_DOMAIN_SEPARATOR + canonical).encode("utf-8")).hexdigest()
    return REDACTION_POLICY_DIGEST_PREFIX + digest


def _normalize_record_class(value: str) -> str:
    lowered = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    return _RECORD_CLASS_NORM_RE.sub("_", lowered).strip("_")


def is_sensitive_record_class(record_class: str) -> bool:
    """Return True if a record class represents sensitive evidence or credential material."""
    norm = _normalize_record_class(record_class)
    if not norm:
        return True
    if norm in _SENSITIVE_CLASS_HINTS:
        return True
    parts = [p for p in norm.split("_") if p]
    if any(p in _SENSITIVE_CLASS_HINTS for p in parts):
        return True
    for i in range(len(parts) - 1):
        if f"{parts[i]}_{parts[i + 1]}" in _SENSITIVE_CLASS_HINTS:
            return True
    return False


def _value_contains_credential_pattern(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return any(pat.search(value) is not None for pat in _CREDENTIAL_VALUE_PATTERNS)


def classify_record_class(entry: Any) -> str:
    """Derive a canonical record class name for an exported log entry."""
    labels = getattr(entry, "labels", None)
    if isinstance(labels, dict) and labels.get("category"):
        return _normalize_record_class(str(labels["category"]))
    event_name = getattr(entry, "event_name", "") or "operational_event"
    return _normalize_record_class(str(event_name))


def entry_contains_sensitive_material(entry: Any) -> Tuple[bool, List[str]]:
    """Inspect a log entry for sensitive evidence or credential material."""
    reasons: List[str] = []
    record_class = classify_record_class(entry)
    if is_sensitive_record_class(record_class):
        reasons.append(f"sensitive_record_class:{record_class}")

    event_name = getattr(entry, "event_name", "")
    if event_name and is_sensitive_record_class(str(event_name)):
        reasons.append(f"sensitive_event_name:{event_name}")

    labels = getattr(entry, "labels", None)
    if isinstance(labels, dict):
        for k, v in labels.items():
            if is_sensitive_record_class(str(k)):
                reasons.append(f"sensitive_label_key:{k}")
            if _value_contains_credential_pattern(v):
                reasons.append(f"credential_in_label:{k}")

    counters = getattr(entry, "counters", None)
    if isinstance(counters, dict):
        for k in counters:
            if is_sensitive_record_class(str(k)):
                reasons.append(f"sensitive_counter_key:{k}")

    summary = getattr(entry, "message_summary", None)
    if _value_contains_credential_pattern(summary):
        reasons.append("credential_in_message_summary")

    return (len(reasons) > 0, reasons)


def filter_entries_for_tenant_export(entries: List[Any]) -> Tuple[List[Any], List[str]]:
    """Exclude entries carrying sensitive evidence or credential material by construction."""
    safe: List[Any] = []
    excluded_ids: List[str] = []
    for entry in entries:
        is_sensitive, _ = entry_contains_sensitive_material(entry)
        if is_sensitive:
            excluded_ids.append(str(getattr(entry, "entry_id", "")))
        else:
            safe.append(entry)
    return safe, excluded_ids


@dataclass
class TenantExportManifest:
    """Verifiable manifest binding exported record classes and redaction policy to a digest."""

    artifact_id: str
    payload_sha256: str
    entry_count: int
    record_classes: Tuple[str, ...]
    redaction_policy_version: str
    redaction_policy_digest: str
    consent_policy_revision: Optional[str] = None
    consent_state: str = CONSENT_STATE_NEVER_COLLECTED
    tenant_tag: Optional[str] = None
    excluded_sensitive_classes: Tuple[str, ...] = EXCLUDED_SENSITIVE_CLASSES
    manifest_version: str = TENANT_EXPORT_MANIFEST_VERSION
    manifest_digest: str = ""

    def to_canonical_payload(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "consent_policy_revision": self.consent_policy_revision,
            "consent_state": self.consent_state,
            "entry_count": int(self.entry_count),
            "excluded_sensitive_classes": list(self.excluded_sensitive_classes),
            "manifest_version": self.manifest_version,
            "payload_sha256": self.payload_sha256,
            "record_classes": list(self.record_classes),
            "redaction_policy_digest": self.redaction_policy_digest,
            "redaction_policy_version": self.redaction_policy_version,
            "tenant_tag": self.tenant_tag,
        }

    def to_dict(self) -> Dict[str, Any]:
        data = self.to_canonical_payload()
        data["manifest_digest"] = self.manifest_digest
        return data


def compute_manifest_digest(manifest: TenantExportManifest) -> str:
    """Compute the canonical domain-separated SHA-256 digest of a TenantExportManifest."""
    canonical = _canonical_json(manifest.to_canonical_payload())
    digest = hashlib.sha256((MANIFEST_DOMAIN_SEPARATOR + canonical).encode("utf-8")).hexdigest()
    return MANIFEST_DIGEST_PREFIX + digest


def build_tenant_export_manifest(
    *,
    artifact_id: str,
    serialized_payload: str,
    entry_count: int,
    record_classes: Iterable[str],
    redaction_policy_version: str = "harpocrates-redaction-v1",
    redaction_policy_digest: Optional[str] = None,
    consent_policy_revision: Optional[str] = None,
    consent_state: str = CONSENT_STATE_NEVER_COLLECTED,
    tenant_tag: Optional[str] = None,
) -> TenantExportManifest:
    """Construct a verifiable TenantExportManifest, failing closed on sensitive record classes."""
    normalized_classes = sorted({_normalize_record_class(rc) for rc in record_classes})
    for rc in normalized_classes:
        if is_sensitive_record_class(rc):
            raise ValueError(f"sensitive record class excluded by construction: {rc}")

    policy_digest = (
        redaction_policy_digest
        if redaction_policy_digest is not None
        else compute_redaction_policy_digest(redaction_version=redaction_policy_version)
    )
    payload_sha256 = hashlib.sha256(serialized_payload.encode("utf-8")).hexdigest()
    manifest = TenantExportManifest(
        artifact_id=artifact_id,
        payload_sha256=payload_sha256,
        entry_count=int(entry_count),
        record_classes=tuple(normalized_classes),
        redaction_policy_version=redaction_policy_version,
        redaction_policy_digest=policy_digest,
        consent_policy_revision=consent_policy_revision,
        consent_state=consent_state,
        tenant_tag=tenant_tag,
        excluded_sensitive_classes=EXCLUDED_SENSITIVE_CLASSES,
        manifest_version=TENANT_EXPORT_MANIFEST_VERSION,
    )
    manifest.manifest_digest = compute_manifest_digest(manifest)
    return manifest


def verify_tenant_export_manifest(
    manifest: TenantExportManifest,
    serialized_payload: str,
    *,
    expected_redaction_policy_digest: Optional[str] = None,
    expected_tenant_tag: Optional[str] = None,
) -> Tuple[bool, List[str]]:
    """Fail-closed verification of a TenantExportManifest against its serialized payload."""
    errors: List[str] = []
    if not isinstance(manifest, TenantExportManifest):
        return False, ["invalid_manifest_type"]

    if manifest.manifest_version != TENANT_EXPORT_MANIFEST_VERSION:
        errors.append(f"unsupported_manifest_version:{manifest.manifest_version}")

    digest_val = manifest.manifest_digest or ""
    if not digest_val.startswith(MANIFEST_DIGEST_PREFIX) or not _HEX64_RE.match(
        digest_val[len(MANIFEST_DIGEST_PREFIX):]
    ):
        errors.append("malformed_manifest_digest")
    else:
        expected_digest = compute_manifest_digest(manifest)
        if not hmac.compare_digest(digest_val, expected_digest):
            errors.append("manifest_digest_mismatch")

    actual_payload_sha256 = hashlib.sha256(serialized_payload.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(manifest.payload_sha256 or "", actual_payload_sha256):
        errors.append("payload_sha256_mismatch")

    rc_list = list(manifest.record_classes)
    if rc_list != sorted(set(rc_list)):
        errors.append("record_classes_not_canonical")
    for rc in rc_list:
        if is_sensitive_record_class(rc):
            errors.append(f"sensitive_record_class_present:{rc}")

    if not set(EXCLUDED_SENSITIVE_CLASSES).issubset(set(manifest.excluded_sensitive_classes)):
        errors.append("missing_required_excluded_sensitive_classes")

    if expected_redaction_policy_digest is not None:
        if not hmac.compare_digest(
            manifest.redaction_policy_digest or "", expected_redaction_policy_digest
        ):
            errors.append("redaction_policy_digest_mismatch")

    if expected_tenant_tag is not None:
        if not hmac.compare_digest(manifest.tenant_tag or "", expected_tenant_tag):
            errors.append("tenant_tag_mismatch")

    # Inspect uncompressed JSON payloads for leaked sensitive keys or credential markers.
    try:
        parsed = json.loads(serialized_payload)
    except Exception:
        parsed = None
    if isinstance(parsed, list):
        if len(parsed) != manifest.entry_count:
            errors.append("entry_count_mismatch")
        for item in parsed:
            if not isinstance(item, dict):
                continue
            labels = item.get("labels")
            if isinstance(labels, dict):
                for k, v in labels.items():
                    if is_sensitive_record_class(str(k)):
                        errors.append(f"payload_contains_sensitive_key:{k}")
                    if _value_contains_credential_pattern(v):
                        errors.append(f"payload_contains_credential:{k}")
            if _value_contains_credential_pattern(item.get("message_summary")):
                errors.append("payload_contains_credential:message_summary")

    return (len(errors) == 0, errors)


def resolve_consent_state(entries: List[LogEntry]) -> Tuple[Optional[str], str]:
    """Derive the consent policy revision and state for a set of entries.

    Each entry may carry a ``consent_policy_revision`` recording the policy
    effective at collection time and a ``consent_withdrawn`` flag. Entries with
    no recorded revision are treated as never collected.
    """
    revisions = set()
    withdrawn = False
    granted = False
    for e in entries:
        rev = getattr(e, "consent_policy_revision", None)
        if rev is None:
            continue
        revisions.add(rev)
        if getattr(e, "consent_withdrawn", False):
            withdrawn = True
        else:
            granted = True
    if not revisions:
        return None, CONSENT_STATE_NEVER_COLLECTED
    revision = sorted(revisions)[-1] if len(revisions) == 1 else ",".join(sorted(revisions))
    if withdrawn and not granted:
        return revision, CONSENT_STATE_WITHDRAWN
    if granted:
        return revision, CONSENT_STATE_GRANTED
    return revision, CONSENT_STATE_WITHDRAWN


def sanitize_display_label(label: Optional[str]) -> Optional[str]:
    """Return a bounded, printable display label. Never used for filesystem paths."""
    if label is None:
        return None
    cleaned = "".join(ch for ch in str(label) if ch.isprintable())
    return cleaned[:128]


class ExportManager:
    def __init__(
        self,
        policy: Optional[ExportPolicy] = None,
        processor: Optional[LogProcessor] = None,
        max_artifacts_memory: int = 1024,
    ) -> None:
        self._lock: threading.RLock = threading.RLock()
        self._artifacts: Dict[str, ExportArtifact] = {}
        self._artifact_queue: List[str] = []
        self._policy: ExportPolicy = policy if policy is not None else EXPORT_POLICY_DEFAULT
        if processor is not None:
            self._processor: LogProcessor = processor
        elif LogProcessor is not None:
            self._processor = LogProcessor()
        else:
            self._processor = None
        self._max_artifacts_memory: int = max_artifacts_memory

    def generate_export_id(self) -> str:
        random_bytes = os.urandom(32)
        timestamp = str(time.time()).encode("utf-8")
        raw = random_bytes + timestamp
        digest = hashlib.sha256(raw).hexdigest()[:16]
        return self._policy.export_id_prefix + digest

    def generate_server_file_name(self, artifact_id: str, compress: bool) -> str:
        """Build a filesystem name solely from server-generated identifiers."""
        token = _SAFE_LABEL_RE.sub("", artifact_id.replace(":", "-"))
        suffix = ".json.gz" if compress else ".json"
        return token + suffix

    def compute_safety_signature(self, entries: List[LogEntry]) -> str:
        sorted_entries = sorted(entries, key=lambda x: x.entry_id)
        parts = []
        for e in sorted_entries:
            sig = e.export_signature or "0"
            parts.append(e.entry_id + ":" + sig)
        payload = "|".join(parts)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
        return self._policy.safety_signature_prefix + digest

    def create_export(
        self,
        entries: Optional[List[LogEntry]] = None,
        exported_by_tag: Optional[str] = None,
        compress: Optional[bool] = None,
        rollout_phase: str = "shadow",
        export_token_verified: bool = False,
        display_label: Optional[str] = None,
    ) -> Tuple[Optional[ExportArtifact], str, int]:
        with self._lock:
            policy = self._policy
            if not export_token_verified and policy.require_export_token and not policy.allow_unauthenticated_export_shadow_mode:
                return None, "export_token_required", 0
            if entries is not None:
                entries_filtered = list(entries)
            elif self._processor is not None:
                entries_filtered = list(self._processor._entries[:])
            else:
                entries_filtered = []
            if not policy.include_sampled_out_events:
                entries_filtered = [e for e in entries_filtered if e.export_safe]
            if validate_log_export_safety is not None:
                entries_filtered = [e for e in entries_filtered if validate_log_export_safety(e)[0]]
            entries_filtered, _ = filter_entries_for_tenant_export(entries_filtered)
            if policy.require_safety_signature:
                all_safe = all(e.export_safe for e in entries_filtered)
                if not all_safe:
                    safety_sig = None
                else:
                    safety_sig = self.compute_safety_signature(entries_filtered)
            else:
                safety_sig = None
            consent_revision, consent_state = resolve_consent_state(entries_filtered)
            if not export_token_verified:
                entries_filtered = []
            entries_filtered = entries_filtered[:policy.max_artifacts_per_export]
            use_compress = compress if compress is not None else policy.compress_default
            if self._processor is not None:
                serialized, count = self._processor.export_json_logs(
                    entries=entries_filtered,
                    compress=use_compress,
                    max_entries=policy.max_artifacts_per_export,
                    max_bytes=policy.max_artifact_bytes,
                )
            else:
                serialized = "[]"
                count = 0
            payload_bytes = len(serialized.encode("utf-8"))
            checksum = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]
            artifact_id = self.generate_export_id()
            exported_entries = entries_filtered[:count]
            record_classes = [classify_record_class(e) for e in exported_entries]
            redaction_version = "harpocrates-redaction-v1"
            manifest = build_tenant_export_manifest(
                artifact_id=artifact_id,
                serialized_payload=serialized,
                entry_count=count,
                record_classes=record_classes,
                redaction_policy_version=redaction_version,
                consent_policy_revision=consent_revision,
                consent_state=consent_state,
                tenant_tag=exported_by_tag if export_token_verified else None,
            )
            artifact = ExportArtifact(
                artifact_id=artifact_id,
                generated_at_epoch_seconds=time.time(),
                entry_count=count,
                payload_bytes=payload_bytes,
                compress=use_compress,
                exported_by_tag=exported_by_tag if export_token_verified else None,
                safety_signature=safety_sig,
                checksum_sha256_prefix16=checksum,
                rollout_phase=rollout_phase,
                redaction_version=redaction_version,
                encryption_at_rest=False,
                consent_policy_revision=consent_revision,
                consent_state=consent_state,
                server_file_name=self.generate_server_file_name(artifact_id, use_compress),
                display_label=sanitize_display_label(display_label) if export_token_verified else None,
                manifest=manifest,
            )
            if len(self._artifacts) >= self._max_artifacts_memory:
                if self._artifact_queue:
                    oldest_id = self._artifact_queue.pop(0)
                    self._artifacts.pop(oldest_id, None)
            self._artifacts[artifact_id] = artifact
            self._artifact_queue.append(artifact_id)
            return artifact, serialized, count

    def verify_artifact_manifest(
        self,
        artifact_id: str,
        serialized_payload: str,
        *,
        expected_redaction_policy_digest: Optional[str] = None,
        expected_tenant_tag: Optional[str] = None,
    ) -> Tuple[bool, List[str]]:
        """Fail-closed verification of a stored artifact's tenant export manifest."""
        with self._lock:
            artifact = self._artifacts.get(artifact_id)
        if artifact is None:
            return False, ["artifact_not_found"]
        if artifact.manifest is None:
            return False, ["manifest_missing"]
        return verify_tenant_export_manifest(
            artifact.manifest,
            serialized_payload,
            expected_redaction_policy_digest=expected_redaction_policy_digest,
            expected_tenant_tag=expected_tenant_tag,
        )

    def get_artifact(self, artifact_id: str) -> Optional[ExportArtifact]:
        with self._lock:
            return self._artifacts.get(artifact_id)

    def list_artifacts(self, limit: int = 50) -> List[ExportArtifact]:
        with self._lock:
            result: List[ExportArtifact] = []
            for aid in reversed(self._artifact_queue):
                if len(result) >= limit:
                    break
                art = self._artifacts.get(aid)
                if art is not None:
                    result.append(art)
            return result

    def delete_artifact(self, artifact_id: str) -> bool:
        with self._lock:
            if artifact_id in self._artifacts:
                self._artifacts.pop(artifact_id, None)
                self._artifact_queue = [aid for aid in self._artifact_queue if aid != artifact_id]
                return True
            return False

    def reset(self) -> None:
        with self._lock:
            self._artifacts.clear()
            self._artifact_queue.clear()