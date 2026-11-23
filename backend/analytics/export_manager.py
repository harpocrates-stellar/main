from __future__ import annotations

import dataclasses
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

try:
    from analytics.consent import CONSENT_SCHEMA_VERSION
except ImportError:
    try:
        from backend.analytics.consent import CONSENT_SCHEMA_VERSION
    except ImportError:
        CONSENT_SCHEMA_VERSION = None


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
_SAFE_CLASS_RE = re.compile(r"[^a-z0-9_.-]")


class TenantAuthorizationError(PermissionError):
    """Raised when a deletion preview request fails tenant isolation checks."""


@dataclass
class DeletionPreviewPolicy:
    """Bounds and retention thresholds governing privacy-preserving deletion previews."""

    count_cap_per_bucket: int = 1000
    max_buckets: int = 64
    export_artifact_retention_seconds: float = 30.0 * 86400.0
    log_entry_retention_seconds: float = 30.0 * 86400.0
    withdrawn_retention_seconds: float = 0.0
    data_class_retention_seconds: Dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.count_cap_per_bucket < 1:
            raise ValueError("count_cap_per_bucket must be >= 1")
        if self.max_buckets < 1:
            raise ValueError("max_buckets must be >= 1")
        if self.export_artifact_retention_seconds < 0:
            raise ValueError("export_artifact_retention_seconds must be >= 0")
        if self.log_entry_retention_seconds < 0:
            raise ValueError("log_entry_retention_seconds must be >= 0")
        if self.withdrawn_retention_seconds < 0:
            raise ValueError("withdrawn_retention_seconds must be >= 0")


DELETION_PREVIEW_POLICY_DEFAULT: DeletionPreviewPolicy = DeletionPreviewPolicy()


@dataclass
class DeletionPreviewBucket:
    """Bounded deletion counts for one (data_class, retention_policy) pair."""

    data_class: str
    retention_policy: str
    eligible_count: int
    retained_count: int
    eligible_capped: bool = False
    retained_capped: bool = False


@dataclass
class DeletionPreviewResult:
    """Privacy-preserving, tenant-isolated, non-destructive deletion preview."""

    schema_version: str = DELETION_PREVIEW_SCHEMA_VERSION
    tenant_scope_digest: str = ""
    generated_at_epoch_seconds: float = 0.0
    count_cap_per_bucket: int = 1000
    buckets: List[DeletionPreviewBucket] = field(default_factory=list)
    buckets_truncated: bool = False
    total_eligible_bounded: int = 0
    total_retained_bounded: int = 0
    any_count_capped: bool = False
    dry_run: bool = True


def _authorize_tenant_scope(
    authorized_tenant: Optional[str],
    requested_tenant: Optional[str],
) -> str:
    """Fail-closed check ensuring the requested tenant matches the authorized tenant."""
    if not isinstance(authorized_tenant, str) or not authorized_tenant.strip():
        raise TenantAuthorizationError("authorized_tenant_required")
    if not isinstance(requested_tenant, str) or not requested_tenant.strip():
        raise TenantAuthorizationError("requested_tenant_required")
    auth_clean = authorized_tenant.strip()
    req_clean = requested_tenant.strip()
    if not hmac.compare_digest(auth_clean, req_clean):
        raise TenantAuthorizationError("tenant_scope_mismatch")
    return auth_clean


def _tenant_scope_digest(tenant: str) -> str:
    return "tdg-v1:" + hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:16]


def _sanitize_data_class(raw: Optional[str], default: str = "analytics_logs") -> str:
    if not isinstance(raw, str) or not raw.strip():
        return default
    cleaned = _SAFE_CLASS_RE.sub("_", raw.strip().lower())[:64].strip("_")
    return cleaned or default


def _entry_belongs_to_tenant(entry: Any, tenant: str) -> bool:
    """Return True only when an entry explicitly belongs to ``tenant``."""
    candidate: Optional[str] = None
    for attr in ("account_tag", "tenant_id"):
        val = getattr(entry, attr, None)
        if isinstance(val, str) and val.strip():
            candidate = val.strip()
            break
    if candidate is None:
        labels = getattr(entry, "labels", None)
        if isinstance(labels, dict):
            for key in ("tenant_id", "account_tag"):
                val = labels.get(key)
                if isinstance(val, str) and val.strip():
                    candidate = val.strip()
                    break
    if candidate is None:
        annotations = getattr(entry, "annotations", None)
        if isinstance(annotations, dict):
            for key in ("account_tag", "tenant_id"):
                val = annotations.get(key)
                if isinstance(val, str) and val.strip():
                    candidate = val.strip()
                    break
    if candidate is None:
        return False
    return hmac.compare_digest(candidate, tenant)


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
    validate_dimensions: bool = True


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

    # Completion receipt (see docs/analytics-export-receipts.md). Metadata only:
    # scope, policy revision, counts and the output digest, never entries.
    receipt: dict[str, Any] | None = None


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


def export_policy_revision(policy: ExportPolicy) -> str:
    """Stable identifier of the export policy settings in force.

    Any change to a policy field changes the revision; equal settings always
    give the same revision. Policies that are not dataclasses (duck-typed
    policy objects are accepted by ``ExportManager``) use their attributes.
    """
    if dataclasses.is_dataclass(policy) and not isinstance(policy, type):
        settings = dataclasses.asdict(policy)
    else:
        settings = {k: v for k, v in vars(policy).items() if not k.startswith("_")}
    canonical = json.dumps(settings, sort_keys=True, separators=(",", ":"), default=str)
    return EXPORT_POLICY_REVISION_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


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
        requested_max_entries: int | None = None,
    ) -> Tuple[Optional[ExportArtifact], str, int]:
        """Create an export artifact from the given or stored log entries.

        Returns a ``(artifact, payload_or_status, count)`` tuple. On success
        ``artifact`` is the :class:`ExportArtifact` and the second element is the
        serialized JSON payload. On failure ``artifact`` is ``None`` and the
        second element is a distinct machine-readable status string:

        - ``"export_token_required"`` - an export token is required but was not
          provided and shadow mode is disabled.
        - ``"analytics_store_unavailable"`` - the analytics store is unavailable
          (its processor is missing or raised while serializing). This status is
          returned instead of a successful zero-record export after a backend
          outage, so an outage can be told apart from a genuinely empty store.
        """
        with self._lock:
            policy = self._policy
            if not export_token_verified and policy.require_export_token and not policy.allow_unauthenticated_export_shadow_mode:
                return None, "export_token_required", 0
            if self._processor is None:
                return None, "analytics_store_unavailable", 0
            if entries is not None:
                entries_filtered = list(entries)
            else:
                entries_filtered = list(self._processor._entries[:])
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
            if not export_token_verified:
                entries_filtered = []
            entries_filtered = entries_filtered[:policy.max_artifacts_per_export]
            use_compress = compress if compress is not None else policy.compress_default
            try:
                serialized, count = self._processor.export_json_logs(
                    entries=entries_filtered,
                    compress=use_compress,
                    max_entries=policy.max_artifacts_per_export,
                    max_bytes=policy.max_artifact_bytes,
                )
            except Exception:
                return None, "analytics_store_unavailable", 0
            payload_bytes = len(serialized.encode("utf-8"))
            output_digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            checksum = output_digest[:16]
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
            artifact.receipt = self._build_receipt(
                artifact,
                policy=policy,
                entry_source=entry_source,
                candidate_count=candidate_count,
                export_token_verified=export_token_verified,
                requested_max_entries=requested_max_entries,
                output_digest=output_digest,
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

    def preview_deletion(
        self,
        authorized_tenant: Optional[str],
        requested_tenant: Optional[str],
        consent_manager: Optional[Any] = None,
        entries: Optional[List[LogEntry]] = None,
        now_epoch_seconds: Optional[float] = None,
        preview_policy: Optional[DeletionPreviewPolicy] = None,
    ) -> DeletionPreviewResult:
        """Compute a privacy-preserving, tenant-isolated deletion preview.

        Returns bounded counts grouped by ``(data_class, retention_policy)``
        without mutating consent state, export artifacts, or log entries, and
        without exposing raw identifiers, payloads, or cross-tenant data.
        """
        tenant = _authorize_tenant_scope(authorized_tenant, requested_tenant)
        policy = preview_policy if preview_policy is not None else DELETION_PREVIEW_POLICY_DEFAULT
        now = now_epoch_seconds if now_epoch_seconds is not None else time.time()

        # Raw tallies: (data_class, retention_policy) -> [eligible, retained]
        tallies: Dict[Tuple[str, str], List[int]] = {}

        def _record(data_class: str, retention_policy: str, eligible: bool) -> None:
            key = (data_class, retention_policy)
            pair = tallies.get(key)
            if pair is None:
                pair = [0, 0]
                tallies[key] = pair
            if eligible:
                pair[0] += 1
            else:
                pair[1] += 1

        # 1. Consent records (strictly single-tenant lookup).
        if consent_manager is not None and hasattr(consent_manager, "preview_tenant_consent_deletion"):
            summary = consent_manager.preview_tenant_consent_deletion(
                tenant, now_epoch_seconds=now
            )
            if isinstance(summary, dict):
                _record(
                    _sanitize_data_class(str(summary.get("data_class", "consent_records")), "consent_records"),
                    _sanitize_data_class(str(summary.get("retention_policy", "active_consent")), "active_consent"),
                    bool(summary.get("eligible", False)),
                )

        # 2. Export artifacts belonging strictly to this tenant.
        with self._lock:
            artifacts_snapshot = list(self._artifacts.values())
            if entries is not None:
                entries_snapshot = list(entries)
            elif self._processor is not None:
                entries_snapshot = list(self._processor._entries[:])
            else:
                entries_snapshot = []

        artifact_window = policy.data_class_retention_seconds.get(
            "export_artifacts", policy.export_artifact_retention_seconds
        )
        for art in artifacts_snapshot:
            owner = getattr(art, "exported_by_tag", None)
            if not isinstance(owner, str) or not owner.strip():
                continue
            if not hmac.compare_digest(owner.strip(), tenant):
                continue
            age = max(0.0, now - float(getattr(art, "generated_at_epoch_seconds", 0.0)))
            if getattr(art, "consent_state", None) == CONSENT_STATE_WITHDRAWN:
                eligible = age >= policy.withdrawn_retention_seconds
                _record("export_artifacts", "consent_withdrawn", eligible)
            elif age >= artifact_window:
                _record("export_artifacts", "retention_expired", True)
            else:
                _record("export_artifacts", "within_retention", False)

        # 3. Analytics log entries belonging strictly to this tenant.
        for entry in entries_snapshot:
            if not _entry_belongs_to_tenant(entry, tenant):
                continue
            labels = getattr(entry, "labels", None)
            raw_class = getattr(entry, "data_class", None)
            if not raw_class and isinstance(labels, dict):
                raw_class = labels.get("category")
            data_class = _sanitize_data_class(raw_class, "analytics_logs")
            entry_window = policy.data_class_retention_seconds.get(
                data_class, policy.log_entry_retention_seconds
            )
            ts = float(getattr(entry, "timestamp_epoch_seconds", 0.0))
            age = max(0.0, now - ts)
            if getattr(entry, "consent_withdrawn", False):
                eligible = age >= policy.withdrawn_retention_seconds
                _record(data_class, "consent_withdrawn", eligible)
            elif age >= entry_window:
                _record(data_class, "retention_expired", True)
            else:
                _record(data_class, "within_retention", False)

        # Build deterministically sorted, bounded buckets.
        sorted_keys = sorted(tallies.keys())
        buckets_truncated = len(sorted_keys) > policy.max_buckets
        cap = policy.count_cap_per_bucket
        buckets: List[DeletionPreviewBucket] = []
        total_eligible = 0
        total_retained = 0
        any_capped = False

        for data_class, retention_policy in sorted_keys[: policy.max_buckets]:
            raw_elig, raw_ret = tallies[(data_class, retention_policy)]
            elig_capped = raw_elig > cap
            ret_capped = raw_ret > cap
            elig_bounded = min(raw_elig, cap)
            ret_bounded = min(raw_ret, cap)
            if elig_capped or ret_capped:
                any_capped = True
            total_eligible += elig_bounded
            total_retained += ret_bounded
            buckets.append(
                DeletionPreviewBucket(
                    data_class=data_class,
                    retention_policy=retention_policy,
                    eligible_count=elig_bounded,
                    retained_count=ret_bounded,
                    eligible_capped=elig_capped,
                    retained_capped=ret_capped,
                )
            )

        return DeletionPreviewResult(
            schema_version=DELETION_PREVIEW_SCHEMA_VERSION,
            tenant_scope_digest=_tenant_scope_digest(tenant),
            generated_at_epoch_seconds=now,
            count_cap_per_bucket=cap,
            buckets=buckets,
            buckets_truncated=buckets_truncated,
            total_eligible_bounded=total_eligible,
            total_retained_bounded=total_retained,
            any_count_capped=any_capped,
            dry_run=True,
        )

    def reset(self) -> None:
        with self._lock:
            self._artifacts.clear()
            self._artifact_queue.clear()
