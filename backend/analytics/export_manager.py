from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

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
DELETION_PREVIEW_SCHEMA_VERSION = "1.0.0"
EXPORT_RECEIPT_VERSION = "receipt-v1"
EXPORT_POLICY_REVISION_PREFIX = "pol-v1:"

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
        """Create an export of ``entries`` (or the processor's buffer).

        ``requested_max_entries`` is the limit the requester asked for, if
        any; it is only recorded in the completion receipt's scope.
        """
        with self._lock:
            policy = self._policy
            if not export_token_verified and policy.require_export_token and not policy.allow_unauthenticated_export_shadow_mode:
                return None, "export_token_required", 0
            if entries is not None:
                entries_filtered = list(entries)
                entry_source = "explicit"
            elif self._processor is not None:
                entries_filtered = list(self._processor._entries[:])
                entry_source = "processor"
            else:
                entries_filtered = []
                entry_source = "none"
            candidate_count = len(entries_filtered)
            if not policy.include_sampled_out_events:
                entries_filtered = [e for e in entries_filtered if e.export_safe]
            if validate_log_export_safety is not None:
                entries_filtered = [e for e in entries_filtered if validate_log_export_safety(e)[0]]
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
            exported_entries = sorted(
                entries_filtered,
                key=lambda entry: entry.timestamp_epoch_seconds,
            )[:count]
            consent_revision, consent_state = resolve_consent_state(exported_entries)
            payload_bytes = len(serialized.encode("utf-8"))
            output_digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            checksum = output_digest[:16]
            artifact_id = self.generate_export_id()
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
                encryption_at_rest=False,
                consent_policy_revision=consent_revision,
                consent_state=consent_state,
                server_file_name=self.generate_server_file_name(artifact_id, use_compress),
                display_label=sanitize_display_label(display_label) if export_token_verified else None,
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

    @staticmethod
    def _build_receipt(
        artifact: ExportArtifact,
        *,
        policy: ExportPolicy,
        entry_source: str,
        candidate_count: int,
        export_token_verified: bool,
        requested_max_entries: int | None,
        output_digest: str,
    ) -> dict[str, Any]:
        """Completion receipt for ``artifact``: built from settings, counts and
        digests only, so no entry field (ids, messages, labels, account or
        session tags) can reach it."""
        return {
            "receipt_version": EXPORT_RECEIPT_VERSION,
            "artifact_id": artifact.artifact_id,
            "completed_at_epoch_seconds": artifact.generated_at_epoch_seconds,
            "scope": {
                "entry_source": entry_source,
                "requested_max_entries": (
                    requested_max_entries
                    if isinstance(requested_max_entries, int) and not isinstance(requested_max_entries, bool)
                    else None
                ),
                "candidate_count": candidate_count if export_token_verified else None,
                "exported_count": artifact.entry_count,
                "max_entries": policy.max_artifacts_per_export,
                "max_bytes": policy.max_artifact_bytes,
                "include_sampled_out_events": policy.include_sampled_out_events,
                "export_token_verified": bool(export_token_verified),
                "compress": artifact.compress,
                "rollout_phase": artifact.rollout_phase,
            },
            "policy_revision": export_policy_revision(policy),
            "consent_policy_revision": (
                artifact.consent_policy_revision if export_token_verified else None
            ),
            "consent_schema_version": CONSENT_SCHEMA_VERSION,
            "redaction_version": artifact.redaction_version,
            "format_version": artifact.schema_version,
            "output_digest": "sha256:" + output_digest,
            "payload_bytes": artifact.payload_bytes,
        }

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
