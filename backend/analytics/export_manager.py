from __future__ import annotations

import hashlib
import hmac
import os
import re
import threading
import time
from dataclasses import dataclass
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
    from analytics.consent import ConsentManager
except Exception:
    try:
        from backend.analytics.consent import ConsentManager
    except Exception:
        ConsentManager = None  # type: ignore[assignment]


EXPORT_FORMAT_VERSION = "1.0.0"
DELETION_PREVIEW_SCHEMA_VERSION = "1.0.0"
DELETION_PREVIEW_TENANT_DOMAIN_TAG = "harpocrates:deletion-preview-tenant:v1"
DEFAULT_PREVIEW_BUCKET_CAP = 100
DEFAULT_LOG_RETENTION_TTL_SECONDS = 86_400.0
DEFAULT_ARTIFACT_RETENTION_TTL_SECONDS = 86_400.0

_TENANT_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class AnalyticsDataClass:
    CONSENT_RECORDS = "consent_records"
    OPERATIONAL_LOGS = "operational_logs"
    EXPORT_ARTIFACTS = "export_artifacts"


class TenantIsolationError(PermissionError):
    """Raised when a deletion preview violates tenant authorization or isolation rules."""


def _validate_authorized_tenant_tag(
    authorized_tenant_tag: Optional[str],
    requested_tenant_tag: Optional[str] = None,
) -> str:
    if not isinstance(authorized_tenant_tag, str) or not _TENANT_TAG_RE.match(authorized_tenant_tag):
        raise TenantIsolationError("a valid non-wildcard authorized_tenant_tag is required")
    if requested_tenant_tag is not None:
        if not isinstance(requested_tenant_tag, str) or not _TENANT_TAG_RE.match(requested_tenant_tag):
            raise TenantIsolationError("invalid requested_tenant_tag")
        if not hmac.compare_digest(
            authorized_tenant_tag.encode("utf-8"),
            requested_tenant_tag.encode("utf-8"),
        ):
            raise TenantIsolationError("cross-tenant deletion preview is forbidden")
    return authorized_tenant_tag


def _hash_tenant_tag(tenant_tag: str) -> str:
    framed = f"{DELETION_PREVIEW_TENANT_DOMAIN_TAG}:{len(tenant_tag)}:{tenant_tag}".encode("utf-8")
    return hashlib.sha256(framed).hexdigest()


def _cap_count(raw_count: int, max_cap: int) -> Tuple[int, bool]:
    if raw_count > max_cap:
        return max_cap, True
    return raw_count, False


@dataclass(frozen=True)
class DeletionPreviewBucket:
    data_class: str
    retention_policy: str
    bounded_count: int
    capped: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "data_class": self.data_class,
            "retention_policy": self.retention_policy,
            "bounded_count": self.bounded_count,
            "capped": self.capped,
        }


@dataclass(frozen=True)
class DeletionPreviewReport:
    schema_version: str
    tenant_tag_digest: str
    generated_at_epoch_seconds: float
    max_count_per_bucket: int
    buckets: List[DeletionPreviewBucket]
    by_data_class: Dict[str, Dict[str, Any]]
    by_retention_policy: Dict[str, Dict[str, Any]]
    total_bounded_count: int
    total_capped: bool
    read_only: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tenant_tag_digest": self.tenant_tag_digest,
            "generated_at_epoch_seconds": self.generated_at_epoch_seconds,
            "max_count_per_bucket": self.max_count_per_bucket,
            "read_only": self.read_only,
            "total_bounded_count": self.total_bounded_count,
            "total_capped": self.total_capped,
            "by_data_class": {k: dict(v) for k, v in self.by_data_class.items()},
            "by_retention_policy": {k: dict(v) for k, v in self.by_retention_policy.items()},
            "buckets": [b.to_dict() for b in self.buckets],
        }


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
    preview_bucket_cap: int = DEFAULT_PREVIEW_BUCKET_CAP
    log_retention_ttl_seconds: float = DEFAULT_LOG_RETENTION_TTL_SECONDS
    artifact_retention_ttl_seconds: float = DEFAULT_ARTIFACT_RETENTION_TTL_SECONDS


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


class ExportManager:
    def __init__(
        self,
        policy: Optional[ExportPolicy] = None,
        processor: Optional[LogProcessor] = None,
        max_artifacts_memory: int = 1024,
        *,
        consent_manager: Optional[ConsentManager] = None,
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
        self._consent_manager: Optional[ConsentManager] = consent_manager

    def preview_tenant_deletion(
        self,
        authorized_tenant_tag: str,
        *,
        requested_tenant_tag: Optional[str] = None,
        export_token_verified: bool = True,
        now_epoch_seconds: Optional[float] = None,
        max_count_per_bucket: Optional[int] = None,
    ) -> DeletionPreviewReport:
        """Compute a read-only, tenant-isolated deletion preview with bounded counts."""
        if not export_token_verified:
            raise TenantIsolationError("verified authorization is required for deletion preview")

        tenant_tag = _validate_authorized_tenant_tag(authorized_tenant_tag, requested_tenant_tag)

        bucket_cap = (
            max_count_per_bucket
            if max_count_per_bucket is not None
            else self._policy.preview_bucket_cap
        )
        if isinstance(bucket_cap, bool) or not isinstance(bucket_cap, int) or bucket_cap <= 0 or bucket_cap > 10_000:
            raise ValueError("max_count_per_bucket must be an integer between 1 and 10000")

        now = float(now_epoch_seconds) if now_epoch_seconds is not None else time.time()
        pair_counts: Dict[Tuple[str, str], int] = {}
        tenant_withdrawn = False

        # 1. Consent records strictly for authorized_tenant_tag
        if self._consent_manager is not None:
            consent_policy, tenant_withdrawn = self._consent_manager.classify_tenant_consent_retention(
                tenant_tag,
                now_epoch_seconds=now,
            )
            if consent_policy is not None:
                key = (AnalyticsDataClass.CONSENT_RECORDS, consent_policy)
                pair_counts[key] = pair_counts.get(key, 0) + 1

        # 2. Operational log entries strictly matching entry.account_id_tag == tenant_tag
        log_ttl = float(self._policy.log_retention_ttl_seconds)
        if self._processor is not None:
            with self._processor._lock:
                for entry in self._processor._entries:
                    if entry.account_id_tag is None:
                        continue
                    if not hmac.compare_digest(
                        entry.account_id_tag.encode("utf-8"),
                        tenant_tag.encode("utf-8"),
                    ):
                        continue
                    if tenant_withdrawn:
                        policy_name = "withdrawn_immediate_purge"
                    elif (now - entry.timestamp_epoch_seconds) > log_ttl:
                        policy_name = "expired_log_ttl"
                    else:
                        policy_name = "active_log_ttl"
                    key = (AnalyticsDataClass.OPERATIONAL_LOGS, policy_name)
                    pair_counts[key] = pair_counts.get(key, 0) + 1

        # 3. Export artifacts strictly matching artifact.exported_by_tag == tenant_tag
        art_ttl = float(self._policy.artifact_retention_ttl_seconds)
        with self._lock:
            for art in self._artifacts.values():
                if art.exported_by_tag is None:
                    continue
                if not hmac.compare_digest(
                    art.exported_by_tag.encode("utf-8"),
                    tenant_tag.encode("utf-8"),
                ):
                    continue
                if tenant_withdrawn:
                    policy_name = "withdrawn_immediate_purge"
                elif (now - art.generated_at_epoch_seconds) > art_ttl:
                    policy_name = "expired_artifact_ttl"
                else:
                    policy_name = "active_artifact_ttl"
                key = (AnalyticsDataClass.EXPORT_ARTIFACTS, policy_name)
                pair_counts[key] = pair_counts.get(key, 0) + 1

        buckets: List[DeletionPreviewBucket] = []
        raw_by_class: Dict[str, int] = {
            AnalyticsDataClass.CONSENT_RECORDS: 0,
            AnalyticsDataClass.OPERATIONAL_LOGS: 0,
            AnalyticsDataClass.EXPORT_ARTIFACTS: 0,
        }
        raw_by_policy: Dict[str, int] = {}
        raw_total = 0

        for (data_class, ret_policy), raw_cnt in sorted(pair_counts.items()):
            bounded, is_capped = _cap_count(raw_cnt, bucket_cap)
            buckets.append(
                DeletionPreviewBucket(
                    data_class=data_class,
                    retention_policy=ret_policy,
                    bounded_count=bounded,
                    capped=is_capped,
                )
            )
            raw_by_class[data_class] = raw_by_class.get(data_class, 0) + raw_cnt
            raw_by_policy[ret_policy] = raw_by_policy.get(ret_policy, 0) + raw_cnt
            raw_total += raw_cnt

        by_data_class: Dict[str, Dict[str, Any]] = {}
        for d_class in sorted(raw_by_class.keys()):
            b_cnt, b_cap = _cap_count(raw_by_class[d_class], bucket_cap)
            by_data_class[d_class] = {"bounded_count": b_cnt, "capped": b_cap}

        by_retention_policy: Dict[str, Dict[str, Any]] = {}
        for r_pol in sorted(raw_by_policy.keys()):
            b_cnt, b_cap = _cap_count(raw_by_policy[r_pol], bucket_cap)
            by_retention_policy[r_pol] = {"bounded_count": b_cnt, "capped": b_cap}

        total_cap_limit = bucket_cap * 3
        total_bounded, total_capped = _cap_count(raw_total, total_cap_limit)

        return DeletionPreviewReport(
            schema_version=DELETION_PREVIEW_SCHEMA_VERSION,
            tenant_tag_digest=_hash_tenant_tag(tenant_tag),
            generated_at_epoch_seconds=now,
            max_count_per_bucket=bucket_cap,
            buckets=buckets,
            by_data_class=by_data_class,
            by_retention_policy=by_retention_policy,
            total_bounded_count=total_bounded,
            total_capped=total_capped,
            read_only=True,
        )

    def generate_export_id(self) -> str:
        random_bytes = os.urandom(32)
        timestamp = str(time.time()).encode("utf-8")
        raw = random_bytes + timestamp
        digest = hashlib.sha256(raw).hexdigest()[:16]
        return self._policy.export_id_prefix + digest

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
            payload_bytes = len(serialized.encode("utf-8"))
            checksum = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]
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
            )
            if len(self._artifacts) >= self._max_artifacts_memory:
                if self._artifact_queue:
                    oldest_id = self._artifact_queue.pop(0)
                    self._artifacts.pop(oldest_id, None)
            self._artifacts[artifact_id] = artifact
            self._artifact_queue.append(artifact_id)
            return artifact, serialized, count

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
