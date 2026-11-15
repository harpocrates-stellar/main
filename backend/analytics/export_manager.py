from __future__ import annotations

import hashlib
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

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
    from analytics.consent import ConsentManager, ConsentStoreUnavailableError
except Exception:
    try:
        from backend.analytics.consent import ConsentManager, ConsentStoreUnavailableError
    except Exception:
        ConsentManager = None  # type: ignore[assignment]
        ConsentStoreUnavailableError = RuntimeError  # type: ignore[assignment,misc]


EXPORT_FORMAT_VERSION = "1.0.0"
_UNSET_PROCESSOR = object()


class AnalyticsStoreUnavailableError(RuntimeError):
    """Raised when the analytics log or consent store is unavailable."""


class ExportStatus:
    COMPLETED = "completed"
    EMPTY = "empty"
    STORE_UNAVAILABLE = "store_unavailable"
    EXPORT_TOKEN_REQUIRED = "export_token_required"


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
    export_status: str = ExportStatus.COMPLETED


@dataclass(frozen=True)
class ExportOutcome:
    """Structured result separating empty exports from unavailable analytics stores."""

    status: str
    artifact: Optional[ExportArtifact]
    serialized: Optional[str]
    entry_count: int
    retryable: bool

    @property
    def ok(self) -> bool:
        return self.status in {ExportStatus.COMPLETED, ExportStatus.EMPTY}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "ok": self.ok,
            "entry_count": self.entry_count,
            "retryable": self.retryable,
            "artifact_id": self.artifact.artifact_id if self.artifact is not None else None,
        }


class ExportManager:
    def __init__(
        self,
        policy: Optional[ExportPolicy] = None,
        processor: Any = _UNSET_PROCESSOR,
        max_artifacts_memory: int = 1024,
        *,
        consent_manager: Optional[ConsentManager] = None,
        store_available: bool = True,
        store_health_check: Optional[Callable[[], bool]] = None,
    ) -> None:
        self._lock: threading.RLock = threading.RLock()
        self._artifacts: Dict[str, ExportArtifact] = {}
        self._artifact_queue: List[str] = []
        self._policy: ExportPolicy = policy if policy is not None else EXPORT_POLICY_DEFAULT
        if processor is _UNSET_PROCESSOR:
            self._processor: Optional[LogProcessor] = LogProcessor() if LogProcessor is not None else None
        else:
            self._processor = processor
        self._max_artifacts_memory: int = max_artifacts_memory
        self._consent_manager: Optional[ConsentManager] = consent_manager
        self._store_available: bool = bool(store_available)
        self._store_health_check: Optional[Callable[[], bool]] = store_health_check

    def is_store_available(self) -> bool:
        with self._lock:
            return self._check_store_ready_locked()

    def set_store_available(self, available: bool) -> None:
        with self._lock:
            self._store_available = bool(available)

    def _check_store_ready_locked(self) -> bool:
        if not self._store_available:
            return False
        if self._processor is None:
            return False
        if getattr(self._processor, "store_available", True) is False:
            return False
        if self._consent_manager is not None:
            is_cm_ready = getattr(self._consent_manager, "is_store_available", None)
            if callable(is_cm_ready):
                try:
                    if not is_cm_ready():
                        return False
                except Exception:
                    return False
        if self._store_health_check is not None:
            try:
                if not bool(self._store_health_check()):
                    return False
            except Exception:
                return False
        return True

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

    def _read_store_entries_locked(self) -> List[LogEntry]:
        assert self._processor is not None
        reader = getattr(self._processor, "read_entries", None)
        if callable(reader):
            return list(reader())
        raw_entries = getattr(self._processor, "_entries", None)
        if raw_entries is None:
            raise AnalyticsStoreUnavailableError("processor entry buffer unavailable")
        return list(raw_entries[:])

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
                return None, ExportStatus.EXPORT_TOKEN_REQUIRED, 0

            if not self._check_store_ready_locked():
                return None, ExportStatus.STORE_UNAVAILABLE, 0

            if self._consent_manager is not None and exported_by_tag is not None and export_token_verified:
                try:
                    self._consent_manager.check_consent(exported_by_tag, scope=None)
                except (ConsentStoreUnavailableError, AnalyticsStoreUnavailableError, OSError, RuntimeError):
                    return None, ExportStatus.STORE_UNAVAILABLE, 0

            try:
                if entries is not None:
                    entries_filtered = list(entries)
                else:
                    entries_filtered = self._read_store_entries_locked()
            except (AnalyticsStoreUnavailableError, ConsentStoreUnavailableError, OSError, RuntimeError):
                return None, ExportStatus.STORE_UNAVAILABLE, 0

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

            try:
                serialized, count = self._processor.export_json_logs(  # type: ignore[union-attr]
                    entries=entries_filtered,
                    compress=use_compress,
                    max_entries=policy.max_artifacts_per_export,
                    max_bytes=policy.max_artifact_bytes,
                )
            except (AnalyticsStoreUnavailableError, OSError, RuntimeError):
                return None, ExportStatus.STORE_UNAVAILABLE, 0

            export_status = ExportStatus.COMPLETED if count > 0 else ExportStatus.EMPTY
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
                export_status=export_status,
            )
            if len(self._artifacts) >= self._max_artifacts_memory:
                if self._artifact_queue:
                    oldest_id = self._artifact_queue.pop(0)
                    self._artifacts.pop(oldest_id, None)
            self._artifacts[artifact_id] = artifact
            self._artifact_queue.append(artifact_id)
            return artifact, serialized, count

    def export_with_status(
        self,
        entries: Optional[List[LogEntry]] = None,
        exported_by_tag: Optional[str] = None,
        compress: Optional[bool] = None,
        rollout_phase: str = "shadow",
        export_token_verified: bool = False,
    ) -> ExportOutcome:
        """Execute an export and return a machine-readable ExportOutcome."""
        artifact, serialized_or_reason, count = self.create_export(
            entries=entries,
            exported_by_tag=exported_by_tag,
            compress=compress,
            rollout_phase=rollout_phase,
            export_token_verified=export_token_verified,
        )
        if artifact is None:
            return ExportOutcome(
                status=serialized_or_reason,
                artifact=None,
                serialized=None,
                entry_count=0,
                retryable=(serialized_or_reason == ExportStatus.STORE_UNAVAILABLE),
            )
        return ExportOutcome(
            status=artifact.export_status,
            artifact=artifact,
            serialized=serialized_or_reason,
            entry_count=count,
            retryable=False,
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
