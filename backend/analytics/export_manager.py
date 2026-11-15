from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
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
    from analytics.consent import ConsentAuditReference, ConsentManager
except Exception:
    try:
        from backend.analytics.consent import ConsentAuditReference, ConsentManager
    except Exception:
        ConsentAuditReference = None  # type: ignore[assignment]
        ConsentManager = None  # type: ignore[assignment]


EXPORT_FORMAT_VERSION = "1.0.0"
RETENTION_CHECKPOINT_VERSION = "1.0.0"
DELETION_AUDIT_DOMAIN_TAG = "harpocrates:deletion-audit-ref:v1"
MAX_DELETION_AUDIT_REFERENCES = 4096
MAX_CHECKPOINT_AUDIT_IDS = 4096


class CleanupPhase:
    CONSENT = "consent"
    LOG_ENTRIES = "log_entries"
    EXPORT_ARTIFACTS = "export_artifacts"
    COMPLETED = "completed"


_VALID_CLEANUP_PHASES = {
    CleanupPhase.CONSENT,
    CleanupPhase.LOG_ENTRIES,
    CleanupPhase.EXPORT_ARTIFACTS,
    CleanupPhase.COMPLETED,
}


@dataclass(frozen=True)
class DeletionAuditReference:
    """Privacy-safe audit reference retained when analytics logs or artifacts are deleted."""

    reference_id: str
    target_kind: str
    target_id_digest: str
    deleted_at_epoch_seconds: float
    reason: str
    checksum_prefix16: Optional[str] = None


def _sanitize_checksum_prefix(raw_checksum: Optional[str]) -> Optional[str]:
    if not raw_checksum or not isinstance(raw_checksum, str):
        return None
    candidate = raw_checksum.split(":", 1)[-1] if ":" in raw_checksum else raw_checksum
    if 12 <= len(candidate) <= 64 and all(ch in "0123456789abcdefABCDEF" for ch in candidate):
        return candidate[:16].lower()
    return None


def _hash_target_id_for_audit(target_kind: str, target_id: str) -> str:
    framed = f"{DELETION_AUDIT_DOMAIN_TAG}:{len(target_kind)}:{target_kind}:{len(target_id)}:{target_id}"
    return hashlib.sha256(framed.encode("utf-8")).hexdigest()


def _parse_cursor_pair(raw: Any, field_name: str) -> Optional[Tuple[float, str]]:
    if raw is None:
        return None
    if not isinstance(raw, (list, tuple)) or len(raw) != 2:
        raise ValueError(f"invalid {field_name} in retention checkpoint")
    ts_val, id_val = raw
    if isinstance(ts_val, bool) or not isinstance(ts_val, (int, float)) or not isinstance(id_val, str):
        raise ValueError(f"invalid {field_name} element types in retention checkpoint")
    return (float(ts_val), id_val)


@dataclass
class RetentionCheckpoint:
    checkpoint_id: str
    schema_version: str = RETENTION_CHECKPOINT_VERSION
    phase: str = CleanupPhase.CONSENT
    consent_cursor: Optional[str] = None
    log_cursor: Optional[Tuple[float, str]] = None
    artifact_cursor: Optional[Tuple[float, str]] = None
    batches_completed: int = 0
    consent_pruned_count: int = 0
    logs_deleted_count: int = 0
    artifacts_deleted_count: int = 0
    consent_audit_ref_ids: List[str] = field(default_factory=list)
    deletion_audit_ref_ids: List[str] = field(default_factory=list)
    cutoff_epoch_seconds: float = 0.0
    updated_at_epoch_seconds: float = 0.0
    completed: bool = False
    interrupted_reason: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.checkpoint_id, str) or not self.checkpoint_id.strip():
            raise ValueError("checkpoint_id must be a non-empty string")
        if self.schema_version != RETENTION_CHECKPOINT_VERSION:
            raise ValueError(f"unsupported retention checkpoint schema_version: {self.schema_version}")
        if self.phase not in _VALID_CLEANUP_PHASES:
            raise ValueError(f"invalid retention checkpoint phase: {self.phase}")
        for count_val in (
            self.batches_completed,
            self.consent_pruned_count,
            self.logs_deleted_count,
            self.artifacts_deleted_count,
        ):
            if isinstance(count_val, bool) or not isinstance(count_val, int) or count_val < 0:
                raise ValueError("retention checkpoint counters must be non-negative integers")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "schema_version": self.schema_version,
            "phase": self.phase,
            "consent_cursor": self.consent_cursor,
            "log_cursor": list(self.log_cursor) if self.log_cursor is not None else None,
            "artifact_cursor": list(self.artifact_cursor) if self.artifact_cursor is not None else None,
            "batches_completed": self.batches_completed,
            "consent_pruned_count": self.consent_pruned_count,
            "logs_deleted_count": self.logs_deleted_count,
            "artifacts_deleted_count": self.artifacts_deleted_count,
            "consent_audit_ref_ids": list(self.consent_audit_ref_ids[-MAX_CHECKPOINT_AUDIT_IDS:]),
            "deletion_audit_ref_ids": list(self.deletion_audit_ref_ids[-MAX_CHECKPOINT_AUDIT_IDS:]),
            "cutoff_epoch_seconds": self.cutoff_epoch_seconds,
            "updated_at_epoch_seconds": self.updated_at_epoch_seconds,
            "completed": self.completed,
            "interrupted_reason": self.interrupted_reason,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RetentionCheckpoint:
        if not isinstance(data, dict):
            raise ValueError("retention checkpoint payload must be a JSON object")
        consent_cursor = data.get("consent_cursor")
        if consent_cursor is not None and not isinstance(consent_cursor, str):
            raise ValueError("invalid consent_cursor in retention checkpoint")
        consent_refs = data.get("consent_audit_ref_ids", [])
        deletion_refs = data.get("deletion_audit_ref_ids", [])
        if not isinstance(consent_refs, list) or not all(isinstance(x, str) for x in consent_refs):
            raise ValueError("invalid consent_audit_ref_ids in retention checkpoint")
        if not isinstance(deletion_refs, list) or not all(isinstance(x, str) for x in deletion_refs):
            raise ValueError("invalid deletion_audit_ref_ids in retention checkpoint")
        interrupted = data.get("interrupted_reason")
        if interrupted is not None and not isinstance(interrupted, str):
            raise ValueError("invalid interrupted_reason in retention checkpoint")
        cutoff = data.get("cutoff_epoch_seconds", 0.0)
        updated = data.get("updated_at_epoch_seconds", 0.0)
        if isinstance(cutoff, bool) or not isinstance(cutoff, (int, float)):
            raise ValueError("invalid cutoff_epoch_seconds in retention checkpoint")
        if isinstance(updated, bool) or not isinstance(updated, (int, float)):
            raise ValueError("invalid updated_at_epoch_seconds in retention checkpoint")
        completed = data.get("completed", False)
        if not isinstance(completed, bool):
            raise ValueError("invalid completed flag in retention checkpoint")

        return cls(
            checkpoint_id=str(data.get("checkpoint_id", "")),
            schema_version=str(data.get("schema_version", "")),
            phase=str(data.get("phase", "")),
            consent_cursor=consent_cursor,
            log_cursor=_parse_cursor_pair(data.get("log_cursor"), "log_cursor"),
            artifact_cursor=_parse_cursor_pair(data.get("artifact_cursor"), "artifact_cursor"),
            batches_completed=data.get("batches_completed", -1),
            consent_pruned_count=data.get("consent_pruned_count", -1),
            logs_deleted_count=data.get("logs_deleted_count", -1),
            artifacts_deleted_count=data.get("artifacts_deleted_count", -1),
            consent_audit_ref_ids=list(consent_refs[-MAX_CHECKPOINT_AUDIT_IDS:]),
            deletion_audit_ref_ids=list(deletion_refs[-MAX_CHECKPOINT_AUDIT_IDS:]),
            cutoff_epoch_seconds=float(cutoff),
            updated_at_epoch_seconds=float(updated),
            completed=completed,
            interrupted_reason=interrupted,
        )


def _check_non_symlink_checkpoint_path(checkpoint_path: str | os.PathLike[str]) -> Path:
    raw = os.fspath(checkpoint_path)
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise ValueError("invalid checkpoint_path")
    path = Path(raw)
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise ValueError("symlink checkpoint_path is not allowed")
    return path


def save_retention_checkpoint(
    checkpoint: RetentionCheckpoint,
    checkpoint_path: str | os.PathLike[str],
) -> Path:
    path = _check_non_symlink_checkpoint_path(checkpoint_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise ValueError("symlink checkpoint directory is not allowed")
    serialized = json.dumps(checkpoint.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    tmp_path = path.parent / f".tmp-{os.urandom(8).hex()}-{path.name}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(str(tmp_path), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(serialized)
            handle.flush()
        os.replace(str(tmp_path), str(path))
    except Exception:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
        raise
    return path


def load_retention_checkpoint(checkpoint_path: str | os.PathLike[str]) -> RetentionCheckpoint:
    path = _check_non_symlink_checkpoint_path(checkpoint_path)
    if not path.is_file():
        raise FileNotFoundError(f"retention checkpoint not found: {path.name}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError("corrupted retention checkpoint JSON") from exc
    return RetentionCheckpoint.from_dict(payload)


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
    default_retention_ttl_seconds: float = 86_400.0
    retention_batch_size: int = 64
    retention_max_batches_per_run: int = 16


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
        consent_manager: Optional[ConsentManager] = None,
        max_deletion_audit_references: int = MAX_DELETION_AUDIT_REFERENCES,
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
        self._max_deletion_audit_refs: int = max(1, int(max_deletion_audit_references))
        self._deletion_audit_refs: Dict[str, DeletionAuditReference] = {}
        self._deletion_audit_order: List[str] = []

    def _record_deletion_audit_locked(
        self,
        *,
        target_kind: str,
        target_id: str,
        deleted_at_epoch_seconds: float,
        reason: str,
        checksum_prefix16: Optional[str] = None,
    ) -> DeletionAuditReference:
        target_digest = _hash_target_id_for_audit(target_kind, target_id)
        seed = (
            f"{DELETION_AUDIT_DOMAIN_TAG}|{target_kind}|{target_digest}|"
            f"{deleted_at_epoch_seconds:.6f}|{reason}"
        ).encode("utf-8") + os.urandom(8)
        ref_id = "dar-v1:" + hashlib.sha256(seed).hexdigest()[:16]
        ref = DeletionAuditReference(
            reference_id=ref_id,
            target_kind=target_kind,
            target_id_digest=target_digest,
            deleted_at_epoch_seconds=deleted_at_epoch_seconds,
            reason=reason,
            checksum_prefix16=_sanitize_checksum_prefix(checksum_prefix16),
        )
        while len(self._deletion_audit_refs) >= self._max_deletion_audit_refs and self._deletion_audit_order:
            oldest = self._deletion_audit_order.pop(0)
            self._deletion_audit_refs.pop(oldest, None)
        self._deletion_audit_refs[ref_id] = ref
        self._deletion_audit_order.append(ref_id)
        return ref

    def get_deletion_audit_reference(self, reference_id: str) -> Optional[DeletionAuditReference]:
        with self._lock:
            return self._deletion_audit_refs.get(reference_id)

    def list_deletion_audit_references(self, limit: int = 100) -> List[DeletionAuditReference]:
        if limit <= 0:
            return []
        with self._lock:
            refs: List[DeletionAuditReference] = []
            for ref_id in reversed(self._deletion_audit_order):
                if len(refs) >= limit:
                    break
                ref = self._deletion_audit_refs.get(ref_id)
                if ref is not None:
                    refs.append(ref)
            return refs

    def generate_export_id(self) -> str:
        random_bytes = os.urandom(32)
        timestamp = str(time.time()).encode("utf-8")
        raw = random_bytes + timestamp
        digest = hashlib.sha256(raw).hexdigest()[:16]
        return self._policy.export_id_prefix + digest

    def _generate_checkpoint_id(self) -> str:
        digest = hashlib.sha256(os.urandom(24) + str(time.time_ns()).encode("utf-8")).hexdigest()[:16]
        return f"rcp-v1:{digest}"

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

    def _cleanup_log_entries_batch(
        self,
        *,
        cutoff_epoch_seconds: float,
        now_epoch_seconds: float,
        batch_size: int,
        after_cursor: Optional[Tuple[float, str]],
    ) -> Tuple[int, Optional[Tuple[float, str]], bool, List[DeletionAuditReference]]:
        if self._processor is None:
            return 0, after_cursor, True, []

        with self._processor._lock:
            ordered = sorted(
                self._processor._entries,
                key=lambda item: (item.timestamp_epoch_seconds, item.entry_id),
            )
            if after_cursor is not None:
                ordered = [
                    item
                    for item in ordered
                    if (item.timestamp_epoch_seconds, item.entry_id) > after_cursor
                ]
            if not ordered:
                return 0, after_cursor, True, []

            batch = ordered[:batch_size]
            phase_done = len(ordered) <= batch_size
            next_cursor = (batch[-1].timestamp_epoch_seconds, batch[-1].entry_id)
            expired_ids = {
                item.entry_id
                for item in batch
                if item.timestamp_epoch_seconds <= cutoff_epoch_seconds
            }
            if expired_ids:
                self._processor._entries = [
                    item for item in self._processor._entries if item.entry_id not in expired_ids
                ]

        refs: List[DeletionAuditReference] = []
        if expired_ids:
            with self._lock:
                for item in batch:
                    if item.entry_id in expired_ids:
                        refs.append(
                            self._record_deletion_audit_locked(
                                target_kind="log_entry",
                                target_id=item.entry_id,
                                deleted_at_epoch_seconds=now_epoch_seconds,
                                reason="retention_expired",
                                checksum_prefix16=item.export_signature,
                            )
                        )
        return len(expired_ids), next_cursor, phase_done, refs

    def _cleanup_artifacts_batch(
        self,
        *,
        cutoff_epoch_seconds: float,
        now_epoch_seconds: float,
        batch_size: int,
        after_cursor: Optional[Tuple[float, str]],
    ) -> Tuple[int, Optional[Tuple[float, str]], bool, List[DeletionAuditReference]]:
        with self._lock:
            ordered = sorted(
                self._artifacts.values(),
                key=lambda art: (art.generated_at_epoch_seconds, art.artifact_id),
            )
            if after_cursor is not None:
                ordered = [
                    art
                    for art in ordered
                    if (art.generated_at_epoch_seconds, art.artifact_id) > after_cursor
                ]
            if not ordered:
                return 0, after_cursor, True, []

            batch = ordered[:batch_size]
            phase_done = len(ordered) <= batch_size
            next_cursor = (batch[-1].generated_at_epoch_seconds, batch[-1].artifact_id)
            refs: List[DeletionAuditReference] = []
            deleted_ids = set()
            for art in batch:
                if art.generated_at_epoch_seconds <= cutoff_epoch_seconds:
                    self._artifacts.pop(art.artifact_id, None)
                    deleted_ids.add(art.artifact_id)
                    refs.append(
                        self._record_deletion_audit_locked(
                            target_kind="export_artifact",
                            target_id=art.artifact_id,
                            deleted_at_epoch_seconds=now_epoch_seconds,
                            reason="retention_expired",
                            checksum_prefix16=art.checksum_sha256_prefix16,
                        )
                    )
            if deleted_ids:
                self._artifact_queue = [aid for aid in self._artifact_queue if aid not in deleted_ids]
            return len(deleted_ids), next_cursor, phase_done, refs

    def run_retention_cleanup(
        self,
        *,
        now_epoch_seconds: Optional[float] = None,
        retention_ttl_seconds: Optional[float] = None,
        batch_size: Optional[int] = None,
        max_batches: Optional[int] = None,
        checkpoint: Optional[RetentionCheckpoint] = None,
        checkpoint_path: Optional[str | os.PathLike[str]] = None,
        should_stop: Optional[Callable[[int, RetentionCheckpoint], bool]] = None,
    ) -> RetentionCheckpoint:
        """Process bounded analytics cleanup batches and persist/return a resumable checkpoint."""
        effective_batch_size = batch_size if batch_size is not None else self._policy.retention_batch_size
        effective_max_batches = (
            max_batches if max_batches is not None else self._policy.retention_max_batches_per_run
        )
        effective_ttl = (
            float(retention_ttl_seconds)
            if retention_ttl_seconds is not None
            else float(self._policy.default_retention_ttl_seconds)
        )
        if (
            isinstance(effective_batch_size, bool)
            or not isinstance(effective_batch_size, int)
            or effective_batch_size <= 0
            or effective_batch_size > 10_000
        ):
            raise ValueError("batch_size must be an integer between 1 and 10000")
        if (
            isinstance(effective_max_batches, bool)
            or not isinstance(effective_max_batches, int)
            or effective_max_batches <= 0
            or effective_max_batches > 10_000
        ):
            raise ValueError("max_batches must be an integer between 1 and 10000")
        if effective_ttl < 0:
            raise ValueError("retention_ttl_seconds must be non-negative")

        now = float(now_epoch_seconds) if now_epoch_seconds is not None else time.time()

        if checkpoint is not None:
            cp = checkpoint
        elif checkpoint_path is not None and _check_non_symlink_checkpoint_path(checkpoint_path).exists():
            cp = load_retention_checkpoint(checkpoint_path)
        else:
            cp = RetentionCheckpoint(
                checkpoint_id=self._generate_checkpoint_id(),
                phase=CleanupPhase.CONSENT,
                cutoff_epoch_seconds=now - effective_ttl,
                updated_at_epoch_seconds=now,
            )

        if cp.completed or cp.phase == CleanupPhase.COMPLETED:
            cp.completed = True
            cp.phase = CleanupPhase.COMPLETED
            if checkpoint_path is not None:
                save_retention_checkpoint(cp, checkpoint_path)
            return cp

        cp.interrupted_reason = None
        batches_executed = 0

        try:
            while batches_executed < effective_max_batches and not cp.completed:
                if should_stop is not None and should_stop(batches_executed, cp):
                    cp.interrupted_reason = "cooperative_stop"
                    cp.updated_at_epoch_seconds = now
                    if checkpoint_path is not None:
                        save_retention_checkpoint(cp, checkpoint_path)
                    return cp

                if cp.phase == CleanupPhase.CONSENT:
                    if self._consent_manager is None:
                        cp.phase = CleanupPhase.LOG_ENTRIES
                        continue
                    pruned, next_consent_cursor, done, c_refs = self._consent_manager.prune_expired_batch(
                        now_epoch_seconds=now,
                        batch_size=effective_batch_size,
                        after_account_tag=cp.consent_cursor,
                    )
                    cp.consent_pruned_count += pruned
                    cp.consent_cursor = next_consent_cursor
                    for ref in c_refs:
                        cp.consent_audit_ref_ids.append(ref.reference_id)
                    if len(cp.consent_audit_ref_ids) > MAX_CHECKPOINT_AUDIT_IDS:
                        cp.consent_audit_ref_ids = cp.consent_audit_ref_ids[-MAX_CHECKPOINT_AUDIT_IDS:]
                    if done:
                        cp.phase = CleanupPhase.LOG_ENTRIES

                elif cp.phase == CleanupPhase.LOG_ENTRIES:
                    deleted_logs, next_log_cursor, done, l_refs = self._cleanup_log_entries_batch(
                        cutoff_epoch_seconds=cp.cutoff_epoch_seconds,
                        now_epoch_seconds=now,
                        batch_size=effective_batch_size,
                        after_cursor=cp.log_cursor,
                    )
                    cp.logs_deleted_count += deleted_logs
                    cp.log_cursor = next_log_cursor
                    for ref in l_refs:
                        cp.deletion_audit_ref_ids.append(ref.reference_id)
                    if len(cp.deletion_audit_ref_ids) > MAX_CHECKPOINT_AUDIT_IDS:
                        cp.deletion_audit_ref_ids = cp.deletion_audit_ref_ids[-MAX_CHECKPOINT_AUDIT_IDS:]
                    if done:
                        cp.phase = CleanupPhase.EXPORT_ARTIFACTS

                elif cp.phase == CleanupPhase.EXPORT_ARTIFACTS:
                    deleted_arts, next_art_cursor, done, a_refs = self._cleanup_artifacts_batch(
                        cutoff_epoch_seconds=cp.cutoff_epoch_seconds,
                        now_epoch_seconds=now,
                        batch_size=effective_batch_size,
                        after_cursor=cp.artifact_cursor,
                    )
                    cp.artifacts_deleted_count += deleted_arts
                    cp.artifact_cursor = next_art_cursor
                    for ref in a_refs:
                        cp.deletion_audit_ref_ids.append(ref.reference_id)
                    if len(cp.deletion_audit_ref_ids) > MAX_CHECKPOINT_AUDIT_IDS:
                        cp.deletion_audit_ref_ids = cp.deletion_audit_ref_ids[-MAX_CHECKPOINT_AUDIT_IDS:]
                    if done:
                        cp.phase = CleanupPhase.COMPLETED
                        cp.completed = True

                batches_executed += 1
                cp.batches_completed += 1
                cp.updated_at_epoch_seconds = now
                if checkpoint_path is not None:
                    save_retention_checkpoint(cp, checkpoint_path)

        except Exception as exc:
            cp.interrupted_reason = f"exception:{type(exc).__name__}"
            cp.updated_at_epoch_seconds = now
            if checkpoint_path is not None:
                save_retention_checkpoint(cp, checkpoint_path)
            raise

        return cp

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
            art = self._artifacts.pop(artifact_id, None)
            if art is not None:
                self._artifact_queue = [aid for aid in self._artifact_queue if aid != artifact_id]
                self._record_deletion_audit_locked(
                    target_kind="export_artifact",
                    target_id=artifact_id,
                    deleted_at_epoch_seconds=time.time(),
                    reason="manual_delete",
                    checksum_prefix16=art.checksum_sha256_prefix16,
                )
                return True
            return False

    def reset(self, *, clear_audit_references: bool = False) -> None:
        with self._lock:
            self._artifacts.clear()
            self._artifact_queue.clear()
            if clear_audit_references:
                self._deletion_audit_refs.clear()
                self._deletion_audit_order.clear()
