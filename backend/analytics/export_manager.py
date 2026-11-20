from __future__ import annotations

import dataclasses
import hashlib
import json
import os
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
    from analytics.consent import CONSENT_SCHEMA_VERSION
except ImportError:
    try:
        from backend.analytics.consent import CONSENT_SCHEMA_VERSION
    except ImportError:
        CONSENT_SCHEMA_VERSION = None


EXPORT_FORMAT_VERSION = "1.0.0"
EXPORT_RECEIPT_VERSION = "receipt-v1"
EXPORT_POLICY_REVISION_PREFIX = "pol-v1:"


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
    # Completion receipt (see docs/analytics-export-receipts.md). Metadata only:
    # scope, policy revision, counts and the output digest, never entries.
    receipt: dict[str, Any] | None = None


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
                "candidate_count": candidate_count,
                "exported_count": artifact.entry_count,
                "max_entries": policy.max_artifacts_per_export,
                "max_bytes": policy.max_artifact_bytes,
                "include_sampled_out_events": policy.include_sampled_out_events,
                "export_token_verified": bool(export_token_verified),
                "compress": artifact.compress,
                "rollout_phase": artifact.rollout_phase,
            },
            "policy_revision": export_policy_revision(policy),
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

    def reset(self) -> None:
        with self._lock:
            self._artifacts.clear()
            self._artifact_queue.clear()
