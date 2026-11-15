from __future__ import annotations

import dataclasses
import hashlib
import os
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
    from analytics.consent import (
        ConsentCollectionDisposition,
        ConsentManager,
        ConsentStatus,
        DEFAULT_CONSENT_POLICY_REVISION,
        validate_consent_policy_revision,
    )
except Exception:
    try:
        from backend.analytics.consent import (
            ConsentCollectionDisposition,
            ConsentManager,
            ConsentStatus,
            DEFAULT_CONSENT_POLICY_REVISION,
            validate_consent_policy_revision,
        )
    except Exception:
        ConsentManager = None  # type: ignore[assignment]
        DEFAULT_CONSENT_POLICY_REVISION = "consent-policy-v1"

        class ConsentCollectionDisposition:  # type: ignore[no-redef]
            COLLECTED_UNDER_CONSENT = "collected_under_consent"
            CONSENT_WITHDRAWN = "consent_withdrawn"
            NEVER_COLLECTED = "never_collected"

        class ConsentStatus:  # type: ignore[no-redef]
            WITHDRAWN = "withdrawn"
            GRANTED = "granted"

        def validate_consent_policy_revision(revision: str) -> str:
            if not isinstance(revision, str) or not revision:
                raise ValueError("invalid consent policy revision")
            return revision


EXPORT_FORMAT_VERSION = "1.0.0"


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
    default_consent_policy_revision: str = DEFAULT_CONSENT_POLICY_REVISION


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
    consent_policy_revisions: List[str] = field(default_factory=list)
    consent_disposition: str = ConsentCollectionDisposition.NEVER_COLLECTED
    prior_collection_policy_revision: Optional[str] = None
    had_prior_collection: bool = False

    def to_consent_summary(self) -> Dict[str, Any]:
        return {
            "consent_disposition": self.consent_disposition,
            "consent_policy_revisions": list(self.consent_policy_revisions),
            "prior_collection_policy_revision": self.prior_collection_policy_revision,
            "had_prior_collection": self.had_prior_collection,
        }


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
        validate_consent_policy_revision(self._policy.default_consent_policy_revision)
        if processor is not None:
            self._processor: LogProcessor = processor
        elif LogProcessor is not None:
            self._processor = LogProcessor()
        else:
            self._processor = None
        self._max_artifacts_memory: int = max_artifacts_memory
        self._consent_manager: Optional[ConsentManager] = consent_manager

    def _resolve_entry_for_export(self, entry: LogEntry) -> Optional[LogEntry]:
        explicit_rev = entry.consent_policy_revision
        if explicit_rev is not None:
            validate_consent_policy_revision(explicit_rev)

        if self._consent_manager is not None and entry.account_id_tag is not None:
            disp, _had_prior, _prior_rev = self._consent_manager.inspect_subject_disposition(
                entry.account_id_tag,
                matched_store_records=1,
            )
            if disp == ConsentCollectionDisposition.CONSENT_WITHDRAWN:
                return None
            effective_rev = explicit_rev or self._consent_manager.policy_effective_at(
                entry.account_id_tag,
                entry.timestamp_epoch_seconds,
            )
            if effective_rev is None:
                return None
            validate_consent_policy_revision(effective_rev)
            return dataclasses.replace(entry, consent_policy_revision=effective_rev)

        final_rev = explicit_rev or self._policy.default_consent_policy_revision
        validate_consent_policy_revision(final_rev)
        return dataclasses.replace(entry, consent_policy_revision=final_rev)

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
        *,
        subject_account_tag: Optional[str] = None,
    ) -> Tuple[Optional[ExportArtifact], str, int]:
        with self._lock:
            policy = self._policy
            validate_consent_policy_revision(policy.default_consent_policy_revision)
            if not export_token_verified and policy.require_export_token and not policy.allow_unauthenticated_export_shadow_mode:
                return None, "export_token_required", 0

            if entries is not None:
                raw_candidates = list(entries)
            elif self._processor is not None:
                raw_candidates = list(self._processor._entries[:])
            else:
                raw_candidates = []

            if subject_account_tag is not None:
                raw_candidates = [
                    e for e in raw_candidates if e.account_id_tag == subject_account_tag
                ]
            matched_before_consent = len(raw_candidates)

            entries_filtered: List[LogEntry] = []
            for item in raw_candidates:
                resolved = self._resolve_entry_for_export(item)
                if resolved is not None:
                    entries_filtered.append(resolved)

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

            target_subject = subject_account_tag
            if (
                target_subject is None
                and self._consent_manager is not None
                and exported_by_tag is not None
                and exported_by_tag in self._consent_manager._consent_states
            ):
                target_subject = exported_by_tag

            withdrawn_subject = False
            prior_rev: Optional[str] = None
            had_prior = False
            if self._consent_manager is not None and target_subject is not None:
                disp, had_prior, prior_rev = self._consent_manager.inspect_subject_disposition(
                    target_subject,
                    matched_store_records=matched_before_consent,
                )
                if disp == ConsentCollectionDisposition.CONSENT_WITHDRAWN:
                    withdrawn_subject = True
                    if subject_account_tag is not None or target_subject == exported_by_tag:
                        entries_filtered = [
                            e for e in entries_filtered if e.account_id_tag != target_subject
                        ]

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

            exported_slice = sorted(entries_filtered, key=lambda e: e.timestamp_epoch_seconds)[:count]
            revisions = sorted(
                {e.consent_policy_revision for e in exported_slice if e.consent_policy_revision}
            )

            if withdrawn_subject and count == 0:
                consent_disposition = ConsentCollectionDisposition.CONSENT_WITHDRAWN
                final_revisions: List[str] = []
                final_had_prior = had_prior
                final_prior_rev = prior_rev
            elif count > 0:
                consent_disposition = ConsentCollectionDisposition.COLLECTED_UNDER_CONSENT
                final_revisions = revisions
                final_had_prior = True
                final_prior_rev = revisions[-1] if revisions else prior_rev
            else:
                consent_disposition = ConsentCollectionDisposition.NEVER_COLLECTED
                final_revisions = []
                final_had_prior = False
                final_prior_rev = None

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
                consent_policy_revisions=final_revisions,
                consent_disposition=consent_disposition,
                prior_collection_policy_revision=final_prior_rev,
                had_prior_collection=final_had_prior,
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
