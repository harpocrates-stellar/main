from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

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
EXPORT_POLICY_REVISION = "export-policy-v1"
EXPORT_RECEIPT_DOMAIN = "harpocrates:analytics-export-receipt:v1"
DEFAULT_EXPORT_SCOPE = "analytics:export"
MAX_RECEIPT_SCOPES = 32

_SCOPE_RE = re.compile(r"^(?:\*|[A-Za-z0-9][A-Za-z0-9_:*.-]{0,63})$")
_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_HEX_SECRET_RE = re.compile(r"^[0-9a-fA-F]{32,}$")
_STELLAR_KEY_RE = re.compile(r"^[GSM][A-Z2-7]{55,68}$")


def validate_receipt_scopes(scopes: Optional[Sequence[str]]) -> Tuple[str, ...]:
    """Validate and canonicalize export scopes so private identifiers cannot enter receipts."""
    if scopes is None:
        return (DEFAULT_EXPORT_SCOPE,)
    if isinstance(scopes, (str, bytes)):
        raise ValueError("selected_scopes must be a sequence of scope strings")
    items = list(scopes)
    if not items:
        return (DEFAULT_EXPORT_SCOPE,)
    if len(items) > MAX_RECEIPT_SCOPES:
        raise ValueError(f"selected_scopes exceeds maximum of {MAX_RECEIPT_SCOPES}")
    cleaned = set()
    for raw in items:
        if not isinstance(raw, str) or not _SCOPE_RE.match(raw):
            raise ValueError("invalid export scope identifier")
        if _HEX_SECRET_RE.match(raw) or _STELLAR_KEY_RE.match(raw):
            raise ValueError("export scope cannot contain digest or key material")
        cleaned.add(raw)
    return tuple(sorted(cleaned))


def validate_policy_revision(
    revision: Optional[str],
    default: str = EXPORT_POLICY_REVISION,
) -> str:
    """Validate policy revision identifier for export receipts."""
    effective = default if revision is None else revision
    if not isinstance(effective, str) or not _REVISION_RE.match(effective):
        raise ValueError("invalid policy revision identifier")
    if _HEX_SECRET_RE.match(effective) or _STELLAR_KEY_RE.match(effective):
        raise ValueError("policy revision cannot contain digest or key material")
    return effective


def compute_output_digest(serialized_payload: str) -> str:
    """Compute canonical SHA-256 digest over the serialized export payload."""
    if not isinstance(serialized_payload, str):
        raise TypeError("serialized_payload must be a str")
    digest = hashlib.sha256(serialized_payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _canonical_receipt_commitment_payload(
    *,
    receipt_id: str,
    artifact_id: str,
    selected_scopes: Tuple[str, ...],
    policy_revision: str,
    output_digest: str,
    completed_at_epoch_seconds: float,
    entry_count: int,
    payload_bytes: int,
    compress: bool,
    rollout_phase: str,
    redaction_version: str,
    safety_signature: Optional[str],
    schema_version: str,
) -> bytes:
    canonical = {
        "domain": EXPORT_RECEIPT_DOMAIN,
        "schema_version": schema_version,
        "receipt_id": receipt_id,
        "artifact_id": artifact_id,
        "selected_scopes": list(selected_scopes),
        "policy_revision": policy_revision,
        "output_digest": output_digest,
        "completed_at_epoch_seconds": completed_at_epoch_seconds,
        "entry_count": entry_count,
        "payload_bytes": payload_bytes,
        "compress": compress,
        "rollout_phase": rollout_phase,
        "redaction_version": redaction_version,
        "safety_signature": safety_signature,
    }
    return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_receipt_digest(**fields: Any) -> str:
    digest = hashlib.sha256(_canonical_receipt_commitment_payload(**fields)).hexdigest()
    return f"sha256:{digest}"


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
    policy_revision: str = EXPORT_POLICY_REVISION
    receipt_id_prefix: str = "rcpt-v1:"


EXPORT_POLICY_DEFAULT: ExportPolicy = ExportPolicy()


@dataclass(frozen=True)
class ExportCompletionReceipt:
    """Privacy-preserving completion receipt for an analytics export.

    Records only operational scope, policy revision, output digest, and bounded
    counts/metadata; never retains raw events, messages, tags, or tokens.
    """

    receipt_id: str
    artifact_id: str
    selected_scopes: Tuple[str, ...]
    policy_revision: str
    output_digest: str
    completed_at_epoch_seconds: float
    entry_count: int = 0
    payload_bytes: int = 0
    compress: bool = False
    rollout_phase: str = "shadow"
    redaction_version: str = "harpocrates-redaction-v1"
    safety_signature: Optional[str] = None
    schema_version: str = EXPORT_FORMAT_VERSION
    receipt_digest: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "artifact_id": self.artifact_id,
            "schema_version": self.schema_version,
            "completed_at_epoch_seconds": self.completed_at_epoch_seconds,
            "selected_scopes": list(self.selected_scopes),
            "policy_revision": self.policy_revision,
            "redaction_version": self.redaction_version,
            "output_digest": self.output_digest,
            "entry_count": self.entry_count,
            "payload_bytes": self.payload_bytes,
            "compress": self.compress,
            "rollout_phase": self.rollout_phase,
            "safety_signature": self.safety_signature,
            "receipt_digest": self.receipt_digest,
        }

    def verify_output(self, serialized_payload: str) -> bool:
        if not isinstance(serialized_payload, str):
            return False
        expected = compute_output_digest(serialized_payload)
        return (
            hmac.compare_digest(self.output_digest, expected)
            and len(serialized_payload.encode("utf-8")) == self.payload_bytes
        )

    def verify_integrity(self) -> bool:
        try:
            scopes = validate_receipt_scopes(self.selected_scopes)
            rev = validate_policy_revision(self.policy_revision)
        except ValueError:
            return False
        if scopes != tuple(self.selected_scopes) or rev != self.policy_revision:
            return False
        if not isinstance(self.output_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", self.output_digest):
            return False
        expected = compute_receipt_digest(
            receipt_id=self.receipt_id,
            artifact_id=self.artifact_id,
            selected_scopes=tuple(self.selected_scopes),
            policy_revision=self.policy_revision,
            output_digest=self.output_digest,
            completed_at_epoch_seconds=self.completed_at_epoch_seconds,
            entry_count=self.entry_count,
            payload_bytes=self.payload_bytes,
            compress=self.compress,
            rollout_phase=self.rollout_phase,
            redaction_version=self.redaction_version,
            safety_signature=self.safety_signature,
            schema_version=self.schema_version,
        )
        return hmac.compare_digest(self.receipt_digest, expected)


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
    receipt_id: Optional[str] = None
    selected_scopes: Tuple[str, ...] = field(default_factory=lambda: (DEFAULT_EXPORT_SCOPE,))
    policy_revision: str = EXPORT_POLICY_REVISION
    output_digest: Optional[str] = None


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
        self._receipts: Dict[str, ExportCompletionReceipt] = {}
        self._receipt_by_artifact: Dict[str, str] = {}
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

    def generate_receipt_id(self) -> str:
        random_bytes = os.urandom(32)
        timestamp = str(time.time()).encode("utf-8")
        raw = b"receipt:" + random_bytes + timestamp
        digest = hashlib.sha256(raw).hexdigest()[:16]
        return self._policy.receipt_id_prefix + digest

    def compute_safety_signature(self, entries: List[LogEntry]) -> str:
        sorted_entries = sorted(entries, key=lambda x: x.entry_id)
        parts = []
        for e in sorted_entries:
            sig = e.export_signature or "0"
            parts.append(e.entry_id + ":" + sig)
        payload = "|".join(parts)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
        return self._policy.safety_signature_prefix + digest

    def create_export_with_receipt(
        self,
        entries: Optional[List[LogEntry]] = None,
        exported_by_tag: Optional[str] = None,
        compress: Optional[bool] = None,
        rollout_phase: str = "shadow",
        export_token_verified: bool = False,
        *,
        selected_scopes: Optional[Sequence[str]] = None,
        policy_revision: Optional[str] = None,
    ) -> Tuple[Optional[ExportArtifact], str, int, Optional[ExportCompletionReceipt]]:
        with self._lock:
            policy = self._policy
            validated_scopes = validate_receipt_scopes(selected_scopes)
            validated_revision = validate_policy_revision(
                policy_revision,
                default=policy.policy_revision,
            )
            if not export_token_verified and policy.require_export_token and not policy.allow_unauthenticated_export_shadow_mode:
                return None, "export_token_required", 0, None
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
            encoded_payload = serialized.encode("utf-8")
            payload_bytes = len(encoded_payload)
            full_digest_hex = hashlib.sha256(encoded_payload).hexdigest()
            checksum = full_digest_hex[:16]
            output_digest = f"sha256:{full_digest_hex}"
            completed_at = time.time()
            artifact_id = self.generate_export_id()
            receipt_id = self.generate_receipt_id()
            redaction_version = "harpocrates-redaction-v1"
            receipt_digest = compute_receipt_digest(
                receipt_id=receipt_id,
                artifact_id=artifact_id,
                selected_scopes=validated_scopes,
                policy_revision=validated_revision,
                output_digest=output_digest,
                completed_at_epoch_seconds=completed_at,
                entry_count=count,
                payload_bytes=payload_bytes,
                compress=use_compress,
                rollout_phase=rollout_phase,
                redaction_version=redaction_version,
                safety_signature=safety_sig,
                schema_version=EXPORT_FORMAT_VERSION,
            )
            receipt = ExportCompletionReceipt(
                receipt_id=receipt_id,
                artifact_id=artifact_id,
                selected_scopes=validated_scopes,
                policy_revision=validated_revision,
                output_digest=output_digest,
                completed_at_epoch_seconds=completed_at,
                entry_count=count,
                payload_bytes=payload_bytes,
                compress=use_compress,
                rollout_phase=rollout_phase,
                redaction_version=redaction_version,
                safety_signature=safety_sig,
                schema_version=EXPORT_FORMAT_VERSION,
                receipt_digest=receipt_digest,
            )
            artifact = ExportArtifact(
                artifact_id=artifact_id,
                generated_at_epoch_seconds=completed_at,
                entry_count=count,
                payload_bytes=payload_bytes,
                compress=use_compress,
                exported_by_tag=exported_by_tag if export_token_verified else None,
                safety_signature=safety_sig,
                checksum_sha256_prefix16=checksum,
                rollout_phase=rollout_phase,
                redaction_version=redaction_version,
                encryption_at_rest=False,
                receipt_id=receipt_id,
                selected_scopes=validated_scopes,
                policy_revision=validated_revision,
                output_digest=output_digest,
            )
            if len(self._artifacts) >= self._max_artifacts_memory:
                if self._artifact_queue:
                    oldest_id = self._artifact_queue.pop(0)
                    self._artifacts.pop(oldest_id, None)
                    oldest_rcpt = self._receipt_by_artifact.pop(oldest_id, None)
                    if oldest_rcpt is not None:
                        self._receipts.pop(oldest_rcpt, None)
            self._artifacts[artifact_id] = artifact
            self._artifact_queue.append(artifact_id)
            self._receipts[receipt_id] = receipt
            self._receipt_by_artifact[artifact_id] = receipt_id
            return artifact, serialized, count, receipt

    def create_export(
        self,
        entries: Optional[List[LogEntry]] = None,
        exported_by_tag: Optional[str] = None,
        compress: Optional[bool] = None,
        rollout_phase: str = "shadow",
        export_token_verified: bool = False,
        *,
        selected_scopes: Optional[Sequence[str]] = None,
        policy_revision: Optional[str] = None,
    ) -> Tuple[Optional[ExportArtifact], str, int]:
        artifact, serialized, count, _receipt = self.create_export_with_receipt(
            entries=entries,
            exported_by_tag=exported_by_tag,
            compress=compress,
            rollout_phase=rollout_phase,
            export_token_verified=export_token_verified,
            selected_scopes=selected_scopes,
            policy_revision=policy_revision,
        )
        return artifact, serialized, count

    def get_artifact(self, artifact_id: str) -> Optional[ExportArtifact]:
        with self._lock:
            return self._artifacts.get(artifact_id)

    def get_receipt(self, receipt_id: str) -> Optional[ExportCompletionReceipt]:
        with self._lock:
            return self._receipts.get(receipt_id)

    def get_receipt_for_artifact(self, artifact_id: str) -> Optional[ExportCompletionReceipt]:
        with self._lock:
            receipt_id = self._receipt_by_artifact.get(artifact_id)
            if receipt_id is None:
                return None
            return self._receipts.get(receipt_id)

    def list_receipts(self, limit: int = 50) -> List[ExportCompletionReceipt]:
        with self._lock:
            result: List[ExportCompletionReceipt] = []
            for aid in reversed(self._artifact_queue):
                if len(result) >= limit:
                    break
                rid = self._receipt_by_artifact.get(aid)
                if rid is not None:
                    rcpt = self._receipts.get(rid)
                    if rcpt is not None:
                        result.append(rcpt)
            return result

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
                rid = self._receipt_by_artifact.pop(artifact_id, None)
                if rid is not None:
                    self._receipts.pop(rid, None)
                return True
            return False

    def reset(self) -> None:
        with self._lock:
            self._artifacts.clear()
            self._artifact_queue.clear()
            self._receipts.clear()
            self._receipt_by_artifact.clear()
