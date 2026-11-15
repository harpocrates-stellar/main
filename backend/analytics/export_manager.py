from __future__ import annotations

import hashlib
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

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

ALLOWED_ANALYTICS_DIMENSIONS: FrozenSet[str] = frozenset({
    "endpoint",
    "endpoint_pattern",
    "method",
    "status",
    "status_code",
    "error_code",
    "error_type",
    "category",
    "operation",
    "operation_status",
    "lifecycle_state",
    "retry_attempt",
    "source",
    "version",
    "schema",
    "rollout",
    "rollout_phase",
    "service",
    "severity",
})

_ENDPOINT_DIMENSION_KEYS = frozenset({"endpoint", "endpoint_pattern"})
_MAX_DIMENSION_VALUE_BYTES = 128

_HEX_DIGEST_RE = re.compile(r"(?:^|[^A-Za-z0-9])(?:0x)?[0-9a-fA-F]{16,}(?:$|[^A-Za-z0-9])")
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_PREFIXED_HASH_RE = re.compile(
    r"(?i)\b(?:sha256|sha384|sha512|sha1|md5|blake2b|blake3|keccak|poseidon|cid)[:_/-][A-Za-z0-9+/=_-]{6,}"
)
_CID_RE = re.compile(r"\b(?:Qm[1-9A-HJ-NP-Za-km-z]{44}|bafy[a-z2-7]{32,})\b")
_STELLAR_ACCOUNT_OR_SEED_RE = re.compile(r"\b[GSM][A-Z2-7]{55,68}\b")
_BASE64_DIGEST_RE = re.compile(r"^(?=[A-Za-z0-9+/_-]*[0-9])(?=[A-Za-z0-9+/_-]*[A-Za-z])[A-Za-z0-9+/]{24,}={0,2}$")

_FILENAME_EXTENSION_RE = re.compile(
    r"(?i)(?:^|[\s/\\:_.-])[A-Za-z0-9_.-]{1,128}\."
    r"(?:mp4|mov|mkv|avi|webm|m4v|flv|wmv|mpg|mpeg|3gp|"
    r"wav|mp3|flac|ogg|m4a|aac|opus|"
    r"png|jpg|jpeg|gif|webp|bmp|tiff|tif|heic|svg|raw|"
    r"pdf|doc|docx|txt|csv|log|json|jsonl|xml|yaml|yml|"
    r"bin|dat|proof|wtns|noir|acir|vk|pk|"
    r"zip|gz|tgz|tar|bz2|xz|7z|rar|"
    r"db|sqlite|sqlite3|env|pem|key)(?:$|[\s?#])"
)
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]|\\\\")
_SAFE_PARAMETERIZED_SEGMENT_RE = re.compile(
    r"^(?:[A-Za-z0-9_-]{1,32}|<[A-Za-z0-9_]{1,32}>|\{[A-Za-z0-9_]{1,32}\})$"
)
_SAFE_LABEL_VALUE_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")


class EvidenceDimensionError(ValueError):
    """Raised when an analytics dimension key or value risks identifying uploaded evidence."""

    def __init__(self, message: str, *, code: str, dimension_key: str) -> None:
        self.code = code
        self.dimension_key = dimension_key
        super().__init__(f"{message} (code={code}, dimension={dimension_key})")

    def to_dict(self) -> Dict[str, str]:
        return {
            "code": self.code,
            "dimension": self.dimension_key,
        }


def _looks_like_hash_or_digest(value: str) -> bool:
    if _PREFIXED_HASH_RE.search(value):
        return True
    if _CID_RE.search(value):
        return True
    if _UUID_RE.search(value):
        return True
    if _STELLAR_ACCOUNT_OR_SEED_RE.search(value):
        return True
    if _HEX_DIGEST_RE.search(value):
        return True
    for token in re.split(r"[/:\s]+", value):
        if len(token) >= 24 and "_" not in token and "-" not in token:
            if _BASE64_DIGEST_RE.match(token):
                return True
    return False


def _looks_like_raw_filename_or_path(key: str, value: str) -> bool:
    if "\\" in value or _WINDOWS_DRIVE_RE.search(value):
        return True
    if ".." in value or "?" in value or "#" in value:
        return True
    if _FILENAME_EXTENSION_RE.search(value):
        return True

    if key in _ENDPOINT_DIMENSION_KEYS:
        if not value.startswith("/"):
            return True
        segments = [seg for seg in value.split("/") if seg]
        for seg in segments:
            if "." in seg:
                return True
            if not _SAFE_PARAMETERIZED_SEGMENT_RE.match(seg):
                return True
        return False

    if "/" in value:
        return True
    return False


def validate_dimension_value(key: str, raw_value: Any) -> str:
    """Validate a single dimension value, rejecting hashes, digests, and raw filenames/paths."""
    if isinstance(raw_value, bool) or raw_value is None:
        raise EvidenceDimensionError(
            "dimension value must be a non-empty string or integer",
            code="invalid_dimension_value",
            dimension_key=key,
        )
    value = str(raw_value) if isinstance(raw_value, int) else raw_value
    if not isinstance(value, str) or not value.strip():
        raise EvidenceDimensionError(
            "dimension value must be a non-empty string",
            code="invalid_dimension_value",
            dimension_key=key,
        )
    if len(value.encode("utf-8")) > _MAX_DIMENSION_VALUE_BYTES:
        raise EvidenceDimensionError(
            "dimension value exceeds byte cap",
            code="dimension_value_too_long",
            dimension_key=key,
        )
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise EvidenceDimensionError(
            "dimension value contains control characters",
            code="invalid_dimension_value",
            dimension_key=key,
        )

    # Check filename/path and hash patterns BEFORE generic character checks so error codes are specific
    if _looks_like_raw_filename_or_path(key, value):
        raise EvidenceDimensionError(
            "raw filenames and unparameterized paths are forbidden as metric labels",
            code="filename_dimension_value",
            dimension_key=key,
        )
    if _looks_like_hash_or_digest(value):
        raise EvidenceDimensionError(
            "hashes and cryptographic digests are forbidden as metric labels",
            code="hash_like_dimension_value",
            dimension_key=key,
        )
    if key not in _ENDPOINT_DIMENSION_KEYS and not _SAFE_LABEL_VALUE_RE.match(value):
        raise EvidenceDimensionError(
            "dimension value contains disallowed characters",
            code="invalid_dimension_value",
            dimension_key=key,
        )
    return value


def validate_analytics_dimensions(
    dimensions: Mapping[str, Any],
    *,
    allowed_vocabulary: FrozenSet[str] = ALLOWED_ANALYTICS_DIMENSIONS,
) -> Dict[str, str]:
    """Validate dimension keys against the allowed vocabulary and reject evidence-identifying values."""
    if not isinstance(dimensions, Mapping):
        raise EvidenceDimensionError(
            "dimensions must be a mapping",
            code="invalid_dimensions_mapping",
            dimension_key="<root>",
        )
    validated: Dict[str, str] = {}
    for raw_key, raw_val in dimensions.items():
        if not isinstance(raw_key, str) or raw_key not in allowed_vocabulary:
            safe_key_ref = raw_key[:32] if isinstance(raw_key, str) and raw_key.isidentifier() else "<disallowed>"
            raise EvidenceDimensionError(
                "analytics dimension key is outside the allowed vocabulary",
                code="disallowed_dimension_key",
                dimension_key=safe_key_ref,
            )
        validated[raw_key] = validate_dimension_value(raw_key, raw_val)
    return validated


def validate_dimension_vocabulary(
    dimension_keys: Iterable[str],
    *,
    allowed_vocabulary: FrozenSet[str] = ALLOWED_ANALYTICS_DIMENSIONS,
) -> Tuple[str, ...]:
    keys_list: List[str] = []
    for key in dimension_keys:
        if not isinstance(key, str) or key not in allowed_vocabulary:
            safe_key_ref = key[:32] if isinstance(key, str) and key.isidentifier() else "<disallowed>"
            raise EvidenceDimensionError(
                "analytics dimension key is outside the allowed vocabulary",
                code="disallowed_dimension_key",
                dimension_key=safe_key_ref,
            )
        if key not in keys_list:
            keys_list.append(key)
    if not keys_list:
        raise EvidenceDimensionError(
            "at least one allowed dimension key is required for aggregation",
            code="empty_dimension_selection",
            dimension_key="<empty>",
        )
    return tuple(keys_list)


def entry_has_evidence_identifying_labels(entry: LogEntry) -> bool:
    """Return True if a LogEntry carries any hash-like or filename-like label or endpoint."""
    if entry.endpoint_pattern:
        try:
            validate_dimension_value("endpoint_pattern", entry.endpoint_pattern)
        except EvidenceDimensionError:
            return True
    for lk, lv in (entry.labels or {}).items():
        if not isinstance(lk, str):
            return True
        check_key = lk if lk in _ENDPOINT_DIMENSION_KEYS else "category"
        try:
            validate_dimension_value(check_key, lv)
        except EvidenceDimensionError:
            return True
    return False


def _extract_entry_dimension_value(entry: LogEntry, key: str) -> Optional[Any]:
    if key in entry.labels:
        return entry.labels[key]
    attr_map = {
        "endpoint": entry.endpoint_pattern,
        "endpoint_pattern": entry.endpoint_pattern,
        "method": entry.method,
        "status": entry.status_code,
        "status_code": entry.status_code,
        "error_code": entry.error_code,
        "error_type": entry.error_type,
        "category": entry.category,
        "operation_status": entry.operation_status,
        "lifecycle_state": entry.lifecycle_state,
        "source": entry.source,
        "version": entry.schema_version,
        "schema": entry.schema_version,
        "severity": entry.severity,
    }
    return attr_map.get(key)


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

    def aggregate_by_dimensions(
        self,
        group_by: Sequence[str],
        entries: Optional[List[LogEntry]] = None,
    ) -> Dict[Tuple[Tuple[str, str], ...], int]:
        """Validate dimension vocabulary and values before aggregating entry counts."""
        canonical_keys = validate_dimension_vocabulary(group_by)

        with self._lock:
            if entries is not None:
                source_entries = list(entries)
            elif self._processor is not None:
                source_entries = list(self._processor._entries[:])
            else:
                source_entries = []

        # Validate every record's dimensions BEFORE mutating any aggregation bucket
        staged_keys: List[Tuple[Tuple[str, str], ...]] = []
        for entry in source_entries:
            # First ensure all labels attached to the entry obey allowed vocabulary & value rules
            if entry.labels:
                validate_analytics_dimensions(entry.labels)
            dim_map: Dict[str, Any] = {}
            for key in canonical_keys:
                val = _extract_entry_dimension_value(entry, key)
                dim_map[key] = val if (val is not None and val != "") else "unspecified"
            validated_dims = validate_analytics_dimensions(dim_map)
            staged_keys.append(tuple((k, validated_dims[k]) for k in canonical_keys))

        counts: Dict[Tuple[Tuple[str, str], ...], int] = {}
        for bucket_key in staged_keys:
            counts[bucket_key] = counts.get(bucket_key, 0) + 1
        return counts

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
            entries_filtered = [
                e for e in entries_filtered if not entry_has_evidence_identifying_labels(e)
            ]
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
