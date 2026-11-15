from __future__ import annotations

import hashlib
import math
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
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
    from analytics.consent import ConsentManager
except Exception:
    try:
        from backend.analytics.consent import ConsentManager
    except Exception:
        ConsentManager = None  # type: ignore[assignment]


EXPORT_FORMAT_VERSION = "1.0.0"
DEFAULT_MAX_EXPORT_RANGE_SECONDS = 30 * 86_400  # 30 days (2,592,000s)
MAX_SUPPORTED_UTC_EPOCH_SECONDS = 253_402_300_799.0  # 9999-12-31T23:59:59Z


class ExportDateRangeError(ValueError):
    """Validation error exposing deterministic UTC boundaries for invalid export intervals."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        start_utc: Optional[str] = None,
        end_utc: Optional[str] = None,
        allowed_start_utc: Optional[str] = None,
        allowed_end_utc: Optional[str] = None,
        max_range_seconds: int = DEFAULT_MAX_EXPORT_RANGE_SECONDS,
    ) -> None:
        self.code = code
        self.detail_message = message
        self.start_utc = start_utc
        self.end_utc = end_utc
        self.allowed_start_utc = allowed_start_utc
        self.allowed_end_utc = allowed_end_utc
        self.max_range_seconds = int(max_range_seconds)
        boundary_parts = [f"code={code}"]
        if start_utc is not None:
            boundary_parts.append(f"start_utc={start_utc}")
        if end_utc is not None:
            boundary_parts.append(f"end_utc={end_utc}")
        if allowed_start_utc is not None:
            boundary_parts.append(f"allowed_start_utc={allowed_start_utc}")
        if allowed_end_utc is not None:
            boundary_parts.append(f"allowed_end_utc={allowed_end_utc}")
        boundary_parts.append(f"max_range_seconds={self.max_range_seconds}")
        super().__init__(f"{message} ({', '.join(boundary_parts)})")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": self.detail_message,
            "start_utc": self.start_utc,
            "end_utc": self.end_utc,
            "allowed_start_utc": self.allowed_start_utc,
            "allowed_end_utc": self.allowed_end_utc,
            "max_range_seconds": self.max_range_seconds,
        }


def format_utc_iso8601(epoch_seconds: float) -> str:
    """Format an epoch timestamp deterministically as ISO-8601 UTC (`...Z`)."""
    dt = datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc)
    if dt.microsecond:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc_timestamp(
    value: Any,
    *,
    field_name: str,
    max_range_seconds: int = DEFAULT_MAX_EXPORT_RANGE_SECONDS,
) -> float:
    """Parse an epoch number, timezone-aware datetime, or explicit-TZ ISO-8601 string into UTC epoch seconds."""
    if isinstance(value, bool) or value is None:
        raise ExportDateRangeError(
            f"{field_name} must be a finite UTC timestamp",
            code="invalid_timestamp",
            allowed_start_utc="1970-01-01T00:00:00Z",
            allowed_end_utc="9999-12-31T23:59:59Z",
            max_range_seconds=max_range_seconds,
        )

    if isinstance(value, datetime):
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ExportDateRangeError(
                f"{field_name} datetime must include an explicit timezone",
                code="timezone_required",
                allowed_start_utc="1970-01-01T00:00:00Z",
                allowed_end_utc="9999-12-31T23:59:59Z",
                max_range_seconds=max_range_seconds,
            )
        epoch = value.astimezone(timezone.utc).timestamp()
    elif isinstance(value, (int, float)):
        epoch = float(value)
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise ExportDateRangeError(
                f"{field_name} timestamp string must not be empty",
                code="invalid_timestamp",
                allowed_start_utc="1970-01-01T00:00:00Z",
                allowed_end_utc="9999-12-31T23:59:59Z",
                max_range_seconds=max_range_seconds,
            )
        normalized = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
        try:
            parsed_dt = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ExportDateRangeError(
                f"{field_name} must be a valid ISO-8601 timestamp",
                code="invalid_timestamp",
                allowed_start_utc="1970-01-01T00:00:00Z",
                allowed_end_utc="9999-12-31T23:59:59Z",
                max_range_seconds=max_range_seconds,
            ) from exc
        if parsed_dt.tzinfo is None or parsed_dt.tzinfo.utcoffset(parsed_dt) is None:
            raise ExportDateRangeError(
                f"{field_name} ISO-8601 timestamp must specify UTC ('Z') or an explicit offset",
                code="timezone_required",
                allowed_start_utc="1970-01-01T00:00:00Z",
                allowed_end_utc="9999-12-31T23:59:59Z",
                max_range_seconds=max_range_seconds,
            )
        epoch = parsed_dt.astimezone(timezone.utc).timestamp()
    else:
        raise ExportDateRangeError(
            f"{field_name} has unsupported timestamp type",
            code="invalid_timestamp",
            allowed_start_utc="1970-01-01T00:00:00Z",
            allowed_end_utc="9999-12-31T23:59:59Z",
            max_range_seconds=max_range_seconds,
        )

    if not math.isfinite(epoch) or epoch < 0.0 or epoch > MAX_SUPPORTED_UTC_EPOCH_SECONDS:
        raise ExportDateRangeError(
            f"{field_name} is outside supported UTC range",
            code="invalid_timestamp",
            allowed_start_utc="1970-01-01T00:00:00Z",
            allowed_end_utc="9999-12-31T23:59:59Z",
            max_range_seconds=max_range_seconds,
        )
    return epoch


@dataclass(frozen=True)
class ExportDateRange:
    start_epoch_seconds: float
    end_epoch_seconds: float
    start_utc: str
    end_utc: str
    span_seconds: float


def validate_export_date_range(
    start_time: Any,
    end_time: Any,
    *,
    max_range_seconds: int = DEFAULT_MAX_EXPORT_RANGE_SECONDS,
) -> ExportDateRange:
    """Validate an analytics export date interval and return deterministic UTC bounds."""
    if isinstance(max_range_seconds, bool) or not isinstance(max_range_seconds, int) or max_range_seconds <= 0:
        raise ValueError("max_range_seconds must be a positive integer")

    if start_time is None and end_time is not None:
        end_ep = parse_utc_timestamp(end_time, field_name="end_time", max_range_seconds=max_range_seconds)
        end_str = format_utc_iso8601(end_ep)
        min_start_ep = max(0.0, end_ep - max_range_seconds)
        raise ExportDateRangeError(
            "both start_time and end_time are required when bounding an export",
            code="incomplete_date_range",
            start_utc=None,
            end_utc=end_str,
            allowed_start_utc=format_utc_iso8601(min_start_ep),
            allowed_end_utc=end_str,
            max_range_seconds=max_range_seconds,
        )

    if start_time is not None and end_time is None:
        start_ep = parse_utc_timestamp(start_time, field_name="start_time", max_range_seconds=max_range_seconds)
        start_str = format_utc_iso8601(start_ep)
        max_end_ep = min(MAX_SUPPORTED_UTC_EPOCH_SECONDS, start_ep + max_range_seconds)
        raise ExportDateRangeError(
            "both start_time and end_time are required when bounding an export",
            code="incomplete_date_range",
            start_utc=start_str,
            end_utc=None,
            allowed_start_utc=start_str,
            allowed_end_utc=format_utc_iso8601(max_end_ep),
            max_range_seconds=max_range_seconds,
        )

    start_ep = parse_utc_timestamp(start_time, field_name="start_time", max_range_seconds=max_range_seconds)
    end_ep = parse_utc_timestamp(end_time, field_name="end_time", max_range_seconds=max_range_seconds)
    start_str = format_utc_iso8601(start_ep)
    end_str = format_utc_iso8601(end_ep)
    max_allowed_end_ep = min(MAX_SUPPORTED_UTC_EPOCH_SECONDS, start_ep + max_range_seconds)
    max_allowed_end_str = format_utc_iso8601(max_allowed_end_ep)

    if end_ep < start_ep:
        raise ExportDateRangeError(
            "end_time must be greater than or equal to start_time",
            code="contradictory_date_range",
            start_utc=start_str,
            end_utc=end_str,
            allowed_start_utc=start_str,
            allowed_end_utc=max_allowed_end_str,
            max_range_seconds=max_range_seconds,
        )

    span = end_ep - start_ep
    if span > max_range_seconds:
        raise ExportDateRangeError(
            "requested export interval exceeds maximum allowed span",
            code="date_range_too_large",
            start_utc=start_str,
            end_utc=end_str,
            allowed_start_utc=start_str,
            allowed_end_utc=max_allowed_end_str,
            max_range_seconds=max_range_seconds,
        )

    return ExportDateRange(
        start_epoch_seconds=start_ep,
        end_epoch_seconds=end_ep,
        start_utc=start_str,
        end_utc=end_str,
        span_seconds=span,
    )


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
    max_export_range_seconds: int = DEFAULT_MAX_EXPORT_RANGE_SECONDS


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
    window_start_utc: Optional[str] = None
    window_end_utc: Optional[str] = None


class ExportManager:
    def __init__(
        self,
        policy: Optional[ExportPolicy] = None,
        processor: Optional[LogProcessor] = None,
        max_artifacts_memory: int = 1024,
        *,
        consent_manager: Optional[ConsentManager] = None,
        storage_query: Optional[Callable[[Optional[float], Optional[float]], List[LogEntry]]] = None,
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
        self._storage_query: Optional[Callable[[Optional[float], Optional[float]], List[LogEntry]]] = storage_query

    def _validate_consent_bounds(
        self,
        account_tag: Optional[str],
        date_range: ExportDateRange,
    ) -> None:
        if self._consent_manager is None or not account_tag:
            return
        bounds = self._consent_manager.get_consent_window_bounds(account_tag)
        if bounds is None:
            return
        consent_start, consent_end = bounds
        if consent_end is not None and consent_start > 0 and consent_end < consent_start:
            raise ExportDateRangeError(
                "stored consent window has contradictory timestamps",
                code="contradictory_consent_window",
                start_utc=date_range.start_utc,
                end_utc=date_range.end_utc,
                allowed_start_utc=format_utc_iso8601(consent_start),
                allowed_end_utc=format_utc_iso8601(consent_start),
                max_range_seconds=self._policy.max_export_range_seconds,
            )
        if (consent_start > 0 and date_range.end_epoch_seconds < consent_start) or (
            consent_end is not None and date_range.start_epoch_seconds > consent_end
        ):
            raise ExportDateRangeError(
                "requested export interval falls outside recorded consent window",
                code="outside_consent_window",
                start_utc=date_range.start_utc,
                end_utc=date_range.end_utc,
                allowed_start_utc=format_utc_iso8601(consent_start),
                allowed_end_utc=(
                    format_utc_iso8601(consent_end) if consent_end is not None else None
                ),
                max_range_seconds=self._policy.max_export_range_seconds,
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
        *,
        start_time: Any = None,
        end_time: Any = None,
    ) -> Tuple[Optional[ExportArtifact], str, int]:
        with self._lock:
            policy = self._policy

            # Validate date bounds BEFORE touching entries, processor buffers, or storage_query!
            validated_range: Optional[ExportDateRange] = None
            if start_time is not None or end_time is not None:
                validated_range = validate_export_date_range(
                    start_time,
                    end_time,
                    max_range_seconds=policy.max_export_range_seconds,
                )
                self._validate_consent_bounds(exported_by_tag, validated_range)

            if not export_token_verified and policy.require_export_token and not policy.allow_unauthenticated_export_shadow_mode:
                return None, "export_token_required", 0

            if entries is not None:
                entries_filtered = list(entries)
            elif self._storage_query is not None:
                entries_filtered = list(
                    self._storage_query(
                        validated_range.start_epoch_seconds if validated_range else None,
                        validated_range.end_epoch_seconds if validated_range else None,
                    )
                )
            elif self._processor is not None:
                entries_filtered = list(self._processor._entries[:])
            else:
                entries_filtered = []

            if validated_range is not None:
                entries_filtered = [
                    e
                    for e in entries_filtered
                    if validated_range.start_epoch_seconds
                    <= e.timestamp_epoch_seconds
                    <= validated_range.end_epoch_seconds
                ]

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
                window_start_utc=validated_range.start_utc if validated_range else None,
                window_end_utc=validated_range.end_utc if validated_range else None,
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
