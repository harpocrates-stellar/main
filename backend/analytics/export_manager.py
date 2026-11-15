from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import threading
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
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
SAFE_EXPORT_FILENAME_PREFIX = "harpocrates-analytics-export-"
MAX_DISPLAY_LABEL_BYTES = 128

_SERVER_PREFIX_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}-$")
_SERVER_FILENAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}-[0-9a-f]{32}\.json(?:\.gz)?$")
_SECRET_LABEL_PATTERNS = (
    re.compile(r"\bS[A-Z2-7]{55}\b"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\b[0-9a-fA-F]{32,}\b"),
)


class ExportDestinationError(ValueError):
    """Raised when an export filesystem destination violates containment or safety rules."""


def allocate_server_export_filename(
    *,
    compress: bool = False,
    prefix: str = SAFE_EXPORT_FILENAME_PREFIX,
) -> str:
    """Allocate a CSPRNG server-controlled filename with zero user-controlled components."""
    if not isinstance(prefix, str) or not _SERVER_PREFIX_RE.match(prefix):
        raise ValueError("unsafe server export filename prefix")
    token_hex = os.urandom(16).hex()
    suffix = ".json.gz" if bool(compress) else ".json"
    candidate = f"{prefix}{token_hex}{suffix}"
    if not _SERVER_FILENAME_RE.match(candidate):
        raise ValueError("generated server export filename failed safety validation")
    return candidate


def _truncate_utf8_bytes(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    return encoded[:max_bytes].decode("utf-8", errors="ignore").rstrip()


def sanitize_display_label(
    display_label: Optional[str],
    *,
    max_bytes: int = MAX_DISPLAY_LABEL_BYTES,
) -> Optional[str]:
    """Sanitize a user-requested display label for inclusion inside authorized output only."""
    if display_label is None:
        return None
    if not isinstance(display_label, str):
        raise ValueError("display_label must be a string or None")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")

    filtered_chars: List[str] = []
    for ch in display_label:
        code = ord(ch)
        if code < 32 or (127 <= code <= 159):
            filtered_chars.append(" ")
            continue
        if unicodedata.category(ch) == "Cf":
            continue
        filtered_chars.append(ch)

    normalized = " ".join("".join(filtered_chars).split())
    if not normalized:
        return None

    for pattern in _SECRET_LABEL_PATTERNS:
        normalized = pattern.sub("[REDACTED]", normalized)

    capped = _truncate_utf8_bytes(normalized, max_bytes)
    return capped if capped else None


def _validate_destination_directory(destination_dir: str | os.PathLike[str]) -> Path:
    if destination_dir is None:
        raise ExportDestinationError("destination_dir is required")
    raw_str = os.fspath(destination_dir)
    if not isinstance(raw_str, str) or not raw_str.strip():
        raise ExportDestinationError("destination_dir must be a non-empty path")
    if "\x00" in raw_str:
        raise ExportDestinationError("destination_dir contains null byte")

    raw_path = Path(raw_str)
    for candidate in (raw_path, *raw_path.parents):
        try:
            if candidate.exists() and candidate.is_symlink():
                raise ExportDestinationError("symlink destination directory is not allowed")
            if candidate.is_symlink():
                raise ExportDestinationError("symlink destination directory is not allowed")
        except OSError as exc:
            raise ExportDestinationError("unable to inspect destination directory") from exc

    if raw_path.exists() and not raw_path.is_dir():
        raise ExportDestinationError("destination_dir must be a directory")

    raw_path.mkdir(parents=True, exist_ok=True)
    if raw_path.is_symlink() or not raw_path.is_dir():
        raise ExportDestinationError("destination_dir failed post-creation directory verification")

    return raw_path.resolve()


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
    export_file_prefix: str = SAFE_EXPORT_FILENAME_PREFIX
    max_display_label_bytes: int = MAX_DISPLAY_LABEL_BYTES


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
    server_filename: str = ""
    display_label: Optional[str] = None

    def to_metadata_dict(self, *, authorized: bool = False) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {
            "artifact_id": self.artifact_id,
            "server_filename": self.server_filename,
            "schema_version": self.schema_version,
            "generated_at_epoch_seconds": self.generated_at_epoch_seconds,
            "entry_count": self.entry_count,
            "payload_bytes": self.payload_bytes,
            "compress": self.compress,
            "payload_type": self.payload_type,
            "safety_signature": self.safety_signature,
            "checksum_sha256_prefix16": self.checksum_sha256_prefix16,
            "rollout_phase": self.rollout_phase,
            "redaction_version": self.redaction_version,
            "encryption_at_rest": self.encryption_at_rest,
        }
        if authorized:
            metadata["exported_by_tag"] = self.exported_by_tag
            metadata["display_label"] = self.display_label
        return metadata


class ExportManager:
    def __init__(
        self,
        policy: Optional[ExportPolicy] = None,
        processor: Optional[LogProcessor] = None,
        max_artifacts_memory: int = 1024,
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

    def _is_output_authorized(
        self,
        *,
        export_token_verified: bool,
        exported_by_tag: Optional[str],
        now_epoch_seconds: Optional[float] = None,
    ) -> bool:
        if not export_token_verified:
            return False
        if self._consent_manager is not None:
            return self._consent_manager.is_export_authorized(
                exported_by_tag,
                now_epoch_seconds=now_epoch_seconds,
            )
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

    def create_export(
        self,
        entries: Optional[List[LogEntry]] = None,
        exported_by_tag: Optional[str] = None,
        compress: Optional[bool] = None,
        rollout_phase: str = "shadow",
        export_token_verified: bool = False,
        display_label: Optional[str] = None,
    ) -> Tuple[Optional[ExportArtifact], str, int]:
        sanitized_label = sanitize_display_label(
            display_label,
            max_bytes=self._policy.max_display_label_bytes,
        )
        with self._lock:
            policy = self._policy
            if not export_token_verified and policy.require_export_token and not policy.allow_unauthenticated_export_shadow_mode:
                return None, "export_token_required", 0

            now = time.time()
            authorized = self._is_output_authorized(
                export_token_verified=export_token_verified,
                exported_by_tag=exported_by_tag,
                now_epoch_seconds=now,
            )

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
            if not authorized:
                entries_filtered = []
            entries_filtered = entries_filtered[:policy.max_artifacts_per_export]
            use_compress = compress if compress is not None else policy.compress_default
            server_filename = allocate_server_export_filename(
                compress=use_compress,
                prefix=policy.export_file_prefix,
            )
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
                generated_at_epoch_seconds=now,
                entry_count=count,
                payload_bytes=payload_bytes,
                compress=use_compress,
                exported_by_tag=exported_by_tag if authorized else None,
                safety_signature=safety_sig,
                checksum_sha256_prefix16=checksum,
                payload_type="application/gzip" if use_compress else "application/json",
                rollout_phase=rollout_phase,
                encryption_at_rest=False,
                server_filename=server_filename,
                display_label=sanitized_label if authorized else None,
            )
            if len(self._artifacts) >= self._max_artifacts_memory:
                if self._artifact_queue:
                    oldest_id = self._artifact_queue.pop(0)
                    self._artifacts.pop(oldest_id, None)
            self._artifacts[artifact_id] = artifact
            self._artifact_queue.append(artifact_id)
            return artifact, serialized, count

    def build_export_envelope(
        self,
        artifact: ExportArtifact,
        serialized: str,
        *,
        authorized: bool = False,
    ) -> Dict[str, Any]:
        envelope: Dict[str, Any] = {
            "metadata": artifact.to_metadata_dict(authorized=authorized),
        }
        if artifact.compress:
            envelope["compressed_records"] = serialized
        else:
            envelope["records"] = json.loads(serialized) if serialized else []
        return envelope

    def write_export_to_directory(
        self,
        destination_dir: str | os.PathLike[str],
        entries: Optional[List[LogEntry]] = None,
        *,
        exported_by_tag: Optional[str] = None,
        compress: Optional[bool] = None,
        rollout_phase: str = "shadow",
        export_token_verified: bool = False,
        display_label: Optional[str] = None,
        requested_filename: Optional[str] = None,
    ) -> Tuple[Optional[ExportArtifact], Optional[Path], str]:
        """Write an export using a server-allocated filename inside destination_dir.

        User-supplied filenames (`requested_filename`) are intentionally ignored for
        filesystem path construction. `display_label` is sanitized and preserved only
        inside the authorized output envelope.
        """
        _ = requested_filename  # Explicitly ignored for filesystem path safety
        resolved_dir = _validate_destination_directory(destination_dir)

        artifact, serialized_or_reason, _ = self.create_export(
            entries=entries,
            exported_by_tag=exported_by_tag,
            compress=compress,
            rollout_phase=rollout_phase,
            export_token_verified=export_token_verified,
            display_label=display_label,
        )
        if artifact is None:
            return None, None, serialized_or_reason

        if not _SERVER_FILENAME_RE.match(artifact.server_filename):
            raise ExportDestinationError("server filename failed strict format validation")

        authorized = self._is_output_authorized(
            export_token_verified=export_token_verified,
            exported_by_tag=exported_by_tag,
            now_epoch_seconds=artifact.generated_at_epoch_seconds,
        )
        envelope = self.build_export_envelope(artifact, serialized_or_reason, authorized=authorized)
        envelope_bytes = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        output_bytes = gzip.compress(envelope_bytes) if artifact.compress else envelope_bytes

        target_path = resolved_dir / artifact.server_filename
        if target_path.parent != resolved_dir or target_path.resolve().parent != resolved_dir:
            raise ExportDestinationError("export target escaped destination directory")

        temp_name = f".tmp-{os.urandom(8).hex()}-{artifact.server_filename}"
        temp_path = resolved_dir / temp_name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        fd = os.open(str(temp_path), flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(output_bytes)
                handle.flush()
            os.replace(str(temp_path), str(target_path))
        except Exception:
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except OSError:
                pass
            raise

        return artifact, target_path, "ok"

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
