from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

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
    from analytics.redaction import (
        DEFAULT_CAP_BYTES,
        RedactionConfig,
        RedactionEngine,
        RedactionPatterns,
        SENSITIVE_FIELD_CATEGORIES,
        stable_encode_key,
    )
except Exception:
    try:
        from backend.analytics.redaction import (
            DEFAULT_CAP_BYTES,
            RedactionConfig,
            RedactionEngine,
            RedactionPatterns,
            SENSITIVE_FIELD_CATEGORIES,
            stable_encode_key,
        )
    except Exception:
        DEFAULT_CAP_BYTES = 256
        RedactionConfig = None  # type: ignore[assignment]
        RedactionEngine = None  # type: ignore[assignment]
        RedactionPatterns = None  # type: ignore[assignment]
        SENSITIVE_FIELD_CATEGORIES = {}
        stable_encode_key = lambda k: str(k).lower()  # noqa: E731


EXPORT_FORMAT_VERSION = "1.0.0"

_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_SYNTHETIC_MARKER_KEYS = ("_synthetic", "synthetic", "dataset_origin")
_FORBIDDEN_PROD_PATTERNS = (
    re.compile(r"\bS[A-Z2-7]{55}\b"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bpostgres(?:ql)?://[^\s]+"),
)


class SyntheticFixtureError(ValueError):
    """Raised when non-synthetic or credential-bearing records are passed to policy comparison."""


def _scan_record_for_forbidden_material(node: Any) -> None:
    if isinstance(node, (bytes, bytearray, memoryview)):
        raise SyntheticFixtureError("binary media or byte payloads are forbidden in synthetic fixtures")
    if isinstance(node, str):
        for pat in _FORBIDDEN_PROD_PATTERNS:
            if pat.search(node):
                raise SyntheticFixtureError(
                    "credential or live connection material is forbidden in synthetic fixtures"
                )
        return
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str):
                _scan_record_for_forbidden_material(k)
            _scan_record_for_forbidden_material(v)
        return
    if isinstance(node, (list, tuple)):
        for item in node:
            _scan_record_for_forbidden_material(item)


def validate_synthetic_analytics_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure a comparison input record is explicitly synthetic and contains no live secrets."""
    if not isinstance(record, dict) or not record:
        raise SyntheticFixtureError("synthetic analytics record must be a non-empty dict")

    env_val = str(record.get("environment", "")).strip().lower()
    origin_val = str(record.get("dataset_origin", "")).strip().lower()
    if env_val in {"prod", "production", "live"} or origin_val in {"prod", "production", "live"}:
        raise SyntheticFixtureError("production analytics records are forbidden in policy comparison")

    is_synthetic = (
        record.get("_synthetic") is True
        or record.get("synthetic") is True
        or origin_val == "synthetic"
    )
    if not is_synthetic:
        raise SyntheticFixtureError(
            "analytics record must explicitly declare synthetic=True or dataset_origin='synthetic'"
        )

    _scan_record_for_forbidden_material(record)

    stripped = {
        k: copy.deepcopy(v)
        for k, v in record.items()
        if k not in _SYNTHETIC_MARKER_KEYS and k != "environment"
    }
    if not stripped:
        raise SyntheticFixtureError("synthetic analytics record has no evaluable fields")
    return stripped


def build_default_synthetic_analytics_records() -> List[Dict[str, Any]]:
    """Construct runtime-only synthetic records without committing production fixtures."""
    return [
        {
            "_synthetic": True,
            "operation": "proof_verify",
            "status_code": 200,
            "endpoint": "/api/proofs/verify",
            "client_region": "synthetic-region-01",
            "device_fingerprint": "synthetic-fp-placeholder",
            "auth": {
                "token": "synthetic-token-placeholder",
                "session_hint": "synthetic-session-hint",
            },
            "evidence": {
                "witness_data": "synthetic-witness-placeholder",
                "codec_profile": "synthetic-h264-baseline",
            },
        },
        {
            "_synthetic": True,
            "operation": "worker_dispatch",
            "status_code": 202,
            "endpoint": "/api/jobs",
            "operator_note": "synthetic-operator-note",
            "debug_context": {
                "retry_budget": 2,
                "internal_host_label": "synthetic-worker-node-a",
            },
        },
    ]


@dataclass
class RedactionPolicySpec:
    """Declarative redaction policy revision for synthetic comparison."""

    revision: str
    extra_sensitive_fields: Dict[str, List[str]] = field(default_factory=dict)
    dropped_fields: List[str] = field(default_factory=list)
    exempt_fields: List[str] = field(default_factory=list)
    cap_bytes: int = DEFAULT_CAP_BYTES

    def __post_init__(self) -> None:
        if not isinstance(self.revision, str) or not _REVISION_RE.match(self.revision):
            raise ValueError(f"invalid redaction policy revision: {self.revision!r}")

    def _build_engine(self) -> Any:
        if RedactionPatterns is None or RedactionConfig is None or RedactionEngine is None:
            raise RuntimeError("RedactionEngine is required for policy comparison")

        patterns = RedactionPatterns.build()
        exempt_encoded = {stable_encode_key(f) for f in self.exempt_fields if isinstance(f, str)}

        merged_categories: Dict[str, Set[str]] = {}
        for cat, hints in SENSITIVE_FIELD_CATEGORIES.items():
            encoded_set = {stable_encode_key(h) for h in hints} - exempt_encoded
            merged_categories[cat] = encoded_set

        for cat, extra_hints in self.extra_sensitive_fields.items():
            target = merged_categories.setdefault(cat, set())
            for hint in extra_hints:
                enc = stable_encode_key(hint)
                if enc and enc not in exempt_encoded:
                    target.add(enc)

        for cat, encoded_hints in merged_categories.items():
            patterns.stable_hints_by_category[cat] = set(encoded_hints)
            escaped = sorted(re.escape(h) for h in encoded_hints if h)
            if escaped:
                patterns.sensitive_field_regexes[cat] = re.compile(
                    "(" + "|".join(escaped) + ")", re.IGNORECASE
                )
            else:
                patterns.sensitive_field_regexes[cat] = re.compile(r"a^")

        config = RedactionConfig(patterns=patterns, cap_bytes=self.cap_bytes)
        return RedactionEngine(config=config)

    def apply_to_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        dropped_encoded = {stable_encode_key(f) for f in self.dropped_fields if isinstance(f, str)}
        exempt_encoded = {stable_encode_key(f) for f in self.exempt_fields if isinstance(f, str)}

        def _prune_dropped(obj: Any, prefix: str = "") -> Any:
            if isinstance(obj, dict):
                pruned: Dict[str, Any] = {}
                for k, v in obj.items():
                    key_str = str(k)
                    dotted = f"{prefix}.{key_str}" if prefix else key_str
                    if (
                        key_str in self.dropped_fields
                        or dotted in self.dropped_fields
                        or stable_encode_key(key_str) in dropped_encoded
                    ):
                        continue
                    pruned[key_str] = _prune_dropped(v, dotted)
                return pruned
            if isinstance(obj, list):
                return [_prune_dropped(item, prefix) for item in obj]
            return copy.deepcopy(obj)

        working = _prune_dropped(record)
        engine = self._build_engine()
        sanitized = engine.sanitize(working).data

        if exempt_encoded:
            def _restore_exempt(orig: Any, san: Any, prefix: str = "") -> Any:
                if isinstance(orig, dict) and isinstance(san, dict):
                    out: Dict[str, Any] = {}
                    for k, sv in san.items():
                        dotted = f"{prefix}.{k}" if prefix else k
                        if (
                            k in self.exempt_fields
                            or dotted in self.exempt_fields
                            or stable_encode_key(k) in exempt_encoded
                        ) and k in orig:
                            out[k] = copy.deepcopy(orig[k])
                        else:
                            out[k] = _restore_exempt(orig.get(k), sv, dotted)
                    return out
                return san

            sanitized = _restore_exempt(working, sanitized)

        return sanitized


@dataclass(frozen=True)
class FieldPolicyTransition:
    field_path: str
    baseline_state: str
    candidate_state: str


@dataclass(frozen=True)
class RedactionPolicyComparisonReport:
    baseline_revision: str
    candidate_revision: str
    records_evaluated: int
    newly_removed_fields: List[str]
    newly_exposed_fields: List[str]
    unchanged_protected_fields: List[str]
    unchanged_exposed_fields: List[str]
    field_transitions: List[FieldPolicyTransition]

    @property
    def has_exposure_regression(self) -> bool:
        return len(self.newly_exposed_fields) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "baseline_revision": self.baseline_revision,
            "candidate_revision": self.candidate_revision,
            "records_evaluated": self.records_evaluated,
            "has_exposure_regression": self.has_exposure_regression,
            "newly_removed_fields": list(self.newly_removed_fields),
            "newly_exposed_fields": list(self.newly_exposed_fields),
            "unchanged_protected_fields": list(self.unchanged_protected_fields),
            "unchanged_exposed_fields": list(self.unchanged_exposed_fields),
            "field_transitions": [
                {
                    "field_path": t.field_path,
                    "baseline_state": t.baseline_state,
                    "candidate_state": t.candidate_state,
                }
                for t in self.field_transitions
            ],
        }


def _collect_leaf_paths(obj: Any, prefix: str = "") -> Set[str]:
    paths: Set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_str = str(k)
            dotted = f"{prefix}.{key_str}" if prefix else key_str
            if isinstance(v, dict) and v:
                paths.update(_collect_leaf_paths(v, dotted))
            else:
                paths.add(dotted)
    return paths


def _lookup_path_state(sanitized_record: Dict[str, Any], path: str) -> str:
    cur: Any = sanitized_record
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return "omitted"
        cur = cur[part]
    if isinstance(cur, str) and cur.startswith("[REDACTED"):
        return "redacted"
    if isinstance(cur, list) and cur and all(isinstance(x, str) and x.startswith("[REDACTED") for x in cur):
        return "redacted"
    return "exposed"


def _merge_field_states(states: Set[str]) -> str:
    # Conservative aggregation across multiple synthetic records:
    # if a field is exposed in any synthetic record, treat its policy state as exposed.
    if "exposed" in states:
        return "exposed"
    if "redacted" in states:
        return "redacted"
    return "omitted"


def compare_redaction_policies(
    baseline_policy: RedactionPolicySpec,
    candidate_policy: RedactionPolicySpec,
    synthetic_records: Optional[Iterable[Dict[str, Any]]] = None,
) -> RedactionPolicyComparisonReport:
    """Compare two redaction policy revisions against validated synthetic records only."""
    if not isinstance(baseline_policy, RedactionPolicySpec) or not isinstance(
        candidate_policy, RedactionPolicySpec
    ):
        raise TypeError("baseline_policy and candidate_policy must be RedactionPolicySpec instances")

    raw_records = (
        list(synthetic_records)
        if synthetic_records is not None
        else build_default_synthetic_analytics_records()
    )
    if not raw_records:
        raise SyntheticFixtureError("at least one synthetic analytics record is required")

    validated_records = [validate_synthetic_analytics_record(rec) for rec in raw_records]

    baseline_states_by_field: Dict[str, Set[str]] = {}
    candidate_states_by_field: Dict[str, Set[str]] = {}

    for rec in validated_records:
        leaf_paths = _collect_leaf_paths(rec)
        base_out = baseline_policy.apply_to_record(rec)
        cand_out = candidate_policy.apply_to_record(rec)
        for path in leaf_paths:
            baseline_states_by_field.setdefault(path, set()).add(_lookup_path_state(base_out, path))
            candidate_states_by_field.setdefault(path, set()).add(_lookup_path_state(cand_out, path))

    newly_removed: List[str] = []
    newly_exposed: List[str] = []
    unchanged_protected: List[str] = []
    unchanged_exposed: List[str] = []
    transitions: List[FieldPolicyTransition] = []

    for path in sorted(baseline_states_by_field.keys()):
        b_state = _merge_field_states(baseline_states_by_field[path])
        c_state = _merge_field_states(candidate_states_by_field[path])

        b_protected = b_state in {"redacted", "omitted"}
        c_protected = c_state in {"redacted", "omitted"}

        if not b_protected and c_protected:
            newly_removed.append(path)
            transitions.append(FieldPolicyTransition(path, b_state, c_state))
        elif b_state == "redacted" and c_state == "omitted":
            newly_removed.append(path)
            transitions.append(FieldPolicyTransition(path, b_state, c_state))
        elif b_protected and not c_protected:
            newly_exposed.append(path)
            transitions.append(FieldPolicyTransition(path, b_state, c_state))
        elif b_protected and c_protected:
            unchanged_protected.append(path)
            if b_state != c_state:
                transitions.append(FieldPolicyTransition(path, b_state, c_state))
        else:
            unchanged_exposed.append(path)

    return RedactionPolicyComparisonReport(
        baseline_revision=baseline_policy.revision,
        candidate_revision=candidate_policy.revision,
        records_evaluated=len(validated_records),
        newly_removed_fields=newly_removed,
        newly_exposed_fields=newly_exposed,
        unchanged_protected_fields=unchanged_protected,
        unchanged_exposed_fields=unchanged_exposed,
        field_transitions=transitions,
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

    def compare_redaction_policies(
        self,
        baseline_policy: RedactionPolicySpec,
        candidate_policy: RedactionPolicySpec,
        synthetic_records: Optional[Iterable[Dict[str, Any]]] = None,
    ) -> RedactionPolicyComparisonReport:
        return compare_redaction_policies(
            baseline_policy=baseline_policy,
            candidate_policy=candidate_policy,
            synthetic_records=synthetic_records,
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
