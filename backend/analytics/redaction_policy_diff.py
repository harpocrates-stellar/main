from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple, Union

try:
    from analytics.redaction import (
        DEFAULT_CAP_BYTES,
        DEFAULT_MAX_DEPTH,
        DEFAULT_MAX_TOTAL_NODES,
        SENSITIVE_FIELD_CATEGORIES,
        RedactionConfig,
        RedactionEngine,
        RedactionPatterns,
        _safe_compile,
        stable_encode_key,
    )
except Exception:
    from backend.analytics.redaction import (
        DEFAULT_CAP_BYTES,
        DEFAULT_MAX_DEPTH,
        DEFAULT_MAX_TOTAL_NODES,
        SENSITIVE_FIELD_CATEGORIES,
        RedactionConfig,
        RedactionEngine,
        RedactionPatterns,
        _safe_compile,
        stable_encode_key,
    )


def _clone_default_categories() -> Dict[str, List[str]]:
    return {cat: list(hints) for cat, hints in SENSITIVE_FIELD_CATEGORIES.items()}


def _build_patterns_for_categories(
    categories: Mapping[str, Sequence[str]],
    value_patterns: Optional[Mapping[str, Tuple[str, str]]] = None,
) -> RedactionPatterns:
    patterns = RedactionPatterns.build()
    patterns.sensitive_field_regexes = {}
    patterns.stable_hints_by_category = {}

    for cat, hints in categories.items():
        stable_hints = [stable_encode_key(h) for h in hints if h]
        patterns.stable_hints_by_category[cat] = set(stable_hints)
        escaped = [re.escape(sh) for sh in stable_hints if sh]
        if escaped:
            regex_str = r"(" + "|".join(escaped) + r")"
            patterns.sensitive_field_regexes[cat] = _safe_compile(regex_str, re.IGNORECASE)
        else:
            patterns.sensitive_field_regexes[cat] = _safe_compile(r"a^", 0)

    if value_patterns is not None:
        patterns.value_patterns = {}
        patterns.value_category_map = {}
        for name, (pat, cat) in value_patterns.items():
            flags = 0 if name in ("stellar_address", "stellar_muxed") else re.IGNORECASE
            patterns.value_patterns[name] = _safe_compile(pat, flags)
            patterns.value_category_map[name] = cat

    return patterns


@dataclass
class RedactionPolicyRevision:
    """Declarative redaction policy revision for before/after comparison."""

    name: str
    sensitive_field_categories: Optional[Dict[str, List[str]]] = None
    add_sensitive_fields: Dict[str, List[str]] = field(default_factory=dict)
    remove_sensitive_fields: Dict[str, List[str]] = field(default_factory=dict)
    value_patterns: Optional[Dict[str, Tuple[str, str]]] = None
    max_depth: int = DEFAULT_MAX_DEPTH
    max_total_nodes: int = DEFAULT_MAX_TOTAL_NODES
    cap_bytes: int = DEFAULT_CAP_BYTES
    redact_markers: Optional[Dict[str, str]] = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("policy revision name must be a non-empty string")
        if self.max_depth <= 0:
            raise ValueError("max_depth must be positive")
        if self.max_total_nodes <= 0:
            raise ValueError("max_total_nodes must be positive")
        if self.cap_bytes <= 0:
            raise ValueError("cap_bytes must be positive")

    def resolved_categories(self) -> Dict[str, List[str]]:
        if self.sensitive_field_categories is not None:
            categories = {
                cat: list(hints) for cat, hints in self.sensitive_field_categories.items()
            }
        else:
            categories = _clone_default_categories()

        for cat, hints in self.add_sensitive_fields.items():
            bucket = categories.setdefault(cat, [])
            for hint in hints:
                if hint not in bucket:
                    bucket.append(hint)

        for cat, hints in self.remove_sensitive_fields.items():
            if cat not in categories:
                continue
            remove_encoded = {stable_encode_key(h) for h in hints}
            categories[cat] = [
                h for h in categories[cat] if stable_encode_key(h) not in remove_encoded
            ]

        return categories

    def to_config(self) -> RedactionConfig:
        categories = self.resolved_categories()
        patterns = _build_patterns_for_categories(
            categories, value_patterns=self.value_patterns
        )
        config = RedactionConfig(
            patterns=patterns,
            max_depth=self.max_depth,
            max_total_nodes=self.max_total_nodes,
            cap_bytes=self.cap_bytes,
        )
        if self.redact_markers is not None:
            config.redact_markers = dict(self.redact_markers)
        return config


@dataclass
class FieldDiff:
    path: str
    status: str  # "newly_removed" | "newly_exposed" | "redaction_changed" | "unchanged"
    before_redacted: bool
    after_redacted: bool
    before_marker: Optional[str] = None
    after_marker: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status,
            "before_redacted": self.before_redacted,
            "after_redacted": self.after_redacted,
            "before_marker": self.before_marker,
            "after_marker": self.after_marker,
        }


@dataclass
class RecordComparison:
    record_index: int
    newly_removed: List[str] = field(default_factory=list)
    newly_exposed: List[str] = field(default_factory=list)
    redaction_changed: List[str] = field(default_factory=list)
    field_diffs: List[FieldDiff] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_index": self.record_index,
            "newly_removed": list(self.newly_removed),
            "newly_exposed": list(self.newly_exposed),
            "redaction_changed": list(self.redaction_changed),
            "field_diffs": [fd.to_dict() for fd in self.field_diffs],
        }


@dataclass
class PolicyComparisonReport:
    before_policy: str
    after_policy: str
    records_compared: int
    newly_removed_fields: List[str] = field(default_factory=list)
    newly_exposed_fields: List[str] = field(default_factory=list)
    redaction_changed_fields: List[str] = field(default_factory=list)
    record_comparisons: List[RecordComparison] = field(default_factory=list)

    @property
    def has_newly_exposed(self) -> bool:
        return bool(self.newly_exposed_fields)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "before_policy": self.before_policy,
            "after_policy": self.after_policy,
            "records_compared": self.records_compared,
            "has_newly_exposed": self.has_newly_exposed,
            "newly_removed_fields": list(self.newly_removed_fields),
            "newly_exposed_fields": list(self.newly_exposed_fields),
            "redaction_changed_fields": list(self.redaction_changed_fields),
            "record_comparisons": [rc.to_dict() for rc in self.record_comparisons],
        }

    def format_summary(self) -> str:
        lines = [
            f"Redaction Policy Comparison: {self.before_policy} -> {self.after_policy}",
            f"Synthetic records compared: {self.records_compared}",
            f"Newly removed (redacted/dropped) fields ({len(self.newly_removed_fields)}):",
        ]
        if self.newly_removed_fields:
            for path in self.newly_removed_fields:
                lines.append(f"  - {path}")
        else:
            lines.append("  (none)")

        lines.append(f"Newly exposed fields ({len(self.newly_exposed_fields)}):")
        if self.newly_exposed_fields:
            for path in self.newly_exposed_fields:
                lines.append(f"  + {path}")
        else:
            lines.append("  (none)")

        if self.redaction_changed_fields:
            lines.append(
                f"Redaction marker changed ({len(self.redaction_changed_fields)}):"
            )
            for path in self.redaction_changed_fields:
                lines.append(f"  ~ {path}")

        return "\n".join(lines)


_SENTINEL_MISSING = object()
_REDACTED_MARKER_RE = re.compile(r"^\[REDACTED(?::[A-Za-z0-9_]+)?\]$")


def _is_redacted_value(value: Any, markers: Set[str]) -> Tuple[bool, Optional[str]]:
    if value is _SENTINEL_MISSING:
        return True, "[DROPPED]"
    if isinstance(value, str):
        if value in markers or _REDACTED_MARKER_RE.match(value):
            return True, value
    return False, None


def _flatten_leaves(data: Any, prefix: str = "") -> Dict[str, Any]:
    leaves: Dict[str, Any] = {}
    if isinstance(data, Mapping):
        if not data and prefix:
            leaves[prefix] = {}
            return leaves
        for key, val in data.items():
            key_str = str(key)
            next_path = f"{prefix}.{key_str}" if prefix else key_str
            leaves.update(_flatten_leaves(val, next_path))
        return leaves
    if isinstance(data, (list, tuple)):
        if not data and prefix:
            leaves[prefix] = []
            return leaves
        for idx, item in enumerate(data):
            next_path = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            leaves.update(_flatten_leaves(item, next_path))
        return leaves
    leaves[prefix or "$"] = data
    return leaves


def _resolve_policy(
    policy: Union[RedactionConfig, RedactionPolicyRevision],
    fallback_name: str,
) -> Tuple[RedactionConfig, str]:
    if isinstance(policy, RedactionPolicyRevision):
        return policy.to_config(), policy.name
    if isinstance(policy, RedactionConfig):
        return policy, fallback_name
    raise ValueError(
        "policy must be a RedactionConfig or RedactionPolicyRevision instance"
    )


def compare_redaction_policies(
    records: Sequence[Mapping[str, Any]],
    before_policy: Union[RedactionConfig, RedactionPolicyRevision],
    after_policy: Union[RedactionConfig, RedactionPolicyRevision],
    *,
    before_name: str = "before",
    after_name: str = "after",
) -> PolicyComparisonReport:
    """Compare two redaction policies over synthetic analytics records.

    Reports fields that become newly removed (redacted or dropped) or newly
    exposed between policy revisions, without embedding raw sensitive values
    in the output report.
    """
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        raise ValueError("records must be a sequence of mapping objects")

    before_cfg, resolved_before_name = _resolve_policy(before_policy, before_name)
    after_cfg, resolved_after_name = _resolve_policy(after_policy, after_name)

    before_engine = RedactionEngine(config=before_cfg)
    after_engine = RedactionEngine(config=after_cfg)

    before_markers = set(before_cfg.redact_markers.values())
    after_markers = set(after_cfg.redact_markers.values())

    all_newly_removed: Set[str] = set()
    all_newly_exposed: Set[str] = set()
    all_redaction_changed: Set[str] = set()
    record_comparisons: List[RecordComparison] = []

    for idx, record in enumerate(records):
        if not isinstance(record, Mapping):
            raise ValueError(f"record at index {idx} must be a mapping")

        before_outcome = before_engine.sanitize(copy.deepcopy(dict(record)))
        after_outcome = after_engine.sanitize(copy.deepcopy(dict(record)))

        before_leaves = _flatten_leaves(before_outcome.data)
        after_leaves = _flatten_leaves(after_outcome.data)
        all_paths = sorted(set(before_leaves.keys()) | set(after_leaves.keys()))

        rec_removed: List[str] = []
        rec_exposed: List[str] = []
        rec_changed: List[str] = []
        field_diffs: List[FieldDiff] = []

        for path in all_paths:
            b_val = before_leaves.get(path, _SENTINEL_MISSING)
            a_val = after_leaves.get(path, _SENTINEL_MISSING)

            b_redacted, b_marker = _is_redacted_value(b_val, before_markers)
            a_redacted, a_marker = _is_redacted_value(a_val, after_markers)

            if not b_redacted and a_redacted:
                status = "newly_removed"
                rec_removed.append(path)
                all_newly_removed.add(path)
            elif b_redacted and not a_redacted:
                status = "newly_exposed"
                rec_exposed.append(path)
                all_newly_exposed.add(path)
            elif b_redacted and a_redacted and b_marker != a_marker:
                status = "redaction_changed"
                rec_changed.append(path)
                all_redaction_changed.add(path)
            else:
                status = "unchanged"

            if status != "unchanged":
                field_diffs.append(
                    FieldDiff(
                        path=path,
                        status=status,
                        before_redacted=b_redacted,
                        after_redacted=a_redacted,
                        before_marker=b_marker,
                        after_marker=a_marker,
                    )
                )

        record_comparisons.append(
            RecordComparison(
                record_index=idx,
                newly_removed=rec_removed,
                newly_exposed=rec_exposed,
                redaction_changed=rec_changed,
                field_diffs=field_diffs,
            )
        )

    return PolicyComparisonReport(
        before_policy=resolved_before_name,
        after_policy=resolved_after_name,
        records_compared=len(records),
        newly_removed_fields=sorted(all_newly_removed),
        newly_exposed_fields=sorted(all_newly_exposed),
        redaction_changed_fields=sorted(all_redaction_changed),
        record_comparisons=record_comparisons,
    )


def load_policy_revision(
    data: Mapping[str, Any], default_name: str = "policy"
) -> RedactionPolicyRevision:
    """Load a RedactionPolicyRevision from a JSON-compatible mapping."""
    if not isinstance(data, Mapping):
        raise ValueError("policy specification must be a mapping")

    name = str(data.get("name") or default_name)
    sensitive_cats = data.get("sensitive_field_categories")
    if sensitive_cats is not None and not isinstance(sensitive_cats, Mapping):
        raise ValueError("sensitive_field_categories must be a mapping")

    add_fields = data.get("add_sensitive_fields") or {}
    if not isinstance(add_fields, Mapping):
        raise ValueError("add_sensitive_fields must be a mapping")

    remove_fields = data.get("remove_sensitive_fields") or {}
    if not isinstance(remove_fields, Mapping):
        raise ValueError("remove_sensitive_fields must be a mapping")

    redact_markers = data.get("redact_markers")
    if redact_markers is not None and not isinstance(redact_markers, Mapping):
        raise ValueError("redact_markers must be a mapping")

    return RedactionPolicyRevision(
        name=name,
        sensitive_field_categories=(
            {str(k): [str(x) for x in v] for k, v in sensitive_cats.items()}
            if sensitive_cats is not None
            else None
        ),
        add_sensitive_fields={
            str(k): [str(x) for x in v] for k, v in add_fields.items()
        },
        remove_sensitive_fields={
            str(k): [str(x) for x in v] for k, v in remove_fields.items()
        },
        max_depth=int(data.get("max_depth", DEFAULT_MAX_DEPTH)),
        max_total_nodes=int(data.get("max_total_nodes", DEFAULT_MAX_TOTAL_NODES)),
        cap_bytes=int(data.get("cap_bytes", DEFAULT_CAP_BYTES)),
        redact_markers=(
            {str(k): str(v) for k, v in redact_markers.items()}
            if redact_markers is not None
            else None
        ),
    )


def build_synthetic_analytics_records() -> List[Dict[str, Any]]:
    """Return deterministic, purely synthetic analytics records for policy diffing.

    Uses RFC 2606 (.invalid) domains and RFC 5737 TEST-NET-1 addresses so no
    production analytics data or real user identifiers are ever committed.
    """
    return [
        {
            "event_type": "proof_verification_completed",
            "correlation_id": "corr-synthetic-0001",
            "duration_ms": 142,
            "status": "ok",
            "context": {
                "email": "synthetic.user@example.invalid",
                "client_ip": "192.0.2.10",
                "telemetry_device_id": "synth-device-001",
                "region": "test-region-1",
            },
        },
        {
            "event_type": "export_requested",
            "correlation_id": "corr-synthetic-0002",
            "status": "ok",
            "payload": {
                "api_token": "synth-token-placeholder",
                "witness_data": "synth-witness-placeholder",
                "batch_size": 16,
            },
        },
    ]


def _load_json_file(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare two analytics redaction policy revisions against synthetic "
            "analytics records and report newly removed or exposed fields."
        )
    )
    parser.add_argument(
        "--before",
        required=True,
        help="Path to JSON file describing the baseline redaction policy revision.",
    )
    parser.add_argument(
        "--after",
        required=True,
        help="Path to JSON file describing the candidate redaction policy revision.",
    )
    parser.add_argument(
        "--records",
        default=None,
        help=(
            "Optional path to JSON file containing a list of synthetic analytics "
            "records. Defaults to built-in synthetic records."
        ),
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--fail-on-exposed",
        action="store_true",
        help="Exit with status 2 if any fields are newly exposed in the after policy.",
    )

    args = parser.parse_args(argv)

    try:
        before_data = _load_json_file(Path(args.before))
        after_data = _load_json_file(Path(args.after))
        before_rev = load_policy_revision(before_data, default_name="before")
        after_rev = load_policy_revision(after_data, default_name="after")

        if args.records is not None:
            records_data = _load_json_file(Path(args.records))
            if not isinstance(records_data, list):
                raise ValueError("records file must contain a JSON array of objects")
            records = records_data
        else:
            records = build_synthetic_analytics_records()

        report = compare_redaction_policies(records, before_rev, after_rev)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(report.format_summary())

    if args.fail_on_exposed and report.has_newly_exposed:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
