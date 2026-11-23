from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from backend.analytics.redaction_policy_diff import (
    PolicyComparisonReport,
    RedactionPolicyRevision,
    build_synthetic_analytics_records,
    compare_redaction_policies,
    load_policy_revision,
    main,
)


def test_detects_newly_removed_field_when_policy_tightens() -> None:
    records = build_synthetic_analytics_records()
    before = RedactionPolicyRevision(name="policy-v1")
    after = RedactionPolicyRevision(
        name="policy-v2",
        add_sensitive_fields={"pii": ["telemetry_device_id"]},
    )

    report = compare_redaction_policies(records, before, after)

    assert isinstance(report, PolicyComparisonReport)
    assert report.before_policy == "policy-v1"
    assert report.after_policy == "policy-v2"
    assert report.records_compared == len(records)
    assert report.newly_removed_fields == ["context.telemetry_device_id"]
    assert report.newly_exposed_fields == []
    assert report.has_newly_exposed is False


def test_detects_newly_exposed_field_when_policy_relaxes() -> None:
    records = [
        {
            "event_type": "proof_verification_completed",
            "context": {
                "telemetry_device_id": "synth-device-001",
                "region": "test-region-1",
            },
        }
    ]
    before = RedactionPolicyRevision(
        name="policy-v1",
        add_sensitive_fields={"pii": ["telemetry_device_id"]},
    )
    after = RedactionPolicyRevision(name="policy-v2")

    report = compare_redaction_policies(records, before, after)

    assert report.newly_exposed_fields == ["context.telemetry_device_id"]
    assert report.newly_removed_fields == []
    assert report.has_newly_exposed is True


def test_detects_redaction_marker_category_change() -> None:
    records = [
        {
            "event_type": "export_requested",
            "context": {"custom_tag": "synth-tag-value"},
        }
    ]
    before = RedactionPolicyRevision(
        name="policy-v1",
        add_sensitive_fields={"pii": ["custom_tag"]},
    )
    after = RedactionPolicyRevision(
        name="policy-v2",
        add_sensitive_fields={"secret": ["custom_tag"]},
    )

    report = compare_redaction_policies(records, before, after)

    assert report.newly_removed_fields == []
    assert report.newly_exposed_fields == []
    assert report.redaction_changed_fields == ["context.custom_tag"]
    diff = report.record_comparisons[0].field_diffs[0]
    assert diff.before_marker == "[REDACTED:pii]"
    assert diff.after_marker == "[REDACTED:secret]"


def test_identical_policies_produce_no_diffs() -> None:
    records = build_synthetic_analytics_records()
    before = RedactionPolicyRevision(name="policy-v1")
    after = RedactionPolicyRevision(name="policy-v1-copy")

    report = compare_redaction_policies(records, before, after)

    assert report.newly_removed_fields == []
    assert report.newly_exposed_fields == []
    assert report.redaction_changed_fields == []
    assert report.has_newly_exposed is False


def test_handles_nested_lists_and_does_not_mutate_input_records() -> None:
    records = [
        {
            "events": [
                {"name": "ok", "device_fingerprint": "synth-fp-1"},
                {"name": "ok", "device_fingerprint": "synth-fp-2"},
            ]
        }
    ]
    snapshot = copy.deepcopy(records)
    before = RedactionPolicyRevision(name="v1")
    after = RedactionPolicyRevision(
        name="v2",
        add_sensitive_fields={"pii": ["device_fingerprint"]},
    )

    report = compare_redaction_policies(records, before, after)

    assert records == snapshot
    assert report.newly_removed_fields == [
        "events[0].device_fingerprint",
        "events[1].device_fingerprint",
    ]


def test_depth_limit_tightening_reports_newly_removed_fields() -> None:
    records = [{"a": {"b": {"c": {"leaf": "synthetic-value"}}}}]
    before = RedactionPolicyRevision(name="v1", max_depth=8)
    after = RedactionPolicyRevision(name="v2", max_depth=2)

    report = compare_redaction_policies(records, before, after)

    assert "a.b.c.leaf" in report.newly_removed_fields
    assert report.newly_exposed_fields == []


def test_report_never_leaks_raw_sensitive_values() -> None:
    secret_marker = "SYNTH-RAW-SECRET-VALUE-999"
    records = [{"custom_secret_field": secret_marker}]
    before = RedactionPolicyRevision(name="v1")
    after = RedactionPolicyRevision(
        name="v2",
        add_sensitive_fields={"secret": ["custom_secret_field"]},
    )

    report = compare_redaction_policies(records, before, after)
    serialized = json.dumps(report.to_dict())
    summary = report.format_summary()

    assert secret_marker not in serialized
    assert secret_marker not in summary


def test_empty_records_boundary_returns_empty_report() -> None:
    before = RedactionPolicyRevision(name="v1")
    after = RedactionPolicyRevision(name="v2")

    report = compare_redaction_policies([], before, after)

    assert report.records_compared == 0
    assert report.newly_removed_fields == []
    assert report.newly_exposed_fields == []
    assert report.has_newly_exposed is False


def test_invalid_inputs_raise_value_error() -> None:
    before = RedactionPolicyRevision(name="v1")
    after = RedactionPolicyRevision(name="v2")

    with pytest.raises(ValueError, match="must be a mapping"):
        compare_redaction_policies(["not-a-dict"], before, after)  # type: ignore[list-item]

    with pytest.raises(ValueError, match="max_depth must be positive"):
        RedactionPolicyRevision(name="bad", max_depth=0)

    with pytest.raises(ValueError, match="cap_bytes must be positive"):
        RedactionPolicyRevision(name="bad", cap_bytes=-1)

    with pytest.raises(ValueError, match="policy revision name"):
        RedactionPolicyRevision(name="   ")


def test_load_policy_revision_validation() -> None:
    rev = load_policy_revision(
        {
            "name": "rev-2",
            "add_sensitive_fields": {"pii": ["telemetry_device_id"]},
            "max_depth": 10,
        }
    )
    assert rev.name == "rev-2"
    assert rev.max_depth == 10
    assert "telemetry_device_id" in rev.resolved_categories()["pii"]

    with pytest.raises(ValueError, match="must be a mapping"):
        load_policy_revision("invalid")  # type: ignore[arg-type]


def test_cli_json_and_fail_on_exposed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before_file = tmp_path / "before.json"
    after_file = tmp_path / "after.json"
    records_file = tmp_path / "records.json"

    before_file.write_text(
        json.dumps(
            {
                "name": "v1",
                "add_sensitive_fields": {"pii": ["telemetry_device_id"]},
            }
        ),
        encoding="utf-8",
    )
    after_file.write_text(json.dumps({"name": "v2"}), encoding="utf-8")
    records_file.write_text(
        json.dumps(
            [
                {
                    "event_type": "synthetic_check",
                    "context": {"telemetry_device_id": "synth-001"},
                }
            ]
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "--before",
            str(before_file),
            "--after",
            str(after_file),
            "--records",
            str(records_file),
            "--format",
            "json",
            "--fail-on-exposed",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 2
    assert payload["has_newly_exposed"] is True
    assert payload["newly_exposed_fields"] == ["context.telemetry_device_id"]


def test_cli_missing_file_returns_error_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(
        [
            "--before",
            str(tmp_path / "missing-before.json"),
            "--after",
            str(tmp_path / "missing-after.json"),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "error:" in captured.err
