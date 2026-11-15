"""Tests for synthetic-only analytics redaction-policy comparison tool."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_BACKEND_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _BACKEND_DIR.parent
for _p in (str(_BACKEND_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from analytics.consent import ConsentManager
from analytics.export_manager import (
    ExportManager,
    ExportPolicy,
    RedactionPolicySpec,
    SyntheticFixtureError,
    build_default_synthetic_analytics_records,
    compare_redaction_policies,
    validate_synthetic_analytics_record,
)
from analytics.log_processor import LogProcessor


def test_compare_policies_detects_newly_removed_fields_without_echoing_values() -> None:
    baseline = RedactionPolicySpec(revision="harpocrates-redaction-v1")
    candidate = RedactionPolicySpec(
        revision="harpocrates-redaction-v2",
        extra_sensitive_fields={"pii": ["device_fingerprint", "client_region"]},
        dropped_fields=["debug_context.internal_host_label"],
    )

    mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor())
    report = mgr.compare_redaction_policies(baseline, candidate)

    assert report.baseline_revision == "harpocrates-redaction-v1"
    assert report.candidate_revision == "harpocrates-redaction-v2"
    assert report.records_evaluated == 2
    assert report.has_exposure_regression is False
    assert report.newly_exposed_fields == []
    assert report.newly_removed_fields == [
        "client_region",
        "debug_context.internal_host_label",
        "device_fingerprint",
    ]
    assert "auth.token" in report.unchanged_protected_fields
    assert "evidence.witness_data" in report.unchanged_protected_fields
    assert "operation" in report.unchanged_exposed_fields
    assert "status_code" in report.unchanged_exposed_fields

    # Raw synthetic values are never echoed in the diff report
    serialized_report = json.dumps(report.to_dict())
    assert "synthetic-fp-placeholder" not in serialized_report
    assert "synthetic-token-placeholder" not in serialized_report
    assert "synthetic-worker-node-a" not in serialized_report

    cm = ConsentManager()
    assert cm.requires_reconsent_for_policy_diff(report) is False


def test_compare_policies_detects_newly_exposed_fields_and_flags_reconsent() -> None:
    strict_baseline = RedactionPolicySpec(
        revision="harpocrates-redaction-v2",
        extra_sensitive_fields={"pii": ["device_fingerprint"]},
        dropped_fields=["operator_note"],
    )
    regressed_candidate = RedactionPolicySpec(
        revision="harpocrates-redaction-v3-draft",
        exempt_fields=["auth.token"],
    )

    report = compare_redaction_policies(strict_baseline, regressed_candidate)
    assert report.has_exposure_regression is True
    assert report.newly_exposed_fields == [
        "auth.token",
        "device_fingerprint",
        "operator_note",
    ]
    transitions_map = {
        t.field_path: (t.baseline_state, t.candidate_state) for t in report.field_transitions
    }
    assert transitions_map["auth.token"] == ("redacted", "exposed")
    assert transitions_map["device_fingerprint"] == ("redacted", "exposed")
    assert transitions_map["operator_note"] == ("omitted", "exposed")

    cm = ConsentManager()
    assert cm.requires_reconsent_for_policy_diff(report) is True
    assert cm.requires_reconsent_for_policy_diff(report.to_dict()) is True


def test_redacted_to_omitted_transition_is_classified_as_newly_removed() -> None:
    baseline = RedactionPolicySpec(revision="rev-mask")
    candidate = RedactionPolicySpec(revision="rev-drop", dropped_fields=["auth.token"])

    records = [
        {
            "dataset_origin": "synthetic",
            "operation": "verify",
            "auth": {"token": "synthetic-tok"},
        }
    ]
    report = compare_redaction_policies(baseline, candidate, synthetic_records=records)
    assert report.newly_removed_fields == ["auth.token"]
    assert report.newly_exposed_fields == []
    assert report.field_transitions[0].baseline_state == "redacted"
    assert report.field_transitions[0].candidate_state == "omitted"


@pytest.mark.parametrize(
    "bad_record",
    [
        {"operation": "verify", "status_code": 200},  # Missing synthetic marker
        {"_synthetic": False, "operation": "verify"},
        {"_synthetic": True, "environment": "production", "operation": "verify"},
        {"dataset_origin": "production", "operation": "verify"},
        {"_synthetic": True},  # No evaluable fields
        {},
    ],
)
def test_non_synthetic_or_production_records_rejected_fail_closed(bad_record: dict) -> None:
    p1 = RedactionPolicySpec(revision="v1")
    p2 = RedactionPolicySpec(revision="v2")
    with pytest.raises(SyntheticFixtureError):
        compare_redaction_policies(p1, p2, synthetic_records=[bad_record])


def test_credential_or_binary_material_rejected_even_when_marked_synthetic() -> None:
    stellar_seed = "S" + ("C" * 55)
    pem_header = "-----BEGIN " + "EC PRIVATE KEY-----"
    dsn = "postgresql://" + "admin:pass@db.internal:5432/prod"

    for payload in (
        {"_synthetic": True, "note": stellar_seed},
        {"_synthetic": True, "key": pem_header},
        {"_synthetic": True, "db": dsn},
        {"_synthetic": True, "raw": b"\x00\x01\x02"},
    ):
        with pytest.raises(SyntheticFixtureError):
            validate_synthetic_analytics_record(payload)


def test_invalid_inputs_rejected() -> None:
    with pytest.raises(ValueError, match="invalid redaction policy revision"):
        RedactionPolicySpec(revision="../bad revision!")

    p1 = RedactionPolicySpec(revision="v1")
    with pytest.raises(SyntheticFixtureError, match="at least one"):
        compare_redaction_policies(p1, p1, synthetic_records=[])

    with pytest.raises(TypeError):
        compare_redaction_policies("v1", p1)  # type: ignore[arg-type]

    cm = ConsentManager()
    with pytest.raises(ValueError, match="invalid redaction policy comparison report"):
        cm.requires_reconsent_for_policy_diff({"unexpected": []})

    defaults = build_default_synthetic_analytics_records()
    assert len(defaults) == 2
    assert all(rec.get("_synthetic") is True for rec in defaults)
