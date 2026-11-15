"""Focused tests for analytics export completion receipts (Issue #1123)."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sys
from pathlib import Path

backend_dir = str(Path(__file__).resolve().parent)
repo_root = str(Path(__file__).resolve().parents[1])
for p in (backend_dir, repo_root):
    if p not in sys.path:
        sys.path.insert(0, p)

import pytest

from analytics.consent import (
    CONSENT_POLICY_REVISION,
    ConsentDecision,
    ConsentManager,
    ConsentSource,
    ConsentStatus,
    normalize_consent_scopes,
)
from analytics.export_manager import (
    DEFAULT_EXPORT_SCOPE,
    EXPORT_POLICY_REVISION,
    ExportCompletionReceipt,
    ExportManager,
    ExportPolicy,
    compute_output_digest,
    validate_policy_revision,
    validate_receipt_scopes,
)
from analytics.log_processor import LogEntry, LogProcessor


def _make_safe_entry(
    entry_id: str,
    *,
    ts: float = 100.0,
    message: str = "request completed",
    account_tag: str = "acct_tag_private_01",
    session_tag: str = "sess_tag_private_02",
    correlation_tag: str = "corr_tag_private_03",
) -> LogEntry:
    return LogEntry(
        entry_id=entry_id,
        event_name="ops.progress_tick",
        category="ops.signal",
        message_summary=message,
        endpoint_pattern="/api/health",
        method="GET",
        status_code=200,
        timestamp_epoch_seconds=ts,
        account_id_tag=account_tag,
        session_id_tag=session_tag,
        correlation_id_tag=correlation_tag,
        labels={"service": "harpocrates-test-svc"},
        counters={"retry_attempt": 1},
        sanitized=True,
        export_safe=True,
        export_signature="sig-v1:112233445566",
    )


def _make_manager(**policy_kwargs) -> ExportManager:
    return ExportManager(
        policy=ExportPolicy(**policy_kwargs),
        processor=LogProcessor(),
    )


def test_completion_receipt_records_scope_policy_revision_and_output_digest() -> None:
    cm = ConsentManager()
    decision = ConsentDecision(
        status=ConsentStatus.GRANTED,
        source=ConsentSource.USER_EXPLICIT,
        scope=["analytics:ops.progress_tick", "analytics:system.health_check", "analytics:ops.progress_tick"],
        expires_at_epoch_seconds=2_000_000_000.0,
        granted_at_epoch_seconds=1_700_000_000.0,
        policy_revision="consent-policy-2026.11",
    )
    state = cm.set_consent("acct_1", decision)
    assert state.policy_revision == "consent-policy-2026.11"
    assert state.to_decision().policy_revision == "consent-policy-2026.11"

    mgr = _make_manager(policy_revision="export-policy-v2")
    entries = [
        _make_safe_entry("eid-v1:0001", ts=10.0),
        _make_safe_entry("eid-v1:0002", ts=20.0),
    ]

    artifact, serialized, count, receipt = mgr.create_export_with_receipt(
        entries=entries,
        exported_by_tag="auditor_tag",
        rollout_phase="canary",
        export_token_verified=True,
        selected_scopes=state.granted_scopes,
        policy_revision=state.policy_revision,
    )

    assert artifact is not None
    assert receipt is not None
    assert count == 2
    assert receipt.artifact_id == artifact.artifact_id
    assert artifact.receipt_id == receipt.receipt_id
    assert receipt.selected_scopes == (
        "analytics:ops.progress_tick",
        "analytics:system.health_check",
    )
    assert receipt.policy_revision == "consent-policy-2026.11"
    expected_digest = "sha256:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    assert receipt.output_digest == expected_digest
    assert artifact.output_digest == expected_digest
    assert receipt.entry_count == 2
    assert receipt.payload_bytes == len(serialized.encode("utf-8"))
    assert receipt.rollout_phase == "canary"
    assert receipt.verify_output(serialized) is True
    assert receipt.verify_integrity() is True
    assert mgr.get_receipt(receipt.receipt_id) is receipt
    assert mgr.get_receipt_for_artifact(artifact.artifact_id) is receipt


def test_create_export_defaults_populate_receipt_compatibly() -> None:
    mgr = _make_manager()
    art, serialized, count = mgr.create_export(
        entries=[_make_safe_entry("eid-v1:aaaa")],
        export_token_verified=True,
    )
    assert art is not None
    assert count == 1
    receipt = mgr.get_receipt_for_artifact(art.artifact_id)
    assert isinstance(receipt, ExportCompletionReceipt)
    assert receipt.selected_scopes == (DEFAULT_EXPORT_SCOPE,)
    assert receipt.policy_revision == EXPORT_POLICY_REVISION
    assert receipt.output_digest == compute_output_digest(serialized)
    assert receipt.verify_output(serialized) is True
    assert receipt.verify_integrity() is True


def test_compressed_export_receipt_binds_compressed_output_digest() -> None:
    mgr = _make_manager()
    art, compressed_payload, count, receipt = mgr.create_export_with_receipt(
        entries=[_make_safe_entry("eid-v1:comp1")],
        compress=True,
        export_token_verified=True,
        selected_scopes=["analytics:export"],
        policy_revision="rev-compressed-1",
    )
    assert art is not None and receipt is not None
    assert count == 1
    assert receipt.compress is True
    assert receipt.output_digest == compute_output_digest(compressed_payload)
    assert receipt.verify_output(compressed_payload) is True
    assert receipt.verify_output("[]") is False


def test_receipt_never_includes_raw_private_events_or_tags() -> None:
    mgr = _make_manager()
    safe_entry = _make_safe_entry(
        "eid-v1:sentinel_entry_999",
        message="unique_operational_summary_marker_42",
        account_tag="private_acct_tag_marker_77",
        session_tag="private_sess_tag_marker_88",
        correlation_tag="private_corr_tag_marker_99",
    )
    unsafe_private_entry = LogEntry(
        entry_id="eid-v1:private_raw_event_000",
        event_name="media.upload_started",
        message_summary="raw_private_witness_material_never_leak",
        labels={"BAD PRIVATE KEY": "raw_private_label_value"},
        account_id_tag="private_acct_unsafe_111",
        export_safe=False,
    )

    art, serialized, count, receipt = mgr.create_export_with_receipt(
        entries=[safe_entry, unsafe_private_entry],
        exported_by_tag="exporter_private_operator_tag",
        export_token_verified=True,
        selected_scopes=["analytics:ops"],
        policy_revision="policy-2026-r3",
    )
    assert art is not None and receipt is not None
    assert count == 1

    receipt_dict = receipt.to_dict()
    receipt_json = json.dumps(receipt_dict, sort_keys=True)

    # Strictly bounded metadata keys only; no events/entries/exported_by_tag slots.
    assert set(receipt_dict.keys()) == {
        "receipt_id",
        "artifact_id",
        "schema_version",
        "completed_at_epoch_seconds",
        "selected_scopes",
        "policy_revision",
        "redaction_version",
        "output_digest",
        "entry_count",
        "payload_bytes",
        "compress",
        "rollout_phase",
        "safety_signature",
        "receipt_digest",
    }

    forbidden_Needles = [
        "eid-v1:sentinel_entry_999",
        "unique_operational_summary_marker_42",
        "private_acct_tag_marker_77",
        "private_sess_tag_marker_88",
        "private_corr_tag_marker_99",
        "harpocrates-test-svc",
        "eid-v1:private_raw_event_000",
        "raw_private_witness_material_never_leak",
        "raw_private_label_value",
        "private_acct_unsafe_111",
        "exporter_private_operator_tag",
        "/api/health",
    ]
    for needle in forbidden_Needles:
        assert needle not in receipt_json


def test_receipt_tampering_and_payload_mismatch_fail_verification() -> None:
    mgr = _make_manager()
    _art, serialized, _count, receipt = mgr.create_export_with_receipt(
        entries=[_make_safe_entry("eid-v1:tamper1")],
        export_token_verified=True,
        selected_scopes=["analytics:ops"],
        policy_revision="policy-v1",
    )
    assert receipt is not None
    assert receipt.verify_integrity() is True
    assert receipt.verify_output(serialized) is True
    assert receipt.verify_output(serialized + " ") is False
    assert receipt.verify_output(123) is False  # type: ignore[arg-type]

    tampered_scope = dataclasses.replace(receipt, selected_scopes=("analytics:other",))
    assert tampered_scope.verify_integrity() is False

    tampered_rev = dataclasses.replace(receipt, policy_revision="policy-v99")
    assert tampered_rev.verify_integrity() is False

    tampered_digest = dataclasses.replace(receipt, output_digest="sha256:" + "0" * 64)
    assert tampered_digest.verify_integrity() is False

    malformed_digest = dataclasses.replace(receipt, output_digest="md5:1234")
    assert malformed_digest.verify_integrity() is False


def test_rejected_unauthenticated_export_emits_no_receipt() -> None:
    mgr = _make_manager(allow_unauthenticated_export_shadow_mode=False)
    art, reason, count, receipt = mgr.create_export_with_receipt(
        entries=[_make_safe_entry("eid-v1:unauth")],
        export_token_verified=False,
    )
    assert art is None
    assert reason == "export_token_required"
    assert count == 0
    assert receipt is None
    assert mgr.list_receipts() == []


@pytest.mark.parametrize(
    "bad_scopes",
    [
        "analytics:export",  # bare string instead of sequence
        [""],
        ["scope with spaces"],
        ["../etc/passwd"],
        ["a" * 65],
        ["ab" * 16],  # 32-char hex digest rejected
        ["G" + "A" * 55],  # Stellar key shape rejected
        ["S" + "B" * 55],  # Stellar secret shape rejected
        [f"analytics:s{i}" for i in range(33)],  # exceeds MAX_RECEIPT_SCOPES
    ],
)
def test_invalid_or_sensitive_scopes_rejected_fail_closed(bad_scopes) -> None:
    mgr = _make_manager()
    with pytest.raises(ValueError):
        mgr.create_export_with_receipt(
            entries=[_make_safe_entry("eid-v1:s1")],
            export_token_verified=True,
            selected_scopes=bad_scopes,
        )
    assert mgr.list_artifacts() == []
    assert mgr.list_receipts() == []


@pytest.mark.parametrize(
    "bad_revision",
    [
        "",
        "   ",
        "rev/../../bad",
        "rev with space",
        "r" * 65,
        "cd" * 16,
        "G" + "A" * 55,
    ],
)
def test_invalid_policy_revision_rejected_fail_closed(bad_revision: str) -> None:
    mgr = _make_manager()
    with pytest.raises(ValueError):
        mgr.create_export_with_receipt(
            entries=[_make_safe_entry("eid-v1:r1")],
            export_token_verified=True,
            policy_revision=bad_revision,
        )
    assert mgr.list_artifacts() == []
    assert mgr.list_receipts() == []

    with pytest.raises(ValueError):
        ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            expires_at_epoch_seconds=100.0,
            granted_at_epoch_seconds=10.0,
            policy_revision=bad_revision,
        )


def test_consent_scope_normalization_and_default_revision() -> None:
    assert CONSENT_POLICY_REVISION == "consent-policy-v1"
    assert normalize_consent_scopes(["b:scope", "a:scope", "b:scope"]) == ["a:scope", "b:scope"]
    assert normalize_consent_scopes(None) == []
    with pytest.raises(ValueError):
        normalize_consent_scopes(["bad/scope"])
    with pytest.raises(ValueError):
        normalize_consent_scopes(["ef" * 16])


def test_receipt_lifecycle_eviction_delete_and_reset() -> None:
    mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor(), max_artifacts_memory=2)
    a1, _, _, r1 = mgr.create_export_with_receipt(entries=[_make_safe_entry("e1")], export_token_verified=True)
    a2, _, _, r2 = mgr.create_export_with_receipt(entries=[_make_safe_entry("e2")], export_token_verified=True)
    a3, _, _, r3 = mgr.create_export_with_receipt(entries=[_make_safe_entry("e3")], export_token_verified=True)

    assert a1 is not None and r1 is not None
    assert a2 is not None and r2 is not None
    assert a3 is not None and r3 is not None

    # Evicted oldest artifact also evicts its receipt
    assert mgr.get_receipt(r1.receipt_id) is None
    assert mgr.get_receipt_for_artifact(a1.artifact_id) is None
    assert [r.receipt_id for r in mgr.list_receipts()] == [r3.receipt_id, r2.receipt_id]
    assert [r.receipt_id for r in mgr.list_receipts(limit=1)] == [r3.receipt_id]

    # Deleting artifact removes its receipt
    assert mgr.delete_artifact(a2.artifact_id) is True
    assert mgr.get_receipt(r2.receipt_id) is None
    assert mgr.get_receipt_for_artifact(a2.artifact_id) is None

    # Reset clears remaining receipts
    mgr.reset()
    assert mgr.list_receipts() == []
    assert mgr.get_receipt(r3.receipt_id) is None


def test_validate_helpers_defaults() -> None:
    assert validate_receipt_scopes(None) == (DEFAULT_EXPORT_SCOPE,)
    assert validate_receipt_scopes([]) == (DEFAULT_EXPORT_SCOPE,)
    assert validate_policy_revision(None) == EXPORT_POLICY_REVISION
    with pytest.raises(TypeError):
        compute_output_digest(b"bytes")  # type: ignore[arg-type]
