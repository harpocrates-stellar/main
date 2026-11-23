"""Tests for analytics dimension validation.

Ensures analytics dimensions that can identify uploaded evidence
(such as cryptographic hashes and raw filenames) are rejected before
aggregation, and that dimension keys are restricted to the allowed vocabulary.
"""

from __future__ import annotations

import sys
from pathlib import Path

backend_dir = str(Path(__file__).resolve().parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import pytest

from analytics.analytics_engine import AnalyticsEngine, RequestContext
from analytics.config import AnalyticsConfig, AnalyticsFeatureFlags
from analytics.consent import ConsentDecision, ConsentSource, ConsentStatus
from analytics.events import EventAllowlist, EventLifecycleState, EventOperationStatus
from analytics.export_manager import ExportManager, ExportPolicy
from analytics.log_processor import (
    ALLOWED_DIMENSION_VOCABULARY,
    LogEntry,
    LogProcessor,
    is_evidence_hash,
    is_raw_filename,
    validate_dimension,
    validate_log_export_safety,
)


@pytest.fixture
def engine():
    """Minimal engine initialization with test allowlist including test events."""
    allowlist = EventAllowlist()
    allowlist.add_allowed("test_event")
    allowlist.add_allowed("user.action")
    eng = AnalyticsEngine(allowlist=allowlist)
    decision = ConsentDecision(
        status=ConsentStatus.GRANTED,
        source=ConsentSource.USER_EXPLICIT,
        scope=["*"],
        expires_at_epoch_seconds=2000000000.0,
        granted_at_epoch_seconds=1000000000.0,
    )
    eng.consent.set_consent("test_account", decision)
    return eng


# ===========================================================================
# Engine Dimension Validation Tests
# ===========================================================================


def test_reject_hash_label_40_hex(engine):
    ctx = RequestContext(account_id_tag="test_account")
    payload = {"labels": {"evidence_hash": "a3f5c6d7e8f9b0c1d2e3f4a5b6c7d8e9f0a1b2c3"}}
    event = engine.process_event(
        event_name="test_event",
        category="user.action",
        payload=payload,
        context=ctx,
    )
    assert event.lifecycle_state == EventLifecycleState.DROPPED
    assert event.rejection_reason == "dimension_rejected_hash"
    assert event.operation_status == EventOperationStatus.INVALID


def test_reject_hash_label_64_hex(engine):
    ctx = RequestContext(account_id_tag="test_account")
    sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    payload = {"labels": {"operation": sha256_hash}}
    event = engine.process_event(
        event_name="test_event",
        category="user.action",
        payload=payload,
        context=ctx,
    )
    assert event.lifecycle_state == EventLifecycleState.DROPPED
    assert event.rejection_reason == "dimension_rejected_hash"
    assert event.operation_status == EventOperationStatus.INVALID


def test_reject_hash_label_0x_prefixed(engine):
    ctx = RequestContext(account_id_tag="test_account")
    payload = {"labels": {"error_code": "0x" + "a" * 64}}
    event = engine.process_event(
        event_name="test_event",
        category="user.action",
        payload=payload,
        context=ctx,
    )
    assert event.lifecycle_state == EventLifecycleState.DROPPED
    assert event.rejection_reason == "dimension_rejected_hash"


def test_reject_filename_label_upload_path(engine):
    ctx = RequestContext(account_id_tag="test_account")
    payload = {"labels": {"evidence_file": "uploads/evidence123.png"}}
    event = engine.process_event(
        event_name="test_event",
        category="user.action",
        payload=payload,
        context=ctx,
    )
    assert event.lifecycle_state == EventLifecycleState.DROPPED
    assert event.rejection_reason == "dimension_rejected_filename"
    assert event.operation_status == EventOperationStatus.INVALID


def test_reject_filename_label_media_extension(engine):
    ctx = RequestContext(account_id_tag="test_account")
    payload = {"labels": {"operation": "raw_footage.mp4"}}
    event = engine.process_event(
        event_name="test_event",
        category="user.action",
        payload=payload,
        context=ctx,
    )
    assert event.lifecycle_state == EventLifecycleState.DROPPED
    assert event.rejection_reason == "dimension_rejected_filename"


def test_reject_disallowed_vocabulary_dimension(engine):
    ctx = RequestContext(account_id_tag="test_account")
    payload = {"labels": {"unauthorized_custom_dim": "safe_value"}}
    event = engine.process_event(
        event_name="test_event",
        category="user.action",
        payload=payload,
        context=ctx,
    )
    assert event.lifecycle_state == EventLifecycleState.DROPPED
    assert event.rejection_reason == "dimension_rejected_vocabulary"
    assert event.operation_status == EventOperationStatus.INVALID


def test_allow_valid_vocabulary_and_safe_values(engine):
    ctx = RequestContext(account_id_tag="test_account")
    payload = {
        "labels": {
            "endpoint": "/api/proof/verify",
            "method": "POST",
            "status": "200",
            "operation": "proof_verification",
        }
    }
    event = engine.process_event(
        event_name="test_event",
        category="user.action",
        payload=payload,
        context=ctx,
    )
    assert event.lifecycle_state != EventLifecycleState.DROPPED
    assert event.rejection_reason is None


def test_boundary_semver_not_rejected_as_filename(engine):
    ctx = RequestContext(account_id_tag="test_account")
    payload = {"labels": {"version": "1.0.0", "schema": "2.1"}}
    event = engine.process_event(
        event_name="test_event",
        category="user.action",
        payload=payload,
        context=ctx,
    )
    assert event.lifecycle_state != EventLifecycleState.DROPPED


def test_boundary_category_not_rejected_as_filename(engine):
    ctx = RequestContext(account_id_tag="test_account")
    payload = {"labels": {"category": "user.action"}}
    event = engine.process_event(
        event_name="test_event",
        category="user.action",
        payload=payload,
        context=ctx,
    )
    assert event.lifecycle_state != EventLifecycleState.DROPPED


def test_boundary_short_tag_not_rejected_as_hash(engine):
    ctx = RequestContext(account_id_tag="test_account")
    payload = {"labels": {"error_code": "err_1234"}}
    event = engine.process_event(
        event_name="test_event",
        category="user.action",
        payload=payload,
        context=ctx,
    )
    assert event.lifecycle_state != EventLifecycleState.DROPPED


def test_aggregation_not_performed_on_rejected_dimensions():
    allowlist = EventAllowlist()
    allowlist.add_allowed("test_event")
    eng = AnalyticsEngine(allowlist=allowlist)

    # Initial event seen count
    initial_counts = eng.metrics._events_seen.get("test_event", 0)

    # Process rejected event
    eng.process_event(
        event_name="test_event",
        category="user.action",
        payload={"labels": {"evidence_hash": "a3f5c6d7e8f9b0c1d2e3f4a5b6c7d8e9f0a1b2c3"}},
    )

    # Ensure event was not counted in aggregation
    assert eng.metrics._events_seen.get("test_event", 0) == initial_counts


# ===========================================================================
# Log Processor and Export Manager Tests
# ===========================================================================


def test_log_processor_filter_labels_drops_evidence_identifiers():
    proc = LogProcessor()
    raw_labels = {
        "operation": "proof_gen",
        "evidence_hash": "a3f5c6d7e8f9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
        "evidence_file": "uploads/evidence.png",
        "status": "200",
        "disallowed_key": "safe_value",
    }
    filtered = proc._filter_labels(raw_labels)
    assert "operation" in filtered
    assert "status" in filtered
    assert "evidence_hash" not in filtered
    assert "evidence_file" not in filtered
    assert "disallowed_key" not in filtered


def test_validate_log_export_safety_rejects_hash_and_filename():
    safe_entry = LogEntry(
        entry_id="eid-1",
        event_name="evt",
        message_summary="ok",
        labels={"operation": "verify", "status": "200"},
    )
    ok, reasons = validate_log_export_safety(safe_entry)
    assert ok is True
    assert reasons == []

    hash_entry = LogEntry(
        entry_id="eid-2",
        event_name="evt",
        message_summary="ok",
        labels={"operation": "a3f5c6d7e8f9b0c1d2e3f4a5b6c7d8e9f0a1b2c3"},
    )
    ok, reasons = validate_log_export_safety(hash_entry)
    assert ok is False
    assert any("dimension_rejected_hash" in r for r in reasons)

    file_entry = LogEntry(
        entry_id="eid-3",
        event_name="evt",
        message_summary="ok",
        labels={"operation": "uploads/evidence.png"},
    )
    ok, reasons = validate_log_export_safety(file_entry)
    assert ok is False
    assert any("dimension_rejected_filename" in r for r in reasons)

    vocab_entry = LogEntry(
        entry_id="eid-4",
        event_name="evt",
        message_summary="ok",
        labels={"custom_bad_dim": "val"},
    )
    ok, reasons = validate_log_export_safety(vocab_entry)
    assert ok is False
    assert any("invalid_label_key" in r or "dimension_rejected_vocabulary" in r for r in reasons)


def test_export_manager_drops_entries_with_evidence_dimensions():
    proc = LogProcessor()
    safe_entry = LogEntry(
        entry_id="safe-1",
        event_name="evt",
        message_summary="ok",
        labels={"operation": "verify"},
        export_safe=True,
        export_signature="sig-v1:safe",
    )
    unsafe_entry = LogEntry(
        entry_id="unsafe-1",
        event_name="evt",
        message_summary="ok",
        labels={"operation": "0x" + "a" * 64},
        export_safe=True,
        export_signature="sig-v1:unsafe",
    )
    mgr = ExportManager(policy=ExportPolicy(), processor=proc)
    art, serialized, count = mgr.create_export(
        entries=[safe_entry, unsafe_entry],
        export_token_verified=True,
    )
    assert count == 1
    assert "safe-1" in serialized
    assert "unsafe-1" not in serialized


def test_feature_flag_dimension_validation_disabled():
    cfg = AnalyticsConfig(
        features=AnalyticsFeatureFlags(dimension_validation_enabled=False)
    )
    allowlist = EventAllowlist()
    allowlist.add_allowed("test_event")
    eng = AnalyticsEngine(config=cfg, allowlist=allowlist)

    # When disabled, event is not dropped by dimension validation
    payload = {"labels": {"evidence_hash": "a3f5c6d7e8f9b0c1d2e3f4a5b6c7d8e9f0a1b2c3"}}
    event = eng.process_event(
        event_name="test_event",
        category="user.action",
        payload=payload,
    )
    assert event.rejection_reason != "dimension_rejected_hash"
