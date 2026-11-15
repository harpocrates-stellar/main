"""Tests separating empty analytics exports from unavailable analytics stores."""

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

from analytics.consent import (
    ConsentManager,
    ConsentStoreUnavailableError,
)
from analytics.export_manager import (
    AnalyticsStoreUnavailableError,
    ExportManager,
    ExportPolicy,
    ExportStatus,
)
from analytics.log_processor import LogEntry, LogProcessor


def _safe_entry(entry_id: str = "evt-1", ts: float = 100.0) -> LogEntry:
    return LogEntry(
        entry_id=entry_id,
        event_name="api_request",
        message_summary="request ok",
        timestamp_epoch_seconds=ts,
        export_safe=True,
        export_signature="sig-v1:123456789abc",
    )


def test_healthy_empty_export_reports_empty_status_distinct_from_completed() -> None:
    mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor())

    empty_outcome = mgr.export_with_status(entries=[], export_token_verified=True)
    assert empty_outcome.status == ExportStatus.EMPTY
    assert empty_outcome.ok is True
    assert empty_outcome.retryable is False
    assert empty_outcome.entry_count == 0
    assert empty_outcome.artifact is not None
    assert empty_outcome.artifact.export_status == ExportStatus.EMPTY
    assert json.loads(empty_outcome.serialized or "") == []
    assert empty_outcome.to_dict()["status"] == "empty"

    completed_outcome = mgr.export_with_status(
        entries=[_safe_entry("e1")],
        export_token_verified=True,
    )
    assert completed_outcome.status == ExportStatus.COMPLETED
    assert completed_outcome.ok is True
    assert completed_outcome.retryable is False
    assert completed_outcome.entry_count == 1
    assert completed_outcome.artifact is not None
    assert completed_outcome.artifact.export_status == ExportStatus.COMPLETED


def test_missing_processor_returns_store_unavailable_not_zero_record_artifact() -> None:
    mgr = ExportManager(policy=ExportPolicy(), processor=None)
    assert mgr.is_store_available() is False

    art, reason, count = mgr.create_export(
        entries=[_safe_entry("e1")],
        export_token_verified=True,
    )
    assert art is None
    assert reason == ExportStatus.STORE_UNAVAILABLE
    assert count == 0
    assert mgr.list_artifacts() == []

    outcome = mgr.export_with_status(export_token_verified=True)
    assert outcome.status == ExportStatus.STORE_UNAVAILABLE
    assert outcome.ok is False
    assert outcome.retryable is True
    assert outcome.artifact is None
    assert outcome.serialized is None
    assert outcome.to_dict() == {
        "status": "store_unavailable",
        "ok": False,
        "entry_count": 0,
        "retryable": True,
        "artifact_id": None,
    }


def test_store_outage_toggle_and_health_callback_prevent_false_empty_export() -> None:
    proc = LogProcessor()
    ok, _ = proc.ingest(_safe_entry("p1"))
    assert ok

    healthy = {"up": True}
    mgr = ExportManager(
        policy=ExportPolicy(),
        processor=proc,
        store_health_check=lambda: healthy["up"],
    )

    # Healthy baseline exports 1 record
    up_outcome = mgr.export_with_status(export_token_verified=True)
    assert up_outcome.status == ExportStatus.COMPLETED
    assert up_outcome.entry_count == 1

    # Simulate backend store outage via health check
    healthy["up"] = False
    down_outcome = mgr.export_with_status(export_token_verified=True)
    assert down_outcome.status == ExportStatus.STORE_UNAVAILABLE
    assert down_outcome.artifact is None
    assert down_outcome.retryable is True
    assert len(mgr.list_artifacts()) == 1  # No bogus empty artifact recorded!

    # Simulate outage via explicit set_store_available(False)
    healthy["up"] = True
    mgr.set_store_available(False)
    down2 = mgr.export_with_status(export_token_verified=True)
    assert down2.status == ExportStatus.STORE_UNAVAILABLE
    assert down2.artifact is None

    # Recovery restores normal operation
    mgr.set_store_available(True)
    recovered = mgr.export_with_status(export_token_verified=True)
    assert recovered.status == ExportStatus.COMPLETED
    assert recovered.entry_count == 1


def test_processor_read_or_serialize_exception_reports_store_unavailable() -> None:
    class BrokenReadProcessor(LogProcessor):
        def read_entries(self):
            raise OSError("disk read failure on /var/private/analytics.db")

    mgr_read_err = ExportManager(policy=ExportPolicy(), processor=BrokenReadProcessor())
    out1 = mgr_read_err.export_with_status(export_token_verified=True)
    assert out1.status == ExportStatus.STORE_UNAVAILABLE
    assert out1.artifact is None
    assert out1.retryable is True
    assert "/var/private" not in json.dumps(out1.to_dict())

    class BrokenSerializeProcessor(LogProcessor):
        def export_json_logs(self, *args, **kwargs):
            raise AnalyticsStoreUnavailableError("serializer backend unreachable")

    mgr_ser_err = ExportManager(policy=ExportPolicy(), processor=BrokenSerializeProcessor())
    out2 = mgr_ser_err.export_with_status(entries=[_safe_entry("x")], export_token_verified=True)
    assert out2.status == ExportStatus.STORE_UNAVAILABLE
    assert out2.artifact is None
    assert out2.retryable is True


def test_consent_store_outage_propagates_store_unavailable() -> None:
    cm = ConsentManager(store_available=False)
    assert cm.is_store_available() is False
    with pytest.raises(ConsentStoreUnavailableError):
        cm.check_consent("acct_1", scope="telemetry")

    mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor(), consent_manager=cm)
    outcome = mgr.export_with_status(exported_by_tag="acct_1", export_token_verified=True)
    assert outcome.status == ExportStatus.STORE_UNAVAILABLE
    assert outcome.artifact is None
    assert outcome.retryable is True

    cm.set_store_available(True)
    recovered = mgr.export_with_status(entries=[], exported_by_tag="acct_1", export_token_verified=True)
    assert recovered.status == ExportStatus.EMPTY
    assert recovered.ok is True


def test_unauthenticated_rejection_remains_distinct_from_store_unavailable() -> None:
    mgr = ExportManager(
        policy=ExportPolicy(allow_unauthenticated_export_shadow_mode=False),
        processor=LogProcessor(),
    )
    outcome = mgr.export_with_status(entries=[_safe_entry("a")], export_token_verified=False)
    assert outcome.status == ExportStatus.EXPORT_TOKEN_REQUIRED
    assert outcome.ok is False
    assert outcome.retryable is False
    assert outcome.artifact is None
