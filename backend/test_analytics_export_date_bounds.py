"""Tests for pre-storage analytics export date range validation and UTC error bounds."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

_BACKEND_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _BACKEND_DIR.parent
for _p in (str(_BACKEND_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from analytics.consent import (
    ConsentDecision,
    ConsentManager,
    ConsentSource,
    ConsentStatus,
)
from analytics.export_manager import (
    DEFAULT_MAX_EXPORT_RANGE_SECONDS,
    ExportDateRangeError,
    ExportManager,
    ExportPolicy,
    format_utc_iso8601,
    validate_export_date_range,
)
from analytics.log_processor import LogEntry, LogProcessor


def _safe_entry(entry_id: str, ts: float) -> LogEntry:
    return LogEntry(
        entry_id=entry_id,
        event_name=f"evt_{entry_id}",
        message_summary="request ok",
        timestamp_epoch_seconds=ts,
        export_safe=True,
        export_signature="sig-v1:123456789abc",
    )


def test_contradictory_interval_rejected_before_querying_storage() -> None:
    storage_calls = {"count": 0}

    def _exploding_storage(_start, _end):
        storage_calls["count"] += 1
        raise AssertionError("storage must never be queried on invalid date bounds")

    mgr = ExportManager(
        policy=ExportPolicy(max_export_range_seconds=86_400),
        processor=LogProcessor(),
        storage_query=_exploding_storage,
    )

    with pytest.raises(ExportDateRangeError) as exc_info:
        mgr.create_export(
            export_token_verified=True,
            start_time="2026-03-10T12:00:00Z",
            end_time="2026-03-10T11:59:59Z",
        )

    assert storage_calls["count"] == 0
    err = exc_info.value
    assert err.code == "contradictory_date_range"
    assert err.start_utc == "2026-03-10T12:00:00Z"
    assert err.end_utc == "2026-03-10T11:59:59Z"
    assert err.allowed_start_utc == "2026-03-10T12:00:00Z"
    assert err.allowed_end_utc == "2026-03-11T12:00:00Z"
    assert err.max_range_seconds == 86_400
    assert "2026-03-10T12:00:00Z" in str(err)


def test_excessively_large_interval_rejected_before_querying_storage() -> None:
    storage_calls = {"count": 0}

    def _spy_storage(_start, _end):
        storage_calls["count"] += 1
        return []

    mgr = ExportManager(
        policy=ExportPolicy(max_export_range_seconds=3_600),
        processor=LogProcessor(),
        storage_query=_spy_storage,
    )

    with pytest.raises(ExportDateRangeError) as exc_info:
        mgr.create_export(
            export_token_verified=True,
            start_time="2026-05-01T00:00:00Z",
            end_time="2026-05-01T01:00:01Z",
        )

    assert storage_calls["count"] == 0
    err = exc_info.value
    assert err.to_dict() == {
        "code": "date_range_too_large",
        "message": "requested export interval exceeds maximum allowed span",
        "start_utc": "2026-05-01T00:00:00Z",
        "end_utc": "2026-05-01T01:00:01Z",
        "allowed_start_utc": "2026-05-01T00:00:00Z",
        "allowed_end_utc": "2026-05-01T01:00:00Z",
        "max_range_seconds": 3600,
    }


def test_non_utc_offset_inputs_normalize_to_deterministic_utc_boundaries() -> None:
    tz_plus_2 = timezone(timedelta(hours=2))
    dt_start = datetime(2026, 6, 15, 14, 0, 0, tzinfo=tz_plus_2)  # 12:00:00Z
    dt_end = "2026-06-15T11:00:00+00:00"  # 11:00:00Z -> contradictory!

    with pytest.raises(ExportDateRangeError) as exc_info:
        validate_export_date_range(dt_start, dt_end, max_range_seconds=7_200)

    err = exc_info.value
    assert err.code == "contradictory_date_range"
    assert err.start_utc == "2026-06-15T12:00:00Z"
    assert err.end_utc == "2026-06-15T11:00:00Z"
    assert err.allowed_end_utc == "2026-06-15T14:00:00Z"


def test_valid_date_range_queries_storage_and_filters_entries_inclusively() -> None:
    queried_bounds: list[tuple[float | None, float | None]] = []

    t0 = 1_770_000_000.0
    all_entries = [
        _safe_entry("before", t0 - 1.0),
        _safe_entry("at_start", t0),
        _safe_entry("middle", t0 + 300.0),
        _safe_entry("at_end", t0 + 600.0),
        _safe_entry("after", t0 + 601.0),
    ]

    def _storage_reader(start_ep, end_ep):
        queried_bounds.append((start_ep, end_ep))
        return list(all_entries)

    mgr = ExportManager(
        policy=ExportPolicy(max_export_range_seconds=3_600),
        processor=LogProcessor(),
        storage_query=_storage_reader,
    )

    art, serialized, count = mgr.create_export(
        export_token_verified=True,
        start_time=t0,
        end_time=t0 + 600.0,
    )
    assert queried_bounds == [(t0, t0 + 600.0)]
    assert art is not None
    assert count == 3
    assert [item["entry_id"] for item in json.loads(serialized)] == [
        "at_start",
        "middle",
        "at_end",
    ]
    assert art.window_start_utc == format_utc_iso8601(t0)
    assert art.window_end_utc == format_utc_iso8601(t0 + 600.0)


def test_consent_window_bounds_reject_out_of_window_exports_before_storage() -> None:
    cm = ConsentManager()
    cm.set_consent(
        "acct_bounded",
        ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            granted_at_epoch_seconds=1_770_001_000.0,
            expires_at_epoch_seconds=1_770_005_000.0,
        ),
    )

    storage_hit = {"called": False}

    def _never_called(_s, _e):
        storage_hit["called"] = True
        return []

    mgr = ExportManager(
        policy=ExportPolicy(),
        processor=LogProcessor(),
        consent_manager=cm,
        storage_query=_never_called,
    )

    with pytest.raises(ExportDateRangeError) as exc_info:
        mgr.create_export(
            exported_by_tag="acct_bounded",
            export_token_verified=True,
            start_time=1_770_000_000.0,
            end_time=1_770_000_500.0,
        )

    assert storage_hit["called"] is False
    err = exc_info.value
    assert err.code == "outside_consent_window"
    assert err.allowed_start_utc == format_utc_iso8601(1_770_001_000.0)
    assert err.allowed_end_utc == format_utc_iso8601(1_770_005_000.0)


@pytest.mark.parametrize(
    ("start_val", "end_val", "expected_code"),
    [
        ("2026-01-01T00:00:00Z", None, "incomplete_date_range"),
        (None, "2026-01-01T01:00:00Z", "incomplete_date_range"),
        ("2026-01-01T00:00:00", "2026-01-01T01:00:00Z", "timezone_required"),
        (datetime(2026, 1, 1, 0, 0, 0), "2026-01-01T01:00:00Z", "timezone_required"),
        ("not-a-timestamp", "2026-01-01T01:00:00Z", "invalid_timestamp"),
        (-10.0, 100.0, "invalid_timestamp"),
        (float("nan"), 100.0, "invalid_timestamp"),
        (True, 100.0, "invalid_timestamp"),
    ],
)
def test_invalid_or_incomplete_date_inputs_rejected_with_deterministic_utc_bounds(
    start_val, end_val, expected_code: str
) -> None:
    with pytest.raises(ExportDateRangeError) as exc_info:
        validate_export_date_range(start_val, end_val)
    err = exc_info.value
    assert err.code == expected_code
    assert err.max_range_seconds == DEFAULT_MAX_EXPORT_RANGE_SECONDS
    assert err.allowed_start_utc is not None and err.allowed_start_utc.endswith("Z")
    assert err.allowed_end_utc is not None and err.allowed_end_utc.endswith("Z")
