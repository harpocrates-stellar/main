"""Focused tests for analytics export date-range validation (issue #1118).

Covers validate_export_date_range directly and the create_export integration:
- Contradictory ranges (start > end) are rejected before storage access.
- Excessively large ranges are rejected before storage access.
- Negative timestamps are rejected.
- Both-None is accepted (unrestricted query).
- Policy override of max_export_range_seconds is respected.
- Zero max_export_range_seconds disables the upper-bound check.
- Valid ranges filter entries correctly and return deterministic UTC boundaries
  in the validation error payload.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

backend_dir = str(Path(__file__).resolve().parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import pytest

from analytics.export_manager import (
    EXPORT_MAX_RANGE_SECONDS_DEFAULT,
    ExportManager,
    ExportPolicy,
    validate_export_date_range,
)
from analytics.log_processor import LogEntry, LogProcessor


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _entry(entry_id: str, ts: float) -> LogEntry:
    return LogEntry(
        entry_id=entry_id,
        event_name="evt",
        message_summary="ok",
        timestamp_epoch_seconds=ts,
        export_safe=True,
        export_signature="sig-v1:abc",
    )


def _manager(**policy_kw) -> ExportManager:
    return ExportManager(policy=ExportPolicy(**policy_kw), processor=LogProcessor())


def _export(mgr: ExportManager, entries, **kw):
    kw.setdefault("export_token_verified", True)
    return mgr.create_export(entries=entries, **kw)


# ---------------------------------------------------------------------------
# validate_export_date_range — unit tests
# ---------------------------------------------------------------------------


class TestValidateExportDateRange:
    def test_both_none_is_ok(self):
        ok, reason, s, e = validate_export_date_range(None, None)
        assert ok is True
        assert reason == "ok"
        assert s is None and e is None

    def test_valid_range_returned_unchanged(self):
        ok, reason, s, e = validate_export_date_range(1_000.0, 2_000.0)
        assert ok is True
        assert s == 1_000.0 and e == 2_000.0

    def test_start_equals_end_is_ok(self):
        ok, reason, s, e = validate_export_date_range(5_000.0, 5_000.0)
        assert ok is True
        assert s == 5_000.0 and e == 5_000.0

    def test_contradictory_range_start_after_end(self):
        ok, reason, s, e = validate_export_date_range(2_000.0, 1_000.0)
        assert ok is False
        assert reason == "start_time_after_end_time"
        # Boundaries are deterministic UTC values, not None.
        assert s == 2_000.0
        assert e == 1_000.0

    def test_range_exceeds_maximum(self):
        limit = 7 * 86400.0  # 7 days
        span = limit + 1.0
        ok, reason, s, e = validate_export_date_range(0.0, span, max_range_seconds=limit)
        assert ok is False
        assert reason == "date_range_exceeds_maximum"
        assert s == 0.0 and e == span

    def test_range_exactly_at_maximum_is_ok(self):
        limit = 7 * 86400.0
        ok, reason, s, e = validate_export_date_range(0.0, limit, max_range_seconds=limit)
        assert ok is True

    def test_negative_start_rejected(self):
        ok, reason, s, e = validate_export_date_range(-1.0, 1_000.0)
        assert ok is False
        assert reason == "start_time_negative"
        assert s is None and e is None

    def test_negative_end_rejected(self):
        ok, reason, s, e = validate_export_date_range(1_000.0, -1.0)
        assert ok is False
        assert reason == "end_time_negative"
        assert s is None and e is None

    def test_zero_max_range_disables_upper_bound(self):
        # With max_range_seconds=0 any span is accepted.
        ok, reason, s, e = validate_export_date_range(0.0, 999_999_999.0, max_range_seconds=0)
        assert ok is True

    def test_only_start_provided(self):
        ok, reason, s, e = validate_export_date_range(1_000.0, None)
        assert ok is True
        assert s == 1_000.0 and e is None

    def test_only_end_provided(self):
        ok, reason, s, e = validate_export_date_range(None, 5_000.0)
        assert ok is True
        assert s is None and e == 5_000.0

    def test_custom_max_range_respected(self):
        ok, _, _, _ = validate_export_date_range(0.0, 3600.0, max_range_seconds=3600.0)
        assert ok is True
        ok2, reason, _, _ = validate_export_date_range(0.0, 3601.0, max_range_seconds=3600.0)
        assert ok2 is False
        assert reason == "date_range_exceeds_maximum"

    def test_default_max_range_is_90_days(self):
        assert EXPORT_MAX_RANGE_SECONDS_DEFAULT == 90 * 86400.0
        ok, _, _, _ = validate_export_date_range(0.0, EXPORT_MAX_RANGE_SECONDS_DEFAULT)
        assert ok is True
        ok2, reason, _, _ = validate_export_date_range(0.0, EXPORT_MAX_RANGE_SECONDS_DEFAULT + 1.0)
        assert ok2 is False
        assert reason == "date_range_exceeds_maximum"


# ---------------------------------------------------------------------------
# create_export date-range integration tests
# ---------------------------------------------------------------------------


class TestCreateExportDateRange:
    def test_contradictory_range_rejected_before_storage(self):
        mgr = _manager()
        # Processor is present; failure must come from range validation, not storage.
        art, reason, count = _export(mgr, [_entry("a", 100.0)], start_time=500.0, end_time=100.0)
        assert art is None
        assert reason == "start_time_after_end_time"
        assert count == 0
        # Nothing stored.
        assert mgr.list_artifacts() == []

    def test_oversized_range_rejected_before_storage(self):
        limit = 86400.0  # 1 day
        mgr = _manager(max_export_range_seconds=limit)
        art, reason, count = _export(
            mgr, [_entry("a", 100.0)], start_time=0.0, end_time=limit + 1.0
        )
        assert art is None
        assert reason == "date_range_exceeds_maximum"
        assert count == 0
        assert mgr.list_artifacts() == []

    def test_valid_range_filters_entries_correctly(self):
        mgr = _manager()
        entries = [
            _entry("before", 50.0),
            _entry("in_range_1", 100.0),
            _entry("in_range_2", 200.0),
            _entry("after", 350.0),
        ]
        art, serialized, count = _export(mgr, entries, start_time=100.0, end_time=300.0)
        assert art is not None
        assert count == 2
        ids = [d["entry_id"] for d in json.loads(serialized)]
        assert "in_range_1" in ids
        assert "in_range_2" in ids
        assert "before" not in ids
        assert "after" not in ids

    def test_no_range_exports_all_entries(self):
        mgr = _manager()
        entries = [_entry(f"e{i}", float(i)) for i in range(5)]
        art, serialized, count = _export(mgr, entries)
        assert count == 5

    def test_range_with_no_matching_entries_returns_empty_artifact(self):
        mgr = _manager()
        entries = [_entry("a", 1000.0), _entry("b", 2000.0)]
        art, serialized, count = _export(mgr, entries, start_time=5000.0, end_time=6000.0)
        assert art is not None
        assert count == 0
        assert json.loads(serialized) == []

    def test_policy_max_range_overrides_default(self):
        small_limit = 3600.0
        mgr = _manager(max_export_range_seconds=small_limit)
        art, reason, count = _export(
            mgr, [_entry("a", 0.0)], start_time=0.0, end_time=small_limit + 1.0
        )
        assert art is None
        assert reason == "date_range_exceeds_maximum"

    def test_policy_zero_max_range_disables_limit(self):
        mgr = _manager(max_export_range_seconds=0)
        entries = [_entry("a", 0.0), _entry("b", 999_999_999.0)]
        art, serialized, count = _export(mgr, entries, start_time=0.0, end_time=999_999_999.0)
        assert art is not None
        assert count == 2

    def test_range_validation_runs_before_token_check(self):
        # Even with shadow mode disabled, an invalid range is caught first.
        mgr = _manager(allow_unauthenticated_export_shadow_mode=False)
        art, reason, count = mgr.create_export(
            entries=[_entry("a", 100.0)],
            export_token_verified=False,
            start_time=500.0,
            end_time=100.0,
        )
        assert art is None
        assert reason == "start_time_after_end_time"

    def test_start_time_boundary_inclusive(self):
        mgr = _manager()
        art, serialized, count = _export(mgr, [_entry("a", 100.0)], start_time=100.0)
        assert count == 1

    def test_end_time_boundary_inclusive(self):
        mgr = _manager()
        art, serialized, count = _export(mgr, [_entry("a", 100.0)], end_time=100.0)
        assert count == 1
