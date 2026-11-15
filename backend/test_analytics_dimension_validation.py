"""Tests rejecting analytics dimensions and label values that can identify uploaded evidence."""

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

from analytics.consent import ConsentDecision, ConsentManager, ConsentSource, ConsentStatus
from analytics.export_manager import (
    ALLOWED_ANALYTICS_DIMENSIONS,
    EvidenceDimensionError,
    ExportManager,
    ExportPolicy,
    validate_analytics_dimensions,
    validate_dimension_vocabulary,
)
from analytics.log_processor import LogEntry, LogProcessor
from analytics.metrics_collector import AnalyticsOperationalMetrics, MetricDomain


def _entry(
    entry_id: str,
    *,
    endpoint: str = "/api/proofs/by-video/<video_hash>",
    method: str = "GET",
    status_code: int = 200,
    labels: dict[str, str] | None = None,
) -> LogEntry:
    return LogEntry(
        entry_id=entry_id,
        event_name="request_done",
        message_summary="request completed",
        timestamp_epoch_seconds=100.0,
        endpoint_pattern=endpoint,
        method=method,
        status_code=status_code,
        labels=labels or {},
        export_safe=True,
        export_signature="sig-v1:123456789abc",
    )


def test_allowed_dimensions_aggregate_cleanly() -> None:
    mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor())
    entries = [
        _entry("e1", endpoint="/api/proofs/by-video/<video_hash>", method="GET", status_code=200),
        _entry("e2", endpoint="/api/proofs/by-video/<video_hash>", method="GET", status_code=200),
        _entry("e3", endpoint="/api/stego/embed", method="POST", status_code=201),
    ]

    grouped = mgr.aggregate_by_dimensions(["endpoint", "method", "status"], entries=entries)
    assert grouped[(("endpoint", "/api/proofs/by-video/<video_hash>"), ("method", "GET"), ("status", "200"))] == 2
    assert grouped[(("endpoint", "/api/stego/embed"), ("method", "POST"), ("status", "201"))] == 1


@pytest.mark.parametrize(
    "forbidden_key",
    [
        "video_hash",
        "metadata_hash",
        "embedded_hash",
        "tx_hash",
        "proof_id",
        "witness_hash",
        "filename",
        "file_name",
        "upload_path",
        "cid",
        "account_id",
    ],
)
def test_disallowed_dimension_keys_rejected_before_aggregation(forbidden_key: str) -> None:
    mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor())

    with pytest.raises(EvidenceDimensionError) as exc_info:
        validate_dimension_vocabulary(["endpoint", forbidden_key])
    assert exc_info.value.code == "disallowed_dimension_key"

    with pytest.raises(EvidenceDimensionError) as exc_info2:
        mgr.aggregate_by_dimensions([forbidden_key], entries=[_entry("e1")])
    assert exc_info2.value.code == "disallowed_dimension_key"

    # Also rejected if attached inside entry.labels even when group_by uses allowed keys
    bad_entry = _entry("e_bad", labels={forbidden_key: "ok_val"})
    with pytest.raises(EvidenceDimensionError) as exc_info3:
        mgr.aggregate_by_dimensions(["method"], entries=[bad_entry])
    assert exc_info3.value.code == "disallowed_dimension_key"


@pytest.mark.parametrize(
    ("dim_key", "hash_value"),
    [
        ("error_code", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
        ("category", "0x0123456789abcdef0123456789abcdef"),
        ("source", "sha256:4b227777d4dd1fc61c6f884f48641d02"),
        ("operation", "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"),
        ("operation", "550e8400-e29b-41d4-a716-446655440000"),
        ("source", "G" + ("A" * 55)),
        ("source", "S" + ("B" * 55)),
        ("endpoint", "/api/proofs/by-video/9f86d081884c7d659a2feaa0c55ad015"),
        ("category", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="),
    ],
)
def test_hash_and_digest_values_rejected_without_echoing_sensitive_value(
    dim_key: str, hash_value: str
) -> None:
    assert dim_key in ALLOWED_ANALYTICS_DIMENSIONS
    with pytest.raises(EvidenceDimensionError) as exc_info:
        validate_analytics_dimensions({dim_key: hash_value})

    err = exc_info.value
    assert err.code == "hash_like_dimension_value"
    assert err.dimension_key == dim_key
    # Offending hash must never be echoed in error string or structured dict
    assert hash_value not in str(err)
    assert hash_value not in json.dumps(err.to_dict())


@pytest.mark.parametrize(
    ("dim_key", "filename_value"),
    [
        ("source", "whistleblower_clip.mp4"),
        ("category", "interview_recording.wav"),
        ("operation", "frame_capture_001.png"),
        ("error_code", "witness_dump.wtns"),
        ("version", "archive_bundle.tar.gz"),
        ("endpoint", "/uploads/raw_evidence.mov"),
        ("endpoint", "C:\\Users\\reporter\\evidence.mkv"),
        ("source", "/var/tmp/upload_991"),
        ("endpoint", "/api/v1/../secret"),
    ],
)
def test_raw_filenames_and_paths_rejected_as_dimension_labels(
    dim_key: str, filename_value: str
) -> None:
    assert dim_key in ALLOWED_ANALYTICS_DIMENSIONS
    with pytest.raises(EvidenceDimensionError) as exc_info:
        validate_analytics_dimensions({dim_key: filename_value})

    err = exc_info.value
    assert err.code == "filename_dimension_value"
    assert filename_value not in str(err)


def test_metrics_collector_and_consent_manager_reject_evidence_dimensions_atomically() -> None:
    metrics = AnalyticsOperationalMetrics()

    # Valid low-cardinality operational dimensions succeed
    val = metrics.record_dimensioned_counter(
        MetricDomain.ANALYTICS,
        "http_requests_total",
        {"endpoint": "/api/stego/embed", "method": "POST", "status": 200},
    )
    assert val == 1
    snap = metrics.snapshot()
    assert snap["dimensioned_counters"][
        "analytics:http_requests_total{endpoint=/api/stego/embed,method=POST,status=200}"
    ] == 1

    # Attempt to record hash or filename fails BEFORE polluting metric series
    with pytest.raises(EvidenceDimensionError):
        metrics.record_dimensioned_counter(
            MetricDomain.ANALYTICS,
            "http_requests_total",
            {"endpoint": "/uploads/leaked_clip.mp4", "method": "POST"},
        )
    with pytest.raises(EvidenceDimensionError):
        metrics.record_dimensioned_counter(
            MetricDomain.ANALYTICS,
            "http_requests_total",
            {"video_hash": "abcdef0123456789abcdef0123456789"},
        )
    assert len(metrics.snapshot()["dimensioned_counters"]) == 1

    # ConsentManager.validate_consented_dimensions enforces vocabulary before consent check
    cm = ConsentManager()
    cm.set_consent(
        "acct_ok",
        ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            granted_at_epoch_seconds=10.0,
            expires_at_epoch_seconds=99_999.0,
        ),
    )
    allowed, clean = cm.validate_consented_dimensions(
        "acct_ok",
        "telemetry",
        {"method": "GET", "status": 200},
        now_epoch_seconds=50.0,
    )
    assert allowed is True
    assert clean == {"method": "GET", "status": "200"}

    with pytest.raises(EvidenceDimensionError):
        cm.validate_consented_dimensions(
            "acct_ok",
            "telemetry",
            {"source": "evidence_video.mp4"},
            now_epoch_seconds=50.0,
        )


def test_create_export_filters_entries_carrying_hash_or_filename_labels() -> None:
    mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor())
    clean = _entry("clean_1", labels={"category": "stego", "method": "POST"})
    leaky_file = _entry("leak_file", labels={"source": "captured_evidence.mp4"})
    leaky_hash = _entry("leak_hash", labels={"category": "0123456789abcdef0123456789abcdef"})

    art, serialized, count = mgr.create_export(
        entries=[clean, leaky_file, leaky_hash],
        export_token_verified=True,
    )
    assert art is not None
    assert count == 1
    assert [d["entry_id"] for d in json.loads(serialized)] == ["clean_1"]
    assert "captured_evidence.mp4" not in serialized
    assert "0123456789abcdef0123456789abcdef" not in serialized
