"""Tests for tenant-isolated, bounded analytics deletion previews."""

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
    ConsentDecision,
    ConsentManager,
    ConsentSource,
    ConsentStatus,
)
from analytics.export_manager import (
    AnalyticsDataClass,
    ExportManager,
    ExportPolicy,
    TenantIsolationError,
)
from analytics.log_processor import LogEntry, LogProcessor


def _make_log(entry_id: str, ts: float, account_tag: str | None) -> LogEntry:
    return LogEntry(
        entry_id=entry_id,
        event_name=f"evt_{entry_id}",
        message_summary="operational metric",
        timestamp_epoch_seconds=ts,
        account_id_tag=account_tag,
        export_safe=True,
        export_signature="sig-v1:123456789abc",
    )


def test_deletion_preview_groups_bounded_counts_by_class_and_policy_without_mutating() -> None:
    now = 200_000.0
    cm = ConsentManager()
    proc = LogProcessor()
    mgr = ExportManager(
        policy=ExportPolicy(
            preview_bucket_cap=4,
            log_retention_ttl_seconds=10_000.0,
            artifact_retention_ttl_seconds=10_000.0,
        ),
        processor=proc,
        consent_manager=cm,
    )

    cm.set_consent(
        "tenant_alpha",
        ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            granted_at_epoch_seconds=now - 1_000.0,
            expires_at_epoch_seconds=now + 50_000.0,
            consent_token="cst-v1:secret_alpha_token",
        ),
    )

    # 6 active logs (exceeds cap=4) + 2 expired logs for tenant_alpha
    for i in range(6):
        ok, err = proc.ingest(_make_log(f"alpha_active_{i}", now - 500.0, "tenant_alpha"), allow_duplicate=True)
        assert ok, err
    for i in range(2):
        ok, err = proc.ingest(_make_log(f"alpha_old_{i}", now - 20_000.0, "tenant_alpha"), allow_duplicate=True)
        assert ok, err

    # 3 export artifacts (2 active, 1 expired) for tenant_alpha
    for i in range(2):
        art, _, _ = mgr.create_export(
            entries=[_make_log(f"a_exp_{i}", 10.0, "tenant_alpha")],
            exported_by_tag="tenant_alpha",
            export_token_verified=True,
        )
        assert art is not None
        art.generated_at_epoch_seconds = now - 200.0
    art_old, _, _ = mgr.create_export(
        entries=[_make_log("a_exp_old", 10.0, "tenant_alpha")],
        exported_by_tag="tenant_alpha",
        export_token_verified=True,
    )
    assert art_old is not None
    art_old.generated_at_epoch_seconds = now - 30_000.0

    # Populate noise for tenant_bravo and anonymous logs — must NOT leak into tenant_alpha's preview!
    cm.withdraw_consent("tenant_bravo")
    for i in range(10):
        proc.ingest(_make_log(f"bravo_{i}", now - 100.0, "tenant_bravo"), allow_duplicate=True)
    proc.ingest(_make_log("anon_0", now - 100.0, None), allow_duplicate=True)
    mgr.create_export(
        entries=[_make_log("b_exp", 10.0, "tenant_bravo")],
        exported_by_tag="tenant_bravo",
        export_token_verified=True,
    )

    report = mgr.preview_tenant_deletion(
        "tenant_alpha",
        requested_tenant_tag="tenant_alpha",
        export_token_verified=True,
        now_epoch_seconds=now,
    )

    assert report.read_only is True
    assert report.max_count_per_bucket == 4
    assert len(report.tenant_tag_digest) == 64

    bucket_map = {(b.data_class, b.retention_policy): (b.bounded_count, b.capped) for b in report.buckets}
    assert bucket_map[(AnalyticsDataClass.CONSENT_RECORDS, "active_consent_revocation")] == (1, False)
    assert bucket_map[(AnalyticsDataClass.OPERATIONAL_LOGS, "active_log_ttl")] == (4, True)
    assert bucket_map[(AnalyticsDataClass.OPERATIONAL_LOGS, "expired_log_ttl")] == (2, False)
    assert bucket_map[(AnalyticsDataClass.EXPORT_ARTIFACTS, "active_artifact_ttl")] == (2, False)
    assert bucket_map[(AnalyticsDataClass.EXPORT_ARTIFACTS, "expired_artifact_ttl")] == (1, False)

    # Class rollup for operational_logs (6 + 2 = 8 > 4) is also bounded!
    assert report.by_data_class[AnalyticsDataClass.CONSENT_RECORDS] == {"bounded_count": 1, "capped": False}
    assert report.by_data_class[AnalyticsDataClass.OPERATIONAL_LOGS] == {"bounded_count": 4, "capped": True}
    assert report.by_data_class[AnalyticsDataClass.EXPORT_ARTIFACTS] == {"bounded_count": 3, "capped": False}
    assert report.total_bounded_count == 12
    assert report.total_capped is False

    # Privacy check: no raw tenant tags, tokens, or entry IDs appear in serialized preview
    serialized = json.dumps(report.to_dict())
    assert "tenant_alpha" not in serialized
    assert "tenant_bravo" not in serialized
    assert "secret_alpha_token" not in serialized
    assert "alpha_active" not in serialized

    # Read-only guarantee: underlying stores are completely untouched
    assert "tenant_alpha" in cm._consent_states
    assert len(proc._entries) == 19
    assert len(mgr.list_artifacts()) == 4


def test_withdrawn_tenant_classifies_logs_and_artifacts_under_immediate_purge() -> None:
    now = 50_000.0
    cm = ConsentManager()
    proc = LogProcessor()
    mgr = ExportManager(policy=ExportPolicy(), processor=proc, consent_manager=cm)

    cm.withdraw_consent("tenant_withdrawn")
    proc.ingest(_make_log("w_log_1", now - 10.0, "tenant_withdrawn"), allow_duplicate=True)
    art, _, _ = mgr.create_export(
        entries=[_make_log("w_exp", 10.0, "tenant_withdrawn")],
        exported_by_tag="tenant_withdrawn",
        export_token_verified=True,
    )
    assert art is not None
    art.generated_at_epoch_seconds = now - 10.0

    report = mgr.preview_tenant_deletion("tenant_withdrawn", now_epoch_seconds=now)
    bucket_map = {(b.data_class, b.retention_policy): b.bounded_count for b in report.buckets}
    assert bucket_map[(AnalyticsDataClass.CONSENT_RECORDS, "withdrawn_consent_grace")] == 1
    assert bucket_map[(AnalyticsDataClass.OPERATIONAL_LOGS, "withdrawn_immediate_purge")] == 1
    assert bucket_map[(AnalyticsDataClass.EXPORT_ARTIFACTS, "withdrawn_immediate_purge")] == 1
    assert report.by_retention_policy["withdrawn_immediate_purge"] == {"bounded_count": 2, "capped": False}


def test_tenant_isolation_rejects_cross_tenant_wildcard_and_unverified_requests() -> None:
    cm = ConsentManager()
    proc = LogProcessor()
    mgr = ExportManager(policy=ExportPolicy(), processor=proc, consent_manager=cm)
    proc.ingest(_make_log("v1", 100.0, "tenant_victim"), allow_duplicate=True)

    # Cross-tenant request rejected fail-closed
    with pytest.raises(TenantIsolationError, match="cross-tenant"):
        mgr.preview_tenant_deletion(
            "tenant_caller",
            requested_tenant_tag="tenant_victim",
            export_token_verified=True,
        )

    # Unverified caller rejected fail-closed
    with pytest.raises(TenantIsolationError, match="verified authorization"):
        mgr.preview_tenant_deletion("tenant_victim", export_token_verified=False)

    # Wildcard / empty / malformed tenant tags rejected
    for bad_tag in ("", "   ", "*", "tenant/*", "tenant\x00id"):
        with pytest.raises(TenantIsolationError):
            mgr.preview_tenant_deletion(bad_tag, export_token_verified=True)

    with pytest.raises(ValueError, match="max_count_per_bucket"):
        mgr.preview_tenant_deletion("tenant_victim", max_count_per_bucket=0)

    # Tenant with zero data sees clean zero counts and zero leakage of tenant_victim
    clean_report = mgr.preview_tenant_deletion("tenant_empty", export_token_verified=True)
    assert clean_report.total_bounded_count == 0
    assert clean_report.buckets == []
