"""Tests for privacy-preserving, tenant-isolated analytics deletion preview.

Covers:
- Bounded counts grouped by data_class and retention_policy across consent
  records, export artifacts, and analytics log entries
- Strict fail-closed tenant isolation (missing/empty/mismatched tenant rejected;
  cross-tenant and untagged records excluded)
- Upper-bound count capping (count_cap_per_bucket) and bucket truncation
  (max_buckets)
- Privacy guarantees (no raw tenant IDs, consent tokens, artifact IDs, or entry
  payloads leaked) and non-destructive dry-run behavior
"""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

backend_dir = str(Path(__file__).resolve().parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import pytest

from analytics.consent import (
    ConsentDecision,
    ConsentManager,
    ConsentSource,
    ConsentStatus,
)
from analytics.export_manager import (
    CONSENT_STATE_WITHDRAWN,
    DELETION_PREVIEW_SCHEMA_VERSION,
    DeletionPreviewPolicy,
    ExportManager,
    ExportPolicy,
    TenantAuthorizationError,
)
from analytics.log_processor import LogEntry, LogProcessor


def _make_entry(
    entry_id: str,
    ts: float,
    tenant: str | None = None,
    category: str | None = None,
    consent_withdrawn: bool = False,
) -> LogEntry:
    labels = {}
    if tenant is not None:
        labels["tenant_id"] = tenant
    if category is not None:
        labels["category"] = category
    entry = LogEntry(
        entry_id=entry_id,
        event_name="evt_test",
        message_summary="synthetic operational event",
        timestamp_epoch_seconds=ts,
        labels=labels,
        export_safe=True,
        export_signature="sig-v1:test",
    )
    if consent_withdrawn:
        setattr(entry, "consent_withdrawn", True)
    return entry


class TestDeletionPreviewTenantIsolation:
    """Fail-closed authorization and strict cross-tenant isolation."""

    @pytest.mark.parametrize(
        ("authorized", "requested", "match"),
        [
            (None, "tenant_a", "authorized_tenant_required"),
            ("", "tenant_a", "authorized_tenant_required"),
            ("   ", "tenant_a", "authorized_tenant_required"),
            ("tenant_a", None, "requested_tenant_required"),
            ("tenant_a", "", "requested_tenant_required"),
            ("tenant_a", "   ", "requested_tenant_required"),
            ("tenant_a", "tenant_b", "tenant_scope_mismatch"),
        ],
    )
    def test_unauthorized_or_mismatched_tenant_fails_closed(
        self, authorized: str | None, requested: str | None, match: str
    ) -> None:
        mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor())
        with pytest.raises(TenantAuthorizationError, match=match):
            mgr.preview_deletion(
                authorized_tenant=authorized,
                requested_tenant=requested,
            )

    def test_cross_tenant_and_untagged_records_are_excluded(self) -> None:
        now = 1_700_100_000.0
        consent_mgr = ConsentManager(grace_period_seconds=600)
        consent_mgr.set_consent(
            "tenant_a",
            ConsentDecision(
                status=ConsentStatus.GRANTED,
                source=ConsentSource.USER_EXPLICIT,
                scope=["telemetry"],
                expires_at_epoch_seconds=now + 3600,
                granted_at_epoch_seconds=now - 100,
                consent_token="cst-v1:secret_token_a",
                policy_revision="pol-v2",
            ),
        )
        consent_mgr.withdraw_consent("tenant_b")
        consent_mgr._consent_states["tenant_b"].last_modified_epoch_seconds = now - 5000

        export_mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor())
        art_a, _, _ = export_mgr.create_export(
            entries=[_make_entry("e_a", ts=now - 100, tenant="tenant_a")],
            exported_by_tag="tenant_a",
            export_token_verified=True,
        )
        art_b, _, _ = export_mgr.create_export(
            entries=[_make_entry("e_b", ts=now - 100, tenant="tenant_b")],
            exported_by_tag="tenant_b",
            export_token_verified=True,
        )
        art_anon, _, _ = export_mgr.create_export(
            entries=[],
            exported_by_tag=None,
            export_token_verified=False,
        )
        assert art_a is not None and art_b is not None and art_anon is not None
        art_a.generated_at_epoch_seconds = now - 100
        art_b.generated_at_epoch_seconds = now - 90 * 86400
        art_anon.generated_at_epoch_seconds = now - 90 * 86400

        entries = [
            _make_entry("log_a1", ts=now - 50, tenant="tenant_a", category="telemetry"),
            _make_entry("log_b1", ts=now - 90 * 86400, tenant="tenant_b", category="telemetry"),
            _make_entry("log_untagged", ts=now - 90 * 86400, tenant=None, category="telemetry"),
        ]

        preview = export_mgr.preview_deletion(
            authorized_tenant="tenant_a",
            requested_tenant="tenant_a",
            consent_manager=consent_mgr,
            entries=entries,
            now_epoch_seconds=now,
        )

        assert preview.schema_version == DELETION_PREVIEW_SCHEMA_VERSION
        assert preview.dry_run is True
        assert preview.total_eligible_bounded == 0
        assert preview.total_retained_bounded == 3  # 1 consent + 1 artifact + 1 log

        by_key = {(b.data_class, b.retention_policy): b for b in preview.buckets}
        assert set(by_key.keys()) == {
            ("consent_records", "active_consent"),
            ("export_artifacts", "within_retention"),
            ("telemetry", "within_retention"),
        }
        assert by_key[("consent_records", "active_consent")].retained_count == 1
        assert by_key[("export_artifacts", "within_retention")].retained_count == 1
        assert by_key[("telemetry", "within_retention")].retained_count == 1

        # Privacy check: serialized output must not leak raw IDs, tokens, or other tenants
        serialized = json.dumps(dataclasses.asdict(preview))
        for sensitive in (
            "tenant_a",
            "tenant_b",
            "cst-v1:secret_token_a",
            art_a.artifact_id,
            art_b.artifact_id,
            "log_a1",
            "log_b1",
            "synthetic operational event",
        ):
            assert sensitive not in serialized


class TestDeletionPreviewClassificationAndBounds:
    """Retention classification, bounded counts, bucket truncation, and dry-run."""

    def test_counts_by_data_class_and_retention_policy(self) -> None:
        now = 1_700_500_000.0
        consent_mgr = ConsentManager(grace_period_seconds=300)
        consent_mgr.withdraw_consent("tenant_x")
        consent_mgr._consent_states["tenant_x"].last_modified_epoch_seconds = now - 1000

        export_mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor())
        art_expired, _, _ = export_mgr.create_export(
            entries=[_make_entry("e1", ts=now - 40 * 86400, tenant="tenant_x")],
            exported_by_tag="tenant_x",
            export_token_verified=True,
        )
        art_withdrawn, _, _ = export_mgr.create_export(
            entries=[_make_entry("e2", ts=now - 10, tenant="tenant_x")],
            exported_by_tag="tenant_x",
            export_token_verified=True,
        )
        assert art_expired is not None and art_withdrawn is not None
        art_expired.generated_at_epoch_seconds = now - 40 * 86400
        art_withdrawn.generated_at_epoch_seconds = now - 10
        art_withdrawn.consent_state = CONSENT_STATE_WITHDRAWN

        entries = [
            _make_entry("l1", ts=now - 40 * 86400, tenant="tenant_x", category="audit"),
            _make_entry("l2", ts=now - 2 * 86400, tenant="tenant_x", category="audit"),
            _make_entry(
                "l3",
                ts=now - 5,
                tenant="tenant_x",
                category="metrics",
                consent_withdrawn=True,
            ),
        ]

        policy = DeletionPreviewPolicy(
            export_artifact_retention_seconds=30 * 86400,
            log_entry_retention_seconds=30 * 86400,
            withdrawn_retention_seconds=0.0,
            data_class_retention_seconds={"audit": 7 * 86400},
        )

        preview = export_mgr.preview_deletion(
            authorized_tenant="tenant_x",
            requested_tenant="tenant_x",
            consent_manager=consent_mgr,
            entries=entries,
            now_epoch_seconds=now,
            preview_policy=policy,
        )

        by_key = {(b.data_class, b.retention_policy): b for b in preview.buckets}
        assert by_key[("consent_records", "grace_period_expired")].eligible_count == 1
        assert by_key[("export_artifacts", "retention_expired")].eligible_count == 1
        assert by_key[("export_artifacts", "consent_withdrawn")].eligible_count == 1
        assert by_key[("audit", "retention_expired")].eligible_count == 1
        assert by_key[("audit", "within_retention")].retained_count == 1
        assert by_key[("metrics", "consent_withdrawn")].eligible_count == 1
        assert preview.total_eligible_bounded == 5
        assert preview.total_retained_bounded == 1

        # Non-destructive check: consent state and artifacts remain intact
        assert "tenant_x" in consent_mgr._consent_states
        assert export_mgr.get_artifact(art_expired.artifact_id) is art_expired
        assert export_mgr.get_artifact(art_withdrawn.artifact_id) is art_withdrawn

    def test_count_cap_and_bucket_truncation(self) -> None:
        now = 1_700_500_000.0
        export_mgr = ExportManager(policy=ExportPolicy(), processor=LogProcessor())
        entries = [
            _make_entry(f"e_{i}", ts=now - 40 * 86400, tenant="tenant_cap", category="cat_a")
            for i in range(10)
        ] + [
            _make_entry(f"b_{i}", ts=now - 40 * 86400, tenant="tenant_cap", category="cat_b")
            for i in range(3)
        ] + [
            _make_entry(f"c_{i}", ts=now - 40 * 86400, tenant="tenant_cap", category="cat_c")
            for i in range(2)
        ]

        policy = DeletionPreviewPolicy(
            count_cap_per_bucket=4,
            max_buckets=2,
            log_entry_retention_seconds=30 * 86400,
        )
        preview = export_mgr.preview_deletion(
            authorized_tenant="tenant_cap",
            requested_tenant="tenant_cap",
            entries=entries,
            now_epoch_seconds=now,
            preview_policy=policy,
        )

        assert preview.buckets_truncated is True
        assert len(preview.buckets) == 2
        assert preview.any_count_capped is True
        assert preview.buckets[0].data_class == "cat_a"
        assert preview.buckets[0].eligible_count == 4
        assert preview.buckets[0].eligible_capped is True
        assert preview.buckets[1].data_class == "cat_b"
        assert preview.buckets[1].eligible_count == 3
        assert preview.buckets[1].eligible_capped is False
        assert preview.total_eligible_bounded == 7

    def test_invalid_policy_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="count_cap_per_bucket"):
            DeletionPreviewPolicy(count_cap_per_bucket=0)
        with pytest.raises(ValueError, match="max_buckets"):
            DeletionPreviewPolicy(max_buckets=0)
        with pytest.raises(ValueError, match="export_artifact_retention_seconds"):
            DeletionPreviewPolicy(export_artifact_retention_seconds=-1.0)
