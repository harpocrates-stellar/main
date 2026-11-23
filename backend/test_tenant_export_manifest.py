"""Focused tests for the verifiable tenant data export manifest.

Covers canonical digest binding of record classes and redaction policy,
exclusion of sensitive evidence and credential material by construction,
consent summary credential stripping, and fail-closed verification.
"""

from __future__ import annotations

import copy
import json

import pytest

from backend.analytics.consent import (
    ConsentDecision,
    ConsentManager,
    ConsentSource,
    ConsentStatus,
)
from backend.analytics.export_manager import (
    CONSENT_STATE_GRANTED,
    EXCLUDED_SENSITIVE_CLASSES,
    MANIFEST_DIGEST_PREFIX,
    ExportManager,
    ExportPolicy,
    TenantExportManifest,
    build_tenant_export_manifest,
    compute_manifest_digest,
    compute_redaction_policy_digest,
    is_sensitive_record_class,
    verify_tenant_export_manifest,
)
from backend.analytics.log_processor import LogEntry, LogProcessor


def _safe_entry(
    entry_id: str,
    *,
    event_name: str = "operational_metric",
    category: str | None = None,
    message_summary: str = "ok",
    labels: dict | None = None,
    ts: float = 1.0,
    consent_policy_revision: str | None = None,
    consent_withdrawn: bool = False,
) -> LogEntry:
    merged_labels = dict(labels or {})
    if category is not None:
        merged_labels["category"] = category
    entry = LogEntry(
        entry_id=entry_id,
        event_name=event_name,
        message_summary=message_summary,
        timestamp_epoch_seconds=ts,
        labels=merged_labels,
        export_safe=True,
        export_signature="sig-v1:abc",
    )
    if consent_policy_revision is not None:
        entry.consent_policy_revision = consent_policy_revision
        entry.consent_withdrawn = consent_withdrawn
    return entry


def _manager(**policy_kw) -> ExportManager:
    return ExportManager(policy=ExportPolicy(**policy_kw), processor=LogProcessor())


# ------------------------------------------------ canonical digest binding


def test_create_export_attaches_verifiable_manifest_bound_to_classes_and_policy():
    mgr = _manager()
    entries = [
        _safe_entry("e1", category="latency_sample", consent_policy_revision="rev-2026-01"),
        _safe_entry("e2", category="error_count", consent_policy_revision="rev-2026-01"),
        _safe_entry("e3", category="latency_sample", consent_policy_revision="rev-2026-01"),
    ]
    art, serialized, count = mgr.create_export(
        entries=entries,
        exported_by_tag="tenant-alpha",
        export_token_verified=True,
    )
    assert art is not None
    assert count == 3
    assert art.manifest is not None

    manifest = art.manifest
    assert manifest.manifest_digest.startswith(MANIFEST_DIGEST_PREFIX)
    assert manifest.record_classes == ("error_count", "latency_sample")
    assert manifest.redaction_policy_version == "harpocrates-redaction-v1"
    assert manifest.redaction_policy_digest == compute_redaction_policy_digest("harpocrates-redaction-v1")
    assert manifest.tenant_tag == "tenant-alpha"
    assert manifest.consent_policy_revision == "rev-2026-01"
    assert manifest.consent_state == CONSENT_STATE_GRANTED
    assert set(EXCLUDED_SENSITIVE_CLASSES).issubset(set(manifest.excluded_sensitive_classes))

    ok, errors = mgr.verify_artifact_manifest(
        art.artifact_id,
        serialized,
        expected_redaction_policy_digest=manifest.redaction_policy_digest,
        expected_tenant_tag="tenant-alpha",
    )
    assert ok, f"expected valid manifest, got errors={errors}"
    assert errors == []


def test_manifest_digest_is_deterministic_across_record_class_order_and_duplicates():
    payload = '[{"entry_id":"e1"}]'
    m1 = build_tenant_export_manifest(
        artifact_id="exp-v1:0001",
        serialized_payload=payload,
        entry_count=1,
        record_classes=["zeta_metric", "alpha_metric", "zeta_metric"],
        tenant_tag="tenant-1",
    )
    m2 = build_tenant_export_manifest(
        artifact_id="exp-v1:0001",
        serialized_payload=payload,
        entry_count=1,
        record_classes=["alpha_metric", "zeta_metric"],
        tenant_tag="tenant-1",
    )
    assert m1.record_classes == ("alpha_metric", "zeta_metric")
    assert m1.manifest_digest == m2.manifest_digest


def test_compressed_export_manifest_verifies_cleanly():
    mgr = _manager()
    art, serialized, count = mgr.create_export(
        entries=[_safe_entry("e1", category="throughput_metric")],
        exported_by_tag="tenant-gz",
        compress=True,
        export_token_verified=True,
    )
    assert art is not None and count == 1 and art.manifest is not None
    ok, errors = verify_tenant_export_manifest(art.manifest, serialized, expected_tenant_tag="tenant-gz")
    assert ok and errors == []


# ------------------------------------ sensitive evidence & credential exclusion


@pytest.mark.parametrize(
    "sensitive_class",
    [
        "evidence_media",
        "witness",
        "proof_payload",
        "private_key",
        "credential",
        "wallet_signature",
        "pii",
        "raw_video_blob",
        "user_consent_token",
    ],
)
def test_sensitive_record_classes_rejected_by_construction(sensitive_class: str):
    assert is_sensitive_record_class(sensitive_class)
    with pytest.raises(ValueError, match="sensitive record class excluded by construction"):
        build_tenant_export_manifest(
            artifact_id="exp-v1:0002",
            serialized_payload="[]",
            entry_count=0,
            record_classes=[sensitive_class],
        )


def test_export_excludes_sensitive_evidence_and_credential_entries_by_construction():
    mgr = _manager()
    safe = _safe_entry("safe-1", category="request_latency")
    evidence_entry = _safe_entry("ev-1", category="evidence_media")
    witness_entry = _safe_entry("wit-1", event_name="zk_proof_witness")
    cred_summary = _safe_entry("cred-1", category="audit_event", message_summary="Bearer supersecrettoken123")
    consent_tok_entry = _safe_entry(
        "tok-1",
        category="audit_event",
        message_summary="token=cst-v1:0123456789abcdef01234567",
    )
    pem_entry = _safe_entry(
        "pem-1",
        category="audit_event",
        message_summary="-----BEGIN EC PRIVATE KEY----- synthetic",
    )

    art, serialized, count = mgr.create_export(
        entries=[safe, evidence_entry, witness_entry, cred_summary, consent_tok_entry, pem_entry],
        exported_by_tag="tenant-safe",
        export_token_verified=True,
    )
    assert art is not None
    assert count == 1
    exported_ids = [item["entry_id"] for item in json.loads(serialized)]
    assert exported_ids == ["safe-1"]
    assert art.manifest is not None
    assert art.manifest.record_classes == ("request_latency",)

    ok, errors = mgr.verify_artifact_manifest(art.artifact_id, serialized)
    assert ok and errors == []


def test_consent_export_summary_omits_consent_token():
    cm = ConsentManager()
    token = cm.generate_consent_token("acct-tag-1", ConsentStatus.GRANTED, ["analytics"])
    state = cm.set_consent(
        "acct-tag-1",
        ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["analytics"],
            expires_at_epoch_seconds=9_999_999_999.0,
            granted_at_epoch_seconds=1_000.0,
            consent_token=token,
            policy_revision="pol-v2",
        ),
    )
    summary = state.to_export_summary()
    assert "consent_token" not in summary
    assert token not in json.dumps(summary)
    assert summary["account_tag"] == "acct-tag-1"
    assert summary["status"] == ConsentStatus.GRANTED
    assert summary["policy_revision"] == "pol-v2"


# -------------------------------------------- fail-closed verification & tamper


def test_tampering_with_record_classes_or_redaction_policy_fails_verification():
    mgr = _manager()
    art, serialized, _ = mgr.create_export(
        entries=[_safe_entry("e1", category="latency_sample")],
        exported_by_tag="tenant-t",
        export_token_verified=True,
    )
    assert art is not None and art.manifest is not None

    # Tamper record_classes
    tampered_rc = copy.deepcopy(art.manifest)
    tampered_rc.record_classes = ("latency_sample", "injected_class")
    ok, errors = verify_tenant_export_manifest(tampered_rc, serialized)
    assert not ok
    assert "manifest_digest_mismatch" in errors

    # Tamper redaction policy digest
    tampered_pol = copy.deepcopy(art.manifest)
    tampered_pol.redaction_policy_digest = compute_redaction_policy_digest("harpocrates-redaction-v2")
    ok, errors = verify_tenant_export_manifest(tampered_pol, serialized)
    assert not ok
    assert "manifest_digest_mismatch" in errors

    # Policy digest expectation mismatch (even with untouched manifest)
    ok, errors = verify_tenant_export_manifest(
        art.manifest,
        serialized,
        expected_redaction_policy_digest=compute_redaction_policy_digest("harpocrates-redaction-v2"),
    )
    assert not ok
    assert "redaction_policy_digest_mismatch" in errors


def test_tampering_with_payload_or_tenant_tag_fails_verification():
    mgr = _manager()
    art, serialized, _ = mgr.create_export(
        entries=[_safe_entry("e1", category="latency_sample")],
        exported_by_tag="tenant-a",
        export_token_verified=True,
    )
    assert art is not None and art.manifest is not None

    # Tamper serialized payload
    ok, errors = verify_tenant_export_manifest(art.manifest, serialized + " ")
    assert not ok
    assert "payload_sha256_mismatch" in errors

    # Mismatched expected tenant tag
    ok, errors = verify_tenant_export_manifest(
        art.manifest,
        serialized,
        expected_tenant_tag="tenant-b",
    )
    assert not ok
    assert "tenant_tag_mismatch" in errors


def test_verify_manifest_fails_closed_on_malformed_or_missing_fields():
    mgr = _manager()
    ok, errors = mgr.verify_artifact_manifest("exp-v1:nonexistent", "[]")
    assert not ok
    assert errors == ["artifact_not_found"]

    bad = TenantExportManifest(
        artifact_id="exp-v1:bad",
        payload_sha256="0" * 64,
        entry_count=0,
        record_classes=("evidence_media",),
        redaction_policy_version="harpocrates-redaction-v1",
        redaction_policy_digest=compute_redaction_policy_digest(),
        excluded_sensitive_classes=(),
        manifest_version="9.9.9",
        manifest_digest="bad-digest",
    )
    ok, errors = verify_tenant_export_manifest(bad, "[]")
    assert not ok
    assert "unsupported_manifest_version:9.9.9" in errors
    assert "malformed_manifest_digest" in errors
    assert "sensitive_record_class_present:evidence_media" in errors
    assert "missing_required_excluded_sensitive_classes" in errors


def test_unverified_shadow_export_produces_empty_verifiable_manifest():
    mgr = _manager()
    art, serialized, count = mgr.create_export(
        entries=[_safe_entry("e1", category="latency_sample")],
        exported_by_tag="tenant-hidden",
        export_token_verified=False,
    )
    assert art is not None and count == 0 and art.manifest is not None
    assert art.manifest.tenant_tag is None
    assert art.manifest.record_classes == ()
    assert art.manifest.entry_count == 0
    ok, errors = mgr.verify_artifact_manifest(art.artifact_id, serialized)
    assert ok and errors == []
