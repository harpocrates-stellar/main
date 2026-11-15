from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import sys
import pytest

_BACKEND_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _BACKEND_DIR.parent
for _p in (str(_BACKEND_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from analytics.consent import ConsentDecision, ConsentManager, ConsentSource, ConsentStatus
from analytics.export_manager import (
    ALLOWED_TENANT_EXPORT_CLASSES,
    DEFAULT_EXCLUDED_SENSITIVE_CATEGORIES,
    ExportManager,
    ExportMaterialExclusionError,
    ExportPolicy,
    ManifestVerificationError,
    RedactionPolicyBinding,
    TENANT_CLASS_FIELD_ALLOWLISTS,
    TENANT_EXPORT_MANIFEST_DOMAIN_TAG,
    TENANT_MANIFEST_SCHEMA_VERSION,
    assert_class_records_safe_by_construction,
    build_tenant_export_manifest,
    verify_tenant_export_manifest,
)
from analytics.log_processor import LogEntry, LogProcessor


def _make_safe_log_entry(
    *,
    entry_id: str,
    tenant_tag: str | None,
    event_name: str = "proof.verified",
    ts: float = 1_700_000_100.0,
    export_safe: bool = True,
    message_summary: str = "internal diagnostic text",
    labels: dict[str, str] | None = None,
) -> LogEntry:
    return LogEntry(
        entry_id=entry_id,
        event_name=event_name,
        category="verification",
        severity="info",
        timestamp_epoch_seconds=ts,
        message_summary=message_summary,
        endpoint_pattern="/api/verify",
        method="POST",
        status_code=200,
        account_id_tag=tenant_tag,
        duration_seconds=0.125,
        operation_status="succeeded",
        lifecycle_state="completed",
        labels=labels if labels is not None else {"service": "verifier", "status": "ok"},
        counters={"verified_total": 1},
        sanitized=True,
        export_safe=export_safe,
        export_signature="abcdef012345",
    )


def test_end_to_end_tenant_export_bundle_binds_classes_and_isolates_tenants() -> None:
    cm = ConsentManager()
    tok_a = cm.generate_consent_token("tenant_alpha", ConsentStatus.GRANTED, ["operational", "audit"])
    cm.set_consent(
        "tenant_alpha",
        ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["audit", "operational"],
            granted_at_epoch_seconds=1_700_000_000.0,
            expires_at_epoch_seconds=1_700_086_400.0,
            consent_token=tok_a,
        ),
    )
    tok_b = cm.generate_consent_token("tenant_bravo", ConsentStatus.GRANTED, ["operational"])
    cm.set_consent(
        "tenant_bravo",
        ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["operational"],
            granted_at_epoch_seconds=1_700_000_050.0,
            expires_at_epoch_seconds=1_700_086_450.0,
            consent_token=tok_b,
        ),
    )

    lp = LogProcessor()
    entry_a = _make_safe_log_entry(
        entry_id="eid-v1:0000000000000001",
        tenant_tag="tenant_alpha",
        ts=1_700_000_100.0,
        message_summary="internal summary must not appear in tenant bundle",
    )
    entry_a_unsafe = _make_safe_log_entry(
        entry_id="eid-v1:0000000000000002",
        tenant_tag="tenant_alpha",
        ts=1_700_000_110.0,
        export_safe=False,
    )
    entry_b = _make_safe_log_entry(
        entry_id="eid-v1:0000000000000003",
        tenant_tag="tenant_bravo",
        ts=1_700_000_120.0,
    )
    entry_anon = _make_safe_log_entry(
        entry_id="eid-v1:0000000000000004",
        tenant_tag=None,
        ts=1_700_000_130.0,
    )
    lp._entries.extend([entry_a, entry_a_unsafe, entry_b, entry_anon])

    em = ExportManager(
        policy=ExportPolicy(redaction_version="harpocrates-redaction-v1"),
        processor=lp,
        consent_manager=cm,
    )
    em.create_export(
        entries=[entry_a],
        exported_by_tag="tenant_alpha",
        export_token_verified=True,
    )
    em.create_export(
        entries=[entry_b],
        exported_by_tag="tenant_bravo",
        export_token_verified=True,
    )

    bundle = em.create_tenant_export_bundle(
        "tenant_alpha",
        export_token_verified=True,
        generated_at_epoch_seconds=1_700_000_500.0,
    )

    assert bundle.manifest.schema_version == TENANT_MANIFEST_SCHEMA_VERSION
    assert bundle.manifest.domain_tag == TENANT_EXPORT_MANIFEST_DOMAIN_TAG
    assert set(bundle.records_by_class.keys()) == set(ALLOWED_TENANT_EXPORT_CLASSES)
    assert len(bundle.records_by_class["consent_posture"]) == 1
    assert len(bundle.records_by_class["operational_telemetry"]) == 1
    assert len(bundle.records_by_class["export_audit_metadata"]) == 1

    # Verify sensitive / internal fields are excluded by construction
    serialized_bundle = repr(bundle.to_dict())
    assert tok_a not in serialized_bundle
    assert tok_b not in serialized_bundle
    assert "tenant_alpha" not in serialized_bundle
    assert "tenant_bravo" not in serialized_bundle
    assert "consent_token" not in serialized_bundle
    assert "account_id_tag" not in serialized_bundle
    assert "exported_by_tag" not in serialized_bundle
    assert "message_summary" not in serialized_bundle
    assert "internal summary must not appear" not in serialized_bundle

    # Cryptographic verification succeeds for authorized tenant and policy
    assert verify_tenant_export_manifest(
        bundle.manifest,
        bundle.records_by_class,
        expected_tenant_tag="tenant_alpha",
        expected_redaction_policy=RedactionPolicyBinding.build(
            redaction_version="harpocrates-redaction-v1"
        ),
        raise_on_error=True,
    )


def test_create_tenant_export_bundle_requires_verified_export_token_and_valid_tenant() -> None:
    em = ExportManager()
    with pytest.raises(PermissionError):
        em.create_tenant_export_bundle("tenant_alpha", export_token_verified=False)

    with pytest.raises(ValueError):
        em.create_tenant_export_bundle("", export_token_verified=True)

    with pytest.raises(ValueError):
        em.create_tenant_export_bundle("../escape", export_token_verified=True)

    with pytest.raises(ValueError):
        em.create_tenant_export_bundle("tenant_alpha", include_classes=[])

    with pytest.raises(ExportMaterialExclusionError):
        em.create_tenant_export_bundle("tenant_alpha", include_classes=["raw_witness_dump"])


def test_exclusion_by_construction_rejects_sensitive_classes_fields_and_values() -> None:
    # Disallowed record class
    with pytest.raises(ExportMaterialExclusionError):
        build_tenant_export_manifest("tenant_alpha", {"evidence_blobs": [{}]})

    # Non-allowlisted fields per class
    for forbidden_field in ("witness", "proof", "video_bytes", "consent_token", "private_key"):
        with pytest.raises(ExportMaterialExclusionError):
            assert_class_records_safe_by_construction(
                "consent_posture",
                [{forbidden_field: "val"}],
            )

    # Binary bytes in allowlisted container
    with pytest.raises(ExportMaterialExclusionError):
        assert_class_records_safe_by_construction(
            "operational_telemetry",
            [{"labels": {"raw": b"\x00\x01"}}],  # type: ignore[dict-item]
        )

    # Constructed secret / credential / evidence patterns inside allowlisted label values
    stellar_seed = "S" + ("D" * 55)
    stellar_pub = "G" + ("B" * 55)
    pem_header = "-----BEGIN " + "PRIVATE KEY-----"
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9." + ("a" * 16) + "." + ("b" * 16)
    fake_bearer = "Bearer " + ("tok1234567890")
    fake_dsn = "postgres" + "ql://dbuser:pw@localhost:5432/harpocrates"
    evidence_hash = "ab" * 32
    media_filename = "evidence_clip.mp4"
    consent_tok = "cst-v1:" + ("9f" * 12)

    for leaked_value in (
        stellar_seed,
        stellar_pub,
        pem_header,
        fake_jwt,
        fake_bearer,
        fake_dsn,
        evidence_hash,
        media_filename,
        consent_tok,
        "[REDACTED:secret]",
    ):
        with pytest.raises(ExportMaterialExclusionError):
            assert_class_records_safe_by_construction(
                "operational_telemetry",
                [{"labels": {"status": leaked_value}}],
            )

    # Forbidden nested key inside allowlisted labels map
    for bad_nested_key in ("witness_data", "consent_token", "private_key", "stellar_xdr"):
        with pytest.raises(ExportMaterialExclusionError):
            assert_class_records_safe_by_construction(
                "operational_telemetry",
                [{"labels": {bad_nested_key: "ok"}}],
            )

    # Redaction policy attempting to drop mandatory sensitive categories must fail
    reduced_cats = [c for c in DEFAULT_EXCLUDED_SENSITIVE_CATEGORIES if c != "witness"]
    with pytest.raises(ExportMaterialExclusionError):
        RedactionPolicyBinding.build(excluded_categories=reduced_cats)


def test_operational_telemetry_projection_drops_tainted_entries_and_strips_unsafe_labels() -> None:
    from analytics.export_manager import _project_safe_operational_telemetry

    lp = LogProcessor()
    stellar_seed = "S" + ("C" * 55)
    tainted_entry = _make_safe_log_entry(
        entry_id="eid-v1:0000000000000099",
        tenant_tag="tenant_alpha",
        labels={
            "service": "prover",
            "leaked_seed": stellar_seed,
            "private_key": "nope",
        },
    )
    clean_entry = _make_safe_log_entry(
        entry_id="eid-v1:0000000000000100",
        tenant_tag="tenant_alpha",
        labels={"service": "prover", "status": "ok"},
    )
    lp._entries.extend([tainted_entry, clean_entry])
    em = ExportManager(processor=lp)
    bundle = em.create_tenant_export_bundle(
        "tenant_alpha",
        include_classes=["operational_telemetry"],
    )
    rows = bundle.records_by_class["operational_telemetry"]
    assert len(rows) == 1
    assert rows[0]["labels"] == {"service": "prover", "status": "ok"}
    assert stellar_seed not in repr(bundle.to_dict())
    assert verify_tenant_export_manifest(bundle.manifest, bundle.records_by_class, raise_on_error=True)

    # Defense-in-depth: direct projection also strips sensitive label keys/values
    direct_projected = _project_safe_operational_telemetry(tainted_entry)
    assert direct_projected["labels"] == {"service": "prover"}
    assert stellar_seed not in repr(direct_projected)


def test_manifest_verification_detects_payload_policy_and_tenant_tampering() -> None:
    records = {
        "consent_posture": [
            {
                "schema_version": "1.0.0",
                "status": "granted",
                "source": "user_explicit",
                "granted_scopes": ["operational"],
                "granted_at_epoch_seconds": 1_700_000_000.0,
                "expires_at_epoch_seconds": 1_700_086_400.0,
                "withdrawal_epoch_seconds": None,
            }
        ],
        "operational_telemetry": [
            {
                "schema_version": "1.0.0",
                "event_name": "proof.verified",
                "category": "verification",
                "severity": "info",
                "timestamp_epoch_seconds": 1_700_000_100.0,
                "endpoint_pattern": "/api/verify",
                "method": "POST",
                "status_code": 200,
                "operation_status": "succeeded",
                "lifecycle_state": "completed",
                "duration_seconds": 0.25,
                "labels": {"service": "verifier"},
                "counters": {"ok": 1},
            }
        ],
    }
    bundle = build_tenant_export_manifest(
        "tenant_alpha",
        records,
        generated_at_epoch_seconds=1_700_000_200.0,
    )
    assert verify_tenant_export_manifest(
        bundle.manifest,
        bundle.records_by_class,
        expected_tenant_tag="tenant_alpha",
    )

    # 1. Mutate a scalar value in exported records
    tampered_records = {
        "consent_posture": [dict(bundle.records_by_class["consent_posture"][0], status="withdrawn")],
        "operational_telemetry": list(bundle.records_by_class["operational_telemetry"]),
    }
    assert not verify_tenant_export_manifest(bundle.manifest, tampered_records)
    with pytest.raises(ManifestVerificationError):
        verify_tenant_export_manifest(bundle.manifest, tampered_records, raise_on_error=True)

    # 2. Delete a record from a class
    truncated_records = {
        "consent_posture": [],
        "operational_telemetry": list(bundle.records_by_class["operational_telemetry"]),
    }
    assert not verify_tenant_export_manifest(bundle.manifest, truncated_records)

    # 3. Drop an entire record class
    missing_class = {"consent_posture": list(bundle.records_by_class["consent_posture"])}
    assert not verify_tenant_export_manifest(bundle.manifest, missing_class)

    # 4. Wrong expected tenant tag
    assert not verify_tenant_export_manifest(
        bundle.manifest,
        bundle.records_by_class,
        expected_tenant_tag="tenant_other",
    )

    # 5. Expected redaction policy version mismatch
    newer_policy = RedactionPolicyBinding.build(redaction_version="harpocrates-redaction-v2")
    assert not verify_tenant_export_manifest(
        bundle.manifest,
        bundle.records_by_class,
        expected_redaction_policy=newer_policy,
    )

    # 6. Tamper with redaction_policy version inside manifest without updating policy_digest
    forged_policy = replace(bundle.manifest.redaction_policy, redaction_version="harpocrates-redaction-v9")
    forged_manifest = replace(bundle.manifest, redaction_policy=forged_policy)
    assert not verify_tenant_export_manifest(forged_manifest, bundle.records_by_class)

    # 7. Flip 1 hex character in manifest_digest
    orig_digest = bundle.manifest.manifest_digest
    flipped = ("0" if orig_digest[0] != "0" else "1") + orig_digest[1:]
    corrupted_manifest = replace(bundle.manifest, manifest_digest=flipped)
    assert not verify_tenant_export_manifest(corrupted_manifest, bundle.records_by_class)
    with pytest.raises(ManifestVerificationError):
        verify_tenant_export_manifest(
            corrupted_manifest,
            bundle.records_by_class,
            raise_on_error=True,
        )

    # 8. Deterministic digest across identical inputs
    bundle_again = build_tenant_export_manifest(
        "tenant_alpha",
        records,
        generated_at_epoch_seconds=1_700_099_999.0,
    )
    assert bundle_again.manifest.manifest_digest == bundle.manifest.manifest_digest
    assert bundle_again.manifest.tenant_tag_digest == bundle.manifest.tenant_tag_digest
    assert set(TENANT_CLASS_FIELD_ALLOWLISTS.keys()) == set(ALLOWED_TENANT_EXPORT_CLASSES)
