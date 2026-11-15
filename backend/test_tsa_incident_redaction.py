"""Focused tests for TSA URL redaction in private incident exports (#1082)."""

from __future__ import annotations

import json

from time_attestation import (
    INCIDENT_EXPORT_SCHEMA,
    add_rfc3161_anchor,
    classify_tsa_error_category,
    create_time_attestation,
    export_time_attestation_for_incident,
    redact_tsa_url,
)

DIGEST = "a" * 64


def test_removes_credentials_and_sensitive_query_values_while_retaining_provider_identity() -> None:
    raw = (
        "https://svc_account:s3cr3t_pw!@TSA.Example.org:8443/v1/tsr/"
        "bearer_9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"
        "?api_key=live_tok_999&alg=sha256&sig=deadbeef123&tenant_id=priv_org_42#internal-frag"
    )
    redacted = redact_tsa_url(raw)

    assert redacted.url_valid is True
    assert redacted.provider_identity == "https://tsa.example.org:8443"
    assert redacted.redacted_credentials is True
    assert redacted.redacted_fragment is True
    assert redacted.redacted_query_keys == ("api_key", "sig", "tenant_id")
    assert redacted.redacted_url == "https://tsa.example.org:8443/v1/tsr/_redacted_?alg=sha256"

    for leaked in (
        "svc_account",
        "s3cr3t_pw",
        "live_tok_999",
        "deadbeef123",
        "priv_org_42",
        "internal-frag",
        "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c",
    ):
        assert leaked not in redacted.redacted_url
        assert leaked not in (redacted.provider_identity or "")


def test_incident_export_maps_stable_error_categories_and_rejects_unsafe_urls() -> None:
    att = create_time_attestation(DIGEST, claimed_time_ms=1_720_000_000_000)
    att = add_rfc3161_anchor(
        att,
        token_bytes="BASE64TOKENPAYLOAD==",
        tsa_url="https://user:secret_pass@timestamp.digicert.com/tsr?token=tok_abc123&hash=sha256",
        gen_time=1_720_000_001_000,
        policy_oid="2.16.840.1.114412.7.1",
        cert_fingerprint="b" * 64,
        verification_status="untrusted",
        verification_error="untrusted_root",
    )
    att = add_rfc3161_anchor(
        att,
        token_bytes="BASE64TOKEN2==",
        tsa_url="https://tsa-internal.corp/sign?apikey=xyz987",
        gen_time=1_720_000_002_000,
        verification_status="invalid",
        verification_error="HTTP 401 from https://admin:topsecret@tsa-internal.corp/sign?apikey=xyz987",
    )
    att = add_rfc3161_anchor(
        att,
        token_bytes="BASE64TOKEN3==",
        tsa_url="file:///etc/passwd?secret=123",
        gen_time=1_720_000_003_000,
        verification_status="invalid",
        verification_error="signature_invalid",
    )

    exported = export_time_attestation_for_incident(att)
    blob = json.dumps(exported)

    assert exported["schema"] == INCIDENT_EXPORT_SCHEMA
    anchors = exported["rfc3161Anchors"]
    assert len(anchors) == 3

    assert anchors[0]["providerIdentity"] == "https://timestamp.digicert.com"
    assert anchors[0]["tsaUrl"] == "https://timestamp.digicert.com/tsr?hash=sha256"
    assert anchors[0]["errorCategory"] == "untrusted_root"
    assert anchors[0]["redactedCredentials"] is True

    # Unstructured error text containing leaked credentials is mapped to stable category
    assert anchors[1]["providerIdentity"] == "https://tsa-internal.corp"
    assert anchors[1]["errorCategory"] == "verification_failed"

    # Non-HTTP scheme is marked invalid and replaced without echoing path/query
    assert anchors[2]["providerIdentity"] is None
    assert anchors[2]["tsaUrl"] == "[redacted-invalid-tsa-url]"
    assert anchors[2]["errorCategory"] == "malformed_tsa_url"

    for secret in ("secret_pass", "tok_abc123", "xyz987", "topsecret", "/etc/passwd", "BASE64TOKENPAYLOAD=="):
        assert secret not in blob

    assert classify_tsa_error_category("valid", None) == "none"
    assert classify_tsa_error_category("expired", "expired_certificate") == "certificate_expired_or_not_yet_valid"
    assert classify_tsa_error_category("invalid", "revoked_certificate") == "certificate_revoked"
    assert classify_tsa_error_category("invalid", "signature_invalid") == "signature_invalid"
