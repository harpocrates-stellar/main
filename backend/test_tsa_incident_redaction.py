"""Focused tests for privacy-safe TSA incident exports."""

import json

from time_attestation import (
    add_rfc3161_anchor,
    create_time_attestation,
    encode_time_attestation,
    export_time_attestation_for_incident,
)


def _attestation():
    return create_time_attestation(
        evidence_digest="a" * 64,
        claimed_time_ms=1_800_000_000_000,
        claimed_source_label="synthetic",
    )


def test_incident_export_redacts_tsa_url_secrets_and_categorizes_errors():
    tsa_url = (
        "https://user:password@tsa.example.com/tsr/bearer-token"
        "?api_key=query-secret&policy=1#fragment-secret"
    )
    attestation = add_rfc3161_anchor(
        _attestation(),
        token_bytes="synthetic-token",
        tsa_url=tsa_url,
        gen_time=1_800_000_000_000,
        verification_status="invalid",
        verification_error="invalid TSA signature for query-secret",
    )

    exported = export_time_attestation_for_incident(attestation)
    anchor = exported["rfc3161Anchors"][0]
    serialized = json.dumps(exported)

    assert anchor["tsaUrl"] == "https://tsa.example.com"
    assert anchor["providerIdentity"] == "https://tsa.example.com"
    assert anchor["verificationErrorCategory"] == "signature_invalid"
    assert "verificationError" not in anchor
    for secret in ("user", "password", "bearer-token", "query-secret", "fragment-secret"):
        assert secret not in serialized
    assert encode_time_attestation(attestation)["rfc3161Anchors"][0]["tsaUrl"] == tsa_url


def test_incident_export_does_not_echo_invalid_tsa_url():
    attestation = add_rfc3161_anchor(
        _attestation(),
        token_bytes="synthetic-token",
        tsa_url="javascript:secret-token",
        gen_time=1_800_000_000_000,
        verification_status="unverified",
    )

    anchor = export_time_attestation_for_incident(attestation)["rfc3161Anchors"][0]

    assert anchor["tsaUrl"] == "[redacted-invalid-tsa-url]"
    assert anchor["providerIdentity"] == "unknown"
    assert anchor["verificationErrorCategory"] == "unverified_no_chain"
    assert "secret-token" not in json.dumps(anchor)
