from __future__ import annotations

import base64
import json

import pytest

import app as app_module
from verification_receipt import (
    MAX_RECEIPT_SIGNING_KEYS,
    RECEIPT_PROTOCOL,
    RECEIPT_SIGNING_ALGORITHM,
    RECEIPT_VERSION,
    PrivateSigningKeyRejectedError,
    load_public_receipt_signing_keys_from_env,
    parse_public_receipt_signing_key_entries,
    sanitize_public_ec_p256_jwk,
)


def _b64u_32(byte_val: int) -> str:
    return base64.urlsafe_b64encode(bytes([byte_val]) * 32).decode("ascii").rstrip("=")


def _sample_entries() -> list[dict[str, object]]:
    return [
        {
            "keyId": "portal-2026-q3",
            "status": "rotated",
            "notBefore": "2026-07-01T00:00:00Z",
            "notAfter": "2026-10-01T00:00:00Z",
            "publicKeyJwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": _b64u_32(1),
                "y": _b64u_32(2),
                "key_ops": ["verify"],
            },
        },
        {
            "keyId": "portal-2026-q4",
            "status": "active",
            "notBefore": "2026-10-01T00:00:00Z",
            "notAfter": None,
            "publicKeyJwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": _b64u_32(3),
                "y": _b64u_32(4),
            },
        },
    ]


def test_read_only_endpoint_serves_bounded_public_key_history_and_validity_intervals(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("RECEIPT_PUBLIC_SIGNING_KEYS_JSON", json.dumps(_sample_entries()))
    client = app_module.create_app().test_client()

    resp = client.get("/api/receipts/signing-keys?limit=1")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    assert body["protocol"] == RECEIPT_PROTOCOL
    assert body["version"] == RECEIPT_VERSION
    assert body["algorithm"] == RECEIPT_SIGNING_ALGORITHM
    assert body["signingOwnership"] == "frontend"
    assert body["totalEntries"] == 2
    assert len(body["entries"]) == 1
    assert body["entries"][0]["keyId"] == "portal-2026-q4"
    assert set(body["keys"].keys()) == {"portal-2026-q4"}
    assert "d" not in body["keys"]["portal-2026-q4"]
    assert body["keyValidity"]["portal-2026-q4"] == {
        "notBefore": "2026-10-01T00:00:00Z",
    }

    # Filter by rotated historical key preserves both notBefore and notAfter
    rotated_resp = client.get("/api/receipts/signing-keys?status=rotated")
    assert rotated_resp.status_code == 200
    rotated_body = rotated_resp.get_json()
    assert rotated_body["totalEntries"] == 1
    assert rotated_body["keyValidity"]["portal-2026-q3"] == {
        "notBefore": "2026-07-01T00:00:00Z",
        "notAfter": "2026-10-01T00:00:00Z",
    }

    # Endpoint is strictly read-only (POST/PUT/DELETE rejected 405)
    assert client.post("/api/receipts/signing-keys", json={}).status_code == 405
    assert client.delete("/api/receipts/signing-keys").status_code == 405


def test_rejects_private_signing_keys_in_jwk_and_env_without_echoing_secrets(monkeypatch: pytest.MonkeyPatch):
    sentinel_secret = "PRIVATE_SCALAR_DO_NOT_ECHO_998877"

    with pytest.raises(PrivateSigningKeyRejectedError):
        sanitize_public_ec_p256_jwk(
            {
                "kty": "EC",
                "crv": "P-256",
                "x": _b64u_32(5),
                "y": _b64u_32(6),
                "d": sentinel_secret,
            }
        )

    with pytest.raises(PrivateSigningKeyRejectedError):
        sanitize_public_ec_p256_jwk(
            {
                "kty": "EC",
                "crv": "P-256",
                "x": _b64u_32(5),
                "y": _b64u_32(6),
                "key_ops": ["sign", "verify"],
            }
        )

    with pytest.raises(PrivateSigningKeyRejectedError):
        load_public_receipt_signing_keys_from_env(
            {"RECEIPT_SIGNING_PRIVATE_KEY": sentinel_secret}
        )

    bad_entries = [
        {
            "keyId": "leaked-key",
            "status": "active",
            "notBefore": "2026-10-01T00:00:00Z",
            "publicKeyJwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": _b64u_32(7),
                "y": _b64u_32(8),
                "d": sentinel_secret,
            },
        }
    ]
    monkeypatch.setenv("RECEIPT_PUBLIC_SIGNING_KEYS_JSON", json.dumps(bad_entries))
    client = app_module.create_app().test_client()
    resp = client.get("/api/receipts/signing-keys")
    assert resp.status_code == 500
    raw = resp.get_data(as_text=True)
    assert sentinel_secret not in raw
    body = resp.get_json()
    assert body["ok"] is False
    assert body["error"]["code"] == "INTERNAL_ERROR"


def test_bounds_and_validation_edge_cases(monkeypatch: pytest.MonkeyPatch):
    # Exceeding MAX_RECEIPT_SIGNING_KEYS rejected
    oversized = [
        {
            "keyId": f"key-{idx}",
            "status": "active",
            "notBefore": "2026-10-01T00:00:00Z",
            "publicKeyJwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": _b64u_32((idx % 200) + 1),
                "y": _b64u_32((idx % 200) + 2),
            },
        }
        for idx in range(MAX_RECEIPT_SIGNING_KEYS + 1)
    ]
    with pytest.raises(ValueError, match="exceeds maximum"):
        parse_public_receipt_signing_key_entries(oversized)

    # Inverted validity interval (notAfter <= notBefore) rejected
    inverted = [
        {
            **_sample_entries()[0],
            "notBefore": "2026-10-01T00:00:00Z",
            "notAfter": "2026-10-01T00:00:00Z",
        }
    ]
    with pytest.raises(ValueError, match="strictly after"):
        parse_public_receipt_signing_key_entries(inverted)

    # Query validation errors return standardized 400 VALIDATION_ERROR envelope
    monkeypatch.delenv("RECEIPT_PUBLIC_SIGNING_KEYS_JSON", raising=False)
    client = app_module.create_app().test_client()
    bad_limit = client.get("/api/receipts/signing-keys?limit=not-an-int")
    assert bad_limit.status_code == 400
    assert bad_limit.get_json()["error"]["code"] == "VALIDATION_ERROR"

    bad_status = client.get("/api/receipts/signing-keys?status=unknown")
    assert bad_status.status_code == 400
    assert bad_status.get_json()["error"]["code"] == "VALIDATION_ERROR"
