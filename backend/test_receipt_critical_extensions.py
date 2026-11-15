"""Focused tests for rejecting unsupported critical receipt extensions (#1080)."""

from __future__ import annotations

import pytest

from verification_receipt import (
    build_verification_receipt,
    parse_receipt_metadata,
    serialize_receipt_metadata,
)


def _base_context() -> dict[str, object]:
    return {
        "verifiedAt": "2026-09-01T12:00:00+00:00",
        "proofId": "a" * 64,
        "videoHash": "b" * 64,
        "metadataHash": "c" * 64,
        "tier": "source",
        "networkPassphrase": "Test SDF Network ; September 2015",
        "contractId": "C" + "d" * 55,
        "ledgerSequence": 42,
        "transactionHash": "e" * 64,
        "circuitVersion": "1",
        "verifierVersion": "2026.09",
    }


def test_preserves_optional_and_supported_critical_extensions_in_round_trips() -> None:
    ctx = {
        **_base_context(),
        "extensions": {
            "timeAttestationDigest": "F" * 64,
            "revocationEpochBinding": {"epoch": 7, "rootHash": "1" * 64},
            "auditorDisplayNote": {"label": "newsroom-desk-2", "tags": ["reverified", "archive"]},
            "optionalFeatureHint": {"critical": False, "value": "v2-preview"},
        },
        "criticalExtensions": ["revocationEpochBinding", "timeAttestationDigest"],
    }

    receipt = build_verification_receipt(ctx, result="verified")
    encoded = serialize_receipt_metadata(receipt)
    restored = parse_receipt_metadata(encoded)

    assert restored == receipt
    assert restored["criticalExtensions"] == ["revocationEpochBinding", "timeAttestationDigest"]
    assert restored["extensions"]["timeAttestationDigest"] == "f" * 64
    assert restored["extensions"]["revocationEpochBinding"] == {"epoch": 7, "rootHash": "1" * 64}
    assert restored["extensions"]["auditorDisplayNote"] == {
        "label": "newsroom-desk-2",
        "tags": ["reverified", "archive"],
    }
    assert restored["extensions"]["optionalFeatureHint"] == {
        "critical": False,
        "value": "v2-preview",
    }


def test_fails_closed_for_unsupported_or_malformed_critical_extensions() -> None:
    # 1. Unknown critical extension in criticalExtensions list
    unknown_crit = {
        **_base_context(),
        "extensions": {"mandatoryFuturePolicy": {"mode": "strict"}},
        "criticalExtensions": ["mandatoryFuturePolicy"],
    }
    with pytest.raises(ValueError, match="unsupported critical receipt extension: mandatoryFuturePolicy"):
        build_verification_receipt(unknown_crit, result="verified")

    # 2. Inline {"critical": True} declaration for unknown extension even without criticalExtensions list
    inline_unknown = {
        **_base_context(),
        "extensions": {"unknownInlineGate": {"critical": True, "value": 1}},
    }
    with pytest.raises(ValueError, match="unsupported critical receipt extension: unknownInlineGate"):
        parse_receipt_metadata({**inline_unknown, "result": "verified"})

    # 3. Supported critical extension declared in criticalExtensions but omitted from extensions
    missing_payload = {
        **_base_context(),
        "extensions": {"optionalNote": "ok"},
        "criticalExtensions": ["timeAttestationDigest"],
    }
    with pytest.raises(ValueError, match="missing from extensions"):
        build_verification_receipt(missing_payload)

    # 4. Supported critical extension with invalid schema value
    malformed_digest = {
        **_base_context(),
        "extensions": {"timeAttestationDigest": "not-a-hex-digest"},
        "criticalExtensions": ["timeAttestationDigest"],
    }
    with pytest.raises(ValueError, match="timeAttestationDigest"):
        build_verification_receipt(malformed_digest)

    # 5. Forbidden private/secret key inside optional extensions rejected fail-closed
    leaked_secret = {
        **_base_context(),
        "extensions": {"captureNonce": "9" * 64},
    }
    with pytest.raises(ValueError, match="private witness or secret"):
        build_verification_receipt(leaked_secret)

    # 6. Unknown top-level receipt metadata field rejected fail-closed on parse
    with pytest.raises(ValueError, match="unknown top-level receipt fields"):
        parse_receipt_metadata({**_base_context(), "result": "verified", "requiredPolicyMode": "v99"})
