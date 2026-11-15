"""Focused tests for bounded historical issuer-key validity explanations (#1088)."""

from __future__ import annotations

import hashlib
import json

import pytest
from issuer_key_transparency import (
    HISTORICAL_VALIDITY_EXPLANATION_SCHEMA,
    MAX_EXPLANATION_EVENT_REFS,
    DirectoryEvent,
    EventType,
    HistoricalKeyValidityExplanation,
    HistoricalKeyValidityReason,
    TransparencyError,
    create_activation_event,
    create_rotation_event,
    event_hash,
    explain_historical_issuer_key_validity,
    key_valid_for_historical_signature,
    rebuild_directory,
)

ORG = "a" * 64
K1_HASH = "1" * 64
K2_HASH = "2" * 64
K3_HASH = "3" * 64


def _build_lifecycle_directory():
    e0 = create_activation_event(ORG, "k1", K1_HASH, 0, 1_000)
    e1 = create_rotation_event(ORG, "k2", K2_HASH, "k1", 1, 2_000, event_hash(e0))
    e2 = DirectoryEvent(
        event_type=EventType.COMPROMISE,
        sequence=2,
        timestamp=3_000,
        organization_identity_hash=ORG,
        key_id="k2",
        public_key_hash=K2_HASH,
        previous_event_hash=event_hash(e1),
        reason_hash="9" * 64,
    )
    e3 = create_activation_event(ORG, "k3", K3_HASH, 3, 3_100, previous_event_hash=event_hash(e2))
    e4 = DirectoryEvent(
        event_type=EventType.RETIREMENT,
        sequence=4,
        timestamp=4_000,
        organization_identity_hash=ORG,
        key_id="k3",
        public_key_hash=K3_HASH,
        previous_event_hash=event_hash(e3),
    )
    e5 = create_activation_event(ORG, "k4", "4" * 64, 5, 4_100, previous_event_hash=event_hash(e4))
    return rebuild_directory(ORG, [e0, e1, e2, e3, e4, e5])


def test_reuses_signature_time_validity_and_emits_stable_reason_codes_and_public_refs() -> None:
    directory = _build_lifecycle_directory()

    cases = [
        ("k4", 4_500, True, HistoricalKeyValidityReason.VALID_ACTIVE_KEY, False, False),
        ("k1", 1_500, True, HistoricalKeyValidityReason.VALID_HISTORICAL_ROTATED_KEY, False, False),
        ("k1", 2_000, False, HistoricalKeyValidityReason.INVALID_AT_OR_AFTER_ROTATION, False, False),
        ("k1", 999, False, HistoricalKeyValidityReason.INVALID_BEFORE_ACTIVATION, False, False),
        ("k2", 2_500, True, HistoricalKeyValidityReason.VALID_PRE_COMPROMISE_WARNING, True, False),
        ("k2", 3_000, False, HistoricalKeyValidityReason.INVALID_AT_OR_AFTER_COMPROMISE, True, True),
        ("k3", 3_500, True, HistoricalKeyValidityReason.VALID_HISTORICAL_RETIRED_KEY, False, False),
        ("k3", 4_000, False, HistoricalKeyValidityReason.INVALID_AT_OR_AFTER_RETIREMENT, False, False),
        ("unknown", 2_500, False, HistoricalKeyValidityReason.INVALID_UNKNOWN_KEY, False, False),
    ]

    for key_id, ts, expected_valid, expected_reason, expected_warn, expected_comp_at in cases:
        rec = explain_historical_issuer_key_validity(directory, key_id, ts)
        assert rec.valid is key_valid_for_historical_signature(directory, key_id, ts)
        assert rec.valid is expected_valid
        assert rec.reason_code == expected_reason
        assert rec.compromise_warning is expected_warn
        assert rec.compromised_at_signature_time is expected_comp_at

    k1_rec = explain_historical_issuer_key_validity(directory, "k1", 1_500)
    payload = k1_rec.to_dict()
    assert payload["schema"] == HISTORICAL_VALIDITY_EXPLANATION_SCHEMA
    assert [r["eventType"] for r in payload["eventReferences"]] == ["activation", "rotation"]
    assert payload["eventReferences"][1]["relatedKeyId"] == "k1"
    restored = HistoricalKeyValidityExplanation.from_dict(payload)
    assert restored == k1_rec


def test_bounds_event_references_and_keeps_private_evidence_identifiers_out() -> None:
    events: list[DirectoryEvent] = []
    e0 = create_activation_event(ORG, "k-cycling", K1_HASH, 0, 1_000)
    events.append(e0)
    prev = event_hash(e0)
    ts = 1_100
    for seq in range(1, 7, 2):
        ret = DirectoryEvent(
            event_type=EventType.RETIREMENT,
            sequence=seq,
            timestamp=ts,
            organization_identity_hash=ORG,
            key_id="k-cycling",
            public_key_hash=K1_HASH,
            previous_event_hash=prev,
        )
        events.append(ret)
        prev = event_hash(ret)
        ts += 100
        act = create_activation_event(ORG, "k-cycling", K1_HASH, seq + 1, ts, previous_event_hash=prev)
        events.append(act)
        prev = event_hash(act)
        ts += 100
    directory = rebuild_directory(ORG, events)

    private_video = hashlib.sha256(b"raw-private-video").hexdigest()
    private_nonce = hashlib.sha256(b"raw-capture-nonce").hexdigest()
    explanation = explain_historical_issuer_key_validity(
        directory,
        "k-cycling",
        ts + 50,
        max_event_refs=3,
        evidence_context={
            "videoHash": private_video,
            "captureNonce": private_nonce,
            "proofId": "8" * 64,
            "deviceCommitment": "7" * 64,
        },
    )
    assert explanation.total_matching_events == 7
    assert len(explanation.event_references) == 3
    assert explanation.truncated_event_references is True
    assert explanation.event_references[0].sequence == 0
    assert explanation.event_references[-1].sequence == 6

    serialized = json.dumps(explanation.to_dict())
    for forbidden in (private_video, private_nonce, "videoHash", "captureNonce", "proofId", "deviceCommitment"):
        assert forbidden not in serialized

    injected = {**explanation.to_dict(), "evidenceDigestBinding": private_video}
    with pytest.raises(TransparencyError, match="private evidence identifiers"):
        HistoricalKeyValidityExplanation.from_dict(injected)

    with pytest.raises(TransparencyError, match="max_event_refs"):
        explain_historical_issuer_key_validity(
            directory, "k-cycling", 1_500, max_event_refs=MAX_EXPLANATION_EVENT_REFS + 1
        )
    with pytest.raises(TransparencyError, match="signature_timestamp"):
        explain_historical_issuer_key_validity(directory, "k-cycling", True)
