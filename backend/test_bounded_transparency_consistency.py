"""Focused tests for bounded issuer transparency consistency verification work (#1090)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

import issuer_key_transparency as ikt
from issuer_key_transparency import (
    CONSISTENCY_WORK_SCHEMA,
    ConsistencyWorkBudget,
    DirectoryCheckpoint,
    IssuerKey,
    IssuerManifest,
    TransparencyError,
    create_activation_event,
    create_rotation_event,
    event_hash,
    rebuild_directory,
    verify_directory_consistency_bounded,
)

ORG = "a" * 64
POLICY = "b" * 64
KEY_A = "c" * 64
KEY_B = "d" * 64
SIG = "f" * 64


def _sample_chain():
    e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1_000)
    e1 = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2_000, event_hash(e0))
    manifest = IssuerManifest(
        organization_identity_hash=ORG,
        issuer_address="GTESTISSUERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        active_keys=[IssuerKey("k2", KEY_B, "ed25519", 2_000)],
        policy_hash=POLICY,
        valid_from=2_000,
        signature_hash=SIG,
    )
    directory = rebuild_directory(ORG, [e0, e1], [manifest])
    cp = directory.make_checkpoint(timestamp=2_500, signature_hash=SIG)
    return [e0, e1], manifest, cp


def test_verifies_consistent_directory_within_event_and_byte_bounds() -> None:
    events, manifest, cp = _sample_chain()
    res = verify_directory_consistency_bounded(
        ORG,
        events,
        cp,
        manifests=[manifest],
        budget=ConsistencyWorkBudget(max_events=8, max_total_bytes=16_384),
    )

    assert res.status == "consistent"
    assert res.consistent is True
    assert res.incomplete is False
    assert res.reason_code is None
    assert res.inspected_events == 2
    assert res.directory is not None
    assert res.to_dict()["schema"] == CONSISTENCY_WORK_SCHEMA


def test_stops_before_rebuild_and_returns_incomplete_proof_when_event_or_byte_limits_exceeded() -> None:
    events, manifest, cp = _sample_chain()

    def infinite_events():
        seq = 0
        prev = None
        while True:
            ev = create_activation_event(ORG, f"k-{seq}", KEY_A, seq, 1_000 + seq, prev)
            prev = event_hash(ev)
            seq += 1
            yield ev

    with patch.object(ikt, "rebuild_directory", wraps=ikt.rebuild_directory) as rebuild_spy:
        over_events = verify_directory_consistency_bounded(
            ORG,
            infinite_events(),
            cp,
            budget=ConsistencyWorkBudget(max_events=3, max_total_bytes=65_536),
        )
        assert over_events.status == "incomplete_proof"
        assert over_events.consistent is False
        assert over_events.incomplete is True
        assert over_events.reason_code == "event_count_limit_exceeded"
        assert over_events.inspected_events == 3
        assert over_events.directory is None
        rebuild_spy.assert_not_called()

        over_bytes = verify_directory_consistency_bounded(
            ORG,
            events,
            cp,
            manifests=[manifest],
            budget=ConsistencyWorkBudget(max_events=10, max_total_bytes=350),
        )
        assert over_bytes.status == "incomplete_proof"
        assert over_bytes.consistent is False
        assert over_bytes.incomplete is True
        assert over_bytes.reason_code == "byte_budget_exceeded"
        assert over_bytes.directory is None
        rebuild_spy.assert_not_called()

        over_single = verify_directory_consistency_bounded(
            ORG,
            events,
            cp,
            budget=ConsistencyWorkBudget(
                max_events=10,
                max_total_bytes=65_536,
                max_single_event_bytes=50,
            ),
        )
        assert over_single.status == "incomplete_proof"
        assert over_single.reason_code == "single_event_byte_limit_exceeded"
        rebuild_spy.assert_not_called()


def test_distinguishes_truncated_log_incomplete_proof_from_tampered_split_view() -> None:
    events, manifest, cp = _sample_chain()

    # Only 1 of 2 events supplied for an event_count=2 checkpoint -> incomplete_proof
    truncated = verify_directory_consistency_bounded(
        ORG,
        events[:1],
        cp,
        manifests=[manifest],
    )
    assert truncated.status == "incomplete_proof"
    assert truncated.incomplete is True
    assert truncated.consistent is False
    assert truncated.reason_code == "checkpoint_ahead_of_supplied_events"

    # Full 2 events supplied, but checkpoint tree_head_hash tampered -> inconsistent
    forged_cp = DirectoryCheckpoint(
        tree_head_hash="9" * 64,
        event_count=cp.event_count,
        timestamp=cp.timestamp,
        organization_identity_hash=ORG,
        manifest_hash=cp.manifest_hash,
        signature_hash=SIG,
    )
    tampered = verify_directory_consistency_bounded(
        ORG,
        events,
        forged_cp,
        manifests=[manifest],
    )
    assert tampered.status == "inconsistent"
    assert tampered.incomplete is False
    assert tampered.consistent is False
    assert tampered.reason_code == "consistency_verification_failed"


def test_rejects_invalid_budget_configuration() -> None:
    with pytest.raises(TransparencyError, match="positive integer"):
        ConsistencyWorkBudget(max_events=0)
    with pytest.raises(TransparencyError, match="positive integer"):
        ConsistencyWorkBudget(max_total_bytes=True)  # type: ignore[arg-type]
    with pytest.raises(TransparencyError, match="MAX_EVENTS"):
        ConsistencyWorkBudget(max_events=ikt.MAX_EVENTS + 1)
