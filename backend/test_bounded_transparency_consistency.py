"""Focused tests for bounded issuer transparency consistency verification."""

import json
from unittest.mock import patch

from issuer_key_transparency import (
    ConsistencyWorkBudget,
    DirectoryCheckpoint,
    IssuerKey,
    IssuerManifest,
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
SIGNATURE = "f" * 64


def _history():
    event = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
    directory = rebuild_directory(ORG, [event])
    manifest = IssuerManifest(
        organization_identity_hash=ORG,
        issuer_address="GTESTISSUERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        active_keys=[IssuerKey("k1", KEY_A, "ed25519", 1000)],
        policy_hash=POLICY,
        valid_from=1000,
        signature_hash=SIGNATURE,
    )
    directory.publish_manifest(manifest)
    return [event], directory.make_checkpoint(timestamp=1500, signature_hash=SIGNATURE)


def test_event_limit_returns_incomplete_before_rebuild():
    events, checkpoint = _history()
    second = create_rotation_event(
        ORG, "k2", KEY_B, "k1", 1, 2000, event_hash(events[0])
    )

    with patch("issuer_key_transparency.rebuild_directory") as rebuild:
        result = verify_directory_consistency_bounded(
            ORG,
            [*events, second],
            checkpoint,
            budget=ConsistencyWorkBudget(max_events=1),
        )

    assert result.status == "incomplete_proof"
    assert result.consistent is False
    assert result.incomplete is True
    assert result.reason_code == "event_count_limit_exceeded"
    rebuild.assert_not_called()


def test_byte_limits_return_incomplete_before_rebuild():
    events, checkpoint = _history()
    second = create_rotation_event(
        ORG, "k2", KEY_B, "k1", 1, 2000, event_hash(events[0])
    )
    all_events = [*events, second]
    sizes = [
        len(json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":")).encode())
        for event in all_events
    ]

    with patch("issuer_key_transparency.rebuild_directory") as rebuild:
        result = verify_directory_consistency_bounded(
            ORG,
            all_events,
            checkpoint,
            budget=ConsistencyWorkBudget(
                max_events=2,
                max_total_bytes=sum(sizes) - 1,
                max_single_event_bytes=max(sizes),
            ),
        )

    assert result.status == "incomplete_proof"
    assert result.reason_code == "byte_budget_exceeded"
    rebuild.assert_not_called()

    result = verify_directory_consistency_bounded(
        ORG,
        events,
        checkpoint,
        budget=ConsistencyWorkBudget(
            max_events=1,
            max_total_bytes=sizes[0],
            max_single_event_bytes=sizes[0] - 1,
        ),
    )
    assert result.reason_code == "single_event_byte_limit_exceeded"


def test_checkpoint_ahead_is_incomplete_and_valid_history_completes():
    events, checkpoint = _history()
    ahead = DirectoryCheckpoint(
        tree_head_hash=checkpoint.tree_head_hash,
        event_count=2,
        timestamp=checkpoint.timestamp,
        organization_identity_hash=ORG,
        manifest_hash=checkpoint.manifest_hash,
        signature_hash=SIGNATURE,
    )

    incomplete = verify_directory_consistency_bounded(ORG, events, ahead)
    assert incomplete.status == "incomplete_proof"
    assert incomplete.reason_code == "checkpoint_ahead_of_supplied_events"

    complete = verify_directory_consistency_bounded(ORG, events, checkpoint)
    assert complete.status == "consistent"
    assert complete.consistent is True
    assert complete.incomplete is False
