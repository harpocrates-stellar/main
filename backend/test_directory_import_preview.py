"""Focused tests for issuer directory import preview (#1087)."""

from __future__ import annotations

import pytest

from issuer_key_transparency import (
    DIRECTORY_IMPORT_PREVIEW_SCHEMA,
    DirectoryCheckpoint,
    DirectoryEvent,
    EventType,
    IssuerKey,
    IssuerManifest,
    KeyStatus,
    TransparencyError,
    accept_directory_import,
    create_activation_event,
    create_rotation_event,
    event_hash,
    manifest_hash,
    preview_directory_import,
    rebuild_directory,
)

ORG = "a" * 64
POLICY = "b" * 64
SIG = "f" * 64
K1 = "1" * 64
K2 = "2" * 64
K3 = "3" * 64


def _initial_directory():
    e0 = create_activation_event(ORG, "k1", K1, 0, 1_000)
    m1 = IssuerManifest(
        organization_identity_hash=ORG,
        issuer_address="GTESTISSUERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        active_keys=[IssuerKey("k1", K1, "ed25519", 1_000)],
        policy_hash=POLICY,
        valid_from=1_000,
        signature_hash=SIG,
    )
    directory = rebuild_directory(ORG, [e0], [m1])
    cp = directory.make_checkpoint(timestamp=1_100, signature_hash=SIG)
    return directory, e0, m1, cp


def test_reports_proposed_lifecycle_changes_and_mutates_only_on_accept() -> None:
    directory, e0, m1, cp0 = _initial_directory()
    before_head = directory.tree_head()
    before_mh = manifest_hash(directory.current_manifest)

    e1 = create_rotation_event(ORG, "k2", K2, "k1", 1, 2_000, event_hash(e0))
    e2 = DirectoryEvent(
        event_type=EventType.COMPROMISE,
        sequence=2,
        timestamp=2_500,
        organization_identity_hash=ORG,
        key_id="k1",
        public_key_hash=K1,
        previous_event_hash=event_hash(e1),
    )
    e3 = create_activation_event(ORG, "k3", K3, 3, 2_600, previous_event_hash=event_hash(e2))
    m2 = IssuerManifest(
        organization_identity_hash=ORG,
        issuer_address="GTESTISSUERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        active_keys=[
            IssuerKey("k2", K2, "ed25519", 2_000),
            IssuerKey("k3", K3, "ed25519", 2_600),
        ],
        policy_hash=POLICY,
        valid_from=2_600,
        predecessor_manifest_hash=manifest_hash(m1),
        signature_hash=SIG,
    )
    candidate_dir = rebuild_directory(ORG, [e0, e1, e2, e3], [m1, m2])
    cp1 = candidate_dir.make_checkpoint(timestamp=2_700, signature_hash=SIG)

    preview = preview_directory_import(
        directory,
        [e0, e1, e2, e3],
        [m1, m2],
        previously_seen_checkpoint=cp0,
        candidate_checkpoint=cp1,
    )
    payload = preview.to_dict()
    assert payload["schema"] == DIRECTORY_IMPORT_PREVIEW_SCHEMA
    assert preview.accepted_ready is True
    assert preview.errors == ()
    assert payload["checkpointLineage"]["appendedEventCount"] == 3
    assert payload["checkpointLineage"]["extendsPreviousLog"] is True
    assert payload["checkpointLineage"]["manifestLineageValid"] is True
    assert payload["checkpointLineage"]["candidateCheckpointConsistent"] is True

    by_key = {item["keyId"]: item for item in payload["keyLifecycleChanges"]}
    assert by_key["k1"]["changeType"] == "compromised"
    assert by_key["k1"]["previousStatus"] == "active"
    assert by_key["k2"]["changeType"] == "added"
    assert by_key["k3"]["changeType"] == "added"

    # Active trust state was NOT mutated by preview_directory_import
    assert len(directory.events) == 1
    assert directory.tree_head() == before_head
    assert manifest_hash(directory.current_manifest) == before_mh
    assert set(directory.keys.keys()) == {"k1"}
    assert directory.keys["k1"].status == KeyStatus.ACTIVE

    # Explicit acceptance installs the staged state
    accept_directory_import(directory, preview)
    assert len(directory.events) == 4
    assert directory.tree_head() == cp1.tree_head_hash
    assert manifest_hash(directory.current_manifest) == manifest_hash(m2)
    assert directory.keys["k1"].status == KeyStatus.COMPROMISED
    assert directory.keys["k2"].status == KeyStatus.ACTIVE


def test_rejects_divergent_or_rollback_imports_and_blocks_drifted_acceptance() -> None:
    directory, e0, m1, cp0 = _initial_directory()

    # Divergent genesis event
    forged_e0 = create_activation_event(ORG, "k1", K2, 0, 1_000)
    bad_preview = preview_directory_import(directory, [forged_e0], [m1])
    assert bad_preview.accepted_ready is False
    assert any("diverges from active directory" in err for err in bad_preview.errors)
    with pytest.raises(TransparencyError, match="cannot accept rejected"):
        accept_directory_import(directory, bad_preview)

    # Checkpoint rollback detected without mutating directory
    rollback_cp = DirectoryCheckpoint(
        tree_head_hash="0" * 64,
        event_count=0,
        timestamp=900,
        organization_identity_hash=ORG,
        manifest_hash=manifest_hash(m1),
    )
    rollback_preview = preview_directory_import(
        directory,
        [e0],
        [m1],
        previously_seen_checkpoint=cp0,
        candidate_checkpoint=rollback_cp,
    )
    assert rollback_preview.accepted_ready is False
    assert rollback_preview.checkpoint_lineage.rollback_errors
    assert len(directory.events) == 1

    # Valid preview fails closed if active directory mutates before accept
    e1 = create_rotation_event(ORG, "k2", K2, "k1", 1, 2_000, event_hash(e0))
    m2 = IssuerManifest(
        organization_identity_hash=ORG,
        issuer_address="GTESTISSUERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        active_keys=[IssuerKey("k2", K2, "ed25519", 2_000)],
        policy_hash=POLICY,
        valid_from=2_000,
        predecessor_manifest_hash=manifest_hash(m1),
        signature_hash=SIG,
    )
    valid_preview = preview_directory_import(directory, [e0, e1], [m1, m2])
    assert valid_preview.accepted_ready is True

    # Mutate directory out-of-band before calling accept_directory_import
    directory.append_event(e1)
    with pytest.raises(TransparencyError, match="changed after preview"):
        accept_directory_import(directory, valid_preview)
