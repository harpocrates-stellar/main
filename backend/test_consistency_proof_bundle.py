"""Focused tests for portable issuer transparency consistency proof bundles (#1084)."""

from __future__ import annotations

import pytest

from issuer_key_transparency import (
    CONSISTENCY_PROOF_BUNDLE_SCHEMA,
    ConsistencyProofBundle,
    DirectoryCheckpoint,
    DirectoryEvent,
    EventType,
    IssuerKey,
    IssuerManifest,
    TransparencyError,
    build_consistency_proof_bundle,
    create_activation_event,
    create_rotation_event,
    event_hash,
    manifest_hash,
    rebuild_directory,
    require_valid_consistency_proof_bundle,
    verify_consistency_proof_bundle,
)

ORG = "a" * 64
POLICY = "b" * 64
SIG = "f" * 64
KEY_1 = "1" * 64
KEY_2 = "2" * 64
KEY_3 = "3" * 64
ADDR = "GTESTISSUERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"


def _manifest(keys: list[IssuerKey], *, predecessor: str | None = None, valid_from: int = 1_000) -> IssuerManifest:
    return IssuerManifest(
        organization_identity_hash=ORG,
        issuer_address=ADDR,
        active_keys=keys,
        policy_hash=POLICY,
        valid_from=valid_from,
        predecessor_manifest_hash=predecessor,
        signature_hash=SIG,
    )


def _multi_checkpoint_history():
    e0 = create_activation_event(ORG, "k1", KEY_1, 0, 1_000)
    m1 = _manifest([IssuerKey("k1", KEY_1, "ed25519", 1_000)], valid_from=1_000)
    d = rebuild_directory(ORG, [e0], [m1])
    cp1 = d.make_checkpoint(timestamp=1_100, signature_hash=SIG)

    e1 = create_rotation_event(ORG, "k2", KEY_2, "k1", 1, 2_000, event_hash(e0))
    d.append_event(e1)
    m2 = _manifest(
        [IssuerKey("k2", KEY_2, "ed25519", 2_000)],
        predecessor=manifest_hash(m1),
        valid_from=2_000,
    )
    d.publish_manifest(m2)

    e2 = create_rotation_event(ORG, "k3", KEY_3, "k2", 2, 3_000, event_hash(e1))
    e3 = DirectoryEvent(
        event_type=EventType.RETIREMENT,
        sequence=3,
        timestamp=3_200,
        organization_identity_hash=ORG,
        key_id="k1",
        public_key_hash=KEY_1,
        previous_event_hash=event_hash(e2),
    )
    d.append_event(e2)
    d.append_event(e3)
    m3 = _manifest(
        [IssuerKey("k3", KEY_3, "ed25519", 3_000)],
        predecessor=manifest_hash(m2),
        valid_from=3_000,
    )
    d.publish_manifest(m3)
    cp3 = d.make_checkpoint(timestamp=3_300, signature_hash=SIG)
    return d, cp1, cp3, m1, m2, m3


def test_builds_and_verifies_portable_consistency_proof_bundle_offline() -> None:
    directory, cp1, cp3, _, m2, m3 = _multi_checkpoint_history()

    bundle = build_consistency_proof_bundle(directory, cp1, cp3)
    encoded_json = bundle.to_canonical_json()

    # Offline verifier reconstructs from JSON alone — zero live IssuerDirectory access
    restored = ConsistencyProofBundle.from_canonical_json(encoded_json)
    assert restored.to_dict()["schema"] == CONSISTENCY_PROOF_BUNDLE_SCHEMA
    assert len(restored.intervening_events) == 3
    assert [mf_h for mf_h in (manifest_hash(m) for m in restored.intervening_manifests)] == [
        manifest_hash(m2),
        manifest_hash(m3),
    ]

    verdict = require_valid_consistency_proof_bundle(
        restored,
        trusted_earlier_checkpoint=cp1,
    )
    assert verdict.valid is True
    assert verdict.errors == ()
    assert verdict.intervening_event_count == 3
    assert verdict.verified_tree_head_hash == cp3.tree_head_hash

    # Zero-step identity bundle (cp1 -> cp1) also verifies cleanly
    identity_bundle = build_consistency_proof_bundle(directory, cp1, cp1)
    id_verdict = require_valid_consistency_proof_bundle(identity_bundle, trusted_earlier_checkpoint=cp1)
    assert id_verdict.valid is True
    assert id_verdict.intervening_event_count == 0


def test_rejects_tampered_events_missing_manifests_rollbacks_and_unpinned_roots() -> None:
    directory, cp1, cp3, m1, _, _ = _multi_checkpoint_history()
    bundle = build_consistency_proof_bundle(directory, cp1, cp3)

    # 1. Tamper with an intervening event's timestamp (re-computing bundleHash to bypass outer envelope)
    ev_list = list(bundle.intervening_events)
    ev_list[1] = DirectoryEvent(
        event_type=ev_list[1].event_type,
        sequence=ev_list[1].sequence,
        timestamp=ev_list[1].timestamp + 1,
        organization_identity_hash=ORG,
        key_id=ev_list[1].key_id,
        public_key_hash=ev_list[1].public_key_hash,
        previous_event_hash=ev_list[1].previous_event_hash,
        related_key_id=ev_list[1].related_key_id,
    )
    forged_bundle = ConsistencyProofBundle(
        organization_identity_hash=ORG,
        earlier_checkpoint=cp1,
        later_checkpoint=cp3,
        intervening_events=tuple(ev_list),
        anchor_event_hash=bundle.anchor_event_hash,
        intervening_manifests=bundle.intervening_manifests,
    )
    tampered_res = verify_consistency_proof_bundle(forged_bundle, trusted_earlier_checkpoint=cp1)
    assert tampered_res.valid is False
    assert any("tree head" in err or "previousEventHash" in err for err in tampered_res.errors)
    with pytest.raises(TransparencyError):
        require_valid_consistency_proof_bundle(forged_bundle)

    # 2. Strip intervening manifests when checkpoint manifestHash changed
    missing_manifests = ConsistencyProofBundle(
        organization_identity_hash=ORG,
        earlier_checkpoint=cp1,
        later_checkpoint=cp3,
        intervening_events=bundle.intervening_events,
        anchor_event_hash=bundle.anchor_event_hash,
        intervening_manifests=(),
    )
    no_mf_res = verify_consistency_proof_bundle(missing_manifests)
    assert no_mf_res.valid is False
    assert any("interveningManifests" in err for err in no_mf_res.errors)

    # 3. Caller's pinned earlier checkpoint differs from bundle's earlierCheckpoint
    other_pinned = DirectoryCheckpoint(
        tree_head_hash="9" * 64,
        event_count=1,
        timestamp=1_100,
        organization_identity_hash=ORG,
        manifest_hash=manifest_hash(m1),
    )
    unpinned_res = verify_consistency_proof_bundle(bundle, trusted_earlier_checkpoint=other_pinned)
    assert unpinned_res.valid is False
    assert any("pinned checkpoint" in err for err in unpinned_res.errors)

    # 4. Rollback (cp3 -> cp1) rejected at build and verify time
    with pytest.raises(TransparencyError, match="rollback"):
        build_consistency_proof_bundle(directory, cp3, cp1)

    # 5. Outer bundleHash integrity tampering rejected on deserialization
    raw_dict = bundle.to_dict()
    raw_dict["anchorEventHash"] = "8" * 64
    with pytest.raises(TransparencyError, match="bundleHash integrity mismatch"):
        ConsistencyProofBundle.from_dict(raw_dict)
