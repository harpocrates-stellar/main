"""Focused tests for rejecting issuer manifests with repeated keyIds and conflicts (#1086)."""

from __future__ import annotations

import pytest

from issuer_key_transparency import (
    DirectoryEvent,
    EventType,
    IssuerKey,
    IssuerManifest,
    KeyStatus,
    TransparencyError,
    canonicalize_manifest,
    create_activation_event,
    create_rotation_event,
    event_hash,
    manifest_hash,
    rebuild_directory,
    validate_issuer_manifest,
)

ORG = "a" * 64
POLICY = "b" * 64
SIG = "f" * 64
KEY_A = "c" * 64
KEY_B = "d" * 64
KEY_C = "e" * 64
ADDR = "GTESTISSUERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"


def _make_manifest(
    keys: list[IssuerKey],
    *,
    predecessor: str | None = None,
    valid_from: int = 1_000,
) -> IssuerManifest:
    return IssuerManifest(
        organization_identity_hash=ORG,
        issuer_address=ADDR,
        active_keys=keys,
        policy_hash=POLICY,
        valid_from=valid_from,
        predecessor_manifest_hash=predecessor,
        signature_hash=SIG,
    )


def test_rejects_repeated_key_ids_and_reports_all_conflicting_attributes() -> None:
    conflicting = _make_manifest(
        [
            IssuerKey("k1", KEY_A, "ed25519", 1_000, valid_until=None, status=KeyStatus.ACTIVE),
            IssuerKey("k1", KEY_B, "ed25519", 1_000, valid_until=2_000, status=KeyStatus.ROTATED),
            IssuerKey("k2", KEY_C, "ed25519", 1_500),
            IssuerKey("k2", KEY_C, "ed25519", 1_500),
        ]
    )

    with pytest.raises(TransparencyError) as exc_info:
        validate_issuer_manifest(conflicting)
    msg = str(exc_info.value)
    # Complete manifest validation surfaces both k1 attribute conflict and k2 duplicate
    assert "repeated keyId 'k1' with conflicting attributes" in msg
    assert "publicKeyHash" in msg
    assert "validUntil" in msg
    assert "status" in msg
    assert "repeated keyId 'k2' in manifest activeKeys" in msg

    with pytest.raises(TransparencyError, match="repeated keyId 'k1'"):
        canonicalize_manifest(conflicting)

    raw_dict = conflicting.to_dict()
    with pytest.raises(TransparencyError, match="repeated keyId 'k1'"):
        IssuerManifest.from_dict(raw_dict)


def test_retains_previous_trusted_directory_on_single_or_batch_manifest_conflict() -> None:
    e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1_000)
    e1 = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2_000, event_hash(e0))
    e2 = DirectoryEvent(
        event_type=EventType.COMPROMISE,
        sequence=2,
        timestamp=2_500,
        organization_identity_hash=ORG,
        key_id="k1",
        public_key_hash=KEY_A,
        previous_event_hash=event_hash(e1),
    )
    e3 = create_activation_event(ORG, "k3", KEY_C, 3, 2_600, previous_event_hash=event_hash(e2))

    m1 = _make_manifest([IssuerKey("k1", KEY_A, "ed25519", 1_000)], valid_from=1_000)
    directory = rebuild_directory(ORG, [e0], [m1])
    trusted_m1_hash = manifest_hash(m1)

    # Candidate manifest attempts to publish repeated conflicting k1 — rejected cleanly
    bad_dup = _make_manifest(
        [
            IssuerKey("k1", KEY_A, "ed25519", 1_000),
            IssuerKey("k1", KEY_B, "ed25519", 1_000),
        ],
        predecessor=trusted_m1_hash,
        valid_from=1_500,
    )
    with pytest.raises(TransparencyError, match="repeated keyId 'k1'"):
        directory.publish_manifest(bad_dup)

    assert directory.current_manifest == m1
    assert set(directory.manifests_by_hash.keys()) == {trusted_m1_hash}
    assert directory.manifests_by_hash[trusted_m1_hash].successor_manifest_hash is None

    # Advance events to include rotation + compromise of k1 + activation of k3
    for ev in (e1, e2, e3):
        directory.append_event(ev)

    # Candidate manifest conflicts with directory history (compromised k1 re-advertised active)
    re_advertise_compromised = _make_manifest(
        [IssuerKey("k1", KEY_A, "ed25519", 1_000, status=KeyStatus.ACTIVE)],
        predecessor=trusted_m1_hash,
        valid_from=2_700,
    )
    with pytest.raises(TransparencyError, match="conflicts with directory key history"):
        directory.publish_manifest(re_advertise_compromised)
    assert directory.current_manifest == m1

    # Batch install: m2 is valid, m3 has repeated conflicting k3 -> whole batch rolls back!
    m2_valid = _make_manifest(
        [IssuerKey("k2", KEY_B, "ed25519", 2_000)],
        predecessor=trusted_m1_hash,
        valid_from=2_000,
    )
    m3_conflicting = _make_manifest(
        [
            IssuerKey("k3", KEY_C, "ed25519", 2_600),
            IssuerKey("k3", KEY_B, "ed25519", 2_600),
        ],
        predecessor=manifest_hash(m2_valid),
        valid_from=2_700,
    )
    with pytest.raises(TransparencyError, match="repeated keyId 'k3'"):
        directory.install_manifests([m2_valid, m3_conflicting])

    # Previous trusted directory retained completely unchanged
    assert directory.current_manifest == m1
    assert set(directory.manifests_by_hash.keys()) == {trusted_m1_hash}
    assert directory.manifests_by_hash[trusted_m1_hash].successor_manifest_hash is None

    # Installing valid m2 + valid m3 succeeds cleanly
    m3_valid = _make_manifest(
        [
            IssuerKey("k2", KEY_B, "ed25519", 2_000),
            IssuerKey("k3", KEY_C, "ed25519", 2_600),
        ],
        predecessor=manifest_hash(m2_valid),
        valid_from=2_700,
    )
    installed = directory.install_manifests([m2_valid, m3_valid])
    assert len(installed) == 2
    assert manifest_hash(directory.current_manifest) == manifest_hash(m3_valid)
