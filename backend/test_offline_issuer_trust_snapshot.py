"""Focused tests for offline issuer trust snapshot exports (#1089)."""

from __future__ import annotations

import hashlib
import json

import pytest

from capture_attestation import (
    AppIdentity,
    CaptureAttestation,
    encode_attestation,
    make_device_commitment,
)
from issuer_key_transparency import (
    OFFLINE_TRUST_SNAPSHOT_SCHEMA,
    DirectoryCheckpoint,
    IssuerKey,
    IssuerManifest,
    IssuerSnapshotSource,
    OfflineIssuerTrustSnapshot,
    TransparencyError,
    create_activation_event,
    create_rotation_event,
    event_hash,
    export_offline_issuer_trust_snapshot,
    manifest_hash,
    rebuild_directory,
)

ORG_1 = "a" * 64
ORG_2 = "b" * 64
POLICY_1 = "c" * 64
POLICY_2 = "d" * 64
KEY_1 = "1" * 64
KEY_2 = "2" * 64
SIG = "f" * 64


def _build_issuer(org: str, policy: str):
    e0 = create_activation_event(org, "k1", KEY_1, 0, 1_000)
    e1 = create_rotation_event(org, "k2", KEY_2, "k1", 1, 2_000, event_hash(e0))
    m1 = IssuerManifest(
        organization_identity_hash=org,
        issuer_address="GTESTISSUERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        active_keys=[IssuerKey("k1", KEY_1, "ed25519", 1_000)],
        policy_hash=policy,
        valid_from=1_000,
        signature_hash=SIG,
    )
    m2 = IssuerManifest(
        organization_identity_hash=org,
        issuer_address="GTESTISSUERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        active_keys=[IssuerKey("k2", KEY_2, "ed25519", 2_000)],
        policy_hash=policy,
        valid_from=2_000,
        predecessor_manifest_hash=manifest_hash(m1),
        signature_hash=SIG,
    )
    directory = rebuild_directory(org, [e0, e1], [m1, m2])
    cp = directory.make_checkpoint(timestamp=2_500, signature_hash=SIG)
    return directory, cp


def test_exports_public_manifests_checkpoint_refs_and_policy_versions_without_evidence_identifiers() -> None:
    dir1, cp1 = _build_issuer(ORG_1, POLICY_1)
    dir2, cp2 = _build_issuer(ORG_2, POLICY_2)

    private_nonce = hashlib.sha256(b"private-capture-nonce").hexdigest()
    private_key = hashlib.sha256(b"private-session-key").digest()
    private_ev = hashlib.sha256(b"private-video-payload").hexdigest()
    att = CaptureAttestation(
        version=1,
        trust_level=2,
        capture_nonce=private_nonce,
        app_identity=AppIdentity(
            package_name="com.harpocrates.camera",
            version_code="3",
            build_fingerprint="PRIVATE_DEVICE_BUILD_ID",
        ),
        device_commitment=make_device_commitment(private_nonce, private_key),
        privacy_scope="per_session",
        evidence_digest_binding=private_ev,
    )

    snapshot = export_offline_issuer_trust_snapshot(
        [
            IssuerSnapshotSource(
                directory=dir2,
                checkpoint=cp2,
                policy_version="2026.02-seal",
                private_context={
                    "captureAttestation": encode_attestation(att),
                    "proofId": "9" * 64,
                    "videoHash": private_ev,
                },
            ),
            IssuerSnapshotSource(
                directory=dir1,
                checkpoint=cp1,
                policy_version="2026.01-seal",
            ),
        ],
        exported_at=1_730_000_000,
    )

    encoded = snapshot.to_dict()
    raw_json = snapshot.to_canonical_json()

    assert encoded["schema"] == OFFLINE_TRUST_SNAPSHOT_SCHEMA
    assert [i["organizationIdentityHash"] for i in encoded["issuers"]] == [ORG_1, ORG_2]
    assert len(encoded["issuers"][0]["manifests"]) == 2
    assert encoded["issuers"][0]["policy"]["policyVersion"] == "2026.01-seal"
    assert encoded["issuers"][0]["policy"]["policyHash"] == POLICY_1
    assert encoded["issuers"][0]["checkpointReference"]["eventCount"] == 2

    # Evidence-specific private fields must never leak into the exported snapshot
    for secret_value in (
        private_nonce,
        att.device_commitment,
        private_ev,
        "PRIVATE_DEVICE_BUILD_ID",
        "9" * 64,
        "captureNonce",
        "deviceCommitment",
        "evidenceDigestBinding",
        "videoHash",
        "proofId",
    ):
        assert secret_value not in raw_json

    # Round-trip parse succeeds deterministically
    restored = OfflineIssuerTrustSnapshot.from_dict(json.loads(raw_json))
    assert restored.snapshot_hash() == snapshot.snapshot_hash()


def test_rejects_injected_private_evidence_fields_inconsistent_checkpoints_and_tampered_hashes() -> None:
    dir1, cp1 = _build_issuer(ORG_1, POLICY_1)
    snap = export_offline_issuer_trust_snapshot(
        [IssuerSnapshotSource(directory=dir1, checkpoint=cp1, policy_version="v1")],
        exported_at=1_730_000_000,
    )
    base = snap.to_dict()

    with_evidence_field = {**base, "evidenceDigest": "7" * 64}
    with pytest.raises(TransparencyError, match="evidence-specific or private"):
        OfflineIssuerTrustSnapshot.from_dict(with_evidence_field)

    nested_private = json.loads(json.dumps(base))
    nested_private["issuers"][0]["policy"]["captureNonce"] = "8" * 64
    with pytest.raises(TransparencyError, match="evidence-specific or private"):
        OfflineIssuerTrustSnapshot.from_dict(nested_private)

    tampered_hash = {**base, "exportedAt": 1_730_000_001}
    with pytest.raises(TransparencyError, match="snapshotHash integrity mismatch"):
        OfflineIssuerTrustSnapshot.from_dict(tampered_hash)

    forged_cp = DirectoryCheckpoint(
        tree_head_hash="5" * 64,
        event_count=cp1.event_count,
        timestamp=cp1.timestamp,
        organization_identity_hash=ORG_1,
        manifest_hash=cp1.manifest_hash,
        signature_hash=SIG,
    )
    with pytest.raises(TransparencyError, match="inconsistent issuer checkpoint"):
        export_offline_issuer_trust_snapshot(
            [IssuerSnapshotSource(directory=dir1, checkpoint=forged_cp, policy_version="v1")],
            exported_at=1_730_000_000,
        )
