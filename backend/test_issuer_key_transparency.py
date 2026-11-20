"""Adversarial tests for issuer key transparency and rotation history."""

from __future__ import annotations

import unittest

from issuer_key_transparency import (
    DEFAULT_FRESHNESS_SECONDS,
    HIGH_ASSURANCE_FRESHNESS_SECONDS,
    SNAPSHOT_PROTOCOL,
    CheckpointReference,
    DirectoryCache,
    DirectoryCheckpoint,
    DirectoryEvent,
    EventType,
    FreshnessError,
    IssuerDirectory,
    IssuerKey,
    IssuerManifest,
    IssuerTrustSnapshot,
    KeyStatus,
    PolicyVersion,
    TransparencyError,
    canonicalize_trust_snapshot,
    checkpoint_hash,
    compute_tree_head,
    create_activation_event,
    create_rotation_event,
    detect_rollback,
    event_hash,
    export_offline_trust_snapshot,
    import_offline_trust_snapshot,
    key_valid_for_historical_signature,
    key_was_compromised_at,
    manifest_hash,
    rebuild_directory,
    require_fresh_checkpoint,
    trust_snapshot_hash,
    verify_checkpoint_consistency,
    verify_offline_trust_snapshot,
)

ORG = "a" * 64
POLICY = "b" * 64
KEY_A = "c" * 64
KEY_B = "d" * 64
KEY_C = "e" * 64
SIG = "f" * 64


def _manifest(
    keys: list[IssuerKey],
    *,
    predecessor: str | None = None,
    valid_from: int = 1_000,
    address: str = "GTESTISSUERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
) -> IssuerManifest:
    return IssuerManifest(
        organization_identity_hash=ORG,
        issuer_address=address,
        active_keys=keys,
        policy_hash=POLICY,
        valid_from=valid_from,
        predecessor_manifest_hash=predecessor,
        signature_hash=SIG,
    )


class CanonicalEncodingTests(unittest.TestCase):
    def test_manifest_hash_deterministic(self) -> None:
        key = IssuerKey("k1", KEY_A, "ed25519", 1000)
        m1 = _manifest([key])
        m2 = _manifest([key])
        self.assertEqual(manifest_hash(m1), manifest_hash(m2))
        self.assertEqual(len(manifest_hash(m1)), 64)

    def test_conflicting_manifests_differ(self) -> None:
        a = _manifest([IssuerKey("k1", KEY_A, "ed25519", 1000)])
        b = _manifest([IssuerKey("k1", KEY_B, "ed25519", 1000)])
        self.assertNotEqual(manifest_hash(a), manifest_hash(b))


class DirectoryRebuildTests(unittest.TestCase):
    def test_rebuild_from_events_is_deterministic(self) -> None:
        e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
        e1 = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2000, event_hash(e0))
        d1 = rebuild_directory(ORG, [e0, e1])
        d2 = rebuild_directory(ORG, [e0, e1])
        self.assertEqual(d1.tree_head(), d2.tree_head())
        self.assertEqual(d1.keys["k1"].status, KeyStatus.ROTATED)
        self.assertEqual(d1.keys["k2"].status, KeyStatus.ACTIVE)
        self.assertEqual(compute_tree_head([e0, e1]), d1.tree_head())

    def test_broken_rotation_link_rejected(self) -> None:
        e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
        bad = create_rotation_event(ORG, "k2", KEY_B, "missing", 1, 2000, event_hash(e0))
        with self.assertRaises(TransparencyError) as ctx:
            rebuild_directory(ORG, [e0, bad])
        self.assertIn("broken rotation", str(ctx.exception).lower())

    def test_broken_event_chain_rejected(self) -> None:
        e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
        e1 = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2000, "0" * 64)
        with self.assertRaises(TransparencyError) as ctx:
            rebuild_directory(ORG, [e0, e1])
        self.assertIn("previousEventHash", str(ctx.exception))

    def test_broken_manifest_predecessor_link(self) -> None:
        d = IssuerDirectory(ORG)
        d.append_event(create_activation_event(ORG, "k1", KEY_A, 0, 1000))
        m1 = _manifest([IssuerKey("k1", KEY_A, "ed25519", 1000)])
        d.publish_manifest(m1)
        m2 = _manifest(
            [IssuerKey("k2", KEY_B, "ed25519", 2000)],
            predecessor="0" * 64,
            valid_from=2000,
        )
        with self.assertRaises(TransparencyError) as ctx:
            d.publish_manifest(m2)
        self.assertIn("predecessor", str(ctx.exception).lower())


class SplitViewAndRollbackTests(unittest.TestCase):
    def _dir_with_checkpoint(self) -> tuple[IssuerDirectory, DirectoryCheckpoint]:
        e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
        d = rebuild_directory(ORG, [e0])
        m = _manifest([IssuerKey("k1", KEY_A, "ed25519", 1000)])
        d.publish_manifest(m)
        cp = d.make_checkpoint(timestamp=1500, signature_hash=SIG)
        return d, cp

    def test_detects_split_view_tree_head(self) -> None:
        d, cp = self._dir_with_checkpoint()
        forged = DirectoryCheckpoint(
            tree_head_hash="1" * 64,
            event_count=cp.event_count,
            timestamp=cp.timestamp,
            organization_identity_hash=ORG,
            manifest_hash=cp.manifest_hash,
            signature_hash=SIG,
        )
        errors = verify_checkpoint_consistency(d, forged)
        self.assertTrue(any("split view" in e.lower() or "mismatch" in e.lower() for e in errors))

    def test_detects_rollback(self) -> None:
        d, cp1 = self._dir_with_checkpoint()
        e1 = create_rotation_event(
            ORG, "k2", KEY_B, "k1", 1, 2000, event_hash(d.events[0])
        )
        d.append_event(e1)
        m2 = _manifest(
            [IssuerKey("k2", KEY_B, "ed25519", 2000)],
            predecessor=manifest_hash(d.current_manifest),  # type: ignore[arg-type]
            valid_from=2000,
        )
        d.publish_manifest(m2)
        cp2 = d.make_checkpoint(timestamp=2500, signature_hash=SIG)
        # Attacker presents older checkpoint as current after we saw cp2
        errors = detect_rollback(cp2, cp1)
        self.assertTrue(any("rollback" in e.lower() for e in errors))

    def test_detects_equivocation_same_count(self) -> None:
        _, cp = self._dir_with_checkpoint()
        other = DirectoryCheckpoint(
            tree_head_hash="2" * 64,
            event_count=cp.event_count,
            timestamp=cp.timestamp,
            organization_identity_hash=ORG,
            manifest_hash="3" * 64,
            signature_hash=SIG,
        )
        errors = detect_rollback(cp, other)
        self.assertTrue(any("equivocat" in e.lower() or "conflict" in e.lower() for e in errors))

    def test_detects_conflicting_manifests(self) -> None:
        d, cp = self._dir_with_checkpoint()
        other = DirectoryCheckpoint(
            tree_head_hash=cp.tree_head_hash,
            event_count=cp.event_count,
            timestamp=cp.timestamp,
            organization_identity_hash=ORG,
            manifest_hash="9" * 64,
            signature_hash=SIG,
        )
        errors = verify_checkpoint_consistency(d, other)
        self.assertTrue(any("conflict" in e.lower() for e in errors))


class StaleCheckpointTests(unittest.TestCase):
    def test_stale_checkpoint_fail_closed_high_assurance(self) -> None:
        cp = DirectoryCheckpoint(
            tree_head_hash="0" * 64,
            event_count=0,
            timestamp=1,
            organization_identity_hash=ORG,
            manifest_hash="0" * 64,
        )
        cache = DirectoryCache(checkpoint=cp, fetched_at=1_000, max_age_seconds=DEFAULT_FRESHNESS_SECONDS)
        # Within default window but past high-assurance window
        now = 1_000 + HIGH_ASSURANCE_FRESHNESS_SECONDS + 1
        with self.assertRaises(FreshnessError) as ctx:
            require_fresh_checkpoint(cache, high_assurance=True, now=now)
        self.assertIn("stale", str(ctx.exception).lower())

    def test_fresh_checkpoint_accepted(self) -> None:
        cp = DirectoryCheckpoint(
            tree_head_hash="0" * 64,
            event_count=0,
            timestamp=1,
            organization_identity_hash=ORG,
            manifest_hash="0" * 64,
        )
        cache = DirectoryCache(checkpoint=cp, fetched_at=5_000)
        out = require_fresh_checkpoint(cache, high_assurance=True, now=5_000 + 10)
        self.assertIs(out, cp)


class HistoricalSignatureTests(unittest.TestCase):
    def test_rotation_does_not_invalidate_historical_signatures(self) -> None:
        e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
        e1 = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2000, event_hash(e0))
        d = rebuild_directory(ORG, [e0, e1])
        # Signature made at t=1500 while k1 was active must still verify
        self.assertTrue(key_valid_for_historical_signature(d, "k1", 1500))
        # After rotation boundary, k1 no longer covers new signatures
        self.assertFalse(key_valid_for_historical_signature(d, "k1", 2000))
        self.assertTrue(key_valid_for_historical_signature(d, "k2", 2000))

    def test_compromised_key_detected(self) -> None:
        e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
        d = rebuild_directory(ORG, [e0])
        compromise = DirectoryEvent(
            event_type=EventType.COMPROMISE,
            sequence=1,
            timestamp=1800,
            organization_identity_hash=ORG,
            key_id="k1",
            public_key_hash=KEY_A,
            previous_event_hash=event_hash(e0),
            reason_hash="1" * 64,
        )
        d.append_event(compromise)
        self.assertEqual(d.keys["k1"].status, KeyStatus.COMPROMISED)
        self.assertTrue(key_valid_for_historical_signature(d, "k1", 1500))
        self.assertTrue(key_was_compromised_at(d, "k1", 1800))
        self.assertFalse(key_was_compromised_at(d, "k1", 1700))


class PrivacyTests(unittest.TestCase):
    def test_public_artifacts_exclude_private_org_fields(self) -> None:
        m = _manifest([IssuerKey("k1", KEY_A, "ed25519", 1000)])
        encoded = m.to_dict()
        blob = str(encoded).lower()
        for forbidden in ("email", "legalname", "phone", "street", "employee"):
            self.assertNotIn(forbidden, blob)
        self.assertIn("organizationIdentityHash", encoded)


class OfflineTrustSnapshotTests(unittest.TestCase):
    def _build_directory_and_checkpoints(
        self,
    ) -> tuple[IssuerDirectory, list[DirectoryCheckpoint]]:
        e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
        d = rebuild_directory(ORG, [e0])
        m1 = _manifest([IssuerKey("k1", KEY_A, "ed25519", 1000)], valid_from=1000)
        h1 = d.publish_manifest(m1)
        cp1 = d.make_checkpoint(timestamp=1500, signature_hash=SIG)

        e1 = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2000, event_hash(e0))
        d.append_event(e1)
        m2 = _manifest(
            [IssuerKey("k2", KEY_B, "ed25519", 2000)],
            predecessor=h1,
            valid_from=2000,
        )
        d.publish_manifest(m2)
        cp2 = d.make_checkpoint(timestamp=2500, signature_hash=SIG)
        return d, [cp1, cp2]

    def test_export_roundtrip_and_deterministic_hash(self) -> None:
        d, checkpoints = self._build_directory_and_checkpoints()
        policies = [
            PolicyVersion(policy_version="2026.1", policy_hash=POLICY, effective_from=1000),
            PolicyVersion(policy_version="2026.2", policy_hash="1" * 64, effective_from=2000),
        ]

        snap_a = export_offline_trust_snapshot(
            [d], checkpoints, policies, exported_at=3000
        )
        # Reversed input order must yield identical canonical encoding and hash
        snap_b = export_offline_trust_snapshot(
            [d], list(reversed(checkpoints)), list(reversed(policies)), exported_at=3000
        )

        self.assertEqual(snap_a.protocol, SNAPSHOT_PROTOCOL)
        self.assertEqual(len(snap_a.manifests), 2)
        self.assertEqual(len(snap_a.checkpoint_references), 2)
        self.assertEqual(len(snap_a.policy_versions), 2)
        self.assertEqual(canonicalize_trust_snapshot(snap_a), canonicalize_trust_snapshot(snap_b))
        self.assertEqual(trust_snapshot_hash(snap_a), trust_snapshot_hash(snap_b))
        self.assertEqual(snap_a.checkpoint_references[0].checkpoint_hash, checkpoint_hash(checkpoints[0]))

        # Round-trip import and verify
        raw = canonicalize_trust_snapshot(snap_a)
        reloaded = import_offline_trust_snapshot(raw)
        self.assertEqual(trust_snapshot_hash(reloaded), trust_snapshot_hash(snap_a))
        self.assertEqual(verify_offline_trust_snapshot(reloaded), [])

    def test_snapshot_excludes_evidence_private_identifiers(self) -> None:
        d, checkpoints = self._build_directory_and_checkpoints()
        policies = [PolicyVersion(policy_version="2026.1", policy_hash=POLICY)]
        snap = export_offline_trust_snapshot([d], checkpoints, policies, exported_at=3000)

        raw = canonicalize_trust_snapshot(snap).lower()
        for forbidden in (
            "evidencedigestbinding",
            "capturenonce",
            "devicecommitment",
            "evidenceid",
            "sealid",
            "proofid",
            "nullifier",
            "email",
            "legalname",
        ):
            self.assertNotIn(forbidden, raw)

        # Injecting evidence-specific private identifiers must fail closed on import
        tampered_top = snap.to_dict()
        tampered_top["evidenceDigestBinding"] = "a" * 64
        with self.assertRaises(TransparencyError) as ctx:
            import_offline_trust_snapshot(tampered_top)
        self.assertIn("forbidden private field", str(ctx.exception).lower())

        tampered_cp = snap.to_dict()
        tampered_cp["checkpointReferences"][0]["captureNonce"] = "b" * 64
        with self.assertRaises(TransparencyError) as ctx:
            import_offline_trust_snapshot(tampered_cp)
        self.assertIn("forbidden private field", str(ctx.exception).lower())

        tampered_manifest = snap.to_dict()
        tampered_manifest["manifests"][0]["deviceCommitment"] = "c" * 64
        with self.assertRaises(TransparencyError) as ctx:
            import_offline_trust_snapshot(tampered_manifest)
        self.assertIn("forbidden private field", str(ctx.exception).lower())

        tampered_policy = snap.to_dict()
        tampered_policy["policyVersions"][0]["evidenceId"] = "ev-123"
        with self.assertRaises(TransparencyError) as ctx:
            import_offline_trust_snapshot(tampered_policy)
        self.assertIn("forbidden private field", str(ctx.exception).lower())

    def test_export_rejects_inconsistent_checkpoint(self) -> None:
        d, checkpoints = self._build_directory_and_checkpoints()
        forged_cp = DirectoryCheckpoint(
            tree_head_hash="9" * 64,
            event_count=checkpoints[-1].event_count,
            timestamp=2500,
            organization_identity_hash=ORG,
            manifest_hash=checkpoints[-1].manifest_hash,
            signature_hash=SIG,
        )
        with self.assertRaises(TransparencyError) as ctx:
            export_offline_trust_snapshot(
                [d],
                [forged_cp],
                [PolicyVersion(policy_version="2026.1", policy_hash=POLICY)],
                exported_at=3000,
            )
        self.assertIn("inconsistent checkpoint", str(ctx.exception).lower())

    def test_export_rejects_conflicting_policy_versions(self) -> None:
        d, checkpoints = self._build_directory_and_checkpoints()
        with self.assertRaises(TransparencyError) as ctx:
            export_offline_trust_snapshot(
                [d],
                checkpoints,
                [
                    PolicyVersion(policy_version="2026.1", policy_hash=POLICY),
                    PolicyVersion(policy_version="2026.1", policy_hash="2" * 64),
                ],
                exported_at=3000,
            )
        self.assertIn("conflicting policyhash", str(ctx.exception).lower())

    def test_export_rejects_directory_without_manifest(self) -> None:
        empty_dir = IssuerDirectory(ORG)
        with self.assertRaises(TransparencyError) as ctx:
            export_offline_trust_snapshot([empty_dir], [], [], exported_at=3000)
        self.assertIn("without a published manifest", str(ctx.exception).lower())

    def test_verify_flags_checkpoint_referencing_missing_manifest(self) -> None:
        d, checkpoints = self._build_directory_and_checkpoints()
        snap = IssuerTrustSnapshot(
            exported_at=3000,
            manifests=[d.current_manifest],  # type: ignore[list-item]
            checkpoint_references=[CheckpointReference.from_checkpoint(checkpoints[0])],
            policy_versions=[PolicyVersion(policy_version="2026.1", policy_hash=POLICY)],
        )
        errors = verify_offline_trust_snapshot(snap)
        self.assertTrue(any("missing manifest" in e.lower() for e in errors))

    def test_import_rejects_unsupported_protocol_and_unknown_fields(self) -> None:
        d, checkpoints = self._build_directory_and_checkpoints()
        snap = export_offline_trust_snapshot(
            [d], checkpoints, [PolicyVersion("2026.1", POLICY)], exported_at=3000
        )
        bad_proto = snap.to_dict()
        bad_proto["protocol"] = "unknown-protocol"
        with self.assertRaises(TransparencyError):
            import_offline_trust_snapshot(bad_proto)

        extra_field = snap.to_dict()
        extra_field["unexpectedKey"] = "value"
        with self.assertRaises(TransparencyError) as ctx:
            import_offline_trust_snapshot(extra_field)
        self.assertIn("unsupported field", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
