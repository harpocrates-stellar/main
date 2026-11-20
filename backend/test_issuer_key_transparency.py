"""Adversarial tests for issuer key transparency and rotation history."""

from __future__ import annotations

import unittest

from issuer_key_transparency import (
    DEFAULT_FRESHNESS_SECONDS,
    HIGH_ASSURANCE_FRESHNESS_SECONDS,
    CheckpointLineage,
    DirectoryCache,
    DirectoryCheckpoint,
    DirectoryEvent,
    DirectoryImportPreview,
    EventType,
    FreshnessError,
    IssuerDirectory,
    IssuerKey,
    IssuerManifest,
    KeyLifecycleChange,
    KeyStatus,
    TransparencyError,
    apply_directory_import,
    checkpoint_hash,
    compute_tree_head,
    create_activation_event,
    create_rotation_event,
    detect_rollback,
    event_hash,
    key_valid_for_historical_signature,
    key_was_compromised_at,
    manifest_hash,
    preview_directory_import,
    rebuild_directory,
    require_fresh_checkpoint,
    verify_checkpoint_consistency,
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


class DirectoryImportPreviewTests(unittest.TestCase):
    def _base_directory(self) -> tuple[IssuerDirectory, IssuerManifest, DirectoryCheckpoint]:
        e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
        d = rebuild_directory(ORG, [e0])
        m1 = _manifest([IssuerKey("k1", KEY_A, "ed25519", 1000)])
        d.publish_manifest(m1)
        cp1 = d.make_checkpoint(timestamp=1500, signature_hash=SIG)
        return d, m1, cp1

    def test_preview_reports_key_lifecycle_and_lineage_without_mutating_state(self) -> None:
        d, m1, cp1 = self._base_directory()
        e1 = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2000, event_hash(d.events[0]))
        e2 = DirectoryEvent(
            event_type=EventType.COMPROMISE,
            sequence=2,
            timestamp=2500,
            organization_identity_hash=ORG,
            key_id="k1",
            public_key_hash=KEY_A,
            previous_event_hash=event_hash(e1),
            reason_hash="1" * 64,
        )
        m2 = _manifest(
            [IssuerKey("k2", KEY_B, "ed25519", 2000)],
            predecessor=manifest_hash(m1),
            valid_from=2000,
        )
        expected_dir = rebuild_directory(ORG, [d.events[0], e1, e2], [m1, m2])
        cp2 = expected_dir.make_checkpoint(timestamp=2600, signature_hash=SIG)

        before_head = d.tree_head()
        before_events = list(d.events)
        before_keys = dict(d.keys)
        before_manifest = d.current_manifest

        preview = preview_directory_import(
            d,
            [e1, e2],
            incoming_manifests=[m2],
            incoming_checkpoint=cp2,
            previously_seen_checkpoint=cp1,
        )

        # Trust state must NOT be mutated by preview.
        self.assertEqual(d.tree_head(), before_head)
        self.assertEqual(d.events, before_events)
        self.assertEqual(d.keys, before_keys)
        self.assertIs(d.current_manifest, before_manifest)

        self.assertIsInstance(preview, DirectoryImportPreview)
        self.assertTrue(preview.acceptable)
        self.assertEqual(preview.errors, ())

        # Verify proposed key lifecycle changes.
        changes_by_id = {c.key_id: c for c in preview.key_changes}
        self.assertEqual(set(changes_by_id.keys()), {"k1", "k2"})
        self.assertEqual(changes_by_id["k1"].previous_status, KeyStatus.ACTIVE)
        self.assertEqual(changes_by_id["k1"].proposed_status, KeyStatus.COMPROMISED)
        self.assertEqual(
            changes_by_id["k1"].event_types, (EventType.ROTATION, EventType.COMPROMISE)
        )
        self.assertEqual(changes_by_id["k2"].previous_status, None)
        self.assertEqual(changes_by_id["k2"].proposed_status, KeyStatus.ACTIVE)
        self.assertEqual(changes_by_id["k2"].related_key_id, "k1")

        # Verify checkpoint lineage.
        lineage = preview.checkpoint_lineage
        self.assertIsInstance(lineage, CheckpointLineage)
        self.assertTrue(lineage.extends_current_head)
        self.assertEqual(lineage.current_event_count, 1)
        self.assertEqual(lineage.proposed_event_count, 3)
        self.assertEqual(lineage.added_event_count, 2)
        self.assertEqual(lineage.current_tree_head_hash, before_head)
        self.assertEqual(lineage.proposed_tree_head_hash, expected_dir.tree_head())
        self.assertEqual(lineage.current_manifest_hash, manifest_hash(m1))
        self.assertEqual(lineage.proposed_manifest_hash, manifest_hash(m2))
        self.assertEqual(lineage.manifest_chain_hashes, (manifest_hash(m2),))
        self.assertEqual(lineage.previously_seen_checkpoint_hash, checkpoint_hash(cp1))
        self.assertEqual(lineage.incoming_checkpoint_hash, checkpoint_hash(cp2))

        # Apply accepted preview and verify mutation now occurs.
        apply_directory_import(d, preview)
        self.assertEqual(len(d.events), 3)
        self.assertEqual(d.tree_head(), expected_dir.tree_head())
        self.assertEqual(d.keys["k1"].status, KeyStatus.COMPROMISED)
        self.assertEqual(d.keys["k2"].status, KeyStatus.ACTIVE)
        self.assertEqual(manifest_hash(d.current_manifest), manifest_hash(m2))  # type: ignore[arg-type]

    def test_preview_accepts_full_log_with_matching_prefix(self) -> None:
        d, m1, cp1 = self._base_directory()
        e1 = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2000, event_hash(d.events[0]))
        preview = preview_directory_import(
            d,
            [d.events[0], e1],
            incoming_manifests=[m1],
            previously_seen_checkpoint=cp1,
        )
        self.assertTrue(preview.acceptable)
        self.assertEqual(preview.checkpoint_lineage.added_event_count, 1)
        self.assertEqual(len(preview.proposed_events), 1)
        self.assertEqual(len(preview.proposed_manifests), 0)

    def test_preview_noop_import_reports_no_changes(self) -> None:
        d, m1, cp1 = self._base_directory()
        preview = preview_directory_import(
            d,
            [],
            incoming_manifests=[m1],
            incoming_checkpoint=cp1,
            previously_seen_checkpoint=cp1,
        )
        self.assertTrue(preview.acceptable)
        self.assertEqual(preview.key_changes, ())
        self.assertEqual(preview.checkpoint_lineage.added_event_count, 0)
        self.assertTrue(preview.checkpoint_lineage.extends_current_head)

    def test_preview_rejects_rollback_and_split_view_without_mutating(self) -> None:
        d, m1, cp1 = self._base_directory()
        e1 = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2000, event_hash(d.events[0]))
        d.append_event(e1)
        m2 = _manifest(
            [IssuerKey("k2", KEY_B, "ed25519", 2000)],
            predecessor=manifest_hash(m1),
            valid_from=2000,
        )
        d.publish_manifest(m2)
        cp2 = d.make_checkpoint(timestamp=2500, signature_hash=SIG)

        # Rollback: incoming full log is shorter than current directory
        rb_preview = preview_directory_import(
            d,
            [d.events[0]],
            incoming_checkpoint=cp1,
            previously_seen_checkpoint=cp2,
        )
        self.assertFalse(rb_preview.acceptable)
        self.assertFalse(rb_preview.checkpoint_lineage.extends_current_head)
        self.assertTrue(any("rollback" in e.lower() for e in rb_preview.errors))
        with self.assertRaises(TransparencyError):
            apply_directory_import(d, rb_preview)

        # Split view: forged checkpoint tree head
        forged_cp = DirectoryCheckpoint(
            tree_head_hash="9" * 64,
            event_count=cp2.event_count,
            timestamp=cp2.timestamp,
            organization_identity_hash=ORG,
            manifest_hash=cp2.manifest_hash,
            signature_hash=SIG,
        )
        sv_preview = preview_directory_import(
            d,
            [],
            incoming_checkpoint=forged_cp,
            previously_seen_checkpoint=cp2,
        )
        self.assertFalse(sv_preview.acceptable)
        self.assertTrue(
            any("split view" in e.lower() or "equivocat" in e.lower() for e in sv_preview.errors)
        )
        self.assertEqual(len(d.events), 2)

    def test_apply_rejects_stale_preview_after_directory_mutation(self) -> None:
        d, m1, _ = self._base_directory()
        e1 = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2000, event_hash(d.events[0]))
        preview = preview_directory_import(d, [e1])
        self.assertTrue(preview.acceptable)

        # Mutate directory before applying preview (TOCTOU guard)
        d.append_event(e1)
        with self.assertRaises(TransparencyError) as ctx:
            apply_directory_import(d, preview)
        self.assertIn("changed since preview", str(ctx.exception).lower())

    def test_preview_to_dict_preserves_privacy(self) -> None:
        d, _, cp1 = self._base_directory()
        e1 = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2000, event_hash(d.events[0]))
        preview = preview_directory_import(d, [e1], previously_seen_checkpoint=cp1)
        payload = preview.to_dict()
        blob = str(payload).lower()
        for forbidden in ("email", "legalname", "phone", "street", "employee"):
            self.assertNotIn(forbidden, blob)
        self.assertIn("checkpointLineage", payload)
        self.assertIn("keyChanges", payload)


if __name__ == "__main__":
    unittest.main()
