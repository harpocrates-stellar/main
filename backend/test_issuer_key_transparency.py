"""Adversarial tests for issuer key transparency and rotation history."""

from __future__ import annotations

import unittest

from issuer_key_transparency import (
    DEFAULT_FRESHNESS_SECONDS,
    HIGH_ASSURANCE_FRESHNESS_SECONDS,
    DirectoryCache,
    DirectoryCheckpoint,
    DirectoryEvent,
    EventType,
    FreshnessError,
    IssuerDirectory,
    IssuerKey,
    IssuerManifest,
    IssuerTrustAssessment,
    IssuerTrustChange,
    KeyStatus,
    TransparencyError,
    TrustChangeReason,
    TrustState,
    assess_issuer_trust,
    compare_issuer_trust,
    compute_tree_head,
    create_activation_event,
    create_rotation_event,
    detect_rollback,
    event_hash,
    key_valid_for_historical_signature,
    key_was_compromised_at,
    manifest_hash,
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


class IssuerTrustChangeTests(unittest.TestCase):
    def _active_directory(
        self,
        *,
        key_valid_until: int | None = None,
        manifest_valid_until: int | None = None,
    ) -> tuple[IssuerDirectory, DirectoryCheckpoint]:
        e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
        d = rebuild_directory(ORG, [e0])
        m = IssuerManifest(
            organization_identity_hash=ORG,
            issuer_address="GTESTISSUERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            active_keys=[IssuerKey("k1", KEY_A, "ed25519", 1000, valid_until=key_valid_until)],
            policy_hash=POLICY,
            valid_from=1000,
            valid_until=manifest_valid_until,
            signature_hash=SIG,
        )
        d.publish_manifest(m)
        cp = d.make_checkpoint(timestamp=1100, signature_hash=SIG)
        return d, cp

    def test_unchanged_trust_across_runs(self) -> None:
        d, cp = self._active_directory()
        cache = DirectoryCache(checkpoint=cp, fetched_at=1200)
        run1 = assess_issuer_trust(d, "k1", signature_timestamp=1200, cache=cache, now=1200)
        run2 = assess_issuer_trust(d, "k1", signature_timestamp=1200, cache=cache, now=1300)
        change = compare_issuer_trust(run1, run2)
        self.assertFalse(change.changed)
        self.assertEqual(change.previous_state, TrustState.TRUSTED)
        self.assertEqual(change.current_state, TrustState.TRUSTED)
        self.assertEqual(change.reason, TrustChangeReason.UNCHANGED)

    def test_rotation_distinguished_for_historical_and_new_signatures(self) -> None:
        d, _ = self._active_directory()
        run1 = assess_issuer_trust(d, "k1", signature_timestamp=1500, now=1500)
        self.assertEqual(run1.state, TrustState.TRUSTED)

        e1 = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2000, event_hash(d.events[0]))
        d.append_event(e1)

        # Historical signature made before rotation stays historically valid with rotation reason
        run2_hist = assess_issuer_trust(d, "k1", signature_timestamp=1500, now=2100)
        change_hist = compare_issuer_trust(run1, run2_hist)
        self.assertTrue(change_hist.changed)
        self.assertEqual(change_hist.previous_state, TrustState.TRUSTED)
        self.assertEqual(change_hist.current_state, TrustState.HISTORICALLY_VALID)
        self.assertEqual(change_hist.reason, TrustChangeReason.KEY_ROTATED)
        self.assertEqual(change_hist.successor_key_id, "k2")

        # New signature at/after rotation boundary is untrusted due to rotation
        run2_new = assess_issuer_trust(d, "k1", signature_timestamp=2000, now=2100)
        change_new = compare_issuer_trust(run1, run2_new)
        self.assertTrue(change_new.changed)
        self.assertEqual(change_new.current_state, TrustState.UNTRUSTED)
        self.assertEqual(change_new.reason, TrustChangeReason.KEY_ROTATED)
        self.assertEqual(change_new.successor_key_id, "k2")

    def test_expiry_distinguished_from_rotation_and_compromise(self) -> None:
        d, _ = self._active_directory(key_valid_until=2000)
        run1 = assess_issuer_trust(d, "k1", signature_timestamp=1999, now=1999)
        self.assertEqual(run1.state, TrustState.TRUSTED)

        run2 = assess_issuer_trust(d, "k1", signature_timestamp=2000, now=2000)
        change = compare_issuer_trust(run1, run2)
        self.assertTrue(change.changed)
        self.assertEqual(change.previous_state, TrustState.TRUSTED)
        self.assertEqual(change.current_state, TrustState.UNTRUSTED)
        self.assertEqual(change.reason, TrustChangeReason.KEY_EXPIRED)
        self.assertIsNone(change.successor_key_id)

    def test_compromise_distinguished_and_surfaces_reason_hash(self) -> None:
        d, _ = self._active_directory()
        run1 = assess_issuer_trust(d, "k1", signature_timestamp=1500, now=1500)
        self.assertEqual(run1.state, TrustState.TRUSTED)

        reason_digest = "7" * 64
        d.append_event(
            DirectoryEvent(
                event_type=EventType.COMPROMISE,
                sequence=1,
                timestamp=1800,
                organization_identity_hash=ORG,
                key_id="k1",
                public_key_hash=KEY_A,
                previous_event_hash=event_hash(d.events[0]),
                reason_hash=reason_digest,
            )
        )

        # Pre-compromise historical signature surfaces compromise status
        run2_pre = assess_issuer_trust(d, "k1", signature_timestamp=1500, now=1900)
        change_pre = compare_issuer_trust(run1, run2_pre)
        self.assertTrue(change_pre.changed)
        self.assertEqual(change_pre.current_state, TrustState.HISTORICALLY_VALID)
        self.assertEqual(change_pre.reason, TrustChangeReason.KEY_COMPROMISED)
        self.assertEqual(change_pre.reason_hash, reason_digest)

        # Post-compromise signature is untrusted due to compromise
        run2_post = assess_issuer_trust(d, "k1", signature_timestamp=1800, now=1900)
        change_post = compare_issuer_trust(run1, run2_post)
        self.assertTrue(change_post.changed)
        self.assertEqual(change_post.current_state, TrustState.UNTRUSTED)
        self.assertEqual(change_post.reason, TrustChangeReason.KEY_COMPROMISED)
        self.assertEqual(change_post.reason_hash, reason_digest)

    def test_stale_directory_state_fail_closed_across_runs(self) -> None:
        d, cp = self._active_directory()
        cache = DirectoryCache(checkpoint=cp, fetched_at=1500)
        run1 = assess_issuer_trust(
            d, "k1", signature_timestamp=1500, cache=cache, high_assurance=True, now=1500
        )
        self.assertEqual(run1.state, TrustState.TRUSTED)

        stale_now = 1500 + HIGH_ASSURANCE_FRESHNESS_SECONDS + 1
        run2 = assess_issuer_trust(
            d, "k1", signature_timestamp=1500, cache=cache, high_assurance=True, now=stale_now
        )
        change = compare_issuer_trust(run1, run2)
        self.assertTrue(change.changed)
        self.assertEqual(change.previous_state, TrustState.TRUSTED)
        self.assertEqual(change.current_state, TrustState.STALE)
        self.assertEqual(change.reason, TrustChangeReason.STALE_DIRECTORY)
        self.assertEqual(run2.checkpoint_age_seconds, HIGH_ASSURANCE_FRESHNESS_SECONDS + 1)

    def test_checkpoint_rollback_across_runs_flagged_inconsistent(self) -> None:
        d, cp1 = self._active_directory()
        e1 = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2000, event_hash(d.events[0]))
        d.append_event(e1)
        m2 = _manifest(
            [IssuerKey("k2", KEY_B, "ed25519", 2000)],
            predecessor=manifest_hash(d.current_manifest),  # type: ignore[arg-type]
            valid_from=2000,
        )
        d.publish_manifest(m2)
        cp2 = d.make_checkpoint(timestamp=2100, signature_hash=SIG)

        run1 = assess_issuer_trust(d, "k2", signature_timestamp=2100, now=2100)
        run2 = assess_issuer_trust(d, "k2", signature_timestamp=2100, now=2200)
        change = compare_issuer_trust(
            run1, run2, previous_checkpoint=cp2, current_checkpoint=cp1
        )
        self.assertTrue(change.changed)
        self.assertEqual(change.current_state, TrustState.UNTRUSTED)
        self.assertEqual(change.reason, TrustChangeReason.DIRECTORY_INCONSISTENT)
        self.assertTrue(any("rollback" in e.lower() for e in change.rollback_errors))

    def test_boundary_unknown_key_not_yet_valid_and_mismatch_errors(self) -> None:
        d, _ = self._active_directory()
        unknown = assess_issuer_trust(d, "missing", signature_timestamp=1500, now=1500)
        self.assertEqual(unknown.state, TrustState.UNTRUSTED)
        self.assertEqual(unknown.reason, TrustChangeReason.UNKNOWN_KEY)

        early = assess_issuer_trust(d, "k1", signature_timestamp=999, now=1500)
        self.assertEqual(early.state, TrustState.UNTRUSTED)
        self.assertEqual(early.reason, TrustChangeReason.NOT_YET_VALID)

        with self.assertRaises(TransparencyError):
            compare_issuer_trust(unknown, early)

    def test_trust_change_serialization_excludes_private_fields(self) -> None:
        d, _ = self._active_directory(key_valid_until=2000)
        run1 = assess_issuer_trust(d, "k1", signature_timestamp=1500, now=1500)
        run2 = assess_issuer_trust(d, "k1", signature_timestamp=2000, now=2000)
        change = compare_issuer_trust(run1, run2)
        self.assertIsInstance(run2, IssuerTrustAssessment)
        self.assertIsInstance(change, IssuerTrustChange)
        blob = str({"assessment": run2.to_dict(), "change": change.to_dict()}).lower()
        for forbidden in ("email", "legalname", "phone", "street", "employee"):
            self.assertNotIn(forbidden, blob)
        self.assertEqual(change.to_dict()["reason"], "key_expired")


if __name__ == "__main__":
    unittest.main()
