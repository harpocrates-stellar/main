"""Adversarial tests for issuer key transparency and rotation history."""

from __future__ import annotations

import unittest

from issuer_key_transparency import (
    DEFAULT_FRESHNESS_SECONDS,
    HIGH_ASSURANCE_FRESHNESS_SECONDS,
    MAX_EXPLANATION_EVENTS,
    DirectoryCache,
    DirectoryCheckpoint,
    DirectoryEvent,
    EventType,
    FreshnessError,
    HistoricalKeyValidityExplanation,
    HistoricalValidityReason,
    IssuerDirectory,
    IssuerKey,
    IssuerManifest,
    KeyStatus,
    LifecycleEventRef,
    TransparencyError,
    canonicalize_validity_explanation,
    compute_tree_head,
    create_activation_event,
    create_rotation_event,
    detect_rollback,
    event_hash,
    explain_historical_key_validity,
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


class HistoricalValidityExplanationTests(unittest.TestCase):
    def test_valid_before_and_invalid_after_rotation(self) -> None:
        e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
        e1 = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2000, event_hash(e0))
        d = rebuild_directory(ORG, [e0, e1])

        before = explain_historical_key_validity(d, "k1", 1500)
        self.assertTrue(before.valid)
        self.assertEqual(before.reason_code, HistoricalValidityReason.VALID_BEFORE_ROTATION)
        self.assertEqual(before.key_status, KeyStatus.ROTATED)
        self.assertEqual(before.valid_from, 1000)
        self.assertEqual(before.valid_until, 2000)
        self.assertFalse(before.compromised_at_signature_time)
        self.assertFalse(before.compromised_later)
        self.assertFalse(before.events_truncated)
        self.assertEqual(len(before.lifecycle_events), 2)
        self.assertEqual(before.lifecycle_events[0].event_hash, event_hash(e0))
        self.assertEqual(before.lifecycle_events[1].event_hash, event_hash(e1))
        self.assertEqual(before.lifecycle_events[1].related_key_id, "k1")

        at_boundary = explain_historical_key_validity(d, "k1", 2000)
        self.assertFalse(at_boundary.valid)
        self.assertEqual(
            at_boundary.reason_code, HistoricalValidityReason.ROTATED_BEFORE_SIGNATURE_TIME
        )

        active_new = explain_historical_key_validity(d, "k2", 2000)
        self.assertTrue(active_new.valid)
        self.assertEqual(active_new.reason_code, HistoricalValidityReason.VALID_ACTIVE_KEY)
        self.assertEqual(len(active_new.lifecycle_events), 1)
        self.assertEqual(active_new.lifecycle_events[0].event_hash, event_hash(e1))

    def test_compromised_key_explanation_pre_and_post_boundary(self) -> None:
        e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
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
        d = rebuild_directory(ORG, [e0, compromise])

        pre = explain_historical_key_validity(d, "k1", 1500)
        self.assertTrue(pre.valid)
        self.assertEqual(pre.reason_code, HistoricalValidityReason.VALID_BEFORE_COMPROMISE)
        self.assertFalse(pre.compromised_at_signature_time)
        self.assertTrue(pre.compromised_later)

        post = explain_historical_key_validity(d, "k1", 1800)
        self.assertFalse(post.valid)
        self.assertEqual(
            post.reason_code, HistoricalValidityReason.COMPROMISED_AT_SIGNATURE_TIME
        )
        self.assertTrue(post.compromised_at_signature_time)
        self.assertFalse(post.compromised_later)

    def test_retired_unknown_and_before_activation_reasons(self) -> None:
        e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
        retire = DirectoryEvent(
            event_type=EventType.RETIREMENT,
            sequence=1,
            timestamp=2500,
            organization_identity_hash=ORG,
            key_id="k1",
            public_key_hash=KEY_A,
            previous_event_hash=event_hash(e0),
        )
        d = rebuild_directory(ORG, [e0, retire])

        unknown = explain_historical_key_validity(d, "missing-key", 1500)
        self.assertFalse(unknown.valid)
        self.assertEqual(unknown.reason_code, HistoricalValidityReason.UNKNOWN_KEY)
        self.assertIsNone(unknown.key_status)
        self.assertEqual(unknown.lifecycle_events, ())

        early = explain_historical_key_validity(d, "k1", 999)
        self.assertFalse(early.valid)
        self.assertEqual(early.reason_code, HistoricalValidityReason.BEFORE_ACTIVATION)

        valid_pre_retire = explain_historical_key_validity(d, "k1", 2000)
        self.assertTrue(valid_pre_retire.valid)
        self.assertEqual(
            valid_pre_retire.reason_code, HistoricalValidityReason.VALID_BEFORE_RETIREMENT
        )

        post_retire = explain_historical_key_validity(d, "k1", 2500)
        self.assertFalse(post_retire.valid)
        self.assertEqual(
            post_retire.reason_code, HistoricalValidityReason.RETIRED_BEFORE_SIGNATURE_TIME
        )

    def test_bounded_lifecycle_events_and_invalid_bound_rejected(self) -> None:
        e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
        e1 = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2000, event_hash(e0))
        d = rebuild_directory(ORG, [e0, e1])

        bounded = explain_historical_key_validity(d, "k1", 1500, max_events=1)
        self.assertTrue(bounded.events_truncated)
        self.assertEqual(len(bounded.lifecycle_events), 1)
        self.assertEqual(bounded.lifecycle_events[0].sequence, 0)

        with self.assertRaises(TransparencyError):
            explain_historical_key_validity(d, "k1", 1500, max_events=0)
        with self.assertRaises(TransparencyError):
            explain_historical_key_validity(
                d, "k1", 1500, max_events=MAX_EXPLANATION_EVENTS + 1
            )

    def test_canonical_round_trip_and_privacy_boundary(self) -> None:
        e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
        d = rebuild_directory(ORG, [e0])
        exp = explain_historical_key_validity(d, "k1", 1500)
        raw = canonicalize_validity_explanation(exp)
        parsed = HistoricalKeyValidityExplanation.from_dict(exp.to_dict())
        self.assertEqual(parsed, exp)
        self.assertEqual(raw, canonicalize_validity_explanation(parsed))

        blob = raw.lower()
        for forbidden in ("evidence", "media", "email", "legalname", "phone", "device", "nonce"):
            self.assertNotIn(forbidden, blob)


class PrivacyTests(unittest.TestCase):
    def test_public_artifacts_exclude_private_org_fields(self) -> None:
        m = _manifest([IssuerKey("k1", KEY_A, "ed25519", 1000)])
        encoded = m.to_dict()
        blob = str(encoded).lower()
        for forbidden in ("email", "legalname", "phone", "street", "employee"):
            self.assertNotIn(forbidden, blob)
        self.assertIn("organizationIdentityHash", encoded)


class ManifestKeyConflictTests(unittest.TestCase):
    def test_rejects_repeated_key_id_with_conflicting_attributes(self) -> None:
        m = _manifest(
            [
                IssuerKey("k1", KEY_A, "ed25519", 1000),
                IssuerKey("k1", KEY_B, "ed25519", 1000),
            ]
        )
        with self.assertRaises(TransparencyError) as ctx:
            canonicalize_manifest(m)
        self.assertIn("conflicting attributes", str(ctx.exception).lower())

    def test_rejects_duplicate_key_id_with_identical_attributes(self) -> None:
        m = _manifest(
            [
                IssuerKey("k1", KEY_A, "ed25519", 1000),
                IssuerKey("k1", KEY_A, "ed25519", 1000),
            ]
        )
        with self.assertRaises(TransparencyError) as ctx:
            canonicalize_manifest(m)
        self.assertIn("duplicate keyid", str(ctx.exception).lower())

    def test_retains_previous_trusted_directory_on_conflict(self) -> None:
        d = IssuerDirectory(ORG)
        m1 = _manifest([IssuerKey("k1", KEY_A, "ed25519", 1000)])
        h1 = d.publish_manifest(m1)

        conflicting = _manifest(
            [
                IssuerKey("k1", KEY_A, "ed25519", 1000),
                IssuerKey("k1", KEY_B, "ed25519", 2000),
            ],
            predecessor=h1,
            valid_from=2000,
        )
        with self.assertRaises(TransparencyError):
            d.publish_manifest(conflicting)

        self.assertEqual(d.current_manifest, m1)
        self.assertEqual(list(d.manifests_by_hash.keys()), [h1])


if __name__ == "__main__":
    unittest.main()
