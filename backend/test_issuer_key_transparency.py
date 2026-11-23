"""Adversarial tests for issuer key transparency and rotation history."""

from __future__ import annotations

import unittest

from capture_attestation import (
    AppIdentity,
    CameraPipeline,
    CaptureAttestation,
    SecureTime,
)
from issuer_key_transparency import (
    DEFAULT_FRESHNESS_SECONDS,
    HIGH_ASSURANCE_FRESHNESS_SECONDS,
    ConsistencyProofBundle,
    DirectoryCache,
    DirectoryCheckpoint,
    DirectoryEvent,
    DirectoryImportPreview,
    EventType,
    FreshnessError,
    HistoricalKeyValidityExplanation,
    HistoricalValidityReason,
    IssuerDirectory,
    IssuerKey,
    IssuerManifest,
    IssuerTrustAssessment,
    IssuerTrustChange,
    KeyStatus,
    PolicyVersion,
    TransparencyError,
    advance_tree_head,
    build_consistency_proof_bundle,
    canonicalize_consistency_proof_bundle,
    compute_tree_head,
    consistency_proof_bundle_hash,
    create_activation_event,
    create_rotation_event,
    detect_rollback,
    evaluate_captured_evidence,
    event_hash,
    export_offline_trust_snapshot,
    import_offline_trust_snapshot,
    key_valid_for_historical_signature,
    key_was_compromised_at,
    manifest_hash,
    preview_directory_import,
    rebuild_directory,
    require_fresh_checkpoint,
    require_valid_consistency_proof_bundle,
    verify_checkpoint_consistency,
    verify_consistency_proof_bundle,
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


class ConsistencyProofBundleTests(unittest.TestCase):
    def _build_two_checkpoint_history(
        self,
    ) -> tuple[IssuerDirectory, DirectoryCheckpoint, DirectoryCheckpoint]:
        e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
        d = rebuild_directory(ORG, [e0])
        m1 = _manifest([IssuerKey("k1", KEY_A, "ed25519", 1000)], valid_from=1000)
        d.publish_manifest(m1)
        cp1 = d.make_checkpoint(timestamp=1500, signature_hash=SIG)

        e1 = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2000, event_hash(e0))
        d.append_event(e1)
        e2 = DirectoryEvent(
            event_type=EventType.RETIREMENT,
            sequence=2,
            timestamp=2500,
            organization_identity_hash=ORG,
            key_id="k1",
            public_key_hash=KEY_A,
            previous_event_hash=event_hash(e1),
            reason_hash="1" * 64,
        )
        d.append_event(e2)
        m2 = _manifest(
            [IssuerKey("k2", KEY_B, "ed25519", 2000)],
            predecessor=manifest_hash(m1),
            valid_from=2000,
        )
        d.publish_manifest(m2)
        cp2 = d.make_checkpoint(timestamp=3000, signature_hash=SIG)
        return d, cp1, cp2

    def test_portable_bundle_roundtrip_and_offline_verification(self) -> None:
        d, cp1, cp2 = self._build_two_checkpoint_history()
        bundle = d.make_consistency_proof_bundle(cp1, cp2)
        self.assertEqual(len(bundle.intervening_events), 2)
        self.assertEqual(
            advance_tree_head(cp1.tree_head_hash, bundle.intervening_events),
            cp2.tree_head_hash,
        )

        # Serialize to canonical JSON and verify completely offline (no directory).
        raw_json = bundle.to_json()
        restored = ConsistencyProofBundle.from_json(raw_json)
        self.assertEqual(
            consistency_proof_bundle_hash(bundle),
            consistency_proof_bundle_hash(restored),
        )
        self.assertEqual(canonicalize_consistency_proof_bundle(restored), raw_json)
        self.assertEqual(
            verify_consistency_proof_bundle(
                restored,
                expected_organization_identity_hash=ORG,
                expected_earlier_checkpoint=cp1,
            ),
            [],
        )
        self.assertIs(
            require_valid_consistency_proof_bundle(
                restored,
                expected_organization_identity_hash=ORG,
                expected_earlier_checkpoint=cp1,
            ),
            restored,
        )

    def test_zero_event_identity_bundle_and_genesis_bundle(self) -> None:
        d, cp1, _ = self._build_two_checkpoint_history()
        # Same checkpoint -> 0 intervening events
        identity_bundle = build_consistency_proof_bundle(d, cp1, cp1)
        self.assertEqual(identity_bundle.intervening_events, ())
        self.assertEqual(verify_consistency_proof_bundle(identity_bundle), [])

        # Genesis (0 events) -> cp1 (1 event)
        d_gen = IssuerDirectory(ORG)
        m0 = _manifest([], valid_from=500)
        d_gen.publish_manifest(m0)
        cp0 = d_gen.make_checkpoint(timestamp=500, signature_hash=SIG)
        e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1000)
        d_gen.append_event(e0)
        m1 = _manifest(
            [IssuerKey("k1", KEY_A, "ed25519", 1000)],
            predecessor=manifest_hash(m0),
            valid_from=1000,
        )
        d_gen.publish_manifest(m1)
        cp_after = d_gen.make_checkpoint(timestamp=1200, signature_hash=SIG)
        genesis_bundle = d_gen.make_consistency_proof_bundle(cp0, cp_after)
        self.assertEqual(len(genesis_bundle.intervening_events), 1)
        self.assertEqual(verify_consistency_proof_bundle(genesis_bundle), [])

    def test_rejects_tampered_intervening_event(self) -> None:
        d, cp1, cp2 = self._build_two_checkpoint_history()
        bundle = d.make_consistency_proof_bundle(cp1, cp2)
        ev0 = bundle.intervening_events[0]
        tampered_ev0 = DirectoryEvent(
            event_type=ev0.event_type,
            sequence=ev0.sequence,
            timestamp=ev0.timestamp + 1,
            organization_identity_hash=ev0.organization_identity_hash,
            key_id=ev0.key_id,
            public_key_hash=ev0.public_key_hash,
            previous_event_hash=ev0.previous_event_hash,
            related_key_id=ev0.related_key_id,
        )
        tampered = ConsistencyProofBundle(
            earlier_checkpoint=cp1,
            later_checkpoint=cp2,
            intervening_events=(tampered_ev0, bundle.intervening_events[1]),
        )
        errors = verify_consistency_proof_bundle(tampered)
        self.assertTrue(any("broken continuity" in e.lower() for e in errors))
        with self.assertRaises(TransparencyError):
            require_valid_consistency_proof_bundle(tampered)

    def test_rejects_missing_intervening_event(self) -> None:
        d, cp1, cp2 = self._build_two_checkpoint_history()
        bundle = d.make_consistency_proof_bundle(cp1, cp2)
        truncated = ConsistencyProofBundle(
            earlier_checkpoint=cp1,
            later_checkpoint=cp2,
            intervening_events=(bundle.intervening_events[0],),
        )
        errors = verify_consistency_proof_bundle(truncated)
        self.assertTrue(any("count mismatch" in e.lower() for e in errors))

    def test_rejects_rollback_and_equivocation(self) -> None:
        d, cp1, cp2 = self._build_two_checkpoint_history()
        # Rollback: later < earlier
        with self.assertRaises(TransparencyError) as ctx:
            d.make_consistency_proof_bundle(cp2, cp1)
        self.assertIn("rollback", str(ctx.exception).lower())

        rollback_bundle = ConsistencyProofBundle(
            earlier_checkpoint=cp2,
            later_checkpoint=cp1,
            intervening_events=(),
        )
        errors = verify_consistency_proof_bundle(rollback_bundle)
        self.assertTrue(any("rollback" in e.lower() for e in errors))

        # Equivocation: same eventCount, diverging tree head
        forged_same_count = DirectoryCheckpoint(
            tree_head_hash="9" * 64,
            event_count=cp1.event_count,
            timestamp=cp1.timestamp + 10,
            organization_identity_hash=ORG,
            manifest_hash=cp1.manifest_hash,
            signature_hash=SIG,
        )
        equiv_bundle = ConsistencyProofBundle(
            earlier_checkpoint=cp1,
            later_checkpoint=forged_same_count,
            intervening_events=(),
        )
        errors = verify_consistency_proof_bundle(equiv_bundle)
        self.assertTrue(any("equivocat" in e.lower() for e in errors))

    def test_rejects_anchor_and_org_mismatch(self) -> None:
        d, cp1, cp2 = self._build_two_checkpoint_history()
        bundle = d.make_consistency_proof_bundle(cp1, cp2)
        errors = verify_consistency_proof_bundle(
            bundle,
            expected_organization_identity_hash="9" * 64,
            expected_earlier_checkpoint=cp2,
        )
        self.assertTrue(any("organizationidentityhash mismatch" in e.lower() for e in errors))
        self.assertTrue(any("expected anchor" in e.lower() for e in errors))

    def test_rejects_malformed_or_unsupported_bundle_json(self) -> None:
        with self.assertRaises(TransparencyError):
            ConsistencyProofBundle.from_json("{not-json")
        with self.assertRaises(TransparencyError):
            ConsistencyProofBundle.from_dict({"protocol": "wrong", "version": 1})
        with self.assertRaises(TransparencyError):
            ConsistencyProofBundle.from_dict(
                {"protocol": "harpocrates-issuer-key-transparency", "version": 99}
            )

    def test_bundle_preserves_privacy(self) -> None:
        d, cp1, cp2 = self._build_two_checkpoint_history()
        raw = d.make_consistency_proof_bundle(cp1, cp2).to_json().lower()
        for forbidden in ("email", "legalname", "phone", "street", "employee"):
            self.assertNotIn(forbidden, raw)


if __name__ == "__main__":
    unittest.main()
