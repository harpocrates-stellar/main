"""Focused tests for cross-run issuer trust change explanations (#1085)."""

from __future__ import annotations

import pytest

from issuer_key_transparency import (
    HIGH_ASSURANCE_FRESHNESS_SECONDS,
    ISSUER_TRUST_CHANGE_SCHEMA,
    DirectoryCache,
    DirectoryCheckpoint,
    DirectoryEvent,
    EventType,
    IssuerKey,
    IssuerManifest,
    IssuerTrustChangeReason,
    IssuerVerificationObservation,
    TransparencyError,
    create_activation_event,
    create_rotation_event,
    event_hash,
    explain_issuer_trust_change,
    manifest_hash,
    rebuild_directory,
)

ORG = "a" * 64
POLICY = "b" * 64
SIG = "f" * 64
KEY_A = "1" * 64
KEY_B = "2" * 64
ADDR = "GTESTISSUERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"


def _make_manifest(
    keys: list[IssuerKey],
    *,
    predecessor: str | None = None,
    valid_from: int = 1_000,
    valid_until: int | None = None,
) -> IssuerManifest:
    return IssuerManifest(
        organization_identity_hash=ORG,
        issuer_address=ADDR,
        active_keys=keys,
        policy_hash=POLICY,
        valid_from=valid_from,
        valid_until=valid_until,
        predecessor_manifest_hash=predecessor,
        signature_hash=SIG,
    )


def _baseline_observation(*, sig_ts: int = 1_500, evaluated_at: int = 1_600, high_assurance: bool = True):
    e0 = create_activation_event(ORG, "k1", KEY_A, 0, 1_000)
    m1 = _make_manifest([IssuerKey("k1", KEY_A, "ed25519", 1_000)])
    d = rebuild_directory(ORG, [e0], [m1])
    cp = d.make_checkpoint(timestamp=1_550, signature_hash=SIG)
    obs = IssuerVerificationObservation(
        directory=d,
        cache=DirectoryCache(checkpoint=cp, fetched_at=1_550),
        key_id="k1",
        signature_timestamp=sig_ts,
        evaluated_at=evaluated_at,
        high_assurance=high_assurance,
    )
    return obs, e0, m1


def test_distinguishes_rotation_expiry_compromise_and_stale_directory_state() -> None:
    prev_obs, e0, m1 = _baseline_observation(sig_ts=1_500, evaluated_at=1_600)

    # 1. Unchanged run
    same_report = explain_issuer_trust_change(prev_obs, prev_obs)
    assert same_report.primary_reason == IssuerTrustChangeReason.UNCHANGED
    assert same_report.trust_changed is False
    assert same_report.to_dict()["schema"] == ISSUER_TRUST_CHANGE_SCHEMA

    # 2. Rotation: pre-rotation signature stays cryptographically valid, reason is KEY_ROTATED
    e_rot = create_rotation_event(ORG, "k2", KEY_B, "k1", 1, 2_000, event_hash(e0))
    m_rot = _make_manifest(
        [IssuerKey("k2", KEY_B, "ed25519", 2_000)],
        predecessor=manifest_hash(m1),
        valid_from=2_000,
    )
    d_rot = rebuild_directory(ORG, [e0, e_rot], [m1, m_rot])
    cp_rot = d_rot.make_checkpoint(timestamp=2_100, signature_hash=SIG)
    rot_obs = IssuerVerificationObservation(
        directory=d_rot,
        cache=DirectoryCache(checkpoint=cp_rot, fetched_at=2_100),
        key_id="k1",
        signature_timestamp=1_500,
        evaluated_at=2_150,
        high_assurance=True,
    )
    rot_report = explain_issuer_trust_change(prev_obs, rot_obs)
    assert rot_report.primary_reason == IssuerTrustChangeReason.KEY_ROTATED
    assert rot_report.current_run.trusted is True
    assert "generic" not in rot_report.summary.lower()

    # 3. Expiry / retirement: manifest or key retired/expired -> KEY_EXPIRED
    e_ret = DirectoryEvent(
        event_type=EventType.RETIREMENT,
        sequence=1,
        timestamp=1_800,
        organization_identity_hash=ORG,
        key_id="k1",
        public_key_hash=KEY_A,
        previous_event_hash=event_hash(e0),
    )
    m_exp = _make_manifest(
        [IssuerKey("k1", KEY_A, "ed25519", 1_000, valid_until=1_800)],
        predecessor=manifest_hash(m1),
        valid_from=1_000,
        valid_until=1_900,
    )
    d_exp = rebuild_directory(ORG, [e0, e_ret], [m1, m_exp])
    cp_exp = d_exp.make_checkpoint(timestamp=1_850, signature_hash=SIG)
    exp_obs = IssuerVerificationObservation(
        directory=d_exp,
        cache=DirectoryCache(checkpoint=cp_exp, fetched_at=2_000),
        key_id="k1",
        signature_timestamp=1_850,
        evaluated_at=2_050,
        high_assurance=True,
    )
    exp_report = explain_issuer_trust_change(prev_obs, exp_obs)
    assert exp_report.primary_reason == IssuerTrustChangeReason.KEY_EXPIRED
    assert exp_report.current_run.trusted is False

    # 4. Compromise -> KEY_COMPROMISED
    e_comp = DirectoryEvent(
        event_type=EventType.COMPROMISE,
        sequence=1,
        timestamp=1_900,
        organization_identity_hash=ORG,
        key_id="k1",
        public_key_hash=KEY_A,
        previous_event_hash=event_hash(e0),
        reason_hash="9" * 64,
    )
    d_comp = rebuild_directory(ORG, [e0, e_comp], [m1])
    cp_comp = d_comp.make_checkpoint(timestamp=1_950, signature_hash=SIG)
    comp_obs = IssuerVerificationObservation(
        directory=d_comp,
        cache=DirectoryCache(checkpoint=cp_comp, fetched_at=1_950),
        key_id="k1",
        signature_timestamp=1_500,
        evaluated_at=2_000,
        high_assurance=True,
    )
    comp_report = explain_issuer_trust_change(prev_obs, comp_obs)
    assert comp_report.primary_reason == IssuerTrustChangeReason.KEY_COMPROMISED
    assert comp_report.current_run.trusted is False
    assert comp_report.current_run.compromise_flagged is True

    # 5. Stale directory state -> STALE_DIRECTORY_STATE
    stale_obs = IssuerVerificationObservation(
        directory=prev_obs.directory,
        cache=prev_obs.cache,
        key_id="k1",
        signature_timestamp=1_500,
        evaluated_at=1_550 + HIGH_ASSURANCE_FRESHNESS_SECONDS + 10,
        high_assurance=True,
    )
    stale_report = explain_issuer_trust_change(prev_obs, stale_obs)
    assert stale_report.primary_reason == IssuerTrustChangeReason.STALE_DIRECTORY_STATE
    assert stale_report.current_run.checkpoint_fresh is False
    assert stale_report.current_run.trusted is False


def test_detects_rollback_and_rejects_mismatched_org_or_key_comparisons() -> None:
    prev_obs, _, m1 = _baseline_observation(sig_ts=1_500, evaluated_at=1_600)
    rollback_cp = DirectoryCheckpoint(
        tree_head_hash="0" * 64,
        event_count=0,
        timestamp=900,
        organization_identity_hash=ORG,
        manifest_hash=manifest_hash(m1),
    )
    rollback_obs = IssuerVerificationObservation(
        directory=prev_obs.directory,
        cache=DirectoryCache(checkpoint=rollback_cp, fetched_at=1_600),
        key_id="k1",
        signature_timestamp=1_500,
        evaluated_at=1_650,
        high_assurance=True,
    )
    report = explain_issuer_trust_change(prev_obs, rollback_obs)
    assert report.primary_reason == IssuerTrustChangeReason.CHECKPOINT_ROLLBACK_OR_SPLIT_VIEW
    assert report.current_run.trusted is False

    wrong_key_obs = IssuerVerificationObservation(
        directory=prev_obs.directory,
        cache=prev_obs.cache,
        key_id="k99",
        signature_timestamp=1_500,
        evaluated_at=1_650,
    )
    with pytest.raises(TransparencyError, match="different key_id"):
        explain_issuer_trust_change(prev_obs, wrong_key_obs)
