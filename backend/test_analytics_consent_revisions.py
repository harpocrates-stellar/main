"""Tests for collection-time consent policy revisions and withdrawn vs never-collected exports."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_BACKEND_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _BACKEND_DIR.parent
for _p in (str(_BACKEND_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from analytics.consent import (
    ConsentCollectionDisposition,
    ConsentDecision,
    ConsentManager,
    ConsentSource,
    ConsentStatus,
    validate_consent_policy_revision,
)
from analytics.export_manager import ExportManager, ExportPolicy
from analytics.log_processor import LogEntry, LogProcessor


def _entry(
    entry_id: str,
    ts: float,
    *,
    account_tag: str | None = None,
    policy_revision: str | None = None,
) -> LogEntry:
    return LogEntry(
        entry_id=entry_id,
        event_name=f"evt_{entry_id}",
        message_summary="operational event",
        timestamp_epoch_seconds=ts,
        account_id_tag=account_tag,
        consent_policy_revision=policy_revision,
        export_safe=True,
        export_signature="sig-v1:123456789abc",
    )


def test_collection_time_policy_revision_preserved_across_policy_upgrades() -> None:
    cm = ConsentManager()
    proc = LogProcessor()
    mgr = ExportManager(policy=ExportPolicy(), processor=proc, consent_manager=cm)

    # Grant policy v1 at t=1000
    cm.set_consent(
        "acct_upgrade",
        ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            granted_at_epoch_seconds=1_000.0,
            expires_at_epoch_seconds=99_000.0,
            policy_revision="consent-policy-2026-01",
        ),
    )

    ok1, rev1 = cm.record_collection("acct_upgrade", "telemetry", collected_at_epoch_seconds=1_200.0)
    assert ok1 is True
    assert rev1 == "consent-policy-2026-01"

    # Upgrade to policy v2 at t=2000
    cm.set_consent(
        "acct_upgrade",
        ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            granted_at_epoch_seconds=2_000.0,
            expires_at_epoch_seconds=99_000.0,
            policy_revision="consent-policy-2026-06",
        ),
    )

    ok2, rev2 = cm.record_collection("acct_upgrade", "telemetry", collected_at_epoch_seconds=2_500.0)
    assert ok2 is True
    assert rev2 == "consent-policy-2026-06"

    # Event 0 occurred BEFORE consent was granted (t=500) -> must be excluded!
    # Event 1 occurred at t=1200 (resolved dynamically from collection_policy_history -> 2026-01)
    # Event 2 occurred at t=1500 (explicitly stamped at collection time -> 2026-01)
    # Event 3 occurred at t=2500 (resolved under 2026-06)
    entries = [
        _entry("pre_grant", 500.0, account_tag="acct_upgrade"),
        _entry("v1_dynamic", 1_200.0, account_tag="acct_upgrade"),
        _entry("v1_stamped", 1_500.0, account_tag="acct_upgrade", policy_revision=rev1),
        _entry("v2_dynamic", 2_500.0, account_tag="acct_upgrade"),
    ]

    art, serialized, count = mgr.create_export(
        entries=entries,
        exported_by_tag="acct_upgrade",
        export_token_verified=True,
        subject_account_tag="acct_upgrade",
    )

    assert art is not None
    assert count == 3
    records = json.loads(serialized)
    by_id = {r["entry_id"]: r["consent_policy_revision"] for r in records}
    assert "pre_grant" not in by_id
    assert by_id["v1_dynamic"] == "consent-policy-2026-01"
    assert by_id["v1_stamped"] == "consent-policy-2026-01"
    assert by_id["v2_dynamic"] == "consent-policy-2026-06"

    assert art.consent_disposition == ConsentCollectionDisposition.COLLECTED_UNDER_CONSENT
    assert art.consent_policy_revisions == ["consent-policy-2026-01", "consent-policy-2026-06"]
    assert art.had_prior_collection is True

    # Round-trip import preserves per-record consent_policy_revision
    reimported = proc.import_json_logs(serialized)
    assert [e.consent_policy_revision for e in reimported] == [
        "consent-policy-2026-01",
        "consent-policy-2026-01",
        "consent-policy-2026-06",
    ]


def test_export_distinguishes_withdrawn_consent_from_data_never_collected() -> None:
    cm = ConsentManager()
    proc = LogProcessor()
    mgr = ExportManager(policy=ExportPolicy(), processor=proc, consent_manager=cm)

    # Subject 1: Granted consent, collected events under v1, then withdrew consent
    cm.set_consent(
        "acct_withdrawn",
        ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            granted_at_epoch_seconds=1_000.0,
            expires_at_epoch_seconds=50_000.0,
            policy_revision="consent-policy-v1",
        ),
    )
    cm.record_collection("acct_withdrawn", "telemetry", collected_at_epoch_seconds=1_100.0)
    proc.ingest(_entry("w1", 1_100.0, account_tag="acct_withdrawn"), allow_duplicate=True)
    cm.withdraw_consent("acct_withdrawn", now_epoch_seconds=2_000.0)

    # Subject 2: Denied consent — data never collected
    cm.set_consent(
        "acct_denied",
        ConsentDecision(
            status=ConsentStatus.DENIED,
            source=ConsentSource.USER_EXPLICIT,
            scope=[],
            granted_at_epoch_seconds=1_000.0,
            expires_at_epoch_seconds=0.0,
            policy_revision="consent-policy-v1",
        ),
    )

    # Subject 3: Granted consent, but zero events ever collected
    cm.set_consent(
        "acct_quiet",
        ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            granted_at_epoch_seconds=1_000.0,
            expires_at_epoch_seconds=50_000.0,
            policy_revision="consent-policy-v1",
        ),
    )

    # Export for withdrawn subject: 0 records exported, disposition == consent_withdrawn
    art_w, ser_w, cnt_w = mgr.create_export(
        export_token_verified=True,
        subject_account_tag="acct_withdrawn",
    )
    assert art_w is not None
    assert cnt_w == 0
    assert json.loads(ser_w) == []
    assert art_w.to_consent_summary() == {
        "consent_disposition": "consent_withdrawn",
        "consent_policy_revisions": [],
        "prior_collection_policy_revision": "consent-policy-v1",
        "had_prior_collection": True,
    }

    # Export for denied subject: 0 records exported, disposition == never_collected
    art_d, ser_d, cnt_d = mgr.create_export(
        export_token_verified=True,
        subject_account_tag="acct_denied",
    )
    assert art_d is not None
    assert cnt_d == 0
    assert json.loads(ser_d) == []
    assert art_d.to_consent_summary() == {
        "consent_disposition": "never_collected",
        "consent_policy_revisions": [],
        "prior_collection_policy_revision": None,
        "had_prior_collection": False,
    }

    # Export for unseen subject: 0 records exported, disposition == never_collected
    art_u, _, cnt_u = mgr.create_export(
        export_token_verified=True,
        subject_account_tag="acct_unseen",
    )
    assert art_u is not None
    assert cnt_u == 0
    assert art_u.consent_disposition == ConsentCollectionDisposition.NEVER_COLLECTED
    assert art_u.had_prior_collection is False

    # Export for granted-but-quiet subject: 0 records exported, disposition == never_collected
    art_q, _, cnt_q = mgr.create_export(
        export_token_verified=True,
        subject_account_tag="acct_quiet",
    )
    assert art_q is not None
    assert cnt_q == 0
    assert art_q.consent_disposition == ConsentCollectionDisposition.NEVER_COLLECTED
    assert art_q.had_prior_collection is False


@pytest.mark.parametrize(
    "bad_revision",
    [
        "",
        "   ",
        "../traversal",
        "policy with spaces",
        "a" * 64,  # hex32+ digest rejected
        "S" + ("A" * 55),  # Stellar seed rejected
        "G" + ("B" * 55),  # Stellar address rejected
    ],
)
def test_invalid_policy_revision_rejected_fail_closed(bad_revision: str) -> None:
    with pytest.raises(ValueError, match="invalid consent policy revision"):
        validate_consent_policy_revision(bad_revision)

    with pytest.raises(ValueError, match="invalid consent policy revision"):
        ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            granted_at_epoch_seconds=1.0,
            expires_at_epoch_seconds=2.0,
            policy_revision=bad_revision,
        )
