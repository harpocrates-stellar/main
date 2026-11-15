"""Focused tests for index freshness and coverage in proof read responses (#1065)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

import app as app_module
import db
from chain_indexer import (
    evaluate_proof_read_outcome,
    get_index_freshness_and_coverage,
    observe_chain_head_ledger,
    reset_observed_chain_head,
)
from db import (
    clear_indexer_coverage_gaps,
    record_indexer_coverage_gap,
    save_indexer_cursor,
)

VIDEO_HASH = "31" * 32
PROOF_ID = "32" * 32


@pytest.fixture(autouse=True)
def reset_indexer_read_state(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db._INDEXER_STATE.pop("soroban_events", None)
    clear_indexer_coverage_gaps("soroban_events")
    reset_observed_chain_head("soroban_events")
    yield
    db._INDEXER_STATE.pop("soroban_events", None)
    clear_indexer_coverage_gaps("soroban_events")
    reset_observed_chain_head("soroban_events")


def test_uninitialized_index_never_implies_invalid_on_chain_proof():
    client = app_module.app.test_client()

    res = client.get(f"/api/proofs/by-video/{VIDEO_HASH}")
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["events"] == []

    freshness = body["indexFreshness"]
    assert freshness["status"] == "uninitialized"
    assert freshness["stale"] is True
    assert freshness["coverageComplete"] is False
    assert freshness["lastTrustedLedger"] is None
    assert freshness["knownGaps"] == []
    assert freshness["authoritativeForInvalidity"] is False
    assert freshness["impliesInvalidOnChainProof"] is False
    assert freshness["onChainVerificationRequired"] is True

    outcome = body["readOutcome"]
    assert outcome["readVerdict"] == "indeterminate_uninitialized_index"
    assert outcome["impliesInvalidOnChainProof"] is False
    assert outcome["onChainVerificationRequired"] is True


def test_fresh_caught_up_index_exposes_last_trusted_ledger_and_lag():
    save_indexer_cursor("soroban_events", "cursor-1500", ledger=1500)
    observe_chain_head_ledger(1505)

    client = app_module.app.test_client()
    for path in (
        "/api/proofs?limit=5",
        f"/api/proofs/by-video/{VIDEO_HASH}",
        f"/api/proofs/history/{PROOF_ID}",
    ):
        res = client.get(path)
        assert res.status_code == 200
        freshness = res.get_json()["indexFreshness"]
        assert freshness["status"] == "fresh"
        assert freshness["stale"] is False
        assert freshness["coverageComplete"] is True
        assert freshness["lastTrustedLedger"] == 1500
        assert freshness["latestObservedChainLedger"] == 1505
        assert freshness["ledgerLag"] == 5
        assert freshness["knownGaps"] == []
        assert freshness["impliesInvalidOnChainProof"] is False


def test_stale_index_by_age_or_ledger_lag_prevents_false_invalidity():
    old_ts = datetime.now(timezone.utc) - timedelta(seconds=600)
    db._INDEXER_STATE["soroban_events"] = {
        "cursor": "cursor-1600",
        "ledger": 1600,
        "updated_at": old_ts,
    }
    observe_chain_head_ledger(1602)

    age_stale = get_index_freshness_and_coverage(max_stale_seconds=60.0)
    assert age_stale["status"] == "stale"
    assert age_stale["stale"] is True
    assert age_stale["coverageComplete"] is False
    assert age_stale["onChainVerificationRequired"] is True

    # Recent timestamp, but lagging behind chain head by > max_ledger_lag
    save_indexer_cursor("soroban_events", "cursor-1600", ledger=1600)
    observe_chain_head_ledger(1700)
    lag_stale = get_index_freshness_and_coverage(max_ledger_lag=10)
    assert lag_stale["status"] == "stale"
    assert lag_stale["ledgerLag"] == 100
    assert lag_stale["stale"] is True

    client = app_module.app.test_client()
    batch_res = client.post(
        "/api/proofs/verify-batch",
        json={"proofs": [{"videoHash": VIDEO_HASH}]},
    )
    assert batch_res.status_code == 200
    batch_body = batch_res.get_json()
    assert batch_body["indexFreshness"]["stale"] is True
    item = batch_body["results"][0]
    assert item["status"] == "not_found"
    assert item["impliesInvalidOnChainProof"] is False
    assert item["readOutcome"]["readVerdict"] == "indeterminate_stale_index"
    assert item["readOutcome"]["onChainVerificationRequired"] is True


def test_known_gaps_merged_and_exposed_while_positive_revocation_remains_honored():
    save_indexer_cursor("soroban_events", "cursor-2000", ledger=2000)
    observe_chain_head_ledger(2002)

    record_indexer_coverage_gap(1200, 1205, reason="rpc_backfill_pending")
    record_indexer_coverage_gap(1206, 1210, reason="rpc_backfill_pending")
    record_indexer_coverage_gap(1400, 1402, reason="page_timeout")

    freshness = get_index_freshness_and_coverage()
    assert freshness["status"] == "gapped"
    assert freshness["stale"] is False
    assert freshness["coverageComplete"] is False
    assert freshness["onChainVerificationRequired"] is True
    assert freshness["knownGaps"] == [
        {
            "startLedger": 1200,
            "endLedger": 1210,
            "span": 11,
            "reason": "rpc_backfill_pending",
        },
        {
            "startLedger": 1400,
            "endLedger": 1402,
            "span": 3,
            "reason": "page_timeout",
        },
    ]

    # Empty read under gapped coverage is indeterminate, NOT invalid
    miss_outcome = evaluate_proof_read_outcome([], freshness)
    assert miss_outcome["readVerdict"] == "indeterminate_gapped_index"
    assert miss_outcome["impliesInvalidOnChainProof"] is False

    # Positive indexed revocation still accurately signals revoked on-chain state
    revoked_outcome = evaluate_proof_read_outcome(
        [{"event_type": "revoke", "tx_status": "revoked"}],
        freshness,
    )
    assert revoked_outcome["readVerdict"] == "revoked"
    assert revoked_outcome["impliesInvalidOnChainProof"] is True


def test_coverage_gap_and_threshold_boundaries_fail_closed():
    with pytest.raises(ValueError, match="end_ledger must be >= start_ledger"):
        record_indexer_coverage_gap(500, 499)

    with pytest.raises(ValueError, match="positive integers"):
        record_indexer_coverage_gap(True, 10)

    with pytest.raises(ValueError, match="max_stale_seconds must be positive"):
        get_index_freshness_and_coverage(max_stale_seconds=0)

    with pytest.raises(ValueError, match="max_ledger_lag must be >= 1"):
        get_index_freshness_and_coverage(max_ledger_lag=0)
