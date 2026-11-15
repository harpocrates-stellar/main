from __future__ import annotations

from unittest import mock

import pytest

from chain_indexer import (
    IndexerBackpressurePolicy,
    poll_indexer_once,
    process_events_batch,
)
from db import get_indexer_cursor, save_indexer_cursor

CONTRACT_ID = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXGI"


def _make_revoke_event(seq: int, tx_prefix: str) -> dict[str, object]:
    tx_hash = f"{tx_prefix}{seq:02x}" + ("ab" * 30)
    proof_id = f"{seq:02x}" * 32
    return {
        "type": "contract",
        "ledger": 800 + seq,
        "contractId": CONTRACT_ID,
        "id": f"0000000{800 + seq:03d}-{seq:010d}",
        "txHash": tx_hash,
        "topic": ["proof", "revoke", proof_id],
        "value": 2,
    }


def test_bounds_in_memory_batch_and_reduces_page_size_on_slow_writes() -> None:
    policy = IndexerBackpressurePolicy(
        max_in_memory_events=3,
        min_page_size=2,
        slow_write_threshold_ms=50.0,
        max_batch_write_budget_ms=120.0,
        slow_cooldown_seconds=1.5,
    )
    events = [_make_revoke_event(i, "a1") for i in range(1, 6)]

    # Simulated clock: each DB write takes 70ms -> 2 writes = 140ms >= 120ms budget
    ticks = iter([0.0, 0.070, 0.100, 0.170, 0.200, 0.270])
    summary = process_events_batch(
        events,
        contract_id=CONTRACT_ID,
        backpressure_policy=policy,
        clock=lambda: next(ticks),
    )

    # 5 events passed in -> 2 capped by memory (max_in_memory_events=3)
    # Within the 3 admitted, budget stops after 2 slow writes -> 1 more deferred -> total deferred = 3
    assert summary["scanned"] == 2
    assert summary["indexed"] == 2
    assert summary["deferred"] == 3
    bp = summary["backpressure"]
    assert bp["throttled"] is True
    assert bp["capped_by_memory"] is True
    assert bp["budget_exhausted"] is True
    assert bp["slow_writes"] == 2
    assert bp["effective_page_size"] == 2
    assert bp["cooldown_seconds"] == 1.5
    assert bp["last_safe_cursor"] == events[1]["id"]


@mock.patch("chain_indexer.fetch_contract_events")
def test_partial_batch_checkpoints_safe_cursor_and_replays_idempotently_after_restart(
    mock_fetch_events: mock.MagicMock,
) -> None:
    save_indexer_cursor("soroban_events", "cursor-initial", ledger=800)
    events = [_make_revoke_event(i, "b2") for i in range(1, 5)]

    policy = IndexerBackpressurePolicy(
        max_in_memory_events=10,
        min_page_size=2,
        slow_write_threshold_ms=50.0,
        max_batch_write_budget_ms=100.0,
    )

    # Cycle 1: slow DB writes (60ms each) exhaust the 100ms budget after event #2.
    # Top-level RPC cursor "cursor-page-end" MUST NOT be persisted yet!
    mock_fetch_events.return_value = {
        "cursor": "cursor-page-end",
        "latestLedger": 804,
        "events": events,
    }
    ticks_slow = iter([0.0, 0.060, 0.100, 0.160])
    cycle1 = poll_indexer_once(
        contract_id=CONTRACT_ID,
        limit=10,
        backpressure_policy=policy,
        clock=lambda: next(ticks_slow),
    )
    assert cycle1["indexed"] == 2
    assert cycle1["deferred"] == 2
    assert get_indexer_cursor() == events[1]["id"]

    # Simulate process restart with fresh policy; RPC returns overlapping replay [events[1], events[2], events[3]]
    restarted_policy = IndexerBackpressurePolicy(
        max_in_memory_events=10,
        min_page_size=2,
        slow_write_threshold_ms=50.0,
        max_batch_write_budget_ms=1000.0,
    )
    mock_fetch_events.reset_mock()
    mock_fetch_events.return_value = {
        "cursor": "cursor-page-end",
        "latestLedger": 804,
        "events": [events[1], events[2], events[3]],
    }
    ticks_fast = iter([0.0, 0.005, 0.010, 0.015, 0.020, 0.025])
    cycle2 = poll_indexer_once(
        contract_id=CONTRACT_ID,
        limit=10,
        backpressure_policy=restarted_policy,
        clock=lambda: next(ticks_fast),
    )

    # Event #2 is deduplicated idempotently; events #3 and #4 are indexed; page cursor advances!
    assert cycle2["scanned"] == 3
    assert cycle2["duplicates"] == 1
    assert cycle2["indexed"] == 2
    assert cycle2["deferred"] == 0
    assert get_indexer_cursor() == "cursor-page-end"


def test_concurrent_batch_admission_rejection_preserves_cursor() -> None:
    save_indexer_cursor("soroban_events", "cursor-steady", ledger=900)
    policy = IndexerBackpressurePolicy(max_concurrent_batches=1)
    assert policy.try_acquire_batch() is True
    try:
        rejected = poll_indexer_once(
            contract_id=CONTRACT_ID,
            backpressure_policy=policy,
        )
        assert rejected["reason"] == "backpressure_admission_rejected"
        assert rejected["backpressure"]["status"] == "admission_rejected"
        assert get_indexer_cursor() == "cursor-steady"
    finally:
        policy.release_batch()


def test_invalid_backpressure_policy_bounds_rejected() -> None:
    with pytest.raises(ValueError, match="max_in_memory_events"):
        IndexerBackpressurePolicy(max_in_memory_events=0)
    with pytest.raises(ValueError, match="slow_write_threshold_ms"):
        IndexerBackpressurePolicy(slow_write_threshold_ms=0.0)
