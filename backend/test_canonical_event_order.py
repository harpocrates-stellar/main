"""Focused tests: canonical event order when multiple events share a ledger.

Verifies that chain-indexed events are ordered by
  (ledger ASC, event_index ASC, tx_hash ASC)
rather than by database insertion time (id / created_at).

All tests run against the in-memory stub (no DATABASE_URL required).
Synthetic fixtures only; no production credentials or live fund movement.
"""

from __future__ import annotations

import pytest

from chain_indexer import (
    classify_and_decode_event,
    process_events_batch,
)
from db import (
    _INDEXED_EVENTS,
    find_proof_events_by_proof_id,
    get_indexed_proof_events,
    insert_indexed_proof_event,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TX_A = "aa" * 32  # lexicographically first
TX_B = "bb" * 32
TX_C = "cc" * 32

PROOF_1 = "11" * 32
PROOF_2 = "22" * 32
PROOF_3 = "33" * 32

CONTRACT = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXGI"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clear_store() -> None:
    """Reset the in-memory indexed-event store between tests."""
    _INDEXED_EVENTS.clear()


def _ingest_event(
    *,
    tx_hash: str,
    ledger: int,
    event_index: int,
    proof_id: str,
    event_type: str = "revoke",
    tx_status: str = "revoked",
) -> dict:
    """Insert one synthetic event directly and return the stored row."""
    row, _ = insert_indexed_proof_event(
        event_type=event_type,
        tx_hash=tx_hash,
        event_index=event_index,
        proof_id=proof_id,
        contract_id=CONTRACT,
        tx_status=tx_status,
        ledger=ledger,
    )
    return row


# ---------------------------------------------------------------------------
# 1. insert_indexed_proof_event persists the ledger field
# ---------------------------------------------------------------------------


class TestLedgerFieldPersisted:
    def setup_method(self):
        _clear_store()

    def test_ledger_stored_on_insert(self):
        row, created = insert_indexed_proof_event(
            event_type="revoke",
            tx_hash=TX_A,
            event_index=1,
            proof_id=PROOF_1,
            ledger=500,
        )
        assert created is True
        assert row["ledger"] == 500

    def test_ledger_none_when_not_supplied(self):
        row, created = insert_indexed_proof_event(
            event_type="revoke",
            tx_hash=TX_A,
            event_index=2,
            proof_id=PROOF_1,
        )
        assert created is True
        assert row.get("ledger") is None

    def test_idempotent_insert_returns_stored_ledger(self):
        insert_indexed_proof_event(
            event_type="revoke",
            tx_hash=TX_A,
            event_index=3,
            proof_id=PROOF_1,
            ledger=750,
        )
        row, created = insert_indexed_proof_event(
            event_type="revoke",
            tx_hash=TX_A,
            event_index=3,
            proof_id=PROOF_1,
            ledger=750,
        )
        assert created is False
        assert row["ledger"] == 750


# ---------------------------------------------------------------------------
# 2. process_events_batch threads ledger through classify → insert
# ---------------------------------------------------------------------------


class TestProcessEventsBatchLedger:
    def setup_method(self):
        _clear_store()

    def test_ledger_propagated_from_raw_event_through_batch(self):
        events = [
            {
                "txHash": TX_A,
                "id": "0000000600-0000000001",
                "ledger": 600,
                "topic": ["proof", "revoke", PROOF_1],
            }
        ]
        summary = process_events_batch(events, contract_id=CONTRACT)
        assert summary["indexed"] == 1

        stored = _INDEXED_EVENTS[(TX_A, 1)]
        assert stored["ledger"] == 600

    def test_multiple_events_same_ledger_all_store_ledger(self):
        events = [
            {
                "txHash": TX_A,
                "id": "0000000700-0000000001",
                "ledger": 700,
                "topic": ["proof", "revoke", PROOF_1],
            },
            {
                "txHash": TX_B,
                "id": "0000000700-0000000002",
                "ledger": 700,
                "topic": ["proof", "revoke", PROOF_2],
            },
        ]
        process_events_batch(events, contract_id=CONTRACT)
        assert _INDEXED_EVENTS[(TX_A, 1)]["ledger"] == 700
        assert _INDEXED_EVENTS[(TX_B, 2)]["ledger"] == 700


# ---------------------------------------------------------------------------
# 3. get_indexed_proof_events — canonical order
# ---------------------------------------------------------------------------


class TestGetIndexedProofEventsOrder:
    """get_indexed_proof_events must return events in
    (ledger ASC, event_index ASC, tx_hash ASC) order,
    regardless of insertion order.
    """

    def setup_method(self):
        _clear_store()

    def test_same_ledger_ordered_by_event_index(self):
        # Insert in reverse event_index order
        _ingest_event(tx_hash=TX_A, ledger=800, event_index=5, proof_id=PROOF_1)
        _ingest_event(tx_hash=TX_A, ledger=800, event_index=2, proof_id=PROOF_2)
        _ingest_event(tx_hash=TX_A, ledger=800, event_index=9, proof_id=PROOF_3)

        keys = [(TX_A, 5), (TX_A, 2), (TX_A, 9)]
        rows = get_indexed_proof_events(keys)

        assert len(rows) == 3
        event_indexes = [r["event_index"] for r in rows]
        assert event_indexes == [2, 5, 9], f"expected [2,5,9], got {event_indexes}"

    def test_different_ledgers_ordered_by_ledger_then_event_index(self):
        # Insert later ledger first
        _ingest_event(tx_hash=TX_A, ledger=900, event_index=1, proof_id=PROOF_1)
        _ingest_event(tx_hash=TX_B, ledger=800, event_index=3, proof_id=PROOF_2)
        _ingest_event(tx_hash=TX_C, ledger=800, event_index=1, proof_id=PROOF_3)

        keys = [(TX_A, 1), (TX_B, 3), (TX_C, 1)]
        rows = get_indexed_proof_events(keys)

        assert len(rows) == 3
        # ledger 800/index 1 < ledger 800/index 3 < ledger 900/index 1
        assert rows[0]["ledger"] == 800 and rows[0]["event_index"] == 1
        assert rows[1]["ledger"] == 800 and rows[1]["event_index"] == 3
        assert rows[2]["ledger"] == 900 and rows[2]["event_index"] == 1

    def test_same_ledger_same_event_index_ordered_by_tx_hash(self):
        """When ledger and event_index are identical, tx_hash is the tie-breaker."""
        _ingest_event(tx_hash=TX_C, ledger=1000, event_index=1, proof_id=PROOF_1)
        _ingest_event(tx_hash=TX_A, ledger=1000, event_index=1, proof_id=PROOF_2)
        _ingest_event(tx_hash=TX_B, ledger=1000, event_index=1, proof_id=PROOF_3)

        keys = [(TX_C, 1), (TX_A, 1), (TX_B, 1)]
        rows = get_indexed_proof_events(keys)

        assert len(rows) == 3
        tx_hashes = [r["tx_hash"] for r in rows]
        assert tx_hashes == [TX_A, TX_B, TX_C], (
            f"tx_hash tie-break failed: got {tx_hashes}"
        )

    def test_null_ledger_sorted_last(self):
        """Events without a ledger (not from the indexer) sort after all ledgered events."""
        _ingest_event(tx_hash=TX_A, ledger=100, event_index=1, proof_id=PROOF_1)
        # Insert a no-ledger event
        insert_indexed_proof_event(
            event_type="revoke",
            tx_hash=TX_B,
            event_index=99,
            proof_id=PROOF_2,
            ledger=None,
        )

        keys = [(TX_A, 1), (TX_B, 99)]
        rows = get_indexed_proof_events(keys)

        assert len(rows) == 2
        assert rows[0]["ledger"] == 100   # ledgered event first
        assert rows[1]["ledger"] is None  # null-ledger event last

    def test_stable_order_independent_of_insertion_sequence(self):
        """Inserting events out of chain order must not affect the returned order."""
        # Insert events in reverse chain order
        _ingest_event(tx_hash=TX_A, ledger=300, event_index=4, proof_id=PROOF_3)
        _ingest_event(tx_hash=TX_A, ledger=200, event_index=2, proof_id=PROOF_2)
        _ingest_event(tx_hash=TX_A, ledger=100, event_index=1, proof_id=PROOF_1)

        keys = [(TX_A, 4), (TX_A, 2), (TX_A, 1)]
        rows = get_indexed_proof_events(keys)

        ledgers = [r["ledger"] for r in rows]
        assert ledgers == [100, 200, 300], (
            f"events must be in ledger-ascending order regardless of insertion order; got {ledgers}"
        )


# ---------------------------------------------------------------------------
# 4. find_proof_events_by_proof_id — canonical order
# ---------------------------------------------------------------------------


class TestFindProofEventsByProofIdOrder:
    """find_proof_events_by_proof_id must also use canonical chain order."""

    def setup_method(self):
        _clear_store()

    def test_same_proof_multiple_ledgers_ordered_by_ledger_asc(self):
        # Three lifecycle events for the same proof across different ledgers.
        # Each event must have a unique (tx_hash, event_index) pair.
        _ingest_event(tx_hash=TX_A, ledger=500, event_index=1, proof_id=PROOF_1, event_type="correct")
        _ingest_event(tx_hash=TX_B, ledger=200, event_index=1, proof_id=PROOF_1, event_type="revoke")
        _ingest_event(tx_hash=TX_C, ledger=350, event_index=1, proof_id=PROOF_1, event_type="expire")

        rows = find_proof_events_by_proof_id(PROOF_1)

        assert len(rows) == 3
        ledgers = [r["ledger"] for r in rows]
        assert ledgers == [200, 350, 500], (
            f"expected ascending ledger order [200,350,500], got {ledgers}"
        )

    def test_same_proof_same_ledger_ordered_by_event_index(self):
        _ingest_event(tx_hash=TX_A, ledger=600, event_index=7, proof_id=PROOF_1)
        _ingest_event(tx_hash=TX_A, ledger=600, event_index=3, proof_id=PROOF_1, event_type="expire")

        rows = find_proof_events_by_proof_id(PROOF_1)

        assert len(rows) == 2
        assert rows[0]["event_index"] == 3
        assert rows[1]["event_index"] == 7

    def test_null_ledger_sorted_after_ledgered_events(self):
        _ingest_event(tx_hash=TX_A, ledger=100, event_index=1, proof_id=PROOF_1)
        insert_indexed_proof_event(
            event_type="expire",
            tx_hash=TX_B,
            event_index=5,
            proof_id=PROOF_1,
            ledger=None,
        )

        rows = find_proof_events_by_proof_id(PROOF_1)
        assert rows[0]["ledger"] == 100
        assert rows[1]["ledger"] is None


# ---------------------------------------------------------------------------
# 5. End-to-end: batch ingest → canonical query order
# ---------------------------------------------------------------------------


class TestEndToEndCanonicalOrder:
    """Ingest a batch of raw events (as chain_indexer would) then verify
    the canonical retrieval order reflects ledger position, not insertion time.
    """

    def setup_method(self):
        _clear_store()

    def test_batch_ingest_out_of_order_returns_canonical_sequence(self):
        # Events arrive from RPC in reverse ledger order (simulates backfill or
        # out-of-order delivery).
        events = [
            {
                "txHash": TX_C,
                "id": f"000000{900:06d}-0000000003",
                "ledger": 900,
                "topic": ["proof", "revoke", PROOF_3],
            },
            {
                "txHash": TX_A,
                "id": f"000000{700:06d}-0000000001",
                "ledger": 700,
                "topic": ["proof", "revoke", PROOF_1],
            },
            {
                "txHash": TX_B,
                "id": f"000000{800:06d}-0000000002",
                "ledger": 800,
                "topic": ["proof", "revoke", PROOF_2],
            },
        ]
        summary = process_events_batch(events, contract_id=CONTRACT)
        assert summary["indexed"] == 3

        keys = [(TX_C, 3), (TX_A, 1), (TX_B, 2)]
        rows = get_indexed_proof_events(keys)

        ledgers = [r["ledger"] for r in rows]
        assert ledgers == [700, 800, 900], (
            f"batch-ingested events must return in canonical ledger order; got {ledgers}"
        )

    def test_two_events_same_ledger_same_tx_different_index(self):
        """Two operations from the same transaction in the same ledger are
        distinguished only by event_index — the canonical tie-breaker must
        preserve their on-chain order."""
        events = [
            {
                "txHash": TX_A,
                "id": f"000000{1000:06d}-0000000005",
                "ledger": 1000,
                "topic": ["proof", "revoke", PROOF_2],
            },
            {
                "txHash": TX_A,
                "id": f"000000{1000:06d}-0000000002",
                "ledger": 1000,
                "topic": ["proof", "history", PROOF_1],
                "value": {"action": 3},
            },
        ]
        process_events_batch(events, contract_id=CONTRACT)

        keys = [(TX_A, 5), (TX_A, 2)]
        rows = get_indexed_proof_events(keys)

        assert [r["event_index"] for r in rows] == [2, 5], (
            "events within same tx must be ordered by event_index ASC"
        )

    def test_no_regression_different_proofs_different_ledgers(self):
        """Canonical ordering must not mix up events that belong to different proofs."""
        events = [
            {
                "txHash": TX_B,
                "id": "0000001100-0000000002",
                "ledger": 1100,
                "topic": ["proof", "revoke", PROOF_2],
            },
            {
                "txHash": TX_A,
                "id": "0000001000-0000000001",
                "ledger": 1000,
                "topic": ["proof", "revoke", PROOF_1],
            },
        ]
        process_events_batch(events, contract_id=CONTRACT)

        rows_proof1 = find_proof_events_by_proof_id(PROOF_1)
        rows_proof2 = find_proof_events_by_proof_id(PROOF_2)

        assert len(rows_proof1) == 1 and rows_proof1[0]["ledger"] == 1000
        assert len(rows_proof2) == 1 and rows_proof2[0]["ledger"] == 1100
