"""Focused tests for canonical event ordering within shared ledgers (#1068)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from chain_indexer import (
    extract_canonical_event_order,
    process_events_batch,
    sort_events_canonically,
)
from db import (
    find_proof_events_by_proof_id,
    insert_indexed_proof_event,
    sort_proof_events_canonically,
)
from tx_verification import parse_stellar_toid, verify_transaction

ORDER_CONTRACT = "CORDERCONTRACTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2I"
ORDER_PROOF = "6a" * 32
ORDER_DISPUTE = "6b" * 32
TX_EARLY_HASH = "61" * 32
TX_LATE_HASH = "62" * 32
TX_SAME_ORDER_A = "63" * 32
TX_SAME_ORDER_B = "64" * 32


def test_same_ledger_tie_breaks_by_tx_and_operation_identity():
    # All four events share ledger 700, delivered in scrambled arrival order.
    ev_tx2_op2 = {
        "ledger": 700,
        "txIndex": 2,
        "operationIndex": 2,
        "eventIndex": 0,
        "txHash": TX_EARLY_HASH,  # intentionally smaller hash on later txIndex=2
        "topic": ["dispute", "resolve", ORDER_DISPUTE, ORDER_PROOF],
        "value": {"resolved_at": 1700000100},
    }
    ev_tx2_op1 = {
        "ledger": 700,
        "txIndex": 2,
        "operationIndex": 1,
        "eventIndex": 0,
        "txHash": TX_EARLY_HASH,
        "topic": ["dispute", "open", ORDER_DISPUTE, ORDER_PROOF],
        "value": {"reason": 1},
    }
    ev_tx1_op1_ev2 = {
        "ledger": 700,
        "txIndex": 1,
        "operationIndex": 1,
        "eventIndex": 2,
        "txHash": TX_LATE_HASH,
        "topic": ["proof", "history", ORDER_PROOF],
        "value": {"action": 5, "reason_code": 10, "actor": "GACTOR"},
    }
    ev_tx1_op1_ev1 = {
        "ledger": 700,
        "txIndex": 1,
        "operationIndex": 1,
        "eventIndex": 1,
        "txHash": TX_LATE_HASH,
        "topic": ["proof", "revoke", ORDER_PROOF],
        "value": 2,
    }

    scrambled = [ev_tx2_op2, ev_tx1_op1_ev2, ev_tx2_op1, ev_tx1_op1_ev1]
    ordered = sort_events_canonically(scrambled)
    assert ordered == [ev_tx1_op1_ev1, ev_tx1_op1_ev2, ev_tx2_op1, ev_tx2_op2]


def test_tx_hash_and_operation_id_tie_breakers_when_numeric_orders_absent():
    # Same ledger 705 without numeric txIndex/operationIndex:
    # tx_hash and operationId provide deterministic, arrival-independent tie-breaking.
    ev_b_op2 = {
        "ledger": 705,
        "txHash": TX_SAME_ORDER_B,
        "operationId": "op-beta",
        "eventIndex": 0,
        "topic": ["proof", "revoke", "6c" * 32],
    }
    ev_a_op2 = {
        "ledger": 705,
        "txHash": TX_SAME_ORDER_A,
        "operationId": "op-beta",
        "eventIndex": 0,
        "topic": ["proof", "revoke", "6c" * 32],
    }
    ev_a_op1 = {
        "ledger": 705,
        "txHash": TX_SAME_ORDER_A,
        "operationId": "op-alpha",
        "eventIndex": 5,  # higher eventIndex, but earlier operationId within same tx
        "topic": ["proof", "history", "6c" * 32],
        "value": {"action": 4},
    }

    perm_1 = sort_events_canonically([ev_b_op2, ev_a_op2, ev_a_op1])
    perm_2 = sort_events_canonically([ev_a_op2, ev_b_op2, ev_a_op1])
    assert perm_1 == [ev_a_op1, ev_a_op2, ev_b_op2]
    assert perm_2 == perm_1


def test_read_order_ignores_database_insertion_timestamp_and_row_id(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    proof_id = "6d" * 32
    earlier_wall_clock = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    later_wall_clock = earlier_wall_clock + timedelta(minutes=30)

    # Insert the LATER on-chain event FIRST (gives it lower DB id and earlier created_at).
    insert_indexed_proof_event(
        event_type="dispute_resolve",
        proof_id=proof_id,
        tx_hash="66" * 32,
        event_index=0,
        contract_id=ORDER_CONTRACT,
        metadata={
            "stage": "resolved",
            "canonical_order": {
                "ledger": 800,
                "tx_order": 2,
                "tx_hash": "66" * 32,
                "operation_order": 2,
                "operation_id": f"{'66' * 32}:2",
                "event_index": 0,
            },
        },
        created_at=earlier_wall_clock,
    )

    # Insert the EARLIER on-chain event SECOND (gives it higher DB id and later created_at).
    insert_indexed_proof_event(
        event_type="dispute_open",
        proof_id=proof_id,
        tx_hash="65" * 32,
        event_index=3,
        contract_id=ORDER_CONTRACT,
        metadata={
            "stage": "open",
            "canonical_order": {
                "ledger": 800,
                "tx_order": 1,
                "tx_hash": "65" * 32,
                "operation_order": 1,
                "operation_id": f"{'65' * 32}:1",
                "event_index": 3,
            },
        },
        created_at=later_wall_clock,
    )

    events = find_proof_events_by_proof_id(proof_id)
    assert [e["event_type"] for e in events] == ["dispute_open", "dispute_resolve"]
    # Verify the first returned event actually had the higher id and later created_at!
    assert events[0]["id"] > events[1]["id"]
    assert events[0]["created_at"] > events[1]["created_at"]

    desc = sort_proof_events_canonically(events, descending=True)
    assert [e["event_type"] for e in desc] == ["dispute_resolve", "dispute_open"]


def test_process_events_batch_ingests_in_canonical_order(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    proof_id = "6e" * 32
    ingested_types: list[str] = []

    raw_batch = [
        {
            "ledger": 900,
            "txIndex": 4,
            "operationIndex": 1,
            "eventIndex": 0,
            "txHash": "67" * 32,
            "topic": ["proof", "revoke", proof_id],
        },
        {
            "ledger": 900,
            "txIndex": 1,
            "operationIndex": 2,
            "eventIndex": 0,
            "txHash": "68" * 32,
            "topic": ["proof", "history", proof_id],
            "value": {"action": 5, "reason_code": 1},
        },
    ]

    orig_insert = insert_indexed_proof_event

    def spy_insert(**kwargs):
        ingested_types.append(kwargs["event_type"])
        return orig_insert(**kwargs)

    with mock.patch("chain_indexer.insert_indexed_proof_event", side_effect=spy_insert):
        summary = process_events_batch(raw_batch, contract_id=ORDER_CONTRACT)

    assert summary["indexed"] == 2
    assert ingested_types == ["correct", "revoke"]


def test_stellar_toid_decoding_and_horizon_verification_metadata():
    # Encode ledger=12345, tx_order=7, op_index=3 into 64-bit Stellar TOID
    toid = (12345 << 32) | (7 << 12) | 3
    assert parse_stellar_toid(str(toid)) == (12345, 7, 3)
    assert parse_stellar_toid("100") is None

    coord = extract_canonical_event_order(
        {
            "id": f"{toid}-0000000002",
            "txHash": "69" * 32,
        }
    )
    assert coord.ledger == 12345
    assert coord.tx_order == 7
    assert coord.operation_order == 3
    assert coord.event_index == 2

    tx_toid = str((12345 << 32) | (7 << 12))
    with mock.patch(
        "tx_verification._fetch_json",
        side_effect=[
            (200, {"successful": True, "ledger": 12345, "paging_token": tx_toid}),
            (200, {"last_ledger": 12350}),
        ],
    ):
        res = verify_transaction("69" * 32, min_confirmations=1)
    assert res.status == "confirmed"
    assert res.paging_token == tx_toid
    assert res.tx_application_order == 7


def test_invalid_ordering_coordinates_fail_closed():
    with pytest.raises(ValueError, match="tx_index"):
        extract_canonical_event_order({"ledger": 100, "txIndex": -1, "txHash": TX_EARLY_HASH})

    with pytest.raises(ValueError, match="operation_index"):
        extract_canonical_event_order({"ledger": 100, "operationIndex": True, "txHash": TX_EARLY_HASH})

    with pytest.raises(ValueError, match="ledger"):
        extract_canonical_event_order({"ledger": "not-a-ledger", "txHash": TX_EARLY_HASH})

    with pytest.raises(ValueError, match="paging_token"):
        parse_stellar_toid(-42)
