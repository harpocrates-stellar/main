from __future__ import annotations

import json
from contextlib import nullcontext
from types import SimpleNamespace
from unittest import mock

import pytest

import db
import projection_reconcile
from chain_indexer import fetch_contract_events


CONTRACT_ID = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXGI"
TX_1 = "11" * 32
TX_2 = "22" * 32
TX_3 = "33" * 32
PROOF_1 = "aa" * 32
PROOF_2 = "bb" * 32
PROOF_3 = "cc" * 32


def _event(tx_hash, proof_id, event_index):
    return {
        "txHash": tx_hash,
        "id": f"0000000100-{event_index:010d}",
        "topic": ["proof", "revoke", proof_id],
    }


def test_reconcile_reports_missing_and_conflicting_projections():
    events = [
        _event(TX_1, PROOF_1, 1),
        _event(TX_2, PROOF_2, 2),
        _event(TX_3, PROOF_3, 3),
    ]
    indexed_rows = [
        {
            "tx_hash": TX_1,
            "event_index": 1,
            "event_type": "revoke",
            "proof_id": PROOF_1,
            "contract_id": CONTRACT_ID,
            "tx_status": "revoked",
            "metadata": {"status": "revoked", "raw_value": None},
        },
        {
            "tx_hash": TX_2,
            "event_index": 2,
            "event_type": "expire",
            "proof_id": PROOF_2,
            "contract_id": CONTRACT_ID,
            "tx_status": "confirmed",
            "metadata": {"action": "expired"},
        },
    ]

    with (
        mock.patch(
            "projection_reconcile.fetch_contract_events",
            return_value={"events": events, "cursor": "cursor-100"},
        ) as fetch_events,
        mock.patch(
            "projection_reconcile.get_indexed_proof_events",
            return_value=indexed_rows,
        ) as get_rows,
    ):
        report = projection_reconcile.reconcile_projection_range(
            start_ledger=100,
            end_ledger=100,
            contract_id=CONTRACT_ID,
        )

    assert report["complete"] is True
    assert report["ok"] is False
    assert report["summary"] == {
        "scanned": 3,
        "recognized": 3,
        "unknown": 0,
        "missing": 1,
        "conflicts": 1,
    }
    assert report["missing_events"] == [
        {
            "tx_hash": TX_3,
            "event_index": 3,
            "event_type": "revoke",
            "proof_id": PROOF_3,
        }
    ]
    assert report["conflicts"][0]["tx_hash"] == TX_2
    assert "event_type" in report["conflicts"][0]["fields"]
    fetch_events.assert_called_once()
    assert fetch_events.call_args.kwargs["start_ledger"] == 100
    assert fetch_events.call_args.kwargs["end_ledger"] == 100
    get_rows.assert_called_once()


def test_reconcile_stops_at_event_limit_without_comparing_partial_range():
    with (
        mock.patch(
            "projection_reconcile.fetch_contract_events",
            return_value={
                "events": [_event(TX_1, PROOF_1, 1), _event(TX_2, PROOF_2, 2)],
                "cursor": "cursor-100",
            },
        ) as fetch_events,
        mock.patch("projection_reconcile.get_indexed_proof_events") as get_rows,
    ):
        report = projection_reconcile.reconcile_projection_range(
            start_ledger=100,
            end_ledger=100,
            contract_id=CONTRACT_ID,
            max_events=1,
        )

    assert report["complete"] is False
    assert report["reason"] == "event_limit_exceeded"
    assert report["ok"] is False
    assert report["missing_events"] == []
    assert report["conflicts"] == []
    assert fetch_events.call_args.kwargs["limit"] == 2
    get_rows.assert_not_called()


def test_reconcile_rejects_ranges_over_ledger_bound():
    with mock.patch("projection_reconcile.fetch_contract_events") as fetch_events:
        with pytest.raises(ValueError, match="ledger range"):
            projection_reconcile.reconcile_projection_range(
                start_ledger=1,
                end_ledger=projection_reconcile.MAX_LEDGER_RANGE + 1,
                contract_id=CONTRACT_ID,
            )
    fetch_events.assert_not_called()


def test_reconcile_paginates_with_end_ledger_and_event_cap():
    page_one = [
        _event(TX_1, PROOF_1, index)
        for index in range(1, projection_reconcile.INDEXER_MAX_PAGE_SIZE + 1)
    ]
    page_two = [
        _event(TX_2, PROOF_2, index)
        for index in range(1, 51)
    ]
    with (
        mock.patch(
            "projection_reconcile.fetch_contract_events",
            side_effect=[
                {"events": page_one, "cursor": "cursor-100"},
                {"events": page_two, "cursor": "cursor-150"},
            ],
        ) as fetch_events,
        mock.patch(
            "projection_reconcile.get_indexed_proof_events",
            return_value=[],
        ),
    ):
        report = projection_reconcile.reconcile_projection_range(
            start_ledger=40,
            end_ledger=50,
            contract_id=CONTRACT_ID,
            max_events=150,
        )

    assert report["complete"] is True
    assert report["summary"]["scanned"] == 150
    assert report["summary"]["missing"] == 150
    assert fetch_events.call_count == 2
    first, second = [call.kwargs for call in fetch_events.call_args_list]
    assert first["start_ledger"] == 40
    assert first["end_ledger"] == 50
    assert first["limit"] == 100
    assert second["start_ledger"] is None
    assert second["end_ledger"] == 50
    assert second["cursor"] == "cursor-100"
    assert second["limit"] == 51


def test_fetch_contract_events_sends_end_ledger_bound():
    response = SimpleNamespace(
        body=json.dumps({"result": {"events": []}}).encode("utf-8")
    )
    with mock.patch("chain_indexer.safe_urlopen", return_value=response) as urlopen:
        fetch_contract_events(
            rpc_url="https://rpc.invalid",
            contract_id=CONTRACT_ID,
            start_ledger=40,
            end_ledger=50,
        )

    request = urlopen.call_args.args[0]
    payload = json.loads(request.data)
    assert payload["params"]["startLedger"] == 40
    assert payload["params"]["endLedger"] == 50


def test_indexed_projection_lookup_uses_read_only_bounded_query():
    cursor = mock.MagicMock()
    cursor.fetchall.return_value = [{"tx_hash": TX_1, "event_index": 1}]
    connection = mock.MagicMock()
    connection.cursor.return_value = nullcontext(cursor)

    with (
        mock.patch("db.database_url", return_value="postgresql://test"),
        mock.patch("db.get_connection", return_value=nullcontext(connection)),
    ):
        rows = db.get_indexed_proof_events([(TX_1, 1), (TX_2, 2)])

    assert rows == [{"tx_hash": TX_1, "event_index": 1}]
    query, params = cursor.execute.call_args.args
    assert "select tx_hash, event_index" in query
    assert "unnest" in query
    assert params == ([TX_1, TX_2], [1, 2])
    connection.commit.assert_not_called()
    connection.rollback.assert_not_called()
