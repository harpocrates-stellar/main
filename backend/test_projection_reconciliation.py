"""Focused tests for read-only bounded projection reconciliation (#1067)."""

from __future__ import annotations

import json
from unittest import mock

import pytest

import db
import manage
from chain_indexer import (
    MAX_RECONCILE_LEDGER_SPAN,
    fetch_contract_events_in_range,
    process_events_batch,
    reconcile_projection_range,
    validate_reconcile_ledger_range,
)
from tx_verification import TxVerificationResult

RECON_CONTRACT = "CRECONCILECONTRACTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2I"
TX_MATCH = "71" * 32
TX_MISSING = "72" * 32
TX_CONFLICT = "73" * 32
TX_UNANCHORED = "74" * 32
TX_OUT_OF_RANGE = "75" * 32
PROOF_A = "7a" * 32
PROOF_B = "7b" * 32


def test_reconcile_bounded_range_clean_and_stops_at_end_ledger(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    in_range_event = {
        "ledger": 2005,
        "txHash": TX_MATCH,
        "id": "0000002005-0000000001",
        "contractId": RECON_CONTRACT,
        "topic": ["proof", "revoke", PROOF_A],
        "value": 2,
    }
    past_end_event = {
        "ledger": 2015,
        "txHash": TX_OUT_OF_RANGE,
        "id": "0000002015-0000000001",
        "contractId": RECON_CONTRACT,
        "topic": ["proof", "revoke", PROOF_B],
        "value": 2,
    }
    process_events_batch([in_range_event], contract_id=RECON_CONTRACT)

    with mock.patch(
        "chain_indexer.fetch_contract_events",
        return_value={
            "cursor": "cursor-2015",
            "latestLedger": 2020,
            "events": [in_range_event, past_end_event],
        },
    ) as mock_fetch:
        report = reconcile_projection_range(
            start_ledger=2000,
            end_ledger=2010,
            contract_id=RECON_CONTRACT,
        )

    mock_fetch.assert_called_once()
    assert report["ok"] is True
    assert report["read_only"] is True
    assert report["range"] == {"start_ledger": 2000, "end_ledger": 2010, "span": 11}
    assert report["summary"]["matched"] == 1
    assert report["summary"]["missing_count"] == 0
    assert report["summary"]["conflicting_count"] == 0
    assert report["missing_events"] == []
    assert report["conflicting_state"] == []


def test_reconcile_distinguishes_missing_events_from_conflicting_state(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    isolated_contract = "CRECONCILEISOLATEDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7Q"

    # Seed indexed state with:
    # 1. TX_CONFLICT: exists on-chain, but indexed tx_status/proof_id disagree
    db.insert_indexed_proof_event(
        event_type="revoke",
        proof_id=PROOF_B,  # conflicts with PROOF_A on-chain
        tx_hash=TX_CONFLICT,
        event_index=2,
        contract_id=isolated_contract,
        tx_status="confirmed",  # conflicts with "revoked" on-chain
        metadata={"status": "revoked", "raw_value": 2, "ledger": 2102},
    )
    # 2. TX_UNANCHORED: claims ledger 2104 in metadata, but absent from chain range
    db.insert_indexed_proof_event(
        event_type="expire",
        proof_id=PROOF_A,
        tx_hash=TX_UNANCHORED,
        event_index=1,
        contract_id=isolated_contract,
        tx_status="confirmed",
        metadata={"action": "expired", "ledger": 2104},
    )

    before_events = dict(db._INDEXED_EVENTS)
    before_cursor = dict(db._INDEXER_STATE)

    chain_events = [
        # Missing from DB entirely:
        {
            "ledger": 2101,
            "txHash": TX_MISSING,
            "id": "0000002101-0000000001",
            "contractId": isolated_contract,
            "topic": ["proof", "revoke", PROOF_A],
            "value": 1,
        },
        # Present in DB, but conflicting state:
        {
            "ledger": 2102,
            "txHash": TX_CONFLICT,
            "id": "0000002102-0000000002",
            "contractId": isolated_contract,
            "topic": ["proof", "revoke", PROOF_A],
            "value": 2,
        },
    ]

    with mock.patch("chain_indexer.queue_webhook_deliveries") as mock_wh:
        report = reconcile_projection_range(
            start_ledger=2100,
            end_ledger=2105,
            contract_id=isolated_contract,
            chain_events=chain_events,
        )

    assert report["ok"] is False
    assert report["read_only"] is True
    assert report["summary"]["missing_count"] == 1
    assert report["summary"]["conflicting_count"] == 2

    missing = report["missing_events"]
    assert len(missing) == 1
    assert missing[0]["category"] == "missing_event"
    assert missing[0]["tx_hash"] == TX_MISSING
    assert missing[0]["ledger"] == 2101

    conflicts = report["conflicting_state"]
    reasons = {item["tx_hash"]: item for item in conflicts}
    assert reasons[TX_CONFLICT]["reason"] == "field_mismatch"
    assert set(reasons[TX_CONFLICT]["mismatched_fields"]) >= {"proof_id", "tx_status"}
    assert reasons[TX_UNANCHORED]["reason"] == "unanchored_indexed_event"

    # Guaranteed read-only: zero mutations to DB or cursor or webhooks!
    assert db._INDEXED_EVENTS == before_events
    assert db._INDEXER_STATE == before_cursor
    mock_wh.assert_not_called()


def test_reconcile_optional_verify_tx_flags_horizon_conflict(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    tx_failed_on_horizon = "76" * 32
    ev = {
        "ledger": 2200,
        "txHash": tx_failed_on_horizon,
        "id": "0000002200-0000000001",
        "contractId": RECON_CONTRACT,
        "topic": ["proof", "revoke", PROOF_A],
        "value": 2,
    }
    indexed_row = {
        "tx_hash": tx_failed_on_horizon,
        "event_index": 1,
        "event_type": "revoke",
        "proof_id": PROOF_A,
        "contract_id": RECON_CONTRACT,
        "tx_status": "revoked",
        "metadata": {"status": "revoked", "raw_value": 2},
    }

    with mock.patch(
        "chain_indexer.verify_transaction",
        return_value=TxVerificationResult(status="failed", reason="tx_unsuccessful"),
    ):
        report = reconcile_projection_range(
            start_ledger=2200,
            end_ledger=2200,
            contract_id=RECON_CONTRACT,
            chain_events=[ev],
            indexed_records=[indexed_row],
            verify_tx=True,
        )

    assert report["ok"] is False
    assert report["missing_events"] == []
    assert len(report["conflicting_state"]) == 1
    assert report["conflicting_state"][0]["reason"] == "tx_verification_conflict"
    assert report["conflicting_state"][0]["horizon_status"] == "failed"


def test_reconcile_range_boundaries_and_page_budget_fail_closed():
    with pytest.raises(ValueError, match="end_ledger must be >= start_ledger"):
        validate_reconcile_ledger_range(500, 499)

    with pytest.raises(ValueError, match="exceeds maximum allowed span"):
        validate_reconcile_ledger_range(1, MAX_RECONCILE_LEDGER_SPAN + 2)

    with pytest.raises(ValueError, match="positive integers"):
        validate_reconcile_ledger_range(True, 10)

    def endless_pages(**kwargs):
        cur = kwargs.get("cursor") or "0"
        nxt = str(int(cur) + 1)
        return {
            "cursor": nxt,
            "events": [
                {
                    "ledger": 3000,
                    "txHash": TX_MATCH,
                    "id": f"0000003000-{nxt.zfill(10)}",
                    "topic": ["proof", "revoke", PROOF_A],
                }
            ],
        }

    with mock.patch("chain_indexer.fetch_contract_events", side_effect=endless_pages):
        with pytest.raises(RuntimeError, match="exceeded maximum page budget"):
            fetch_contract_events_in_range(
                rpc_url="https://soroban-testnet.stellar.org",
                contract_id=RECON_CONTRACT,
                start_ledger=3000,
                end_ledger=3010,
                max_pages=3,
            )


def test_manage_cli_reconcile_projection_command(monkeypatch, capsys):
    secret_db = "postgresql://operator:topsecret@db.internal:5432/harpocrates"
    monkeypatch.setenv("DATABASE_URL", secret_db)

    with mock.patch(
        "chain_indexer.reconcile_projection_range",
        return_value={
            "ok": False,
            "read_only": True,
            "contract_id": RECON_CONTRACT,
            "range": {"start_ledger": 100, "end_ledger": 110, "span": 11},
            "summary": {"missing_count": 1, "conflicting_count": 0, "matched": 2},
            "missing_events": [{"category": "missing_event", "tx_hash": TX_MISSING, "event_index": 1}],
            "conflicting_state": [],
        },
    ):
        code = manage.main(
            [
                "--json",
                "reconcile-projection",
                "--start-ledger",
                "100",
                "--end-ledger",
                "110",
                "--contract-id",
                RECON_CONTRACT,
            ]
        )
    raw_out = capsys.readouterr().out
    assert "topsecret" not in raw_out
    payload = json.loads(raw_out)
    assert code == manage.EXIT_PROBLEMS
    assert payload["command"] == "reconcile-projection"
    assert payload["read_only"] is True
    assert payload["summary"]["missing_count"] == 1

    # Inverted range returns EXIT_USAGE (2)
    code_bad = manage.main(
        [
            "--json",
            "reconcile-projection",
            "--start-ledger",
            "200",
            "--end-ledger",
            "100",
            "--contract-id",
            RECON_CONTRACT,
        ]
    )
    out_bad = json.loads(capsys.readouterr().out)
    assert code_bad == manage.EXIT_USAGE
    assert out_bad["ok"] is False
