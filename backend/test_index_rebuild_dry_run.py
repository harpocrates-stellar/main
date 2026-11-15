"""Focused tests for index rebuild dry-run and deterministic projection fingerprints (#1069)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

import db
import manage
from chain_indexer import (
    INDEXER_MAX_DRY_RUN_EVENTS,
    PROJECTION_FINGERPRINT_DOMAIN,
    compute_projection_fingerprint,
    dry_run_index_rebuild,
    process_events_batch,
    reconstruct_temporary_projection,
)

DRY_CONTRACT = "CDRYRUNCONTRACTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2I"
DRY_TX_A = "81" * 32
DRY_TX_B = "82" * 32
DRY_TX_C = "83" * 32
DRY_PROOF_1 = "91" * 32
DRY_PROOF_2 = "92" * 32


def _synthetic_events() -> list[dict]:
    return [
        {
            "txHash": DRY_TX_A,
            "id": "0000001200-0000000001",
            "contractId": DRY_CONTRACT,
            "topic": ["proof", "revoke", DRY_PROOF_1],
            "value": 2,
        },
        {
            "txHash": DRY_TX_B,
            "id": "0000001201-0000000003",
            "contractId": DRY_CONTRACT,
            "topic": ["proof", "history", DRY_PROOF_2],
            "value": {"action": 5, "reason_code": 7, "actor": "GADMIN"},
        },
        {
            "txHash": DRY_TX_B,
            "id": "0000001201-0000000004",
            "contractId": DRY_CONTRACT,
            "topic": ["unknown", "topic"],
        },
    ]


def test_temporary_projection_is_deterministic_and_side_effect_free(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    before_keys = set(db._INDEXED_EVENTS.keys())
    before_state = dict(db._INDEXER_STATE)

    events = _synthetic_events()
    reordered_with_dup = [events[2], events[1], events[0], events[0]]

    with mock.patch("chain_indexer.queue_webhook_deliveries") as mock_webhook:
        proj_1 = reconstruct_temporary_projection(events, contract_id=DRY_CONTRACT)
        proj_2 = reconstruct_temporary_projection(reordered_with_dup, contract_id=DRY_CONTRACT)

    assert proj_1["fingerprint"] == proj_2["fingerprint"]
    assert len(proj_1["fingerprint"]) == 64
    assert proj_1["records"] == proj_2["records"]
    assert proj_1["summary"] == {
        "scanned": 3,
        "projected": 2,
        "skipped": 1,
        "duplicates": 0,
    }
    assert proj_2["summary"] == {
        "scanned": 4,
        "projected": 2,
        "skipped": 1,
        "duplicates": 1,
    }
    assert set(db._INDEXED_EVENTS.keys()) == before_keys
    assert db._INDEXER_STATE == before_state
    mock_webhook.assert_not_called()


def test_fingerprint_ignores_volatile_db_fields_but_detects_state_change():
    now = datetime.now(timezone.utc)
    later = now + timedelta(hours=3)

    row_v1 = {
        "id": 10,
        "created_at": now,
        "tx_hash": DRY_TX_A.upper(),
        "event_index": 1,
        "event_type": "revoke",
        "proof_id": DRY_PROOF_1,
        "contract_id": DRY_CONTRACT,
        "tx_status": "revoked",
        "metadata": {"b": 2, "a": 1},
    }
    row_v2 = {
        "id": 99999,
        "created_at": later,
        "tx_hash": "0x" + DRY_TX_A,
        "event_index": 1,
        "event_type": "revoke",
        "proof_id": DRY_PROOF_1.upper(),
        "contract_id": DRY_CONTRACT,
        "tx_status": "revoked",
        "metadata": {"a": 1, "b": 2},
    }
    assert compute_projection_fingerprint([row_v1]) == compute_projection_fingerprint([row_v2])

    tampered = dict(row_v1, tx_status="confirmed")
    assert compute_projection_fingerprint([row_v1]) != compute_projection_fingerprint([tampered])


def test_dry_run_in_sync_against_live_projection(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    events = _synthetic_events()
    process_events_batch(events, contract_id=DRY_CONTRACT)

    report = dry_run_index_rebuild(events, contract_id=DRY_CONTRACT)
    assert report["dry_run"] is True
    assert report["in_sync"] is True
    assert report["domain"] == PROJECTION_FINGERPRINT_DOMAIN
    assert report["rebuilt_fingerprint"] == report["live_fingerprint"]
    assert report["summary"]["missing_in_live_count"] == 0
    assert report["summary"]["extra_in_live_count"] == 0
    assert report["summary"]["mismatched_count"] == 0
    assert report["differences"] == {
        "missing_in_live": [],
        "extra_in_live": [],
        "mismatched": [],
    }


def test_dry_run_reports_differences_without_mutating_live_index(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    # Seed live index for a distinct contract so we can verify zero mutation.
    isolated_contract = "CDRYRUNISOLATEDCONTRACTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7Q"
    tx_shared = "84" * 32
    tx_extra = "85" * 32
    tx_missing = "86" * 32

    db.insert_indexed_proof_event(
        event_type="revoke",
        proof_id=DRY_PROOF_1,
        tx_hash=tx_shared,
        event_index=1,
        contract_id=isolated_contract,
        tx_status="confirmed",  # deliberately out-of-date vs rebuilt "revoked"
        metadata={"status": "stale"},
    )
    db.insert_indexed_proof_event(
        event_type="expire",
        proof_id=DRY_PROOF_2,
        tx_hash=tx_extra,
        event_index=2,
        contract_id=isolated_contract,
        tx_status="confirmed",
        metadata={"action": "expired"},
    )
    live_before = db.list_indexed_proof_events_snapshot(contract_id=isolated_contract)

    synthetic_stream = [
        {
            "txHash": tx_shared,
            "id": "0000001300-0000000001",
            "contractId": isolated_contract,
            "topic": ["proof", "revoke", DRY_PROOF_1],
            "value": 2,
        },
        {
            "txHash": tx_missing,
            "id": "0000001301-0000000007",
            "contractId": isolated_contract,
            "topic": ["proof", "revoke", DRY_PROOF_2],
            "value": 1,
        },
    ]

    report = dry_run_index_rebuild(synthetic_stream, contract_id=isolated_contract)
    assert report["in_sync"] is False
    assert report["rebuilt_fingerprint"] != report["live_fingerprint"]
    assert report["summary"]["missing_in_live_count"] == 1
    assert report["summary"]["extra_in_live_count"] == 1
    assert report["summary"]["mismatched_count"] == 1

    missing = report["differences"]["missing_in_live"]
    assert len(missing) == 1
    assert missing[0]["tx_hash"] == tx_missing
    assert missing[0]["event_index"] == 7

    extra = report["differences"]["extra_in_live"]
    assert len(extra) == 1
    assert extra[0]["tx_hash"] == tx_extra
    assert extra[0]["event_index"] == 2

    mismatched = report["differences"]["mismatched"]
    assert len(mismatched) == 1
    assert mismatched[0]["tx_hash"] == tx_shared
    assert set(mismatched[0]["differing_fields"]) == {"tx_status", "metadata"}

    # Live index must remain 100% untouched after dry-run.
    live_after = db.list_indexed_proof_events_snapshot(contract_id=isolated_contract)
    assert live_after == live_before


def test_dry_run_boundary_and_invalid_inputs_rejected():
    with pytest.raises(ValueError, match="events must be a list"):
        reconstruct_temporary_projection("not-a-list")  # type: ignore[arg-type]

    oversized = [{"txHash": DRY_TX_C}] * (INDEXER_MAX_DRY_RUN_EVENTS + 1)
    with pytest.raises(ValueError, match="exceeds maximum dry-run batch size"):
        reconstruct_temporary_projection(oversized)

    with pytest.raises(ValueError, match="event_index"):
        compute_projection_fingerprint([{"tx_hash": DRY_TX_C, "event_index": -1}])


def test_manage_cli_rebuild_dry_run_exit_codes(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("DATABASE_URL", "postgresql://operator:secret@db.internal:5432/harpocrates")
    events_path = tmp_path / "events.json"
    events = _synthetic_events()
    events_path.write_text(json.dumps({"events": events}), encoding="utf-8")

    matching_live = reconstruct_temporary_projection(events, contract_id=DRY_CONTRACT)["records"]
    with mock.patch("chain_indexer.list_indexed_proof_events_snapshot", return_value=matching_live):
        code_ok = manage.main(
            ["--json", "rebuild-dry-run", "--events-file", str(events_path), "--contract-id", DRY_CONTRACT]
        )
    out_ok = json.loads(capsys.readouterr().out)
    assert code_ok == manage.EXIT_OK
    assert out_ok["ok"] is True
    assert out_ok["in_sync"] is True

    with mock.patch("chain_indexer.list_indexed_proof_events_snapshot", return_value=[]):
        code_diff = manage.main(
            ["--json", "rebuild-dry-run", "--events-file", str(events_path), "--contract-id", DRY_CONTRACT]
        )
    out_diff = json.loads(capsys.readouterr().out)
    assert code_diff == manage.EXIT_PROBLEMS
    assert out_diff["ok"] is False
    assert out_diff["summary"]["missing_in_live_count"] == 2
