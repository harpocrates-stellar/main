"""Focused tests for read-only operator registration repair previews."""

from __future__ import annotations

import copy
import json
import os
import sys
from unittest import mock

import pytest

_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_BACKEND_DIR)
for _p in (_BACKEND_DIR, _REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from app import app
import idempotency as idem_mod
from registration_reconcile import (
    compute_registration_row_revision,
    preview_registration_repair,
    reconcile_registration,
)
from tx_verification import TxVerificationResult


VALID_TX = "a" * 64


@mock.patch("registration_reconcile.update_tx_status")
@mock.patch(
    "registration_reconcile.verify_transaction",
    return_value=TxVerificationResult(
        status="confirmed",
        reason="confirmed",
        ledger=4500,
        latest_ledger=4503,
        confirmations=4,
        successful=True,
        source="https://horizon-testnet.stellar.org",
    ),
)
def test_repair_preview_shows_proposed_updates_chain_evidence_and_expected_revision(
    _mock_verify, mock_update
):
    pending_row = {
        "id": 17,
        "proof_id": "1" * 64,
        "tier": "source",
        "tx_hash": VALID_TX,
        "tx_status": "pending",
        "contract_id": None,
        "idempotency_key": "2" * 64,
    }
    expected_rev = compute_registration_row_revision(pending_row)

    report = preview_registration_repair(
        VALID_TX,
        min_confirmations=2,
        rows=[pending_row],
    )

    assert report["ok"] is True
    assert report["preview"] is True
    assert report["writesApplied"] is False
    assert report["contradictory"] is False
    assert report["chainEvidence"]["status"] == "confirmed"
    assert report["chainEvidence"]["ledger"] == 4500
    assert report["chainEvidence"]["confirmations"] == 4

    assert len(report["proposedUpdates"]) == 1
    upd = report["proposedUpdates"][0]
    assert upd["table"] == "proof_events"
    assert upd["eventId"] == 17
    assert upd["expectedRevision"] == expected_rev
    assert upd["changes"] == {"tx_status": {"from": "pending", "to": "confirmed"}}
    assert upd["requiresForce"] is False
    assert upd["contradictory"] is False
    mock_update.assert_not_called()


@mock.patch("registration_reconcile.update_tx_status")
@mock.patch(
    "registration_reconcile.verify_transaction",
    return_value=TxVerificationResult(
        status="failed",
        reason="tx_unsuccessful",
        ledger=4600,
        latest_ledger=4610,
        successful=False,
        source="https://horizon-testnet.stellar.org",
    ),
)
def test_previewing_contradictory_record_applies_zero_writes(
    _mock_verify, mock_update
):
    contradictory_row = {
        "id": 23,
        "proof_id": "3" * 64,
        "tier": "seal",
        "tx_hash": VALID_TX,
        "tx_status": "confirmed",  # Contradicts on-chain failed status!
        "contract_id": None,
        "idempotency_key": "4" * 64,
    }
    original_snapshot = copy.deepcopy(contradictory_row)

    report = preview_registration_repair(
        VALID_TX,
        min_confirmations=1,
        rows=[contradictory_row],
    )

    assert report["writesApplied"] is False
    assert report["contradictory"] is True
    assert "terminal_status_mismatch:confirmed->failed" in report["contradictionReasons"]
    assert len(report["proposedUpdates"]) == 1
    upd = report["proposedUpdates"][0]
    assert upd["requiresForce"] is True
    assert upd["contradictory"] is True
    assert upd["changes"] == {"tx_status": {"from": "confirmed", "to": "failed"}}
    assert contradictory_row == original_snapshot
    mock_update.assert_not_called()


@mock.patch("registration_reconcile.update_tx_status")
@mock.patch(
    "registration_reconcile.verify_transaction",
    return_value=TxVerificationResult(status="confirmed", reason="confirmed", ledger=99, confirmations=2),
)
def test_reconcile_registration_preview_mode_performs_no_write(_mock_verify, mock_update):
    res = reconcile_registration(
        VALID_TX,
        previous_status="missing",
        min_confirmations=1,
        force=True,
        preview=True,
    )
    assert res["preview"] is True
    assert res["writesApplied"] is False
    assert res["updated"] is False
    assert res["status"] == "confirmed"
    mock_update.assert_not_called()


def test_idempotency_repair_preview_is_strictly_read_only():
    stored = {
        "id": 88,
        "request_digest": "d" * 64,
        "request_type": "register",
        "status": "PENDING",
    }
    with mock.patch.object(idem_mod, "_db_available", return_value=True), mock.patch.object(
        idem_mod, "get_idempotency_record", return_value=stored
    ), mock.patch.object(idem_mod, "clear_idempotency_record") as mock_clear:
        preview = idem_mod.preview_idempotency_repair("d" * 64, "register")

    assert preview["found"] is True
    assert preview["recordId"] == 88
    assert preview["proposedAction"] == "clear_pending"
    assert preview["writesApplied"] is False
    assert len(preview["expectedRevision"]) == 64
    mock_clear.assert_not_called()


def test_http_repair_preview_endpoints_apply_no_writes_and_validate_inputs():
    client = app.test_client()
    contradictory_rows = [
        {
            "id": 31,
            "proof_id": "5" * 64,
            "tier": "silent",
            "tx_hash": VALID_TX,
            "tx_status": "missing",
            "contract_id": None,
            "idempotency_key": "6" * 64,
        }
    ]
    with mock.patch(
        "registration_reconcile.find_registration_events_by_tx_hash",
        return_value=contradictory_rows,
    ), mock.patch(
        "registration_reconcile.verify_transaction",
        return_value=TxVerificationResult(
            status="confirmed",
            reason="confirmed",
            ledger=7000,
            latest_ledger=7005,
            confirmations=6,
            successful=True,
            source="https://horizon.test",
        ),
    ), mock.patch("registration_reconcile.update_tx_status") as mock_update:
        resp = client.post(
            "/api/proofs/reconcile/preview",
            json={"txHash": VALID_TX, "minConfirmations": 3},
        )
        resp_inline = client.post(
            "/api/proofs/reconcile",
            json={"txHash": VALID_TX, "minConfirmations": 3, "preview": True},
        )

    assert resp.status_code == 200
    assert resp_inline.status_code == 200
    body = resp.get_json()
    assert body["preview"] is True
    assert body["writesApplied"] is False
    assert body["contradictory"] is True
    assert body["proposedUpdates"][0]["requiresForce"] is True
    assert body["proposedUpdates"][0]["changes"]["tx_status"] == {
        "from": "missing",
        "to": "confirmed",
    }
    mock_update.assert_not_called()

    bad = client.post("/api/proofs/reconcile/preview", json={"txHash": "invalid"})
    assert bad.status_code == 400
    raw = json.dumps(body)
    assert "file_name" not in raw
    assert "source_address" not in raw
