"""Focused tests for administrative reconciliation batch limit reporting."""

from __future__ import annotations

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
from idempotency import MAX_IDEMPOTENCY_BATCH, cleanup_expired_idempotency_records
from registration_reconcile import (
    MAX_RECONCILE_BATCH,
    parse_reconcile_limit,
    reconcile_pending_registrations,
)


def _row(idx: int) -> dict[str, object]:
    return {
        "id": idx,
        "proof_id": f"{idx:064x}",
        "tx_hash": f"{idx + 1000:064x}",
        "tx_status": "pending",
    }


def test_parse_reconcile_limit_clamps_and_rejects_invalid_values():
    assert parse_reconcile_limit(None) == (MAX_RECONCILE_BATCH, MAX_RECONCILE_BATCH, False)
    assert parse_reconcile_limit(10) == (10, 10, False)
    assert parse_reconcile_limit(120) == (120, MAX_RECONCILE_BATCH, True)

    for invalid in (0, -3, "bad", True, False):
        with pytest.raises(ValueError, match="positive integer"):
            parse_reconcile_limit(invalid)


@mock.patch("registration_reconcile.count_pending_registration_txs", return_value=7)
@mock.patch(
    "registration_reconcile.list_pending_registration_txs",
    return_value=[_row(1), _row(2), _row(3)],
)
@mock.patch(
    "registration_reconcile.reconcile_registration",
    return_value={"status": "confirmed", "updated": True},
)
def test_complete_batch_is_distinguished_from_incomplete_backlog(
    _mock_reconcile, _mock_list, _mock_count
):
    report = reconcile_pending_registrations(limit=3, min_confirmations=1)

    assert report["ok"] is True
    assert report["summary"]["selected"] == 3
    assert report["summary"]["processed"] == 3
    assert report["summary"]["deferred"] == 4
    assert report["batchComplete"] is True
    assert report["backlogComplete"] is False

    batch = report["batch"]
    assert batch["requestedLimit"] == 3
    assert batch["effectiveLimit"] == 3
    assert batch["maxLimit"] == MAX_RECONCILE_BATCH
    assert batch["limitClamped"] is False
    assert batch["totalPending"] == 7
    assert batch["selected"] == 3
    assert batch["processed"] == 3
    assert batch["deferred"] == 4
    assert batch["remainingPending"] == 4
    assert batch["batchComplete"] is True
    assert batch["backlogComplete"] is False
    assert batch["completionState"] == "batch_complete"


@mock.patch("registration_reconcile.count_pending_registration_txs", return_value=2)
@mock.patch(
    "registration_reconcile.list_pending_registration_txs",
    return_value=[_row(1), _row(2)],
)
@mock.patch(
    "registration_reconcile.reconcile_registration",
    side_effect=[
        {"status": "confirmed", "updated": True},
        {"status": "failed", "updated": True},
    ],
)
def test_complete_backlog_when_no_deferred_or_unresolved_rows_remain(
    _mock_reconcile, _mock_list, _mock_count
):
    report = reconcile_pending_registrations(limit=2, min_confirmations=1)

    assert report["summary"]["selected"] == 2
    assert report["summary"]["processed"] == 2
    assert report["summary"]["deferred"] == 0
    assert report["batchComplete"] is True
    assert report["backlogComplete"] is True
    assert report["batch"]["remainingPending"] == 0
    assert report["batch"]["completionState"] == "backlog_complete"


@mock.patch("registration_reconcile.count_pending_registration_txs", return_value=2)
@mock.patch(
    "registration_reconcile.list_pending_registration_txs",
    return_value=[_row(1), _row(2)],
)
@mock.patch(
    "registration_reconcile.reconcile_registration",
    side_effect=[
        {"status": "confirmed", "updated": True},
        {"status": "pending", "reason": "awaiting_confirmations", "updated": False},
    ],
)
def test_batch_complete_but_backlog_incomplete_when_row_awaits_confirmations(
    _mock_reconcile, _mock_list, _mock_count
):
    report = reconcile_pending_registrations(limit=10, min_confirmations=3)

    assert report["summary"]["selected"] == 2
    assert report["summary"]["processed"] == 2
    assert report["summary"]["deferred"] == 0
    assert report["summary"]["pending"] == 1
    assert report["batchComplete"] is True
    assert report["backlogComplete"] is False
    assert report["batch"]["remainingPending"] == 1
    assert report["batch"]["completionState"] == "batch_complete"


@mock.patch("registration_reconcile.count_pending_registration_txs", return_value=5)
@mock.patch(
    "registration_reconcile.list_pending_registration_txs",
    return_value=[_row(1), _row(2), _row(3)],
)
@mock.patch(
    "registration_reconcile.reconcile_registration",
    return_value={"status": "confirmed", "updated": True},
)
def test_partial_batch_tracks_unprocessed_and_unselected_as_deferred(
    _mock_reconcile, _mock_list, _mock_count
):
    report = reconcile_pending_registrations(limit=3, min_confirmations=1, max_processed=2)

    assert report["summary"]["selected"] == 3
    assert report["summary"]["processed"] == 2
    assert report["summary"]["deferred"] == 3  # 2 unselected + 1 unprocessed selected
    assert report["batchComplete"] is False
    assert report["backlogComplete"] is False
    assert report["batch"]["completionState"] == "batch_incomplete"


def test_http_reconcile_endpoint_preserves_requested_limit_when_clamped():
    client = app.test_client()
    rows = [_row(i) for i in range(1, 51)]
    with mock.patch(
        "registration_reconcile.count_pending_registration_txs", return_value=65
    ), mock.patch(
        "registration_reconcile.list_pending_registration_txs", return_value=rows
    ), mock.patch(
        "registration_reconcile.reconcile_registration",
        return_value={"status": "confirmed", "updated": True},
    ):
        resp = client.post("/api/proofs/reconcile", json={"limit": 200, "minConfirmations": 2})

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    assert body["batch"]["requestedLimit"] == 200
    assert body["batch"]["effectiveLimit"] == 50
    assert body["batch"]["limitClamped"] is True
    assert body["batch"]["selected"] == 50
    assert body["batch"]["processed"] == 50
    assert body["batch"]["deferred"] == 15
    assert body["batchComplete"] is True
    assert body["backlogComplete"] is False

    bad_resp = client.post("/api/proofs/reconcile", json={"limit": 0})
    assert bad_resp.status_code == 400


def test_idempotency_cleanup_reports_matching_batch_limits():
    no_db = cleanup_expired_idempotency_records(limit=99)
    assert no_db["selected"] == 0
    assert no_db["processed"] == 0
    assert no_db["deferred"] == 0
    assert no_db["requestedLimit"] == 99
    assert no_db["effectiveLimit"] == MAX_IDEMPOTENCY_BATCH
    assert no_db["limitClamped"] is True
    assert no_db["batchComplete"] is True
    assert no_db["backlogComplete"] is True

    with pytest.raises(ValueError, match="positive integer"):
        cleanup_expired_idempotency_records(limit=0)
