"""Focused tests for on-chain registration confirmation reconciliation."""

from __future__ import annotations

from unittest import mock

import pytest

from registration_reconcile import (
    clamp_reconcile_limit,
    process_verify_tx_job,
    reconcile_pending_registrations,
    reconcile_registration,
)
from tx_verification import TxVerificationResult, normalize_tx_hash, verify_transaction


VALID_TX = "a" * 64


def test_normalize_tx_hash_accepts_hex_and_0x_prefix():
    assert normalize_tx_hash(VALID_TX) == VALID_TX
    assert normalize_tx_hash("0x" + "B" * 64) == "b" * 64


def test_normalize_tx_hash_rejects_malformed():
    with pytest.raises(ValueError):
        normalize_tx_hash("not-a-hash")
    with pytest.raises(ValueError):
        normalize_tx_hash(123)


def test_clamp_reconcile_limit_bounds():
    assert clamp_reconcile_limit(1) == 1
    assert clamp_reconcile_limit(999) == 50
    with pytest.raises(ValueError):
        clamp_reconcile_limit(0)
    with pytest.raises(ValueError):
        clamp_reconcile_limit("nope")


@mock.patch("tx_verification._latest_ledger", return_value=200)
@mock.patch("tx_verification._fetch_json")
def test_verify_transaction_confirmed_with_depth(mock_fetch, _mock_latest):
    mock_fetch.return_value = (200, {"successful": True, "ledger": 198})
    result = verify_transaction(VALID_TX, min_confirmations=2)
    assert result.status == "confirmed"
    assert result.confirmations == 3


@mock.patch("tx_verification._latest_ledger", return_value=198)
@mock.patch("tx_verification._fetch_json")
def test_verify_transaction_awaits_confirmations(mock_fetch, _mock_latest):
    mock_fetch.return_value = (200, {"successful": True, "ledger": 198})
    result = verify_transaction(VALID_TX, min_confirmations=5)
    assert result.status == "pending"
    assert result.reason == "awaiting_confirmations"
    assert result.confirmations == 1


@mock.patch("tx_verification._fetch_json")
def test_verify_transaction_failed_unsuccessful(mock_fetch):
    mock_fetch.return_value = (200, {"successful": False, "ledger": 10})
    result = verify_transaction(VALID_TX)
    assert result.status == "failed"
    assert result.reason == "tx_unsuccessful"


@mock.patch("tx_verification.horizon_urls", return_value=["https://horizon.test"])
@mock.patch("tx_verification._fetch_json", return_value=(404, None))
def test_verify_transaction_missing(mock_fetch, _urls):
    result = verify_transaction(VALID_TX)
    assert result.status == "missing"


@mock.patch("tx_verification.horizon_urls", return_value=["https://horizon.test"])
@mock.patch("tx_verification._fetch_json", side_effect=RuntimeError("boom"))
def test_verify_transaction_dependency_error(mock_fetch, _urls):
    result = verify_transaction(VALID_TX)
    assert result.status == "error"
    assert result.reason == "horizon_dependency_failure"


@mock.patch("registration_reconcile.update_tx_status", return_value=True)
@mock.patch(
    "registration_reconcile.verify_transaction",
    return_value=TxVerificationResult(
        status="confirmed",
        confirmations=3,
        ledger=10,
        reason="confirmed",
    ),
)
def test_reconcile_registration_updates_terminal(mock_verify, mock_update):
    result = reconcile_registration(VALID_TX, previous_status="pending", min_confirmations=1)
    assert result["status"] == "confirmed"
    assert result["updated"] is True
    mock_update.assert_called_once_with(VALID_TX, "confirmed", force=False)


@mock.patch("registration_reconcile.update_tx_status")
@mock.patch(
    "registration_reconcile.verify_transaction",
    return_value=TxVerificationResult(status="confirmed", reason="confirmed"),
)
def test_reconcile_skips_already_terminal(mock_verify, mock_update):
    result = reconcile_registration(VALID_TX, previous_status="confirmed")
    assert result["status"] == "confirmed"
    assert result["updated"] is False
    assert result["reason"] == "already_terminal"
    mock_verify.assert_not_called()
    mock_update.assert_not_called()


def test_reconcile_malformed_hash_is_stable():
    result = reconcile_registration("bad")
    assert result["status"] == "failed"
    assert result["error"] == "malformed_tx_hash"
    assert result["updated"] is False


@mock.patch(
    "registration_reconcile.list_pending_registration_txs",
    return_value=[
        {"id": 1, "proof_id": "p" * 64, "tx_hash": VALID_TX, "tx_status": "pending"},
        {"id": 2, "proof_id": "q" * 64, "tx_hash": "b" * 64, "tx_status": "pending"},
    ],
)
@mock.patch(
    "registration_reconcile.reconcile_registration",
    side_effect=[
        {"status": "confirmed", "updated": True},
        {"status": "missing", "updated": True},
    ],
)
def test_reconcile_pending_batch_summary(mock_one, mock_list):
    report = reconcile_pending_registrations(limit=10, min_confirmations=1)
    assert report["ok"] is True
    assert report["summary"]["scanned"] == 2
    assert report["summary"]["confirmed"] == 1
    assert report["summary"]["missing"] == 1
    assert report["summary"]["updated"] == 2


@mock.patch(
    "registration_reconcile.reconcile_registration",
    return_value={"status": "pending", "reason": "awaiting_confirmations", "updated": False},
)
def test_process_verify_tx_job_success(mock_reconcile):
    out = process_verify_tx_job({"tx_hash": VALID_TX, "proof_id": "p" * 64})
    assert out["status"] == "pending"
    mock_reconcile.assert_called_once()


@mock.patch(
    "registration_reconcile.reconcile_registration",
    return_value={"status": "error", "reason": "horizon_dependency_failure"},
)
def test_process_verify_tx_job_raises_on_dependency_failure(mock_reconcile):
    with pytest.raises(RuntimeError):
        process_verify_tx_job({"txHash": VALID_TX})
