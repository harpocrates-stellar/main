"""Focused tests keeping RPC provider outages distinct from missing transactions."""

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
import idempotency as idem_mod
from registration_reconcile import (
    OPERATIONAL_PROVIDER_UNAVAILABLE,
    OPERATIONAL_TX_NOT_FOUND,
    OPERATIONAL_VALIDATION_ERROR,
    ProviderOutageError,
    process_verify_tx_job,
    reconcile_pending_registrations,
    reconcile_registration,
)
from tx_verification import verify_transaction


VALID_TX = "a" * 64


def test_empty_horizon_urls_reports_provider_outage_not_missing(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HORIZON_URLS", " , ")
    res = verify_transaction(VALID_TX)
    assert res.status == "error"
    assert res.reason == "horizon_dependency_failure"


@mock.patch(
    "tx_verification.horizon_urls",
    return_value=("https://primary-horizon.test", "https://backup-horizon.test"),
)
def test_partial_failover_404_plus_503_is_provider_outage_not_missing(_mock_urls):
    # Primary has not indexed tx yet (404), backup is down (503) -> must preserve pending!
    with mock.patch(
        "tx_verification._fetch_json",
        side_effect=[(404, None), (503, None)],
    ):
        res = verify_transaction(VALID_TX)

    assert res.status == "error"
    assert res.reason == "horizon_dependency_failure"


@mock.patch("registration_reconcile.update_tx_status")
@mock.patch("tx_verification.horizon_urls", return_value=("https://horizon.test",))
def test_reconcile_provider_outage_preserves_pending_intent_and_returns_retryable_code(
    _mock_urls, mock_update
):
    with mock.patch("tx_verification._fetch_json", side_effect=TimeoutError("rpc timed out")):
        outage = reconcile_registration(VALID_TX, previous_status="pending", proof_id="1" * 64)

    assert outage["status"] == "error"
    assert outage["intentStatus"] == "pending"
    assert outage["operationalCode"] == OPERATIONAL_PROVIDER_UNAVAILABLE
    assert outage["retryable"] is True
    assert outage["outcomeCategory"] == "provider_outage"
    assert outage["updated"] is False
    assert outage["operationalCode"] != OPERATIONAL_VALIDATION_ERROR
    mock_update.assert_not_called()


@mock.patch("registration_reconcile.update_tx_status", return_value=True)
@mock.patch("tx_verification.horizon_urls", return_value=("https://horizon.test",))
def test_reconcile_missing_transaction_is_non_retryable_and_distinct_from_outage(
    _mock_urls, mock_update
):
    with mock.patch("tx_verification._fetch_json", return_value=(404, None)):
        missing = reconcile_registration(VALID_TX, previous_status="pending", proof_id="1" * 64)

    assert missing["status"] == "missing"
    assert missing["intentStatus"] == "missing"
    assert missing["operationalCode"] == OPERATIONAL_TX_NOT_FOUND
    assert missing["retryable"] is False
    assert missing["outcomeCategory"] == "missing_transaction"
    assert missing["updated"] is True
    mock_update.assert_called_once_with(VALID_TX, "missing", force=False)


def test_process_verify_tx_job_raises_retryable_provider_outage_error():
    with mock.patch(
        "registration_reconcile.reconcile_registration",
        return_value={
            "status": "error",
            "reason": "horizon_dependency_failure",
            "operationalCode": OPERATIONAL_PROVIDER_UNAVAILABLE,
            "retryable": True,
        },
    ):
        with pytest.raises(ProviderOutageError) as exc_info:
            process_verify_tx_job({"tx_hash": VALID_TX})
    assert exc_info.value.operational_code == OPERATIONAL_PROVIDER_UNAVAILABLE
    assert exc_info.value.retryable is True


def test_http_reconcile_returns_503_retryable_operational_code_on_outage():
    client = app.test_client()
    with mock.patch("tx_verification.horizon_urls", return_value=("https://horizon.test",)), mock.patch(
        "tx_verification._fetch_json", return_value=(503, None)
    ), mock.patch("registration_reconcile.update_tx_status") as mock_update:
        resp = client.post("/api/proofs/reconcile", json={"txHash": VALID_TX})

    assert resp.status_code == 503
    assert resp.headers.get("Retry-After") == "5"
    body = resp.get_json()
    assert body["ok"] is False
    assert body["code"] == "DEPENDENCY_UNAVAILABLE"
    assert body["operationalCode"] == OPERATIONAL_PROVIDER_UNAVAILABLE
    assert body["retryable"] is True
    assert body["intentStatus"] == "pending"
    mock_update.assert_not_called()

    # Batch summary reports providerOutages and retryable=True without mutating DB.
    with mock.patch(
        "registration_reconcile.list_pending_registration_txs",
        return_value=[{"id": 1, "proof_id": "2" * 64, "tx_hash": VALID_TX, "tx_status": "pending"}],
    ), mock.patch(
        "tx_verification.horizon_urls", return_value=("https://horizon.test",)
    ), mock.patch("tx_verification._fetch_json", return_value=(502, None)):
        batch_resp = client.post("/api/proofs/reconcile", json={"limit": 5})

    assert batch_resp.status_code == 200
    batch_body = batch_resp.get_json()
    assert batch_body["providerOutages"] == 1
    assert batch_body["retryable"] is True
    assert batch_body["operationalCode"] == OPERATIONAL_PROVIDER_UNAVAILABLE


def test_idempotent_decorator_clears_pending_lock_on_retryable_provider_outage():
    @idem_mod.idempotent("register")
    def _flaky_view():
        raise ProviderOutageError("horizon_dependency_failure")

    with mock.patch.object(idem_mod, "_db_available", return_value=True), mock.patch.object(
        idem_mod, "_canonical_digest", return_value="d" * 64
    ), mock.patch.object(
        idem_mod, "get_idempotency_record", return_value=None
    ), mock.patch.object(
        idem_mod, "create_idempotency_record", return_value=(99, "PENDING")
    ), mock.patch.object(
        idem_mod, "clear_idempotency_record"
    ) as mock_clear, mock.patch.object(
        idem_mod, "store_error"
    ) as mock_store_error:
        with pytest.raises(ProviderOutageError):
            _flaky_view()

    mock_clear.assert_called_once_with(99)
    mock_store_error.assert_not_called()
