"""Focused tests for rejecting obsolete registration attempt callbacks."""

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
    apply_registration_callback,
    begin_registration_attempt,
    get_registration_attempt_state,
    parse_attempt_generation,
    process_verify_tx_job,
    reconcile_registration,
    reset_registration_attempts_for_tests,
)
from tx_verification import TxVerificationResult


VALID_TX = "a" * 64


@pytest.fixture(autouse=True)
def _reset_trackers():
    reset_registration_attempts_for_tests()
    idem_mod.reset_idempotency_attempts_for_tests()
    yield
    reset_registration_attempts_for_tests()
    idem_mod.reset_idempotency_attempts_for_tests()


def test_parse_attempt_generation_rejects_invalid_inputs():
    assert parse_attempt_generation(1) == 1
    assert parse_attempt_generation("4") == 4
    for bad in (None, 0, -1, True, False, 1.5, "nope"):
        with pytest.raises(ValueError, match="attemptGeneration"):
            parse_attempt_generation(bad)


@mock.patch("registration_reconcile.update_tx_status", return_value=True)
def test_obsolete_callback_is_rejected_and_preserves_newer_attempt_state(mock_update):
    gen1 = begin_registration_attempt(VALID_TX, proof_id="1" * 64)
    gen2 = begin_registration_attempt(VALID_TX, proof_id="1" * 64)
    assert (gen1, gen2) == (1, 2)

    # Newer attempt (gen 2) confirms the transaction at ledger 555.
    accepted = apply_registration_callback(
        tx_hash=VALID_TX,
        attempt_generation=gen2,
        status="confirmed",
        proof_id="1" * 64,
        ledger=555,
        confirmations=4,
        min_confirmations=2,
    )
    assert accepted["accepted"] is True
    assert accepted["obsoleteAttempt"] is False
    assert accepted["status"] == "confirmed"
    assert accepted["updated"] is True
    mock_update.assert_called_once_with(VALID_TX, "confirmed", force=False)

    # Stale attempt (gen 1) reports "missing" late (even with force=True) -> rejected!
    rejected = apply_registration_callback(
        tx_hash=VALID_TX,
        attempt_generation=gen1,
        status="missing",
        proof_id="1" * 64,
        force=True,
    )
    assert rejected["accepted"] is False
    assert rejected["obsoleteAttempt"] is True
    assert rejected["updated"] is False
    assert rejected["reason"] == "obsolete_attempt_generation"
    assert rejected["attemptGeneration"] == 1
    assert rejected["currentAttemptGeneration"] == 2
    assert rejected["status"] == "confirmed"
    assert rejected["ledger"] == 555
    # No second DB write occurred!
    assert mock_update.call_count == 1

    state = get_registration_attempt_state(VALID_TX)
    assert state is not None
    assert state["generation"] == 2
    assert state["status"] == "confirmed"
    assert state["ledger"] == 555


@mock.patch("registration_reconcile.update_tx_status", return_value=True)
def test_midflight_superseded_reconcile_attempt_does_not_overwrite_newer_attempt(mock_update):
    gen1 = begin_registration_attempt(VALID_TX, proof_id="2" * 64)
    assert gen1 == 1

    def _slow_verify_that_gets_superseded(_tx: str, *, min_confirmations: int = 1):
        # While attempt 1 is querying Horizon, attempt 2 starts and commits confirmed state!
        gen2 = begin_registration_attempt(VALID_TX, proof_id="2" * 64)
        apply_registration_callback(
            tx_hash=VALID_TX,
            attempt_generation=gen2,
            status="confirmed",
            ledger=900,
            confirmations=3,
            min_confirmations=min_confirmations,
        )
        return TxVerificationResult(status="missing", reason="not_found_on_horizon")

    with mock.patch("registration_reconcile.verify_transaction", side_effect=_slow_verify_that_gets_superseded):
        stale_res = reconcile_registration(
            VALID_TX,
            previous_status="pending",
            proof_id="2" * 64,
            min_confirmations=1,
            attempt_generation=gen1,
            force=True,
        )

    assert stale_res["obsoleteAttempt"] is True
    assert stale_res["accepted"] is False
    assert stale_res["updated"] is False
    assert stale_res["status"] == "confirmed"
    assert stale_res["currentAttemptGeneration"] == 2
    # Only attempt 2's confirmed update ran; attempt 1's "missing" write was blocked.
    mock_update.assert_called_once_with(VALID_TX, "confirmed", force=False)


@mock.patch("registration_reconcile.update_tx_status", return_value=True)
def test_callback_below_min_confirmations_fails_closed_to_pending(mock_update):
    res = apply_registration_callback(
        tx_hash="b" * 64,
        attempt_generation=1,
        status="confirmed",
        ledger=100,
        confirmations=1,
        min_confirmations=3,
    )
    assert res["accepted"] is True
    assert res["status"] == "pending"
    assert res["reason"] == "awaiting_confirmations"
    assert res["updated"] is False
    mock_update.assert_not_called()


def test_process_verify_tx_job_rejects_obsolete_attempt_without_error():
    begin_registration_attempt(VALID_TX)
    begin_registration_attempt(VALID_TX)  # current == 2
    with mock.patch("registration_reconcile.verify_transaction") as mock_verify:
        out = process_verify_tx_job(
            {"tx_hash": VALID_TX, "proof_id": "3" * 64, "attempt_generation": 1}
        )
    assert out["obsoleteAttempt"] is True
    assert out["updated"] is False
    mock_verify.assert_not_called()


def test_http_callback_endpoint_returns_409_for_obsolete_attempt():
    client = app.test_client()
    with mock.patch("registration_reconcile.update_tx_status", return_value=True):
        r2 = client.post(
            "/api/proofs/reconcile/callback",
            json={
                "txHash": VALID_TX,
                "attemptGeneration": 3,
                "status": "confirmed",
                "ledger": 777,
                "confirmations": 2,
                "minConfirmations": 1,
            },
        )
        assert r2.status_code == 200
        assert r2.get_json()["ok"] is True

        r1 = client.post(
            "/api/proofs/reconcile/callback",
            json={
                "txHash": VALID_TX,
                "attemptGeneration": 2,
                "status": "failed",
            },
        )
        assert r1.status_code == 409
        body = r1.get_json()
        assert body["ok"] is False
        assert body["error"] == "obsolete_attempt_generation"
        assert body["result"]["status"] == "confirmed"
        assert body["result"]["currentAttemptGeneration"] == 3

        bad = client.post(
            "/api/proofs/reconcile/callback",
            json={"txHash": VALID_TX, "attemptGeneration": 0, "status": "confirmed"},
        )
        assert bad.status_code == 400


def test_idempotency_store_response_and_error_reject_obsolete_attempts():
    g1 = idem_mod.begin_idempotency_attempt(42)
    g2 = idem_mod.begin_idempotency_attempt(42)
    assert (g1, g2) == (1, 2)

    with mock.patch.object(idem_mod, "get_connection") as mock_conn:
        assert idem_mod.store_response(42, {"ok": True}, attempt_generation=g1) is False
        assert idem_mod.store_error(42, {"error": "stale"}, attempt_generation=g1) is False
        mock_conn.assert_not_called()
