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


# --- Proof registration intent binding tests ---

SAMPLE_STATEMENT = {
    "video_hash": "1" * 64,
    "metadata_hash": "2" * 64,
    "proof_id": "3" * 64,
    "tier": "seal",
    "source_address": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    "contract_id": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
}


def test_canonical_intent_digest_deterministic_and_normalized():
    from idempotency import canonical_evidence_statement, compute_intent_digest

    camel = {
        "videoHash": "0x" + "1" * 64,
        "metadataHash": "2" * 64,
        "proofId": "3" * 64,
        "tier": "  SEAL ",
        "sourceAddress": SAMPLE_STATEMENT["source_address"],
        "contractId": SAMPLE_STATEMENT["contract_id"],
    }
    d1 = compute_intent_digest(SAMPLE_STATEMENT)
    d2 = compute_intent_digest(camel)
    assert d1 == d2
    assert len(d1) == 64

    # Altering any canonical field changes the digest
    altered = dict(SAMPLE_STATEMENT, tier="source")
    assert compute_intent_digest(altered) != d1
    canonical = canonical_evidence_statement(**SAMPLE_STATEMENT)
    assert canonical["tier"] == "seal"


def test_reconcile_persists_intent_before_verify_and_confirms_matching_statement():
    from idempotency import compute_intent_digest

    expected_digest = compute_intent_digest(SAMPLE_STATEMENT)
    call_order: list[str] = []

    def fake_persist(tx_hash, digest):
        call_order.append("persist")
        assert tx_hash == VALID_TX
        assert digest == expected_digest
        return digest

    def fake_verify(tx_hash, min_confirmations=1):
        call_order.append("verify")
        return TxVerificationResult(
            status="confirmed",
            confirmations=2,
            ledger=42,
            reason="confirmed",
            registered_statement=dict(SAMPLE_STATEMENT),
        )

    with mock.patch("registration_reconcile.persist_registration_intent", side_effect=fake_persist), \
         mock.patch("registration_reconcile.verify_transaction", side_effect=fake_verify), \
         mock.patch("registration_reconcile.update_tx_status", return_value=True) as mock_update:
        result = reconcile_registration(
            VALID_TX,
            previous_status="pending",
            expected_statement=SAMPLE_STATEMENT,
        )

    assert call_order == ["persist", "verify"]
    assert result["status"] == "confirmed"
    assert result["intentDigest"] == expected_digest
    assert result["intentVerified"] is True
    assert result["updated"] is True
    mock_update.assert_called_once_with(VALID_TX, "confirmed", force=False)


def test_reconcile_rejects_mismatched_registered_statement():
    from idempotency import compute_intent_digest

    expected_digest = compute_intent_digest(SAMPLE_STATEMENT)
    tampered_statement = dict(SAMPLE_STATEMENT, video_hash="f" * 64)

    with mock.patch("registration_reconcile.persist_registration_intent", return_value=expected_digest) as mock_persist, \
         mock.patch(
             "registration_reconcile.verify_transaction",
             return_value=TxVerificationResult(
                 status="confirmed",
                 confirmations=3,
                 ledger=50,
                 reason="confirmed",
                 registered_statement=tampered_statement,
             ),
         ), \
         mock.patch("registration_reconcile.update_tx_status", return_value=True) as mock_update:
        result = reconcile_registration(
            VALID_TX,
            previous_status="pending",
            expected_statement=SAMPLE_STATEMENT,
        )

    mock_persist.assert_called_once_with(VALID_TX, expected_digest)
    assert result["status"] == "failed"
    assert result["reason"] == "registered_statement_mismatch"
    assert result["intentVerified"] is False
    assert result["updated"] is True
    mock_update.assert_called_once_with(VALID_TX, "failed", force=False)


def test_reconcile_fails_closed_when_bound_intent_has_no_registered_statement():
    from idempotency import compute_intent_digest

    expected_digest = compute_intent_digest(SAMPLE_STATEMENT)

    with mock.patch("registration_reconcile.persist_registration_intent", return_value=expected_digest), \
         mock.patch(
             "registration_reconcile.verify_transaction",
             return_value=TxVerificationResult(
                 status="confirmed",
                 confirmations=3,
                 ledger=50,
                 reason="confirmed",
             ),
         ), \
         mock.patch("registration_reconcile.update_tx_status", return_value=True) as mock_update:
        result = reconcile_registration(
            VALID_TX,
            previous_status="pending",
            intent_digest=expected_digest,
        )

    assert result["status"] == "failed"
    assert result["reason"] == "registered_statement_missing"
    assert result["intentVerified"] is False
    mock_update.assert_called_once_with(VALID_TX, "failed", force=False)


def test_reconcile_rejects_on_persisted_intent_conflict_before_verify():
    from idempotency import IntentConflictError, compute_intent_digest

    expected_digest = compute_intent_digest(SAMPLE_STATEMENT)

    with mock.patch(
        "registration_reconcile.persist_registration_intent",
        side_effect=IntentConflictError("conflict"),
    ), mock.patch("registration_reconcile.verify_transaction") as mock_verify:
        result = reconcile_registration(
            VALID_TX,
            previous_status="pending",
            expected_statement=SAMPLE_STATEMENT,
        )

    assert result["status"] == "failed"
    assert result["reason"] == "intent_digest_conflict"
    assert result["intentDigest"] == expected_digest
    assert result["intentVerified"] is False
    mock_verify.assert_not_called()


def test_verify_transaction_extracts_horizon_hash_memo():
    import base64
    from idempotency import compute_intent_digest

    digest = compute_intent_digest(SAMPLE_STATEMENT)
    memo_b64 = base64.b64encode(bytes.fromhex(digest)).decode("ascii")

    with mock.patch("tx_verification._latest_ledger", return_value=200), \
         mock.patch(
             "tx_verification._fetch_json",
             return_value=(
                 200,
                 {
                     "successful": True,
                     "ledger": 198,
                     "memo_type": "hash",
                     "memo": memo_b64,
                 },
             ),
         ):
        result = verify_transaction(VALID_TX, min_confirmations=1)

    assert result.status == "confirmed"
    assert result.registered_intent_digest == digest


def test_process_verify_tx_job_forwards_intent_digest():
    from idempotency import compute_intent_digest

    digest = compute_intent_digest(SAMPLE_STATEMENT)
    with mock.patch(
        "registration_reconcile.reconcile_registration",
        return_value={"status": "confirmed", "intentDigest": digest, "intentVerified": True, "updated": True},
    ) as mock_reconcile:
        out = process_verify_tx_job({"tx_hash": VALID_TX, "proof_id": "3" * 64, "intent_digest": digest})

    assert out["status"] == "confirmed"
    mock_reconcile.assert_called_once_with(
        VALID_TX,
        previous_status="pending",
        proof_id="3" * 64,
        min_confirmations=None,
        intent_digest=digest,
    )
