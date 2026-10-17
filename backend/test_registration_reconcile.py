"""Focused tests for on-chain registration confirmation reconciliation."""

from __future__ import annotations

import base64
from unittest import mock

import pytest

from registration_reconcile import (
    clamp_reconcile_limit,
    process_verify_tx_job,
    reconcile_pending_registrations,
    reconcile_registration,
)
from strkey import make_strkey
from tx_verification import (
    RegistrationBinding,
    TxVerificationResult,
    horizon_urls,
    normalize_tx_hash,
    verify_transaction,
)


VALID_TX = "a" * 64
PROOF_ID = "11" * 32
REGISTRY_RAW = bytes(range(32))
REGISTRY_ID = make_strkey(2 << 3, REGISTRY_RAW)


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
    result = reconcile_registration(
        VALID_TX,
        previous_status="pending",
        min_confirmations=1,
        proof_id=PROOF_ID,
        contract_id=REGISTRY_ID,
    )
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



# ---------------------------------------------------------------------------
# Network, contract and proof binding
# ---------------------------------------------------------------------------

SCV_ADDRESS_CONTRACT = bytes([0, 0, 0, 18, 0, 0, 0, 1])
SCV_BYTES_32 = bytes([0, 0, 0, 13, 0, 0, 0, 32])


def _scval_address(raw: bytes) -> str:
    return base64.b64encode(SCV_ADDRESS_CONTRACT + raw).decode()


def _scval_bytes32(raw: bytes) -> str:
    return base64.b64encode(SCV_BYTES_32 + raw).decode()


def _horizon(operations: list[dict] | None):
    """Fake Horizon keyed by URL path."""

    def fetch(url: str, *, timeout: float):
        if "/operations" in url:
            return 200, {"_embedded": {"records": operations or []}}
        if "/transactions/" in url:
            return 200, {"successful": True, "ledger": 100}
        return 200, {"history_latest_ledger": 105}

    return fetch


def _invoke(contract_raw: bytes, *args: bytes) -> dict:
    return {
        "type": "invoke_host_function",
        "function": "HostFunctionTypeHostFunctionTypeInvokeContract",
        "parameters": [{"type": "Address", "value": _scval_address(contract_raw)}]
        + [{"type": "Bytes", "value": _scval_bytes32(a)} for a in args],
    }


BINDING = RegistrationBinding(contract_id=REGISTRY_ID, proof_id=PROOF_ID)


@pytest.fixture
def testnet(monkeypatch):
    monkeypatch.setenv("HARPOCRATES_RELEASE_NETWORK", "testnet")
    monkeypatch.delenv("HORIZON_URLS", raising=False)
    monkeypatch.delenv("HARPOCRATES_REGISTRY_CONTRACT_ID", raising=False)


def test_horizon_urls_never_cross_networks(testnet, monkeypatch):
    assert horizon_urls() == ["https://horizon-testnet.stellar.org"]

    monkeypatch.setenv(
        "HORIZON_URLS", "https://horizon-testnet.stellar.org,https://horizon.stellar.org"
    )
    assert horizon_urls() == ["https://horizon-testnet.stellar.org"]

    monkeypatch.setenv("HARPOCRATES_RELEASE_NETWORK", "mainnet")
    monkeypatch.delenv("HORIZON_URLS", raising=False)
    assert horizon_urls() == ["https://horizon.stellar.org"]


def test_mainnet_hash_is_not_accepted_on_testnet(testnet):
    seen: list[str] = []

    def fetch(url: str, *, timeout: float):
        seen.append(url)
        # Only mainnet knows this transaction.
        if url.startswith("https://horizon.stellar.org"):
            return 200, {"successful": True, "ledger": 100}
        return 404, None

    with mock.patch("tx_verification._fetch_json", side_effect=fetch):
        result = verify_transaction(VALID_TX, binding=BINDING)
    assert result.status == "missing"
    assert seen and all(url.startswith("https://horizon-testnet.stellar.org") for url in seen)


def test_unrelated_successful_transaction_is_rejected(testnet):
    payment = {"type": "payment", "amount": "1"}
    with mock.patch("tx_verification._fetch_json", side_effect=_horizon([payment])):
        result = verify_transaction(VALID_TX, binding=BINDING)
    assert result.status == "failed"
    assert result.reason == "wrong_contract"


def test_wrong_contract_is_rejected(testnet):
    other = _invoke(bytes([0xEE]) * 32, bytes.fromhex(PROOF_ID))
    with mock.patch("tx_verification._fetch_json", side_effect=_horizon([other])):
        result = verify_transaction(VALID_TX, binding=BINDING)
    assert result.status == "failed"
    assert result.reason == "wrong_contract"


def test_registry_call_for_another_proof_is_rejected(testnet):
    op = _invoke(REGISTRY_RAW, bytes([0x22]) * 32)
    with mock.patch("tx_verification._fetch_json", side_effect=_horizon([op])):
        result = verify_transaction(VALID_TX, binding=BINDING)
    assert result.status == "failed"
    assert result.reason == "proof_not_bound"


def test_matching_registration_confirms(testnet):
    op = _invoke(REGISTRY_RAW, bytes([0x33]) * 32, bytes.fromhex(PROOF_ID))
    with mock.patch("tx_verification._fetch_json", side_effect=_horizon([op])):
        result = verify_transaction(VALID_TX, binding=BINDING)
    assert result.status == "confirmed"
    assert result.confirmations == 6


@mock.patch("registration_reconcile.update_tx_status", return_value=True)
@mock.patch("registration_reconcile.verify_transaction")
def test_reconcile_rejects_row_for_another_contract(mock_verify, mock_update, monkeypatch):
    pinned = make_strkey(2 << 3, bytes([1]) * 32)
    monkeypatch.setenv("HARPOCRATES_REGISTRY_CONTRACT_ID", pinned)
    result = reconcile_registration(
        VALID_TX, proof_id=PROOF_ID, contract_id=REGISTRY_ID, event_id=7
    )
    assert result["status"] == "failed"
    assert result["reason"] == "wrong_contract"
    mock_verify.assert_not_called()
    mock_update.assert_called_once_with(VALID_TX, "failed", force=False, event_id=7)


@mock.patch("registration_reconcile.update_tx_status", return_value=True)
@mock.patch("registration_reconcile.verify_transaction")
def test_reconcile_without_binding_never_confirms(mock_verify, mock_update, testnet):
    result = reconcile_registration(VALID_TX, proof_id=PROOF_ID)
    assert result["status"] == "failed"
    assert result["reason"] == "registry_contract_unbound"
    mock_verify.assert_not_called()
