from __future__ import annotations

from unittest import mock

from chain_indexer import process_events_batch
from registration_reconcile import process_verify_tx_job, reconcile_registration
from tx_verification import (
    TERMINAL_STATUSES,
    clear_network_mismatch_cache,
    verify_transaction,
    verify_transaction_status,
)

TX_MAINNET = "aa" * 32
TX_VALID = "bb" * 32
PROOF_VALID = "cc" * 32
CONTRACT_ID = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXGI"


def setup_function() -> None:
    clear_network_mismatch_cache()


@mock.patch("tx_verification._fetch_json")
def test_wrong_network_tx_distinct_from_malformed_proof_and_not_retried_indefinitely(
    mock_fetch: mock.MagicMock,
) -> None:
    # Horizon reports a mainnet network_passphrase while expected network is testnet
    mock_fetch.return_value = (
        200,
        {
            "successful": True,
            "ledger": 5000,
            "network_passphrase": "Public Global Stellar Network ; September 2015",
        },
    )

    wrong_net = verify_transaction(TX_MAINNET, expected_network="testnet")
    assert wrong_net.status == "network_mismatch"
    assert wrong_net.reason == "network_binding_mismatch"
    assert wrong_net.failure_kind == "wrong_network"
    assert wrong_net.expected_network == "Test SDF Network ; September 2015"
    assert wrong_net.observed_network == "Public Global Stellar Network ; September 2015"
    assert wrong_net.retryable is False
    assert "network_mismatch" in TERMINAL_STATUSES

    # Repeated calls for the same incompatible tx hit the terminal cache without RPC retries
    call_count_after_first = mock_fetch.call_count
    cached = verify_transaction(TX_MAINNET, expected_network="testnet")
    assert cached.status == "network_mismatch"
    assert mock_fetch.call_count == call_count_after_first
    assert verify_transaction_status(TX_MAINNET, expected_network="testnet") == "network_mismatch"

    # Malformed proof/tx inputs remain distinct from wrong_network
    malformed_hash = verify_transaction("not-a-valid-hash", expected_network="testnet")
    assert malformed_hash.status == "failed"
    assert malformed_hash.reason == "malformed_tx_hash"
    assert malformed_hash.failure_kind == "malformed_proof_data"

    malformed_proof = verify_transaction(
        TX_VALID,
        expected_network="testnet",
        proof_id="short-proof-id",
    )
    assert malformed_proof.status == "failed"
    assert malformed_proof.reason == "malformed_proof_data"
    assert malformed_proof.failure_kind == "malformed_proof_data"


@mock.patch("registration_reconcile.update_tx_status", return_value=True)
@mock.patch("tx_verification._fetch_json")
def test_reconcile_persists_terminal_network_mismatch_and_skips_repeat_rechecks(
    mock_fetch: mock.MagicMock,
    mock_update: mock.MagicMock,
) -> None:
    # Testnet returns 404, pubnet returns 200 -> strict URL binding flags wrong_network
    mock_fetch.side_effect = [
        (404, None),
        (200, {"successful": True, "ledger": 777}),
    ]

    first = reconcile_registration(
        TX_MAINNET,
        previous_status="pending",
        proof_id=PROOF_VALID,
        expected_network="testnet",
    )
    assert first["status"] == "network_mismatch"
    assert first["reason"] == "network_binding_mismatch"
    assert first["failureKind"] == "wrong_network"
    assert first["retryable"] is False
    assert first["updated"] is True
    mock_update.assert_called_once_with(TX_MAINNET, "network_mismatch", force=False)

    # Once marked network_mismatch, subsequent reconcile attempts skip Horizon completely
    mock_fetch.reset_mock()
    mock_update.reset_mock()
    second = reconcile_registration(
        TX_MAINNET,
        previous_status="network_mismatch",
        proof_id=PROOF_VALID,
        expected_network="testnet",
    )
    assert second["status"] == "network_mismatch"
    assert second["reason"] == "already_terminal"
    assert second["updated"] is False
    mock_fetch.assert_not_called()
    mock_update.assert_not_called()

    # Worker job entrypoint does not raise on terminal network_mismatch (no retry loop)
    job_res = process_verify_tx_job({"txHash": TX_MAINNET, "proofId": PROOF_VALID})
    assert job_res["status"] == "network_mismatch"


def test_indexer_batch_separates_wrong_network_events_from_malformed_proof_data() -> None:
    events = [
        {
            "txHash": "12" * 32,
            "id": "0000000100-0000000001",
            "networkPassphrase": "Public Global Stellar Network ; September 2015",
            "topic": ["proof", "revoke", PROOF_VALID],
        },
        {
            "txHash": "13" * 32,
            "id": "0000000100-0000000002",
            "topic": ["proof", "revoke", "not-32-byte-hex"],
        },
        {
            "txHash": "14" * 32,
            "id": "0000000100-0000000003",
            "networkPassphrase": "Test SDF Network ; September 2015",
            "topic": ["proof", "revoke", PROOF_VALID],
        },
    ]

    summary = process_events_batch(
        events,
        contract_id=CONTRACT_ID,
        expected_network="testnet",
    )
    assert summary["scanned"] == 3
    assert summary["network_mismatches"] == 1
    assert summary["malformed"] == 1
    assert summary["indexed"] == 1
    kinds = [m["failureKind"] for m in summary["mismatches"]]
    assert kinds == ["wrong_network", "malformed_proof_data"]
