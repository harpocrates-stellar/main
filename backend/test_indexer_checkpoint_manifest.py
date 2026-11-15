"""Focused tests for verified indexer checkpoint manifests (#1064)."""

from __future__ import annotations

import json
from unittest import mock

import pytest

import db
from chain_indexer import (
    CHECKPOINT_MANIFEST_DOMAIN_TAG,
    DEFAULT_PROJECTION_SCHEMA,
    IncompatibleCheckpointError,
    build_checkpoint_manifest,
    get_verified_checkpoint_manifest,
    parse_and_verify_checkpoint_manifest,
    poll_indexer_once,
)
from db import (
    get_indexer_checkpoint_manifest_raw,
    get_indexer_cursor,
    save_indexer_cursor,
)

CONTRACT_A = "CCHECKPOINTCONTRACTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2I"
CONTRACT_B = "CCHECKPOINTCONTRACTBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB7Q"
TX_SEED = "23" * 32
TX_RESUME = "24" * 32
TX_TAINTED = "25" * 32
PROOF_1 = "2a" * 32
PROOF_2 = "2b" * 32


@pytest.fixture(autouse=True)
def reset_checkpoint_state(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("STELLAR_NETWORK_PASSPHRASE", raising=False)
    monkeypatch.delenv("HARPOCRATES_RELEASE_NETWORK", raising=False)
    monkeypatch.delenv("INDEXER_PROJECTION_SCHEMA", raising=False)
    monkeypatch.delenv("INDEXER_REQUIRE_CHECKPOINT_MANIFEST", raising=False)
    save_indexer_cursor("soroban_events", "")
    yield
    save_indexer_cursor("soroban_events", "")


def test_poll_records_verified_manifest_and_resumes_compatibly():
    page_1 = {
        "cursor": "0000000900-0000000001",
        "latestLedger": 900,
        "events": [
            {
                "ledger": 900,
                "txHash": TX_SEED,
                "id": "0000000900-0000000001",
                "topic": ["proof", "revoke", PROOF_1],
                "value": 2,
            }
        ],
    }
    page_2 = {
        "cursor": "0000000905-0000000002",
        "latestLedger": 905,
        "events": [
            {
                "ledger": 905,
                "txHash": TX_RESUME,
                "id": "0000000905-0000000002",
                "topic": ["proof", "revoke", PROOF_2],
                "value": 2,
            }
        ],
    }

    with (
        mock.patch("chain_indexer.fetch_latest_ledger", return_value=899),
        mock.patch("chain_indexer.fetch_contract_events", side_effect=[page_1, page_2]),
    ):
        s1 = poll_indexer_once(contract_id=CONTRACT_A, network="testnet")
        m1 = get_verified_checkpoint_manifest("soroban_events")
        assert m1 is not None
        assert m1.domain == CHECKPOINT_MANIFEST_DOMAIN_TAG
        assert m1.network == "testnet"
        assert m1.network_passphrase == "Test SDF Network ; September 2015"
        assert m1.contract_id == CONTRACT_A
        assert m1.projection_schema == DEFAULT_PROJECTION_SCHEMA
        assert m1.cursor == "0000000900-0000000001"
        assert m1.observed_ledger == 900
        assert s1["checkpoint_manifest"]["manifestDigest"] == m1.manifest_digest

        s2 = poll_indexer_once(contract_id=CONTRACT_A, network="testnet")
        m2 = get_verified_checkpoint_manifest("soroban_events")
        assert s2["indexed"] == 1
        assert m2 is not None
        assert m2.cursor == "0000000905-0000000002"
        assert m2.observed_ledger == 905


def test_incompatible_network_contract_or_schema_rejected_without_mutating_projection():
    seed_page = {
        "cursor": "cursor-trusted-910",
        "latestLedger": 910,
        "events": [
            {
                "ledger": 910,
                "txHash": "26" * 32,
                "id": "0000000910-0000000001",
                "topic": ["proof", "revoke", PROOF_1],
                "value": 2,
            }
        ],
    }
    with (
        mock.patch("chain_indexer.fetch_latest_ledger", return_value=909),
        mock.patch("chain_indexer.fetch_contract_events", return_value=seed_page),
    ):
        poll_indexer_once(contract_id=CONTRACT_A, network="testnet")

    trusted_events_snapshot = dict(db._INDEXED_EVENTS)
    trusted_cursor = get_indexer_cursor("soroban_events")
    trusted_manifest_raw = get_indexer_checkpoint_manifest_raw("soroban_events")

    # 1. Network mismatch (testnet checkpoint vs mainnet runtime)
    with mock.patch("chain_indexer.fetch_contract_events") as mock_rpc:
        with pytest.raises(IncompatibleCheckpointError) as net_err:
            poll_indexer_once(contract_id=CONTRACT_A, network="mainnet")
    assert net_err.value.reason == "network_mismatch"
    mock_rpc.assert_not_called()

    # 2. Contract mismatch (CONTRACT_A checkpoint vs CONTRACT_B runtime)
    with mock.patch("chain_indexer.fetch_contract_events") as mock_rpc:
        with pytest.raises(IncompatibleCheckpointError) as cid_err:
            poll_indexer_once(contract_id=CONTRACT_B, network="testnet")
    assert cid_err.value.reason == "contract_mismatch"
    mock_rpc.assert_not_called()

    # 3. Projection schema mismatch (v1 checkpoint vs v2 runtime)
    with mock.patch("chain_indexer.fetch_contract_events") as mock_rpc:
        with pytest.raises(IncompatibleCheckpointError) as schema_err:
            poll_indexer_once(
                contract_id=CONTRACT_A,
                network="testnet",
                projection_schema="harpocrates-proof-events-projection/v2",
            )
    assert schema_err.value.reason == "schema_mismatch"
    mock_rpc.assert_not_called()

    # Trusted projection and stored checkpoint remain 100% untouched!
    assert db._INDEXED_EVENTS == trusted_events_snapshot
    assert get_indexer_cursor("soroban_events") == trusted_cursor
    assert get_indexer_checkpoint_manifest_raw("soroban_events") == trusted_manifest_raw


def test_observed_ledger_regression_rejected_before_projection_mutation():
    seed_page = {
        "cursor": "cursor-trusted-950",
        "latestLedger": 950,
        "events": [
            {
                "ledger": 950,
                "txHash": "27" * 32,
                "id": "0000000950-0000000001",
                "topic": ["proof", "revoke", PROOF_1],
                "value": 2,
            }
        ],
    }
    with (
        mock.patch("chain_indexer.fetch_latest_ledger", return_value=949),
        mock.patch("chain_indexer.fetch_contract_events", return_value=seed_page),
    ):
        poll_indexer_once(contract_id=CONTRACT_A, network="testnet")

    trusted_events_snapshot = dict(db._INDEXED_EVENTS)

    # Simulate chain reset / wrong RPC node returning regressed latestLedger=400 with events
    regressed_page = {
        "cursor": "cursor-regressed-400",
        "latestLedger": 400,
        "events": [
            {
                "ledger": 400,
                "txHash": TX_TAINTED,
                "id": "0000000400-0000000001",
                "topic": ["proof", "revoke", PROOF_2],
                "value": 2,
            }
        ],
    }
    with (
        mock.patch("chain_indexer.fetch_contract_events", return_value=regressed_page),
        mock.patch("chain_indexer.queue_webhook_deliveries") as mock_wh,
    ):
        with pytest.raises(IncompatibleCheckpointError) as reg_err:
            poll_indexer_once(contract_id=CONTRACT_A, network="testnet")

    assert reg_err.value.reason == "observed_ledger_regression"
    assert (TX_TAINTED, 1) not in db._INDEXED_EVENTS
    assert db._INDEXED_EVENTS == trusted_events_snapshot
    assert get_indexer_cursor("soroban_events") == "cursor-trusted-950"
    assert get_verified_checkpoint_manifest("soroban_events").observed_ledger == 950
    mock_wh.assert_not_called()


def test_tampered_manifest_digest_and_cursor_desync_fail_closed():
    manifest = build_checkpoint_manifest(
        contract_id=CONTRACT_A,
        network="testnet",
        cursor="cursor-1000",
        observed_ledger=1000,
    )
    tampered = manifest.to_dict()
    tampered["observedLedger"] = 999  # mutate bound ledger without updating digest
    with pytest.raises(IncompatibleCheckpointError) as dig_err:
        parse_and_verify_checkpoint_manifest(json.dumps(tampered))
    assert dig_err.value.reason == "manifest_digest_mismatch"

    # Length-prefixed framing prevents boundary shifting collisions
    m_boundary_a = build_checkpoint_manifest(
        contract_id=CONTRACT_A,
        network="testnet",
        projection_schema="schema:a",
        cursor="b:cursor",
        observed_ledger=1000,
    )
    m_boundary_b = build_checkpoint_manifest(
        contract_id=CONTRACT_A,
        network="testnet",
        projection_schema="schema",
        cursor="a:b:cursor",
        observed_ledger=1000,
    )
    assert m_boundary_a.manifest_digest != m_boundary_b.manifest_digest

    # Out-of-band edit to raw cursor while manifest stays at cursor-1000
    db._INDEXER_STATE["soroban_events"] = {"cursor": "tampered-cursor-1005", "ledger": 1005}
    db._INDEXER_CHECKPOINT_MANIFESTS["soroban_events"] = manifest.to_json()
    with mock.patch("chain_indexer.fetch_contract_events") as mock_rpc:
        with pytest.raises(IncompatibleCheckpointError) as desync_err:
            poll_indexer_once(contract_id=CONTRACT_A, network="testnet")
    assert desync_err.value.reason == "cursor_manifest_mismatch"
    mock_rpc.assert_not_called()


def test_strict_require_manifest_rejects_unverified_bare_cursor():
    save_indexer_cursor("soroban_events", "legacy-bare-cursor-200", ledger=200)
    with mock.patch("chain_indexer.fetch_contract_events") as mock_rpc:
        with pytest.raises(IncompatibleCheckpointError) as missing_err:
            poll_indexer_once(
                contract_id=CONTRACT_A,
                network="testnet",
                require_manifest=True,
            )
    assert missing_err.value.reason == "missing_checkpoint_manifest"
    mock_rpc.assert_not_called()
