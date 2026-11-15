"""Focused tests for rejecting event pages whose contract identity changes (#1066)."""

from __future__ import annotations

import base64
import struct
from unittest import mock

import pytest

import db
from chain_indexer import (
    EventPageContractIdentityError,
    poll_indexer_once,
    process_events_batch,
    scan_contract_event_pages,
    validate_event_page_contract_identity,
)
from db import get_indexer_cursor, save_indexer_cursor
from strkey import _VERSION_BYTE_CONTRACT, make_strkey

EXPECTED_RAW_32 = b"\x41" * 32
FOREIGN_RAW_32 = b"\x42" * 32
EXPECTED_CONTRACT = make_strkey(_VERSION_BYTE_CONTRACT, EXPECTED_RAW_32)
FOREIGN_CONTRACT = make_strkey(_VERSION_BYTE_CONTRACT, FOREIGN_RAW_32)

TX_PAGE1 = "41" * 32
TX_CONFLICT_0 = "42" * 32
TX_CONFLICT_1 = "43" * 32
TX_UNKNOWN_FOREIGN = "44" * 32
TX_XDR_OK = "45" * 32
PROOF_1 = "4a" * 32
PROOF_2 = "4b" * 32


def _encode_contract_scval_xdr(raw_32: bytes) -> str:
    # SCV_ADDRESS (disc=18), SC_ADDRESS_TYPE_CONTRACT (addr_type=1), 32-byte contract hash
    payload = struct.pack(">II", 18, 1) + raw_32
    return base64.b64encode(payload).decode("ascii")


def test_mid_page_contract_change_rejects_entire_page_and_preserves_cursor(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    save_indexer_cursor("soroban_events", "cursor-committed-400", ledger=400)
    before_keys = set(db._INDEXED_EVENTS.keys())

    conflicting_page = {
        "cursor": "cursor-tainted-401",
        "latestLedger": 401,
        "events": [
            # Event 0 matches EXPECTED_CONTRACT — must NOT be projected when Event 1 conflicts!
            {
                "ledger": 401,
                "contractId": EXPECTED_CONTRACT,
                "txHash": TX_CONFLICT_0,
                "id": "0000000401-0000000001",
                "topic": ["proof", "revoke", PROOF_1],
                "value": 2,
            },
            # Event 1 switches contractId mid-page
            {
                "ledger": 401,
                "contractId": FOREIGN_CONTRACT,
                "txHash": TX_CONFLICT_1,
                "id": "0000000401-0000000002",
                "topic": ["proof", "revoke", PROOF_2],
                "value": 2,
            },
        ],
    }

    with (
        mock.patch("chain_indexer.fetch_contract_events", return_value=conflicting_page),
        mock.patch("chain_indexer.queue_webhook_deliveries") as mock_wh,
    ):
        with pytest.raises(EventPageContractIdentityError) as exc_info:
            poll_indexer_once(contract_id=EXPECTED_CONTRACT)

    err = exc_info.value
    assert err.reason == "mid_page_contract_change"
    assert err.expected_contract_id == EXPECTED_CONTRACT
    assert err.observed_contract_id == FOREIGN_CONTRACT
    assert err.event_position == 1

    # Zero rows projected from the conflicting page, zero webhooks, cursor unchanged!
    assert set(db._INDEXED_EVENTS.keys()) == before_keys
    assert (TX_CONFLICT_0, 1) not in db._INDEXED_EVENTS
    assert get_indexer_cursor("soroban_events") == "cursor-committed-400"
    mock_wh.assert_not_called()


def test_foreign_contract_on_unknown_topic_event_still_rejected_before_projection(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    save_indexer_cursor("soroban_events", "cursor-committed-410", ledger=410)
    before_keys = set(db._INDEXED_EVENTS.keys())

    mixed_page = {
        "cursor": "cursor-tainted-411",
        "latestLedger": 411,
        "events": [
            {
                "ledger": 411,
                "contractId": EXPECTED_CONTRACT,
                "txHash": TX_UNKNOWN_FOREIGN,
                "id": "0000000411-0000000001",
                "topic": ["proof", "revoke", PROOF_1],
            },
            {
                "ledger": 411,
                "contractId": FOREIGN_CONTRACT,
                "txHash": TX_UNKNOWN_FOREIGN,
                "id": "0000000411-0000000002",
                "topic": ["unrelated", "unknown_topic"],
            },
        ],
    }

    with mock.patch("chain_indexer.fetch_contract_events", return_value=mixed_page):
        with pytest.raises(EventPageContractIdentityError) as exc_info:
            poll_indexer_once(contract_id=EXPECTED_CONTRACT)

    assert exc_info.value.event_position == 1
    assert set(db._INDEXED_EVENTS.keys()) == before_keys
    assert get_indexer_cursor("soroban_events") == "cursor-committed-410"


def test_multi_page_scan_keeps_page_one_cursor_when_page_two_changes_contract(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    save_indexer_cursor("soroban_events", "cursor-start-500", ledger=500)

    page_1 = {
        "cursor": "cursor-page-501",
        "latestLedger": 501,
        "events": [
            {
                "ledger": 501,
                "contractId": EXPECTED_CONTRACT,
                "txHash": TX_PAGE1,
                "id": "0000000501-0000000001",
                "topic": ["proof", "revoke", PROOF_1],
                "value": 2,
            }
        ],
    }
    page_2_conflicting = {
        "cursor": "cursor-page-502",
        "latestLedger": 502,
        "events": [
            {
                "ledger": 502,
                "contractId": FOREIGN_CONTRACT,
                "txHash": "46" * 32,
                "id": "0000000502-0000000001",
                "topic": ["proof", "revoke", PROOF_2],
                "value": 2,
            }
        ],
    }

    with mock.patch(
        "chain_indexer.fetch_contract_events",
        side_effect=[page_1, page_2_conflicting],
    ):
        with pytest.raises(EventPageContractIdentityError) as exc_info:
            scan_contract_event_pages(EXPECTED_CONTRACT, max_pages=5)

    assert exc_info.value.observed_contract_id == FOREIGN_CONTRACT
    # Page 1 succeeded and committed cursor-page-501; Page 2 was rejected without advancing cursor!
    assert (TX_PAGE1, 1) in db._INDEXED_EVENTS
    assert ("46" * 32, 1) not in db._INDEXED_EVENTS
    assert get_indexer_cursor("soroban_events") == "cursor-page-501"


def test_xdr_encoded_contract_identity_and_boundary_cases(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    xdr_expected = _encode_contract_scval_xdr(EXPECTED_RAW_32)
    xdr_foreign = _encode_contract_scval_xdr(FOREIGN_RAW_32)

    # Matching XDR SCV_ADDRESS contractId decodes to EXPECTED_CONTRACT and succeeds
    summary = process_events_batch(
        [
            {
                "contractId": xdr_expected,
                "txHash": TX_XDR_OK,
                "id": "0000000600-0000000001",
                "topic": ["proof", "revoke", PROOF_1],
            }
        ],
        contract_id=EXPECTED_CONTRACT.lower(),  # case-insensitive StrKey match
    )
    assert summary["indexed"] == 1

    # Mismatched XDR SCV_ADDRESS contractId fails closed
    with pytest.raises(EventPageContractIdentityError):
        validate_event_page_contract_identity(
            [{"contractId": xdr_foreign, "txHash": TX_XDR_OK}],
            expected_contract_id=EXPECTED_CONTRACT,
        )

    # Unbound batch changing contract identity mid-page fails closed
    with pytest.raises(EventPageContractIdentityError) as unbound_exc:
        process_events_batch(
            [
                {"contractId": EXPECTED_CONTRACT, "txHash": TX_XDR_OK, "topic": ["a"]},
                {"contractId": FOREIGN_CONTRACT, "txHash": TX_XDR_OK, "topic": ["b"]},
            ]
        )
    assert unbound_exc.value.reason == "mid_page_contract_change"

    # Explicit require_explicit_contract_id rejects events omitting contractId
    with pytest.raises(EventPageContractIdentityError) as missing_exc:
        process_events_batch(
            [{"txHash": TX_XDR_OK, "topic": ["proof", "revoke", PROOF_1]}],
            contract_id=EXPECTED_CONTRACT,
            require_explicit_contract_id=True,
        )
    assert missing_exc.value.reason == "missing_event_contract_id"

    # Empty explicit contractId fails closed even when require_explicit is False
    with pytest.raises(EventPageContractIdentityError) as invalid_exc:
        process_events_batch(
            [{"contractId": "   ", "txHash": TX_XDR_OK, "topic": ["proof", "revoke", PROOF_1]}],
            contract_id=EXPECTED_CONTRACT,
        )
    assert invalid_exc.value.reason == "invalid_event_contract_id"
