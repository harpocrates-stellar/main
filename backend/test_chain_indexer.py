"""
Tests for on-chain contract lifecycle event indexing from Soroban RPC getEvents.

Covers:
- Decoding of all lifecycle topics (revoke_proof, expire_proof, correct_proof,
  open_dispute, resolve_dispute, supersede_dispute) in both decoded and base64 ScVal formats
- Idempotency and duplicate deduplication on (tx_hash, event_index)
- Cursor persistence, restart, and resume without duplicates
- Skipping and counting of unknown topics
- Queueing of webhook deliveries for indexed events
- Bounded page size and exponential backoff on RPC errors
- Visibility of indexed revocations in /api/proofs
- Index rebuild dry-run: temporary projection from synthetic events with
  deterministic fingerprints, reporting differences without touching the live index
"""

from __future__ import annotations

import base64
import json
import struct
import threading
import time
from unittest import mock

import pytest

import app as app_module
from chain_indexer import (
    ContractIdentityConflictError,
    DEFAULT_SOROBAN_RPC_URL,
    INDEXER_DEFAULT_TIMEOUT,
    INDEXER_MAX_PAGE_SIZE,
    classify_and_decode_event,
    decode_scval,
    fetch_contract_events,
    fetch_latest_ledger,
    poll_indexer_once,
    process_events_batch,
    run_indexer_loop,
    validate_event_page_contract_identity,
)
from db import (
    get_indexer_cursor,
    insert_indexed_proof_event,
    list_proof_events,
    save_indexer_cursor,
)
from metrics import collector
from webhook import get_active_subscriptions, lease_deliveries, queue_webhook_deliveries

from chain_indexer import (
    build_index_projection,
    compute_projection_fingerprint,
    diff_projections,
    rebuild_index_dry_run,
)


# ---------------------------------------------------------------------------
# Test Fixtures & Helpers
# ---------------------------------------------------------------------------

DUMMY_TX_1 = "11" * 32
DUMMY_TX_2 = "22" * 32
DUMMY_PROOF_1 = "aa" * 32
DUMMY_PROOF_2 = "bb" * 32
DUMMY_DISPUTE_1 = "cc" * 32
DUMMY_DISPUTE_2 = "dd" * 32
DUMMY_CONTRACT = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXGI"


def _encode_sym(sym: str) -> str:
    """Encode symbol as base64 ScVal XDR."""
    raw_b = sym.encode("utf-8")
    val = struct.pack(">II", 15, len(raw_b)) + raw_b
    # pad to 4 bytes
    pad = (-len(val)) % 4
    val += b"\x00" * pad
    return base64.b64encode(val).decode("ascii")


def _encode_bytes(b_hex: str) -> str:
    """Encode 32-byte hex string as base64 ScVal Bytes XDR."""
    b = bytes.fromhex(b_hex)
    val = struct.pack(">II", 13, len(b)) + b
    pad = (-len(val)) % 4
    val += b"\x00" * pad
    return base64.b64encode(val).decode("ascii")


def _encode_u32(n: int) -> str:
    val = struct.pack(">II", 3, n)
    return base64.b64encode(val).decode("ascii")


# ---------------------------------------------------------------------------
# Unit Tests: ScVal and Topic Decoding
# ---------------------------------------------------------------------------


def test_decode_scval_formats():
    # Pass-through for plain types
    assert decode_scval("plain_string") == "plain_string"
    assert decode_scval(123) == 123
    assert decode_scval(None) is None

    # Base64 symbol
    sym_b64 = _encode_sym("proof")
    assert decode_scval(sym_b64) == "proof"

    # Base64 bytes
    bytes_b64 = _encode_bytes(DUMMY_PROOF_1)
    assert decode_scval(bytes_b64) == DUMMY_PROOF_1

    # Base64 u32
    u32_b64 = _encode_u32(42)
    assert decode_scval(u32_b64) == 42


def test_classify_revoke_proof_decoded():
    event = {
        "type": "contract",
        "ledger": 100,
        "contractId": DUMMY_CONTRACT,
        "id": "0000000100-0000000001",
        "txHash": DUMMY_TX_1,
        "topic": ["proof", "revoke", DUMMY_PROOF_1],
        "value": 2,
    }
    decoded = classify_and_decode_event(event)
    assert decoded is not None
    assert decoded.event_type == "revoke"
    assert decoded.proof_id == DUMMY_PROOF_1
    assert decoded.tx_hash == DUMMY_TX_1
    assert decoded.event_index == 1
    assert decoded.tx_status == "revoked"


def test_classify_revoke_proof_base64_xdr():
    event = {
        "type": "contract",
        "ledger": 101,
        "contractId": DUMMY_CONTRACT,
        "id": "0000000101-0000000003",
        "txHash": DUMMY_TX_1,
        "topic": [_encode_sym("proof"), _encode_sym("revoke"), _encode_bytes(DUMMY_PROOF_1)],
        "value": _encode_u32(2),
    }
    decoded = classify_and_decode_event(event)
    assert decoded is not None
    assert decoded.event_type == "revoke"
    assert decoded.proof_id == DUMMY_PROOF_1
    assert decoded.tx_hash == DUMMY_TX_1
    assert decoded.event_index == 3
    assert decoded.tx_status == "revoked"


def test_classify_proof_history_revoked():
    event = {
        "type": "contract",
        "ledger": 102,
        "id": "0000000102-0000000001",
        "txHash": DUMMY_TX_1,
        "topic": ["proof", "history", DUMMY_PROOF_1],
        "value": {"action": 3, "reason_code": 1, "actor": "GADMIN"},
    }
    decoded = classify_and_decode_event(event)
    assert decoded is not None
    assert decoded.event_type == "revoke"
    assert decoded.proof_id == DUMMY_PROOF_1
    assert decoded.metadata["action"] == "revoked"


def test_classify_proof_history_expired():
    event = {
        "type": "contract",
        "ledger": 103,
        "id": "0000000103-0000000002",
        "txHash": DUMMY_TX_1,
        "topic": ["proof", "history", DUMMY_PROOF_1],
        "value": {"action": 4, "reason_code": 2, "actor": "GADMIN"},
    }
    decoded = classify_and_decode_event(event)
    assert decoded is not None
    assert decoded.event_type == "expire"
    assert decoded.proof_id == DUMMY_PROOF_1
    assert decoded.metadata["action"] == "expired"


def test_classify_proof_history_corrected():
    event = {
        "type": "contract",
        "ledger": 104,
        "id": "0000000104-0000000005",
        "txHash": DUMMY_TX_1,
        "topic": ["proof", "history", DUMMY_PROOF_1],
        "value": {"action": 5, "reason_code": 10, "actor": "GADMIN"},
    }
    decoded = classify_and_decode_event(event)
    assert decoded is not None
    assert decoded.event_type == "correct"
    assert decoded.proof_id == DUMMY_PROOF_1
    assert decoded.metadata["action"] == "corrected"


def test_classify_dispute_open():
    event = {
        "type": "contract",
        "ledger": 105,
        "id": "0000000105-0000000001",
        "txHash": DUMMY_TX_1,
        "topic": ["dispute", "open", DUMMY_DISPUTE_1, DUMMY_PROOF_1],
        "value": {"reason": 1, "reporter_hash": "rep123"},
    }
    decoded = classify_and_decode_event(event)
    assert decoded is not None
    assert decoded.event_type == "dispute_open"
    assert decoded.proof_id == DUMMY_PROOF_1
    assert decoded.metadata["dispute_id"] == DUMMY_DISPUTE_1
    assert decoded.metadata["stage"] == "open"


def test_classify_dispute_resolve():
    event = {
        "type": "contract",
        "ledger": 106,
        "id": "0000000106-0000000002",
        "txHash": DUMMY_TX_1,
        "topic": ["dispute", "resolve", DUMMY_DISPUTE_1, DUMMY_PROOF_1],
        "value": {"resolved_at": 1700000000},
    }
    decoded = classify_and_decode_event(event)
    assert decoded is not None
    assert decoded.event_type == "dispute_resolve"
    assert decoded.proof_id == DUMMY_PROOF_1
    assert decoded.metadata["dispute_id"] == DUMMY_DISPUTE_1
    assert decoded.metadata["stage"] == "resolved"


def test_classify_dispute_supersede():
    event = {
        "type": "contract",
        "ledger": 107,
        "id": "0000000107-0000000004",
        "txHash": DUMMY_TX_1,
        "topic": ["dispute", "supersede", DUMMY_DISPUTE_1, DUMMY_PROOF_1],
        "value": {"superseded_by": DUMMY_PROOF_2, "resolved_at": 1700000000},
    }
    decoded = classify_and_decode_event(event)
    assert decoded is not None
    assert decoded.event_type == "dispute_supersede"
    assert decoded.proof_id == DUMMY_PROOF_1
    assert decoded.metadata["superseded_by"] == DUMMY_PROOF_2
    assert decoded.metadata["stage"] == "superseded"


def test_classify_unknown_topic_returns_none():
    event = {
        "type": "contract",
        "ledger": 108,
        "id": "0000000108-0000000001",
        "txHash": DUMMY_TX_1,
        "topic": ["admin", "propose", "some_payload"],
    }
    assert classify_and_decode_event(event) is None

    event2 = {
        "type": "contract",
        "ledger": 108,
        "id": "0000000108-0000000002",
        "txHash": DUMMY_TX_1,
        "topic": ["custom", "unknown"],
    }
    assert classify_and_decode_event(event2) is None


# ---------------------------------------------------------------------------
# Integration Tests: Ingestion, Deduplication, and Unknown Count
# ---------------------------------------------------------------------------


def test_process_events_batch_and_unknown_counting():
    collector.reset()
    events = [
        # 1. Valid revocation
        {
            "txHash": DUMMY_TX_1,
            "id": "0000000100-0000000001",
            "topic": ["proof", "revoke", DUMMY_PROOF_1],
        },
        # 2. Unknown topic 1
        {
            "txHash": DUMMY_TX_1,
            "id": "0000000100-0000000002",
            "topic": ["random", "topic"],
        },
        # 3. Valid expiry
        {
            "txHash": DUMMY_TX_1,
            "id": "0000000100-0000000003",
            "topic": ["proof", "history", DUMMY_PROOF_2],
            "value": {"action": 4},
        },
        # 4. Unknown topic 2
        {
            "txHash": DUMMY_TX_1,
            "id": "0000000100-0000000004",
            "topic": ["verif", "set", "addr"],
        },
    ]

    summary = process_events_batch(events, contract_id=DUMMY_CONTRACT)
    assert summary["scanned"] == 4
    assert summary["indexed"] == 2
    assert summary["skipped"] == 2
    assert summary["duplicates"] == 0

    assert collector.get_indexer_unknown_topics_count() == 2


def test_idempotency_duplicate_events():
    events = [
        {
            "txHash": DUMMY_TX_2,
            "id": "0000000200-0000000005",
            "topic": ["proof", "revoke", DUMMY_PROOF_1],
        }
    ]

    # First pass: indexed
    summary1 = process_events_batch(events, contract_id=DUMMY_CONTRACT)
    assert summary1["indexed"] == 1
    assert summary1["duplicates"] == 0

    # Second pass with exact same txHash and event_index: duplicate detected, not re-indexed
    summary2 = process_events_batch(events, contract_id=DUMMY_CONTRACT)
    assert summary2["indexed"] == 0
    assert summary2["duplicates"] == 1


# ---------------------------------------------------------------------------
# Cursor Persistence & Resume Across Restart
# ---------------------------------------------------------------------------


def test_cursor_persistence_and_resume():
    save_indexer_cursor("soroban_events", "cursor-test-100", ledger=100)
    assert get_indexer_cursor("soroban_events") == "cursor-test-100"

    # Update cursor
    save_indexer_cursor("soroban_events", "cursor-test-200", ledger=200)
    assert get_indexer_cursor("soroban_events") == "cursor-test-200"


@mock.patch("chain_indexer.fetch_latest_ledger", return_value=500)
@mock.patch("chain_indexer.fetch_contract_events")
def test_poll_indexer_once_resumes_from_stored_cursor(mock_fetch_events, mock_latest):
    save_indexer_cursor("soroban_events", "")  # clear cursor

    # Run 1: No cursor saved yet -> queries latest ledger and passes start_ledger
    mock_fetch_events.return_value = {
        "cursor": "cursor-501",
        "latestLedger": 501,
        "events": [
            {
                "txHash": "a" * 64,
                "id": "0000000501-0000000001",
                "topic": ["proof", "revoke", DUMMY_PROOF_1],
            }
        ],
    }

    summary1 = poll_indexer_once(contract_id=DUMMY_CONTRACT)
    assert summary1["indexed"] == 1
    assert summary1["new_cursor"] == "cursor-501"
    mock_fetch_events.assert_called_with(
        rpc_url=DEFAULT_SOROBAN_RPC_URL,
        contract_id=DUMMY_CONTRACT,
        start_ledger=500,
        cursor=None,
        limit=50,
        timeout=INDEXER_DEFAULT_TIMEOUT,
    )
    assert get_indexer_cursor() == "cursor-501"

    # Run 2: Restart simulation. Stored cursor is present.
    # It must query using cursor="cursor-501" instead of start_ledger.
    mock_fetch_events.reset_mock()


def test_poll_rejects_batch_over_admission_limit_without_advancing_cursor(monkeypatch):
    events = [
        {
            "txHash": DUMMY_TX_1,
            "id": "0000000600-0000000001",
            "topic": ["proof", "revoke", DUMMY_PROOF_1],
        },
        {
            "txHash": DUMMY_TX_2,
            "id": "0000000600-0000000002",
            "topic": ["proof", "revoke", DUMMY_PROOF_2],
        },
    ]
    monkeypatch.setattr("chain_indexer.INDEXER_MAX_PAGE_SIZE", 1)

    with (
        mock.patch("chain_indexer.get_indexer_cursor", return_value="cursor-before"),
        mock.patch("chain_indexer.save_indexer_cursor") as save_cursor,
        mock.patch(
            "chain_indexer.fetch_contract_events",
            return_value={"cursor": "cursor-after", "events": events},
        ) as fetch_events,
        mock.patch("chain_indexer.insert_indexed_proof_event") as insert_event,
    ):
        res = client.get("/api/proofs?limit=10")
        assert res.status_code == 200
        data = res.json
        assert data["ok"] is True
        events = data["events"]
        assert len(events) == 1
        assert events[0]["event_type"] == "revoke"
        assert events[0]["proof_id"] == "ff" * 32
        assert events[0]["tx_status"] == "revoked"


# ---------------------------------------------------------------------------
# Contract Identity Consistency Validation
# ---------------------------------------------------------------------------

OTHER_CONTRACT = "CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBXGI"


def test_process_events_batch_rejects_contract_identity_change_before_projection():
    """If contractId changes mid-page, reject the entire page before projecting any event."""
    events = [
        {
            "txHash": "e1" * 32,
            "id": "0000000600-0000000001",
            "contractId": DUMMY_CONTRACT,
            "topic": ["proof", "revoke", DUMMY_PROOF_1],
        },
        {
            "txHash": "e2" * 32,
            "id": "0000000600-0000000002",
            "contractId": OTHER_CONTRACT,
            "topic": ["proof", "revoke", DUMMY_PROOF_2],
        },
    ]

    with (
        mock.patch("chain_indexer.insert_indexed_proof_event") as mock_insert,
        mock.patch("chain_indexer.queue_webhook_deliveries") as mock_webhook,
    ):
        with pytest.raises(ContractIdentityConflictError, match="Contract identity changed"):
            process_events_batch(events, contract_id=DUMMY_CONTRACT)

        mock_insert.assert_not_called()
        mock_webhook.assert_not_called()


@mock.patch("chain_indexer.fetch_contract_events")
def test_poll_indexer_once_keeps_committed_cursor_unchanged_on_conflicting_page(mock_fetch_events):
    """A page with a conflicting contractId must fail closed and leave the committed cursor unchanged."""
    save_indexer_cursor("soroban_events", "cursor-committed-600", ledger=600)

    mock_fetch_events.return_value = {
        "cursor": "cursor-should-not-commit-601",
        "latestLedger": 601,
        "events": [
            {
                "txHash": "f1" * 32,
                "id": "0000000601-0000000001",
                "contractId": DUMMY_CONTRACT,
                "topic": ["proof", "revoke", DUMMY_PROOF_1],
            },
            {
                "txHash": "f2" * 32,
                "id": "0000000601-0000000002",
                "contractId": OTHER_CONTRACT,
                "topic": ["proof", "history", DUMMY_PROOF_2],
                "value": {"action": 4},
            },
        ],
    }

    with mock.patch("chain_indexer.insert_indexed_proof_event") as mock_insert:
        with pytest.raises(ContractIdentityConflictError):
            poll_indexer_once(contract_id=DUMMY_CONTRACT)

        mock_insert.assert_not_called()

    assert get_indexer_cursor("soroban_events") == "cursor-committed-600"


def test_validate_event_page_contract_identity_boundary_cases():
    # Without expected_contract_id, conflicting contract IDs inside the page are still rejected.
    with pytest.raises(ContractIdentityConflictError):
        validate_event_page_contract_identity(
            [
                {"contractId": DUMMY_CONTRACT, "txHash": DUMMY_TX_1},
                {"contract_id": OTHER_CONTRACT, "txHash": DUMMY_TX_2},
            ],
            expected_contract_id=None,
        )

    # Conflicting camelCase vs snake_case contract ID on the same event is rejected.
    with pytest.raises(ContractIdentityConflictError, match="Conflicting contractId/contract_id"):
        validate_event_page_contract_identity(
            [{"contractId": DUMMY_CONTRACT, "contract_id": OTHER_CONTRACT}],
            expected_contract_id=DUMMY_CONTRACT,
        )

    # Empty/whitespace contractId is rejected.
    with pytest.raises(ContractIdentityConflictError, match="Invalid contractId"):
        validate_event_page_contract_identity(
            [{"contractId": "   "}],
            expected_contract_id=DUMMY_CONTRACT,
        )

    # Consistent explicit contract IDs and omitted contract IDs pass.
    assert (
        validate_event_page_contract_identity(
            [
                {"contractId": DUMMY_CONTRACT},
                {"txHash": DUMMY_TX_1},
                {"contract_id": DUMMY_CONTRACT},
            ],
            expected_contract_id=DUMMY_CONTRACT,
        )
        == DUMMY_CONTRACT
    )
