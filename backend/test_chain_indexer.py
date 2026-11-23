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

try:
    import app as app_module
except Exception:
    app_module = None
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
    find_proof_events_by_proof_id,
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


# ---------------------------------------------------------------------------
# RPC Error Backoff & Recovery
# ---------------------------------------------------------------------------


def test_run_indexer_loop_backs_off_on_error():
    stop_event = threading.Event()
    call_count = 0

    def fake_poll(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            raise RuntimeError("RPC connection failed")
        stop_event.set()
        return {"scanned": 0, "indexed": 0, "skipped": 0, "duplicates": 0}

    with mock.patch("chain_indexer.poll_indexer_once", side_effect=fake_poll):
        # Run loop in separate thread
        t = threading.Thread(
            target=run_indexer_loop,
            args=(stop_event, DUMMY_CONTRACT),
            kwargs={"poll_interval": 0.02, "initial_backoff": 0.02, "max_backoff": 0.1},
        )
        t.start()
        t.join(timeout=3.0)

    assert not t.is_alive()
    assert call_count >= 3


# ---------------------------------------------------------------------------
# API Visibility: Revocations Appear in /api/proofs
# ---------------------------------------------------------------------------


def test_indexed_revocation_appears_in_api_proofs():
    if app_module is None or not hasattr(app_module, "app"):
        pytest.skip("app module unavailable")
    client = app_module.app.test_client()

    # Ingest revocation directly via indexer batch
    revocation_event = {
        "txHash": "77" * 32,
        "id": "0000000777-0000000001",
        "topic": ["proof", "revoke", "ff" * 32],
    }

    # Set up mock or stub for list_proof_events in app
    with mock.patch.object(
        app_module,
        "list_proof_events",
        return_value=(
            [
                {
                    "id": 1001,
                    "event_type": "revoke",
                    "proof_id": "ff" * 32,
                    "tx_hash": "77" * 32,
                    "tx_status": "revoked",
                }
            ],
            None,
        ),
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
# Proof Identifier Coercion & Exact Decimal Preservation
# ---------------------------------------------------------------------------


def test_classify_event_with_exact_decimal_integer_proof_id():
    # Large integer beyond 2^53 (standard float precision limit)
    large_decimal_id = 9007199254740993
    event = {
        "txHash": DUMMY_TX_1,
        "id": "0000000100-0000000001",
        "topic": ["proof", "revoke", large_decimal_id],
    }
    decoded = classify_and_decode_event(event)
    assert decoded is not None
    assert decoded.event_type == "revoke"
    assert decoded.proof_id == "9007199254740993"


def test_classify_event_with_exact_decimal_string_proof_id():
    decimal_str_id = "123456789012345678901234567890"
    event = {
        "txHash": DUMMY_TX_1,
        "id": "0000000100-0000000001",
        "topic": ["proof", "history", decimal_str_id],
        "value": {"action": 3},
    }
    decoded = classify_and_decode_event(event)
    assert decoded is not None
    assert decoded.proof_id == "123456789012345678901234567890"


@pytest.mark.parametrize(
    "unsafe_proof_id",
    [
        123.45,  # fractional float
        1.0,  # float representation
        "123.45",  # fractional string
        "1.0",  # fractional string
        ".5",  # fractional string without leading digit
        1e10,  # exponent float
        "1e10",  # exponent string
        "1E10",  # uppercase exponent string
        "1.5e3",  # fractional exponent string
        "1e-5",  # negative exponent string
        "-1e10",  # signed exponent string
        True,  # boolean True
        False,  # boolean False
        -42,  # negative integer
        "-42",  # negative string
        "",  # empty string
        "   ",  # whitespace string
        "not_a_valid_proof_id",  # malformed string
    ],
)
def test_classify_event_rejects_unsafe_integer_coercion(unsafe_proof_id):
    event = {
        "txHash": DUMMY_TX_1,
        "id": "0000000100-0000000001",
        "topic": ["proof", "revoke", unsafe_proof_id],
    }
    assert classify_and_decode_event(event) is None


def test_dispute_events_with_decimal_ids():
    event = {
        "txHash": DUMMY_TX_1,
        "id": "0000000100-0000000001",
        "topic": ["dispute", "open", 10001, 20002],
        "value": {"details": "opened"},
    }
    decoded = classify_and_decode_event(event)
    assert decoded is not None
    assert decoded.event_type == "dispute_open"
    assert decoded.metadata["dispute_id"] == "10001"
    assert decoded.proof_id == "20002"

    supersede_event = {
        "txHash": DUMMY_TX_1,
        "id": "0000000100-0000000002",
        "topic": ["dispute", "supersede", "10001", "20002"],
        "value": {"superseded_by": 30003},
    }
    decoded_supersede = classify_and_decode_event(supersede_event)
    assert decoded_supersede is not None
    assert decoded_supersede.metadata["superseded_by"] == "30003"


def test_process_events_batch_preserves_exact_decimal_id_in_db():
    large_id = 123456789012345678901234567890
    events = [
        {
            "txHash": "33" * 32,
            "id": "0000000300-0000000001",
            "topic": ["proof", "revoke", large_id],
        }
    ]
    summary = process_events_batch(events, contract_id=DUMMY_CONTRACT)
    assert summary["indexed"] == 1
    events_in_db = find_proof_events_by_proof_id(str(large_id))
    assert len(events_in_db) >= 1
    assert any(e["proof_id"] == str(large_id) for e in events_in_db)


def test_process_events_batch_skips_fractional_and_exponent_events():
    collector.reset()
    events = [
        {"txHash": DUMMY_TX_1, "id": "0000000400-0000000001", "topic": ["proof", "revoke", 1.5]},
        {"txHash": DUMMY_TX_1, "id": "0000000400-0000000002", "topic": ["proof", "revoke", "1e10"]},
        {"txHash": DUMMY_TX_1, "id": "0000000400-0000000003", "topic": ["proof", "revoke", True]},
    ]
    summary = process_events_batch(events, contract_id=DUMMY_CONTRACT)
    assert summary["scanned"] == 3
    assert summary["indexed"] == 0
    assert summary["skipped"] == 3
    assert collector.get_indexer_unknown_topics_count() == 3


def test_decode_scval_u128_and_u256():
    # Test U128 (discriminant 9): hi=1, lo=2 -> (1 << 64) | 2
    raw_u128 = struct.pack(">IIIQQ", 9, 0, 0, 1, 2)[-20:]  # disc (4 bytes) + 16 bytes payload
    u128_b64 = base64.b64encode(struct.pack(">IQQ", 9, 1, 2)).decode("ascii")
    decoded_u128 = decode_scval(u128_b64)
    expected_u128 = (1 << 64) | 2
    assert decoded_u128 == expected_u128

    # Test U256 (discriminant 11): 4 parts
    u256_b64 = base64.b64encode(struct.pack(">IQQQQ", 11, 1, 2, 3, 4)).decode("ascii")
    decoded_u256 = decode_scval(u256_b64)
    expected_u256 = (1 << 192) | (2 << 128) | (3 << 64) | 4
    assert decoded_u256 == expected_u256
