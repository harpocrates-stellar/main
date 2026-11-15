from __future__ import annotations

from unittest import mock

from chain_indexer import (
    UnsupportedEventQuarantine,
    clear_quarantined_event_versions,
    poll_indexer_once,
    process_events_batch,
)
from db import get_indexer_cursor, save_indexer_cursor

CONTRACT_ID = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXGI"
PROOF_A = "aa" * 32
PROOF_B = "bb" * 32


def setup_function() -> None:
    clear_quarantined_event_versions()


def test_unsupported_event_versions_quarantined_without_halting_supported_events() -> None:
    quarantine = UnsupportedEventQuarantine(max_entries=10)
    events = [
        # 1. Supported v1 event (explicit v1 topic tag)
        {
            "type": "contract",
            "ledger": 500,
            "id": "0000000500-0000000001",
            "txHash": "51" * 32,
            "topic": ["proof_v1", "revoke", PROOF_A],
            "value": 2,
        },
        # 2. Unsupported v2 topic tag -> quarantined with version reason
        {
            "type": "contract",
            "ledger": 501,
            "id": "0000000501-0000000002",
            "txHash": "52" * 32,
            "topic": ["proof_v2", "revoke", PROOF_A],
            "value": {"version": 2, "new_field": "opaque"},
        },
        # 3. Malformed version envelope -> quarantined with malformed reason
        {
            "type": "contract",
            "ledger": 502,
            "id": "0000000502-0000000001",
            "txHash": "53" * 32,
            "eventVersion": "v_experimental",
            "topic": ["dispute", "open", "cc" * 32, PROOF_B],
            "value": {"reason": 1},
        },
        # 4. Supported implicit v1 event AFTER unsupported events -> still indexed!
        {
            "type": "contract",
            "ledger": 503,
            "id": "0000000503-0000000001",
            "txHash": "54" * 32,
            "topic": ["proof", "history", PROOF_B],
            "value": {"action": 4},
        },
    ]

    summary = process_events_batch(events, contract_id=CONTRACT_ID, quarantine=quarantine)
    assert summary["scanned"] == 4
    assert summary["indexed"] == 2
    assert summary["unsupported_versions"] == 2
    assert summary["skipped"] == 0

    refs = quarantine.list_entries()
    assert len(refs) == 2
    assert refs[0]["observed_version"] == "2"
    assert refs[0]["reason"] == "unsupported_event_version:2"
    assert refs[0]["topic_family"] == "proof"
    assert refs[1]["reason"] == "malformed_event_version:v_experimental"


def test_quarantine_is_bounded_and_deduplicates_idempotently() -> None:
    quarantine = UnsupportedEventQuarantine(max_entries=2)
    batch = [
        {
            "ledger": 600 + idx,
            "id": f"0000000{600 + idx:03d}-0000000001",
            "txHash": f"{idx + 10:02x}" * 32,
            "eventVersion": idx + 2,
            "topic": ["proof", "revoke", PROOF_A],
        }
        for idx in range(3)
    ]

    process_events_batch(batch, contract_id=CONTRACT_ID, quarantine=quarantine)
    entries = quarantine.list_entries()
    assert len(entries) == 2
    assert quarantine.evicted_count == 1
    assert [e["observed_version"] for e in entries] == ["3", "4"]

    # Re-processing the surviving entry does not duplicate or evict
    replay = process_events_batch([batch[2]], contract_id=CONTRACT_ID, quarantine=quarantine)
    assert replay["quarantined_references"][0]["newly_quarantined"] is False
    assert quarantine.evicted_count == 1


@mock.patch("chain_indexer.fetch_contract_events")
def test_poll_indexer_once_preserves_cursor_and_gap_semantics_across_mixed_page(
    mock_fetch_events: mock.MagicMock,
) -> None:
    save_indexer_cursor("soroban_events", "cursor-700", ledger=700)
    quarantine = UnsupportedEventQuarantine(max_entries=8)
    mock_fetch_events.return_value = {
        "cursor": "cursor-705",
        "latestLedger": 705,
        "events": [
            {
                "ledger": 702,
                "id": "0000000702-0000000001",
                "txHash": "71" * 32,
                "eventVersion": 3,
                "topic": ["proof", "revoke", PROOF_A],
            },
            {
                "ledger": 704,
                "id": "0000000704-0000000001",
                "txHash": "72" * 32,
                "topic": ["proof", "revoke", PROOF_B],
            },
        ],
    }

    summary = poll_indexer_once(contract_id=CONTRACT_ID, quarantine=quarantine)
    assert summary["indexed"] == 1
    assert summary["unsupported_versions"] == 1
    assert summary["new_cursor"] == "cursor-705"
    assert get_indexer_cursor() == "cursor-705"
    assert len(summary["known_version_gaps"]) == 1
    assert summary["known_version_gaps"][0]["ledger"] == 702
    assert summary["known_version_gaps"][0]["reason"] == "unsupported_event_version:3"
