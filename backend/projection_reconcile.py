"""Read-only comparison of Soroban lifecycle events and indexed projections."""

from __future__ import annotations

import os
from typing import Any

from chain_indexer import (
    DEFAULT_SOROBAN_RPC_URL,
    INDEXER_DEFAULT_TIMEOUT,
    INDEXER_MAX_PAGE_SIZE,
    IndexerBackpressureError,
    classify_and_decode_event,
    fetch_contract_events,
)
from db import get_indexed_proof_events

MAX_LEDGER_RANGE = 10_000
DEFAULT_MAX_EVENTS = 1_000
MAX_EVENTS = 10_000

_PROJECTED_FIELDS = (
    "event_type",
    "proof_id",
    "contract_id",
    "tx_status",
    "metadata",
)


def _validate_range(start_ledger: int, end_ledger: int) -> None:
    if (
        not isinstance(start_ledger, int)
        or isinstance(start_ledger, bool)
        or not isinstance(end_ledger, int)
        or isinstance(end_ledger, bool)
    ):
        raise ValueError("ledger range must use integer sequences")
    if start_ledger < 1 or end_ledger < start_ledger:
        raise ValueError("invalid ledger range")
    if end_ledger - start_ledger + 1 > MAX_LEDGER_RANGE:
        raise ValueError(f"ledger range exceeds maximum of {MAX_LEDGER_RANGE}")


def reconcile_projection_range(
    *,
    start_ledger: int,
    end_ledger: int,
    contract_id: str,
    max_events: int = DEFAULT_MAX_EVENTS,
    rpc_url: str | None = None,
    timeout: float = INDEXER_DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Compare lifecycle events in a bounded ledger range with DB projections.

    The command reads at most ``max_events`` events and performs no writes. If
    the requested event cap is exceeded, it returns an incomplete report rather
    than treating an unexamined suffix as clean.
    """
    _validate_range(start_ledger, end_ledger)
    if not contract_id or not isinstance(contract_id, str):
        raise ValueError("contract_id is required")
    if (
        not isinstance(max_events, int)
        or isinstance(max_events, bool)
        or not 1 <= max_events <= MAX_EVENTS
    ):
        raise ValueError(f"max_events must be between 1 and {MAX_EVENTS}")

    active_rpc_url = (
        rpc_url
        or os.getenv("SOROBAN_RPC_URL")
        or os.getenv("STELLAR_RPC_URL")
        or DEFAULT_SOROBAN_RPC_URL
    )
    raw_events: list[dict[str, Any]] = []
    cursor: str | None = None

    while True:
        remaining = max_events - len(raw_events)
        page_limit = min(INDEXER_MAX_PAGE_SIZE, remaining + 1)
        page = fetch_contract_events(
            rpc_url=active_rpc_url,
            contract_id=contract_id,
            start_ledger=start_ledger if cursor is None else None,
            end_ledger=end_ledger,
            cursor=cursor,
            limit=page_limit,
            timeout=timeout,
        )
        events = page.get("events") or []
        if not isinstance(events, list):
            raise RuntimeError("Soroban RPC events must be a list")
        if any(not isinstance(event, dict) for event in events):
            raise RuntimeError("Soroban RPC event entries must be objects")
        if len(events) > page_limit:
            raise IndexerBackpressureError(
                f"RPC event page of {len(events)} exceeds requested limit {page_limit}"
            )
        if len(events) > remaining:
            return {
                "ok": False,
                "complete": False,
                "reason": "event_limit_exceeded",
                "range": {
                    "start_ledger": start_ledger,
                    "end_ledger": end_ledger,
                },
                "summary": {
                    "scanned": max_events,
                    "recognized": None,
                    "unknown": None,
                    "missing": None,
                    "conflicts": None,
                },
                "missing_events": [],
                "conflicts": [],
            }

        raw_events.extend(events)
        if len(events) < page_limit:
            break

        next_cursor = page.get("cursor")
        if not next_cursor and events:
            next_cursor = events[-1].get("id") or events[-1].get("pagingToken")
        if next_cursor is not None:
            next_cursor = str(next_cursor)
        if not next_cursor or next_cursor == cursor:
            raise RuntimeError("Soroban RPC pagination cursor did not advance")
        cursor = next_cursor

    decoded_events = []
    unknown = 0
    for event in raw_events:
        decoded = classify_and_decode_event(event, default_contract_id=contract_id)
        if decoded is None:
            unknown += 1
        else:
            decoded_events.append(decoded)

    keys = list(
        dict.fromkeys((event.tx_hash, event.event_index) for event in decoded_events)
    )
    rows = get_indexed_proof_events(keys)
    indexed_by_key = {
        (str(row["tx_hash"]), int(row["event_index"])): row
        for row in rows
    }

    missing_events = []
    conflicts = []
    for event in decoded_events:
        key = (event.tx_hash, event.event_index)
        row = indexed_by_key.get(key)
        identity = {
            "tx_hash": event.tx_hash,
            "event_index": event.event_index,
            "event_type": event.event_type,
            "proof_id": event.proof_id,
        }
        if row is None:
            missing_events.append(identity)
            continue

        expected = {
            "event_type": event.event_type,
            "proof_id": event.proof_id,
            "contract_id": event.contract_id,
            "tx_status": event.tx_status,
            "metadata": event.metadata,
        }
        differing_fields = [
            field
            for field in _PROJECTED_FIELDS
            if row.get(field) != expected[field]
        ]
        if differing_fields:
            conflicts.append({**identity, "fields": differing_fields})

    summary = {
        "scanned": len(raw_events),
        "recognized": len(decoded_events),
        "unknown": unknown,
        "missing": len(missing_events),
        "conflicts": len(conflicts),
    }
    return {
        "ok": not missing_events and not conflicts,
        "complete": True,
        "range": {
            "start_ledger": start_ledger,
            "end_ledger": end_ledger,
        },
        "summary": summary,
        "missing_events": missing_events,
        "conflicts": conflicts,
    }
