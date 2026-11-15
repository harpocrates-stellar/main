"""
Soroban RPC Contract Event Indexer.

Indexes lifecycle events emitted directly on-chain by the Harpocrates Registry contract:
- revoke_proof (ProofRevoked, ProofHistoryEvent with Revoked action)
- expire_proof (ProofHistoryEvent with Expired action)
- correct_proof (ProofHistoryEvent with Corrected action)
- open_dispute (DisputeOpened)
- resolve_dispute (DisputeResolved)
- supersede_dispute (DisputeSuperseded)

Decodes events into proof_events rows idempotently (unique on tx_hash + event_index),
persists the ledger cursor, queues webhook deliveries, skips and counts unknown topics,
bounds page size, and backs off exponentially on RPC errors.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import struct
import threading
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from db import (
    get_indexer_cursor,
    insert_indexed_proof_event,
    list_indexed_proof_events_for_reconcile,
    save_indexer_cursor,
)
from fetch_external import safe_urlopen
from metrics import collector
from strkey import (
    _VERSION_BYTE_CONTRACT,
    _VERSION_BYTE_ED25519_PUBLIC,
    make_strkey,
)
from tx_verification import verify_transaction
from webhook import queue_webhook_deliveries

LOGGER = logging.getLogger("harpocrates.chain_indexer")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)

DEFAULT_SOROBAN_RPC_URL = "https://soroban-testnet.stellar.org"
INDEXER_DEFAULT_PAGE_SIZE = 50
INDEXER_MAX_PAGE_SIZE = 100
INDEXER_DEFAULT_POLL_INTERVAL = 5.0
INDEXER_DEFAULT_TIMEOUT = 10.0
MAX_RECONCILE_LEDGER_SPAN = 1000
MAX_RECONCILE_PAGES = 50


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------


@dataclass
class DecodedLifecycleEvent:
    event_type: str
    proof_id: str | None
    tx_hash: str
    event_index: int
    contract_id: str | None = None
    tx_status: str = "confirmed"
    metadata: dict[str, Any] | None = None
    ledger: int | None = None
    created_at: datetime | None = None


# ---------------------------------------------------------------------------
# ScVal / XDR Decoder
# ---------------------------------------------------------------------------


def decode_scval(raw: Any) -> Any:
    """Decode a Soroban ScVal from base64 XDR or pass through already-decoded values."""
    if not isinstance(raw, str):
        return raw

    # If it is not a base64 string, or is plain ascii text / hex, keep as is
    try:
        data = base64.b64decode(raw, validate=True)
    except Exception:
        return raw

    if len(data) < 4:
        return raw

    try:
        disc = struct.unpack(">I", data[:4])[0]
        payload = data[4:]

        if disc == 0:  # SCV_BOOL
            return bool(struct.unpack(">I", payload[:4])[0])
        if disc == 1:  # SCV_VOID
            return None
        if disc in (3, 4):  # SCV_U32, SCV_I32
            return struct.unpack(">I" if disc == 3 else ">i", payload[:4])[0]
        if disc in (5, 6, 7, 8):  # SCV_U64, SCV_I64, SCV_TIMEPOINT, SCV_DURATION
            return struct.unpack(">Q" if disc in (5, 7, 8) else ">q", payload[:8])[0]
        if disc in (13, 14, 15):  # SCV_BYTES, SCV_STRING, SCV_SYMBOL
            b_len = struct.unpack(">I", payload[:4])[0]
            val_bytes = payload[4 : 4 + b_len]
            if disc == 13:
                return val_bytes.hex()
            return val_bytes.decode("utf-8", errors="replace")
        if disc == 16:  # SCV_VEC
            return raw
        if disc == 18:  # SCV_ADDRESS
            addr_type = struct.unpack(">I", payload[:4])[0]
            if addr_type == 0:  # Account
                # skip 4 bytes of public key type
                pk = payload[8:40]
                return make_strkey(_VERSION_BYTE_ED25519_PUBLIC, pk)
            if addr_type == 1:  # Contract
                cid = payload[4:36]
                return make_strkey(_VERSION_BYTE_CONTRACT, cid)
    except Exception:
        return raw

    return raw


def _normalize_hex(val: Any) -> str | None:
    """Return a 64-character lowercase hex string if valid, else stringified."""
    if val is None:
        return None
    if isinstance(val, bytes):
        return val.hex().lower()
    text = str(val).strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    return text


# ---------------------------------------------------------------------------
# Lifecycle Topic Classifier
# ---------------------------------------------------------------------------


def classify_and_decode_event(
    event: dict[str, Any],
    default_contract_id: str | None = None,
) -> DecodedLifecycleEvent | None:
    """Parse a Soroban RPC event and decode it if it matches a known lifecycle topic.

    Returns DecodedLifecycleEvent if recognized, or None if unknown/unhandled.
    """
    if not isinstance(event, dict):
        return None

    # Resolve tx_hash
    tx_hash = (
        event.get("txHash")
        or event.get("transactionHash")
        or event.get("tx_hash")
    )
    if not tx_hash or not isinstance(tx_hash, str):
        return None
    tx_hash = _normalize_hex(tx_hash) or tx_hash

    # Resolve event index
    event_index = event.get("eventIndex")
    if event_index is None:
        event_index = event.get("event_index")
    if event_index is None:
        # Paging token format commonly: "<ledger>-<index>"
        token = str(event.get("id") or event.get("pagingToken") or "")
        if "-" in token:
            try:
                event_index = int(token.split("-")[-1])
            except (ValueError, TypeError):
                event_index = 0
        else:
            event_index = 0
    else:
        try:
            event_index = int(event_index)
        except (ValueError, TypeError):
            event_index = 0

    contract_id = (
        event.get("contractId")
        or event.get("contract_id")
        or default_contract_id
    )
    ledger = event.get("ledger")

    # Decode topics
    raw_topics = event.get("topic") or event.get("topics") or []
    if not isinstance(raw_topics, list) or not raw_topics:
        return None

    topics = [decode_scval(t) for t in raw_topics]
    first = str(topics[0]).lower() if len(topics) > 0 else ""
    second = str(topics[1]).lower() if len(topics) > 1 else ""

    # Decode value if available
    raw_val = event.get("value")
    val = decode_scval(raw_val)

    # 1. Proof Revocation: topics = ["proof", "revoke", proof_id]
    if first == "proof" and second == "revoke" and len(topics) >= 3:
        proof_id = _normalize_hex(topics[2])
        return DecodedLifecycleEvent(
            event_type="revoke",
            proof_id=proof_id,
            tx_hash=tx_hash,
            event_index=event_index,
            contract_id=contract_id,
            tx_status="revoked",
            metadata={"status": "revoked", "raw_value": val},
            ledger=ledger,
        )

    # 2. Proof History: topics = ["proof", "history", proof_id]
    if first == "proof" and second == "history" and len(topics) >= 3:
        proof_id = _normalize_hex(topics[2])
        # Value carries ProofHistoryEntry: action (u32), timestamp (u64), actor (Option<Address>), reason_code (u32)
        # Action codes: 1=Registered, 2=Verified, 3=Revoked, 4=Expired, 5=Corrected, 6=TtlUpdated
        action = None
        actor = None
        reason_code = None
        if isinstance(val, dict):
            action = val.get("action")
            actor = val.get("actor")
            reason_code = val.get("reason_code")
        elif isinstance(val, (list, tuple)) and len(val) >= 1:
            action = val[0]
            if len(val) >= 3:
                actor = val[2]
            if len(val) >= 4:
                reason_code = val[3]
        elif isinstance(val, int):
            action = val

        try:
            action_int = int(action) if action is not None else 0
        except (ValueError, TypeError):
            action_int = 0

        if action_int == 3:  # Revoked
            return DecodedLifecycleEvent(
                event_type="revoke",
                proof_id=proof_id,
                tx_hash=tx_hash,
                event_index=event_index,
                contract_id=contract_id,
                tx_status="revoked",
                metadata={"action": "revoked", "actor": actor, "reason_code": reason_code},
                ledger=ledger,
            )
        if action_int == 4:  # Expired
            return DecodedLifecycleEvent(
                event_type="expire",
                proof_id=proof_id,
                tx_hash=tx_hash,
                event_index=event_index,
                contract_id=contract_id,
                tx_status="confirmed",
                metadata={"action": "expired", "actor": actor, "reason_code": reason_code},
                ledger=ledger,
            )
        if action_int == 5:  # Corrected
            return DecodedLifecycleEvent(
                event_type="correct",
                proof_id=proof_id,
                tx_hash=tx_hash,
                event_index=event_index,
                contract_id=contract_id,
                tx_status="confirmed",
                metadata={"action": "corrected", "actor": actor, "reason_code": reason_code},
                ledger=ledger,
            )

    # 3. Dispute Lifecycle Events: topics = ["dispute", action, dispute_id, proof_id]
    if first == "dispute" and len(topics) >= 2:
        action = second
        dispute_id = _normalize_hex(topics[2]) if len(topics) >= 3 else None
        proof_id = _normalize_hex(topics[3]) if len(topics) >= 4 else None
        if proof_id is None and len(topics) == 3:
            # Fallback if dispute_id / proof_id single identifier
            proof_id = dispute_id

        if action == "open":
            return DecodedLifecycleEvent(
                event_type="dispute_open",
                proof_id=proof_id,
                tx_hash=tx_hash,
                event_index=event_index,
                contract_id=contract_id,
                tx_status="confirmed",
                metadata={"dispute_id": dispute_id, "stage": "open", "details": val},
                ledger=ledger,
            )
        if action == "resolve":
            return DecodedLifecycleEvent(
                event_type="dispute_resolve",
                proof_id=proof_id,
                tx_hash=tx_hash,
                event_index=event_index,
                contract_id=contract_id,
                tx_status="confirmed",
                metadata={"dispute_id": dispute_id, "stage": "resolved", "details": val},
                ledger=ledger,
            )
        if action == "supersede":
            superseded_by = None
            if isinstance(val, dict):
                superseded_by = _normalize_hex(val.get("superseded_by"))
            return DecodedLifecycleEvent(
                event_type="dispute_supersede",
                proof_id=proof_id,
                tx_hash=tx_hash,
                event_index=event_index,
                contract_id=contract_id,
                tx_status="confirmed",
                metadata={
                    "dispute_id": dispute_id,
                    "stage": "superseded",
                    "superseded_by": superseded_by,
                    "details": val,
                },
                ledger=ledger,
            )
        if action == "dismiss":
            return DecodedLifecycleEvent(
                event_type="dispute_dismiss",
                proof_id=proof_id,
                tx_hash=tx_hash,
                event_index=event_index,
                contract_id=contract_id,
                tx_status="confirmed",
                metadata={"dispute_id": dispute_id, "stage": "dismissed", "details": val},
                ledger=ledger,
            )

    # Unknown topic
    return None


# ---------------------------------------------------------------------------
# Batch Processing & Ingestion
# ---------------------------------------------------------------------------


def process_events_batch(
    events: list[dict[str, Any]],
    contract_id: str | None = None,
) -> dict[str, Any]:
    """Ingest a list of raw Soroban RPC events.

    Decodes lifecycle events, inserts them idempotently into proof_events,
    queues webhooks for newly written events, and tracks unknown topics.
    """
    summary = {
        "scanned": 0,
        "indexed": 0,
        "skipped": 0,
        "duplicates": 0,
    }

    for raw in events:
        summary["scanned"] += 1
        decoded = classify_and_decode_event(raw, default_contract_id=contract_id)

        if decoded is None:
            collector.record_indexer_unknown_topic()
            summary["skipped"] += 1
            continue

        row, created = insert_indexed_proof_event(
            event_type=decoded.event_type,
            proof_id=decoded.proof_id,
            tx_hash=decoded.tx_hash,
            event_index=decoded.event_index,
            contract_id=decoded.contract_id,
            tx_status=decoded.tx_status,
            metadata=decoded.metadata,
            created_at=decoded.created_at,
        )

        if created:
            summary["indexed"] += 1
            collector.record_indexer_event(decoded.event_type)
            if row and row.get("id"):
                try:
                    queue_webhook_deliveries(row["id"])
                except Exception as exc:
                    LOGGER.warning("webhook_queue_failed event_id=%s exc=%s", row["id"], exc)
        else:
            summary["duplicates"] += 1

    return summary


# ---------------------------------------------------------------------------
# Soroban RPC Client
# ---------------------------------------------------------------------------


def fetch_latest_ledger(rpc_url: str, timeout: float = INDEXER_DEFAULT_TIMEOUT) -> int | None:
    """Fetch the latest ledger sequence from Soroban RPC via getLatestLedger."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLatestLedger",
        "params": [],
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        rpc_url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Harpocrates-Indexer/1.0"},
        method="POST",
    )
    try:
        res = safe_urlopen(req, connect_timeout=min(timeout, 5.0), read_timeout=timeout)
        data = json.loads(res.body.decode("utf-8"))
        result = data.get("result") or {}
        sequence = result.get("sequence") or result.get("latestLedger")
        return int(sequence) if sequence is not None else None
    except Exception as exc:
        LOGGER.warning("fetch_latest_ledger_failed rpc=%s exc=%s", rpc_url, exc)
        return None


def fetch_contract_events(
    rpc_url: str,
    contract_id: str,
    start_ledger: int | None = None,
    cursor: str | None = None,
    limit: int = INDEXER_DEFAULT_PAGE_SIZE,
    timeout: float = INDEXER_DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Call Soroban RPC getEvents with bounded pagination and filter."""
    page_limit = max(1, min(int(limit), INDEXER_MAX_PAGE_SIZE))
    params: dict[str, Any] = {
        "filters": [
            {
                "type": "contract",
                "contractIds": [contract_id],
            }
        ],
        "pagination": {
            "limit": page_limit,
        },
    }

    if cursor:
        params["pagination"]["cursor"] = cursor
        params["cursor"] = cursor
    elif start_ledger is not None:
        params["startLedger"] = start_ledger

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getEvents",
        "params": params,
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        rpc_url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Harpocrates-Indexer/1.0"},
        method="POST",
    )

    res = safe_urlopen(req, connect_timeout=min(timeout, 5.0), read_timeout=timeout)
    data = json.loads(res.body.decode("utf-8"))
    if "error" in data:
        raise RuntimeError(f"Soroban RPC error: {data['error']}")
    return data.get("result") or {}


# ---------------------------------------------------------------------------
# Read-Only Bounded Projection Reconciliation
# ---------------------------------------------------------------------------

_RECONCILE_COMPARE_FIELDS = (
    "event_type",
    "proof_id",
    "contract_id",
    "tx_status",
    "metadata",
)


def _extract_event_ledger(event: dict[str, Any]) -> int | None:
    """Resolve integer ledger sequence from explicit field or paging token prefix."""
    raw_ledger = event.get("ledger")
    if raw_ledger is not None and not isinstance(raw_ledger, bool):
        try:
            parsed = int(raw_ledger)
            if parsed >= 0:
                return parsed
        except (TypeError, ValueError):
            pass

    token = str(event.get("id") or event.get("pagingToken") or "").strip()
    if "-" in token:
        prefix = token.split("-", 1)[0]
        try:
            parsed_prefix = int(prefix, 10)
            if parsed_prefix >= 0:
                return parsed_prefix
        except ValueError:
            pass
    return None


def _extract_record_ledger(row: dict[str, Any]) -> int | None:
    """Resolve optional ledger recorded on an indexed proof_events row."""
    raw_ledger = row.get("ledger")
    if raw_ledger is None and isinstance(row.get("metadata"), dict):
        meta = row["metadata"]
        raw_ledger = meta.get("ledger")
        if raw_ledger is None and isinstance(meta.get("canonical_order"), dict):
            raw_ledger = meta["canonical_order"].get("ledger")
    if raw_ledger is not None and not isinstance(raw_ledger, bool):
        try:
            parsed = int(raw_ledger)
            if parsed >= 0:
                return parsed
        except (TypeError, ValueError):
            return None
    return None


def validate_reconcile_ledger_range(
    start_ledger: Any,
    end_ledger: Any,
    *,
    max_span: int = MAX_RECONCILE_LEDGER_SPAN,
) -> tuple[int, int]:
    """Validate an inclusive bounded ``[start_ledger, end_ledger]`` range."""
    if isinstance(start_ledger, bool) or isinstance(end_ledger, bool):
        raise ValueError("start_ledger and end_ledger must be positive integers")
    try:
        start = int(start_ledger)
        end = int(end_ledger)
    except (TypeError, ValueError) as exc:
        raise ValueError("start_ledger and end_ledger must be positive integers") from exc

    if start < 1 or end < 1:
        raise ValueError("start_ledger and end_ledger must be >= 1")
    if end < start:
        raise ValueError("end_ledger must be >= start_ledger")

    bounded_max = max(1, min(int(max_span), 10000))
    span = end - start + 1
    if span > bounded_max:
        raise ValueError(
            f"ledger range span ({span}) exceeds maximum allowed span ({bounded_max})"
        )
    return start, end


def fetch_contract_events_in_range(
    *,
    rpc_url: str,
    contract_id: str,
    start_ledger: int,
    end_ledger: int,
    page_limit: int = INDEXER_DEFAULT_PAGE_SIZE,
    timeout: float = INDEXER_DEFAULT_TIMEOUT,
    max_pages: int = MAX_RECONCILE_PAGES,
) -> list[dict[str, Any]]:
    """Read-only bounded scan of Soroban contract events within ``[start_ledger, end_ledger]``."""
    start, end = validate_reconcile_ledger_range(start_ledger, end_ledger)
    collected: list[dict[str, Any]] = []
    cursor: str | None = None
    pages_fetched = 0

    while True:
        if pages_fetched >= max_pages:
            raise RuntimeError(
                f"reconciliation scan exceeded maximum page budget ({max_pages})"
            )
        pages_fetched += 1
        rpc_result = fetch_contract_events(
            rpc_url=rpc_url,
            contract_id=contract_id,
            start_ledger=start if cursor is None else None,
            cursor=cursor,
            limit=page_limit,
            timeout=timeout,
        )
        page_events = rpc_result.get("events") or []
        if not page_events:
            break

        reached_past_end = False
        for ev in page_events:
            if not isinstance(ev, dict):
                continue
            ev_ledger = _extract_event_ledger(ev)
            if ev_ledger is not None and ev_ledger > end:
                reached_past_end = True
                break
            if ev_ledger is None or ev_ledger >= start:
                collected.append(ev)

        if reached_past_end:
            break

        next_cursor = rpc_result.get("cursor")
        if not next_cursor:
            last_id = page_events[-1].get("id") or page_events[-1].get("pagingToken")
            next_cursor = str(last_id) if last_id else None

        if not next_cursor or next_cursor == cursor:
            break
        cursor = str(next_cursor)

    return collected


def _normalize_Comparable_record(
    *,
    event_type: Any,
    proof_id: Any,
    contract_id: Any,
    tx_status: Any,
    metadata: Any,
) -> dict[str, Any]:
    norm_meta = dict(metadata) if isinstance(metadata, dict) else None
    if isinstance(norm_meta, dict):
        norm_meta.pop("canonical_order", None)
    return {
        "event_type": str(event_type or ""),
        "proof_id": _normalize_hex(proof_id) if proof_id is not None else None,
        "contract_id": str(contract_id).strip() if contract_id else None,
        "tx_status": str(tx_status or "confirmed"),
        "metadata": norm_meta,
    }


def reconcile_projection_range(
    *,
    start_ledger: int,
    end_ledger: int,
    contract_id: str | None = None,
    rpc_url: str | None = None,
    chain_events: list[dict[str, Any]] | None = None,
    indexed_records: list[dict[str, Any]] | None = None,
    verify_tx: bool = False,
    max_span: int = MAX_RECONCILE_LEDGER_SPAN,
    page_limit: int = INDEXER_DEFAULT_PAGE_SIZE,
    timeout: float = INDEXER_DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Compare a bounded chain ledger range against indexed proof records (read-only).

    Distinguishes ``missing_events`` (present on-chain in ``[start_ledger, end_ledger]``
    but absent from the indexed projection) from ``conflicting_state`` (present in
    both with mismatched projection attributes, unanchored indexed rows claiming a
    ledger in ``[start_ledger, end_ledger]``, or Horizon transaction verification
    conflicts). Never mutates ``proof_events`` or ``indexer_state``.
    """
    start, end = validate_reconcile_ledger_range(
        start_ledger,
        end_ledger,
        max_span=max_span,
    )
    active_contract_id = (
        contract_id
        or os.getenv("HARPOCRATES_REGISTRY_CONTRACT_ID")
        or os.getenv("CONTRACT_ID")
    )
    if chain_events is None and not active_contract_id:
        raise ValueError("contract_id is required when fetching chain events from RPC")

    active_rpc_url = (
        rpc_url
        or os.getenv("SOROBAN_RPC_URL")
        or os.getenv("STELLAR_RPC_URL")
        or DEFAULT_SOROBAN_RPC_URL
    )

    raw_events = (
        fetch_contract_events_in_range(
            rpc_url=active_rpc_url,
            contract_id=str(active_contract_id),
            start_ledger=start,
            end_ledger=end,
            page_limit=page_limit,
            timeout=timeout,
        )
        if chain_events is None
        else list(chain_events)
    )

    on_chain_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    scanned_chain_events = 0
    skipped_unknown_events = 0

    for raw in raw_events:
        if not isinstance(raw, dict):
            continue
        ev_ledger = _extract_event_ledger(raw)
        if ev_ledger is not None and (ev_ledger < start or ev_ledger > end):
            continue
        scanned_chain_events += 1
        decoded = classify_and_decode_event(raw, default_contract_id=active_contract_id)
        if decoded is None:
            skipped_unknown_events += 1
            continue

        key = (decoded.tx_hash, int(decoded.event_index))
        if key not in on_chain_by_key:
            on_chain_by_key[key] = {
                "ledger": ev_ledger if ev_ledger is not None else decoded.ledger,
                "tx_hash": decoded.tx_hash,
                "event_index": int(decoded.event_index),
                "state": _normalize_Comparable_record(
                    event_type=decoded.event_type,
                    proof_id=decoded.proof_id,
                    contract_id=decoded.contract_id,
                    tx_status=decoded.tx_status,
                    metadata=decoded.metadata,
                ),
            }

    db_rows = (
        list_indexed_proof_events_for_reconcile(contract_id=active_contract_id)
        if indexed_records is None
        else list(indexed_records)
    )
    indexed_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    for row in db_rows:
        if not isinstance(row, dict):
            continue
        raw_tx = row.get("tx_hash")
        raw_idx = row.get("event_index")
        if not raw_tx or raw_idx is None or isinstance(raw_idx, bool):
            continue
        norm_tx = _normalize_hex(raw_tx) or str(raw_tx).strip().lower()
        norm_idx = int(raw_idx)
        key = (norm_tx, norm_idx)
        row_ledger = _extract_record_ledger(row)

        # Include row if it matches an on-chain key in [start, end] OR declares a ledger in [start, end].
        if key in on_chain_by_key or (row_ledger is not None and start <= row_ledger <= end):
            if key not in indexed_by_key:
                indexed_by_key[key] = {
                    "ledger": row_ledger,
                    "tx_hash": norm_tx,
                    "event_index": norm_idx,
                    "state": _normalize_Comparable_record(
                        event_type=row.get("event_type"),
                        proof_id=row.get("proof_id"),
                        contract_id=row.get("contract_id"),
                        tx_status=row.get("tx_status"),
                        metadata=row.get("metadata"),
                    ),
                }

    missing_events: list[dict[str, Any]] = []
    conflicting_state: list[dict[str, Any]] = []
    matched_count = 0
    tx_verification_cache: dict[str, Any] = {}

    for key in sorted(on_chain_by_key.keys()):
        expected_item = on_chain_by_key[key]
        if key not in indexed_by_key:
            missing_events.append(
                {
                    "category": "missing_event",
                    "ledger": expected_item["ledger"],
                    "tx_hash": key[0],
                    "event_index": key[1],
                    "expected": expected_item["state"],
                }
            )
            continue

        indexed_item = indexed_by_key[key]
        mismatched_fields = [
            field
            for field in _RECONCILE_COMPARE_FIELDS
            if expected_item["state"].get(field) != indexed_item["state"].get(field)
        ]
        if mismatched_fields:
            conflicting_state.append(
                {
                    "category": "conflicting_state",
                    "reason": "field_mismatch",
                    "ledger": expected_item["ledger"],
                    "tx_hash": key[0],
                    "event_index": key[1],
                    "mismatched_fields": mismatched_fields,
                    "expected": expected_item["state"],
                    "indexed": indexed_item["state"],
                }
            )
            continue

        if verify_tx:
            tx_hash = key[0]
            if tx_hash not in tx_verification_cache:
                tx_verification_cache[tx_hash] = verify_transaction(tx_hash)
            tx_res = tx_verification_cache[tx_hash]
            if tx_res.status in {"failed", "missing"} and indexed_item["state"]["tx_status"] in {
                "confirmed",
                "revoked",
            }:
                conflicting_state.append(
                    {
                        "category": "conflicting_state",
                        "reason": "tx_verification_conflict",
                        "ledger": expected_item["ledger"],
                        "tx_hash": tx_hash,
                        "event_index": key[1],
                        "horizon_status": tx_res.status,
                        "horizon_reason": tx_res.reason,
                        "indexed": indexed_item["state"],
                    }
                )
                continue

        matched_count += 1

    # Detect indexed records claiming a ledger inside [start, end] that do not exist on-chain.
    for key in sorted(indexed_by_key.keys()):
        if key not in on_chain_by_key:
            indexed_item = indexed_by_key[key]
            conflicting_state.append(
                {
                    "category": "conflicting_state",
                    "reason": "unanchored_indexed_event",
                    "ledger": indexed_item["ledger"],
                    "tx_hash": key[0],
                    "event_index": key[1],
                    "indexed": indexed_item["state"],
                }
            )

    in_sync = not missing_events and not conflicting_state
    return {
        "ok": in_sync,
        "read_only": True,
        "contract_id": active_contract_id,
        "range": {
            "start_ledger": start,
            "end_ledger": end,
            "span": end - start + 1,
        },
        "summary": {
            "scanned_chain_events": scanned_chain_events,
            "lifecycle_chain_events": len(on_chain_by_key),
            "skipped_unknown_events": skipped_unknown_events,
            "matched": matched_count,
            "missing_count": len(missing_events),
            "conflicting_count": len(conflicting_state),
        },
        "missing_events": missing_events,
        "conflicting_state": conflicting_state,
    }


# ---------------------------------------------------------------------------
# Polling & Worker Loop
# ---------------------------------------------------------------------------


def poll_indexer_once(
    contract_id: str | None = None,
    rpc_url: str | None = None,
    limit: int = INDEXER_DEFAULT_PAGE_SIZE,
    timeout: float = INDEXER_DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Execute one indexing cycle: fetch, ingest, and persist cursor."""
    active_contract_id = contract_id or os.getenv("HARPOCRATES_REGISTRY_CONTRACT_ID") or os.getenv("CONTRACT_ID")
    if not active_contract_id:
        return {"scanned": 0, "indexed": 0, "skipped": 0, "duplicates": 0, "reason": "no_contract_id"}

    active_rpc_url = rpc_url or os.getenv("SOROBAN_RPC_URL") or os.getenv("STELLAR_RPC_URL") or DEFAULT_SOROBAN_RPC_URL

    cursor = get_indexer_cursor()
    start_ledger = None

    if not cursor:
        cursor = None
        # Out of scope: backfilling history before the first cursor.
        # Query latest ledger on fresh startup to start from head.
        latest = fetch_latest_ledger(active_rpc_url, timeout=timeout)
        start_ledger = latest

    rpc_result = fetch_contract_events(
        rpc_url=active_rpc_url,
        contract_id=active_contract_id,
        start_ledger=start_ledger,
        cursor=cursor,
        limit=limit,
        timeout=timeout,
    )

    events = rpc_result.get("events") or []
    summary = process_events_batch(events, contract_id=active_contract_id)

    new_cursor = rpc_result.get("cursor")
    latest_ledger = rpc_result.get("latestLedger")

    if new_cursor and new_cursor != cursor:
        save_indexer_cursor(cursor=new_cursor, ledger=latest_ledger)
        summary["new_cursor"] = new_cursor
    elif events and not new_cursor:
        # If RPC provides event IDs without top-level cursor, use last event's id/pagingToken
        last_id = events[-1].get("id") or events[-1].get("pagingToken")
        if last_id:
            save_indexer_cursor(cursor=str(last_id), ledger=latest_ledger)
            summary["new_cursor"] = str(last_id)

    return summary


def run_indexer_loop(
    stop_event: threading.Event,
    contract_id: str | None = None,
    rpc_url: str | None = None,
    poll_interval: float = INDEXER_DEFAULT_POLL_INTERVAL,
    initial_backoff: float = 1.0,
    max_backoff: float = 60.0,
) -> None:
    """Run indexer polling in a loop with exponential error backoff."""
    LOGGER.info("Starting on-chain contract events indexer loop")
    backoff = initial_backoff

    while not stop_event.is_set():
        try:
            summary = poll_indexer_once(
                contract_id=contract_id,
                rpc_url=rpc_url,
            )
            backoff = initial_backoff  # Reset backoff on success
            if summary.get("indexed", 0) > 0 or summary.get("skipped", 0) > 0:
                LOGGER.info(
                    "chain_indexer_batch scanned=%s indexed=%s skipped=%s duplicates=%s",
                    summary.get("scanned"),
                    summary.get("indexed"),
                    summary.get("skipped"),
                    summary.get("duplicates"),
                )
            stop_event.wait(poll_interval)
        except Exception as exc:
            LOGGER.warning(
                "chain_indexer_poll_error err_type=%s msg=%s backoff=%.1fs",
                type(exc).__name__,
                exc,
                backoff,
            )
            stop_event.wait(backoff)
            backoff = min(max_backoff, backoff * 2.0)
