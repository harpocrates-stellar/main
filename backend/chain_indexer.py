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
    save_indexer_cursor,
)
from fetch_external import safe_urlopen
from metrics import collector
from strkey import (
    _VERSION_BYTE_CONTRACT,
    _VERSION_BYTE_ED25519_PUBLIC,
    make_strkey,
)
from tx_verification import parse_stellar_toid
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


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CanonicalEventOrder:
    """Deterministic chain ordering coordinates independent of DB insertion time."""

    ledger: int
    tx_order: int | None
    tx_hash: str
    operation_order: int | None
    operation_id: str
    event_index: int

    def sort_key(self) -> tuple[int, int, int, str, int, int, str, int]:
        return (
            self.ledger,
            0 if self.tx_order is not None else 1,
            self.tx_order if self.tx_order is not None else 0,
            self.tx_hash,
            0 if self.operation_order is not None else 1,
            self.operation_order if self.operation_order is not None else 0,
            self.operation_id,
            self.event_index,
        )

    def to_metadata(self) -> dict[str, Any]:
        return {
            "ledger": self.ledger,
            "tx_order": self.tx_order,
            "tx_hash": self.tx_hash,
            "operation_order": self.operation_order,
            "operation_id": self.operation_id or None,
            "event_index": self.event_index,
        }


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
    canonical_order: CanonicalEventOrder | None = None


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


def _parse_non_negative_int_field(raw: Any, field_name: str) -> int | None:
    """Parse an optional non-negative integer coordinate, failing closed on bad values."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ValueError(f"{field_name} must be a non-negative integer, got boolean")
    if isinstance(raw, int):
        val = raw
    elif isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            raise ValueError(f"{field_name} must be a non-negative integer")
        try:
            val = int(stripped, 10)
        except ValueError as exc:
            raise ValueError(f"{field_name} must be a non-negative integer") from exc
    else:
        raise ValueError(f"{field_name} must be a non-negative integer")
    if val < 0:
        raise ValueError(f"{field_name} must be non-negative")
    return val


def extract_canonical_event_order(event: dict[str, Any]) -> CanonicalEventOrder:
    """Extract canonical chain ordering coordinates from a raw Soroban RPC event.

    Uses ``(ledger, tx_order, tx_hash, operation_order, operation_id, event_index)``
    so multiple events sharing a ledger are ordered deterministically by
    transaction and operation identity rather than arrival or DB insertion time.
    """
    if not isinstance(event, dict):
        raise ValueError("event must be a mapping")

    raw_tx = (
        event.get("txHash")
        or event.get("transactionHash")
        or event.get("tx_hash")
    )
    tx_hash = (_normalize_hex(raw_tx) or str(raw_tx).strip().lower()) if isinstance(raw_tx, str) and raw_tx.strip() else ""

    explicit_ledger = _parse_non_negative_int_field(event.get("ledger"), "ledger")

    raw_tx_order = None
    for key in ("txIndex", "tx_index", "transactionIndex", "transaction_index", "txOrder", "tx_order"):
        if key in event and event.get(key) is not None:
            raw_tx_order = event.get(key)
            break
    tx_order = _parse_non_negative_int_field(raw_tx_order, "tx_index")

    raw_op_order = None
    for key in ("operationIndex", "operation_index", "opIndex", "op_index", "operationOrder", "operation_order"):
        if key in event and event.get(key) is not None:
            raw_op_order = event.get(key)
            break
    operation_order = _parse_non_negative_int_field(raw_op_order, "operation_index")

    raw_op_id = None
    for key in ("operationId", "operation_id", "opId", "op_id"):
        if key in event and event.get(key) is not None:
            raw_op_id = event.get(key)
            break
    if isinstance(raw_op_id, bool):
        raise ValueError("operation_id must not be a boolean")
    operation_id = str(raw_op_id).strip() if raw_op_id is not None else ""

    raw_event_index = event.get("eventIndex")
    if raw_event_index is None:
        raw_event_index = event.get("event_index")
    explicit_event_index = _parse_non_negative_int_field(raw_event_index, "event_index")

    token_ledger: int | None = None
    token_tx_order: int | None = None
    token_op_order: int | None = None
    token_event_index: int | None = None

    token = str(event.get("id") or event.get("pagingToken") or "").strip()
    if token and "-" in token:
        parts = token.split("-")
        try:
            first_num = int(parts[0], 10)
            last_num = int(parts[-1], 10)
        except ValueError:
            first_num = None
            last_num = None

        if first_num is not None and first_num >= 0:
            try:
                parsed_toid = parse_stellar_toid(first_num)
            except ValueError:
                parsed_toid = None
            if parsed_toid is not None:
                token_ledger, token_tx_order, token_op_order = parsed_toid
            else:
                token_ledger = first_num

        if len(parts) == 3 and token_op_order is None:
            try:
                mid_num = int(parts[1], 10)
                if mid_num >= 0:
                    token_op_order = mid_num
            except ValueError:
                pass
        elif len(parts) >= 4:
            try:
                t_idx = int(parts[1], 10)
                o_idx = int(parts[2], 10)
                if t_idx >= 0 and token_tx_order is None:
                    token_tx_order = t_idx
                if o_idx >= 0 and token_op_order is None:
                    token_op_order = o_idx
            except ValueError:
                pass

        if last_num is not None and last_num >= 0:
            token_event_index = last_num

    resolved_ledger = explicit_ledger if explicit_ledger is not None else (token_ledger if token_ledger is not None else 0)
    resolved_tx_order = tx_order if tx_order is not None else token_tx_order
    resolved_op_order = operation_order if operation_order is not None else token_op_order
    resolved_event_index = (
        explicit_event_index
        if explicit_event_index is not None
        else (token_event_index if token_event_index is not None else 0)
    )

    if not operation_id and resolved_op_order is not None and tx_hash:
        operation_id = f"{tx_hash}:{resolved_op_order}"

    return CanonicalEventOrder(
        ledger=resolved_ledger,
        tx_order=resolved_tx_order,
        tx_hash=tx_hash,
        operation_order=resolved_op_order,
        operation_id=operation_id,
        event_index=resolved_event_index,
    )


def sort_events_canonically(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a new list of raw Soroban events ordered by canonical chain coordinates.

    Events sharing a ledger are ordered by transaction identity (``tx_order``,
    ``tx_hash``), operation identity (``operation_order``, ``operation_id``),
    and ``event_index`` — never by arrival or database insertion time.
    """
    if not isinstance(events, (list, tuple)):
        raise ValueError("events must be a list of event mappings")

    keyed: list[tuple[tuple[Any, ...], int, dict[str, Any]]] = []
    for pos, raw in enumerate(events):
        if not isinstance(raw, dict):
            # Preserve non-dict entries at the end so classify_and_decode_event skips them cleanly.
            keyed.append(((1, 0, 1, 0, "", 1, 0, "", 0), pos, raw))
            continue
        order = extract_canonical_event_order(raw)
        keyed.append(((0, *order.sort_key()), pos, raw))

    keyed.sort(key=lambda item: item[0])
    return [item[2] for item in keyed]


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

    # Extract canonical chain ordering coordinates (fails closed on malformed explicit indices)
    order = extract_canonical_event_order(event)
    event_index = order.event_index

    contract_id = (
        event.get("contractId")
        or event.get("contract_id")
        or default_contract_id
    )
    ledger = event.get("ledger") if event.get("ledger") is not None else (order.ledger or None)

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
            canonical_order=order,
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
                canonical_order=order,
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
                canonical_order=order,
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
                canonical_order=order,
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
                canonical_order=order,
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
                canonical_order=order,
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
                canonical_order=order,
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
                canonical_order=order,
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
    """Ingest a list of raw Soroban RPC events in canonical chain order.

    Sorts events canonically by ``(ledger, tx_order, tx_hash, operation_order,
    operation_id, event_index)`` before ingestion so same-ledger events never
    depend on RPC or database insertion timing.
    """
    summary = {
        "scanned": 0,
        "indexed": 0,
        "skipped": 0,
        "duplicates": 0,
    }

    ordered_events = sort_events_canonically(events)

    for raw in ordered_events:
        summary["scanned"] += 1
        decoded = classify_and_decode_event(raw, default_contract_id=contract_id)

        if decoded is None:
            collector.record_indexer_unknown_topic()
            summary["skipped"] += 1
            continue

        persisted_metadata = dict(decoded.metadata) if isinstance(decoded.metadata, dict) else {}
        if decoded.canonical_order is not None:
            persisted_metadata["canonical_order"] = decoded.canonical_order.to_metadata()

        row, created = insert_indexed_proof_event(
            event_type=decoded.event_type,
            proof_id=decoded.proof_id,
            tx_hash=decoded.tx_hash,
            event_index=decoded.event_index,
            contract_id=decoded.contract_id,
            tx_status=decoded.tx_status,
            metadata=persisted_metadata or None,
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
