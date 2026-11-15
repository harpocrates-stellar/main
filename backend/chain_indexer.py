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
from decimal import Decimal
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
from tx_verification import (
    UnsafeProofIdentifierError,
    normalize_proof_identifier,
    normalize_tx_hash,
    parse_strict_uint,
)
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
        if disc in (9, 10) and len(payload) >= 16:  # SCV_U128, SCV_I128
            hi_fmt = ">Q" if disc == 9 else ">q"
            hi = struct.unpack(hi_fmt, payload[:8])[0]
            lo = struct.unpack(">Q", payload[8:16])[0]
            return (hi << 64) | lo
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


def _json_safe_metadata_value(value: Any) -> Any:
    """Ensure metadata values preserve large integers as exact strings and reject floats/Decimals."""
    if isinstance(value, (float, Decimal)):
        raise UnsafeProofIdentifierError("fractional or exponent notation is rejected in indexed event payloads")
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        # Preserve exact decimal representation when outside IEEE-754 safe integer range
        if abs(value) > 9_007_199_254_740_991:
            return f"{value:d}"
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe_metadata_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe_metadata_value(v) for v in value]
    return value


# ---------------------------------------------------------------------------
# Lifecycle Topic Classifier
# ---------------------------------------------------------------------------


def classify_and_decode_event(
    event: dict[str, Any],
    default_contract_id: str | None = None,
) -> DecodedLifecycleEvent | None:
    """Parse a Soroban RPC event and decode it if it matches a known lifecycle topic.

    Returns DecodedLifecycleEvent if recognized, None if unknown/unhandled, or
    raises UnsafeProofIdentifierError when an indexed identifier or integer uses
    unsafe float, fractional, boolean, or exponent coercion.
    """
    if not isinstance(event, dict):
        return None

    # Resolve tx_hash
    tx_hash_raw = (
        event.get("txHash")
        or event.get("transactionHash")
        or event.get("tx_hash")
    )
    if tx_hash_raw is None:
        return None
    if isinstance(tx_hash_raw, (bool, int, float, Decimal)):
        raise UnsafeProofIdentifierError("txHash must be a 32-byte hex string")
    if not isinstance(tx_hash_raw, str) or not tx_hash_raw.strip():
        return None
    try:
        tx_hash = normalize_tx_hash(tx_hash_raw)
    except ValueError as exc:
        raise UnsafeProofIdentifierError("txHash must be a 32-byte hex string") from exc

    # Resolve event index strictly without float/exponent coercion
    event_index_raw = event.get("eventIndex")
    if event_index_raw is None and "event_index" in event:
        event_index_raw = event.get("event_index")
    if event_index_raw is None:
        token_raw = event.get("id") or event.get("pagingToken")
        if token_raw is not None:
            if isinstance(token_raw, (bool, float, Decimal)):
                raise UnsafeProofIdentifierError("paging token must not use float or boolean coercion")
            token = str(token_raw)
            if "-" in token:
                event_index = parse_strict_uint(
                    token.split("-")[-1],
                    field="event_index",
                    allow_zero_padded_str=True,
                )
            else:
                event_index = 0
        else:
            event_index = 0
    else:
        event_index = parse_strict_uint(
            event_index_raw,
            field="event_index",
            allow_zero_padded_str=True,
        )

    contract_id = (
        event.get("contractId")
        or event.get("contract_id")
        or default_contract_id
    )
    ledger_raw = event.get("ledger")
    ledger = (
        parse_strict_uint(ledger_raw, field="ledger")
        if ledger_raw is not None
        else None
    )

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
        proof_id = normalize_proof_identifier(topics[2], field="proof_id")
        safe_val = _json_safe_metadata_value(val)
        return DecodedLifecycleEvent(
            event_type="revoke",
            proof_id=proof_id,
            tx_hash=tx_hash,
            event_index=event_index,
            contract_id=contract_id,
            tx_status="revoked",
            metadata={"status": "revoked", "raw_value": safe_val},
            ledger=ledger,
        )

    # 2. Proof History: topics = ["proof", "history", proof_id]
    if first == "proof" and second == "history" and len(topics) >= 3:
        proof_id = normalize_proof_identifier(topics[2], field="proof_id")
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
        elif isinstance(val, (int, float, Decimal, str)):
            action = val

        action_int = (
            parse_strict_uint(action, field="action")
            if action is not None
            else 0
        )
        safe_reason = (
            parse_strict_uint(reason_code, field="reason_code")
            if reason_code is not None
            else None
        )

        if action_int == 3:  # Revoked
            return DecodedLifecycleEvent(
                event_type="revoke",
                proof_id=proof_id,
                tx_hash=tx_hash,
                event_index=event_index,
                contract_id=contract_id,
                tx_status="revoked",
                metadata={"action": "revoked", "actor": actor, "reason_code": safe_reason},
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
                metadata={"action": "expired", "actor": actor, "reason_code": safe_reason},
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
                metadata={"action": "corrected", "actor": actor, "reason_code": safe_reason},
                ledger=ledger,
            )

    # 3. Dispute Lifecycle Events: topics = ["dispute", action, dispute_id, proof_id]
    if first == "dispute" and len(topics) >= 2:
        action = second
        if action in ("open", "resolve", "supersede", "dismiss"):
            dispute_id = (
                normalize_proof_identifier(topics[2], field="dispute_id")
                if len(topics) >= 3
                else None
            )
            proof_id = (
                normalize_proof_identifier(topics[3], field="proof_id")
                if len(topics) >= 4
                else None
            )
            if proof_id is None and len(topics) == 3:
                proof_id = dispute_id

            safe_details = _json_safe_metadata_value(val)
            if action == "open":
                return DecodedLifecycleEvent(
                    event_type="dispute_open",
                    proof_id=proof_id,
                    tx_hash=tx_hash,
                    event_index=event_index,
                    contract_id=contract_id,
                    tx_status="confirmed",
                    metadata={"dispute_id": dispute_id, "stage": "open", "details": safe_details},
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
                    metadata={"dispute_id": dispute_id, "stage": "resolved", "details": safe_details},
                    ledger=ledger,
                )
            if action == "supersede":
                superseded_by = None
                if isinstance(val, dict) and val.get("superseded_by") is not None:
                    superseded_by = normalize_proof_identifier(
                        val.get("superseded_by"),
                        field="superseded_by",
                    )
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
                        "details": safe_details,
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
                    metadata={"dispute_id": dispute_id, "stage": "dismissed", "details": safe_details},
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

    Decodes lifecycle events, rejects unsafe integer/identifier coercions,
    inserts valid events idempotently into proof_events, queues webhooks, and
    tracks unknown topics.
    """
    summary: dict[str, Any] = {
        "scanned": 0,
        "indexed": 0,
        "skipped": 0,
        "duplicates": 0,
        "rejected_identifiers": 0,
        "rejection_reasons": [],
    }

    for raw in events:
        summary["scanned"] += 1
        try:
            decoded = classify_and_decode_event(raw, default_contract_id=contract_id)
        except UnsafeProofIdentifierError as exc:
            summary["rejected_identifiers"] += 1
            summary["rejection_reasons"].append(str(exc))
            continue

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
        data = json.loads(res.body.decode("utf-8"), parse_float=Decimal)
        result = data.get("result") or {}
        sequence = result.get("sequence") if result.get("sequence") is not None else result.get("latestLedger")
        return parse_strict_uint(sequence, field="sequence") if sequence is not None else None
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
    strict_limit = parse_strict_uint(limit, field="limit")
    page_limit = max(1, min(strict_limit, INDEXER_MAX_PAGE_SIZE))
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
        params["startLedger"] = parse_strict_uint(start_ledger, field="startLedger")

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
    data = json.loads(res.body.decode("utf-8"), parse_float=Decimal)
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
