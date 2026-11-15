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
import hashlib
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
    list_indexed_proof_events_snapshot,
    save_indexer_cursor,
)
from fetch_external import safe_urlopen
from metrics import collector
from strkey import (
    _VERSION_BYTE_CONTRACT,
    _VERSION_BYTE_ED25519_PUBLIC,
    make_strkey,
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
INDEXER_MAX_DRY_RUN_EVENTS = 10000
PROJECTION_FINGERPRINT_DOMAIN = "harpocrates:indexer-projection:v1"


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
# Index Rebuild Dry-Run & Deterministic Projection Fingerprints
# ---------------------------------------------------------------------------

_PROJECTION_COMPARE_FIELDS = (
    "event_type",
    "proof_id",
    "contract_id",
    "tx_status",
    "metadata",
)


def _canonicalize_json_value(value: Any) -> Any:
    """Normalize nested dicts/lists into deterministic JSON-compatible structures."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return value.hex().lower()
    if isinstance(value, (list, tuple)):
        return [_canonicalize_json_value(item) for item in value]
    if isinstance(value, dict):
        return {
            str(k): _canonicalize_json_value(v)
            for k, v in sorted(value.items(), key=lambda item: str(item[0]))
        }
    return str(value)


def canonical_projection_entry(record: dict[str, Any]) -> dict[str, Any]:
    """Extract canonical, insertion-order-independent projection attributes."""
    if not isinstance(record, dict):
        raise ValueError("projection record must be a mapping")

    raw_tx_hash = record.get("tx_hash")
    if not raw_tx_hash or not isinstance(raw_tx_hash, str):
        raise ValueError("projection record requires a non-empty tx_hash string")
    tx_hash = _normalize_hex(raw_tx_hash) or raw_tx_hash.strip().lower()

    raw_event_index = record.get("event_index")
    if raw_event_index is None or isinstance(raw_event_index, bool):
        raise ValueError("projection record requires an integer event_index")
    try:
        event_index = int(raw_event_index)
    except (TypeError, ValueError) as exc:
        raise ValueError("projection record requires an integer event_index") from exc
    if event_index < 0:
        raise ValueError("projection record event_index must be non-negative")

    raw_proof_id = record.get("proof_id")
    proof_id = _normalize_hex(raw_proof_id) if raw_proof_id is not None else None

    raw_contract_id = record.get("contract_id")
    contract_id = str(raw_contract_id).strip() if raw_contract_id else None

    raw_metadata = record.get("metadata")
    metadata = (
        _canonicalize_json_value(raw_metadata)
        if isinstance(raw_metadata, dict)
        else None
    )

    return {
        "tx_hash": tx_hash,
        "event_index": event_index,
        "event_type": str(record.get("event_type") or ""),
        "proof_id": proof_id,
        "contract_id": contract_id,
        "tx_status": str(record.get("tx_status") or "confirmed"),
        "metadata": metadata,
    }


def compute_projection_fingerprint(records: list[dict[str, Any]]) -> str:
    """Compute a deterministic domain-separated SHA-256 fingerprint for a projection.

    Entries are deduplicated on ``(tx_hash, event_index)`` (first-seen wins,
    matching idempotent live ingestion) and sorted canonically by
    ``(tx_hash, event_index)``. Volatile database fields such as ``id`` and
    ``created_at`` are excluded.
    """
    if not isinstance(records, (list, tuple)):
        raise ValueError("records must be a sequence of mappings")

    by_key: dict[tuple[str, int], dict[str, Any]] = {}
    for record in records:
        entry = canonical_projection_entry(record)
        key = (entry["tx_hash"], entry["event_index"])
        if key not in by_key:
            by_key[key] = entry

    ordered = [by_key[key] for key in sorted(by_key.keys())]
    serialized = json.dumps(
        ordered,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    material = f"{PROJECTION_FINGERPRINT_DOMAIN}\x00{serialized}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def reconstruct_temporary_projection(
    events: list[dict[str, Any]],
    *,
    contract_id: str | None = None,
) -> dict[str, Any]:
    """Reconstruct an isolated temporary projection from synthetic or replayed events.

    Performs zero database writes, zero cursor updates, zero metrics mutations,
    and zero webhook queueing.
    """
    if not isinstance(events, (list, tuple)):
        raise ValueError("events must be a list of Soroban event objects")
    if len(events) > INDEXER_MAX_DRY_RUN_EVENTS:
        raise ValueError(
            f"events exceeds maximum dry-run batch size ({INDEXER_MAX_DRY_RUN_EVENTS})"
        )

    temp_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    summary = {
        "scanned": 0,
        "projected": 0,
        "skipped": 0,
        "duplicates": 0,
    }

    for raw in events:
        summary["scanned"] += 1
        decoded = classify_and_decode_event(raw, default_contract_id=contract_id)
        if decoded is None:
            summary["skipped"] += 1
            continue

        entry = canonical_projection_entry(
            {
                "event_type": decoded.event_type,
                "proof_id": decoded.proof_id,
                "tx_hash": decoded.tx_hash,
                "event_index": decoded.event_index,
                "contract_id": decoded.contract_id,
                "tx_status": decoded.tx_status,
                "metadata": decoded.metadata,
            }
        )
        key = (entry["tx_hash"], entry["event_index"])
        if key in temp_by_key:
            summary["duplicates"] += 1
            continue

        temp_by_key[key] = entry
        summary["projected"] += 1

    ordered_records = [temp_by_key[key] for key in sorted(temp_by_key.keys())]
    return {
        "summary": summary,
        "records": ordered_records,
        "fingerprint": compute_projection_fingerprint(ordered_records),
    }


def dry_run_index_rebuild(
    events: list[dict[str, Any]],
    *,
    live_records: list[dict[str, Any]] | None = None,
    contract_id: str | None = None,
) -> dict[str, Any]:
    """Rebuild a temporary projection from *events* and diff against the live index.

    Never mutates ``proof_events``, ``indexer_state``, metrics, or webhook queues.
    """
    rebuilt = reconstruct_temporary_projection(events, contract_id=contract_id)
    rebuilt_records: list[dict[str, Any]] = rebuilt["records"]
    rebuilt_fingerprint: str = rebuilt["fingerprint"]

    snapshot = (
        list_indexed_proof_events_snapshot(
            contract_id=contract_id,
            limit=INDEXER_MAX_DRY_RUN_EVENTS,
        )
        if live_records is None
        else live_records
    )
    if not isinstance(snapshot, (list, tuple)):
        raise ValueError("live_records must be a list of proof-event mappings")

    live_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    for row in snapshot:
        entry = canonical_projection_entry(row)
        key = (entry["tx_hash"], entry["event_index"])
        if key not in live_by_key:
            live_by_key[key] = entry

    rebuilt_by_key = {
        (entry["tx_hash"], entry["event_index"]): entry for entry in rebuilt_records
    }
    live_ordered = [live_by_key[key] for key in sorted(live_by_key.keys())]
    live_fingerprint = compute_projection_fingerprint(live_ordered)

    all_keys = sorted(set(rebuilt_by_key.keys()) | set(live_by_key.keys()))
    missing_in_live: list[dict[str, Any]] = []
    extra_in_live: list[dict[str, Any]] = []
    mismatched: list[dict[str, Any]] = []

    for key in all_keys:
        in_rebuilt = key in rebuilt_by_key
        in_live = key in live_by_key
        if in_rebuilt and not in_live:
            missing_in_live.append(
                {
                    "tx_hash": key[0],
                    "event_index": key[1],
                    "rebuilt": rebuilt_by_key[key],
                }
            )
        elif in_live and not in_rebuilt:
            extra_in_live.append(
                {
                    "tx_hash": key[0],
                    "event_index": key[1],
                    "live": live_by_key[key],
                }
            )
        else:
            rebuilt_entry = rebuilt_by_key[key]
            live_entry = live_by_key[key]
            differing_fields = [
                field
                for field in _PROJECTION_COMPARE_FIELDS
                if rebuilt_entry.get(field) != live_entry.get(field)
            ]
            if differing_fields:
                mismatched.append(
                    {
                        "tx_hash": key[0],
                        "event_index": key[1],
                        "differing_fields": differing_fields,
                        "live": live_entry,
                        "rebuilt": rebuilt_entry,
                    }
                )

    in_sync = (
        rebuilt_fingerprint == live_fingerprint
        and not missing_in_live
        and not extra_in_live
        and not mismatched
    )

    return {
        "dry_run": True,
        "in_sync": in_sync,
        "domain": PROJECTION_FINGERPRINT_DOMAIN,
        "rebuilt_fingerprint": rebuilt_fingerprint,
        "live_fingerprint": live_fingerprint,
        "summary": {
            **rebuilt["summary"],
            "live_count": len(live_by_key),
            "rebuilt_count": len(rebuilt_by_key),
            "missing_in_live_count": len(missing_in_live),
            "extra_in_live_count": len(extra_in_live),
            "mismatched_count": len(mismatched),
        },
        "differences": {
            "missing_in_live": missing_in_live,
            "extra_in_live": extra_in_live,
            "mismatched": mismatched,
        },
    }


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
