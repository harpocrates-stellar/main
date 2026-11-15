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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

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
INDEXER_DEFAULT_MIN_PAGE_SIZE = 5
INDEXER_DEFAULT_SLOW_WRITE_THRESHOLD_MS = 250.0
INDEXER_DEFAULT_MAX_BATCH_WRITE_BUDGET_MS = 2000.0
INDEXER_DEFAULT_MAX_CONCURRENT_BATCHES = 1
INDEXER_DEFAULT_SLOW_COOLDOWN_SECONDS = 2.0


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


def _env_float(name: str, default: float, *, minimum: float = 0.0) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return max(minimum, float(raw))
    except ValueError:
        return default


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------


@dataclass
class IndexerBackpressurePolicy:
    """Bounded in-memory admission and adaptive batch policy for slow DB writes."""

    max_in_memory_events: int = INDEXER_MAX_PAGE_SIZE
    min_page_size: int = INDEXER_DEFAULT_MIN_PAGE_SIZE
    slow_write_threshold_ms: float = INDEXER_DEFAULT_SLOW_WRITE_THRESHOLD_MS
    max_batch_write_budget_ms: float = INDEXER_DEFAULT_MAX_BATCH_WRITE_BUDGET_MS
    max_concurrent_batches: int = INDEXER_DEFAULT_MAX_CONCURRENT_BATCHES
    slow_cooldown_seconds: float = INDEXER_DEFAULT_SLOW_COOLDOWN_SECONDS
    effective_page_size: int = field(init=False)
    _semaphore: threading.BoundedSemaphore = field(init=False, repr=False)
    _lock: threading.Lock = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.max_in_memory_events < 1:
            raise ValueError("max_in_memory_events must be >= 1")
        if self.min_page_size < 1:
            raise ValueError("min_page_size must be >= 1")
        if self.max_concurrent_batches < 1:
            raise ValueError("max_concurrent_batches must be >= 1")
        if self.slow_write_threshold_ms <= 0:
            raise ValueError("slow_write_threshold_ms must be > 0")
        if self.max_batch_write_budget_ms <= 0:
            raise ValueError("max_batch_write_budget_ms must be > 0")
        self.min_page_size = min(self.min_page_size, self.max_in_memory_events)
        self.effective_page_size = min(INDEXER_MAX_PAGE_SIZE, self.max_in_memory_events)
        self._semaphore = threading.BoundedSemaphore(self.max_concurrent_batches)
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls) -> "IndexerBackpressurePolicy":
        max_mem = _env_int("INDEXER_MAX_IN_MEMORY_EVENTS", INDEXER_MAX_PAGE_SIZE)
        min_page = _env_int("INDEXER_MIN_PAGE_SIZE", INDEXER_DEFAULT_MIN_PAGE_SIZE)
        return cls(
            max_in_memory_events=max_mem,
            min_page_size=min(min_page, max_mem),
            slow_write_threshold_ms=_env_float(
                "INDEXER_SLOW_WRITE_THRESHOLD_MS",
                INDEXER_DEFAULT_SLOW_WRITE_THRESHOLD_MS,
                minimum=1.0,
            ),
            max_batch_write_budget_ms=_env_float(
                "INDEXER_MAX_BATCH_WRITE_BUDGET_MS",
                INDEXER_DEFAULT_MAX_BATCH_WRITE_BUDGET_MS,
                minimum=1.0,
            ),
            max_concurrent_batches=_env_int(
                "INDEXER_MAX_CONCURRENT_BATCHES",
                INDEXER_DEFAULT_MAX_CONCURRENT_BATCHES,
            ),
            slow_cooldown_seconds=_env_float(
                "INDEXER_SLOW_COOLDOWN_SECONDS",
                INDEXER_DEFAULT_SLOW_COOLDOWN_SECONDS,
                minimum=0.0,
            ),
        )

    def try_acquire_batch(self) -> bool:
        return self._semaphore.acquire(blocking=False)

    def release_batch(self) -> None:
        self._semaphore.release()

    def bounded_fetch_limit(self, requested_limit: int) -> int:
        with self._lock:
            cap = min(
                max(1, int(requested_limit)),
                INDEXER_MAX_PAGE_SIZE,
                self.max_in_memory_events,
                self.effective_page_size,
            )
            return max(1, cap)

    def observe_batch(self, *, slow_writes: int, budget_exhausted: bool) -> dict[str, Any]:
        with self._lock:
            throttled = slow_writes > 0 or budget_exhausted
            if throttled:
                halved = max(self.min_page_size, self.effective_page_size // 2)
                self.effective_page_size = min(self.max_in_memory_events, halved)
            else:
                recovered = self.effective_page_size + max(1, self.min_page_size)
                self.effective_page_size = min(
                    INDEXER_MAX_PAGE_SIZE,
                    self.max_in_memory_events,
                    recovered,
                )
            return {
                "throttled": throttled,
                "effective_page_size": self.effective_page_size,
                "cooldown_seconds": self.slow_cooldown_seconds if throttled else 0.0,
            }


_DEFAULT_BACKPRESSURE_POLICY = IndexerBackpressurePolicy.from_env()


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


def _event_paging_token(raw: dict[str, Any]) -> str | None:
    token = raw.get("id") or raw.get("pagingToken")
    if token is None:
        return None
    text = str(token).strip()
    return text or None


def process_events_batch(
    events: list[dict[str, Any]],
    contract_id: str | None = None,
    *,
    backpressure_policy: IndexerBackpressurePolicy | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Ingest a list of raw Soroban RPC events with bounded batch backpressure.

    Decodes lifecycle events, inserts them idempotently into proof_events,
    queues webhooks for newly written events, bounds in-memory batch size, and
    pauses early when database writes exceed the configured write budget.
    """
    policy = backpressure_policy or _DEFAULT_BACKPRESSURE_POLICY
    total_received = len(events)
    admitted_events = events[: policy.max_in_memory_events]
    capped_by_memory = max(0, total_received - len(admitted_events))

    summary: dict[str, Any] = {
        "scanned": 0,
        "indexed": 0,
        "skipped": 0,
        "duplicates": 0,
        "deferred": capped_by_memory,
    }

    slow_writes = 0
    total_write_ms = 0.0
    budget_exhausted = False
    contiguous_tokens = True
    last_safe_cursor: str | None = None
    last_safe_ledger: int | None = None

    for idx, raw in enumerate(admitted_events):
        summary["scanned"] += 1
        token = _event_paging_token(raw) if isinstance(raw, dict) else None
        raw_ledger = raw.get("ledger") if isinstance(raw, dict) else None

        decoded = classify_and_decode_event(raw, default_contract_id=contract_id)

        if decoded is None:
            collector.record_indexer_unknown_topic()
            summary["skipped"] += 1
            if contiguous_tokens and token:
                last_safe_cursor = token
                if isinstance(raw_ledger, int):
                    last_safe_ledger = raw_ledger
            else:
                contiguous_tokens = False
            continue

        started_at = clock()
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
        write_ms = max(0.0, (clock() - started_at) * 1000.0)
        total_write_ms += write_ms
        if write_ms >= policy.slow_write_threshold_ms:
            slow_writes += 1

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

        if contiguous_tokens and token:
            last_safe_cursor = token
            if isinstance(decoded.ledger, int):
                last_safe_ledger = decoded.ledger
        else:
            contiguous_tokens = False

        remaining_in_admitted = len(admitted_events) - (idx + 1)
        if remaining_in_admitted > 0 and total_write_ms >= policy.max_batch_write_budget_ms:
            budget_exhausted = True
            summary["deferred"] += remaining_in_admitted
            break

    observation = policy.observe_batch(
        slow_writes=slow_writes,
        budget_exhausted=budget_exhausted or capped_by_memory > 0,
    )
    summary["backpressure"] = {
        "status": "throttled" if (observation["throttled"] or summary["deferred"] > 0) else "normal",
        "throttled": bool(observation["throttled"] or summary["deferred"] > 0),
        "admitted": len(admitted_events),
        "slow_writes": slow_writes,
        "write_ms": round(total_write_ms, 3),
        "budget_exhausted": budget_exhausted,
        "capped_by_memory": capped_by_memory > 0,
        "effective_page_size": observation["effective_page_size"],
        "cooldown_seconds": observation["cooldown_seconds"],
        "last_safe_cursor": last_safe_cursor,
        "last_safe_ledger": last_safe_ledger,
    }
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
    *,
    backpressure_policy: IndexerBackpressurePolicy | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Execute one indexing cycle: bound admission, fetch, ingest, and safely checkpoint cursor."""
    active_contract_id = contract_id or os.getenv("HARPOCRATES_REGISTRY_CONTRACT_ID") or os.getenv("CONTRACT_ID")
    if not active_contract_id:
        return {"scanned": 0, "indexed": 0, "skipped": 0, "duplicates": 0, "reason": "no_contract_id"}

    policy = backpressure_policy or _DEFAULT_BACKPRESSURE_POLICY
    if not policy.try_acquire_batch():
        return {
            "scanned": 0,
            "indexed": 0,
            "skipped": 0,
            "duplicates": 0,
            "deferred": 0,
            "reason": "backpressure_admission_rejected",
            "backpressure": {
                "status": "admission_rejected",
                "throttled": True,
                "admitted": 0,
                "cooldown_seconds": policy.slow_cooldown_seconds,
            },
        }

    try:
        active_rpc_url = rpc_url or os.getenv("SOROBAN_RPC_URL") or os.getenv("STELLAR_RPC_URL") or DEFAULT_SOROBAN_RPC_URL

        cursor = get_indexer_cursor()
        start_ledger = None

        if not cursor:
            cursor = None
            # Out of scope: backfilling history before the first cursor.
            # Query latest ledger on fresh startup to start from head.
            latest = fetch_latest_ledger(active_rpc_url, timeout=timeout)
            start_ledger = latest

        fetch_limit = policy.bounded_fetch_limit(limit)
        rpc_result = fetch_contract_events(
            rpc_url=active_rpc_url,
            contract_id=active_contract_id,
            start_ledger=start_ledger,
            cursor=cursor,
            limit=fetch_limit,
            timeout=timeout,
        )

        events = rpc_result.get("events") or []
        summary = process_events_batch(
            events,
            contract_id=active_contract_id,
            backpressure_policy=policy,
            clock=clock,
        )

        new_cursor = rpc_result.get("cursor")
        latest_ledger = rpc_result.get("latestLedger")

        if summary.get("deferred", 0) > 0:
            # Partial page processed under backpressure: advance only up to the last
            # contiguous durably processed event token so unprocessed tail events are
            # fetched again on the next cycle (at-least-once + idempotent replay).
            bp = summary.get("backpressure") or {}
            safe_cursor = bp.get("last_safe_cursor")
            safe_ledger = bp.get("last_safe_ledger") or latest_ledger
            if safe_cursor and safe_cursor != cursor:
                save_indexer_cursor(cursor=safe_cursor, ledger=safe_ledger)
                summary["new_cursor"] = safe_cursor
        elif new_cursor and new_cursor != cursor:
            save_indexer_cursor(cursor=new_cursor, ledger=latest_ledger)
            summary["new_cursor"] = new_cursor
        elif events and not new_cursor:
            # If RPC provides event IDs without top-level cursor, use last event's id/pagingToken
            last_id = events[-1].get("id") or events[-1].get("pagingToken")
            if last_id:
                save_indexer_cursor(cursor=str(last_id), ledger=latest_ledger)
                summary["new_cursor"] = str(last_id)

        return summary
    finally:
        policy.release_batch()


def run_indexer_loop(
    stop_event: threading.Event,
    contract_id: str | None = None,
    rpc_url: str | None = None,
    poll_interval: float = INDEXER_DEFAULT_POLL_INTERVAL,
    initial_backoff: float = 1.0,
    max_backoff: float = 60.0,
    *,
    backpressure_policy: IndexerBackpressurePolicy | None = None,
) -> None:
    """Run indexer polling in a loop with exponential error backoff and write backpressure."""
    LOGGER.info("Starting on-chain contract events indexer loop")
    backoff = initial_backoff
    policy = backpressure_policy or _DEFAULT_BACKPRESSURE_POLICY

    while not stop_event.is_set():
        try:
            summary = poll_indexer_once(
                contract_id=contract_id,
                rpc_url=rpc_url,
                backpressure_policy=policy,
            )
            backoff = initial_backoff  # Reset backoff on success
            if summary.get("indexed", 0) > 0 or summary.get("skipped", 0) > 0:
                LOGGER.info(
                    "chain_indexer_batch scanned=%s indexed=%s skipped=%s duplicates=%s deferred=%s",
                    summary.get("scanned"),
                    summary.get("indexed"),
                    summary.get("skipped"),
                    summary.get("duplicates"),
                    summary.get("deferred", 0),
                )
            bp = summary.get("backpressure") or {}
            wait_seconds = max(poll_interval, float(bp.get("cooldown_seconds", 0.0)))
            stop_event.wait(wait_seconds)
        except Exception as exc:
            LOGGER.warning(
                "chain_indexer_poll_error err_type=%s msg=%s backoff=%.1fs",
                type(exc).__name__,
                exc,
                backoff,
            )
            stop_event.wait(backoff)
            backoff = min(max_backoff, backoff * 2.0)
