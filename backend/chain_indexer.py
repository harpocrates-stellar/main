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


class EventPageContractIdentityError(ValueError):
    """Raised when an event page contains a mismatched or changing contract identity."""

    def __init__(
        self,
        message: str,
        *,
        reason: str,
        expected_contract_id: str | None = None,
        observed_contract_id: str | None = None,
        event_position: int | None = None,
        tx_hash: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.expected_contract_id = expected_contract_id
        self.observed_contract_id = observed_contract_id
        self.event_position = event_position
        self.tx_hash = tx_hash


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


def normalize_contract_identity(raw: Any) -> str:
    """Normalize a Soroban contract identifier (strkey or base64 XDR SCV_ADDRESS)."""
    if isinstance(raw, bool) or raw is None:
        raise ValueError("contract identity must be a non-empty string")
    decoded = decode_scval(raw) if isinstance(raw, str) else raw
    if not isinstance(decoded, str):
        raise ValueError("contract identity must decode to a string")
    cleaned = decoded.strip()
    if not cleaned:
        raise ValueError("contract identity must be non-empty")
    if len(cleaned) == 56 and cleaned[0] in ("C", "c"):
        return cleaned.upper()
    return cleaned


def _require_explicit_contract_id_default() -> bool:
    raw = (os.getenv("INDEXER_REQUIRE_EXPLICIT_CONTRACT_ID") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def validate_event_page_contract_identity(
    events: list[dict[str, Any]],
    *,
    expected_contract_id: str | None = None,
    require_explicit: bool | None = None,
) -> str | None:
    """Validate that every event in *events* originates from one consistent contract.

    Runs prior to projection so a conflicting or mixed-contract page is rejected
    atomically before any database writes, webhook deliveries, or cursor updates.
    """
    if not isinstance(events, (list, tuple)):
        raise EventPageContractIdentityError(
            "event page must be a sequence of event objects",
            reason="malformed_event_page",
        )

    must_be_explicit = (
        _require_explicit_contract_id_default()
        if require_explicit is None
        else bool(require_explicit)
    )

    normalized_expected: str | None = None
    if expected_contract_id is not None:
        try:
            normalized_expected = normalize_contract_identity(expected_contract_id)
        except ValueError as exc:
            raise EventPageContractIdentityError(
                f"invalid expected_contract_id: {exc}",
                reason="invalid_expected_contract_id",
            ) from exc

    active_page_contract: str | None = normalized_expected
    saw_explicit_contract = False
    saw_implicit_contract = False

    for idx, raw in enumerate(events):
        if not isinstance(raw, dict):
            raise EventPageContractIdentityError(
                f"event at position {idx} must be a mapping",
                reason="malformed_event_entry",
                expected_contract_id=active_page_contract,
                event_position=idx,
            )

        ev_tx = raw.get("txHash") or raw.get("transactionHash") or raw.get("tx_hash")
        norm_tx = _normalize_hex(ev_tx) if isinstance(ev_tx, str) else None

        has_explicit_key = (
            "contractId" in raw or "contract_id" in raw or "sourceContractId" in raw
        )
        if has_explicit_key:
            raw_cid = (
                raw["contractId"]
                if "contractId" in raw
                else (
                    raw["contract_id"]
                    if "contract_id" in raw
                    else raw.get("sourceContractId")
                )
            )
            try:
                observed = normalize_contract_identity(raw_cid)
            except ValueError as exc:
                raise EventPageContractIdentityError(
                    f"event at position {idx} carries an invalid contractId",
                    reason="invalid_event_contract_id",
                    expected_contract_id=active_page_contract,
                    observed_contract_id=str(raw_cid) if raw_cid is not None else None,
                    event_position=idx,
                    tx_hash=norm_tx,
                ) from exc

            if saw_implicit_contract and normalized_expected is None:
                raise EventPageContractIdentityError(
                    f"event page mixes unbound and explicit contract identities at position {idx}",
                    reason="ambiguous_mixed_contract_identity",
                    expected_contract_id=active_page_contract,
                    observed_contract_id=observed,
                    event_position=idx,
                    tx_hash=norm_tx,
                )

            if active_page_contract is None:
                active_page_contract = observed
            elif observed != active_page_contract:
                reason = (
                    "mid_page_contract_change"
                    if saw_explicit_contract or idx > 0
                    else "contract_identity_mismatch"
                )
                raise EventPageContractIdentityError(
                    f"event at position {idx} has contractId {observed}, expected {active_page_contract}",
                    reason=reason,
                    expected_contract_id=active_page_contract,
                    observed_contract_id=observed,
                    event_position=idx,
                    tx_hash=norm_tx,
                )
            saw_explicit_contract = True
        else:
            if must_be_explicit:
                raise EventPageContractIdentityError(
                    f"event at position {idx} is missing explicit contractId",
                    reason="missing_event_contract_id",
                    expected_contract_id=active_page_contract,
                    event_position=idx,
                    tx_hash=norm_tx,
                )
            if saw_explicit_contract and normalized_expected is None:
                raise EventPageContractIdentityError(
                    f"event page drops explicit contractId at position {idx}",
                    reason="ambiguous_mixed_contract_identity",
                    expected_contract_id=active_page_contract,
                    event_position=idx,
                    tx_hash=norm_tx,
                )
            saw_implicit_contract = True

    return active_page_contract


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

    raw_cid = (
        event.get("contractId")
        if "contractId" in event
        else (
            event.get("contract_id")
            if "contract_id" in event
            else (
                event.get("sourceContractId")
                if "sourceContractId" in event
                else default_contract_id
            )
        )
    )
    try:
        contract_id = normalize_contract_identity(raw_cid) if raw_cid is not None else None
    except ValueError:
        return None
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
    *,
    require_explicit_contract_id: bool | None = None,
) -> dict[str, Any]:
    """Ingest a list of raw Soroban RPC events.

    Pre-validates the entire page's contract identity before projecting any row
    so a conflicting page never partially mutates ``proof_events``.
    """
    resolved_contract_id = validate_event_page_contract_identity(
        events,
        expected_contract_id=contract_id,
        require_explicit=require_explicit_contract_id,
    )

    summary = {
        "scanned": 0,
        "indexed": 0,
        "skipped": 0,
        "duplicates": 0,
    }

    for raw in events:
        summary["scanned"] += 1
        decoded = classify_and_decode_event(raw, default_contract_id=resolved_contract_id)

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
# Polling & Worker Loop
# ---------------------------------------------------------------------------


def poll_indexer_once(
    contract_id: str | None = None,
    rpc_url: str | None = None,
    limit: int = INDEXER_DEFAULT_PAGE_SIZE,
    timeout: float = INDEXER_DEFAULT_TIMEOUT,
    *,
    require_explicit_contract_id: bool | None = None,
) -> dict[str, Any]:
    """Execute one indexing cycle: fetch, validate source contract, ingest, and persist cursor."""
    raw_contract_id = contract_id or os.getenv("HARPOCRATES_REGISTRY_CONTRACT_ID") or os.getenv("CONTRACT_ID")
    if not raw_contract_id:
        return {"scanned": 0, "indexed": 0, "skipped": 0, "duplicates": 0, "reason": "no_contract_id"}
    active_contract_id = normalize_contract_identity(raw_contract_id)

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
    # Pre-validate the full page before projection or cursor commit; raises
    # EventPageContractIdentityError and leaves the committed cursor unchanged on conflict.
    summary = process_events_batch(
        events,
        contract_id=active_contract_id,
        require_explicit_contract_id=require_explicit_contract_id,
    )

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


def scan_contract_event_pages(
    contract_id: str,
    *,
    rpc_url: str | None = None,
    max_pages: int = 10,
    limit: int = INDEXER_DEFAULT_PAGE_SIZE,
    timeout: float = INDEXER_DEFAULT_TIMEOUT,
    require_explicit_contract_id: bool | None = None,
) -> dict[str, Any]:
    """Scan up to *max_pages* event pages locked to a single *contract_id*.

    Validates each page's event contract identities before projecting rows or
    advancing the committed cursor. If page ``k`` carries a conflicting contract
    identity, pages ``0..k-1`` keep their committed cursor and page ``k`` raises
    ``EventPageContractIdentityError`` without projecting any row from page ``k``.
    """
    locked_contract_id = normalize_contract_identity(contract_id)
    bounded_pages = max(1, min(int(max_pages), 100))
    totals = {
        "pages": 0,
        "scanned": 0,
        "indexed": 0,
        "skipped": 0,
        "duplicates": 0,
        "contract_id": locked_contract_id,
    }

    for _ in range(bounded_pages):
        before_cursor = get_indexer_cursor()
        page_summary = poll_indexer_once(
            contract_id=locked_contract_id,
            rpc_url=rpc_url,
            limit=limit,
            timeout=timeout,
            require_explicit_contract_id=require_explicit_contract_id,
        )
        totals["pages"] += 1
        totals["scanned"] += int(page_summary.get("scanned", 0))
        totals["indexed"] += int(page_summary.get("indexed", 0))
        totals["skipped"] += int(page_summary.get("skipped", 0))
        totals["duplicates"] += int(page_summary.get("duplicates", 0))

        after_cursor = page_summary.get("new_cursor") or get_indexer_cursor()
        if page_summary.get("scanned", 0) == 0 or after_cursor == before_cursor:
            break

    return totals


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
