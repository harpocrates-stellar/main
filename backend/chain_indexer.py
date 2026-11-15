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
from collections import OrderedDict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import re
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
SUPPORTED_CONTRACT_EVENT_VERSIONS = frozenset({1})
INDEXER_DEFAULT_MAX_QUARANTINE_ENTRIES = 256

_VERSION_TAG_RE = re.compile(r"^(?:(proof|dispute)_)?v([0-9]+|[a-z0-9_.-]+)$")


def _max_quarantine_entries() -> int:
    raw = os.getenv("INDEXER_MAX_QUARANTINE_ENTRIES")
    if raw and raw.strip():
        try:
            return max(1, int(raw.strip()))
        except ValueError:
            pass
    return INDEXER_DEFAULT_MAX_QUARANTINE_ENTRIES


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


@dataclass(frozen=True)
class QuarantinedEventVersion:
    tx_hash: str
    event_index: int
    paging_token: str | None
    ledger: int | None
    contract_id: str | None
    topic_family: str
    observed_version: str
    supported_versions: tuple[int, ...]
    reason: str
    recorded_at: str


class UnsupportedEventQuarantine:
    """Bounded FIFO quarantine for unsupported contract event versions and ledger gaps."""

    def __init__(self, max_entries: int | None = None) -> None:
        self._max_entries = max(1, int(max_entries if max_entries is not None else _max_quarantine_entries()))
        self._lock = threading.Lock()
        self._entries: OrderedDict[tuple[str, int], QuarantinedEventVersion] = OrderedDict()
        self._evicted_count = 0

    @property
    def max_entries(self) -> int:
        return self._max_entries

    @property
    def evicted_count(self) -> int:
        with self._lock:
            return self._evicted_count

    def record(self, item: QuarantinedEventVersion) -> bool:
        """Record a quarantined event idempotently. Returns True if newly added."""
        key = (item.tx_hash, item.event_index)
        with self._lock:
            if key in self._entries:
                return False
            while len(self._entries) >= self._max_entries:
                self._entries.popitem(last=False)
                self._evicted_count += 1
            self._entries[key] = item
            return True

    def list_entries(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    **asdict(entry),
                    "supported_versions": list(entry.supported_versions),
                }
                for entry in self._entries.values()
            ]

    def list_gaps(self) -> list[dict[str, Any]]:
        """Return ordered ledger-gap markers caused by unprojected unsupported versions."""
        with self._lock:
            gaps: list[dict[str, Any]] = []
            for entry in self._entries.values():
                gaps.append(
                    {
                        "ledger": entry.ledger,
                        "paging_token": entry.paging_token,
                        "tx_hash": entry.tx_hash,
                        "event_index": entry.event_index,
                        "topic_family": entry.topic_family,
                        "observed_version": entry.observed_version,
                        "reason": entry.reason,
                    }
                )
            return gaps

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._evicted_count = 0


_DEFAULT_VERSION_QUARANTINE = UnsupportedEventQuarantine()


def get_quarantined_event_versions() -> list[dict[str, Any]]:
    return _DEFAULT_VERSION_QUARANTINE.list_entries()


def get_indexer_version_gaps() -> list[dict[str, Any]]:
    return _DEFAULT_VERSION_QUARANTINE.list_gaps()


def clear_quarantined_event_versions() -> None:
    _DEFAULT_VERSION_QUARANTINE.clear()


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


def _parse_version_token(raw_ver: Any) -> tuple[int | None, str, bool]:
    """Return ``(parsed_int, display_str, is_malformed)`` for a raw version marker."""
    if isinstance(raw_ver, bool):
        return None, str(raw_ver), True
    if isinstance(raw_ver, int):
        return raw_ver, str(raw_ver), False
    if isinstance(raw_ver, str):
        cleaned = raw_ver.strip()
        if not cleaned:
            return None, "", True
        lower = cleaned.lower()
        if lower.startswith("v"):
            suffix = lower[1:]
            if suffix.isdigit():
                return int(suffix), str(int(suffix)), False
            return None, cleaned, True
        if lower.lstrip("-").isdigit():
            return int(lower), str(int(lower)), False
        return None, cleaned, True
    return None, str(raw_ver), True


def _extract_event_envelope_fields(
    event: dict[str, Any],
    default_contract_id: str | None = None,
) -> tuple[str | None, int, str | None, int | None, str | None]:
    tx_hash = event.get("txHash") or event.get("transactionHash") or event.get("tx_hash")
    norm_tx = _normalize_hex(tx_hash) if isinstance(tx_hash, str) and tx_hash.strip() else None

    paging_token_raw = event.get("id") or event.get("pagingToken")
    paging_token = str(paging_token_raw).strip() if paging_token_raw is not None else None

    event_index = event.get("eventIndex")
    if event_index is None:
        event_index = event.get("event_index")
    if event_index is None:
        token = paging_token or ""
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

    contract_id = event.get("contractId") or event.get("contract_id") or default_contract_id
    ledger_raw = event.get("ledger")
    ledger = ledger_raw if isinstance(ledger_raw, int) and not isinstance(ledger_raw, bool) else None
    return norm_tx, event_index, contract_id, ledger, paging_token


def inspect_event_version(
    event: dict[str, Any],
    default_contract_id: str | None = None,
) -> QuarantinedEventVersion | None:
    """Return a quarantine descriptor when *event* carries an unsupported contract event version."""
    if not isinstance(event, dict):
        return None

    tx_hash, event_index, contract_id, ledger, paging_token = _extract_event_envelope_fields(
        event, default_contract_id=default_contract_id
    )
    if not tx_hash:
        return None

    raw_topics = event.get("topic") or event.get("topics") or []
    topics = [decode_scval(t) for t in raw_topics] if isinstance(raw_topics, list) else []
    str_topics = [str(t).strip().lower() for t in topics]

    val = decode_scval(event.get("value"))

    topic_family = "contract"
    if str_topics:
        if str_topics[0].startswith("proof") or (len(str_topics) > 1 and str_topics[1] == "proof"):
            topic_family = "proof"
        elif str_topics[0].startswith("dispute") or (len(str_topics) > 1 and str_topics[1] == "dispute"):
            topic_family = "dispute"

    raw_version: Any = None
    has_version_marker = False

    for env_key in ("eventVersion", "schemaVersion", "version"):
        if env_key in event and event[env_key] is not None:
            raw_version = event[env_key]
            has_version_marker = True
            break

    if not has_version_marker and isinstance(val, dict):
        for val_key in ("event_version", "schema_version", "version"):
            if val_key in val and val[val_key] is not None:
                raw_version = val[val_key]
                has_version_marker = True
                break

    if not has_version_marker and str_topics:
        m0 = _VERSION_TAG_RE.match(str_topics[0])
        if m0 and (m0.group(1) in ("proof", "dispute") or (len(str_topics) > 1 and str_topics[1] in ("proof", "dispute"))):
            raw_version = f"v{m0.group(2)}"
            has_version_marker = True
            if m0.group(1):
                topic_family = m0.group(1)
        elif str_topics[0] in ("proof", "dispute") and len(str_topics) >= 3:
            m2 = _VERSION_TAG_RE.match(str_topics[2])
            # Avoid misclassifying 64-char hex proof_id/dispute_id starting with 'v' (hex is 0-9a-f, never 'v')
            if m2 and m2.group(1) is None:
                raw_version = f"v{m2.group(2)}"
                has_version_marker = True

    if not has_version_marker:
        return None

    parsed_ver, display_ver, malformed = _parse_version_token(raw_version)
    if not malformed and parsed_ver in SUPPORTED_CONTRACT_EVENT_VERSIONS:
        return None

    reason = (
        f"malformed_event_version:{display_ver or 'empty'}"
        if malformed
        else f"unsupported_event_version:{display_ver}"
    )
    return QuarantinedEventVersion(
        tx_hash=tx_hash,
        event_index=event_index,
        paging_token=paging_token,
        ledger=ledger,
        contract_id=contract_id,
        topic_family=topic_family,
        observed_version=display_ver or "unknown",
        supported_versions=tuple(sorted(SUPPORTED_CONTRACT_EVENT_VERSIONS)),
        reason=reason,
        recorded_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )


def classify_and_decode_event(
    event: dict[str, Any],
    default_contract_id: str | None = None,
) -> DecodedLifecycleEvent | None:
    """Parse a Soroban RPC event and decode it if it matches a known lifecycle topic.

    Returns DecodedLifecycleEvent if recognized and supported, or None if unknown
    or carrying an unsupported schema version.
    """
    if not isinstance(event, dict):
        return None

    if inspect_event_version(event, default_contract_id=default_contract_id) is not None:
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
    # Normalize optional explicit v1 version markers into canonical topic positions
    if len(topics) >= 2 and str(topics[0]).strip().lower() == "v1":
        topics = topics[1:]
    elif len(topics) >= 1 and str(topics[0]).strip().lower() in ("proof_v1", "dispute_v1"):
        topics = [str(topics[0]).strip().lower().split("_", 1)[0], *topics[1:]]
    if len(topics) >= 4 and str(topics[0]).strip().lower() in ("proof", "dispute") and str(topics[2]).strip().lower() == "v1":
        topics = [topics[0], topics[1], *topics[3:]]

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
    quarantine: UnsupportedEventQuarantine | None = None,
) -> dict[str, Any]:
    """Ingest a list of raw Soroban RPC events.

    Decodes supported lifecycle events, quarantines unsupported contract event
    versions without halting unrelated indexing, inserts valid rows idempotently
    into proof_events, queues webhooks, and tracks unknown topics and gaps.
    """
    active_quarantine = quarantine or _DEFAULT_VERSION_QUARANTINE
    summary: dict[str, Any] = {
        "scanned": 0,
        "indexed": 0,
        "skipped": 0,
        "duplicates": 0,
        "unsupported_versions": 0,
        "quarantined_references": [],
        "version_gaps": [],
    }

    for raw in events:
        summary["scanned"] += 1

        quarantined = inspect_event_version(raw, default_contract_id=contract_id)
        if quarantined is not None:
            newly_added = active_quarantine.record(quarantined)
            summary["unsupported_versions"] += 1
            ref = {
                "tx_hash": quarantined.tx_hash,
                "event_index": quarantined.event_index,
                "paging_token": quarantined.paging_token,
                "ledger": quarantined.ledger,
                "topic_family": quarantined.topic_family,
                "observed_version": quarantined.observed_version,
                "supported_versions": list(quarantined.supported_versions),
                "reason": quarantined.reason,
                "newly_quarantined": newly_added,
            }
            summary["quarantined_references"].append(ref)
            summary["version_gaps"].append(
                {
                    "ledger": quarantined.ledger,
                    "paging_token": quarantined.paging_token,
                    "tx_hash": quarantined.tx_hash,
                    "event_index": quarantined.event_index,
                    "reason": quarantined.reason,
                }
            )
            continue

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
# Polling & Worker Loop
# ---------------------------------------------------------------------------


def poll_indexer_once(
    contract_id: str | None = None,
    rpc_url: str | None = None,
    limit: int = INDEXER_DEFAULT_PAGE_SIZE,
    timeout: float = INDEXER_DEFAULT_TIMEOUT,
    *,
    quarantine: UnsupportedEventQuarantine | None = None,
) -> dict[str, Any]:
    """Execute one indexing cycle: fetch, ingest supported events, quarantine unsupported versions, and persist cursor."""
    active_contract_id = contract_id or os.getenv("HARPOCRATES_REGISTRY_CONTRACT_ID") or os.getenv("CONTRACT_ID")
    if not active_contract_id:
        return {"scanned": 0, "indexed": 0, "skipped": 0, "duplicates": 0, "reason": "no_contract_id"}

    active_quarantine = quarantine or _DEFAULT_VERSION_QUARANTINE
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
    summary = process_events_batch(
        events,
        contract_id=active_contract_id,
        quarantine=active_quarantine,
    )
    summary["known_version_gaps"] = active_quarantine.list_gaps()
    summary["quarantine_evicted"] = active_quarantine.evicted_count

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
