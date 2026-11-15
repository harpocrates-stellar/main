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
import hmac
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
    get_indexer_checkpoint_manifest_raw,
    get_indexer_cursor,
    insert_indexed_proof_event,
    save_indexer_checkpoint_manifest_raw,
    save_indexer_cursor,
)
from fetch_external import safe_urlopen
from metrics import collector
from strkey import (
    _VERSION_BYTE_CONTRACT,
    _VERSION_BYTE_ED25519_PUBLIC,
    make_strkey,
)
from tx_verification import resolve_stellar_network_binding
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

CHECKPOINT_MANIFEST_DOMAIN_TAG = "harpocrates:indexer-checkpoint:v1"
CHECKPOINT_MANIFEST_VERSION = 1
DEFAULT_PROJECTION_SCHEMA = "harpocrates-proof-events-projection/v1"


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


class IncompatibleCheckpointError(ValueError):
    """Raised when an indexer checkpoint manifest fails verification or compatibility."""

    def __init__(
        self,
        message: str,
        *,
        reason: str,
        field: str | None = None,
        expected: Any = None,
        observed: Any = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.field = field
        self.expected = expected
        self.observed = observed


@dataclass(frozen=True)
class IndexerCheckpointManifest:
    """Verified checkpoint manifest binding network, contract, schema, and ledger."""

    domain: str
    manifest_version: int
    indexer_id: str
    network: str
    network_passphrase: str
    contract_id: str
    projection_schema: str
    cursor: str
    observed_ledger: int
    recorded_at: str
    manifest_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "manifestVersion": self.manifest_version,
            "indexerId": self.indexer_id,
            "network": self.network,
            "networkPassphrase": self.network_passphrase,
            "contractId": self.contract_id,
            "projectionSchema": self.projection_schema,
            "cursor": self.cursor,
            "observedLedger": self.observed_ledger,
            "recordedAt": self.recorded_at,
            "manifestDigest": self.manifest_digest,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


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
# Polling & Worker Loop
# ---------------------------------------------------------------------------


def _normalize_checkpoint_contract(contract_id: Any) -> str:
    if isinstance(contract_id, bool) or not isinstance(contract_id, str) or not contract_id.strip():
        raise ValueError("contract_id must be a non-empty string")
    cleaned = contract_id.strip()
    if len(cleaned) == 56 and cleaned[0] in ("C", "c"):
        return cleaned.upper()
    return cleaned


def _length_prefixed_digest(domain_tag: str, fields: tuple[str, ...]) -> str:
    """Compute an injective length-prefixed domain-separated SHA-256 hex digest."""
    hasher = hashlib.sha256()
    tag_bytes = domain_tag.encode("utf-8")
    hasher.update(struct.pack(">I", len(tag_bytes)))
    hasher.update(tag_bytes)
    for field in fields:
        encoded = field.encode("utf-8")
        hasher.update(struct.pack(">I", len(encoded)))
        hasher.update(encoded)
    return hasher.hexdigest()


def _extract_ledger_from_events_or_cursor(
    events: list[dict[str, Any]],
    cursor: str | None,
    fallback_ledger: int | None,
) -> int:
    candidates: list[int] = []
    if fallback_ledger is not None and not isinstance(fallback_ledger, bool):
        parsed_fb = int(fallback_ledger)
        if parsed_fb >= 0:
            candidates.append(parsed_fb)

    for ev in events:
        if not isinstance(ev, dict):
            continue
        raw_ev_ledger = ev.get("ledger")
        if raw_ev_ledger is not None and not isinstance(raw_ev_ledger, bool):
            try:
                val = int(raw_ev_ledger)
                if val >= 0:
                    candidates.append(val)
                    continue
            except (TypeError, ValueError):
                pass
        tok = str(ev.get("id") or ev.get("pagingToken") or "")
        if "-" in tok:
            try:
                prefix = int(tok.split("-", 1)[0], 10)
                if 0 <= prefix < (1 << 32):
                    candidates.append(prefix)
            except ValueError:
                pass

    if not candidates and cursor and "-" in cursor:
        try:
            prefix = int(cursor.split("-", 1)[0], 10)
            if 0 <= prefix < (1 << 32):
                candidates.append(prefix)
        except ValueError:
            pass

    return max(candidates) if candidates else 0


def build_checkpoint_manifest(
    *,
    indexer_id: str = "soroban_events",
    network: str | None = None,
    network_passphrase: str | None = None,
    contract_id: str,
    projection_schema: str = DEFAULT_PROJECTION_SCHEMA,
    cursor: str,
    observed_ledger: int,
    recorded_at: datetime | str | None = None,
) -> IndexerCheckpointManifest:
    """Create a cryptographically bound checkpoint manifest."""
    if not isinstance(indexer_id, str) or not indexer_id.strip():
        raise ValueError("indexer_id must be a non-empty string")
    if not isinstance(cursor, str) or not cursor.strip():
        raise ValueError("cursor must be a non-empty string")
    if not isinstance(projection_schema, str) or not projection_schema.strip():
        raise ValueError("projection_schema must be a non-empty string")
    if isinstance(observed_ledger, bool):
        raise ValueError("observed_ledger must be a non-negative integer")
    try:
        parsed_ledger = int(observed_ledger)
    except (TypeError, ValueError) as exc:
        raise ValueError("observed_ledger must be a non-negative integer") from exc
    if parsed_ledger < 0:
        raise ValueError("observed_ledger must be non-negative")

    norm_network, norm_passphrase = resolve_stellar_network_binding(
        network=network,
        network_passphrase=network_passphrase,
    )
    norm_contract = _normalize_checkpoint_contract(contract_id)
    norm_indexer_id = indexer_id.strip()
    norm_schema = projection_schema.strip()
    norm_cursor = cursor.strip()

    if recorded_at is None:
        recorded_iso = datetime.now(timezone.utc).isoformat()
    elif isinstance(recorded_at, datetime):
        ts = recorded_at if recorded_at.tzinfo is not None else recorded_at.replace(tzinfo=timezone.utc)
        recorded_iso = ts.astimezone(timezone.utc).isoformat()
    else:
        recorded_iso = str(recorded_at).strip()

    digest = _length_prefixed_digest(
        CHECKPOINT_MANIFEST_DOMAIN_TAG,
        (
            str(CHECKPOINT_MANIFEST_VERSION),
            norm_indexer_id,
            norm_network,
            norm_passphrase,
            norm_contract,
            norm_schema,
            norm_cursor,
            str(parsed_ledger),
        ),
    )

    return IndexerCheckpointManifest(
        domain=CHECKPOINT_MANIFEST_DOMAIN_TAG,
        manifest_version=CHECKPOINT_MANIFEST_VERSION,
        indexer_id=norm_indexer_id,
        network=norm_network,
        network_passphrase=norm_passphrase,
        contract_id=norm_contract,
        projection_schema=norm_schema,
        cursor=norm_cursor,
        observed_ledger=parsed_ledger,
        recorded_at=recorded_iso,
        manifest_digest=digest,
    )


def parse_and_verify_checkpoint_manifest(
    raw_manifest: str | dict[str, Any],
) -> IndexerCheckpointManifest:
    """Parse a serialized checkpoint manifest and verify its domain-separated digest."""
    if isinstance(raw_manifest, str):
        try:
            data = json.loads(raw_manifest)
        except json.JSONDecodeError as exc:
            raise IncompatibleCheckpointError(
                "checkpoint manifest is not valid JSON",
                reason="corrupted_checkpoint_manifest",
            ) from exc
    elif isinstance(raw_manifest, dict):
        data = dict(raw_manifest)
    else:
        raise IncompatibleCheckpointError(
            "checkpoint manifest must be a JSON string or object",
            reason="corrupted_checkpoint_manifest",
        )

    if not isinstance(data, dict):
        raise IncompatibleCheckpointError(
            "checkpoint manifest payload must be a JSON object",
            reason="corrupted_checkpoint_manifest",
        )

    domain = data.get("domain")
    if domain != CHECKPOINT_MANIFEST_DOMAIN_TAG:
        raise IncompatibleCheckpointError(
            f"unsupported checkpoint manifest domain: {domain!r}",
            reason="manifest_domain_mismatch",
            field="domain",
            expected=CHECKPOINT_MANIFEST_DOMAIN_TAG,
            observed=domain,
        )

    version = data.get("manifestVersion")
    if isinstance(version, bool) or version != CHECKPOINT_MANIFEST_VERSION:
        raise IncompatibleCheckpointError(
            f"unsupported checkpoint manifest version: {version!r}",
            reason="manifest_version_mismatch",
            field="manifestVersion",
            expected=CHECKPOINT_MANIFEST_VERSION,
            observed=version,
        )

    raw_ledger = data.get("observedLedger")
    if isinstance(raw_ledger, bool) or not isinstance(raw_ledger, int) or raw_ledger < 0:
        raise IncompatibleCheckpointError(
            "checkpoint manifest observedLedger must be a non-negative integer",
            reason="corrupted_checkpoint_manifest",
            field="observedLedger",
            observed=raw_ledger,
        )

    for req_field in (
        "indexerId",
        "network",
        "networkPassphrase",
        "contractId",
        "projectionSchema",
        "cursor",
        "manifestDigest",
    ):
        val = data.get(req_field)
        if not isinstance(val, str) or not val.strip():
            raise IncompatibleCheckpointError(
                f"checkpoint manifest missing or invalid string field '{req_field}'",
                reason="corrupted_checkpoint_manifest",
                field=req_field,
            )

    expected_digest = _length_prefixed_digest(
        CHECKPOINT_MANIFEST_DOMAIN_TAG,
        (
            str(CHECKPOINT_MANIFEST_VERSION),
            data["indexerId"].strip(),
            data["network"].strip(),
            data["networkPassphrase"].strip(),
            data["contractId"].strip(),
            data["projectionSchema"].strip(),
            data["cursor"].strip(),
            str(raw_ledger),
        ),
    )
    observed_digest = data["manifestDigest"].strip().lower()
    if not hmac.compare_digest(expected_digest, observed_digest):
        raise IncompatibleCheckpointError(
            "checkpoint manifest digest verification failed",
            reason="manifest_digest_mismatch",
            field="manifestDigest",
            expected=expected_digest,
            observed=observed_digest,
        )

    return IndexerCheckpointManifest(
        domain=domain,
        manifest_version=version,
        indexer_id=data["indexerId"].strip(),
        network=data["network"].strip(),
        network_passphrase=data["networkPassphrase"].strip(),
        contract_id=data["contractId"].strip(),
        projection_schema=data["projectionSchema"].strip(),
        cursor=data["cursor"].strip(),
        observed_ledger=raw_ledger,
        recorded_at=str(data.get("recordedAt") or ""),
        manifest_digest=expected_digest,
    )


def verify_checkpoint_for_resume(
    manifest: IndexerCheckpointManifest,
    *,
    expected_indexer_id: str = "soroban_events",
    expected_network: str | None = None,
    expected_network_passphrase: str | None = None,
    expected_contract_id: str,
    expected_projection_schema: str = DEFAULT_PROJECTION_SCHEMA,
    stored_cursor: str | None = None,
    observed_chain_ledger: int | None = None,
) -> IndexerCheckpointManifest:
    """Verify that *manifest* is compatible with the active runtime before resuming."""
    # Re-verify cryptographic digest integrity first
    verified = parse_and_verify_checkpoint_manifest(manifest.to_dict())

    norm_net, norm_pass = resolve_stellar_network_binding(
        network=expected_network,
        network_passphrase=expected_network_passphrase,
    )
    norm_contract = _normalize_checkpoint_contract(expected_contract_id)
    norm_schema = expected_projection_schema.strip()
    norm_indexer_id = expected_indexer_id.strip()

    if verified.indexer_id != norm_indexer_id:
        raise IncompatibleCheckpointError(
            f"checkpoint indexerId '{verified.indexer_id}' does not match '{norm_indexer_id}'",
            reason="indexer_id_mismatch",
            field="indexerId",
            expected=norm_indexer_id,
            observed=verified.indexer_id,
        )

    if verified.network != norm_net or verified.network_passphrase != norm_pass:
        raise IncompatibleCheckpointError(
            f"checkpoint network ({verified.network}) is incompatible with active network ({norm_net})",
            reason="network_mismatch",
            field="network",
            expected={"network": norm_net, "networkPassphrase": norm_pass},
            observed={
                "network": verified.network,
                "networkPassphrase": verified.network_passphrase,
            },
        )

    if verified.contract_id != norm_contract:
        raise IncompatibleCheckpointError(
            f"checkpoint contractId '{verified.contract_id}' does not match active contract '{norm_contract}'",
            reason="contract_mismatch",
            field="contractId",
            expected=norm_contract,
            observed=verified.contract_id,
        )

    if verified.projection_schema != norm_schema:
        raise IncompatibleCheckpointError(
            f"checkpoint projectionSchema '{verified.projection_schema}' does not match '{norm_schema}'",
            reason="schema_mismatch",
            field="projectionSchema",
            expected=norm_schema,
            observed=verified.projection_schema,
        )

    if stored_cursor is not None and stored_cursor.strip() != verified.cursor:
        raise IncompatibleCheckpointError(
            "stored indexer_state cursor disagrees with verified checkpoint manifest",
            reason="cursor_manifest_mismatch",
            field="cursor",
            expected=verified.cursor,
            observed=stored_cursor,
        )

    if observed_chain_ledger is not None:
        if isinstance(observed_chain_ledger, bool) or int(observed_chain_ledger) < 0:
            raise IncompatibleCheckpointError(
                "observed_chain_ledger must be a non-negative integer",
                reason="observed_ledger_invalid",
                field="observedLedger",
                observed=observed_chain_ledger,
            )
        if int(observed_chain_ledger) < verified.observed_ledger:
            raise IncompatibleCheckpointError(
                f"chain head ledger ({observed_chain_ledger}) regressed behind checkpoint observedLedger ({verified.observed_ledger})",
                reason="observed_ledger_regression",
                field="observedLedger",
                expected=verified.observed_ledger,
                observed=int(observed_chain_ledger),
            )

    return verified


def get_verified_checkpoint_manifest(
    indexer_id: str = "soroban_events",
) -> IndexerCheckpointManifest | None:
    """Load and cryptographically verify the stored checkpoint manifest, if present."""
    raw = get_indexer_checkpoint_manifest_raw(indexer_id)
    if raw is None:
        return None
    return parse_and_verify_checkpoint_manifest(raw)


def save_verified_checkpoint_manifest(
    manifest: IndexerCheckpointManifest,
) -> IndexerCheckpointManifest:
    """Verify *manifest* and atomically persist both cursor and manifest."""
    verified = parse_and_verify_checkpoint_manifest(manifest.to_dict())
    save_indexer_checkpoint_manifest_raw(
        verified.indexer_id,
        cursor=verified.cursor,
        observed_ledger=verified.observed_ledger,
        manifest_json=verified.to_json(),
    )
    return verified


def _require_checkpoint_manifest_default() -> bool:
    raw = (os.getenv("INDEXER_REQUIRE_CHECKPOINT_MANIFEST") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def poll_indexer_once(
    contract_id: str | None = None,
    rpc_url: str | None = None,
    limit: int = INDEXER_DEFAULT_PAGE_SIZE,
    timeout: float = INDEXER_DEFAULT_TIMEOUT,
    *,
    indexer_id: str = "soroban_events",
    network: str | None = None,
    network_passphrase: str | None = None,
    projection_schema: str | None = None,
    require_manifest: bool | None = None,
) -> dict[str, Any]:
    """Execute one indexing cycle with verified checkpoint manifest enforcement."""
    raw_contract_id = contract_id or os.getenv("HARPOCRATES_REGISTRY_CONTRACT_ID") or os.getenv("CONTRACT_ID")
    if not raw_contract_id:
        return {"scanned": 0, "indexed": 0, "skipped": 0, "duplicates": 0, "reason": "no_contract_id"}

    active_contract_id = _normalize_checkpoint_contract(raw_contract_id)
    active_schema = (
        projection_schema
        or os.getenv("INDEXER_PROJECTION_SCHEMA")
        or DEFAULT_PROJECTION_SCHEMA
    )
    active_rpc_url = rpc_url or os.getenv("SOROBAN_RPC_URL") or os.getenv("STELLAR_RPC_URL") or DEFAULT_SOROBAN_RPC_URL
    strict_manifest = (
        _require_checkpoint_manifest_default()
        if require_manifest is None
        else bool(require_manifest)
    )

    cursor = get_indexer_cursor(indexer_id)
    raw_manifest = get_indexer_checkpoint_manifest_raw(indexer_id)
    verified_resume_manifest: IndexerCheckpointManifest | None = None

    # Validate any stored checkpoint manifest BEFORE RPC fetch or projection mutation!
    if raw_manifest is not None:
        parsed_manifest = parse_and_verify_checkpoint_manifest(raw_manifest)
        verified_resume_manifest = verify_checkpoint_for_resume(
            parsed_manifest,
            expected_indexer_id=indexer_id,
            expected_network=network,
            expected_network_passphrase=network_passphrase,
            expected_contract_id=active_contract_id,
            expected_projection_schema=active_schema,
            stored_cursor=cursor if cursor else "",
        )
    elif cursor and strict_manifest:
        raise IncompatibleCheckpointError(
            "stored indexer cursor has no verified checkpoint manifest",
            reason="missing_checkpoint_manifest",
            field="manifest",
            observed=cursor,
        )

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
    latest_ledger_raw = rpc_result.get("latestLedger")
    latest_ledger = (
        int(latest_ledger_raw)
        if latest_ledger_raw is not None and not isinstance(latest_ledger_raw, bool)
        else None
    )

    # Check observed chain ledger monotonicity BEFORE mutating trusted projection!
    if verified_resume_manifest is not None:
        if latest_ledger is not None and latest_ledger < verified_resume_manifest.observed_ledger:
            raise IncompatibleCheckpointError(
                f"RPC latestLedger ({latest_ledger}) regressed behind checkpoint observedLedger ({verified_resume_manifest.observed_ledger})",
                reason="observed_ledger_regression",
                field="observedLedger",
                expected=verified_resume_manifest.observed_ledger,
                observed=latest_ledger,
            )
        for ev in events:
            if isinstance(ev, dict) and ev.get("ledger") is not None and not isinstance(ev.get("ledger"), bool):
                ev_ledger = int(ev["ledger"])
                if ev_ledger < verified_resume_manifest.observed_ledger:
                    raise IncompatibleCheckpointError(
                        f"event ledger ({ev_ledger}) regressed behind checkpoint observedLedger ({verified_resume_manifest.observed_ledger})",
                        reason="observed_ledger_regression",
                        field="observedLedger",
                        expected=verified_resume_manifest.observed_ledger,
                        observed=ev_ledger,
                    )

    summary = process_events_batch(events, contract_id=active_contract_id)

    new_cursor = rpc_result.get("cursor")
    resolved_new_cursor: str | None = None
    if new_cursor and new_cursor != cursor:
        resolved_new_cursor = str(new_cursor)
    elif events and not new_cursor:
        # If RPC provides event IDs without top-level cursor, use last event's id/pagingToken
        last_id = events[-1].get("id") or events[-1].get("pagingToken")
        if last_id:
            resolved_new_cursor = str(last_id)

    if resolved_new_cursor:
        prior_ledger = (
            verified_resume_manifest.observed_ledger
            if verified_resume_manifest is not None
            else start_ledger
        )
        observed_ledger = _extract_ledger_from_events_or_cursor(
            events,
            resolved_new_cursor,
            latest_ledger if latest_ledger is not None else prior_ledger,
        )
        if verified_resume_manifest is not None:
            observed_ledger = max(observed_ledger, verified_resume_manifest.observed_ledger)

        manifest = build_checkpoint_manifest(
            indexer_id=indexer_id,
            network=network,
            network_passphrase=network_passphrase,
            contract_id=active_contract_id,
            projection_schema=active_schema,
            cursor=resolved_new_cursor,
            observed_ledger=observed_ledger,
        )
        save_verified_checkpoint_manifest(manifest)
        summary["new_cursor"] = resolved_new_cursor
        summary["checkpoint_manifest"] = manifest.to_dict()

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
