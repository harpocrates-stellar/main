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
validates that every event in a fetched page belongs to a single consistent contract
identity before projection (rejecting conflicting pages without advancing the cursor),
persists the ledger cursor, queues webhook deliveries, skips and counts unknown topics,
bounds page size, and backs off exponentially on RPC errors.

Proof identifiers:
Accepts 32-byte hex strings (with optional 0x prefix), 32-byte raw values, and exact
decimal integer IDs (preserved as exact strings across JSON and database boundaries).
Rejects unsafe integer coercion, including booleans, floating-point numbers, fractional
inputs, and exponent notation (fail-closed, skipped and recorded as unknown topics).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import struct
import tempfile
import threading
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from db import (
    get_indexer_checkpoint_manifest,
    get_indexer_cursor,
    insert_indexed_proof_event,
    save_indexer_checkpoint_manifest,
    save_indexer_cursor,
)
from fetch_external import safe_urlopen
from metrics import collector
from strkey import (
    _VERSION_BYTE_CONTRACT,
    _VERSION_BYTE_ED25519_PUBLIC,
    make_strkey,
)
from tx_verification import normalize_proof_id, normalize_tx_hash
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

INDEXER_CHECKPOINT_MANIFEST_VERSION = 1
INDEXER_CHECKPOINT_DOMAIN = "harpocrates.indexer.checkpoint.v1"
INDEXER_SCHEMA_VERSION = "1"
DEFAULT_INDEXER_ID = "soroban_events"


# ---------------------------------------------------------------------------
# Verified Checkpoint Manifest
# ---------------------------------------------------------------------------


class IndexerCheckpointError(ValueError):
    """Base error for checkpoint manifest verification or resume failures."""

    def __init__(self, message: str, *, reason: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.details = details or {}


class CheckpointVerificationError(IndexerCheckpointError):
    """Raised when a checkpoint manifest is malformed or fails integrity verification."""


class IncompatibleCheckpointError(IndexerCheckpointError):
    """Raised when a checkpoint manifest is incompatible with the active indexer target."""


def resolve_indexer_network(network: str | None = None, rpc_url: str | None = None) -> str:
    """Resolve and normalize the canonical network identifier for checkpoint binding."""
    raw = (
        network
        or os.getenv("STELLAR_NETWORK")
        or os.getenv("HARPOCRATES_NETWORK")
        or os.getenv("RELEASE_NETWORK")
    )
    if raw and str(raw).strip():
        return str(raw).strip().lower()

    url = (rpc_url or "").strip().lower()
    if "testnet" in url:
        return "testnet"
    if "futurenet" in url:
        return "futurenet"
    if "localhost" in url or "127.0.0.1" in url or "standalone" in url:
        return "standalone"
    if "mainnet" in url or "soroban-rpc.mainnet" in url or "pubnet" in url:
        return "mainnet"
    return "testnet"


def resolve_indexer_schema_version(schema_version: str | None = None) -> str:
    """Resolve the canonical projection schema version bound to checkpoints."""
    raw = schema_version or os.getenv("INDEXER_SCHEMA_VERSION") or INDEXER_SCHEMA_VERSION
    normalized = str(raw).strip()
    if not normalized:
        raise CheckpointVerificationError(
            "schema_version must be a non-empty string",
            reason="invalid_schema_version",
        )
    return normalized


def _is_valid_non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def compute_checkpoint_manifest_hash(payload: dict[str, Any]) -> str:
    """Compute a domain-separated canonical SHA-256 digest for a checkpoint payload."""
    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    preimage = f"{INDEXER_CHECKPOINT_DOMAIN}\n{canonical_json}".encode("utf-8")
    return hashlib.sha256(preimage).hexdigest()


@dataclass(frozen=True)
class IndexerCheckpointManifest:
    """Verified checkpoint manifest binding network, contract, schema, and observed ledger."""

    manifest_version: int
    indexer_id: str
    network: str
    contract_id: str
    schema_version: str
    cursor: str
    observed_ledger: int
    manifest_hash: str

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "indexer_id": self.indexer_id,
            "network": self.network,
            "contract_id": self.contract_id,
            "schema_version": self.schema_version,
            "cursor": self.cursor,
            "observed_ledger": self.observed_ledger,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.canonical_payload()
        data["manifest_hash"] = self.manifest_hash
        return data

    @classmethod
    def from_dict(cls, data: Any) -> IndexerCheckpointManifest:
        if not isinstance(data, dict):
            raise CheckpointVerificationError(
                "Checkpoint manifest must be a JSON object",
                reason="malformed_manifest",
            )

        required = (
            "manifest_version",
            "indexer_id",
            "network",
            "contract_id",
            "schema_version",
            "cursor",
            "observed_ledger",
            "manifest_hash",
        )
        missing = [k for k in required if k not in data]
        if missing:
            raise CheckpointVerificationError(
                f"Checkpoint manifest missing required fields: {', '.join(missing)}",
                reason="malformed_manifest",
                details={"missing": missing},
            )

        manifest_version = data["manifest_version"]
        if not isinstance(manifest_version, int) or isinstance(manifest_version, bool):
            raise CheckpointVerificationError(
                "manifest_version must be an integer",
                reason="malformed_manifest",
            )
        if manifest_version != INDEXER_CHECKPOINT_MANIFEST_VERSION:
            raise CheckpointVerificationError(
                f"Unsupported checkpoint manifest_version: {manifest_version}",
                reason="unsupported_manifest_version",
                details={"manifest_version": manifest_version},
            )

        for field_name in ("indexer_id", "network", "contract_id", "schema_version", "cursor"):
            val = data[field_name]
            if not isinstance(val, str) or not val.strip():
                raise CheckpointVerificationError(
                    f"Checkpoint manifest field '{field_name}' must be a non-empty string",
                    reason="malformed_manifest",
                    details={"field": field_name},
                )

        observed_ledger = data["observed_ledger"]
        if not _is_valid_non_negative_int(observed_ledger):
            raise CheckpointVerificationError(
                "Checkpoint manifest field 'observed_ledger' must be a non-negative integer",
                reason="malformed_manifest",
                details={"field": "observed_ledger"},
            )

        manifest_hash = data["manifest_hash"]
        if (
            not isinstance(manifest_hash, str)
            or len(manifest_hash) != 64
            or any(c not in "0123456789abcdef" for c in manifest_hash)
        ):
            raise CheckpointVerificationError(
                "Checkpoint manifest field 'manifest_hash' must be a 64-character lowercase hex digest",
                reason="malformed_manifest",
                details={"field": "manifest_hash"},
            )

        return cls(
            manifest_version=manifest_version,
            indexer_id=data["indexer_id"].strip(),
            network=data["network"].strip().lower(),
            contract_id=data["contract_id"].strip(),
            schema_version=data["schema_version"].strip(),
            cursor=data["cursor"],
            observed_ledger=observed_ledger,
            manifest_hash=manifest_hash,
        )


def build_checkpoint_manifest(
    *,
    network: str,
    contract_id: str,
    schema_version: str,
    cursor: str,
    observed_ledger: int,
    indexer_id: str = DEFAULT_INDEXER_ID,
) -> IndexerCheckpointManifest:
    """Build and hash a canonical verified indexer checkpoint manifest."""
    if not isinstance(network, str) or not network.strip():
        raise CheckpointVerificationError("network must be a non-empty string", reason="malformed_manifest")
    if not isinstance(contract_id, str) or not contract_id.strip():
        raise CheckpointVerificationError("contract_id must be a non-empty string", reason="malformed_manifest")
    if not isinstance(schema_version, str) or not schema_version.strip():
        raise CheckpointVerificationError("schema_version must be a non-empty string", reason="malformed_manifest")
    if not isinstance(cursor, str) or not cursor.strip():
        raise CheckpointVerificationError("cursor must be a non-empty string", reason="malformed_manifest")
    if not isinstance(indexer_id, str) or not indexer_id.strip():
        raise CheckpointVerificationError("indexer_id must be a non-empty string", reason="malformed_manifest")
    if not _is_valid_non_negative_int(observed_ledger):
        raise CheckpointVerificationError(
            "observed_ledger must be a non-negative integer",
            reason="malformed_manifest",
        )

    payload = {
        "manifest_version": INDEXER_CHECKPOINT_MANIFEST_VERSION,
        "indexer_id": indexer_id.strip(),
        "network": network.strip().lower(),
        "contract_id": contract_id.strip(),
        "schema_version": schema_version.strip(),
        "cursor": cursor,
        "observed_ledger": observed_ledger,
    }
    digest = compute_checkpoint_manifest_hash(payload)
    return IndexerCheckpointManifest(
        manifest_version=INDEXER_CHECKPOINT_MANIFEST_VERSION,
        indexer_id=payload["indexer_id"],
        network=payload["network"],
        contract_id=payload["contract_id"],
        schema_version=payload["schema_version"],
        cursor=payload["cursor"],
        observed_ledger=payload["observed_ledger"],
        manifest_hash=digest,
    )


def verify_checkpoint_manifest(
    manifest: IndexerCheckpointManifest | dict[str, Any],
) -> IndexerCheckpointManifest:
    """Fail-closed integrity verification of a checkpoint manifest."""
    parsed = (
        manifest
        if isinstance(manifest, IndexerCheckpointManifest)
        else IndexerCheckpointManifest.from_dict(manifest)
    )
    # Re-validate fields even when passed as a dataclass instance
    parsed = IndexerCheckpointManifest.from_dict(parsed.to_dict())
    expected_hash = compute_checkpoint_manifest_hash(parsed.canonical_payload())
    if not hmac.compare_digest(parsed.manifest_hash, expected_hash):
        raise CheckpointVerificationError(
            "Checkpoint manifest integrity check failed: manifest_hash mismatch",
            reason="manifest_integrity_failed",
        )
    return parsed


def validate_checkpoint_resume(
    manifest: IndexerCheckpointManifest | dict[str, Any],
    *,
    network: str,
    contract_id: str,
    schema_version: str,
    indexer_id: str = DEFAULT_INDEXER_ID,
    current_ledger: int | None = None,
) -> IndexerCheckpointManifest:
    """Verify manifest integrity and compatibility with the active indexer target."""
    verified = verify_checkpoint_manifest(manifest)

    expected_indexer_id = indexer_id.strip()
    expected_network = network.strip().lower()
    expected_contract_id = contract_id.strip()
    expected_schema_version = schema_version.strip()

    if verified.indexer_id != expected_indexer_id:
        raise IncompatibleCheckpointError(
            f"Checkpoint indexer_id mismatch: stored={verified.indexer_id} expected={expected_indexer_id}",
            reason="indexer_id_mismatch",
            details={"stored": verified.indexer_id, "expected": expected_indexer_id},
        )
    if verified.network != expected_network:
        raise IncompatibleCheckpointError(
            f"Checkpoint network mismatch: stored={verified.network} expected={expected_network}",
            reason="network_mismatch",
            details={"stored": verified.network, "expected": expected_network},
        )
    if verified.contract_id != expected_contract_id:
        raise IncompatibleCheckpointError(
            f"Checkpoint contract_id mismatch: stored={verified.contract_id} expected={expected_contract_id}",
            reason="contract_mismatch",
            details={"stored": verified.contract_id, "expected": expected_contract_id},
        )
    if verified.schema_version != expected_schema_version:
        raise IncompatibleCheckpointError(
            f"Checkpoint schema_version mismatch: stored={verified.schema_version} expected={expected_schema_version}",
            reason="schema_mismatch",
            details={"stored": verified.schema_version, "expected": expected_schema_version},
        )
    if current_ledger is not None:
        if not _is_valid_non_negative_int(current_ledger):
            raise IncompatibleCheckpointError(
                f"Invalid current_ledger: {current_ledger}",
                reason="invalid_ledger",
                details={"current_ledger": current_ledger},
            )
        if current_ledger < verified.observed_ledger:
            raise IncompatibleCheckpointError(
                f"Checkpoint observed ledger regression: current={current_ledger} < stored={verified.observed_ledger}",
                reason="ledger_regression",
                details={"stored": verified.observed_ledger, "current": current_ledger},
            )

    return verified


def load_checkpoint_manifest_file(path: str | Path) -> IndexerCheckpointManifest | None:
    """Load and verify a checkpoint manifest from disk. Returns None if file does not exist."""
    manifest_file = Path(path)
    if not manifest_file.exists():
        return None
    try:
        raw_text = manifest_file.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except Exception as exc:
        raise CheckpointVerificationError(
            f"Failed to read or parse checkpoint manifest file: {exc}",
            reason="malformed_manifest",
        ) from exc
    return verify_checkpoint_manifest(data)


def write_checkpoint_manifest_file(
    path: str | Path,
    manifest: IndexerCheckpointManifest,
) -> None:
    """Atomically write a verified checkpoint manifest to disk."""
    verified = verify_checkpoint_manifest(manifest)
    manifest_file = Path(path)
    manifest_file.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(
        verified.to_dict(),
        sort_keys=True,
        indent=2,
        ensure_ascii=True,
    ) + "\n"

    fd, tmp_name = tempfile.mkstemp(
        prefix=".checkpoint_manifest_",
        suffix=".tmp",
        dir=str(manifest_file.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, manifest_file)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


class IndexerBackpressureError(RuntimeError):
    """Raised when an RPC response exceeds the indexer's bounded batch capacity."""


def _bounded_page_size(limit: int) -> int:
    """Clamp an event page to the supported in-memory batch bounds."""
    return max(1, min(int(limit), INDEXER_MAX_PAGE_SIZE))


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
        if disc in (9, 10):  # SCV_U128, SCV_I128
            hi, lo = struct.unpack(">QQ" if disc == 9 else ">qQ", payload[:16])
            return (hi << 64) | lo
        if disc in (11, 12):  # SCV_U256, SCV_I256
            hi_hi, hi_lo, lo_hi, lo_lo = struct.unpack(
                ">QQQQ" if disc == 11 else ">qQQQ", payload[:32]
            )
            return (hi_hi << 192) | (hi_lo << 128) | (lo_hi << 64) | lo_lo
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
    """Return a normalized proof ID string (hex or decimal) if valid, else None."""
    if val is None:
        return None
    try:
        return normalize_proof_id(val)
    except (ValueError, TypeError):
        return None


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
    try:
        tx_hash = normalize_tx_hash(tx_hash)
    except ValueError:
        return None

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
        try:
            proof_id = normalize_proof_id(topics[2])
        except (ValueError, TypeError):
            return None
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
        try:
            proof_id = normalize_proof_id(topics[2])
        except (ValueError, TypeError):
            return None
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
        dispute_id = None
        if len(topics) >= 3 and topics[2] is not None:
            try:
                dispute_id = normalize_proof_id(topics[2])
            except (ValueError, TypeError):
                return None
        proof_id = None
        if len(topics) >= 4 and topics[3] is not None:
            try:
                proof_id = normalize_proof_id(topics[3])
            except (ValueError, TypeError):
                return None
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
            if isinstance(val, dict) and val.get("superseded_by") is not None:
                try:
                    superseded_by = normalize_proof_id(val.get("superseded_by"))
                except (ValueError, TypeError):
                    return None
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


class ContractIdentityConflictError(ValueError):
    """Raised when an event page contains events from a conflicting contract identity."""


def _extract_event_contract_id(event: dict[str, Any]) -> str | None:
    """Extract and validate explicit contract identity fields from a raw event."""
    raw_camel = event.get("contractId")
    raw_snake = event.get("contract_id")

    candidates: list[str] = []
    for field_name, raw_val in (("contractId", raw_camel), ("contract_id", raw_snake)):
        if raw_val is None:
            continue
        if not isinstance(raw_val, str) or not raw_val.strip():
            raise ContractIdentityConflictError(
                f"Invalid {field_name} in event: expected non-empty string"
            )
        candidates.append(raw_val.strip())

    if len(candidates) == 2 and candidates[0] != candidates[1]:
        raise ContractIdentityConflictError(
            f"Conflicting contractId/contract_id within event: {candidates[0]} != {candidates[1]}"
        )

    return candidates[0] if candidates else None


def validate_event_page_contract_identity(
    events: list[dict[str, Any]],
    expected_contract_id: str | None = None,
) -> str | None:
    """Validate that every event in a page belongs to a single consistent contract identity.

    When expected_contract_id is provided, every event with an explicit contractId/contract_id
    must match it. When expected_contract_id is omitted, all explicit contract IDs in the
    page must agree with each other.

    Raises ContractIdentityConflictError on any mismatch so the page is rejected before
    projection and before any cursor is committed.
    """
    baseline = (
        expected_contract_id.strip()
        if isinstance(expected_contract_id, str) and expected_contract_id.strip()
        else None
    )

    for idx, raw in enumerate(events):
        if not isinstance(raw, dict):
            continue
        event_contract_id = _extract_event_contract_id(raw)
        if event_contract_id is None:
            continue
        if baseline is None:
            baseline = event_contract_id
        elif event_contract_id != baseline:
            raise ContractIdentityConflictError(
                f"Contract identity changed inside event page at index {idx}: "
                f"expected {baseline}, got {event_contract_id}"
            )

    return baseline


def process_events_batch(
    events: list[dict[str, Any]],
    contract_id: str | None = None,
    *,
    max_events: int = INDEXER_MAX_PAGE_SIZE,
) -> dict[str, Any]:
    """Ingest a list of raw Soroban RPC events.

    Validates every event's contract identity before projection, decodes lifecycle events,
    inserts them idempotently into proof_events, queues webhooks for newly written events,
    and tracks unknown topics.
    """
    validate_event_page_contract_identity(events, expected_contract_id=contract_id)

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
    end_ledger: int | None = None,
) -> dict[str, Any]:
    """Call Soroban RPC getEvents with bounded pagination and filter."""
    page_limit = _bounded_page_size(limit)
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
    if end_ledger is not None:
        params["endLedger"] = end_ledger

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


def _extract_observed_ledger(
    rpc_result: dict[str, Any],
    events: list[dict[str, Any]],
    *,
    start_ledger: int | None = None,
    previous_ledger: int | None = None,
) -> int | None:
    """Resolve the highest observed ledger from an RPC response or fallback context."""
    raw_latest = rpc_result.get("latestLedger")
    if raw_latest is not None:
        try:
            latest_int = int(raw_latest)
            if latest_int >= 0:
                return latest_int
        except (TypeError, ValueError):
            pass

    event_ledgers: list[int] = []
    for ev in events:
        if isinstance(ev, dict) and ev.get("ledger") is not None:
            try:
                val = int(ev["ledger"])
                if val >= 0:
                    event_ledgers.append(val)
            except (TypeError, ValueError):
                continue
    if event_ledgers:
        return max(event_ledgers)

    if _is_valid_non_negative_int(start_ledger):
        return start_ledger
    if _is_valid_non_negative_int(previous_ledger):
        return previous_ledger
    return None


def poll_indexer_once(
    contract_id: str | None = None,
    rpc_url: str | None = None,
    limit: int = INDEXER_DEFAULT_PAGE_SIZE,
    timeout: float = INDEXER_DEFAULT_TIMEOUT,
    *,
    network: str | None = None,
    schema_version: str | None = None,
    manifest_path: str | Path | None = None,
    indexer_id: str = DEFAULT_INDEXER_ID,
    require_verified_manifest: bool = False,
) -> dict[str, Any]:
    """Execute one indexing cycle: verify checkpoint, fetch, ingest, and persist manifest."""
    active_contract_id = contract_id or os.getenv("HARPOCRATES_REGISTRY_CONTRACT_ID") or os.getenv("CONTRACT_ID")
    if not active_contract_id:
        return {"scanned": 0, "indexed": 0, "skipped": 0, "duplicates": 0, "reason": "no_contract_id"}

    active_rpc_url = rpc_url or os.getenv("SOROBAN_RPC_URL") or os.getenv("STELLAR_RPC_URL") or DEFAULT_SOROBAN_RPC_URL
    active_network = resolve_indexer_network(network=network, rpc_url=active_rpc_url)
    active_schema_version = resolve_indexer_schema_version(schema_version=schema_version)
    active_manifest_path = manifest_path or os.getenv("INDEXER_CHECKPOINT_MANIFEST_PATH")

    # 1. Load and verify any existing checkpoint manifest BEFORE fetching or mutating projection.
    verified_manifest: IndexerCheckpointManifest | None = None
    if active_manifest_path:
        loaded_file_manifest = load_checkpoint_manifest_file(active_manifest_path)
        if loaded_file_manifest is not None:
            verified_manifest = validate_checkpoint_resume(
                loaded_file_manifest,
                network=active_network,
                contract_id=active_contract_id,
                schema_version=active_schema_version,
                indexer_id=indexer_id,
            )

    if verified_manifest is None:
        stored_manifest = get_indexer_checkpoint_manifest(indexer_id)
        if stored_manifest is not None:
            verified_manifest = validate_checkpoint_resume(
                stored_manifest,
                network=active_network,
                contract_id=active_contract_id,
                schema_version=active_schema_version,
                indexer_id=indexer_id,
            )

    if verified_manifest is not None:
        cursor: str | None = verified_manifest.cursor
    else:
        cursor = get_indexer_cursor(indexer_id)
        if cursor and require_verified_manifest:
            raise IncompatibleCheckpointError(
                "Refusing to resume from unverified legacy cursor without a checkpoint manifest",
                reason="missing_checkpoint_manifest",
                details={"indexer_id": indexer_id},
            )

    start_ledger = None

    if not cursor:
        cursor = None
        # Out of scope: backfilling history before the first cursor.
        # Query latest ledger on fresh startup to start from head.
        latest = fetch_latest_ledger(active_rpc_url, timeout=timeout)
        start_ledger = latest

    page_limit = _bounded_page_size(limit)
    rpc_result = fetch_contract_events(
        rpc_url=active_rpc_url,
        contract_id=active_contract_id,
        start_ledger=start_ledger,
        cursor=cursor,
        limit=page_limit,
        timeout=timeout,
    )

    events = rpc_result.get("events") or []
    observed_ledger = _extract_observed_ledger(
        rpc_result,
        events,
        start_ledger=start_ledger,
        previous_ledger=verified_manifest.observed_ledger if verified_manifest else None,
    )

    # 2. Reject observed ledger regression BEFORE mutating the trusted projection.
    if verified_manifest is not None and observed_ledger is not None:
        validate_checkpoint_resume(
            verified_manifest,
            network=active_network,
            contract_id=active_contract_id,
            schema_version=active_schema_version,
            indexer_id=indexer_id,
            current_ledger=observed_ledger,
        )

    summary = process_events_batch(events, contract_id=active_contract_id)

    new_cursor = rpc_result.get("cursor")
    effective_cursor: str | None = None

    if new_cursor and new_cursor != cursor:
        effective_cursor = str(new_cursor)
    elif events and not new_cursor:
        # If RPC provides event IDs without top-level cursor, use last event's id/pagingToken
        last_id = events[-1].get("id") or events[-1].get("pagingToken")
        if last_id:
            effective_cursor = str(last_id)

    if effective_cursor:
        save_indexer_cursor(indexer_id=indexer_id, cursor=effective_cursor, ledger=observed_ledger)
        summary["new_cursor"] = effective_cursor
        if observed_ledger is not None:
            new_manifest = build_checkpoint_manifest(
                network=active_network,
                contract_id=active_contract_id,
                schema_version=active_schema_version,
                cursor=effective_cursor,
                observed_ledger=observed_ledger,
                indexer_id=indexer_id,
            )
            save_indexer_checkpoint_manifest(new_manifest.to_dict(), indexer_id=indexer_id)
            if active_manifest_path:
                write_checkpoint_manifest_file(active_manifest_path, new_manifest)
            summary["checkpoint_manifest"] = new_manifest.to_dict()

    return summary


def get_index_freshness(
    contract_id: str | None = None,
    max_lag_ledgers: int = 100,
) -> dict[str, Any]:
    """Report index freshness from the persisted cursor for read-side responses.

    Returns the last trusted ledger and a ``stale`` flag. Callers must treat a
    stale index as "unknown", never as evidence that a proof is invalid.
    """
    active_contract_id = contract_id or os.getenv("HARPOCRATES_REGISTRY_CONTRACT_ID") or os.getenv("CONTRACT_ID")
    cursor = get_indexer_cursor() if active_contract_id else None
    last_trusted_ledger = cursor.get("ledger") if isinstance(cursor, dict) else None
    return {
        "contract_id": active_contract_id,
        "last_trusted_ledger": last_trusted_ledger,
        "has_cursor": bool(cursor),
        "max_lag_ledgers": max_lag_ledgers,
        "stale": last_trusted_ledger is None,
        "verdict_impact": "none",
    }


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



# ---------------------------------------------------------------------------
# Index rebuild dry-run: deterministic projection fingerprints
# ---------------------------------------------------------------------------

_PROJECTION_DOMAIN = "harpocrates:index-projection:v1"


def _projection_tx_hash(event: dict[str, Any]) -> str:
    value = event.get("txHash") or event.get("tx_hash") or ""
    return value.strip() if isinstance(value, str) else ""


def _projection_event_id(event: dict[str, Any]) -> str:
    value = event.get("id") or event.get("event_id") or event.get("eventId")
    return str(value) if value is not None else ""


def _projection_topic(event: dict[str, Any]) -> list[Any]:
    value = event.get("topic")
    return value if isinstance(value, list) else []


def build_index_projection(
    events: list[dict[str, Any]],
    *,
    contract_id: str | None = None,
    skipped: list[Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Build an in-memory proof projection from decoded or synthetic events.

    The projection is keyed by ``"<txHash>:<eventId>"`` so a rebuild is
    invariant to the order events are fed in. Malformed events (missing hash,
    empty topic) are skipped and appended to ``skipped`` when provided.
    """
    projection: dict[str, dict[str, Any]] = {}
    for position, event in enumerate(events):
        if not isinstance(event, dict):
            if skipped is not None:
                skipped.append(position)
            continue
        tx_hash = _projection_tx_hash(event)
        topic = _projection_topic(event)
        if not tx_hash or not topic:
            if skipped is not None:
                skipped.append(position)
            continue
        event_id = _projection_event_id(event) or str(position)
        key = f"{tx_hash}:{event_id}"
        event_type = topic[0] if isinstance(topic[0], str) else "unknown"
        projection[key] = {
            "tx_hash": tx_hash,
            "event_id": event_id,
            "event_type": event_type,
            "topic": list(topic),
            "contract_id": event.get("contract_id") or contract_id,
            "value": event.get("value"),
        }
    return projection


def compute_projection_fingerprint(projection: dict[str, dict[str, Any]]) -> str:
    """Return a canonical SHA-256 fingerprint for a projection."""
    canonical = {
        key: projection[key] for key in sorted(projection)
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((_PROJECTION_DOMAIN + payload).encode("utf-8")).hexdigest()


def diff_projections(
    live: dict[str, dict[str, Any]],
    rebuilt: dict[str, dict[str, Any]],
) -> dict[str, list[str]]:
    """Report keys added, removed or changed between two projections."""
    live_keys = set(live)
    rebuilt_keys = set(rebuilt)
    added = sorted(rebuilt_keys - live_keys)
    removed = sorted(live_keys - rebuilt_keys)
    changed = sorted(
        key for key in live_keys & rebuilt_keys if live[key] != rebuilt[key]
    )
    return {"added": added, "removed": removed, "changed": changed}


def rebuild_index_dry_run(
    events: list[dict[str, Any]],
    *,
    contract_id: str | None = None,
    live_projection: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Rebuild the projection in memory and diff it against the live index.

    Nothing is written: the live projection and indexer cursor are untouched.
    """
    skipped: list[Any] = []
    rebuilt = build_index_projection(events, contract_id=contract_id, skipped=skipped)
    live = live_projection if live_projection is not None else {}
    diff = diff_projections(live, rebuilt)
    differences = len(diff["added"]) + len(diff["removed"]) + len(diff["changed"])
    return {
        "dry_run": True,
        "contract_id": contract_id,
        "fingerprint": compute_projection_fingerprint(rebuilt),
        "rebuilt_fingerprint": compute_projection_fingerprint(rebuilt),
        "live_fingerprint": compute_projection_fingerprint(live),
        "added": diff["added"],
        "removed": diff["removed"],
        "changed": diff["changed"],
        "differences": differences,
        "skipped": len(skipped),
        "rebuilt_entries": len(rebuilt),
        "live_entries": len(live),
    }


def dry_run_index_rebuild(*, limit: int = 1000) -> dict[str, Any]:
    """CLI entrypoint: rebuild the projection from stored proof events."""
    rows, _ = list_proof_events(limit=limit)
    events = [
        {
            "txHash": row.get("tx_hash"),
            "id": row.get("id"),
            "topic": [row.get("event_type") or "unknown"],
            "value": None,
            "contract_id": row.get("contract_id"),
        }
        for row in rows
    ]
    live = build_index_projection(events)
    return rebuild_index_dry_run(events, live_projection=live)
