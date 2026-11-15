"""Reconcile off-chain registration rows with on-chain Stellar confirmations.

Harpocrates stores registration evidence in Neon (`proof_events`) and anchors
integrity on Stellar. Clients may submit a `txHash` before Horizon has indexed
the transaction, or with a stale client-reported `txStatus`. This module is the
canonical reconciler: it queries Horizon (with failover), applies a confirmation
depth policy, and updates `tx_status` without creating a second protocol truth.

Privacy: logs and API responses never include media, metadata envelopes,
witness values, credentials, or private keys — only status codes and truncated
transaction hash prefixes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import tempfile
from typing import Any

from db import list_pending_registration_txs, update_tx_status
from strkey import validate_contract_id
from tx_verification import (
    TERMINAL_STATUSES,
    TxVerificationResult,
    normalize_tx_hash,
    verify_transaction,
)

LOGGER = logging.getLogger("harpocrates.registration_reconcile")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)

MAX_RECONCILE_BATCH = 50
DEFAULT_MIN_CONFIRMATIONS = 1
CHECKPOINT_SCHEMA_VERSION = 1
CHECKPOINT_NETWORK_DOMAIN = b"harpocrates:reconcile-checkpoint-network:v1"

_DEFAULT_NETWORK_PASSPHRASES: dict[str, str] = {
    "local": "Standalone Network ; February 2017",
    "testnet": "Test SDF Network ; September 2015",
    "mainnet": "Public Global Stellar Network ; September 2015",
}


class CheckpointConfigMismatchError(ValueError):
    """Raised when a persisted reconciliation checkpoint belongs to another deployment."""

    def __init__(self, reason: str, *, field: str = "networkIdentityDigest") -> None:
        super().__init__(reason)
        self.reason = reason
        self.field = field


@dataclass(frozen=True)
class DeploymentNetworkIdentity:
    """Canonical network & registry identity for binding reconciliation checkpoints."""

    release_network: str
    network_passphrase: str
    contract_id: str | None
    identity_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "releaseNetwork": self.release_network,
            "networkPassphrase": self.network_passphrase,
            "contractId": self.contract_id,
            "networkIdentityDigest": self.identity_digest,
        }


def compute_network_identity_digest(
    *,
    release_network: str,
    network_passphrase: str,
    contract_id: str | None,
) -> str:
    hasher = hashlib.sha256()
    hasher.update(CHECKPOINT_NETWORK_DOMAIN)
    for part in (release_network, network_passphrase, contract_id or ""):
        raw = part.encode("utf-8")
        hasher.update(len(raw).to_bytes(4, "big"))
        hasher.update(raw)
    return hasher.hexdigest()


def resolve_deployment_network_identity(
    *,
    release_network: str | None = None,
    network_passphrase: str | None = None,
    contract_id: str | None = None,
) -> DeploymentNetworkIdentity:
    """Resolve and validate the active Stellar deployment identity."""
    net = (
        release_network
        if release_network is not None
        else os.getenv("HARPOCRATES_RELEASE_NETWORK", "testnet")
    ).strip().lower()
    if net not in _DEFAULT_NETWORK_PASSPHRASES:
        raise ValueError("release_network must be local, testnet, or mainnet")

    raw_passphrase = (
        network_passphrase
        if network_passphrase is not None
        else os.getenv("STELLAR_NETWORK_PASSPHRASE")
    )
    passphrase = (
        raw_passphrase.strip()
        if isinstance(raw_passphrase, str) and raw_passphrase.strip()
        else _DEFAULT_NETWORK_PASSPHRASES[net]
    )

    raw_contract = (
        contract_id
        if contract_id is not None
        else os.getenv("PROOF_REGISTRY_CONTRACT_ID")
    )
    validated_contract = validate_contract_id(raw_contract) if raw_contract else None

    digest = compute_network_identity_digest(
        release_network=net,
        network_passphrase=passphrase,
        contract_id=validated_contract,
    )
    return DeploymentNetworkIdentity(
        release_network=net,
        network_passphrase=passphrase,
        contract_id=validated_contract,
        identity_digest=digest,
    )


@dataclass(frozen=True)
class ReconciliationCheckpoint:
    """Durable, network-boundregistration reconciliation checkpoint."""

    last_trusted_ledger: int
    network: DeploymentNetworkIdentity
    last_confirmed_tx_hash: str | None = None
    last_confirmed_event_id: int | None = None
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": CHECKPOINT_SCHEMA_VERSION,
            "lastTrustedLedger": self.last_trusted_ledger,
            "lastConfirmedTxHash": self.last_confirmed_tx_hash,
            "lastConfirmedEventId": self.last_confirmed_event_id,
            "releaseNetwork": self.network.release_network,
            "networkPassphrase": self.network.network_passphrase,
            "contractId": self.network.contract_id,
            "networkIdentityDigest": self.network.identity_digest,
            "updatedAt": self.updated_at or datetime.now(timezone.utc).isoformat(),
        }


def configured_checkpoint_path() -> Path | None:
    raw = os.getenv("RECONCILE_CHECKPOINT_PATH")
    if raw is None or not raw.strip():
        return None
    return Path(raw.strip())


def validate_checkpoint_payload(
    payload: object,
    *,
    expected_network: DeploymentNetworkIdentity,
) -> ReconciliationCheckpoint:
    """Validate a serialized checkpoint and refuse foreign deployment identities."""
    if not isinstance(payload, dict):
        raise CheckpointConfigMismatchError(
            "checkpoint payload must be a JSON object", field="schemaVersion"
        )
    if payload.get("schemaVersion") != CHECKPOINT_SCHEMA_VERSION:
        raise CheckpointConfigMismatchError(
            "unsupported checkpoint schema version", field="schemaVersion"
        )

    ledger_raw = payload.get("lastTrustedLedger")
    if isinstance(ledger_raw, bool) or not isinstance(ledger_raw, int) or ledger_raw < 0:
        raise CheckpointConfigMismatchError(
            "checkpoint lastTrustedLedger must be a non-negative integer",
            field="lastTrustedLedger",
        )

    stored_net = payload.get("releaseNetwork")
    stored_passphrase = payload.get("networkPassphrase")
    stored_contract = payload.get("contractId")
    stored_digest = payload.get("networkIdentityDigest")

    if not isinstance(stored_net, str) or not isinstance(stored_passphrase, str):
        raise CheckpointConfigMismatchError(
            "checkpoint is missing network identity fields",
            field="releaseNetwork",
        )
    if stored_contract is not None and not isinstance(stored_contract, str):
        raise CheckpointConfigMismatchError(
            "checkpoint contractId must be a string or null",
            field="contractId",
        )
    if not isinstance(stored_digest, str) or len(stored_digest) != 64:
        raise CheckpointConfigMismatchError(
            "checkpoint networkIdentityDigest is missing or malformed",
            field="networkIdentityDigest",
        )

    recomputed = compute_network_identity_digest(
        release_network=stored_net,
        network_passphrase=stored_passphrase,
        contract_id=stored_contract,
    )
    if recomputed != stored_digest:
        raise CheckpointConfigMismatchError(
            "checkpoint networkIdentityDigest integrity check failed",
            field="networkIdentityDigest",
        )

    if stored_net != expected_network.release_network:
        raise CheckpointConfigMismatchError(
            "checkpoint releaseNetwork does not match active deployment",
            field="releaseNetwork",
        )
    if stored_passphrase != expected_network.network_passphrase:
        raise CheckpointConfigMismatchError(
            "checkpoint networkPassphrase does not match active deployment",
            field="networkPassphrase",
        )
    if (stored_contract or None) != expected_network.contract_id:
        raise CheckpointConfigMismatchError(
            "checkpoint contractId does not match active deployment",
            field="contractId",
        )
    if stored_digest != expected_network.identity_digest:
        raise CheckpointConfigMismatchError(
            "checkpoint networkIdentityDigest does not match active deployment",
            field="networkIdentityDigest",
        )

    tx_raw = payload.get("lastConfirmedTxHash")
    normalized_tx = normalize_tx_hash(tx_raw) if tx_raw is not None else None
    event_raw = payload.get("lastConfirmedEventId")
    if event_raw is not None and (isinstance(event_raw, bool) or not isinstance(event_raw, int)):
        raise CheckpointConfigMismatchError(
            "checkpoint lastConfirmedEventId must be an integer or null",
            field="lastConfirmedEventId",
        )

    return ReconciliationCheckpoint(
        last_trusted_ledger=ledger_raw,
        network=expected_network,
        last_confirmed_tx_hash=normalized_tx,
        last_confirmed_event_id=event_raw,
        updated_at=str(payload.get("updatedAt") or ""),
    )


def load_reconciliation_checkpoint(
    checkpoint_path: str | os.PathLike[str] | None = None,
    *,
    expected_network: DeploymentNetworkIdentity | None = None,
) -> ReconciliationCheckpoint | None:
    """Load and verify the persisted network-bound reconciliation checkpoint."""
    target = Path(checkpoint_path) if checkpoint_path is not None else configured_checkpoint_path()
    if target is None or not target.exists():
        return None

    network = expected_network or resolve_deployment_network_identity()
    try:
        raw_data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckpointConfigMismatchError(
            "checkpoint file could not be parsed as valid JSON",
            field="checkpointFile",
        ) from exc

    return validate_checkpoint_payload(raw_data, expected_network=network)


def save_reconciliation_checkpoint(
    checkpoint_path: str | os.PathLike[str],
    *,
    last_trusted_ledger: int,
    network: DeploymentNetworkIdentity | None = None,
    last_confirmed_tx_hash: str | None = None,
    last_confirmed_event_id: int | None = None,
) -> ReconciliationCheckpoint:
    """Persist a network-bound checkpoint atomically, refusing foreign or regressed state."""
    if isinstance(last_trusted_ledger, bool) or not isinstance(last_trusted_ledger, int) or last_trusted_ledger < 0:
        raise ValueError("last_trusted_ledger must be a non-negative integer")

    active_network = network or resolve_deployment_network_identity()
    target = Path(checkpoint_path)

    existing = load_reconciliation_checkpoint(target, expected_network=active_network)
    if existing is not None and last_trusted_ledger < existing.last_trusted_ledger:
        raise ValueError(
            "last_trusted_ledger cannot regress below persisted checkpoint ledger"
        )

    normalized_tx = (
        normalize_tx_hash(last_confirmed_tx_hash)
        if last_confirmed_tx_hash is not None
        else (existing.last_confirmed_tx_hash if existing else None)
    )
    resolved_event_id = (
        last_confirmed_event_id
        if last_confirmed_event_id is not None
        else (existing.last_confirmed_event_id if existing else None)
    )

    checkpoint = ReconciliationCheckpoint(
        last_trusted_ledger=last_trusted_ledger,
        network=active_network,
        last_confirmed_tx_hash=normalized_tx,
        last_confirmed_event_id=resolved_event_id,
        updated_at=datetime.now(timezone.utc).isoformat(),
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(checkpoint.to_dict(), indent=2, sort_keys=True) + "\n"

    fd, tmp_name = tempfile.mkstemp(
        prefix=".reconcile_ckpt_",
        suffix=".tmp",
        dir=str(target.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(serialized)
        os.replace(tmp_name, target)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise

    return checkpoint


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        return default
    return value if value >= 1 else default


def default_min_confirmations() -> int:
    return _env_int("TX_MIN_CONFIRMATIONS", DEFAULT_MIN_CONFIRMATIONS)


def _short_hash(tx_hash: str) -> str:
    return tx_hash[:8]


def clamp_reconcile_limit(limit: object) -> int:
    if limit is None:
        return MAX_RECONCILE_BATCH
    try:
        parsed = int(limit)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise ValueError("limit must be a positive integer") from None
    if parsed < 1:
        raise ValueError("limit must be a positive integer")
    return min(parsed, MAX_RECONCILE_BATCH)


def _result_payload(
    *,
    tx_hash: str,
    previous_status: str | None,
    verification: TxVerificationResult,
    updated: bool,
    proof_id: str | None = None,
    event_id: int | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "txHash": tx_hash,
        "previousStatus": previous_status,
        "status": verification.status,
        "updated": updated,
        "reason": verification.reason,
        "confirmations": verification.confirmations,
        "ledger": verification.ledger,
        "minConfirmationsApplied": None,
    }
    if proof_id is not None:
        payload["proofId"] = proof_id
    if event_id is not None:
        payload["eventId"] = event_id
    return payload


def reconcile_registration(
    tx_hash: object,
    *,
    previous_status: str | None = "pending",
    proof_id: str | None = None,
    event_id: int | None = None,
    min_confirmations: int | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """
    Reconcile a single registration transaction hash against Horizon.

    - Malformed hashes → status ``failed`` / reason ``malformed_tx_hash``
    - Horizon dependency failures → status ``error`` (no durable write)
    - Terminal rows are left unchanged unless ``force`` is true
    """
    min_conf = (
        default_min_confirmations()
        if min_confirmations is None
        else int(min_confirmations)
    )
    if min_conf < 1:
        raise ValueError("minConfirmations must be >= 1")

    try:
        normalized = normalize_tx_hash(tx_hash)
    except ValueError:
        LOGGER.info("registration_reconcile_rejected reason=malformed_tx_hash")
        verification = TxVerificationResult(status="failed", reason="malformed_tx_hash")
        # Malformed hashes cannot be keyed in proof_events; no durable write.
        payload = _result_payload(
            tx_hash="",
            previous_status=previous_status,
            verification=verification,
            updated=False,
            proof_id=proof_id,
            event_id=event_id,
        )
        payload["txHash"] = None
        payload["error"] = "malformed_tx_hash"
        return payload

    if (
        previous_status in TERMINAL_STATUSES
        and not force
        and previous_status is not None
    ):
        verification = TxVerificationResult(
            status=previous_status,
            reason="already_terminal",
        )
        return _result_payload(
            tx_hash=normalized,
            previous_status=previous_status,
            verification=verification,
            updated=False,
            proof_id=proof_id,
            event_id=event_id,
        )

    verification = verify_transaction(normalized, min_confirmations=min_conf)
    updated = False

    if verification.status in TERMINAL_STATUSES:
        updated = bool(update_tx_status(normalized, verification.status, force=force))
        LOGGER.info(
            "registration_reconcile_terminal tx=%s status=%s reason=%s updated=%s",
            _short_hash(normalized),
            verification.status,
            verification.reason,
            updated,
        )
    elif verification.status == "error":
        LOGGER.warning(
            "registration_reconcile_dependency tx=%s reason=%s",
            _short_hash(normalized),
            verification.reason,
        )
    else:
        LOGGER.info(
            "registration_reconcile_pending tx=%s reason=%s confirmations=%s",
            _short_hash(normalized),
            verification.reason,
            verification.confirmations,
        )

    payload = _result_payload(
        tx_hash=normalized,
        previous_status=previous_status,
        verification=verification,
        updated=updated,
        proof_id=proof_id,
        event_id=event_id,
    )
    payload["minConfirmationsApplied"] = min_conf
    return payload


def reconcile_pending_registrations(
    *,
    limit: int = MAX_RECONCILE_BATCH,
    min_confirmations: int | None = None,
    checkpoint_path: str | os.PathLike[str] | None = None,
    network_identity: DeploymentNetworkIdentity | None = None,
) -> dict[str, Any]:
    """Reconcile up to ``limit`` pending registration rows with optional network checkpoint."""
    page_size = clamp_reconcile_limit(limit)
    min_conf = (
        default_min_confirmations()
        if min_confirmations is None
        else int(min_confirmations)
    )
    if min_conf < 1:
        raise ValueError("minConfirmations must be >= 1")

    resolved_ckpt_path = (
        Path(checkpoint_path) if checkpoint_path is not None else configured_checkpoint_path()
    )
    active_network: DeploymentNetworkIdentity | None = None
    prior_checkpoint: ReconciliationCheckpoint | None = None
    if resolved_ckpt_path is not None:
        active_network = network_identity or resolve_deployment_network_identity()
        # Fail closed before querying or updating rows if existing checkpoint mismatches!
        prior_checkpoint = load_reconciliation_checkpoint(
            resolved_ckpt_path, expected_network=active_network
        )

    pending = list_pending_registration_txs(limit=page_size)
    results: list[dict[str, Any]] = []
    summary = {
        "scanned": 0,
        "confirmed": 0,
        "failed": 0,
        "missing": 0,
        "pending": 0,
        "error": 0,
        "updated": 0,
    }

    highest_confirmed_ledger = (
        prior_checkpoint.last_trusted_ledger if prior_checkpoint is not None else 0
    )
    latest_confirmed_tx: str | None = (
        prior_checkpoint.last_confirmed_tx_hash if prior_checkpoint is not None else None
    )
    latest_confirmed_event_id: int | None = (
        prior_checkpoint.last_confirmed_event_id if prior_checkpoint is not None else None
    )

    for row in pending:
        summary["scanned"] += 1
        item = reconcile_registration(
            row.get("tx_hash"),
            previous_status=row.get("tx_status") or "pending",
            proof_id=row.get("proof_id"),
            event_id=row.get("id"),
            min_confirmations=min_conf,
            force=False,
        )
        results.append(item)
        status = item.get("status") or "error"
        if status in summary:
            summary[status] += 1
        else:
            summary["error"] += 1
        if item.get("updated"):
            summary["updated"] += 1
        if status == "confirmed":
            item_ledger = item.get("ledger")
            if isinstance(item_ledger, int) and item_ledger >= highest_confirmed_ledger:
                highest_confirmed_ledger = item_ledger
                if isinstance(item.get("txHash"), str):
                    latest_confirmed_tx = item["txHash"]
                if isinstance(item.get("eventId"), int):
                    latest_confirmed_event_id = item["eventId"]

    response: dict[str, Any] = {
        "ok": True,
        "summary": summary,
        "minConfirmations": min_conf,
        "results": results,
    }

    if resolved_ckpt_path is not None and active_network is not None:
        saved_checkpoint = save_reconciliation_checkpoint(
            resolved_ckpt_path,
            last_trusted_ledger=highest_confirmed_ledger,
            network=active_network,
            last_confirmed_tx_hash=latest_confirmed_tx,
            last_confirmed_event_id=latest_confirmed_event_id,
        )
        response["checkpoint"] = saved_checkpoint.to_dict()

    return response


def process_verify_tx_job(payload: dict[str, Any]) -> dict[str, Any]:
    """Worker entrypoint for ``verify_tx`` jobs enqueued at registration time."""
    if not isinstance(payload, dict):
        raise ValueError("verify_tx payload must be an object")
    tx_hash = payload.get("tx_hash") or payload.get("txHash")
    proof_id = payload.get("proof_id") or payload.get("proofId")
    min_confirmations = payload.get("min_confirmations") or payload.get("minConfirmations")
    result = reconcile_registration(
        tx_hash,
        previous_status="pending",
        proof_id=proof_id if isinstance(proof_id, str) else None,
        min_confirmations=int(min_confirmations) if min_confirmations is not None else None,
    )
    if result.get("status") == "error":
        # Surface dependency failures so the worker can retry non-fatally.
        raise RuntimeError(result.get("reason") or "horizon_dependency_failure")
    return result
