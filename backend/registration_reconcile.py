"""Reconcile off-chain registration rows with on-chain Stellar confirmations.

Harpocrates stores registration evidence in Neon (`proof_events`) and anchors
integrity on Stellar. Clients may submit a `txHash` before Horizon has indexed
the transaction, or with a stale client-reported `txStatus`. This module is the
canonical reconciler: it queries Horizon (with failover), applies a confirmation
depth policy, and updates `tx_status` without creating a second protocol truth.

Race handling: duplicate submissions, delayed indexing and replaced workers all
converge on a single authoritative terminal status per transaction hash. Once a
row reaches a terminal status, later reconciliations (from duplicate jobs or a
replacement worker) observe that status and do not overwrite it unless forced.

Repair preview: `preview_registration_repairs` computes the database updates a
reconciliation would apply, together with the chain evidence and the expected
revision of each row. It performs no writes. A row whose stored state
contradicts the chain evidence is reported as contradictory and never receives
a proposed update.

Privacy: logs and API responses never include media, metadata envelopes,
witness values, credentials, or private keys — only status codes and truncated
transaction hash prefixes.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from db import list_pending_registration_txs, update_tx_status
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

# Retryable operational code returned when the chain dependency is unavailable.
RPC_UNAVAILABLE_CODE = "rpc_unavailable"


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

DOMAIN_TAG = "harpocrates:registration-reconcile:v1"
CHECKPOINT_VERSION = 1
DEFAULT_CHECKPOINT_FILENAME = "registration-reconcile-checkpoint.json"
DEFAULT_STATE_DIR = Path(tempfile.gettempdir()) / "harpocrates-registration-reconcile"

LOGGER = logging.getLogger("harpocrates.registration_reconcile")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)

MAX_RECONCILE_BATCH = 50
MAX_TIMELINE_ENTRIES = 100
DEFAULT_MIN_CONFIRMATIONS = 1

KNOWN_NETWORK_PASSPHRASES = {
    "mainnet": "Public Global Stellar Network ; September 2015",
    "testnet": "Test SDF Network ; September 2015",
    "futurenet": "Test SDF Future Network ; October 2022",
    "local": "Local Sandbox Stellar Network ; September 2022",
    "standalone": "Standalone Network ; February 2017",
}

# Canonical outcome classes exposed in the reconciliation timeline.
OUTCOME_SUBMITTED = "submitted"
OUTCOME_CONFIRMED = "confirmed"
OUTCOME_REJECTED = "rejected"
OUTCOME_UNKNOWN = "unknown"

_STATUS_TO_OUTCOME = {
    "pending": OUTCOME_SUBMITTED,
    "confirmed": OUTCOME_CONFIRMED,
    "failed": OUTCOME_REJECTED,
    "missing": OUTCOME_UNKNOWN,
    "error": OUTCOME_UNKNOWN,
}


class RegistrationReconcileError(RuntimeError):
    pass


class CheckpointError(RegistrationReconcileError):
    pass


class DeploymentMismatchError(CheckpointError):
    pass


class NetworkMismatchError(DeploymentMismatchError):
    pass


class LedgerRollbackError(CheckpointError):
    pass


class TransportError(CheckpointError):
    pass


def classify_outcome(status: str | None) -> str:
    """Map an internal tx status onto the canonical outcome vocabulary."""
    if status is None:
        return OUTCOME_UNKNOWN
    return _STATUS_TO_OUTCOME.get(status, OUTCOME_UNKNOWN)


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
        "outcome": classify_outcome(verification.status),
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


def _digest(*fields: str) -> str:
    payload = "".join(f"{len(field.encode('utf-8'))}:{field}" for field in fields)
    return hashlib.sha256((DOMAIN_TAG + payload).encode("utf-8")).hexdigest()


def _network_identity(network: str, network_passphrase: str) -> str:
    return _digest("network", network, network_passphrase)


def _require_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CheckpointError(f"{name} must be a non-empty string")
    return value.strip()


def _parse_ledger(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CheckpointError("last trusted ledger must be an integer")
    if value < 1:
        raise CheckpointError("last trusted ledger must be positive")
    return value


@dataclass(frozen=True)
class DeploymentIdentity:
    release_id: str
    network: str
    network_passphrase: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "release_id", _require_text("release_id", self.release_id))
        object.__setattr__(self, "network", _require_text("network", self.network).lower())
        object.__setattr__(
            self,
            "network_passphrase",
            _require_text("network_passphrase", self.network_passphrase),
        )

    @classmethod
    def from_config(
        cls,
        config: Any = None,
        *,
        network_passphrase: str | None = None,
        release_id: str | None = None,
        network: str | None = None,
    ) -> "DeploymentIdentity":
        if config is None:
            from config import load_config

            config = load_config()
        resolved_release = release_id or getattr(config, "release_id", None)
        resolved_network = network or getattr(config, "release_network", None)
        if resolved_release is None or resolved_network is None:
            raise DeploymentMismatchError("deployment release and network are required")
        resolved_passphrase = (
            network_passphrase
            or getattr(config, "stellar_network_passphrase", None)
            or os.getenv("STELLAR_NETWORK_PASSPHRASE")
            or os.getenv("HARPOCRATES_NETWORK_PASSPHRASE")
            or KNOWN_NETWORK_PASSPHRASES.get(str(resolved_network).strip().lower())
        )
        if not resolved_passphrase:
            raise DeploymentMismatchError(
                "network passphrase is required for this deployment configuration"
            )
        return cls(
            release_id=str(resolved_release),
            network=str(resolved_network),
            network_passphrase=str(resolved_passphrase),
        )

    @property
    def fingerprint(self) -> str:
        return _digest("deployment", self.release_id, self.network, self.network_passphrase)

    @property
    def identity_hash(self) -> str:
        return self.fingerprint

    @property
    def deployment_id(self) -> str:
        return self.fingerprint

    def to_dict(self) -> dict[str, str]:
        return {
            "releaseId": self.release_id,
            "network": self.network,
            "networkPassphrase": self.network_passphrase,
        }


@dataclass(frozen=True)
class RegistrationCheckpoint:
    last_trusted_ledger: int
    network: str
    network_passphrase: str
    release_id: str = ""
    updated_at: str = ""
    network_identity: str = ""
    deployment_fingerprint: str = ""
    version: int = CHECKPOINT_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "last_trusted_ledger", _parse_ledger(self.last_trusted_ledger))
        object.__setattr__(self, "network", _require_text("network", self.network).lower())
        object.__setattr__(
            self,
            "network_passphrase",
            _require_text("network_passphrase", self.network_passphrase),
        )
        object.__setattr__(self, "release_id", str(self.release_id).strip())
        object.__setattr__(self, "updated_at", str(self.updated_at).strip())
        object.__setattr__(
            self, "network_identity", _network_identity(self.network, self.network_passphrase)
        )
        object.__setattr__(
            self,
            "deployment_fingerprint",
            _digest("deployment", self.release_id, self.network, self.network_passphrase),
        )
        try:
            version = int(self.version)
        except (TypeError, ValueError) as exc:
            raise CheckpointError("checkpoint version must be an integer") from exc
        if version != CHECKPOINT_VERSION:
            raise CheckpointError("unsupported checkpoint version")
        object.__setattr__(self, "version", version)

    @property
    def ledger(self) -> int:
        return self.last_trusted_ledger

    @property
    def network_identity_hash(self) -> str:
        return self.network_identity

    def to_dict(self) -> dict[str, Any]:
        return {
            "deploymentFingerprint": self.deployment_fingerprint,
            "lastTrustedLedger": self.last_trusted_ledger,
            "network": self.network,
            "networkIdentity": self.network_identity,
            "networkPassphrase": self.network_passphrase,
            "releaseId": self.release_id,
            "updatedAt": self.updated_at,
            "version": self.version,
        }

    @staticmethod
    def from_dict(payload: Any) -> "RegistrationCheckpoint":
        if not isinstance(payload, dict):
            raise CheckpointError("checkpoint must be a JSON object")
        try:
            version = int(payload.get("version", CHECKPOINT_VERSION))
        except (TypeError, ValueError) as exc:
            raise CheckpointError("checkpoint version must be an integer") from exc
        if version != CHECKPOINT_VERSION:
            raise CheckpointError("unsupported checkpoint version")
        try:
            ledger = _parse_ledger(
                payload.get("lastTrustedLedger", payload.get("last_trusted_ledger"))
            )
            network = _require_text(
                "network", payload.get("network", payload.get("networkName"))
            )
            passphrase = _require_text(
                "network_passphrase",
                payload.get("networkPassphrase", payload.get("network_passphrase")),
            )
        except CheckpointError:
            raise
        except (TypeError, ValueError) as exc:
            raise CheckpointError("malformed checkpoint") from exc
        checkpoint = RegistrationCheckpoint(
            last_trusted_ledger=ledger,
            network=network,
            network_passphrase=passphrase,
            release_id=str(payload.get("releaseId", payload.get("release_id", ""))),
            updated_at=str(payload.get("updatedAt", payload.get("updated_at", ""))),
            version=version,
        )
        stored_identity = payload.get("networkIdentity", payload.get("network_identity"))
        stored_fingerprint = payload.get(
            "deploymentFingerprint", payload.get("deployment_fingerprint")
        )
        if stored_identity is not None and stored_identity != checkpoint.network_identity:
            raise CheckpointError("checkpoint network identity does not match its fields")
        if (
            stored_fingerprint is not None
            and stored_fingerprint != checkpoint.deployment_fingerprint
        ):
            raise CheckpointError("checkpoint deployment identity does not match its fields")
        return checkpoint


ReconciliationCheckpoint = RegistrationCheckpoint


@dataclass(frozen=True)
class LedgerObservation:
    last_trusted_ledger: int
    network: str
    network_passphrase: str
    release_id: str

    @staticmethod
    def from_response(response: Any, deployment: DeploymentIdentity) -> "LedgerObservation":
        if isinstance(response, dict):
            def value(*names: str) -> Any:
                for name in names:
                    if name in response:
                        return response[name]
                return None

            raw_network = value("network", "networkName", "network_name")
            network_passphrase = value(
                "networkPassphrase", "network_passphrase", "passphrase"
            )
            if isinstance(raw_network, dict):
                network_passphrase = network_passphrase or raw_network.get(
                    "passphrase", raw_network.get("networkPassphrase")
                )
                raw_network = raw_network.get("name", raw_network.get("network"))
            ledger = value(
                "ledger",
                "lastTrustedLedger",
                "last_trusted_ledger",
                "ledger_sequence",
                "sequence",
            )
            release_id = value("releaseId", "release_id")
        else:
            def value(*names: str) -> Any:
                for name in names:
                    if hasattr(response, name):
                        return getattr(response, name)
                return None

            raw_network = value("network", "networkName", "network_name")
            network_passphrase = value(
                "networkPassphrase", "network_passphrase", "passphrase"
            )
            ledger = value(
                "ledger",
                "lastTrustedLedger",
                "last_trusted_ledger",
                "ledger_sequence",
                "sequence",
            )
            release_id = value("releaseId", "release_id")

        network = str(raw_network or deployment.network)
        passphrase = str(network_passphrase or deployment.network_passphrase)
        return LedgerObservation(
            last_trusted_ledger=_parse_ledger(ledger),
            network=network,
            network_passphrase=passphrase,
            release_id=str(release_id or deployment.release_id),
        )


@dataclass(frozen=True)
class ChainEvidence:
    """Redacted on-chain evidence for one transaction hash."""

    tx_hash: str
    status: str
    ledger: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"txHashPrefix": self.tx_hash[:12], "status": self.status, "ledger": self.ledger}


@dataclass(frozen=True)
class RepairPreviewItem:
    """One proposed database update. Previewing never applies it."""

    row_id: str
    tx_hash: str
    expected_revision: int
    current_status: str
    proposed_status: str | None
    chain_evidence: ChainEvidence | None
    contradictory: bool = False
    reason: str = ""

    @property
    def will_update(self) -> bool:
        return (not self.contradictory) and self.proposed_status is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rowId": self.row_id,
            "txHashPrefix": self.tx_hash[:12],
            "expectedRevision": self.expected_revision,
            "currentStatus": self.current_status,
            "proposedStatus": self.proposed_status,
            "chainEvidence": (
                self.chain_evidence.to_dict() if self.chain_evidence is not None else None
            ),
            "contradictory": self.contradictory,
            "willUpdate": self.will_update,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class RepairPreview:
    items: tuple[RepairPreviewItem, ...] = field(default_factory=tuple)

    @property
    def writes_planned(self) -> int:
        return sum(1 for item in self.items if item.will_update)

    @property
    def contradictions(self) -> int:
        return sum(1 for item in self.items if item.contradictory)

    def to_dict(self) -> dict[str, Any]:
        return {
            "writesPlanned": self.writes_planned,
            "contradictions": self.contradictions,
            "items": [item.to_dict() for item in self.items],
        }


def preview_registration_repairs(
    rows: Iterable[Mapping[str, Any]],
    chain_lookup: Callable[[str], ChainEvidence | None],
) -> RepairPreview:
    """Compute proposed updates for registration rows without writing anything.

    Each row mapping must provide `id`, `tx_hash`, `tx_status` and `revision`.
    `chain_lookup` is a read-only query returning chain evidence or None when the
    transaction is not yet indexed. A row whose stored terminal status disagrees
    with chain evidence is flagged contradictory and receives no proposed update.
    """
    items: list[RepairPreviewItem] = []
    for row in rows:
        row_id = str(row["id"])
        tx_hash = _require_text("tx_hash", row["tx_hash"])
        revision = int(row["revision"])
        current = str(row.get("tx_status") or "pending")
        evidence = chain_lookup(tx_hash)

        if evidence is None:
            items.append(
                RepairPreviewItem(
                    row_id=row_id,
                    tx_hash=tx_hash,
                    expected_revision=revision,
                    current_status=current,
                    proposed_status=None,
                    chain_evidence=None,
                    reason="transaction not yet indexed on chain",
                )
            )
            continue

        if current in TERMINAL_STATUSES and current != evidence.status:
            items.append(
                RepairPreviewItem(
                    row_id=row_id,
                    tx_hash=tx_hash,
                    expected_revision=revision,
                    current_status=current,
                    proposed_status=None,
                    chain_evidence=evidence,
                    contradictory=True,
                    reason="stored terminal status contradicts chain evidence",
                )
            )
            continue

NetworkCheckpoint = LedgerObservation


def load_checkpoint(
    state_dir: str | os.PathLike[str] | None = None,
    deployment: DeploymentIdentity | None = None,
) -> RegistrationCheckpoint | None:
    return CheckpointStore(state_dir, deployment).load()


def save_checkpoint(
    checkpoint: RegistrationCheckpoint,
    state_dir: str | os.PathLike[str] | None = None,
    deployment: DeploymentIdentity | None = None,
) -> RegistrationCheckpoint:
    return CheckpointStore(state_dir, deployment).save(checkpoint)


def record_checkpoint(
    last_trusted_ledger: int,
    state_dir: str | os.PathLike[str] | None = None,
    deployment: DeploymentIdentity | None = None,
    *,
    updated_at: str | None = None,
) -> RegistrationCheckpoint:
    return CheckpointStore(state_dir, deployment).record(
        last_trusted_ledger, updated_at=updated_at
    )


def _call_transport(
    transport: Callable[..., Any], deployment: DeploymentIdentity
) -> Any:
    try:
        signature = inspect.signature(transport)
    except (TypeError, ValueError):
        return transport(deployment)
    parameters = list(signature.parameters.values())
    if any(parameter.kind is inspect.Parameter.VAR_POSITIONAL for parameter in parameters):
        return transport(deployment)
    positional = [
        parameter
        for parameter in parameters
        if parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if positional:
        return transport(deployment)
    return transport()


def build_reconciliation_timeline(
    observations: list[dict[str, Any]],
    *,
    limit: int = MAX_TIMELINE_ENTRIES,
) -> dict[str, Any]:
    """Return a bounded, authorized-requester view of reconciliation history.

    Each observation is a reconciliation result payload (see
    ``_result_payload``). Only outcome classes, status transitions, and
    confirmation/ledger metadata are surfaced; no media, envelopes, witness
    values or credentials are ever included.
    """
    if limit < 1:
        raise ValueError("limit must be a positive integer")
    bounded_limit = min(int(limit), MAX_TIMELINE_ENTRIES)

    entries: list[dict[str, Any]] = []
    transitions: list[dict[str, Any]] = []
    previous_outcome: str | None = None

    for index, obs in enumerate(observations):
        if not isinstance(obs, dict):
            continue
        outcome = classify_outcome(obs.get("status"))
        entry = {
            "index": index,
            "outcome": outcome,
            "status": obs.get("status"),
            "reason": obs.get("reason"),
            "confirmations": obs.get("confirmations"),
            "ledger": obs.get("ledger"),
            "updated": bool(obs.get("updated")),
        }
        entries.append(entry)
        if previous_outcome is not None and previous_outcome != outcome:
            transitions.append(
                {
                    "fromOutcome": previous_outcome,
                    "toOutcome": outcome,
                    "atIndex": index,
                }
            )
        previous_outcome = outcome

    truncated = len(entries) > bounded_limit
    entries = entries[-bounded_limit:]

    return {
        "ok": True,
        "observations": entries,
        "transitions": transitions,
        "currentOutcome": previous_outcome,
        "truncated": truncated,
        "limit": bounded_limit,
    }


def reconcile_registration(
    store: CheckpointStore | str | os.PathLike[str],
    transport: Callable[..., Any],
    deployment: DeploymentIdentity | None = None,
) -> RegistrationCheckpoint:
    if not isinstance(store, CheckpointStore):
        store = CheckpointStore(store, deployment)
    active_deployment = deployment or store.deployment
    try:
        response = _call_transport(transport, active_deployment)
        observation = LedgerObservation.from_response(response, active_deployment)
    except RegistrationReconcileError:
        raise
    except Exception as exc:
        raise TransportError("ledger observation could not be read") from exc
    observed = DeploymentIdentity(
        release_id=observation.release_id,
        network=observation.network,
        network_passphrase=observation.network_passphrase,
    )
    if observed.fingerprint != active_deployment.fingerprint:
        if (
            observed.network != active_deployment.network
            or observed.network_passphrase != active_deployment.network_passphrase
        ):
            raise NetworkMismatchError("ledger observation came from another network")
        raise DeploymentMismatchError(
            "ledger observation came from another deployment configuration"
        )
    return store.record(observation.last_trusted_ledger)