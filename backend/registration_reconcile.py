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

Privacy: logs and API responses never include media, metadata envelopes,
witness values, credentials, or private keys — only status codes and truncated
transaction hash prefixes.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

DOMAIN_TAG = "harpocrates:registration-reconcile:v1"
CHECKPOINT_VERSION = 1
DEFAULT_CHECKPOINT_FILENAME = "registration-reconcile-checkpoint.json"
DEFAULT_STATE_DIR = Path(tempfile.gettempdir()) / "harpocrates-registration-reconcile"

KNOWN_NETWORK_PASSPHRASES = {
    "mainnet": "Public Global Stellar Network ; September 2015",
    "testnet": "Test SDF Network ; September 2015",
    "futurenet": "Test SDF Future Network ; October 2022",
    "local": "Local Sandbox Stellar Network ; September 2022",
    "standalone": "Standalone Network ; February 2017",
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


class CheckpointStore:
    def __init__(
        self,
        state_dir: str | os.PathLike[str] | None = None,
        deployment: DeploymentIdentity | None = None,
        filename: str = DEFAULT_CHECKPOINT_FILENAME,
    ) -> None:
        if Path(filename).name != filename or not filename:
            raise CheckpointError("checkpoint filename must be a plain file name")
        raw_state_dir = state_dir or os.getenv(
            "HARPOCRATES_REGISTRATION_RECONCILE_DIR"
        )
        self.state_dir = Path(raw_state_dir) if raw_state_dir else DEFAULT_STATE_DIR
        self.deployment = deployment or DeploymentIdentity.from_config()
        self.filename = filename
        self._lock = threading.RLock()

    @property
    def path(self) -> Path:
        return self.state_dir / self.filename

    def load(self) -> RegistrationCheckpoint | None:
        with self._lock:
            payload = self._read_payload()
            if payload is None:
                return None
            try:
                checkpoint = RegistrationCheckpoint.from_dict(payload)
            except CheckpointError:
                raise
            except Exception as exc:
                raise CheckpointError("malformed checkpoint") from exc
            self._require_matching_deployment(checkpoint)
            return checkpoint

    def save(self, checkpoint: RegistrationCheckpoint) -> RegistrationCheckpoint:
        with self._lock:
            existing = self.load()
            if existing is not None:
                if checkpoint.last_trusted_ledger < existing.last_trusted_ledger:
                    raise LedgerRollbackError("checkpoint ledger cannot move backwards")
                if checkpoint.last_trusted_ledger == existing.last_trusted_ledger:
                    return existing
            self._require_matching_deployment(checkpoint)
            self._write_payload(checkpoint.to_dict())
            return checkpoint

    def record(
        self,
        last_trusted_ledger: int,
        *,
        updated_at: str | None = None,
    ) -> RegistrationCheckpoint:
        checkpoint = RegistrationCheckpoint(
            last_trusted_ledger=last_trusted_ledger,
            network=self.deployment.network,
            network_passphrase=self.deployment.network_passphrase,
            release_id=self.deployment.release_id,
            updated_at=updated_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        return self.save(checkpoint)

    def _read_payload(self) -> dict[str, Any] | None:
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise CheckpointError("checkpoint cannot be read") from exc
        try:
            payload = json.loads(text)
        except (TypeError, ValueError) as exc:
            raise CheckpointError("checkpoint is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise CheckpointError("checkpoint must be a JSON object")
        return payload

    def _write_payload(self, payload: dict[str, Any]) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temp_name = tempfile.mkstemp(
            prefix=f".{self.filename}.", dir=str(self.state_dir)
        )
        try:
            os.chmod(temp_name, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
        except OSError as exc:
            raise CheckpointError("checkpoint cannot be persisted") from exc
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def _require_matching_deployment(
        self, checkpoint: RegistrationCheckpoint
    ) -> None:
        if (
            checkpoint.network.lower() != self.deployment.network
            or checkpoint.network_passphrase != self.deployment.network_passphrase
        ):
            raise NetworkMismatchError("checkpoint belongs to a different Stellar network")
        expected_fingerprint = _digest(
            "deployment",
            self.deployment.release_id,
            self.deployment.network,
            self.deployment.network_passphrase,
        )
        if checkpoint.deployment_fingerprint != expected_fingerprint:
            raise DeploymentMismatchError(
                "checkpoint belongs to a different deployment configuration"
            )


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
    - Terminal writes are conditional at the storage layer, so when duplicate
      or replacement workers race, exactly one terminal write wins and the
      losers report ``updated: false`` with the authoritative stored status
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
        if not updated and not force:
            # Another worker (duplicate job or replacement) already committed a
            # terminal status. Treat that stored value as authoritative.
            verification = TxVerificationResult(
                status=previous_status or verification.status,
                reason="already_terminal",
                confirmations=verification.confirmations,
                ledger=verification.ledger,
            )
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
    return payload