"""Horizon-backed Stellar transaction status checks for registration reconcile.

A registration is only ``confirmed`` when the referenced transaction:

1. exists on the Horizon of the configured release network (never a fallback
   to another network),
2. succeeded with enough ledger confirmations, and
3. (when a :class:`RegistrationBinding` is supplied) invoked the configured
   registry contract with the expected proof id or video hash as an argument.

Privacy: logs carry only truncated hash prefixes and Horizon hosts.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from fetch_external import (
    FetchTimeoutError,
    ResponseTooLargeError,
    safe_urlopen,
)
from strkey import _decode_base32, validate_contract_id
from tracing import traced

LOGGER = logging.getLogger("harpocrates.tx_verification")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)

# One Horizon per release network. There is deliberately no cross-network
# failover: a mainnet transaction must never confirm a testnet registration.
NETWORK_HORIZON_URLS: dict[str, str] = {
    "local": "http://localhost:8000",
    "testnet": "https://horizon-testnet.stellar.org",
    "mainnet": "https://horizon.stellar.org",
}
_PUBLIC_HORIZON_HOSTS: dict[str, str] = {
    "horizon-testnet.stellar.org": "testnet",
    "horizon.stellar.org": "mainnet",
}

TERMINAL_STATUSES = frozenset({"confirmed", "failed", "missing"})
ALLOWED_STATUSES = frozenset({"pending", "confirmed", "failed", "missing", "error"})

_TX_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_RESPONSE_BYTES = 512 * 1024
_OPERATIONS_PAGE_LIMIT = 200
_INVOKE_CONTRACT_FUNCTION = "HostFunctionTypeHostFunctionTypeInvokeContract"
# XDR ScVal discriminants used to recognise arguments without a Stellar SDK.
_SCV_BYTES = 13
_SCV_ADDRESS = 18
_SC_ADDRESS_TYPE_CONTRACT = 1


@dataclass(frozen=True)
class TxVerificationResult:
    status: str
    reason: str | None = None
    ledger: int | None = None
    latest_ledger: int | None = None
    confirmations: int | None = None
    successful: bool | None = None
    source: str | None = None


@dataclass(frozen=True)
class RegistrationBinding:
    """What a confirming transaction must have invoked on chain."""

    contract_id: str
    proof_id: str | None = None
    video_hash: str | None = None


def normalize_tx_hash(value: object) -> str:
    """Return a lowercase 64-char hex tx hash or raise ``ValueError``."""
    if not isinstance(value, str):
        raise ValueError("tx hash must be a string")
    candidate = value.strip().lower()
    if candidate.startswith("0x"):
        candidate = candidate[2:]
    if not _TX_HASH_RE.fullmatch(candidate):
        raise ValueError("tx hash must be 64 hex characters")
    return candidate


def release_network() -> str:
    network = (os.getenv("HARPOCRATES_RELEASE_NETWORK") or "testnet").strip().lower()
    return network if network in NETWORK_HORIZON_URLS else "testnet"


def configured_registry_contract_id() -> str | None:
    """Registry contract id pinned by the operator, if any."""
    raw = os.getenv("HARPOCRATES_REGISTRY_CONTRACT_ID")
    if raw is None or not raw.strip():
        return None
    try:
        return validate_contract_id(raw)
    except ValueError:
        LOGGER.error("tx_verification_invalid_registry_contract_id")
        return None


def horizon_urls() -> list[str]:
    """Horizon endpoints for the configured network only.

    ``HORIZON_URLS`` may list mirrors of the same network; public Horizon hosts
    that belong to a different network are dropped.
    """
    network = release_network()
    override = os.getenv("HORIZON_URLS")
    urls: list[str] = []
    if override:
        for raw in override.split(","):
            url = raw.strip().rstrip("/")
            if not url:
                continue
            host = url.split("//", 1)[-1].split("/", 1)[0].lower()
            if _PUBLIC_HORIZON_HOSTS.get(host, network) != network:
                LOGGER.warning("tx_verification_cross_network_horizon_ignored host=%s", host)
                continue
            urls.append(url)
    return urls or [NETWORK_HORIZON_URLS[network]]


def _short_hash(tx_hash: str) -> str:
    return tx_hash[:8]


def _fetch_json(url: str, *, timeout: float) -> tuple[int, dict[str, Any] | None]:
    """GET ``url`` and return ``(status_code, json_body_or_None)``."""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        result = safe_urlopen(
            req,
            connect_timeout=min(timeout, 5.0),
            read_timeout=timeout,
            max_bytes=_MAX_RESPONSE_BYTES,
        )
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (FetchTimeoutError, ResponseTooLargeError):
        raise
    try:
        data = json.loads(result.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return result.status, None
    return result.status, data if isinstance(data, dict) else None


def _latest_ledger(rpc_url: str, *, timeout: float) -> int | None:
    try:
        status_code, data = _fetch_json(f"{rpc_url}/", timeout=timeout)
    except Exception:  # noqa: BLE001 - dependency failure keeps the row pending
        return None
    if status_code != 200 or not data:
        return None
    try:
        return int(data.get("history_latest_ledger"))
    except (TypeError, ValueError):
        return None


def _contract_id_bytes(contract_id: str) -> bytes:
    normalized = validate_contract_id(contract_id)
    if normalized is None:
        raise ValueError("contract id required")
    return bytes(_decode_base32(normalized)[1:33])


def _hex32(value: str | None) -> bytes | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    if candidate.startswith("0x"):
        candidate = candidate[2:]
    if len(candidate) != 64:
        return None
    try:
        return bytes.fromhex(candidate)
    except ValueError:
        return None


def _scv_bytes32(raw: bytes) -> bytes:
    return _SCV_BYTES.to_bytes(4, "big") + (32).to_bytes(4, "big") + raw


def _decode_param(param: object) -> bytes:
    if not isinstance(param, dict) or not isinstance(param.get("value"), str):
        return b""
    try:
        return base64.b64decode(param["value"], validate=True)
    except (ValueError, TypeError):
        return b""


def _binding_mismatch(
    rpc_url: str,
    tx_hash: str,
    binding: RegistrationBinding,
    *,
    timeout: float,
) -> str | None:
    """Return a stable reason when the tx did not register the expected proof."""
    try:
        contract_raw = _contract_id_bytes(binding.contract_id)
    except ValueError:
        return "registry_contract_unbound"
    expected_args = [
        _scv_bytes32(raw)
        for raw in (_hex32(binding.proof_id), _hex32(binding.video_hash))
        if raw is not None
    ]
    if not expected_args:
        return "registration_unbound"

    status_code, data = _fetch_json(
        f"{rpc_url}/transactions/{tx_hash}/operations?limit={_OPERATIONS_PAGE_LIMIT}",
        timeout=timeout,
    )
    if status_code != 200 or not data:
        raise RuntimeError("operations lookup failed")
    records = (data.get("_embedded") or {}).get("records") or []

    contract_arg = (
        _SCV_ADDRESS.to_bytes(4, "big")
        + _SC_ADDRESS_TYPE_CONTRACT.to_bytes(4, "big")
        + contract_raw
    )
    saw_registry_call = False
    for op in records:
        if not isinstance(op, dict) or op.get("type") != "invoke_host_function":
            continue
        if op.get("function") != _INVOKE_CONTRACT_FUNCTION:
            continue
        params = [_decode_param(p) for p in op.get("parameters") or []]
        if not params or params[0] != contract_arg:
            continue
        saw_registry_call = True
        if any(arg in blob for blob in params[1:] for arg in expected_args):
            return None
    return "proof_not_bound" if saw_registry_call else "wrong_contract"


@traced(
    "stellar.horizon.verify_transaction",
    attributes={"rpc.system": "stellar", "peer.service": "stellar-horizon"},
)
def verify_transaction(
    tx_hash: str,
    *,
    min_confirmations: int = 1,
    timeout: float = 10.0,
    binding: RegistrationBinding | None = None,
) -> TxVerificationResult:
    """
    Check a transaction against the configured network's Horizon.

    Returns one of: pending, confirmed, failed, missing, error.
    ``confirmed`` requires successful=true, confirmations >= min_confirmations
    and, when ``binding`` is given, an invocation of the registry contract that
    carries the expected proof id or video hash.
    """
    try:
        normalized = normalize_tx_hash(tx_hash)
    except ValueError:
        return TxVerificationResult(status="failed", reason="malformed_tx_hash")

    if min_confirmations < 1:
        return TxVerificationResult(status="error", reason="invalid_min_confirmations")

    saw_dependency_failure = False
    saw_not_found = False

    for rpc_url in horizon_urls():
        try:
            status_code, data = _fetch_json(
                f"{rpc_url}/transactions/{normalized}",
                timeout=timeout,
            )
            if status_code == 404:
                saw_not_found = True
                continue
            if status_code != 200 or not data:
                LOGGER.warning(
                    "horizon_tx_lookup_failed source=%s status=%s tx=%s",
                    rpc_url,
                    status_code,
                    _short_hash(normalized),
                )
                saw_dependency_failure = True
                continue

            successful = bool(data.get("successful", False))
            ledger_raw = data.get("ledger")
            try:
                ledger = int(ledger_raw) if ledger_raw is not None else None
            except (TypeError, ValueError):
                ledger = None

            if not successful:
                return TxVerificationResult(
                    status="failed",
                    ledger=ledger,
                    successful=False,
                    source=rpc_url,
                    reason="tx_unsuccessful",
                )

            if binding is not None:
                mismatch = _binding_mismatch(rpc_url, normalized, binding, timeout=timeout)
                if mismatch is not None:
                    return TxVerificationResult(
                        status="failed",
                        ledger=ledger,
                        successful=True,
                        source=rpc_url,
                        reason=mismatch,
                    )

            latest = _latest_ledger(rpc_url, timeout=timeout)
            confirmations = None
            if ledger is not None and latest is not None and latest >= ledger:
                confirmations = latest - ledger + 1

            if confirmations is None:
                # Dependency could not establish ledger depth — keep pending for retry.
                return TxVerificationResult(
                    status="pending",
                    ledger=ledger,
                    latest_ledger=latest,
                    successful=True,
                    source=rpc_url,
                    reason="confirmations_unavailable",
                )

            if confirmations < min_confirmations:
                return TxVerificationResult(
                    status="pending",
                    ledger=ledger,
                    latest_ledger=latest,
                    confirmations=confirmations,
                    successful=True,
                    source=rpc_url,
                    reason="awaiting_confirmations",
                )

            return TxVerificationResult(
                status="confirmed",
                ledger=ledger,
                latest_ledger=latest,
                confirmations=confirmations,
                successful=True,
                source=rpc_url,
                reason="confirmed",
            )
        except Exception as exc:  # noqa: BLE001 - try the next mirror
            saw_dependency_failure = True
            LOGGER.warning(
                "horizon_query_error source=%s tx=%s err_type=%s",
                rpc_url,
                _short_hash(normalized),
                type(exc).__name__,
            )
            continue

    if saw_dependency_failure:
        return TxVerificationResult(status="error", reason="horizon_dependency_failure")
    if saw_not_found:
        return TxVerificationResult(status="missing", reason="not_found_on_horizon")
    return TxVerificationResult(status="missing", reason="not_found_on_horizon")


def verify_transaction_status(
    tx_hash: str,
    *,
    binding: RegistrationBinding | None = None,
) -> str:
    """
    Back-compat wrapper used by the worker loop.

    Returns one of: confirmed, pending, failed, missing.
    Dependency failures map to pending so the recheck queue can retry.
    """
    result = verify_transaction(tx_hash, min_confirmations=1, binding=binding)
    if result.status == "error":
        return "pending"
    return result.status
