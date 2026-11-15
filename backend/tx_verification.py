"""Horizon-backed Stellar transaction status checks for registration reconcile."""

from __future__ import annotations
from dataclasses import dataclass

@dataclass
class TxVerificationResult:
    status: str = ""
    reason: str = ""
    ledger: int | None = None
    latest_ledger: int | None = None
    confirmations: int | None = None
    successful: bool | None = None
    source: str | None = None


def normalize_tx_hash(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("txHash must be a string")
    normalized = value.strip().lower()
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    if len(normalized) != 64 or not all(c in "0123456789abcdef" for c in normalized):
        raise ValueError("txHash must be a 32-byte hex string")
    return normalized


import json
import logging
import os
import urllib.error
import urllib.request

from fetch_external import (
    FetchTimeoutError,
    ResponseTooLargeError,
    safe_urlopen,
)
from tracing import traced

LOGGER = logging.getLogger("harpocrates.tx_verification")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)

# Ordered Horizon failover list. Override with comma-separated HORIZON_URLS.
_DEFAULT_RPC_URLS = (
    "https://horizon-testnet.stellar.org",
    "https://horizon.stellar.org",
)

TERMINAL_STATUSES = frozenset({"confirmed", "failed", "missing"})
ALLOWED_STATUSES = frozenset({"pending", "confirmed", "failed", "missing", "error"})

STELLAR_NETWORK_PASSPHRASES: dict[str, str] = {
    "testnet": "Test SDF Network ; September 2015",
    "mainnet": "Public Global Stellar Network ; September 2015",
    "pubnet": "Public Global Stellar Network ; September 2015",
    "futurenet": "Test SDF Future Network ; October 2022",
    "local": "Standalone Network ; February 2017",
    "standalone": "Standalone Network ; February 2017",
}


def resolve_stellar_network_binding(
    network: str | None = None,
    network_passphrase: str | None = None,
) -> tuple[str, str]:
    """Resolve canonical ``(network_name, network_passphrase)`` for checkpoint & tx binding."""
    raw_net = (
        network
        if network is not None
        else (
            os.getenv("HARPOCRATES_RELEASE_NETWORK")
            or os.getenv("STELLAR_NETWORK")
            or "testnet"
        )
    )
    if not isinstance(raw_net, str) or not raw_net.strip():
        raise ValueError("network must be a non-empty string")
    clean_net = raw_net.strip().lower()
    if clean_net == "pubnet":
        clean_net = "mainnet"
    elif clean_net == "standalone":
        clean_net = "local"

    raw_passphrase = (
        network_passphrase
        if network_passphrase is not None
        else os.getenv("STELLAR_NETWORK_PASSPHRASE")
    )
    if raw_passphrase is not None:
        if not isinstance(raw_passphrase, str) or not raw_passphrase.strip():
            raise ValueError("network_passphrase must be a non-empty string")
        resolved_passphrase = raw_passphrase.strip()
        expected_known = STELLAR_NETWORK_PASSPHRASES.get(clean_net)
        if expected_known and network is None:
            for candidate_net, candidate_pass in STELLAR_NETWORK_PASSPHRASES.items():
                if candidate_pass == resolved_passphrase and candidate_net in {
                    "testnet",
                    "mainnet",
                    "futurenet",
                    "local",
                }:
                    clean_net = candidate_net
                    break
        return clean_net, resolved_passphrase

    if clean_net not in STELLAR_NETWORK_PASSPHRASES:
        raise ValueError(f"unsupported Stellar network '{clean_net}' without explicit passphrase")
    return clean_net, STELLAR_NETWORK_PASSPHRASES[clean_net]


def horizon_urls() -> tuple[str, ...]:
    urls = os.getenv("HORIZON_URLS")
    if urls:
        return tuple(u.strip() for u in urls.split(",") if u.strip())
    return _DEFAULT_RPC_URLS


def _short_hash(tx_hash: str) -> str:
    return tx_hash[:8] if len(tx_hash) >= 8 else tx_hash


def _fetch_json(url: str, timeout: float = 10.0) -> tuple[int, dict | None]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, None


def _latest_ledger(rpc_url: str, timeout: float = 10.0) -> int | None:
    status, data = _fetch_json(f"{rpc_url}/fee_stats", timeout=timeout)
    if status == 200 and data:
        return int(data.get("last_ledger", 0)) or None
    return None


@traced(
    "stellar.horizon.verify_transaction",
    attributes={"rpc.system": "stellar", "peer.service": "stellar-horizon"},
)
def verify_transaction(
    tx_hash: str,
    *,
    min_confirmations: int = 1,
    timeout: float = 10.0,
) -> TxVerificationResult:
    """
    Check a transaction against Horizon with failover.

    Returns one of: pending, confirmed, failed, missing, error.
    ``confirmed`` requires successful=true AND confirmations >= min_confirmations.
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
        except Exception as exc:
            saw_dependency_failure = True
            LOGGER.warning(
                "horizon_query_error source=%s tx=%s err_type=%s",
                rpc_url,
                _short_hash(normalized),
                type(exc).__name__,
            )
            continue

    if saw_not_found and not saw_dependency_failure:
        return TxVerificationResult(status="missing", reason="not_found_on_horizon")
    if saw_dependency_failure:
        return TxVerificationResult(status="error", reason="horizon_dependency_failure")
    return TxVerificationResult(status="missing", reason="not_found_on_horizon")


def verify_transaction_status(tx_hash: str) -> str:
    """
    Back-compat wrapper used by the worker loop.

    Returns one of: confirmed, pending, failed, missing.
    Dependency failures map to pending so the recheck queue can retry.
    """
    result = verify_transaction(tx_hash, min_confirmations=1)
    if result.status == "error":
        return "pending"
    return result.status
