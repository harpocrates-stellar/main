"""Horizon-backed Stellar transaction status checks for registration reconcile."""

from __future__ import annotations
from collections import OrderedDict
from dataclasses import dataclass
import threading

NETWORK_PASSPHRASE_ALIASES: dict[str, str] = {
    "testnet": "Test SDF Network ; September 2015",
    "test sdf network ; september 2015": "Test SDF Network ; September 2015",
    "mainnet": "Public Global Stellar Network ; September 2015",
    "pubnet": "Public Global Stellar Network ; September 2015",
    "public": "Public Global Stellar Network ; September 2015",
    "public global stellar network ; september 2015": "Public Global Stellar Network ; September 2015",
    "futurenet": "Test SDF Future Network ; October 2022",
    "test sdf future network ; october 2022": "Test SDF Future Network ; October 2022",
    "standalone": "Standalone Network ; February 2017",
    "standalone network ; february 2017": "Standalone Network ; February 2017",
}

MAX_TERMINAL_MISMATCH_CACHE = 1024


def normalize_network_identity(value: object) -> str | None:
    """Normalize a Stellar network alias or passphrase to its canonical passphrase."""
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    return NETWORK_PASSPHRASE_ALIASES.get(cleaned.lower(), cleaned)


def infer_url_network(url: str | None) -> str | None:
    """Infer canonical Stellar network passphrase from a well-known Horizon/Soroban URL."""
    if not isinstance(url, str) or not url.strip():
        return None
    lower = url.strip().lower()
    if "testnet" in lower:
        return NETWORK_PASSPHRASE_ALIASES["testnet"]
    if "futurenet" in lower:
        return NETWORK_PASSPHRASE_ALIASES["futurenet"]
    if "horizon.stellar.org" in lower or "mainnet" in lower or "pubnet" in lower:
        return NETWORK_PASSPHRASE_ALIASES["mainnet"]
    return None


def extract_payload_network(payload: object) -> str | None:
    """Extract canonical network passphrase from a Horizon/RPC payload if present."""
    if not isinstance(payload, dict):
        return None
    for key in ("network_passphrase", "networkPassphrase", "network"):
        val = payload.get(key)
        normalized = normalize_network_identity(val)
        if normalized is not None:
            return normalized
    return None


@dataclass
class TxVerificationResult:
    status: str = ""
    reason: str = ""
    ledger: int | None = None
    latest_ledger: int | None = None
    confirmations: int | None = None
    successful: bool | None = None
    source: str | None = None
    failure_kind: str | None = None
    expected_network: str | None = None
    observed_network: str | None = None
    retryable: bool = True


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

TERMINAL_STATUSES = frozenset({"confirmed", "failed", "missing", "network_mismatch"})
ALLOWED_STATUSES = frozenset({"pending", "confirmed", "failed", "missing", "network_mismatch", "error"})

_MISMATCH_LOCK = threading.Lock()
_TERMINAL_NETWORK_MISMATCHES: OrderedDict[tuple[str, str], TxVerificationResult] = OrderedDict()


def clear_network_mismatch_cache() -> None:
    """Clear memoized terminal network-mismatch decisions (primarily for tests)."""
    with _MISMATCH_LOCK:
        _TERMINAL_NETWORK_MISMATCHES.clear()


def _record_terminal_mismatch(key: tuple[str, str], result: TxVerificationResult) -> None:
    with _MISMATCH_LOCK:
        _TERMINAL_NETWORK_MISMATCHES[key] = result
        _TERMINAL_NETWORK_MISMATCHES.move_to_end(key)
        while len(_TERMINAL_NETWORK_MISMATCHES) > MAX_TERMINAL_MISMATCH_CACHE:
            _TERMINAL_NETWORK_MISMATCHES.popitem(last=False)


def _lookup_terminal_mismatch(key: tuple[str, str]) -> TxVerificationResult | None:
    with _MISMATCH_LOCK:
        return _TERMINAL_NETWORK_MISMATCHES.get(key)


def configured_expected_network(explicit: str | None = None) -> tuple[str | None, bool]:
    """Return ``(canonical_network, strict_url_binding)`` for transaction verification."""
    if explicit is not None:
        norm = normalize_network_identity(explicit)
        return norm, norm is not None
    env_explicit = os.getenv("STELLAR_NETWORK_PASSPHRASE") or os.getenv("HARPOCRATES_EXPECTED_NETWORK")
    if env_explicit and env_explicit.strip():
        norm = normalize_network_identity(env_explicit)
        return norm, norm is not None
    release_net = os.getenv("RELEASE_NETWORK") or "testnet"
    return normalize_network_identity(release_net), False


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
    expected_network: str | None = None,
    proof_id: str | None = None,
) -> TxVerificationResult:
    """
    Check a transaction against Horizon with failover and network-binding checks.

    Returns one of: pending, confirmed, failed, missing, network_mismatch, error.
    ``confirmed`` requires successful=true AND confirmations >= min_confirmations
    on the bound Stellar network. Wrong-network transactions resolve terminally
    to ``network_mismatch`` (distinct from ``malformed_proof_data``) and are
    memoized so incompatible transactions are not retried indefinitely.
    """
    if proof_id is not None:
        cleaned_proof = proof_id.strip().lower() if isinstance(proof_id, str) else ""
        if cleaned_proof.startswith("0x"):
            cleaned_proof = cleaned_proof[2:]
        if len(cleaned_proof) != 64 or not all(c in "0123456789abcdef" for c in cleaned_proof):
            return TxVerificationResult(
                status="failed",
                reason="malformed_proof_data",
                failure_kind="malformed_proof_data",
                retryable=False,
            )

    try:
        normalized = normalize_tx_hash(tx_hash)
    except ValueError:
        return TxVerificationResult(
            status="failed",
            reason="malformed_tx_hash",
            failure_kind="malformed_proof_data",
            retryable=False,
        )

    if min_confirmations < 1:
        return TxVerificationResult(
            status="error",
            reason="invalid_min_confirmations",
            failure_kind="configuration_error",
            retryable=False,
        )

    expected_net, strict_url_binding = configured_expected_network(expected_network)
    if expected_net is not None:
        cached = _lookup_terminal_mismatch((normalized, expected_net))
        if cached is not None:
            return cached

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

            observed_net = extract_payload_network(data)
            if observed_net is None and strict_url_binding:
                observed_net = infer_url_network(rpc_url)

            if expected_net is not None and observed_net is not None and observed_net != expected_net:
                mismatch = TxVerificationResult(
                    status="network_mismatch",
                    reason="network_binding_mismatch",
                    ledger=ledger,
                    successful=successful,
                    source=rpc_url,
                    failure_kind="wrong_network",
                    expected_network=expected_net,
                    observed_network=observed_net,
                    retryable=False,
                )
                _record_terminal_mismatch((normalized, expected_net), mismatch)
                return mismatch

            if not successful:
                return TxVerificationResult(
                    status="failed",
                    ledger=ledger,
                    successful=False,
                    source=rpc_url,
                    reason="tx_unsuccessful",
                    failure_kind="tx_unsuccessful",
                    expected_network=expected_net,
                    observed_network=observed_net,
                    retryable=False,
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
                    expected_network=expected_net,
                    observed_network=observed_net,
                    retryable=True,
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
                    expected_network=expected_net,
                    observed_network=observed_net,
                    retryable=True,
                )

            return TxVerificationResult(
                status="confirmed",
                ledger=ledger,
                latest_ledger=latest,
                confirmations=confirmations,
                successful=True,
                source=rpc_url,
                reason="confirmed",
                expected_network=expected_net,
                observed_network=observed_net or expected_net,
                retryable=False,
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
        return TxVerificationResult(
            status="missing",
            reason="not_found_on_horizon",
            expected_network=expected_net,
            retryable=False,
        )
    if saw_dependency_failure:
        return TxVerificationResult(
            status="error",
            reason="horizon_dependency_failure",
            failure_kind="dependency_error",
            expected_network=expected_net,
            retryable=True,
        )
    return TxVerificationResult(
        status="missing",
        reason="not_found_on_horizon",
        expected_network=expected_net,
        retryable=False,
    )


def verify_transaction_status(
    tx_hash: str,
    *,
    expected_network: str | None = None,
) -> str:
    """
    Back-compat wrapper used by the worker loop.

    Returns one of: confirmed, pending, failed, missing, network_mismatch.
    Dependency failures map to pending so the recheck queue can retry.
    """
    result = verify_transaction(
        tx_hash,
        min_confirmations=1,
        expected_network=expected_network,
    )
    if result.status == "error":
        return "pending"
    return result.status
