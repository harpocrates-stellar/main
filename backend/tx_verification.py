"""Horizon-backed Stellar transaction status checks for registration reconcile."""

from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class TxVerificationResult:
    status: str = ""
    reason: str = ""
    ledger: int | None = None
    latest_ledger: int | None = None
    confirmations: int | None = None
    successful: bool | None = None
    source: str | None = None
    # Freshness/coverage metadata so read views can distinguish a stale
    # index from an invalid on-chain proof.
    last_trusted_ledger: int | None = None
    known_gaps: list[tuple[int, int]] = field(default_factory=list)
    index_stale: bool = False


class NetworkMismatchError(ValueError):
    """Raised when a transaction belongs to a different Stellar network."""


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
NETWORK_MISMATCH_REASON = "network_passphrase_mismatch"

# Maximum ledger lag tolerated before a read index is considered stale.
# Override with HORIZON_MAX_INDEX_LAG_LEDGERS.
_DEFAULT_MAX_INDEX_LAG_LEDGERS = 20


def horizon_urls() -> tuple[str, ...]:
    urls = os.getenv("HORIZON_URLS")
    if urls:
        return tuple(u.strip() for u in urls.split(",") if u.strip())
    return _DEFAULT_RPC_URLS


def max_index_lag_ledgers() -> int:
    raw = os.getenv("HORIZON_MAX_INDEX_LAG_LEDGERS")
    if raw is None or not raw.strip():
        return _DEFAULT_MAX_INDEX_LAG_LEDGERS
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_MAX_INDEX_LAG_LEDGERS
    return value if value >= 0 else _DEFAULT_MAX_INDEX_LAG_LEDGERS


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


def index_freshness(
    *,
    indexed_ledger: int | None,
    latest_ledger: int | None,
    known_gaps: list[tuple[int, int]] | None = None,
    max_lag: int | None = None,
) -> dict:
    """
    Describe how fresh and complete the read index is.

    ``last_trusted_ledger`` is the highest ledger the index has fully covered
    with no gaps below it. ``index_stale`` is True when the index lags the
    chain tip beyond ``max_lag``, or when the lag cannot be determined. Stale
    indexes must never be read as evidence that a proof is invalid.
    """
    gaps = sorted(known_gaps or [])
    lag_limit = max_index_lag_ledgers() if max_lag is None else max_lag

    last_trusted: int | None = None
    if indexed_ledger is not None:
        last_trusted = indexed_ledger
        for start, end in gaps:
            if start <= last_trusted:
                last_trusted = start - 1 if start - 1 >= 0 else None
                break

    if indexed_ledger is None or latest_ledger is None:
        stale = True
        lag = None
    else:
        lag = max(0, latest_ledger - indexed_ledger)
        stale = lag > lag_limit

    return {
        "last_trusted_ledger": last_trusted,
        "indexed_ledger": indexed_ledger,
        "latest_ledger": latest_ledger,
        "lag_ledgers": lag,
        "known_gaps": [list(g) for g in gaps],
        "index_stale": stale,
    }


def annotate_with_freshness(
    result: TxVerificationResult,
    *,
    indexed_ledger: int | None,
    known_gaps: list[tuple[int, int]] | None = None,
) -> TxVerificationResult:
    """
    Attach freshness/coverage to a verification result.

    Staleness is reported only; it never changes ``status``. A stale index
    must not turn a confirmed proof into a failed or invalid one, and a
    transaction at or below the last trusted ledger is unaffected by lag.
    """
    info = index_freshness(
        indexed_ledger=indexed_ledger,
        latest_ledger=result.latest_ledger,
        known_gaps=known_gaps,
    )
    result.last_trusted_ledger = info["last_trusted_ledger"]
    result.known_gaps = [tuple(g) for g in info["known_gaps"]]
    result.index_stale = info["index_stale"]
    return result


@traced(
    "stellar.horizon.verify_transaction",
    attributes={"rpc.system": "stellar", "peer.service": "stellar-horizon"},
)
def verify_transaction(
    tx_hash: str,
    *,
    min_confirmations: int = 1,
    timeout: float = 10.0,
    expected_network_passphrase: str | None = None,
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

            try:
                _check_network_binding(data, expected_network_passphrase)
            except NetworkMismatchError as exc:
                # Wrong-network evidence is terminal: retrying the same
                # incompatible transaction cannot succeed, so do not fail over.
                LOGGER.warning(
                    "horizon_network_mismatch source=%s tx=%s",
                    rpc_url,
                    _short_hash(normalized),
                )
                return TxVerificationResult(
                    status="failed",
                    source=rpc_url,
                    reason=str(exc).split(":", 1)[0],
                )

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
            if isinstance(exc, ValueError) and str(exc) == "malformed_network_passphrase":
                return TxVerificationResult(
                    status="failed",
                    source=rpc_url,
                    reason="malformed_network_passphrase",
                )
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
