"""Horizon-backed Stellar transaction status checks for registration reconcile."""

from __future__ import annotations
from dataclasses import dataclass
from decimal import Decimal
import re

_STRICT_DECIMAL_ID_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
_STRICT_ZERO_PADDED_UINT_RE = re.compile(r"^[0-9]+$")
_HEX32_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class UnsafeProofIdentifierError(ValueError):
    """Raised when a proof/event identifier or integer uses lossy, fractional, or exponent coercion."""


def parse_strict_uint(
    value: object,
    *,
    field: str = "value",
    allow_zero_padded_str: bool = False,
) -> int:
    """Parse a non-negative integer without float truncation or exponent coercion."""
    if isinstance(value, bool):
        raise UnsafeProofIdentifierError(f"{field} must not be a boolean")
    if isinstance(value, (float, Decimal)):
        raise UnsafeProofIdentifierError(
            f"{field} must be an exact integer; fractional or exponent notation is rejected"
        )
    if isinstance(value, int):
        if value < 0:
            raise UnsafeProofIdentifierError(f"{field} must be non-negative")
        return value
    if isinstance(value, str):
        pattern = _STRICT_ZERO_PADDED_UINT_RE if allow_zero_padded_str else _STRICT_DECIMAL_ID_RE
        if not pattern.fullmatch(value):
            raise UnsafeProofIdentifierError(
                f"{field} must be an exact base-10 non-negative integer without fractional or exponent notation"
            )
        return int(value, 10)
    raise UnsafeProofIdentifierError(f"{field} must be an exact non-negative integer")


def normalize_proof_identifier(value: object, *, field: str = "proof_id") -> str:
    """Normalize an indexed proof/dispute ID to an exact decimal string or 32-byte hex digest.

    Preserves arbitrary-precision decimal IDs (including u64/u128 values > 2^53 - 1)
    as exact strings across JSON and database boundaries while rejecting floats,
    booleans, fractional values, and scientific/exponent notation.
    """
    if isinstance(value, bool):
        raise UnsafeProofIdentifierError(f"{field} must not be a boolean")
    if isinstance(value, (float, Decimal)):
        raise UnsafeProofIdentifierError(
            f"{field} rejects float, fractional, and exponent notation"
        )
    if isinstance(value, int):
        if value < 0:
            raise UnsafeProofIdentifierError(f"{field} must be non-negative")
        return f"{value:d}"
    if isinstance(value, bytes):
        if len(value) != 32:
            raise UnsafeProofIdentifierError(f"{field} bytes must be 32 bytes")
        return value.hex().lower()
    if isinstance(value, str):
        if not value or value != value.strip():
            raise UnsafeProofIdentifierError(f"{field} must not be empty or whitespace-padded")
        if value.startswith(("0x", "0X")):
            body = value[2:]
            if not _HEX32_RE.fullmatch(body):
                raise UnsafeProofIdentifierError(
                    f"{field} hex identifier must be a 32-byte (64-hex-char) digest"
                )
            return body.lower()
        if len(value) == 64 and _HEX32_RE.fullmatch(value):
            return value.lower()
        if _STRICT_DECIMAL_ID_RE.fullmatch(value):
            return value
        raise UnsafeProofIdentifierError(
            f"{field} must be an exact non-negative decimal ID or 32-byte hex digest"
        )
    raise UnsafeProofIdentifierError(f"{field} has unsupported identifier type")

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
            return response.status, json.loads(
                response.read().decode("utf-8"),
                parse_float=Decimal,
            )
    except urllib.error.HTTPError as e:
        return e.code, None


def _latest_ledger(rpc_url: str, timeout: float = 10.0) -> int | None:
    status, data = _fetch_json(f"{rpc_url}/fee_stats", timeout=timeout)
    if status == 200 and data:
        raw_last = data.get("last_ledger")
        if raw_last is None:
            return None
        try:
            parsed = parse_strict_uint(raw_last, field="last_ledger")
            return parsed or None
        except UnsafeProofIdentifierError:
            return None
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
                ledger = parse_strict_uint(ledger_raw, field="ledger") if ledger_raw is not None else None
            except UnsafeProofIdentifierError:
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
