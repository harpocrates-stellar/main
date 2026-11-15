"""Horizon-backed Stellar transaction status checks for registration reconcile."""

from __future__ import annotations
import base64
import binascii
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass
class TxVerificationResult:
    status: str = ""
    reason: str = ""
    ledger: int | None = None
    latest_ledger: int | None = None
    confirmations: int | None = None
    successful: bool | None = None
    source: str | None = None
    registered_statement_digest: str | None = None
    registered_statement_present: bool = False
    registered_statement_valid: bool | None = None
    tx_source_account: str | None = None
    tx_contract_id: str | None = None


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
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, None


def _latest_ledger(rpc_url: str, timeout: float = 10.0) -> int | None:
    status, data = _fetch_json(f"{rpc_url}/fee_stats", timeout=timeout)
    if status == 200 and data:
        return int(data.get("last_ledger", 0)) or None
    return None


def _decode_hash_memo_or_hex(raw_value: object) -> str | None:
    if not isinstance(raw_value, str):
        return None
    cleaned = raw_value.strip()
    if not cleaned:
        return None
    hex_candidate = cleaned[2:] if cleaned.lower().startswith("0x") else cleaned
    if len(hex_candidate) == 64 and all(c in "0123456789abcdefABCDEF" for c in hex_candidate):
        return hex_candidate.lower()
    try:
        decoded = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(decoded) == 32:
        return decoded.hex()
    return None


def extract_registered_statement_digest(
    tx_data: Mapping[str, Any],
) -> tuple[str | None, bool, bool]:
    """Extract canonical statement digest from a Horizon/indexer transaction payload.

    Returns ``(digest_or_none, statement_present, statement_valid)``.
    """
    from idempotency import CanonicalEvidenceStatement

    source_account = (
        tx_data.get("source_account")
        if isinstance(tx_data.get("source_account"), str)
        else None
    )
    contract_id_raw = tx_data.get("contract_id") or tx_data.get("contractId")
    contract_id = contract_id_raw if isinstance(contract_id_raw, str) else None

    for key in (
        "registered_statement",
        "registeredStatement",
        "evidence_statement",
        "evidenceStatement",
    ):
        if key in tx_data and tx_data[key] is not None:
            raw_stmt = tx_data[key]
            if not isinstance(raw_stmt, Mapping):
                return None, True, False
            try:
                stmt = CanonicalEvidenceStatement.from_mapping(
                    raw_stmt,
                    default_source_address=source_account,
                    default_contract_id=contract_id,
                )
            except ValueError:
                return None, True, False
            return stmt.intent_digest(), True, True

    for key in (
        "registered_statement_digest",
        "registeredStatementDigest",
        "statement_digest",
        "intent_digest",
    ):
        if key in tx_data and tx_data[key] is not None:
            parsed = _decode_hash_memo_or_hex(tx_data[key])
            if parsed is None:
                return None, True, False
            return parsed, True, True

    memo_type = tx_data.get("memo_type")
    if isinstance(memo_type, str) and memo_type.strip().lower() == "hash":
        parsed = _decode_hash_memo_or_hex(tx_data.get("memo"))
        if parsed is None:
            return None, True, False
        return parsed, True, True

    return None, False, True


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

            stmt_digest, stmt_present, stmt_valid = extract_registered_statement_digest(data)
            tx_source_account = (
                data.get("source_account")
                if isinstance(data.get("source_account"), str)
                else None
            )
            raw_contract = data.get("contract_id") or data.get("contractId")
            tx_contract_id = raw_contract if isinstance(raw_contract, str) else None

            if not successful:
                return TxVerificationResult(
                    status="failed",
                    ledger=ledger,
                    successful=False,
                    source=rpc_url,
                    reason="tx_unsuccessful",
                    registered_statement_digest=stmt_digest,
                    registered_statement_present=stmt_present,
                    registered_statement_valid=stmt_valid,
                    tx_source_account=tx_source_account,
                    tx_contract_id=tx_contract_id,
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
                    registered_statement_digest=stmt_digest,
                    registered_statement_present=stmt_present,
                    registered_statement_valid=stmt_valid,
                    tx_source_account=tx_source_account,
                    tx_contract_id=tx_contract_id,
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
                    registered_statement_digest=stmt_digest,
                    registered_statement_present=stmt_present,
                    registered_statement_valid=stmt_valid,
                    tx_source_account=tx_source_account,
                    tx_contract_id=tx_contract_id,
                )

            return TxVerificationResult(
                status="confirmed",
                ledger=ledger,
                latest_ledger=latest,
                confirmations=confirmations,
                successful=True,
                source=rpc_url,
                reason="confirmed",
                registered_statement_digest=stmt_digest,
                registered_statement_present=stmt_present,
                registered_statement_valid=stmt_valid,
                tx_source_account=tx_source_account,
                tx_contract_id=tx_contract_id,
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
