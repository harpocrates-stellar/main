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

import hmac
import logging
import os
from typing import Any

from db import list_pending_registration_txs, update_tx_status
from idempotency import (
    IntentConflictError,
    compute_intent_digest,
    get_registration_intent,
    normalize_intent_digest,
    persist_registration_intent,
)
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
    intent_digest: str | None = None,
    intent_verified: bool | None = None,
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
    if intent_digest is not None:
        payload["intentDigest"] = intent_digest
    if intent_verified is not None:
        payload["intentVerified"] = intent_verified
    return payload


def _resolve_observed_digest(
    registered_statement: dict[str, Any] | None,
    verification: TxVerificationResult,
) -> tuple[str | None, str | None]:
    """Return ``(digest, error_reason)`` for the on-chain registered statement."""
    candidate_statement = (
        registered_statement
        if registered_statement is not None
        else verification.registered_statement
    )
    if candidate_statement is not None:
        try:
            return compute_intent_digest(candidate_statement), None
        except ValueError:
            return None, "registered_statement_invalid"

    if verification.registered_intent_digest is not None:
        try:
            return normalize_intent_digest(verification.registered_intent_digest), None
        except ValueError:
            return None, "registered_statement_invalid"

    return None, None


def reconcile_registration(
    tx_hash: object,
    *,
    previous_status: str | None = "pending",
    proof_id: str | None = None,
    event_id: int | None = None,
    min_confirmations: int | None = None,
    force: bool = False,
    expected_statement: dict[str, Any] | None = None,
    intent_digest: str | None = None,
    registered_statement: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Reconcile a single registration transaction hash against Horizon.

    - Malformed hashes → status ``failed`` / reason ``malformed_tx_hash``
    - Horizon dependency failures → status ``error`` (no durable write)
    - Terminal rows are left unchanged unless ``force`` is true
    - When ``expected_statement`` or ``intent_digest`` is bound (or previously
      persisted for ``tx_hash``), the intent digest is persisted before
      transaction verification and any confirmed transaction whose registered
      statement differs from (or omits) the approved intent is rejected.
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

    effective_intent_digest: str | None = None
    if expected_statement is not None:
        try:
            computed_digest = compute_intent_digest(expected_statement)
        except ValueError:
            verification = TxVerificationResult(
                status="failed",
                reason="invalid_expected_statement",
            )
            return _result_payload(
                tx_hash=normalized,
                previous_status=previous_status,
                verification=verification,
                updated=False,
                proof_id=proof_id,
                event_id=event_id,
            )
        if intent_digest is not None:
            try:
                normalized_arg_digest = normalize_intent_digest(intent_digest)
            except ValueError:
                verification = TxVerificationResult(
                    status="failed",
                    reason="malformed_intent_digest",
                )
                return _result_payload(
                    tx_hash=normalized,
                    previous_status=previous_status,
                    verification=verification,
                    updated=False,
                    proof_id=proof_id,
                    event_id=event_id,
                )
            if not hmac.compare_digest(computed_digest, normalized_arg_digest):
                verification = TxVerificationResult(
                    status="failed",
                    reason="intent_digest_mismatch",
                )
                return _result_payload(
                    tx_hash=normalized,
                    previous_status=previous_status,
                    verification=verification,
                    updated=False,
                    proof_id=proof_id,
                    event_id=event_id,
                    intent_digest=computed_digest,
                    intent_verified=False,
                )
        effective_intent_digest = computed_digest
    elif intent_digest is not None:
        try:
            effective_intent_digest = normalize_intent_digest(intent_digest)
        except ValueError:
            verification = TxVerificationResult(
                status="failed",
                reason="malformed_intent_digest",
            )
            return _result_payload(
                tx_hash=normalized,
                previous_status=previous_status,
                verification=verification,
                updated=False,
                proof_id=proof_id,
                event_id=event_id,
            )
    else:
        stored_intent = get_registration_intent(normalized)
        if stored_intent and isinstance(stored_intent.get("intent_digest"), str):
            effective_intent_digest = stored_intent["intent_digest"]

    if effective_intent_digest is not None:
        try:
            persist_registration_intent(normalized, effective_intent_digest)
        except IntentConflictError:
            LOGGER.warning(
                "registration_reconcile_intent_conflict tx=%s",
                _short_hash(normalized),
            )
            verification = TxVerificationResult(
                status="failed",
                reason="intent_digest_conflict",
            )
            return _result_payload(
                tx_hash=normalized,
                previous_status=previous_status,
                verification=verification,
                updated=False,
                proof_id=proof_id,
                event_id=event_id,
                intent_digest=effective_intent_digest,
                intent_verified=False,
            )

    verification = verify_transaction(normalized, min_confirmations=min_conf)
    intent_verified: bool | None = None

    if verification.status == "confirmed" and effective_intent_digest is not None:
        observed_digest, observed_err = _resolve_observed_digest(
            registered_statement,
            verification,
        )
        if observed_err is not None:
            LOGGER.warning(
                "registration_reconcile_statement_invalid tx=%s",
                _short_hash(normalized),
            )
            verification = TxVerificationResult(
                status="failed",
                reason=observed_err,
                ledger=verification.ledger,
                latest_ledger=verification.latest_ledger,
                confirmations=verification.confirmations,
                successful=verification.successful,
                source=verification.source,
            )
            intent_verified = False
        elif observed_digest is None:
            LOGGER.warning(
                "registration_reconcile_statement_missing tx=%s",
                _short_hash(normalized),
            )
            verification = TxVerificationResult(
                status="failed",
                reason="registered_statement_missing",
                ledger=verification.ledger,
                latest_ledger=verification.latest_ledger,
                confirmations=verification.confirmations,
                successful=verification.successful,
                source=verification.source,
            )
            intent_verified = False
        elif not hmac.compare_digest(effective_intent_digest, observed_digest):
            LOGGER.warning(
                "registration_reconcile_statement_mismatch tx=%s",
                _short_hash(normalized),
            )
            verification = TxVerificationResult(
                status="failed",
                reason="registered_statement_mismatch",
                ledger=verification.ledger,
                latest_ledger=verification.latest_ledger,
                confirmations=verification.confirmations,
                successful=verification.successful,
                source=verification.source,
            )
            intent_verified = False
        else:
            intent_verified = True

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
        intent_digest=effective_intent_digest,
        intent_verified=intent_verified,
    )
    payload["minConfirmationsApplied"] = min_conf
    return payload


def reconcile_pending_registrations(
    *,
    limit: int = MAX_RECONCILE_BATCH,
    min_confirmations: int | None = None,
) -> dict[str, Any]:
    """Reconcile up to ``limit`` pending registration rows."""
    page_size = clamp_reconcile_limit(limit)
    min_conf = (
        default_min_confirmations()
        if min_confirmations is None
        else int(min_confirmations)
    )
    if min_conf < 1:
        raise ValueError("minConfirmations must be >= 1")

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

    return {
        "ok": True,
        "summary": summary,
        "minConfirmations": min_conf,
        "results": results,
    }


def process_verify_tx_job(payload: dict[str, Any]) -> dict[str, Any]:
    """Worker entrypoint for ``verify_tx`` jobs enqueued at registration time."""
    if not isinstance(payload, dict):
        raise ValueError("verify_tx payload must be an object")
    tx_hash = payload.get("tx_hash") or payload.get("txHash")
    proof_id = payload.get("proof_id") or payload.get("proofId")
    min_confirmations = payload.get("min_confirmations") or payload.get("minConfirmations")
    intent_digest = payload.get("intent_digest") or payload.get("intentDigest")
    expected_statement = payload.get("expected_statement") or payload.get("expectedStatement")
    registered_statement = payload.get("registered_statement") or payload.get("registeredStatement")
    kwargs: dict[str, Any] = {
        "previous_status": "pending",
        "proof_id": proof_id if isinstance(proof_id, str) else None,
        "min_confirmations": int(min_confirmations) if min_confirmations is not None else None,
    }
    if intent_digest is not None:
        kwargs["intent_digest"] = intent_digest
    if isinstance(expected_statement, dict):
        kwargs["expected_statement"] = expected_statement
    if isinstance(registered_statement, dict):
        kwargs["registered_statement"] = registered_statement
    result = reconcile_registration(tx_hash, **kwargs)
    if result.get("status") == "error":
        # Surface dependency failures so the worker can retry non-fatally.
        raise RuntimeError(result.get("reason") or "horizon_dependency_failure")
    return result
