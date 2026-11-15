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
from typing import Any, Mapping

from db import list_pending_registration_txs, update_tx_status
from idempotency import (
    CanonicalEvidenceStatement,
    PersistedRegistrationIntent,
    RegistrationIntentStore,
    StatementIntentConflictError,
    _owner_binding_digest,
    compute_statement_intent_digest,
    get_registration_intent,
    persist_registration_intent,
    reset_registration_intents,
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


def _require_onchain_statement_default() -> bool:
    raw = os.getenv("REQUIRE_ONCHAIN_STATEMENT_INTENT")
    if raw is None:
        return False
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _coerce_observed_statement_digest(
    registered_statement: CanonicalEvidenceStatement | Mapping[str, Any] | str,
    *,
    default_source_address: str | None = None,
    default_contract_id: str | None = None,
) -> tuple[str | None, bool]:
    if isinstance(registered_statement, CanonicalEvidenceStatement):
        return registered_statement.intent_digest(), True
    if isinstance(registered_statement, Mapping):
        try:
            stmt = CanonicalEvidenceStatement.from_mapping(
                registered_statement,
                default_source_address=default_source_address,
                default_contract_id=default_contract_id,
            )
        except ValueError:
            return None, False
        return stmt.intent_digest(), True
    if isinstance(registered_statement, str):
        cleaned = registered_statement.strip().lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        if len(cleaned) == 64 and all(c in "0123456789abcdef" for c in cleaned):
            return cleaned, True
        return None, False
    return None, False


def verify_statement_intent_binding(
    intent: PersistedRegistrationIntent,
    verification: TxVerificationResult,
    *,
    registered_statement: CanonicalEvidenceStatement | Mapping[str, Any] | str | None = None,
    require_onchain_statement: bool | None = None,
) -> tuple[bool, str | None]:
    """Compare an observed transaction statement against the persisted registration intent.

    Returns ``(matched, failure_reason)`` failing closed whenever the transaction's
    registered statement, contract, or submitting account diverges from the approved
    canonical evidence statement.
    """
    digest_verified = False

    if registered_statement is not None:
        observed_digest, valid = _coerce_observed_statement_digest(
            registered_statement,
            default_source_address=verification.tx_source_account,
            default_contract_id=verification.tx_contract_id,
        )
        if not valid or observed_digest is None:
            return False, "statement_intent_mismatch"
        if not hmac.compare_digest(intent.intent_digest, observed_digest):
            return False, "statement_intent_mismatch"
        digest_verified = True

    if verification.registered_statement_present:
        if verification.registered_statement_valid is False:
            return False, "statement_intent_mismatch"
        if verification.registered_statement_digest is not None:
            if not hmac.compare_digest(
                intent.intent_digest, verification.registered_statement_digest
            ):
                return False, "statement_intent_mismatch"
            digest_verified = True

    if (
        intent.contract_id
        and verification.tx_contract_id
        and verification.tx_contract_id.strip() != intent.contract_id
    ):
        return False, "statement_intent_mismatch"

    if intent.owner_digest and verification.tx_source_account:
        observed_owner = _owner_binding_digest(verification.tx_source_account)
        if not hmac.compare_digest(intent.owner_digest, observed_owner):
            return False, "statement_intent_mismatch"

    require_stmt = (
        _require_onchain_statement_default()
        if require_onchain_statement is None
        else bool(require_onchain_statement)
    )
    if require_stmt and not digest_verified:
        return False, "missing_registered_statement"

    return True, None


def reconcile_registration(
    tx_hash: object,
    *,
    previous_status: str | None = "pending",
    proof_id: str | None = None,
    event_id: int | None = None,
    min_confirmations: int | None = None,
    force: bool = False,
    approved_statement: CanonicalEvidenceStatement | Mapping[str, Any] | None = None,
    registered_statement: CanonicalEvidenceStatement | Mapping[str, Any] | str | None = None,
    expected_intent_digest: str | None = None,
    require_intent: bool = False,
    require_onchain_statement: bool | None = None,
) -> dict[str, Any]:
    """
    Reconcile a single registration transaction hash against Horizon.

    - Malformed hashes → status ``failed`` / reason ``malformed_tx_hash``
    - Approved statement intent is persisted before transaction verification
    - Mismatched registered statements → status ``failed`` / reason ``statement_intent_mismatch``
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

    intent: PersistedRegistrationIntent | None = None
    if approved_statement is not None:
        try:
            intent = persist_registration_intent(approved_statement, tx_hash=normalized)
        except StatementIntentConflictError:
            LOGGER.warning(
                "registration_reconcile_rejected tx=%s reason=statement_intent_conflict",
                _short_hash(normalized),
            )
            conflict_ver = TxVerificationResult(
                status="failed", reason="statement_intent_conflict"
            )
            payload = _result_payload(
                tx_hash=normalized,
                previous_status=previous_status,
                verification=conflict_ver,
                updated=False,
                proof_id=proof_id,
                event_id=event_id,
            )
            payload["minConfirmationsApplied"] = min_conf
            payload["intentVerified"] = False
            payload["error"] = "statement_intent_conflict"
            return payload
    else:
        intent = get_registration_intent(tx_hash=normalized, proof_id=proof_id)

    if expected_intent_digest is not None:
        cleaned_expected, valid_expected = _coerce_observed_statement_digest(
            expected_intent_digest
        )
        if not valid_expected or cleaned_expected is None:
            raise ValueError("expected_intent_digest must be a 32-byte hex string")
        if intent is None:
            LOGGER.warning(
                "registration_reconcile_rejected tx=%s reason=missing_registration_intent",
                _short_hash(normalized),
            )
            missing_ver = TxVerificationResult(
                status="failed", reason="missing_registration_intent"
            )
            payload = _result_payload(
                tx_hash=normalized,
                previous_status=previous_status,
                verification=missing_ver,
                updated=False,
                proof_id=proof_id,
                event_id=event_id,
            )
            payload["minConfirmationsApplied"] = min_conf
            payload["intentVerified"] = False
            payload["error"] = "missing_registration_intent"
            return payload
        if not hmac.compare_digest(intent.intent_digest, cleaned_expected):
            updated = bool(update_tx_status(normalized, "failed", force=force))
            mismatch_ver = TxVerificationResult(
                status="failed", reason="statement_intent_mismatch"
            )
            payload = _result_payload(
                tx_hash=normalized,
                previous_status=previous_status,
                verification=mismatch_ver,
                updated=updated,
                proof_id=proof_id,
                event_id=event_id,
            )
            payload["minConfirmationsApplied"] = min_conf
            payload["intentDigest"] = intent.intent_digest
            payload["intentVerified"] = False
            return payload

    if intent is None and require_intent:
        LOGGER.warning(
            "registration_reconcile_rejected tx=%s reason=missing_registration_intent",
            _short_hash(normalized),
        )
        missing_ver = TxVerificationResult(
            status="failed", reason="missing_registration_intent"
        )
        payload = _result_payload(
            tx_hash=normalized,
            previous_status=previous_status,
            verification=missing_ver,
            updated=False,
            proof_id=proof_id,
            event_id=event_id,
        )
        payload["minConfirmationsApplied"] = min_conf
        payload["intentVerified"] = False
        payload["error"] = "missing_registration_intent"
        return payload

    verification = verify_transaction(normalized, min_confirmations=min_conf)
    if intent is not None and verification.status in {"confirmed", "pending"}:
        matched, mismatch_reason = verify_statement_intent_binding(
            intent,
            verification,
            registered_statement=registered_statement,
            require_onchain_statement=require_onchain_statement,
        )
        if not matched and (
            mismatch_reason == "statement_intent_mismatch"
            or verification.status == "confirmed"
        ):
            LOGGER.warning(
                "registration_reconcile_intent_mismatch tx=%s reason=%s",
                _short_hash(normalized),
                mismatch_reason or "statement_intent_mismatch",
            )
            verification = TxVerificationResult(
                status="failed",
                reason=mismatch_reason or "statement_intent_mismatch",
                ledger=verification.ledger,
                latest_ledger=verification.latest_ledger,
                confirmations=verification.confirmations,
                successful=verification.successful,
                source=verification.source,
            )

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
    if intent is not None:
        payload["intentDigest"] = intent.intent_digest
        payload["intentVerified"] = verification.status == "confirmed"
    return payload


def _statement_from_pending_row(row: Mapping[str, Any]) -> CanonicalEvidenceStatement | None:
    if not (
        row.get("proof_id")
        and row.get("video_hash")
        and row.get("metadata_hash")
        and row.get("tier")
    ):
        return None
    try:
        return CanonicalEvidenceStatement(
            proof_id=str(row["proof_id"]),
            video_hash=str(row["video_hash"]),
            metadata_hash=str(row["metadata_hash"]),
            tier=str(row["tier"]),
            source_address=str(row.get("source_address") or ""),
            contract_id=str(row.get("contract_id") or ""),
        )
    except ValueError:
        return None


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
        extra_kwargs: dict[str, Any] = {}
        row_statement = _statement_from_pending_row(row)
        if row_statement is not None:
            extra_kwargs["approved_statement"] = row_statement
        item = reconcile_registration(
            row.get("tx_hash"),
            previous_status=row.get("tx_status") or "pending",
            proof_id=row.get("proof_id"),
            event_id=row.get("id"),
            min_confirmations=min_conf,
            force=False,
            **extra_kwargs,
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
    approved_statement = payload.get("approved_statement") or payload.get("approvedStatement")
    registered_statement = (
        payload.get("registered_statement") or payload.get("registeredStatement")
    )

    extra_kwargs: dict[str, Any] = {}
    if isinstance(intent_digest, str) and intent_digest.strip():
        extra_kwargs["expected_intent_digest"] = intent_digest.strip()
        extra_kwargs["require_intent"] = True
    if approved_statement is not None:
        extra_kwargs["approved_statement"] = approved_statement
    if registered_statement is not None:
        extra_kwargs["registered_statement"] = registered_statement

    result = reconcile_registration(
        tx_hash,
        previous_status="pending",
        proof_id=proof_id if isinstance(proof_id, str) else None,
        min_confirmations=int(min_confirmations) if min_confirmations is not None else None,
        **extra_kwargs,
    )
    if result.get("status") == "error":
        # Surface dependency failures so the worker can retry non-fatally.
        raise RuntimeError(result.get("reason") or "horizon_dependency_failure")
    return result
