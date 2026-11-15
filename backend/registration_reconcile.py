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

import hashlib
import logging
import os
from typing import Any, Mapping

from db import (
    find_registration_events_by_tx_hash,
    list_pending_registration_txs,
    update_tx_status,
)
from idempotency import preview_idempotency_repair
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
ROW_REVISION_DOMAIN = b"harpocrates:registration-row-revision:v1"


def compute_registration_row_revision(row: Mapping[str, Any]) -> str:
    """Compute a domain-separated optimistic revision digest over registration state."""
    hasher = hashlib.sha256()
    hasher.update(ROW_REVISION_DOMAIN)
    parts = (
        str(row.get("id") if row.get("id") is not None else ""),
        str(row.get("proof_id") or ""),
        str(row.get("tx_hash") or ""),
        str(row.get("tx_status") or ""),
        str(row.get("idempotency_key") or ""),
    )
    for part in parts:
        encoded = part.encode("utf-8")
        hasher.update(len(encoded).to_bytes(4, "big"))
        hasher.update(encoded)
    return hasher.hexdigest()


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


def reconcile_registration(
    tx_hash: object,
    *,
    previous_status: str | None = "pending",
    proof_id: str | None = None,
    event_id: int | None = None,
    min_confirmations: int | None = None,
    force: bool = False,
    preview: bool = False,
) -> dict[str, Any]:
    """
    Reconcile a single registration transaction hash against Horizon.

    - Malformed hashes → status ``failed`` / reason ``malformed_tx_hash``
    - Horizon dependency failures → status ``error`` (no durable write)
    - Terminal rows are left unchanged unless ``force`` is true
    - ``preview=True`` evaluates chain state without applying any database write
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
        if preview:
            payload["preview"] = True
            payload["writesApplied"] = False
        return payload

    if (
        previous_status in TERMINAL_STATUSES
        and not force
        and not preview
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

    if verification.status in TERMINAL_STATUSES and not preview:
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
    if preview:
        payload["preview"] = True
        payload["writesApplied"] = False
    return payload


def preview_registration_repair(
    tx_hash: object,
    *,
    min_confirmations: int | None = None,
    rows: list[dict[str, Any]] | None = None,
    request_digest: str | None = None,
) -> dict[str, Any]:
    """Generate a strictly read-only operator repair preview for ``tx_hash``.

    Shows proposed database ``tx_status`` updates, observed Horizon chain
    evidence, contradiction flags, and per-row ``expectedRevision`` digests
    while applying zero persistence writes.
    """
    min_conf = (
        default_min_confirmations()
        if min_confirmations is None
        else int(min_confirmations)
    )
    if min_conf < 1:
        raise ValueError("minConfirmations must be >= 1")

    normalized = normalize_tx_hash(tx_hash)
    stored_rows = (
        [dict(item) for item in rows]
        if rows is not None
        else find_registration_events_by_tx_hash(normalized)
    )
    verification = verify_transaction(normalized, min_confirmations=min_conf)

    chain_evidence: dict[str, Any] = {
        "txHash": normalized,
        "status": verification.status,
        "reason": verification.reason,
        "ledger": verification.ledger,
        "latestLedger": verification.latest_ledger,
        "confirmations": verification.confirmations,
        "successful": verification.successful,
        "source": verification.source,
        "minConfirmationsApplied": min_conf,
    }

    distinct_proof_ids = {
        str(r.get("proof_id")) for r in stored_rows if r.get("proof_id") is not None
    }
    distinct_statuses = {
        str(r.get("tx_status")) for r in stored_rows if r.get("tx_status") is not None
    }
    multi_row_divergence = len(distinct_proof_ids) > 1 or len(distinct_statuses) > 1

    inspected_rows: list[dict[str, Any]] = []
    proposed_updates: list[dict[str, Any]] = []
    contradiction_reasons: list[str] = []

    if multi_row_divergence:
        contradiction_reasons.append("divergent_rows_for_tx_hash")

    for row in stored_rows:
        row_id = row.get("id")
        row_proof_id = row.get("proof_id")
        current_status = row.get("tx_status")
        expected_revision = compute_registration_row_revision(row)

        row_contradictions: list[str] = []
        if multi_row_divergence:
            row_contradictions.append("divergent_rows_for_tx_hash")
        if (
            current_status in TERMINAL_STATUSES
            and verification.status in TERMINAL_STATUSES
            and current_status != verification.status
        ):
            reason = f"terminal_status_mismatch:{current_status}->{verification.status}"
            row_contradictions.append(reason)
            if reason not in contradiction_reasons:
                contradiction_reasons.append(reason)

        is_contradictory = len(row_contradictions) > 0
        would_update = (
            verification.status in TERMINAL_STATUSES
            and current_status != verification.status
        )

        inspected_rows.append(
            {
                "eventId": row_id,
                "proofId": row_proof_id,
                "tier": row.get("tier"),
                "contractId": row.get("contract_id"),
                "currentTxStatus": current_status,
                "expectedRevision": expected_revision,
                "contradictory": is_contradictory,
                "contradictionReasons": row_contradictions,
                "proposedAction": "update_tx_status" if would_update else "noop",
            }
        )

        if would_update:
            proposed_updates.append(
                {
                    "table": "proof_events",
                    "eventId": row_id,
                    "proofId": row_proof_id,
                    "txHash": normalized,
                    "expectedRevision": expected_revision,
                    "changes": {
                        "tx_status": {
                            "from": current_status,
                            "to": verification.status,
                        }
                    },
                    "requiresForce": current_status in TERMINAL_STATUSES,
                    "contradictory": is_contradictory,
                    "contradictionReasons": row_contradictions,
                }
            )

    idem_preview = (
        preview_idempotency_repair(request_digest, "register")
        if isinstance(request_digest, str) and request_digest.strip()
        else None
    )

    return {
        "ok": True,
        "preview": True,
        "writesApplied": False,
        "txHash": normalized,
        "contradictory": len(contradiction_reasons) > 0,
        "contradictionReasons": contradiction_reasons,
        "chainEvidence": chain_evidence,
        "inspectedRows": inspected_rows,
        "proposedUpdates": proposed_updates,
        "idempotencyPreview": idem_preview,
    }


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
    result = reconcile_registration(
        tx_hash,
        previous_status="pending",
        proof_id=proof_id if isinstance(proof_id, str) else None,
        min_confirmations=int(min_confirmations) if min_confirmations is not None else None,
    )
    if result.get("status") == "error":
        # Surface dependency failures so the worker can retry non-fatally.
        raise RuntimeError(result.get("reason") or "horizon_dependency_failure")
    return result
