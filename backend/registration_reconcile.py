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

from collections import OrderedDict, deque
from datetime import datetime, timezone
import logging
import os
import threading
from typing import Any

from db import find_proof_events_by_proof_id, list_pending_registration_txs, update_tx_status
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
DEFAULT_TIMELINE_MAX_ENTRIES = 64
MAX_TIMELINE_ENTRIES = 256
MAX_TIMELINE_PROOFS = 2048
TIMELINE_OUTCOMES = frozenset({"submitted", "confirmed", "rejected", "unknown"})


def _is_hex32(value: object) -> bool:
    if not isinstance(value, str):
        return False
    cleaned = value.strip().lower()
    return len(cleaned) == 64 and all(ch in "0123456789abcdef" for ch in cleaned)


def classify_timeline_outcome(status: str | None, reason: str | None = None) -> str:
    """Map reconciliation and registration statuses to canonical timeline outcomes.

    Distinguishes ``submitted``, ``confirmed``, ``rejected``, and ``unknown``.
    """
    normalized_status = (status or "").strip().lower()
    normalized_reason = (reason or "").strip().lower()

    if normalized_status == "confirmed":
        return "confirmed"
    if normalized_status in {"failed", "rejected"} or normalized_reason in {
        "tx_unsuccessful",
        "malformed_tx_hash",
        "idempotency_conflict",
        "validation_rejected",
    }:
        return "rejected"
    if normalized_status in {"pending", "submitted"}:
        return "submitted"
    if normalized_status in {"missing", "error", "unknown", ""}:
        return "unknown"
    return "unknown"


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        return default
    return value if value >= 1 else default


def timeline_max_entries() -> int:
    configured = _env_int("RECONCILE_TIMELINE_MAX_ENTRIES", DEFAULT_TIMELINE_MAX_ENTRIES)
    return max(1, min(configured, MAX_TIMELINE_ENTRIES))


class RegistrationTimelineStore:
    """Bounded, privacy-safe store of registration observations and state transitions."""

    def __init__(
        self,
        *,
        max_entries_per_proof: int | None = None,
        max_proofs: int = MAX_TIMELINE_PROOFS,
    ) -> None:
        per_proof = (
            timeline_max_entries()
            if max_entries_per_proof is None
            else max(1, min(int(max_entries_per_proof), MAX_TIMELINE_ENTRIES))
        )
        self._lock = threading.Lock()
        self._max_entries_per_proof = per_proof
        self._max_proofs = max(1, int(max_proofs))
        self._buckets: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._tx_to_proof: OrderedDict[str, str] = OrderedDict()

    def _get_or_create_bucket(self, proof_id: str) -> dict[str, Any]:
        bucket = self._buckets.get(proof_id)
        if bucket is None:
            bucket = {
                "owner": None,
                "next_seq": 1,
                "evicted": 0,
                "current_outcome": "unknown",
                "entries": deque(maxlen=self._max_entries_per_proof),
            }
            self._buckets[proof_id] = bucket
        self._buckets.move_to_end(proof_id)
        while len(self._buckets) > self._max_proofs:
            self._buckets.popitem(last=False)
        return bucket

    def _append_entry(
        self,
        bucket: dict[str, Any],
        *,
        entry_type: str,
        outcome: str,
        reason: str,
        tx_hash: str | None = None,
        from_status: str | None = None,
        to_status: str | None = None,
        ledger: int | None = None,
        confirmations: int | None = None,
    ) -> dict[str, Any]:
        if outcome not in TIMELINE_OUTCOMES:
            outcome = "unknown"
        entries: deque[dict[str, Any]] = bucket["entries"]
        if len(entries) >= self._max_entries_per_proof:
            bucket["evicted"] = int(bucket["evicted"]) + 1
        seq = int(bucket["next_seq"])
        bucket["next_seq"] = seq + 1
        bucket["current_outcome"] = outcome

        safe_tx = None
        if isinstance(tx_hash, str):
            try:
                safe_tx = normalize_tx_hash(tx_hash)
            except ValueError:
                safe_tx = None

        record: dict[str, Any] = {
            "sequence": seq,
            "recordedAt": datetime.now(timezone.utc).isoformat(),
            "entryType": entry_type,
            "outcome": outcome,
            "reason": (reason or "unspecified")[:64],
            "txHash": safe_tx,
            "fromStatus": from_status,
            "toStatus": to_status,
            "ledger": ledger,
            "confirmations": confirmations,
        }
        entries.append(record)
        return dict(record)

    def record_submission(
        self,
        *,
        proof_id: str,
        tx_hash: str | None = None,
        outcome: str = "submitted",
        reason: str = "registration_submitted",
        owner: str | None = None,
    ) -> dict[str, Any] | None:
        if not _is_hex32(proof_id):
            return None
        norm_proof = proof_id.strip().lower()
        safe_outcome = outcome if outcome in TIMELINE_OUTCOMES else "submitted"
        with self._lock:
            bucket = self._get_or_create_bucket(norm_proof)
            if owner and bucket["owner"] is None:
                bucket["owner"] = owner.strip().upper()
            if tx_hash:
                try:
                    norm_tx = normalize_tx_hash(tx_hash)
                    self._tx_to_proof[norm_tx] = norm_proof
                    self._tx_to_proof.move_to_end(norm_tx)
                    while len(self._tx_to_proof) > self._max_proofs:
                        self._tx_to_proof.popitem(last=False)
                except ValueError:
                    pass
            return self._append_entry(
                bucket,
                entry_type="submission",
                outcome=safe_outcome,
                reason=reason,
                tx_hash=tx_hash,
                from_status=None,
                to_status="pending" if safe_outcome == "submitted" else safe_outcome,
            )

    def record_reconcile_step(
        self,
        *,
        tx_hash: str | None,
        proof_id: str | None,
        previous_status: str | None,
        verification: TxVerificationResult,
        updated: bool,
    ) -> None:
        with self._lock:
            norm_proof: str | None = None
            if proof_id and _is_hex32(proof_id):
                norm_proof = proof_id.strip().lower()
            elif tx_hash and _is_hex32(tx_hash):
                norm_proof = self._tx_to_proof.get(tx_hash.strip().lower())
            if norm_proof is None:
                return

            bucket = self._get_or_create_bucket(norm_proof)
            if tx_hash and _is_hex32(tx_hash):
                self._tx_to_proof[tx_hash.strip().lower()] = norm_proof

            outcome = classify_timeline_outcome(verification.status, verification.reason)
            self._append_entry(
                bucket,
                entry_type="observation",
                outcome=outcome,
                reason=verification.reason or verification.status,
                tx_hash=tx_hash,
                from_status=previous_status,
                to_status=verification.status,
                ledger=verification.ledger,
                confirmations=verification.confirmations,
            )
            if updated or (
                previous_status is not None
                and verification.status in TERMINAL_STATUSES
                and previous_status != verification.status
            ):
                self._append_entry(
                    bucket,
                    entry_type="transition",
                    outcome=outcome,
                    reason=verification.reason or verification.status,
                    tx_hash=tx_hash,
                    from_status=previous_status,
                    to_status=verification.status,
                    ledger=verification.ledger,
                    confirmations=verification.confirmations,
                )

    def get_owner(self, proof_id: str) -> str | None:
        if not _is_hex32(proof_id):
            return None
        with self._lock:
            bucket = self._buckets.get(proof_id.strip().lower())
            return str(bucket["owner"]) if bucket and bucket.get("owner") else None

    def get_timeline(self, proof_id: str, *, limit: object = MAX_RECONCILE_BATCH) -> dict[str, Any]:
        if not _is_hex32(proof_id):
            raise ValueError("proofId must be a 32-byte hex string")
        page_size = clamp_reconcile_limit(limit)
        norm_proof = proof_id.strip().lower()

        with self._lock:
            bucket = self._buckets.get(norm_proof)
            if bucket is None:
                entries: list[dict[str, Any]] = []
                evicted = 0
                current_outcome = "unknown"
            else:
                all_entries = [dict(item) for item in bucket["entries"]]
                entries = all_entries[-page_size:]
                evicted = int(bucket["evicted"])
                current_outcome = str(bucket["current_outcome"])

        if not entries:
            # Synthesize bounded read-only status from persisted proof_events if present.
            db_rows = find_proof_events_by_proof_id(norm_proof)
            if db_rows:
                latest_row = db_rows[0]
                tx_status = latest_row.get("tx_status")
                current_outcome = classify_timeline_outcome(
                    str(tx_status) if tx_status is not None else "unknown",
                    None,
                )
                entries = [
                    {
                        "sequence": 1,
                        "recordedAt": (
                            latest_row["created_at"].isoformat()
                            if hasattr(latest_row.get("created_at"), "isoformat")
                            else str(latest_row.get("created_at") or "")
                        ),
                        "entryType": "observation",
                        "outcome": current_outcome,
                        "reason": "persisted_registration_state",
                        "txHash": latest_row.get("tx_hash"),
                        "fromStatus": None,
                        "toStatus": tx_status,
                        "ledger": None,
                        "confirmations": None,
                    }
                ]

        observations = [e for e in entries if e["entryType"] in {"submission", "observation"}]
        transitions = [e for e in entries if e["entryType"] == "transition"]
        return {
            "ok": True,
            "proofId": norm_proof,
            "currentOutcome": current_outcome,
            "entryLimit": page_size,
            "maxEntriesPerProof": self._max_entries_per_proof,
            "totalReturned": len(entries),
            "evictedCount": evicted,
            "observations": observations,
            "transitions": transitions,
            "entries": entries,
        }

    def clear(self) -> None:
        with self._lock:
            self._buckets.clear()
            self._tx_to_proof.clear()


_TIMELINE_STORE = RegistrationTimelineStore()


def record_registration_timeline_submission(
    *,
    proof_id: str,
    tx_hash: str | None = None,
    outcome: str = "submitted",
    reason: str = "registration_submitted",
    owner: str | None = None,
) -> dict[str, Any] | None:
    return _TIMELINE_STORE.record_submission(
        proof_id=proof_id,
        tx_hash=tx_hash,
        outcome=outcome,
        reason=reason,
        owner=owner,
    )


def get_registration_reconcile_timeline(
    proof_id: str,
    *,
    limit: object = MAX_RECONCILE_BATCH,
) -> dict[str, Any]:
    return _TIMELINE_STORE.get_timeline(proof_id, limit=limit)


def get_timeline_recorded_owner(proof_id: str) -> str | None:
    return _TIMELINE_STORE.get_owner(proof_id)


def reset_reconcile_timeline_for_tests() -> None:
    _TIMELINE_STORE.clear()


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
) -> dict[str, Any]:
    """
    Reconcile a single registration transaction hash against Horizon.

    - Malformed hashes → status ``failed`` / reason ``malformed_tx_hash``
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
        _TIMELINE_STORE.record_reconcile_step(
            tx_hash=None,
            proof_id=proof_id,
            previous_status=previous_status,
            verification=verification,
            updated=False,
        )
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

    _TIMELINE_STORE.record_reconcile_step(
        tx_hash=normalized,
        proof_id=proof_id,
        previous_status=previous_status,
        verification=verification,
        updated=updated,
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
    payload["timelineOutcome"] = classify_timeline_outcome(
        verification.status, verification.reason
    )
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
