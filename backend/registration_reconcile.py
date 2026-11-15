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

from collections import deque
from datetime import datetime, timezone
import hashlib
import logging
import os
import threading
from typing import Any, Mapping

from db import list_pending_registration_txs, update_tx_status
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
DEFAULT_CONFLICT_QUARANTINE_MAX_ENTRIES = 256
MAX_CONFLICT_QUARANTINE_ENTRIES = 4096
STATEMENT_DIGEST_DOMAIN = b"harpocrates:registration-statement:v1"
_SAFE_TIERS = frozenset({"silent", "source", "seal"})
_SAFE_CONFLICT_FIELDS = frozenset(
    {
        "video_hash",
        "metadata_hash",
        "proof_id",
        "tier",
        "source_address",
        "contract_id",
        "tx_hash",
        "statement_digest",
        "tx_status",
        "request_digest",
    }
)


def _safe_hex32(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != 64 or not all(ch in "0123456789abcdef" for ch in cleaned):
        return None
    return cleaned


def _safe_tier(value: object) -> str | None:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _SAFE_TIERS:
            return normalized
    return None


def _safe_contract_id(value: object) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = value.strip().upper()
    if len(cleaned) == 56 and cleaned.startswith("C") and cleaned.isalnum():
        return cleaned
    return ""


def compute_registration_statement_digest(statement: Mapping[str, Any] | None) -> str | None:
    """Compute a canonical, privacy-safe digest over public statement bindings only.

    Explicitly ignores private/evidence fields such as ``metadata``, ``fileName``,
    ``timeAttestation``, ``witness``, and raw request bodies.
    """
    if not isinstance(statement, Mapping):
        return None
    proof_id = _safe_hex32(statement.get("proof_id") or statement.get("proofId")) or ""
    video_hash = _safe_hex32(statement.get("video_hash") or statement.get("videoHash")) or ""
    metadata_hash = _safe_hex32(statement.get("metadata_hash") or statement.get("metadataHash")) or ""
    tier = _safe_tier(statement.get("tier")) or ""
    contract_id = _safe_contract_id(statement.get("contract_id") or statement.get("contractId"))

    if not any((proof_id, video_hash, metadata_hash, tier, contract_id)):
        return None

    hasher = hashlib.sha256()
    hasher.update(STATEMENT_DIGEST_DOMAIN)
    for part in (proof_id, video_hash, metadata_hash, tier, contract_id):
        encoded = part.encode("ascii")
        hasher.update(len(encoded).to_bytes(4, "big"))
        hasher.update(encoded)
    return hasher.hexdigest()


def conflict_quarantine_capacity() -> int:
    configured = _env_int(
        "REGISTRATION_CONFLICT_QUARANTINE_MAX_ENTRIES",
        DEFAULT_CONFLICT_QUARANTINE_MAX_ENTRIES,
    )
    return max(1, min(configured, MAX_CONFLICT_QUARANTINE_ENTRIES))


class RegistrationConflictQuarantine:
    """Bounded, privacy-safe ring buffer of contradictory registration references.

    Retains only canonical statement digests, normalized transaction hashes,
    protocol tier enums, and bounded conflict reason codes for operator review.
    Private evidence metadata, filenames, witnesses, addresses, and raw payloads
    are excluded by construction.
    """

    def __init__(self, max_entries: int | None = None) -> None:
        capacity = conflict_quarantine_capacity() if max_entries is None else int(max_entries)
        if capacity < 1 or capacity > MAX_CONFLICT_QUARANTINE_ENTRIES:
            raise ValueError(
                f"max_entries must be between 1 and {MAX_CONFLICT_QUARANTINE_ENTRIES}"
            )
        self._lock = threading.Lock()
        self._capacity = capacity
        self._entries: deque[dict[str, Any]] = deque(maxlen=capacity)
        self._next_id = 1
        self._evicted = 0

    @property
    def capacity(self) -> int:
        return self._capacity

    def record(
        self,
        *,
        conflict_kind: str,
        conflict_field: str | None = None,
        proof_id: object = None,
        expected_statement: Mapping[str, Any] | None = None,
        observed_statement: Mapping[str, Any] | None = None,
        expected_statement_digest: object = None,
        observed_statement_digest: object = None,
        expected_tx_hash: object = None,
        observed_tx_hash: object = None,
        idempotency_key: object = None,
    ) -> dict[str, Any]:
        safe_kind = (
            conflict_kind.strip().lower()[:64]
            if isinstance(conflict_kind, str) and conflict_kind.strip()
            else "registration_conflict"
        )
        safe_field = (
            conflict_field if conflict_field in _SAFE_CONFLICT_FIELDS else "statement_digest"
        )
        exp_digest = _safe_hex32(expected_statement_digest) or compute_registration_statement_digest(
            expected_statement
        )
        obs_digest = _safe_hex32(observed_statement_digest) or compute_registration_statement_digest(
            observed_statement
        )
        safe_proof_id = (
            _safe_hex32(proof_id)
            or (
                _safe_hex32(expected_statement.get("proof_id") or expected_statement.get("proofId"))
                if isinstance(expected_statement, Mapping)
                else None
            )
            or (
                _safe_hex32(observed_statement.get("proof_id") or observed_statement.get("proofId"))
                if isinstance(observed_statement, Mapping)
                else None
            )
        )
        exp_tx = (
            _safe_hex32(expected_tx_hash)
            or (
                _safe_hex32(expected_statement.get("tx_hash") or expected_statement.get("txHash"))
                if isinstance(expected_statement, Mapping)
                else None
            )
        )
        obs_tx = (
            _safe_hex32(observed_tx_hash)
            or (
                _safe_hex32(observed_statement.get("tx_hash") or observed_statement.get("txHash"))
                if isinstance(observed_statement, Mapping)
                else None
            )
        )
        exp_tier = (
            _safe_tier(expected_statement.get("tier"))
            if isinstance(expected_statement, Mapping)
            else None
        )
        obs_tier = (
            _safe_tier(observed_statement.get("tier"))
            if isinstance(observed_statement, Mapping)
            else None
        )
        idem_digest = _safe_hex32(idempotency_key)
        idem_prefix = idem_digest[:8] if idem_digest else None

        with self._lock:
            if len(self._entries) >= self._capacity:
                self._evicted += 1
            quarantine_id = self._next_id
            self._next_id += 1
            entry: dict[str, Any] = {
                "quarantineId": quarantine_id,
                "recordedAt": datetime.now(timezone.utc).isoformat(),
                "conflictKind": safe_kind,
                "conflictField": safe_field,
                "proofId": safe_proof_id,
                "expectedStatementDigest": exp_digest,
                "observedStatementDigest": obs_digest,
                "expectedTxHash": exp_tx,
                "observedTxHash": obs_tx,
                "expectedTier": exp_tier,
                "observedTier": obs_tier,
                "idempotencyKeyPrefix": idem_prefix,
            }
            self._entries.append(entry)
            LOGGER.warning(
                "registration_conflict_quarantined id=%s kind=%s field=%s",
                quarantine_id,
                safe_kind,
                safe_field,
            )
            return dict(entry)

    def snapshot(
        self,
        *,
        limit: object = MAX_RECONCILE_BATCH,
        proof_id: object = None,
    ) -> dict[str, Any]:
        page_size = clamp_reconcile_limit(limit)
        filter_proof = None
        if proof_id is not None:
            filter_proof = _safe_hex32(proof_id)
            if filter_proof is None:
                raise ValueError("proofId must be a 32-byte hex string")

        with self._lock:
            ordered = list(reversed(self._entries))
            if filter_proof is not None:
                ordered = [item for item in ordered if item.get("proofId") == filter_proof]
            items = [dict(item) for item in ordered[:page_size]]
            return {
                "capacity": self._capacity,
                "count": len(self._entries),
                "evicted": self._evicted,
                "items": items,
            }

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._evicted = 0


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        return default
    return value if value >= 1 else default


_CONFLICT_QUARANTINE = RegistrationConflictQuarantine()


def get_conflict_quarantine() -> RegistrationConflictQuarantine:
    return _CONFLICT_QUARANTINE


def record_registration_conflict(**kwargs: Any) -> dict[str, Any]:
    """Record a contradictory registration statement or tx reference for operator review."""
    return _CONFLICT_QUARANTINE.record(**kwargs)


def inspect_registration_conflicts(
    *,
    limit: object = MAX_RECONCILE_BATCH,
    proof_id: object = None,
) -> dict[str, Any]:
    """Return a bounded, privacy-safe diagnostic view of quarantined conflicts."""
    return _CONFLICT_QUARANTINE.snapshot(limit=limit, proof_id=proof_id)


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
    expected_statement_digest: str | None = None,
    observed_statement_digest: str | None = None,
    expected_tx_hash: str | None = None,
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
        return payload

    if expected_tx_hash is not None:
        normalized_expected_tx = _safe_hex32(expected_tx_hash)
        if normalized_expected_tx is None:
            raise ValueError("expected_tx_hash must be a 32-byte hex string")
        if normalized_expected_tx != normalized:
            quarantine_entry = record_registration_conflict(
                conflict_kind="reconcile_tx_reference_mismatch",
                conflict_field="tx_hash",
                proof_id=proof_id,
                expected_statement_digest=expected_statement_digest,
                observed_statement_digest=observed_statement_digest,
                expected_tx_hash=normalized_expected_tx,
                observed_tx_hash=normalized,
            )
            verification = TxVerificationResult(
                status="failed",
                reason="contradictory_tx_reference",
            )
            payload = _result_payload(
                tx_hash=normalized,
                previous_status=previous_status,
                verification=verification,
                updated=False,
                proof_id=proof_id,
                event_id=event_id,
            )
            payload["quarantined"] = True
            payload["quarantineId"] = quarantine_entry["quarantineId"]
            return payload

    if expected_statement_digest is not None and observed_statement_digest is not None:
        norm_exp_stmt = _safe_hex32(expected_statement_digest)
        norm_obs_stmt = _safe_hex32(observed_statement_digest)
        if norm_exp_stmt is None or norm_obs_stmt is None:
            raise ValueError("statement digests must be 32-byte hex strings")
        if norm_exp_stmt != norm_obs_stmt:
            quarantine_entry = record_registration_conflict(
                conflict_kind="reconcile_statement_contradiction",
                conflict_field="statement_digest",
                proof_id=proof_id,
                expected_statement_digest=norm_exp_stmt,
                observed_statement_digest=norm_obs_stmt,
                expected_tx_hash=normalized,
                observed_tx_hash=normalized,
            )
            verification = TxVerificationResult(
                status="failed",
                reason="contradictory_registration_statement",
            )
            payload = _result_payload(
                tx_hash=normalized,
                previous_status=previous_status,
                verification=verification,
                updated=False,
                proof_id=proof_id,
                event_id=event_id,
            )
            payload["quarantined"] = True
            payload["quarantineId"] = quarantine_entry["quarantineId"]
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

    payload = _result_payload(
        tx_hash=normalized,
        previous_status=previous_status,
        verification=verification,
        updated=updated,
        proof_id=proof_id,
        event_id=event_id,
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
