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

from dataclasses import dataclass
import json
import logging
import os
import threading
from typing import Any, Callable, Sequence

from db import (
    ConflictError,
    list_pending_registration_txs,
    make_idempotency_key,
    update_tx_status,
)
from idempotency import InMemoryIdempotencyStore, compute_canonical_request_digest
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


def reconcile_registration(
    tx_hash: object,
    *,
    previous_status: str | None = "pending",
    proof_id: str | None = None,
    event_id: int | None = None,
    min_confirmations: int | None = None,
    force: bool = False,
    verify_fn: Callable[..., TxVerificationResult] | None = None,
    update_fn: Callable[..., bool] | None = None,
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

    active_verify = verify_transaction if verify_fn is None else verify_fn
    active_update = update_tx_status if update_fn is None else update_fn

    verification = active_verify(normalized, min_confirmations=min_conf)
    updated = False

    if verification.status in TERMINAL_STATUSES:
        updated = bool(active_update(normalized, verification.status, force=force))
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
    list_pending_fn: Callable[..., list[dict[str, Any]]] | None = None,
    verify_fn: Callable[..., TxVerificationResult] | None = None,
    update_fn: Callable[..., bool] | None = None,
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

    active_list_pending = (
        list_pending_registration_txs if list_pending_fn is None else list_pending_fn
    )
    pending = active_list_pending(limit=page_size)
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
            verify_fn=verify_fn,
            update_fn=update_fn,
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


# ---------------------------------------------------------------------------
# Deterministic Registration Race Fixtures (Database + Chain Observations)
# ---------------------------------------------------------------------------

_ALLOWED_FIXTURE_TIERS = frozenset({"silent", "source", "seal"})
_CANONICAL_CONFLICT_FIELDS = (
    "video_hash",
    "metadata_hash",
    "proof_id",
    "tier",
    "source_address",
    "contract_id",
)


@dataclass(frozen=True)
class ChainObservationStep:
    """Single scripted Horizon observation in a deterministic race fixture."""

    kind: str  # "unindexed_grace", "indexed", "dependency_error", "missing"
    ledger: int | None = None
    latest_ledger: int | None = None
    successful: bool = True
    reason: str | None = None


@dataclass(frozen=True)
class RegistrationRaceOutcome:
    """Privacy-safe summary produced by a deterministic registration race run."""

    scenario: str
    submissions: int
    created_count: int
    replayed_count: int
    conflict_count: int
    reconcile_attempts: int
    stale_worker_rejections: int
    final_status: str | None
    authoritative_confirmed_count: int
    terminal_transition_count: int
    enqueued_jobs: int
    live_network_calls: int = 0


class SimulatedChainObserver:
    """Deterministic fake Horizon observer with zero live network calls.

    Evaluates scripted :class:`ChainObservationStep` sequences against the
    caller's ``min_confirmations`` depth policy identically to
    :func:`tx_verification.verify_transaction`, plus explicit modeling for
    delayed Horizon indexing before ledger inclusion is visible.
    """

    def __init__(self, scripts: dict[str, Sequence[ChainObservationStep]] | None = None) -> None:
        self._lock = threading.Lock()
        self._scripts: dict[str, list[ChainObservationStep]] = {}
        self._cursors: dict[str, int] = {}
        self.observation_count = 0
        self.live_network_calls = 0
        if scripts:
            for tx_hash, steps in scripts.items():
                self.set_script(tx_hash, steps)

    def set_script(self, tx_hash: str, steps: Sequence[ChainObservationStep]) -> None:
        normalized = normalize_tx_hash(tx_hash)
        if not steps:
            raise ValueError("observation script must contain at least one step")
        with self._lock:
            self._scripts[normalized] = list(steps)
            self._cursors[normalized] = 0

    def observe(self, tx_hash: str, *, min_confirmations: int = 1) -> TxVerificationResult:
        try:
            normalized = normalize_tx_hash(tx_hash)
        except ValueError:
            return TxVerificationResult(status="failed", reason="malformed_tx_hash")
        if min_confirmations < 1:
            return TxVerificationResult(status="error", reason="invalid_min_confirmations")

        with self._lock:
            self.observation_count += 1
            steps = self._scripts.get(normalized)
            if not steps:
                return TxVerificationResult(status="missing", reason="not_found_on_horizon")
            idx = self._cursors.get(normalized, 0)
            step = steps[min(idx, len(steps) - 1)]
            if idx < len(steps) - 1:
                self._cursors[normalized] = idx + 1

        if step.kind == "dependency_error":
            return TxVerificationResult(
                status="error",
                reason=step.reason or "horizon_dependency_failure",
                source="simulated://horizon",
            )
        if step.kind == "unindexed_grace":
            # Models the post-submission window before Horizon indexes the ledger.
            return TxVerificationResult(
                status="pending",
                ledger=None,
                latest_ledger=step.latest_ledger,
                confirmations=0,
                successful=None,
                source="simulated://horizon",
                reason=step.reason or "awaiting_indexer",
            )
        if step.kind == "missing":
            return TxVerificationResult(
                status="missing",
                reason=step.reason or "not_found_on_horizon",
                source="simulated://horizon",
            )
        if step.kind != "indexed":
            raise ValueError(f"unsupported ChainObservationStep.kind: {step.kind}")

        if not step.successful:
            return TxVerificationResult(
                status="failed",
                ledger=step.ledger,
                latest_ledger=step.latest_ledger,
                successful=False,
                source="simulated://horizon",
                reason=step.reason or "tx_unsuccessful",
            )

        if (
            step.ledger is None
            or step.latest_ledger is None
            or step.latest_ledger < step.ledger
        ):
            return TxVerificationResult(
                status="pending",
                ledger=step.ledger,
                latest_ledger=step.latest_ledger,
                successful=True,
                source="simulated://horizon",
                reason=step.reason or "confirmations_unavailable",
            )

        confirmations = step.latest_ledger - step.ledger + 1
        if confirmations < min_confirmations:
            return TxVerificationResult(
                status="pending",
                ledger=step.ledger,
                latest_ledger=step.latest_ledger,
                confirmations=confirmations,
                successful=True,
                source="simulated://horizon",
                reason=step.reason or "awaiting_confirmations",
            )

        return TxVerificationResult(
            status="confirmed",
            ledger=step.ledger,
            latest_ledger=step.latest_ledger,
            confirmations=confirmations,
            successful=True,
            source="simulated://horizon",
            reason=step.reason or "confirmed",
        )


class SimulatedRegistrationDb:
    """In-memory registration ledger & worker-lease harness for race tests.

    Mirrors ``proof_events`` semantic upsert idempotency, ``pending -> terminal``
    compare-and-swap transitions, and worker attempt-generation fencing without
    requiring external database infrastructure.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._next_id = 1
        self._rows_by_id: dict[int, dict[str, Any]] = {}
        self._idempotency_index: dict[str, int] = {}
        self._attempt_generations: dict[str, int] = {}
        self._active_workers: dict[str, str] = {}
        self.enqueued_jobs: list[dict[str, Any]] = []
        self.stale_worker_rejections = 0

    def upsert_register(
        self,
        *,
        video_hash: str,
        metadata_hash: str,
        proof_id: str,
        tier: str,
        tx_hash: str | None = None,
        source_address: str | None = None,
        contract_id: str | None = None,
    ) -> tuple[dict[str, Any], bool]:
        if tier not in _ALLOWED_FIXTURE_TIERS:
            raise ValueError(f"unsupported tier: {tier}")
        normalized_tx = normalize_tx_hash(tx_hash) if tx_hash is not None else None
        idem_key = make_idempotency_key(video_hash, proof_id, normalized_tx)

        with self._lock:
            existing_id = self._idempotency_index.get(idem_key)
            if existing_id is None:
                row_id = self._next_id
                self._next_id += 1
                row: dict[str, Any] = {
                    "id": row_id,
                    "event_type": "register",
                    "video_hash": video_hash,
                    "metadata_hash": metadata_hash,
                    "proof_id": proof_id,
                    "tier": tier,
                    "tx_hash": normalized_tx,
                    "tx_status": "pending" if normalized_tx else None,
                    "source_address": source_address,
                    "contract_id": contract_id,
                    "idempotency_key": idem_key,
                    "terminal_transitions": 0,
                    "confirmed_by_worker": None,
                }
                self._rows_by_id[row_id] = row
                self._idempotency_index[idem_key] = row_id
                if normalized_tx:
                    self.enqueued_jobs.append(
                        {
                            "type": "verify_tx",
                            "proof_id": proof_id,
                            "tx_hash": normalized_tx,
                            "contract_id": contract_id,
                        }
                    )
                return dict(row), True

            existing = self._rows_by_id[existing_id]
            incoming = {
                "video_hash": video_hash,
                "metadata_hash": metadata_hash,
                "proof_id": proof_id,
                "tier": tier,
                "source_address": source_address,
                "contract_id": contract_id,
            }
            for field in _CANONICAL_CONFLICT_FIELDS:
                if existing.get(field) != incoming.get(field):
                    raise ConflictError(
                        idempotency_key=idem_key,
                        field=field,
                        existing_value=existing.get(field),
                        incoming_value=incoming.get(field),
                    )
            return dict(existing), False

    def list_pending(self, limit: int = MAX_RECONCILE_BATCH) -> list[dict[str, Any]]:
        page_size = clamp_reconcile_limit(limit)
        with self._lock:
            pending = [
                dict(row)
                for row in sorted(self._rows_by_id.values(), key=lambda item: int(item["id"]))
                if row.get("tx_hash") is not None and row.get("tx_status") == "pending"
            ]
            return pending[:page_size]

    def claim_worker_attempt(self, tx_hash: str, worker_id: str) -> int:
        normalized = normalize_tx_hash(tx_hash)
        with self._lock:
            generation = self._attempt_generations.get(normalized, 0) + 1
            self._attempt_generations[normalized] = generation
            self._active_workers[normalized] = worker_id
            return generation

    def fenced_updater(
        self,
        *,
        worker_id: str,
        attempt_generation: int,
    ) -> Callable[..., bool]:
        """Return a ``update_fn`` bound to a specific worker attempt generation."""

        def _apply(tx_hash: str, status: str, *, force: bool = False) -> bool:
            return self.update_tx_status(
                tx_hash,
                status,
                force=force,
                worker_id=worker_id,
                expected_generation=attempt_generation,
            )

        return _apply

    def update_tx_status(
        self,
        tx_hash: str,
        status: str,
        *,
        force: bool = False,
        worker_id: str | None = None,
        expected_generation: int | None = None,
    ) -> bool:
        normalized = normalize_tx_hash(tx_hash)
        if status not in {"pending", "confirmed", "failed", "missing"}:
            raise ValueError("tx status must be pending, confirmed, failed, or missing")

        with self._lock:
            current_gen = self._attempt_generations.get(normalized)
            if expected_generation is not None and current_gen is not None:
                if int(expected_generation) != int(current_gen):
                    self.stale_worker_rejections += 1
                    return False

            updated_any = False
            for row in self._rows_by_id.values():
                if row.get("tx_hash") != normalized:
                    continue
                current_status = row.get("tx_status")
                if not force and current_status not in (None, "pending"):
                    continue
                row["tx_status"] = status
                if status in TERMINAL_STATUSES:
                    row["terminal_transitions"] = int(row.get("terminal_transitions", 0)) + 1
                    if status == "confirmed":
                        row["confirmed_by_worker"] = worker_id
                updated_any = True
            return updated_any

    def get_row_by_proof_id(self, proof_id: str) -> dict[str, Any] | None:
        with self._lock:
            for row in self._rows_by_id.values():
                if row.get("proof_id") == proof_id:
                    return dict(row)
            return None

    def authoritative_confirmed_rows(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                dict(row)
                for row in self._rows_by_id.values()
                if row.get("tx_status") == "confirmed"
            ]


def _synthetic_hex(char: str) -> str:
    if len(char) != 1 or char.lower() not in "0123456789abcdef":
        raise ValueError("char must be a single hex character")
    return char.lower() * 64


def run_duplicate_submission_race_fixture() -> RegistrationRaceOutcome:
    """Model duplicate & conflicting client submissions followed by reconciliation."""
    idem_store = InMemoryIdempotencyStore()
    db_sim = SimulatedRegistrationDb()
    tx_hash = _synthetic_hex("a")
    proof_id = _synthetic_hex("1")
    video_hash = _synthetic_hex("2")
    metadata_hash = _synthetic_hex("3")

    observer = SimulatedChainObserver(
        {
            tx_hash: [
                ChainObservationStep(kind="indexed", ledger=500, latest_ledger=502, successful=True),
            ]
        }
    )

    canonical_payload = {
        "videoHash": video_hash,
        "metadataHash": metadata_hash,
        "proofId": proof_id,
        "tier": "source",
        "txHash": tx_hash,
    }
    digest = compute_canonical_request_digest(
        "POST",
        "/api/proofs/register",
        b"",
        json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
    )

    created_count = 0
    replayed_count = 0
    conflict_count = 0

    # Submission 1 acquires request lock, inserts row, and stores 201 response.
    rec_id, _status, acquired_first, gen_first = idem_store.acquire(
        digest, "register", worker_id="api-worker-1"
    )
    assert acquired_first is True
    row1, created1 = db_sim.upsert_register(
        video_hash=video_hash,
        metadata_hash=metadata_hash,
        proof_id=proof_id,
        tier="source",
        tx_hash=tx_hash,
    )
    if created1:
        created_count += 1
    idem_store.complete(
        rec_id,
        {"status": 201, "body": {"ok": True, "created": True, "proofId": row1["proof_id"]}},
        expected_generation=gen_first,
        worker_id="api-worker-1",
    )

    # Submission 2 (exact byte-identical retry) replays cached response without re-enqueuing.
    _rec_id2, status2, acquired_second, _gen2 = idem_store.acquire(
        digest, "register", worker_id="api-worker-2"
    )
    if not acquired_second and status2 == "COMPLETED":
        replayed_count += 1

    # Submission 3 (different formatting / direct semantic retry) hits DB idempotency cleanly.
    _row3, created3 = db_sim.upsert_register(
        video_hash=video_hash,
        metadata_hash=metadata_hash,
        proof_id=proof_id,
        tier="source",
        tx_hash=tx_hash,
    )
    if not created3:
        replayed_count += 1

    # Submission 4 (conflicting identity tier on same registration key) fails closed.
    try:
        db_sim.upsert_register(
            video_hash=video_hash,
            metadata_hash=metadata_hash,
            proof_id=proof_id,
            tier="seal",
            tx_hash=tx_hash,
        )
    except ConflictError:
        conflict_count += 1

    # Reconcile pending row once and verify a second reconcile pass is a no-op.
    report1 = reconcile_pending_registrations(
        limit=10,
        min_confirmations=2,
        list_pending_fn=db_sim.list_pending,
        verify_fn=observer.observe,
        update_fn=db_sim.update_tx_status,
    )
    report2 = reconcile_pending_registrations(
        limit=10,
        min_confirmations=2,
        list_pending_fn=db_sim.list_pending,
        verify_fn=observer.observe,
        update_fn=db_sim.update_tx_status,
    )
    assert report1["summary"]["confirmed"] == 1
    assert report2["summary"]["scanned"] == 0

    final_row = db_sim.get_row_by_proof_id(proof_id)
    confirmed_rows = db_sim.authoritative_confirmed_rows()
    return RegistrationRaceOutcome(
        scenario="duplicate_submission",
        submissions=4,
        created_count=created_count,
        replayed_count=replayed_count,
        conflict_count=conflict_count,
        reconcile_attempts=2,
        stale_worker_rejections=db_sim.stale_worker_rejections,
        final_status=final_row["tx_status"] if final_row else None,
        authoritative_confirmed_count=len(confirmed_rows),
        terminal_transition_count=int(final_row["terminal_transitions"]) if final_row else 0,
        enqueued_jobs=len(db_sim.enqueued_jobs),
        live_network_calls=observer.live_network_calls,
    )


def run_delayed_indexing_race_fixture(*, min_confirmations: int = 3) -> RegistrationRaceOutcome:
    """Model client submitting txHash before Horizon indexes and confirms depth."""
    db_sim = SimulatedRegistrationDb()
    tx_hash = _synthetic_hex("b")
    proof_id = _synthetic_hex("4")

    observer = SimulatedChainObserver(
        {
            tx_hash: [
                # Step 1: Horizon has not indexed ledger 900 yet.
                ChainObservationStep(kind="unindexed_grace", latest_ledger=899),
                # Step 2: Horizon transient timeout / dependency blip.
                ChainObservationStep(kind="dependency_error"),
                # Step 3: Indexed at ledger 900, latest 900 -> 1 confirmation (< 3).
                ChainObservationStep(kind="indexed", ledger=900, latest_ledger=900, successful=True),
                # Step 4: Latest ledger advances to 902 -> 3 confirmations (>= 3) -> confirmed!
                ChainObservationStep(kind="indexed", ledger=900, latest_ledger=902, successful=True),
            ]
        }
    )

    _row, created = db_sim.upsert_register(
        video_hash=_synthetic_hex("5"),
        metadata_hash=_synthetic_hex("6"),
        proof_id=proof_id,
        tier="silent",
        tx_hash=tx_hash,
    )
    assert created is True

    statuses: list[str] = []
    for _ in range(4):
        report = reconcile_pending_registrations(
            limit=10,
            min_confirmations=min_confirmations,
            list_pending_fn=db_sim.list_pending,
            verify_fn=observer.observe,
            update_fn=db_sim.update_tx_status,
        )
        assert report["summary"]["scanned"] == 1
        statuses.append(str(report["results"][0]["status"]))

    assert statuses == ["pending", "error", "pending", "confirmed"]

    final_row = db_sim.get_row_by_proof_id(proof_id)
    confirmed_rows = db_sim.authoritative_confirmed_rows()
    return RegistrationRaceOutcome(
        scenario="delayed_indexing",
        submissions=1,
        created_count=1,
        replayed_count=0,
        conflict_count=0,
        reconcile_attempts=len(statuses),
        stale_worker_rejections=db_sim.stale_worker_rejections,
        final_status=final_row["tx_status"] if final_row else None,
        authoritative_confirmed_count=len(confirmed_rows),
        terminal_transition_count=int(final_row["terminal_transitions"]) if final_row else 0,
        enqueued_jobs=len(db_sim.enqueued_jobs),
        live_network_calls=observer.live_network_calls,
    )


def run_replaced_worker_race_fixture() -> RegistrationRaceOutcome:
    """Model a stalled reconciliation worker replaced by a newer worker generation."""
    idem_store = InMemoryIdempotencyStore()
    db_sim = SimulatedRegistrationDb()
    tx_hash = _synthetic_hex("c")
    proof_id = _synthetic_hex("7")
    video_hash = _synthetic_hex("8")
    metadata_hash = _synthetic_hex("9")

    digest = compute_canonical_request_digest(
        "POST",
        "/api/proofs/register",
        b"",
        f'{{"proofId":"{proof_id}","txHash":"{tx_hash}"}}'.encode("utf-8"),
    )

    # Initial API worker stalls mid-request; replacement API worker takes over lock.
    rec_id, _st, acquired, gen1 = idem_store.acquire(digest, "register", worker_id="api-stale")
    assert acquired is True
    gen2 = idem_store.replace_stalled_worker(rec_id, new_worker_id="api-replacement")

    # Stale API worker wakes up late and cannot overwrite idempotency record.
    stale_api_completed = idem_store.complete(
        rec_id,
        {"status": 500, "body": {"error": "stale"}},
        expected_generation=gen1,
        worker_id="api-stale",
    )
    assert stale_api_completed is False

    _row, created = db_sim.upsert_register(
        video_hash=video_hash,
        metadata_hash=metadata_hash,
        proof_id=proof_id,
        tier="seal",
        tx_hash=tx_hash,
    )
    assert created is True
    assert idem_store.complete(
        rec_id,
        {"status": 201, "body": {"ok": True, "created": True}},
        expected_generation=gen2,
        worker_id="api-replacement",
    )

    # Now model background reconciliation worker replacement:
    # Worker 1 claims attempt generation 1 and observes an outdated/missing result before stalling.
    worker1_gen = db_sim.claim_worker_attempt(tx_hash, "reconcile-worker-1")
    stale_observer = SimulatedChainObserver(
        {tx_hash: [ChainObservationStep(kind="missing")]}
    )

    # Worker 2 replaces stalled Worker 1 (generation 2) and observes authoritative confirmation.
    worker2_gen = db_sim.claim_worker_attempt(tx_hash, "reconcile-worker-2")
    fresh_observer = SimulatedChainObserver(
        {
            tx_hash: [
                ChainObservationStep(kind="indexed", ledger=1200, latest_ledger=1202, successful=True)
            ]
        }
    )

    res_worker2 = reconcile_registration(
        tx_hash,
        previous_status="pending",
        proof_id=proof_id,
        min_confirmations=2,
        verify_fn=fresh_observer.observe,
        update_fn=db_sim.fenced_updater(
            worker_id="reconcile-worker-2",
            attempt_generation=worker2_gen,
        ),
    )
    assert res_worker2["status"] == "confirmed"
    assert res_worker2["updated"] is True

    # Worker 1 wakes up late with stale "missing" observation (even with force=True!) and is fenced.
    res_worker1_late = reconcile_registration(
        tx_hash,
        previous_status="pending",
        proof_id=proof_id,
        min_confirmations=2,
        force=True,
        verify_fn=stale_observer.observe,
        update_fn=db_sim.fenced_updater(
            worker_id="reconcile-worker-1",
            attempt_generation=worker1_gen,
        ),
    )
    assert res_worker1_late["updated"] is False

    final_row = db_sim.get_row_by_proof_id(proof_id)
    confirmed_rows = db_sim.authoritative_confirmed_rows()
    return RegistrationRaceOutcome(
        scenario="replaced_worker",
        submissions=1,
        created_count=1,
        replayed_count=0,
        conflict_count=0,
        reconcile_attempts=2,
        stale_worker_rejections=db_sim.stale_worker_rejections,
        final_status=final_row["tx_status"] if final_row else None,
        authoritative_confirmed_count=len(confirmed_rows),
        terminal_transition_count=int(final_row["terminal_transitions"]) if final_row else 0,
        enqueued_jobs=len(db_sim.enqueued_jobs),
        live_network_calls=stale_observer.live_network_calls + fresh_observer.live_network_calls,
    )


def run_registration_race_suite() -> dict[str, RegistrationRaceOutcome]:
    """Execute all canonical deterministic registration race fixtures."""
    outcomes = {
        "duplicate_submission": run_duplicate_submission_race_fixture(),
        "delayed_indexing": run_delayed_indexing_race_fixture(),
        "replaced_worker": run_replaced_worker_race_fixture(),
    }
    for name, outcome in outcomes.items():
        if outcome.final_status != "confirmed" or outcome.authoritative_confirmed_count != 1:
            raise AssertionError(f"race fixture {name} failed authoritative confirmation invariant")
        if outcome.terminal_transition_count != 1:
            raise AssertionError(f"race fixture {name} violated single-terminal-transition invariant")
        if outcome.live_network_calls != 0:
            raise AssertionError(f"race fixture {name} performed unexpected live network calls")
    return outcomes
