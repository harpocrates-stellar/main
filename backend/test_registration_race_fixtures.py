"""Deterministic registration race fixture tests across DB and chain observations."""

from __future__ import annotations

import os
import sys
from unittest import mock

import pytest

_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_BACKEND_DIR)
for _p in (_BACKEND_DIR, _REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from db import ConflictError
from idempotency import InMemoryIdempotencyStore, compute_canonical_request_digest
from registration_reconcile import (
    ChainObservationStep,
    SimulatedChainObserver,
    SimulatedRegistrationDb,
    reconcile_pending_registrations,
    reconcile_registration,
    run_delayed_indexing_race_fixture,
    run_duplicate_submission_race_fixture,
    run_registration_race_suite,
    run_replaced_worker_race_fixture,
)


def test_duplicate_submission_race_converges_to_single_confirmed_result():
    with mock.patch(
        "urllib.request.urlopen",
        side_effect=AssertionError("live network call forbidden in deterministic fixture"),
    ):
        outcome = run_duplicate_submission_race_fixture()

    assert outcome.scenario == "duplicate_submission"
    assert outcome.created_count == 1
    assert outcome.replayed_count == 2
    assert outcome.conflict_count == 1
    assert outcome.enqueued_jobs == 1
    assert outcome.final_status == "confirmed"
    assert outcome.authoritative_confirmed_count == 1
    assert outcome.terminal_transition_count == 1
    assert outcome.live_network_calls == 0


def test_delayed_indexing_race_waits_for_confirmation_depth_without_premature_terminal_write():
    with mock.patch(
        "urllib.request.urlopen",
        side_effect=AssertionError("live network call forbidden in deterministic fixture"),
    ):
        outcome = run_delayed_indexing_race_fixture(min_confirmations=3)

    assert outcome.scenario == "delayed_indexing"
    assert outcome.reconcile_attempts == 4
    assert outcome.final_status == "confirmed"
    assert outcome.authoritative_confirmed_count == 1
    assert outcome.terminal_transition_count == 1
    assert outcome.live_network_calls == 0


def test_replaced_worker_race_fences_stale_worker_from_clobbering_confirmed_state():
    with mock.patch(
        "urllib.request.urlopen",
        side_effect=AssertionError("live network call forbidden in deterministic fixture"),
    ):
        outcome = run_replaced_worker_race_fixture()

    assert outcome.scenario == "replaced_worker"
    assert outcome.stale_worker_rejections == 1
    assert outcome.final_status == "confirmed"
    assert outcome.authoritative_confirmed_count == 1
    assert outcome.terminal_transition_count == 1
    assert outcome.live_network_calls == 0


def test_full_registration_race_suite_invariants():
    suite = run_registration_race_suite()
    assert set(suite.keys()) == {"duplicate_submission", "delayed_indexing", "replaced_worker"}
    for outcome in suite.values():
        assert outcome.authoritative_confirmed_count == 1
        assert outcome.final_status == "confirmed"
        assert outcome.terminal_transition_count == 1
        assert outcome.live_network_calls == 0


def test_boundary_onchain_failed_transaction_records_failed_not_confirmed():
    """Boundary case: an indexed unsuccessful transaction resolves terminally to 'failed'."""
    db_sim = SimulatedRegistrationDb()
    tx_hash = "d" * 64
    proof_id = "e" * 64
    observer = SimulatedChainObserver(
        {
            tx_hash: [
                ChainObservationStep(kind="unindexed_grace", latest_ledger=99),
                ChainObservationStep(kind="indexed", ledger=100, latest_ledger=103, successful=False),
            ]
        }
    )

    db_sim.upsert_register(
        video_hash="1" * 64,
        metadata_hash="2" * 64,
        proof_id=proof_id,
        tier="source",
        tx_hash=tx_hash,
    )

    first = reconcile_pending_registrations(
        limit=5,
        min_confirmations=2,
        list_pending_fn=db_sim.list_pending,
        verify_fn=observer.observe,
        update_fn=db_sim.update_tx_status,
    )
    assert first["results"][0]["status"] == "pending"
    assert db_sim.authoritative_confirmed_rows() == []

    second = reconcile_pending_registrations(
        limit=5,
        min_confirmations=2,
        list_pending_fn=db_sim.list_pending,
        verify_fn=observer.observe,
        update_fn=db_sim.update_tx_status,
    )
    assert second["results"][0]["status"] == "failed"
    assert second["results"][0]["reason"] == "tx_unsuccessful"
    assert db_sim.authoritative_confirmed_rows() == []
    row = db_sim.get_row_by_proof_id(proof_id)
    assert row is not None
    assert row["tx_status"] == "failed"
    assert row["terminal_transitions"] == 1


def test_boundary_in_memory_idempotency_store_rejects_replacement_after_completion():
    store = InMemoryIdempotencyStore()
    digest = compute_canonical_request_digest("POST", "/api/proofs/register", b"", b'{"a":1}')
    rec_id, status, acquired, gen = store.acquire(digest, "register", worker_id="w1")
    assert acquired is True
    assert status == "PENDING"
    assert store.complete(rec_id, {"status": 201, "body": {"ok": True}}, expected_generation=gen, worker_id="w1")

    with pytest.raises(ValueError, match="terminal"):
        store.replace_stalled_worker(rec_id, new_worker_id="w2")


def test_simulated_db_enforces_tier_separation_and_malformed_hash_rejection():
    db_sim = SimulatedRegistrationDb()
    with pytest.raises(ValueError, match="unsupported tier"):
        db_sim.upsert_register(
            video_hash="1" * 64,
            metadata_hash="2" * 64,
            proof_id="3" * 64,
            tier="invalid",
            tx_hash="a" * 64,
        )

    db_sim.upsert_register(
        video_hash="1" * 64,
        metadata_hash="2" * 64,
        proof_id="3" * 64,
        tier="silent",
        tx_hash="a" * 64,
    )
    with pytest.raises(ConflictError) as exc_info:
        db_sim.upsert_register(
            video_hash="1" * 64,
            metadata_hash="9" * 64,
            proof_id="3" * 64,
            tier="silent",
            tx_hash="a" * 64,
        )
    assert exc_info.value.field == "metadata_hash"

    bad = reconcile_registration("not-hex", verify_fn=SimulatedChainObserver().observe)
    assert bad["status"] == "failed"
    assert bad["error"] == "malformed_tx_hash"
