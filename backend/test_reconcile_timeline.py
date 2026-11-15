"""Focused tests for bounded, authorized registration reconciliation timelines."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from unittest import mock

import pytest

_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_BACKEND_DIR)
for _p in (_BACKEND_DIR, _REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from app import create_app
from register_auth import ScopedKey
from registration_reconcile import (
    RegistrationTimelineStore,
    classify_timeline_outcome,
    get_registration_reconcile_timeline,
    reconcile_registration,
    record_registration_timeline_submission,
    reset_reconcile_timeline_for_tests,
)
from strkey import _VERSION_BYTE_ED25519_PUBLIC, make_strkey
from tx_verification import TxVerificationResult


PROOF_A = "1" * 64
PROOF_B = "2" * 64
TX_A = "a" * 64
TX_B = "b" * 64
OWNER_A = make_strkey(_VERSION_BYTE_ED25519_PUBLIC, b"\x01" * 32)
OWNER_B = make_strkey(_VERSION_BYTE_ED25519_PUBLIC, b"\x02" * 32)


@pytest.fixture(autouse=True)
def _clean_timeline():
    reset_reconcile_timeline_for_tests()
    yield
    reset_reconcile_timeline_for_tests()


def test_classify_timeline_outcome_distinguishes_all_four_outcomes():
    assert classify_timeline_outcome("pending", "awaiting_confirmations") == "submitted"
    assert classify_timeline_outcome("submitted", None) == "submitted"
    assert classify_timeline_outcome("confirmed", "confirmed") == "confirmed"
    assert classify_timeline_outcome("failed", "tx_unsuccessful") == "rejected"
    assert classify_timeline_outcome("failed", "malformed_tx_hash") == "rejected"
    assert classify_timeline_outcome("missing", "not_found_on_horizon") == "unknown"
    assert classify_timeline_outcome("error", "horizon_dependency_failure") == "unknown"
    assert classify_timeline_outcome(None, None) == "unknown"


@mock.patch("registration_reconcile.update_tx_status", return_value=True)
def test_timeline_records_observations_and_transitions_across_all_outcomes(_mock_update):
    # Unknown outcome before any submission or DB record exists.
    empty = get_registration_reconcile_timeline(PROOF_A)
    assert empty["currentOutcome"] == "unknown"
    assert empty["entries"] == []

    # 1. Submitted
    record_registration_timeline_submission(
        proof_id=PROOF_A,
        tx_hash=TX_A,
        outcome="submitted",
        owner=OWNER_A,
    )

    # 2. Unknown (Horizon dependency outage)
    with mock.patch(
        "registration_reconcile.verify_transaction",
        return_value=TxVerificationResult(status="error", reason="horizon_dependency_failure"),
    ):
        reconcile_registration(TX_A, previous_status="pending", proof_id=PROOF_A)

    # 3. Submitted (awaiting confirmations)
    with mock.patch(
        "registration_reconcile.verify_transaction",
        return_value=TxVerificationResult(
            status="pending",
            reason="awaiting_confirmations",
            ledger=500,
            confirmations=1,
        ),
    ):
        reconcile_registration(TX_A, previous_status="pending", proof_id=PROOF_A, min_confirmations=2)

    # 4. Confirmed (depth satisfied -> records observation + transition!)
    with mock.patch(
        "registration_reconcile.verify_transaction",
        return_value=TxVerificationResult(
            status="confirmed",
            reason="confirmed",
            ledger=500,
            confirmations=3,
        ),
    ):
        reconcile_registration(TX_A, previous_status="pending", proof_id=PROOF_A, min_confirmations=2)

    timeline_a = get_registration_reconcile_timeline(PROOF_A)
    assert timeline_a["currentOutcome"] == "confirmed"
    outcomes_a = [e["outcome"] for e in timeline_a["entries"]]
    assert outcomes_a == ["submitted", "unknown", "submitted", "confirmed", "confirmed"]
    assert len(timeline_a["transitions"]) == 1
    assert timeline_a["transitions"][0]["fromStatus"] == "pending"
    assert timeline_a["transitions"][0]["toStatus"] == "confirmed"

    # Separate proof whose transaction fails on-chain -> rejected!
    record_registration_timeline_submission(proof_id=PROOF_B, tx_hash=TX_B, owner=OWNER_B)
    with mock.patch(
        "registration_reconcile.verify_transaction",
        return_value=TxVerificationResult(status="failed", reason="tx_unsuccessful", ledger=501),
    ):
        reconcile_registration(TX_B, previous_status="pending", proof_id=PROOF_B)

    timeline_b = get_registration_reconcile_timeline(PROOF_B)
    assert timeline_b["currentOutcome"] == "rejected"
    assert timeline_b["transitions"][0]["outcome"] == "rejected"


def test_timeline_store_is_bounded_and_excludes_owner_and_private_metadata():
    store = RegistrationTimelineStore(max_entries_per_proof=3)
    store.record_submission(proof_id=PROOF_A, tx_hash=TX_A, owner=OWNER_A)
    for idx in range(5):
        store.record_reconcile_step(
            tx_hash=TX_A,
            proof_id=PROOF_A,
            previous_status="pending",
            verification=TxVerificationResult(
                status="pending",
                reason="awaiting_confirmations",
                ledger=100 + idx,
                confirmations=1,
            ),
            updated=False,
        )

    view = store.get_timeline(PROOF_A, limit=10)
    assert view["maxEntriesPerProof"] == 3
    assert view["totalReturned"] == 3
    assert view["evictedCount"] == 3
    serialized = json.dumps(view)
    assert OWNER_A not in serialized


def test_http_timeline_enforces_scoped_requester_authorization_and_fail_closed_lookup(
    monkeypatch: pytest.MonkeyPatch,
):
    token_a = "scoped-secret-token-owner-a"
    token_b = "scoped-secret-token-owner-b"
    digest_a = hashlib.sha256(token_a.encode("utf-8")).hexdigest()
    digest_b = hashlib.sha256(token_b.encode("utf-8")).hexdigest()

    monkeypatch.setenv(
        "REGISTER_SCOPED_KEYS",
        f"{OWNER_A}:{digest_a},{OWNER_B}:{digest_b}",
    )
    monkeypatch.delenv("REGISTER_API_KEY", raising=False)

    scoped_app = create_app()
    client = scoped_app.test_client()

    record_registration_timeline_submission(
        proof_id=PROOF_A,
        tx_hash=TX_A,
        outcome="submitted",
        owner=OWNER_A,
    )

    # Missing Authorization header -> 401
    unauth = client.get(f"/api/proofs/{PROOF_A}/reconcile/timeline")
    assert unauth.status_code == 401

    # Owner B may NOT inspect Owner A's proof timeline -> 403 without leaking OWNER_A!
    with mock.patch("app.find_proof_owner", return_value=OWNER_A):
        forbidden = client.get(
            f"/api/proofs/{PROOF_A}/reconcile/timeline",
            headers={"Authorization": f"Bearer {token_b}"},
        )
    assert forbidden.status_code == 403
    assert OWNER_A not in forbidden.get_data(as_text=True)

    # Owner A CAN inspect Owner A's proof timeline -> 200!
    with mock.patch("app.find_proof_owner", return_value=OWNER_A):
        allowed = client.get(
            f"/api/proofs/{PROOF_A}/reconcile/timeline?limit=2",
            headers={"Authorization": f"Bearer {token_a}"},
        )
    assert allowed.status_code == 200
    body = allowed.get_json()
    assert body["ok"] is True
    assert body["proofId"] == PROOF_A
    assert body["currentOutcome"] == "submitted"
    assert OWNER_A not in allowed.get_data(as_text=True)

    # Owner lookup failure -> fails closed with 503!
    with mock.patch("app.find_proof_owner", side_effect=RuntimeError("db down")):
        outage = client.get(
            f"/api/proofs/{PROOF_A}/reconcile/timeline",
            headers={"Authorization": f"Bearer {token_a}"},
        )
    assert outage.status_code == 503

    # Malformed proofId -> 400
    bad_id = client.get(
        "/api/proofs/not-a-hex/reconcile/timeline",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert bad_id.status_code == 400
