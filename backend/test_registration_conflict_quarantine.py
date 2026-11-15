"""Focused tests for bounded registration conflict quarantine and privacy invariants."""

from __future__ import annotations

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

from app import app
from db import ConflictError
from idempotency import quarantine_idempotency_conflict
from registration_reconcile import (
    RegistrationConflictQuarantine,
    compute_registration_statement_digest,
    get_conflict_quarantine,
    inspect_registration_conflicts,
    reconcile_registration,
)


@pytest.fixture(autouse=True)
def _clean_quarantine():
    get_conflict_quarantine().clear()
    yield
    get_conflict_quarantine().clear()


def test_quarantine_is_bounded_and_tracks_evictions():
    quarantine = RegistrationConflictQuarantine(max_entries=3)
    for idx in range(1, 6):
        quarantine.record(
            conflict_kind="idempotency_statement_mismatch",
            conflict_field="tier",
            proof_id=f"{idx:064x}",
            expected_statement={
                "proof_id": f"{idx:064x}",
                "video_hash": "a" * 64,
                "metadata_hash": "b" * 64,
                "tier": "silent",
            },
            observed_statement={
                "proof_id": f"{idx:064x}",
                "video_hash": "a" * 64,
                "metadata_hash": "b" * 64,
                "tier": "seal",
            },
            expected_tx_hash=f"{idx + 100:064x}",
            observed_tx_hash=f"{idx + 200:064x}",
        )

    snap = quarantine.snapshot(limit=10)
    assert snap["capacity"] == 3
    assert snap["count"] == 3
    assert snap["evicted"] == 2
    # Newest-first ordering retains items 5, 4, 3 and evicts 1, 2.
    assert [item["quarantineId"] for item in snap["items"]] == [5, 4, 3]
    assert [item["proofId"] for item in snap["items"]] == [
        f"{5:064x}",
        f"{4:064x}",
        f"{3:064x}",
    ]


def test_quarantine_rejects_invalid_capacity():
    with pytest.raises(ValueError, match="max_entries"):
        RegistrationConflictQuarantine(max_entries=0)
    with pytest.raises(ValueError, match="max_entries"):
        RegistrationConflictQuarantine(max_entries=99999)


def test_diagnostic_excludes_private_evidence_metadata_by_construction():
    sensitive_marker = "CONFIDENTIAL_WITNESS_GPS_37.7749_-122.4194"
    sensitive_filename = "confidential_source_footage_raw_capture"
    sensitive_address = "G" + "A" * 55

    expected_stmt = {
        "proof_id": "1" * 64,
        "video_hash": "2" * 64,
        "metadata_hash": "3" * 64,
        "tier": "source",
        "tx_hash": "4" * 64,
        "metadata": {"notes": sensitive_marker, "cameraSerial": "SN-998877"},
        "fileName": sensitive_filename,
        "source_address": sensitive_address,
        "witness": sensitive_marker,
    }
    observed_stmt = {
        "proof_id": "1" * 64,
        "video_hash": "2" * 64,
        "metadata_hash": "9" * 64,
        "tier": "seal",
        "tx_hash": "5" * 64,
        "metadata": {"notes": sensitive_marker},
        "fileName": sensitive_filename,
        "source_address": sensitive_address,
        "timeAttestation": {"secretToken": sensitive_marker},
    }

    # Changing private metadata alone must not alter the canonical statement digest.
    digest_clean = compute_registration_statement_digest(
        {
            "proof_id": "1" * 64,
            "video_hash": "2" * 64,
            "metadata_hash": "3" * 64,
            "tier": "source",
        }
    )
    assert compute_registration_statement_digest(expected_stmt) == digest_clean

    entry = quarantine_idempotency_conflict(
        idempotency_key="f" * 64,
        conflict_field="metadata_hash",
        expected_statement=expected_stmt,
        observed_statement=observed_stmt,
    )
    snap = inspect_registration_conflicts(limit=10)
    serialized = json.dumps({"entry": entry, "snapshot": snap})

    assert sensitive_marker not in serialized
    assert sensitive_filename not in serialized
    assert sensitive_address not in serialized
    assert entry["expectedStatementDigest"] != entry["observedStatementDigest"]
    assert entry["expectedTxHash"] == "4" * 64
    assert entry["observedTxHash"] == "5" * 64
    assert entry["expectedTier"] == "source"
    assert entry["observedTier"] == "seal"
    assert entry["idempotencyKeyPrefix"] == "ffffffff"


@mock.patch("registration_reconcile.update_tx_status")
@mock.patch("registration_reconcile.verify_transaction")
def test_reconcile_registration_quarantines_contradictory_statement_and_tx_refs(
    mock_verify, mock_update
):
    res_stmt = reconcile_registration(
        "a" * 64,
        proof_id="1" * 64,
        expected_statement_digest="2" * 64,
        observed_statement_digest="3" * 64,
    )
    assert res_stmt["status"] == "failed"
    assert res_stmt["reason"] == "contradictory_registration_statement"
    assert res_stmt["updated"] is False
    assert res_stmt["quarantined"] is True
    mock_verify.assert_not_called()
    mock_update.assert_not_called()

    res_tx = reconcile_registration(
        "b" * 64,
        proof_id="1" * 64,
        expected_tx_hash="c" * 64,
    )
    assert res_tx["status"] == "failed"
    assert res_tx["reason"] == "contradictory_tx_reference"
    assert res_tx["updated"] is False
    assert res_tx["quarantined"] is True

    snap = inspect_registration_conflicts(limit=10, proof_id="1" * 64)
    assert snap["count"] == 2
    assert {item["conflictKind"] for item in snap["items"]} == {
        "reconcile_statement_contradiction",
        "reconcile_tx_reference_mismatch",
    }


def test_register_conflict_populates_quarantine_and_exposes_sanitized_http_diagnostic():
    client = app.test_client()
    private_note = "PRIVATE_REPORTER_IDENTITY_DO_NOT_PUBLISH"

    conflict_exc = ConflictError(
        idempotency_key="e" * 64,
        field="tier",
        existing_value="silent",
        incoming_value="seal",
        existing_statement={
            "proof_id": "1" * 64,
            "video_hash": "2" * 64,
            "metadata_hash": "3" * 64,
            "tier": "silent",
            "contract_id": None,
            "tx_hash": "7" * 64,
        },
    )

    with mock.patch("app.upsert_register_event", side_effect=conflict_exc):
        reg_resp = client.post(
            "/api/proofs/register",
            json={
                "videoHash": "2" * 64,
                "metadataHash": "3" * 64,
                "proofId": "1" * 64,
                "tier": "seal",
                "txHash": "8" * 64,
                "fileName": "witness_interview_raw_cut",
                "customNote": private_note,
            },
        )

    assert reg_resp.status_code == 409
    reg_body = reg_resp.get_json()
    assert reg_body["conflict_field"] == "tier"
    assert reg_body["quarantined"] is True

    diag_resp = client.get(f"/api/proofs/reconcile/conflicts?proofId={'1' * 64}&limit=5")
    assert diag_resp.status_code == 200
    diag_raw = diag_resp.get_data(as_text=True)
    assert private_note not in diag_raw
    assert "witness_interview_raw_cut" not in diag_raw

    diag_json = diag_resp.get_json()
    assert diag_json["ok"] is True
    assert diag_json["quarantine"]["count"] == 1
    item = diag_json["quarantine"]["items"][0]
    assert item["proofId"] == "1" * 64
    assert item["expectedTxHash"] == "7" * 64
    assert item["observedTxHash"] == "8" * 64
    assert item["expectedTier"] == "silent"
    assert item["observedTier"] == "seal"

    bad_filter = client.get("/api/proofs/reconcile/conflicts?proofId=not-a-valid-hex")
    assert bad_filter.status_code == 400
