"""Focused tests for rejecting reused registration keys with a changed identity tier."""

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

from app import app
from idempotency import (
    RegistrationKeyConflictError,
    canonical_registration_idempotency_binding,
    normalize_client_idempotency_key,
    reset_registration_key_bindings_for_tests,
)
from registration_reconcile import (
    process_verify_tx_job,
    reset_reconcile_tier_bindings_for_tests,
)


@pytest.fixture(autouse=True)
def _reset_bindings():
    reset_registration_key_bindings_for_tests()
    reset_reconcile_tier_bindings_for_tests()
    yield
    reset_registration_key_bindings_for_tests()
    reset_reconcile_tier_bindings_for_tests()


def test_canonical_idempotency_binding_differs_across_identity_tiers():
    silent_digest = canonical_registration_idempotency_binding(
        video_hash="1" * 64,
        metadata_hash="2" * 64,
        proof_id="3" * 64,
        tier="silent",
        tx_hash="a" * 64,
    )
    source_digest = canonical_registration_idempotency_binding(
        video_hash="1" * 64,
        metadata_hash="2" * 64,
        proof_id="3" * 64,
        tier="source",
        tx_hash="a" * 64,
    )
    seal_digest = canonical_registration_idempotency_binding(
        video_hash="1" * 64,
        metadata_hash="2" * 64,
        proof_id="3" * 64,
        tier="seal",
        tx_hash="a" * 64,
    )
    assert len({silent_digest, source_digest, seal_digest}) == 3

    with pytest.raises(ValueError, match="tier must be one of"):
        canonical_registration_idempotency_binding(
            video_hash="1" * 64,
            metadata_hash="2" * 64,
            proof_id="3" * 64,
            tier="enterprise",
        )


def test_reused_semantic_registration_key_with_changed_tier_returns_409_without_new_job():
    client = app.test_client()
    base_payload = {
        "videoHash": "1" * 64,
        "metadataHash": "2" * 64,
        "proofId": "3" * 64,
        "tier": "silent",
        "txHash": "a" * 64,
    }

    with mock.patch(
        "app.upsert_register_event",
        return_value=({"id": 101, "proof_id": "3" * 64, "tier": "silent"}, True),
    ) as mock_upsert, mock.patch("app.enqueue_job", return_value=1) as mock_enqueue, mock.patch(
        "app.queue_webhook_deliveries"
    ):
        first = client.post("/api/proofs/register", json=base_payload)
        assert first.status_code == 201
        assert first.get_json()["created"] is True
        assert mock_enqueue.call_count == 1
        assert mock_enqueue.call_args[0][1]["tier"] == "silent"

        # Exact same tier and payload -> idempotent replay (200), zero new jobs!
        replay = client.post("/api/proofs/register", json=base_payload)
        assert replay.status_code == 200
        assert replay.get_json()["created"] is False
        assert mock_enqueue.call_count == 1

        # Changed tier ("silent" -> "seal") on same registration key -> 409 conflict, zero new jobs!
        changed_tier_payload = dict(base_payload, tier="seal")
        conflict = client.post("/api/proofs/register", json=changed_tier_payload)
        assert conflict.status_code == 409
        body = conflict.get_json()
        assert body["ok"] is False
        assert body["code"] == "REGISTRATION_TIER_CONFLICT"
        assert body["conflict_field"] == "tier"
        # upsert_register_event was NOT called for the conflicting tier and NO job was created!
        assert mock_upsert.call_count == 2
        assert mock_enqueue.call_count == 1


def test_reused_idempotency_key_header_with_changed_tier_and_new_tx_returns_409_without_new_job():
    """Even if txHash changes, reusing an Idempotency-Key header with a changed tier fails closed."""
    client = app.test_client()
    headers = {"Idempotency-Key": "reg-client-key-0001"}

    with mock.patch(
        "app.upsert_register_event",
        return_value=({"id": 202, "proof_id": "4" * 64, "tier": "source"}, True),
    ), mock.patch("app.enqueue_job", return_value=2) as mock_enqueue, mock.patch(
        "app.queue_webhook_deliveries"
    ):
        first = client.post(
            "/api/proofs/register",
            headers=headers,
            json={
                "videoHash": "5" * 64,
                "metadataHash": "6" * 64,
                "proofId": "4" * 64,
                "tier": "source",
                "txHash": "b" * 64,
            },
        )
        assert first.status_code == 201
        assert mock_enqueue.call_count == 1

        conflict = client.post(
            "/api/proofs/register",
            headers=headers,
            json={
                "videoHash": "5" * 64,
                "metadataHash": "6" * 64,
                "proofId": "4" * 64,
                "tier": "silent",
                "txHash": "c" * 64,
            },
        )
        assert conflict.status_code == 409
        body = conflict.get_json()
        assert body["code"] == "REGISTRATION_TIER_CONFLICT"
        assert body["conflict_field"] == "tier"
        assert mock_enqueue.call_count == 1


def test_invalid_idempotency_key_header_returns_400_validation_error():
    client = app.test_client()
    oversized = "k" * 200
    resp = client.post(
        "/api/proofs/register",
        headers={"Idempotency-Key": oversized},
        json={
            "videoHash": "1" * 64,
            "metadataHash": "2" * 64,
            "proofId": "3" * 64,
            "tier": "silent",
        },
    )
    assert resp.status_code == 400
    assert normalize_client_idempotency_key("   ") is None


def test_process_verify_tx_job_rejects_changed_tier_binding():
    with mock.patch(
        "registration_reconcile.reconcile_registration",
        return_value={"status": "pending", "reason": "awaiting_confirmations", "updated": False},
    ):
        out = process_verify_tx_job(
            {"tx_hash": "d" * 64, "proof_id": "9" * 64, "tier": "silent"}
        )
        assert out["status"] == "pending"

        with pytest.raises(RegistrationKeyConflictError) as exc_info:
            process_verify_tx_job(
                {"tx_hash": "d" * 64, "proof_id": "9" * 64, "tier": "seal"}
            )
        assert exc_info.value.field == "tier"
        assert exc_info.value.code == "REGISTRATION_TIER_CONFLICT"
