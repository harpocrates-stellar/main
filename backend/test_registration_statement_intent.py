"""Focused tests for binding proof registration intent to canonical evidence statements (#1054)."""

from __future__ import annotations

import base64
import logging
import os
from pathlib import Path
from unittest import mock

import pytest

import app as app_module
import idempotency as idem_mod
from idempotency import (
    CanonicalEvidenceStatement,
    RegistrationIntentStore,
    StatementIntentConflictError,
    compute_statement_intent_digest,
    get_registration_intent,
    persist_registration_intent,
    reset_registration_intents,
)
from registration_reconcile import (
    process_verify_tx_job,
    reconcile_pending_registrations,
    reconcile_registration,
)
from strkey import _VERSION_BYTE_CONTRACT, _VERSION_BYTE_ED25519_PUBLIC, make_strkey
from tx_verification import TxVerificationResult, verify_transaction


OWNER_A = make_strkey(_VERSION_BYTE_ED25519_PUBLIC, bytes([11]) * 32)
OWNER_B = make_strkey(_VERSION_BYTE_ED25519_PUBLIC, bytes([22]) * 32)
CONTRACT_A = make_strkey(_VERSION_BYTE_CONTRACT, bytes([33]) * 32)
CONTRACT_B = make_strkey(_VERSION_BYTE_CONTRACT, bytes([44]) * 32)

PROOF_ID = "11" * 32
VIDEO_HASH = "22" * 32
METADATA_HASH = "33" * 32
TX_HASH_A = "aa" * 32
TX_HASH_B = "bb" * 32


@pytest.fixture(autouse=True)
def _clean_intents(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("REGISTRATION_INTENT_STORE_PATH", raising=False)
    monkeypatch.delenv("REQUIRE_ONCHAIN_STATEMENT_INTENT", raising=False)
    reset_registration_intents()
    yield
    reset_registration_intents()


def _statement(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "proofId": PROOF_ID,
        "videoHash": VIDEO_HASH,
        "metadataHash": METADATA_HASH,
        "tier": "source",
        "sourceAddress": OWNER_A,
        "contractId": CONTRACT_A,
    }
    base.update(overrides)
    return base


def test_canonical_statement_digest_is_deterministic_and_separates_tiers_and_fields():
    stmt_a = CanonicalEvidenceStatement.from_mapping(_statement(videoHash="0x" + VIDEO_HASH.upper()))
    stmt_b = CanonicalEvidenceStatement.from_mapping(
        {
            "proof_id": PROOF_ID,
            "video_hash": VIDEO_HASH,
            "metadata_hash": METADATA_HASH,
            "tier": "source",
            "source_address": OWNER_A,
            "contract_id": CONTRACT_A,
        }
    )
    assert stmt_a.intent_digest() == stmt_b.intent_digest()
    assert len(stmt_a.intent_digest()) == 64

    # Changing any canonical attribute (including identity tier) changes the digest
    silent_digest = compute_statement_intent_digest(_statement(tier="silent"))
    seal_digest = compute_statement_intent_digest(_statement(tier="seal"))
    alt_video_digest = compute_statement_intent_digest(_statement(videoHash="99" * 32))
    alt_meta_digest = compute_statement_intent_digest(_statement(metadataHash="88" * 32))
    alt_owner_digest = compute_statement_intent_digest(_statement(sourceAddress=OWNER_B))
    alt_contract_digest = compute_statement_intent_digest(_statement(contractId=CONTRACT_B))

    digests = {
        stmt_a.intent_digest(),
        silent_digest,
        seal_digest,
        alt_video_digest,
        alt_meta_digest,
        alt_owner_digest,
        alt_contract_digest,
    }
    assert len(digests) == 7

    with pytest.raises(ValueError, match="tier"):
        CanonicalEvidenceStatement.from_mapping(_statement(tier="invalid"))
    with pytest.raises(ValueError, match="videoHash"):
        CanonicalEvidenceStatement.from_mapping(_statement(videoHash="bad-hex"))


def test_intent_digest_persisted_strictly_before_transaction_verification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    store_file = tmp_path / "intents.json"
    monkeypatch.setenv("REGISTRATION_INTENT_STORE_PATH", str(store_file))
    reset_registration_intents()

    events: list[str] = []
    approved = _statement()
    expected_digest = compute_statement_intent_digest(approved)

    def fake_verify(tx_hash: str, *, min_confirmations: int = 1, timeout: float = 10.0) -> TxVerificationResult:
        # Must already be persisted on disk and in store BEFORE verify_transaction executes!
        persisted = get_registration_intent(tx_hash=tx_hash)
        assert persisted is not None
        assert persisted.intent_digest == expected_digest
        assert store_file.exists()
        raw_disk = store_file.read_text(encoding="utf-8")
        assert expected_digest in raw_disk
        assert OWNER_A not in raw_disk  # privacy invariant: raw owner G-address never stored
        events.append("verify_transaction")
        return TxVerificationResult(
            status="confirmed",
            ledger=500,
            latest_ledger=502,
            confirmations=3,
            successful=True,
            reason="confirmed",
            registered_statement_digest=expected_digest,
            registered_statement_present=True,
            registered_statement_valid=True,
            tx_source_account=OWNER_A,
            tx_contract_id=CONTRACT_A,
        )

    orig_persist = persist_registration_intent

    def spy_persist(*args, **kwargs):
        events.append("persist_intent")
        return orig_persist(*args, **kwargs)

    with (
        mock.patch("registration_reconcile.persist_registration_intent", side_effect=spy_persist),
        mock.patch("registration_reconcile.verify_transaction", side_effect=fake_verify),
        mock.patch("registration_reconcile.update_tx_status", return_value=True) as mock_update,
    ):
        result = reconcile_registration(
            TX_HASH_A,
            previous_status="pending",
            proof_id=PROOF_ID,
            approved_statement=approved,
        )

    assert events == ["persist_intent", "verify_transaction"]
    assert result["status"] == "confirmed"
    assert result["intentDigest"] == expected_digest
    assert result["intentVerified"] is True
    mock_update.assert_called_once_with(TX_HASH_A, "confirmed", force=False)

    # Reload from durable file into a fresh store instance and verify survival across restart
    reloaded_store = RegistrationIntentStore(store_path=store_file)
    reloaded = reloaded_store.lookup_intent(tx_hash=TX_HASH_A)
    assert reloaded is not None
    assert reloaded.intent_digest == expected_digest
    assert OWNER_A not in str(reloaded.public_view())


def test_reconcile_rejects_transaction_when_registered_statement_differs():
    approved = _statement(tier="source")
    persisted = persist_registration_intent(approved, tx_hash=TX_HASH_A)

    # On-chain transaction registered a different metadataHash (or tampered statement)
    tampered_onchain = _statement(metadataHash="ff" * 32, tier="source")

    with (
        mock.patch("tx_verification.horizon_urls", return_value=("https://horizon.test",)),
        mock.patch("tx_verification._latest_ledger", return_value=305),
        mock.patch(
            "tx_verification._fetch_json",
            return_value=(
                200,
                {
                    "successful": True,
                    "ledger": 300,
                    "source_account": OWNER_A,
                    "contract_id": CONTRACT_A,
                    "registered_statement": tampered_onchain,
                },
            ),
        ),
        mock.patch("registration_reconcile.update_tx_status", return_value=True) as mock_update,
    ):
        result = reconcile_registration(TX_HASH_A, previous_status="pending", proof_id=PROOF_ID)

    assert result["status"] == "failed"
    assert result["reason"] == "statement_intent_mismatch"
    assert result["intentDigest"] == persisted.intent_digest
    assert result["intentVerified"] is False
    assert result["updated"] is True
    mock_update.assert_called_once_with(TX_HASH_A, "failed", force=False)


def test_reconcile_accepts_matching_stellar_hash_memo_and_rejects_mismatched_memo_or_tier():
    approved = _statement(tier="silent", sourceAddress="")
    persisted = persist_registration_intent(approved, tx_hash=TX_HASH_A)
    memo_b64 = base64.b64encode(bytes.fromhex(persisted.intent_digest)).decode("ascii")

    with (
        mock.patch("tx_verification.horizon_urls", return_value=("https://horizon.test",)),
        mock.patch("tx_verification._latest_ledger", return_value=110),
        mock.patch(
            "tx_verification._fetch_json",
            return_value=(
                200,
                {
                    "successful": True,
                    "ledger": 108,
                    "memo_type": "hash",
                    "memo": memo_b64,
                },
            ),
        ),
        mock.patch("registration_reconcile.update_tx_status", return_value=True) as mock_update,
    ):
        ok_res = reconcile_registration(TX_HASH_A, previous_status="pending", proof_id=PROOF_ID)

    assert ok_res["status"] == "confirmed"
    assert ok_res["intentVerified"] is True
    mock_update.assert_called_once_with(TX_HASH_A, "confirmed", force=False)

    # Same fields except identity tier changed to 'source' -> digest differs -> rejected!
    wrong_tier_digest = compute_statement_intent_digest(_statement(tier="source", sourceAddress=""))
    wrong_memo_b64 = base64.b64encode(bytes.fromhex(wrong_tier_digest)).decode("ascii")
    persist_registration_intent(approved, tx_hash=TX_HASH_B)

    with (
        mock.patch("tx_verification.horizon_urls", return_value=("https://horizon.test",)),
        mock.patch("tx_verification._latest_ledger", return_value=110),
        mock.patch(
            "tx_verification._fetch_json",
            return_value=(
                200,
                {
                    "successful": True,
                    "ledger": 108,
                    "memo_type": "hash",
                    "memo": wrong_memo_b64,
                },
            ),
        ),
        mock.patch("registration_reconcile.update_tx_status", return_value=True) as mock_fail_update,
    ):
        bad_res = reconcile_registration(TX_HASH_B, previous_status="pending", proof_id=PROOF_ID)

    assert bad_res["status"] == "failed"
    assert bad_res["reason"] == "statement_intent_mismatch"
    assert bad_res["intentVerified"] is False
    mock_fail_update.assert_called_once_with(TX_HASH_B, "failed", force=False)


def test_reconcile_rejects_wrong_submitting_account_and_conflicting_tx_rebind():
    approved = _statement(sourceAddress=OWNER_A)
    persist_registration_intent(approved, tx_hash=TX_HASH_A)

    # Re-binding the same tx_hash to a different statement fails closed
    with pytest.raises(StatementIntentConflictError):
        persist_registration_intent(_statement(videoHash="77" * 32), tx_hash=TX_HASH_A)

    # Transaction submitted by OWNER_B instead of approved OWNER_A is rejected
    with (
        mock.patch("tx_verification.horizon_urls", return_value=("https://horizon.test",)),
        mock.patch("tx_verification._latest_ledger", return_value=405),
        mock.patch(
            "tx_verification._fetch_json",
            return_value=(
                200,
                {
                    "successful": True,
                    "ledger": 400,
                    "source_account": OWNER_B,
                },
            ),
        ),
        mock.patch("registration_reconcile.update_tx_status", return_value=True) as mock_update,
    ):
        res = reconcile_registration(TX_HASH_A, previous_status="pending", proof_id=PROOF_ID)

    assert res["status"] == "failed"
    assert res["reason"] == "statement_intent_mismatch"
    mock_update.assert_called_once_with(TX_HASH_A, "failed", force=False)


def test_require_intent_and_require_onchain_statement_fail_closed():
    # Missing persisted intent when require_intent=True rejects without calling Horizon
    with mock.patch("registration_reconcile.verify_transaction") as mock_verify:
        missing_intent = reconcile_registration(
            TX_HASH_A,
            previous_status="pending",
            proof_id=PROOF_ID,
            require_intent=True,
        )
    assert missing_intent["status"] == "failed"
    assert missing_intent["reason"] == "missing_registration_intent"
    mock_verify.assert_not_called()

    # Persisted intent with require_onchain_statement=True rejects plain tx lacking statement
    persist_registration_intent(_statement(), tx_hash=TX_HASH_A)
    with (
        mock.patch(
            "registration_reconcile.verify_transaction",
            return_value=TxVerificationResult(
                status="confirmed",
                ledger=50,
                latest_ledger=52,
                confirmations=3,
                successful=True,
                reason="confirmed",
            ),
        ),
        mock.patch("registration_reconcile.update_tx_status", return_value=True) as mock_update,
    ):
        missing_stmt = reconcile_registration(
            TX_HASH_A,
            previous_status="pending",
            proof_id=PROOF_ID,
            require_onchain_statement=True,
        )
    assert missing_stmt["status"] == "failed"
    assert missing_stmt["reason"] == "missing_registered_statement"
    mock_update.assert_called_once_with(TX_HASH_A, "failed", force=False)


def test_register_endpoint_persists_intent_before_enqueuing_verify_tx_and_rejects_mismatch(
    caplog: pytest.LogCaptureFixture,
):
    saved_key = os.environ.get("REGISTER_API_KEY")
    os.environ.pop("REGISTER_API_KEY", None)
    try:
        client = app_module.create_app().test_client()
        enqueued_jobs: list[tuple[str, dict[str, object]]] = []

        def spy_enqueue(job_type: str, job_payload: dict[str, object]) -> int:
            # Intent MUST already be persisted before verify_tx job is enqueued!
            persisted = get_registration_intent(tx_hash=TX_HASH_A)
            assert persisted is not None
            assert persisted.intent_digest == job_payload["intent_digest"]
            enqueued_jobs.append((job_type, dict(job_payload)))
            return 101

        reg_payload = {
            "fileName": "synthetic_witness_artifact",
            "videoHash": VIDEO_HASH,
            "metadataHash": METADATA_HASH,
            "proofId": PROOF_ID,
            "tier": "source",
            "txHash": TX_HASH_A,
            "sourceAddress": OWNER_A,
            "contractId": CONTRACT_A,
        }
        stub_row = {
            "id": 77,
            "video_hash": VIDEO_HASH,
            "metadata_hash": METADATA_HASH,
            "proof_id": PROOF_ID,
            "tier": "source",
            "tx_hash": TX_HASH_A,
            "tx_status": "pending",
            "source_address": OWNER_A,
            "contract_id": CONTRACT_A,
        }

        with (
            mock.patch.object(app_module, "upsert_register_event", return_value=(stub_row, True)),
            mock.patch.object(app_module, "queue_webhook_deliveries"),
            mock.patch.object(app_module, "enqueue_job", side_effect=spy_enqueue),
        ):
            resp = client.post("/api/proofs/register", json=reg_payload)

        assert resp.status_code == 201
        resp_json = resp.get_json()
        expected_digest = compute_statement_intent_digest(reg_payload)
        assert resp_json["intent_digest"] == expected_digest
        assert len(enqueued_jobs) == 1
        job_type, job_payload = enqueued_jobs[0]
        assert job_type == "verify_tx"
        assert job_payload["intent_digest"] == expected_digest

        # Executing the enqueued verify_tx job against a mismatched on-chain statement fails closed
        caplog.set_level(logging.INFO)
        with (
            mock.patch(
                "registration_reconcile.verify_transaction",
                return_value=TxVerificationResult(
                    status="confirmed",
                    ledger=900,
                    latest_ledger=905,
                    confirmations=6,
                    successful=True,
                    reason="confirmed",
                    registered_statement_digest="dd" * 32,
                    registered_statement_present=True,
                    registered_statement_valid=True,
                ),
            ),
            mock.patch("registration_reconcile.update_tx_status", return_value=True) as mock_update,
        ):
            job_out = process_verify_tx_job(job_payload)

        assert job_out["status"] == "failed"
        assert job_out["reason"] == "statement_intent_mismatch"
        assert job_out["intentVerified"] is False
        mock_update.assert_called_once_with(TX_HASH_A, "failed", force=False)
        assert OWNER_A not in caplog.text
        assert "synthetic_witness_artifact" not in caplog.text
    finally:
        if saved_key is not None:
            os.environ["REGISTER_API_KEY"] = saved_key


def test_db_backed_intent_persistence_and_batch_reconcile_binding():
    stored_records: dict[tuple[str, str], dict[str, object]] = {}

    def fake_create(digest: str, req_type: str, expires_at=None):
        key = (digest, req_type)
        if key not in stored_records:
            stored_records[key] = {"id": len(stored_records) + 1, "status": "PENDING"}
        return int(stored_records[key]["id"]), str(stored_records[key]["status"])

    def fake_store_resp(rec_id: int, payload: object):
        for rec in stored_records.values():
            if rec["id"] == rec_id:
                rec["status"] = "COMPLETED"
                rec["response_payload"] = payload

    def fake_get(digest: str, req_type: str):
        rec = stored_records.get((digest, req_type))
        return dict(rec) if rec else None

    with (
        mock.patch.object(idem_mod, "_db_available", return_value=True),
        mock.patch.object(idem_mod, "create_idempotency_record", side_effect=fake_create),
        mock.patch.object(idem_mod, "store_response", side_effect=fake_store_resp),
        mock.patch.object(idem_mod, "get_idempotency_record", side_effect=fake_get),
    ):
        persisted = persist_registration_intent(_statement(), tx_hash=TX_HASH_A)
        reset_registration_intents()  # evict memory cache so lookup hits DB record
        recovered = get_registration_intent(tx_hash=TX_HASH_A)
        assert recovered is not None
        assert recovered.intent_digest == persisted.intent_digest

    # Batch pending reconcile binds canonical statement from pending DB rows before verifying
    pending_rows = [
        {
            "id": 12,
            "proof_id": PROOF_ID,
            "video_hash": VIDEO_HASH,
            "metadata_hash": METADATA_HASH,
            "tier": "source",
            "source_address": OWNER_A,
            "contract_id": CONTRACT_A,
            "tx_hash": TX_HASH_B,
            "tx_status": "pending",
        }
    ]
    with (
        mock.patch("registration_reconcile.list_pending_registration_txs", return_value=pending_rows),
        mock.patch(
            "registration_reconcile.verify_transaction",
            return_value=TxVerificationResult(
                status="confirmed",
                ledger=200,
                latest_ledger=202,
                confirmations=3,
                successful=True,
                reason="confirmed",
                registered_statement_digest="ee" * 32,
                registered_statement_present=True,
                registered_statement_valid=True,
            ),
        ),
        mock.patch("registration_reconcile.update_tx_status", return_value=True),
    ):
        batch_report = reconcile_pending_registrations(limit=10, min_confirmations=1)

    assert batch_report["summary"]["scanned"] == 1
    assert batch_report["summary"]["failed"] == 1
    assert batch_report["summary"]["confirmed"] == 0
    assert batch_report["results"][0]["reason"] == "statement_intent_mismatch"
