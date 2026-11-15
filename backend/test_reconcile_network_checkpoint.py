"""Focused tests for network-bound registration reconciliation checkpoints."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from unittest import mock

import pytest

_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_BACKEND_DIR)
for _p in (_BACKEND_DIR, _REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from app import app
from idempotency import verify_checkpoint_network_binding
from registration_reconcile import (
    CheckpointConfigMismatchError,
    load_reconciliation_checkpoint,
    reconcile_pending_registrations,
    resolve_deployment_network_identity,
    save_reconciliation_checkpoint,
)
from strkey import _VERSION_BYTE_CONTRACT, make_strkey


CONTRACT_A = make_strkey(_VERSION_BYTE_CONTRACT, b"\x11" * 32)
CONTRACT_B = make_strkey(_VERSION_BYTE_CONTRACT, b"\x22" * 32)


def test_persist_and_reload_network_bound_checkpoint(tmp_path: Path):
    ckpt_file = tmp_path / "reconcile_checkpoint.json"
    testnet_id = resolve_deployment_network_identity(
        release_network="testnet",
        contract_id=CONTRACT_A,
    )

    saved = save_reconciliation_checkpoint(
        ckpt_file,
        last_trusted_ledger=12345,
        network=testnet_id,
        last_confirmed_tx_hash="a" * 64,
        last_confirmed_event_id=9,
    )
    assert saved.last_trusted_ledger == 12345
    assert saved.network.contract_id == CONTRACT_A

    loaded = load_reconciliation_checkpoint(ckpt_file, expected_network=testnet_id)
    assert loaded is not None
    assert loaded.last_trusted_ledger == 12345
    assert loaded.last_confirmed_tx_hash == "a" * 64
    assert loaded.last_confirmed_event_id == 9
    assert loaded.network.identity_digest == testnet_id.identity_digest


def test_refuses_checkpoint_from_different_network_passphrase_or_contract(tmp_path: Path):
    ckpt_file = tmp_path / "ckpt.json"
    testnet_a = resolve_deployment_network_identity(
        release_network="testnet",
        contract_id=CONTRACT_A,
    )
    save_reconciliation_checkpoint(ckpt_file, last_trusted_ledger=500, network=testnet_a)

    mainnet_a = resolve_deployment_network_identity(
        release_network="mainnet",
        contract_id=CONTRACT_A,
    )
    with pytest.raises(CheckpointConfigMismatchError) as exc_net:
        load_reconciliation_checkpoint(ckpt_file, expected_network=mainnet_a)
    assert exc_net.value.field == "releaseNetwork"

    custom_passphrase = resolve_deployment_network_identity(
        release_network="testnet",
        network_passphrase="Custom Private Stellar Network ; 2026",
        contract_id=CONTRACT_A,
    )
    with pytest.raises(CheckpointConfigMismatchError) as exc_pass:
        load_reconciliation_checkpoint(ckpt_file, expected_network=custom_passphrase)
    assert exc_pass.value.field == "networkPassphrase"

    testnet_b = resolve_deployment_network_identity(
        release_network="testnet",
        contract_id=CONTRACT_B,
    )
    with pytest.raises(CheckpointConfigMismatchError) as exc_contract:
        load_reconciliation_checkpoint(ckpt_file, expected_network=testnet_b)
    assert exc_contract.value.field == "contractId"


def test_refuses_tampered_digest_and_ledger_regression(tmp_path: Path):
    ckpt_file = tmp_path / "ckpt.json"
    testnet = resolve_deployment_network_identity(
        release_network="testnet",
        contract_id=CONTRACT_A,
    )
    save_reconciliation_checkpoint(ckpt_file, last_trusted_ledger=800, network=testnet)

    with pytest.raises(ValueError, match="regress"):
        save_reconciliation_checkpoint(ckpt_file, last_trusted_ledger=799, network=testnet)

    # Tamper with networkIdentityDigest on disk.
    raw = json.loads(ckpt_file.read_text(encoding="utf-8"))
    raw["networkIdentityDigest"] = "f" * 64
    ckpt_file.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(CheckpointConfigMismatchError) as exc_tamper:
        load_reconciliation_checkpoint(ckpt_file, expected_network=testnet)
    assert exc_tamper.value.field == "networkIdentityDigest"


def test_reconcile_batch_advances_checkpoint_and_fails_closed_on_deployment_mismatch(
    tmp_path: Path,
):
    ckpt_file = tmp_path / "batch_ckpt.json"
    testnet_a = resolve_deployment_network_identity(
        release_network="testnet",
        contract_id=CONTRACT_A,
    )
    mainnet_a = resolve_deployment_network_identity(
        release_network="mainnet",
        contract_id=CONTRACT_A,
    )

    rows = [
        {"id": 11, "proof_id": "1" * 64, "tx_hash": "a" * 64, "tx_status": "pending"},
        {"id": 12, "proof_id": "2" * 64, "tx_hash": "b" * 64, "tx_status": "pending"},
    ]
    with mock.patch(
        "registration_reconcile.list_pending_registration_txs", return_value=rows
    ), mock.patch(
        "registration_reconcile.reconcile_registration",
        side_effect=[
            {"txHash": "a" * 64, "eventId": 11, "status": "confirmed", "ledger": 2100, "updated": True},
            {"txHash": "b" * 64, "eventId": 12, "status": "confirmed", "ledger": 2105, "updated": True},
        ],
    ):
        report = reconcile_pending_registrations(
            limit=10,
            min_confirmations=1,
            checkpoint_path=ckpt_file,
            network_identity=testnet_a,
        )

    assert report["ok"] is True
    assert report["checkpoint"]["lastTrustedLedger"] == 2105
    assert report["checkpoint"]["lastConfirmedTxHash"] == "b" * 64
    assert report["checkpoint"]["lastConfirmedEventId"] == 12
    assert report["checkpoint"]["contractId"] == CONTRACT_A

    # Now attempt reconciliation under a mainnet deployment pointing at the testnet checkpoint:
    # must fail closed BEFORE listing or mutating any database rows!
    with mock.patch(
        "registration_reconcile.list_pending_registration_txs"
    ) as mock_list:
        with pytest.raises(CheckpointConfigMismatchError):
            reconcile_pending_registrations(
                limit=10,
                min_confirmations=1,
                checkpoint_path=ckpt_file,
                network_identity=mainnet_a,
            )
        mock_list.assert_not_called()

    # Original testnet checkpoint remains completely intact on disk.
    preserved = load_reconciliation_checkpoint(ckpt_file, expected_network=testnet_a)
    assert preserved is not None
    assert preserved.last_trusted_ledger == 2105


def test_http_checkpoint_and_reconcile_routes_surface_409_on_network_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    ckpt_file = tmp_path / "http_ckpt.json"
    testnet = resolve_deployment_network_identity(
        release_network="testnet",
        contract_id=CONTRACT_A,
    )
    saved = save_reconciliation_checkpoint(ckpt_file, last_trusted_ledger=999, network=testnet)

    monkeypatch.setenv("RECONCILE_CHECKPOINT_PATH", str(ckpt_file))
    monkeypatch.setenv("HARPOCRATES_RELEASE_NETWORK", "testnet")
    monkeypatch.setenv("PROOF_REGISTRY_CONTRACT_ID", CONTRACT_A)

    assert verify_checkpoint_network_binding(
        saved.to_dict(), expected_identity_digest=testnet.identity_digest
    )

    client = app.test_client()
    ok_get = client.get("/api/proofs/reconcile/checkpoint")
    assert ok_get.status_code == 200
    assert ok_get.get_json()["checkpoint"]["lastTrustedLedger"] == 999

    # Switch deployment contract ID -> both GET checkpoint and POST reconcile refuse with 409!
    monkeypatch.setenv("PROOF_REGISTRY_CONTRACT_ID", CONTRACT_B)
    mismatch_get = client.get("/api/proofs/reconcile/checkpoint")
    assert mismatch_get.status_code == 409
    assert mismatch_get.get_json()["error"] == "reconciliation_checkpoint_network_mismatch"
    assert mismatch_get.get_json()["field"] == "contractId"

    mismatch_post = client.post("/api/proofs/reconcile", json={"limit": 5})
    assert mismatch_post.status_code == 409
    assert mismatch_post.get_json()["error"] == "reconciliation_checkpoint_network_mismatch"
