"""Focused coverage for network-bound registration reconciliation checkpoints."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from unittest.mock import patch

import pytest

import registration_reconcile as rr
from registration_reconcile import reconcile_registration
from registration_reconcile import clamp_reconcile_limit
from tx_verification import TxVerificationResult, verify_transaction

VALID_TX = "a" * 64

RELEASE_ID = "harpocrates-1.0.0"
NETWORK = "testnet"
PASSPHRASE = "Test SDF Network ; September 2015"
OTHER_PASSPHRASE = "Public Global Stellar Network ; September 2015"


class CheckpointPersistenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self._tmp.name)
        self.deployment = rr.DeploymentIdentity(
            release_id=RELEASE_ID,
            network=NETWORK,
            network_passphrase=PASSPHRASE,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _store(self, deployment: rr.DeploymentIdentity | None = None) -> rr.CheckpointStore:
        return rr.CheckpointStore(self.state_dir, deployment or self.deployment)

    def _raw(self) -> dict:
        return json.loads(self._store().path.read_text(encoding="utf-8"))

    def test_records_last_trusted_ledger_and_network_identity(self) -> None:
        store = self._store()
        self.assertIsNone(store.load())

        checkpoint = store.record(1_250, updated_at="2026-01-01T00:00:00Z")
        reloaded = self._store().load()

        self.assertIsNotNone(reloaded)
        self.assertEqual(reloaded.last_trusted_ledger, 1_250)
        self.assertEqual(reloaded.network, NETWORK)
        self.assertEqual(reloaded.network_passphrase, PASSPHRASE)
        self.assertEqual(reloaded.network_identity, checkpoint.network_identity)
        self.assertEqual(reloaded.deployment_fingerprint, self.deployment.fingerprint)
        self.assertEqual(reloaded.updated_at, "2026-01-01T00:00:00Z")
        self.assertEqual(self._raw()["lastTrustedLedger"], 1_250)

    def test_refuses_checkpoint_from_different_release(self) -> None:
        self._store().record(500)
        other = rr.DeploymentIdentity("other-release", NETWORK, PASSPHRASE)

        with self.assertRaises(rr.DeploymentMismatchError):
            self._store(other).load()
        with self.assertRaises(rr.DeploymentMismatchError):
            self._store(other).record(900)

        self.assertEqual(self._store().load().last_trusted_ledger, 500)

    def test_refuses_checkpoint_from_different_network_identity(self) -> None:
        self._store().record(500)
        other = rr.DeploymentIdentity(RELEASE_ID, "mainnet", OTHER_PASSPHRASE)

        with self.assertRaises(rr.NetworkMismatchError):
            self._store(other).load()
        with self.assertRaises(rr.NetworkMismatchError):
            self._store(other).record(900)

        self.assertEqual(self._store().load().last_trusted_ledger, 500)

    def test_rejects_ledger_rollback_but_allows_forward_progress(self) -> None:
        store = self._store()
        first = store.record(200)
        repeated = store.record(200)
        self.assertEqual(first, repeated)

        with self.assertRaises(rr.LedgerRollbackError):
            store.record(199)
        self.assertEqual(store.load().last_trusted_ledger, 200)

        advanced = store.record(201)
        self.assertEqual(advanced.last_trusted_ledger, 201)

    def test_rejects_invalid_ledger_boundary(self) -> None:
        with self.assertRaises(rr.CheckpointError):
            self._store().record(0)
        with self.assertRaises(rr.CheckpointError):
            self._store().record(True)
        self.assertIsNone(self._store().load())

    def test_rejects_tampered_checkpoint(self) -> None:
        store = self._store()
        store.record(300)
        payload = self._raw()
        payload["networkPassphrase"] = OTHER_PASSPHRASE
        store.path.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaises(rr.CheckpointError):
            store.load()


class ReconcileTransportTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self._tmp.name)
        self.deployment = rr.DeploymentIdentity(
            release_id=RELEASE_ID,
            network=NETWORK,
            network_passphrase=PASSPHRASE,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _observation(self, **overrides):
        observation = {
            "ledger": 900,
            "network": NETWORK,
            "networkPassphrase": PASSPHRASE,
            "releaseId": RELEASE_ID,
        }
        observation.update(overrides)
        return observation

    def test_reconciles_observation_from_fake_transport(self) -> None:
        store = rr.CheckpointStore(self.state_dir, self.deployment)
        result = rr.reconcile_registration(store, lambda deployment: self._observation())

        self.assertEqual(result.last_trusted_ledger, 900)
        self.assertEqual(store.load().last_trusted_ledger, 900)

    def test_rejects_transport_from_different_network(self) -> None:
        store = rr.CheckpointStore(self.state_dir, self.deployment)
        observation = self._observation(networkPassphrase=OTHER_PASSPHRASE)

        with self.assertRaises(rr.NetworkMismatchError):
            rr.reconcile_registration(store, lambda deployment: observation)
        self.assertIsNone(store.load())


class DeploymentIdentityTest(unittest.TestCase):
    def test_from_config_uses_existing_release_network(self) -> None:
        config = SimpleNamespace(release_id=RELEASE_ID, release_network=NETWORK)
        identity = rr.DeploymentIdentity.from_config(config)
        self.assertEqual(identity.network, NETWORK)
        self.assertEqual(identity.network_passphrase, PASSPHRASE)

    def test_from_config_honours_explicit_passphrase(self) -> None:
        config = SimpleNamespace(release_id=RELEASE_ID, release_network=NETWORK)
        with patch.dict(
            "os.environ", {"STELLAR_NETWORK_PASSPHRASE": OTHER_PASSPHRASE}, clear=False
        ):
            identity = rr.DeploymentIdentity.from_config(config)
        self.assertEqual(identity.network_passphrase, OTHER_PASSPHRASE)


def test_clamp_reconcile_limit_bounds():
    assert clamp_reconcile_limit(1) == 1
    assert clamp_reconcile_limit(999) == 50
    with pytest.raises(ValueError):
        clamp_reconcile_limit(0)
    with pytest.raises(ValueError):
        clamp_reconcile_limit("nope")


@mock.patch("tx_verification._latest_ledger", return_value=200)
@mock.patch("tx_verification._fetch_json")
def test_verify_transaction_confirmed_with_depth(mock_fetch, _mock_latest):
    mock_fetch.return_value = (200, {"successful": True, "ledger": 198})
    result = verify_transaction(VALID_TX, min_confirmations=2)
    assert result.status == "confirmed"
    assert result.confirmations == 3


@mock.patch("tx_verification._latest_ledger", return_value=198)
@mock.patch("tx_verification._fetch_json")
def test_verify_transaction_awaits_confirmations(mock_fetch, _mock_latest):
    mock_fetch.return_value = (200, {"successful": True, "ledger": 198})
    result = verify_transaction(VALID_TX, min_confirmations=5)
    assert result.status == "pending"
    assert result.reason == "awaiting_confirmations"
    assert result.confirmations == 1


@mock.patch("tx_verification._fetch_json")
def test_verify_transaction_failed_unsuccessful(mock_fetch):
    mock_fetch.return_value = (200, {"successful": False, "ledger": 10})
    result = verify_transaction(VALID_TX)
    assert result.status == "failed"
    assert result.reason == "tx_unsuccessful"


@mock.patch("tx_verification.horizon_urls", return_value=["https://horizon.test"])
@mock.patch("tx_verification._fetch_json", return_value=(404, None))
def test_verify_transaction_missing(mock_fetch, _urls):
    result = verify_transaction(VALID_TX)
    assert result.status == "missing"


@mock.patch("tx_verification.horizon_urls", return_value=["https://horizon.test"])
@mock.patch("tx_verification._fetch_json", side_effect=RuntimeError("boom"))
def test_verify_transaction_dependency_error(mock_fetch, _urls):
    result = verify_transaction(VALID_TX)
    assert result.status == "error"
    assert result.reason == "horizon_dependency_failure"


@mock.patch("registration_reconcile.update_tx_status", return_value=True)
@mock.patch(
    "registration_reconcile.verify_transaction",
    return_value=TxVerificationResult(
        status="confirmed",
        confirmations=3,
        ledger=10,
        reason="confirmed",
    ),
)
def test_reconcile_registration_updates_terminal(mock_verify, mock_update):
    result = reconcile_registration(VALID_TX, previous_status="pending", min_confirmations=1)
    assert result["status"] == "confirmed"
    assert result["updated"] is True
    mock_update.assert_called_once_with(VALID_TX, "confirmed", force=False)


@mock.patch("registration_reconcile.update_tx_status")
@mock.patch(
    "registration_reconcile.verify_transaction",
    return_value=TxVerificationResult(status="confirmed", reason="confirmed"),
)
def test_reconcile_skips_already_terminal(mock_verify, mock_update):
    result = reconcile_registration(VALID_TX, previous_status="confirmed")
    assert result["status"] == "confirmed"
    assert result["updated"] is False
    assert result["reason"] == "already_terminal"
    mock_verify.assert_not_called()
    mock_update.assert_not_called()


def test_duplicate_submission_resolves_to_single_authoritative_result():
    # Two concurrent workers observe the same tx hash (duplicate submission).
    # Both reconcile against the same fake chain state; only one terminal
    # update must be recorded and the result must be identical.
    verdict = TxVerificationResult(status="confirmed", confirmations=3, ledger=10, reason="confirmed")
    with mock.patch("registration_reconcile.verify_transaction", return_value=verdict), \
            mock.patch("registration_reconcile.update_tx_status", side_effect=[True, False]) as upd:
        first = reconcile_registration(VALID_TX, previous_status="pending", min_confirmations=1)
        second = reconcile_registration(VALID_TX, previous_status="pending", min_confirmations=1)
    assert first["status"] == second["status"] == "confirmed"
    assert first["updated"] is True
    assert second["updated"] is False
    assert upd.call_count == 2


def test_delayed_indexing_stays_pending_then_confirms():
    # Horizon has not indexed the tx yet (404), then indexes it later.
    with mock.patch("tx_verification.horizon_urls", return_value=["https://horizon.test"]), \
            mock.patch("tx_verification._fetch_json", side_effect=[(404, None), (200, {"successful": True, "ledger": 50})]), \
            mock.patch("tx_verification._latest_ledger", return_value=60):
        first = verify_transaction(VALID_TX, min_confirmations=1)
        second = verify_transaction(VALID_TX, min_confirmations=1)
    assert first.status == "missing"
    assert second.status == "confirmed"


def test_replaced_worker_does_not_regress_terminal_state():
    # A replacement worker sees a previously confirmed row and must not
    # re-verify or overwrite the authoritative result.
    with mock.patch("registration_reconcile.verify_transaction") as verify, \
            mock.patch("registration_reconcile.update_tx_status") as upd:
        result = reconcile_registration(VALID_TX, previous_status="confirmed")
    assert result["status"] == "confirmed"
    assert result["updated"] is False
    verify.assert_not_called()
    upd.assert_not_called()


def test_reconcile_malformed_hash_is_stable():
    result = reconcile_registration("bad")
    assert result["status"] == "failed"
    assert result["error"] == "malformed_tx_hash"
    assert result["updated"] is False
