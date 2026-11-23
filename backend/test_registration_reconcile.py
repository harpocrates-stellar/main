"""Focused coverage for network-bound registration reconciliation checkpoints."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import registration_reconcile as rr

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


if __name__ == "__main__":
    unittest.main()
