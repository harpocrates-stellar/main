"""Tests for issuer key manifests, directory events and checkpoints API."""

from __future__ import annotations

import time
import unittest
from unittest.mock import MagicMock, patch

import app as app_module
from db import (
    decode_issuer_events_cursor,
    encode_issuer_events_cursor,
    get_current_issuer_manifest,
    get_latest_checkpoint,
    insert_issuer_checkpoint,
    insert_issuer_directory_event,
    list_issuer_directory_events,
)
from errors import FRESHNESS_ERROR, NOT_FOUND, VALIDATION_ERROR
from issuer_key_transparency import (
    DEFAULT_FRESHNESS_SECONDS,
    HIGH_ASSURANCE_FRESHNESS_SECONDS,
    DirectoryCheckpoint,
    DirectoryEvent,
    EventType,
    IssuerKey,
    IssuerManifest,
    KeyStatus,
    compute_tree_head,
    create_activation_event,
    create_rotation_event,
    event_hash,
    manifest_hash,
)
from test_strkey import VALID_G_ADDRESS

ORG_HASH = "a" * 64
POLICY_HASH = "b" * 64
KEY_HASH_1 = "c" * 64
KEY_HASH_2 = "d" * 64
KEY_HASH_3 = "e" * 64
SIG_HASH = "f" * 64


def _sample_manifest(
    issuer_address: str = VALID_G_ADDRESS,
    status: KeyStatus = KeyStatus.ACTIVE,
) -> IssuerManifest:
    keys = [
        IssuerKey(
            key_id="key-1",
            public_key_hash=KEY_HASH_1,
            algorithm="ed25519",
            valid_from=1000,
            status=status,
        )
    ]
    return IssuerManifest(
        organization_identity_hash=ORG_HASH,
        issuer_address=issuer_address,
        active_keys=keys,
        policy_hash=POLICY_HASH,
        valid_from=1000,
        signature_hash=SIG_HASH,
    )


class IssuerKeysEndpointTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = app_module.app.test_client()

    def test_issuer_keys_success(self) -> None:
        manifest = _sample_manifest()
        with patch.object(
            app_module,
            "get_current_issuer_manifest",
            return_value=(manifest.to_dict(), "active"),
        ) as mock_get:
            response = self.client.get(f"/api/issuers/{VALID_G_ADDRESS}/keys")

        self.assertEqual(response.status_code, 200)
        body = response.json
        self.assertTrue(body["ok"])
        self.assertEqual(body["status"], "active")
        self.assertIn("manifest", body)
        self.assertEqual(body["manifest"]["issuerAddress"], VALID_G_ADDRESS)
        self.assertEqual(len(body["keys"]), 1)
        self.assertEqual(body["keys"][0]["keyId"], "key-1")
        mock_get.assert_called_once_with(VALID_G_ADDRESS)

    def test_issuer_keys_not_found(self) -> None:
        with patch.object(
            app_module,
            "get_current_issuer_manifest",
            return_value=(None, None),
        ):
            response = self.client.get(f"/api/issuers/{VALID_G_ADDRESS}/keys")

        self.assertEqual(response.status_code, 404)
        body = response.json
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"]["code"], NOT_FOUND)

    def test_issuer_keys_invalid_address(self) -> None:
        for bad_addr in ("not-a-valid-address", "G12345", "C" + "A" * 55):
            with self.subTest(address=bad_addr):
                response = self.client.get(f"/api/issuers/{bad_addr}/keys")
                self.assertEqual(response.status_code, 400)
                body = response.json
                self.assertFalse(body["ok"])
                self.assertEqual(body["error"]["code"], VALIDATION_ERROR)

    def test_issuer_keys_read_only_methods(self) -> None:
        for method in ("post", "put", "delete", "patch"):
            with self.subTest(method=method):
                res = getattr(self.client, method)(f"/api/issuers/{VALID_G_ADDRESS}/keys")
                self.assertEqual(res.status_code, 405)


class IssuerEventsEndpointTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = app_module.app.test_client()

    def test_issuer_events_invalid_address(self) -> None:
        response = self.client.get("/api/issuers/invalid-addr/events")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"]["code"], VALIDATION_ERROR)

    def test_issuer_events_invalid_limit(self) -> None:
        response = self.client.get(f"/api/issuers/{VALID_G_ADDRESS}/events?limit=abc")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"]["code"], VALIDATION_ERROR)

    def test_issuer_events_invalid_cursor(self) -> None:
        for bad in ("bad-cursor!", "0", "-1"):
            with self.subTest(cursor=bad):
                response = self.client.get(f"/api/issuers/{VALID_G_ADDRESS}/events?cursor={bad}")
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json["error"]["code"], VALIDATION_ERROR)

    def test_issuer_events_pagination_calls_db(self) -> None:
        ev0 = create_activation_event(
            organization_identity_hash=ORG_HASH,
            key_id="k0",
            public_key_hash=KEY_HASH_1,
            sequence=0,
            timestamp=1000,
        )
        cursor_token = encode_issuer_events_cursor(5)

        with patch.object(
            app_module,
            "list_issuer_directory_events",
            return_value=([ev0.to_dict()], cursor_token),
        ) as mock_list:
            res = self.client.get(f"/api/issuers/{VALID_G_ADDRESS}/events?limit=10")

        self.assertEqual(res.status_code, 200)
        body = res.json
        self.assertTrue(body["ok"])
        self.assertEqual(body["nextCursor"], cursor_token)
        mock_list.assert_called_once_with(VALID_G_ADDRESS, 10, cursor_id=None)

        # Call with cursor
        with patch.object(
            app_module,
            "list_issuer_directory_events",
            return_value=([], None),
        ) as mock_list:
            res2 = self.client.get(f"/api/issuers/{VALID_G_ADDRESS}/events?cursor={cursor_token}")

        self.assertEqual(res2.status_code, 200)
        self.assertIsNone(res2.json["nextCursor"])
        mock_list.assert_called_once_with(VALID_G_ADDRESS, 25, cursor_id=5)

    def test_issuer_events_read_only_methods(self) -> None:
        for method in ("post", "put", "delete", "patch"):
            with self.subTest(method=method):
                res = getattr(self.client, method)(f"/api/issuers/{VALID_G_ADDRESS}/events")
                self.assertEqual(res.status_code, 405)


class EventChainVerificationTest(unittest.TestCase):
    """Verifies that the event chain returned by the API validates with event_hash across pages."""

    def setUp(self) -> None:
        self.client = app_module.app.test_client()

    def test_chain_verification_over_returned_pages(self) -> None:
        # Build 5 sequentially hash-chained events
        ev0 = create_activation_event(
            organization_identity_hash=ORG_HASH,
            key_id="key-0",
            public_key_hash=KEY_HASH_1,
            sequence=0,
            timestamp=1000,
        )
        h0 = event_hash(ev0)

        ev1 = create_rotation_event(
            organization_identity_hash=ORG_HASH,
            new_key_id="key-1",
            new_public_key_hash=KEY_HASH_2,
            predecessor_key_id="key-0",
            sequence=1,
            timestamp=2000,
            previous_event_hash=h0,
        )
        h1 = event_hash(ev1)

        ev2 = DirectoryEvent(
            event_type=EventType.COMPROMISE,
            sequence=2,
            timestamp=3000,
            organization_identity_hash=ORG_HASH,
            key_id="key-1",
            public_key_hash=KEY_HASH_2,
            previous_event_hash=h1,
            reason_hash="1" * 64,
        )
        h2 = event_hash(ev2)

        ev3 = create_activation_event(
            organization_identity_hash=ORG_HASH,
            key_id="key-2",
            public_key_hash=KEY_HASH_3,
            sequence=3,
            timestamp=4000,
            previous_event_hash=h2,
        )
        h3 = event_hash(ev3)

        ev4 = DirectoryEvent(
            event_type=EventType.RETIREMENT,
            sequence=4,
            timestamp=5000,
            organization_identity_hash=ORG_HASH,
            key_id="key-0",
            public_key_hash=KEY_HASH_1,
            previous_event_hash=h3,
        )

        all_events_fixtures = [ev0, ev1, ev2, ev3, ev4]

        # Simulate keyset cursor pagination over all_events_fixtures with page_size=2
        def fake_list_events(addr, limit=25, cursor_id=None):
            start_index = 0 if cursor_id is None else cursor_id
            page = all_events_fixtures[start_index : start_index + limit]
            next_idx = start_index + limit
            next_cursor = (
                encode_issuer_events_cursor(next_idx) if next_idx < len(all_events_fixtures) else None
            )
            return [e.to_dict() for e in page], next_cursor

        with patch.object(app_module, "list_issuer_directory_events", side_effect=fake_list_events):
            collected_events: list[dict] = []
            cursor: str | None = None
            page_count = 0

            while True:
                url = f"/api/issuers/{VALID_G_ADDRESS}/events?limit=2"
                if cursor:
                    url += f"&cursor={cursor}"
                res = self.client.get(url)
                self.assertEqual(res.status_code, 200)
                body = res.json
                self.assertTrue(body["ok"])
                collected_events.extend(body["events"])
                cursor = body.get("nextCursor")
                page_count += 1
                if not cursor:
                    break

        self.assertEqual(len(collected_events), 5)
        self.assertEqual(page_count, 3)  # 2 + 2 + 1 = 5 events in 3 pages

        # Verify the chain with event_hash
        previous_hash: str | None = None
        reconstructed_events: list[DirectoryEvent] = []

        for i, ev_dict in enumerate(collected_events):
            event = DirectoryEvent.from_dict(ev_dict)
            reconstructed_events.append(event)
            self.assertEqual(event.sequence, i)
            self.assertEqual(event.previous_event_hash, previous_hash)
            previous_hash = event_hash(event)

        # Confirm reconstructed tree head matches compute_tree_head
        expected_head = compute_tree_head(all_events_fixtures)
        self.assertEqual(compute_tree_head(reconstructed_events), expected_head)


class CheckpointEndpointTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = app_module.app.test_client()

    def _sample_checkpoint_dict(self, timestamp: int | None = None) -> dict:
        ts = int(time.time()) if timestamp is None else timestamp
        return {
            "id": 1,
            "issuer_address": VALID_G_ADDRESS,
            "organization_identity_hash": ORG_HASH,
            "tree_head_hash": "9" * 64,
            "event_count": 5,
            "timestamp": ts,
            "manifest_hash": "8" * 64,
            "signature_hash": SIG_HASH,
            "version": 1,
            "protocol": "harpocrates-issuer-key-transparency",
            "manifest": {"issuerAddress": VALID_G_ADDRESS},
        }

    def test_checkpoint_success_fresh(self) -> None:
        cp_dict = self._sample_checkpoint_dict()
        with patch.object(app_module, "get_latest_checkpoint", return_value=cp_dict):
            res = self.client.get("/api/issuers/checkpoint")

        self.assertEqual(res.status_code, 200)
        body = res.json
        self.assertTrue(body["ok"])
        self.assertIn("checkpoint", body)
        self.assertEqual(body["checkpoint"]["treeHeadHash"], "9" * 64)
        self.assertEqual(body["checkpoint"]["signatureHash"], SIG_HASH)
        self.assertIn("manifest", body)

    def test_checkpoint_filter_by_issuer_address(self) -> None:
        cp_dict = self._sample_checkpoint_dict()
        with patch.object(app_module, "get_latest_checkpoint", return_value=cp_dict) as mock_cp:
            res = self.client.get(f"/api/issuers/checkpoint?issuer_address={VALID_G_ADDRESS}")

        self.assertEqual(res.status_code, 200)
        mock_cp.assert_called_once_with(VALID_G_ADDRESS)

    def test_checkpoint_invalid_issuer_address(self) -> None:
        res = self.client.get("/api/issuers/checkpoint?issuer_address=bad-address")
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json["error"]["code"], VALIDATION_ERROR)

    def test_checkpoint_not_found(self) -> None:
        with patch.object(app_module, "get_latest_checkpoint", return_value=None):
            res = self.client.get("/api/issuers/checkpoint")

        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json["error"]["code"], NOT_FOUND)

    def test_checkpoint_stale_high_assurance_returns_freshness_error(self) -> None:
        stale_ts = int(time.time()) - (HIGH_ASSURANCE_FRESHNESS_SECONDS + 100)
        cp_dict = self._sample_checkpoint_dict(timestamp=stale_ts)

        with patch.object(app_module, "get_latest_checkpoint", return_value=cp_dict):
            res = self.client.get("/api/issuers/checkpoint?high_assurance=true")

        self.assertEqual(res.status_code, 400)
        body = res.json
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"]["code"], FRESHNESS_ERROR)
        self.assertIn("stale", body["error"]["message"])

    def test_checkpoint_stale_default_returns_freshness_error(self) -> None:
        stale_ts = int(time.time()) - (DEFAULT_FRESHNESS_SECONDS + 3600)
        cp_dict = self._sample_checkpoint_dict(timestamp=stale_ts)

        with patch.object(app_module, "get_latest_checkpoint", return_value=cp_dict):
            res = self.client.get("/api/issuers/checkpoint")

        self.assertEqual(res.status_code, 400)
        body = res.json
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"]["code"], FRESHNESS_ERROR)

    def test_checkpoint_enforce_freshness_can_be_disabled(self) -> None:
        stale_ts = int(time.time()) - (DEFAULT_FRESHNESS_SECONDS + 3600)
        cp_dict = self._sample_checkpoint_dict(timestamp=stale_ts)

        with patch.object(app_module, "get_latest_checkpoint", return_value=cp_dict):
            res = self.client.get("/api/issuers/checkpoint?enforce_freshness=false")

        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json["ok"])

    def test_checkpoint_read_only_methods(self) -> None:
        for method in ("post", "put", "delete", "patch"):
            with self.subTest(method=method):
                res = getattr(self.client, method)("/api/issuers/checkpoint")
                self.assertEqual(res.status_code, 405)


class DatabaseHelpersMockTest(unittest.TestCase):
    def test_encode_decode_issuer_cursor_roundtrip(self) -> None:
        token = encode_issuer_events_cursor(99)
        self.assertEqual(decode_issuer_events_cursor(token), 99)

    def test_list_issuer_directory_events_empty_when_no_db(self) -> None:
        with patch("db.database_url", return_value=None):
            events, cursor = list_issuer_directory_events(VALID_G_ADDRESS)
            self.assertEqual(events, [])
            self.assertIsNone(cursor)

    def test_get_latest_checkpoint_none_when_no_db(self) -> None:
        with patch("db.database_url", return_value=None):
            self.assertIsNone(get_latest_checkpoint())

    def test_get_current_issuer_manifest_none_when_no_db(self) -> None:
        with patch("db.database_url", return_value=None):
            manifest, status = get_current_issuer_manifest(VALID_G_ADDRESS)
            self.assertIsNone(manifest)
            self.assertIsNone(status)


if __name__ == "__main__":
    unittest.main()
