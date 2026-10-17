"""Authorization on proof history, lineage and reconcile write paths.

History and lineage writes need a registration credential once one is
configured, and an owner-scoped key may only write for its own address. The
reconcile repair knobs (``force``, ``minConfirmations``) are operator-only.
All addresses, keys and hashes are synthetic.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

import app as app_module
from test_register_auth import (
    LEGACY_TOKEN,
    OWNER_A,
    OWNER_B,
    TOKEN_A,
    client_with,
    scoped_env,
)

PROOF_ID = "ab" * 32
TX_HASH = "cd" * 32


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def history_body(**overrides):
    body = {"proofId": PROOF_ID, "action": "revoked", "reasonCode": 3}
    body.update(overrides)
    return body


def lineage_body(actor: str) -> dict:
    return {
        "outputDigest": "ef" * 32,
        "parentProofIds": [PROOF_ID],
        "actorAddress": actor,
    }


def configured_client():
    return client_with(
        REGISTER_API_KEY=LEGACY_TOKEN,
        REGISTER_SCOPED_KEYS=scoped_env((OWNER_A, TOKEN_A)),
    )


class HistoryAuthTests(unittest.TestCase):
    def test_unauthenticated_history_write_is_rejected(self):
        with configured_client() as client, patch.object(
            app_module, "insert_proof_history_event"
        ) as insert:
            response = client.post("/api/proofs/history", json=history_body())
        self.assertEqual(response.status_code, 401)
        insert.assert_not_called()

    def test_scoped_key_cannot_write_history_for_another_owner(self):
        with configured_client() as client, patch.object(
            app_module, "find_proof_owner", return_value=OWNER_B
        ), patch.object(app_module, "insert_proof_history_event") as insert:
            response = client.post(
                "/api/proofs/history", json=history_body(), headers=bearer(TOKEN_A)
            )
        self.assertEqual(response.status_code, 403)
        insert.assert_not_called()

    def test_scoped_key_can_write_history_for_its_own_proof(self):
        with configured_client() as client, patch.object(
            app_module, "find_proof_owner", return_value=OWNER_A
        ), patch.object(
            app_module, "insert_proof_history_event", return_value={"id": 1}
        ) as insert:
            response = client.post(
                "/api/proofs/history", json=history_body(), headers=bearer(TOKEN_A)
            )
        self.assertEqual(response.status_code, 200)
        insert.assert_called_once()

    def test_history_rejects_unknown_action_and_bad_fields(self):
        cases = [
            history_body(action="delete_everything"),
            history_body(reasonCode=999),
            history_body(actor="not-an-address"),
            history_body(txHash="xyz"),
        ]
        with configured_client() as client, patch.object(
            app_module, "insert_proof_history_event"
        ) as insert:
            for body in cases:
                response = client.post(
                    "/api/proofs/history", json=body, headers=bearer(LEGACY_TOKEN)
                )
                self.assertEqual(response.status_code, 400, body)
        insert.assert_not_called()


class LineageAuthTests(unittest.TestCase):
    def test_unauthenticated_lineage_write_is_rejected(self):
        with configured_client() as client, patch.object(
            app_module, "insert_lineage_event"
        ) as insert:
            response = client.post("/api/proofs/lineage", json=lineage_body(OWNER_A))
        self.assertEqual(response.status_code, 401)
        insert.assert_not_called()

    def test_scoped_key_cannot_impersonate_another_actor(self):
        with configured_client() as client, patch.object(
            app_module, "insert_lineage_event"
        ) as insert:
            response = client.post(
                "/api/proofs/lineage", json=lineage_body(OWNER_B), headers=bearer(TOKEN_A)
            )
        self.assertEqual(response.status_code, 403)
        insert.assert_not_called()


class ReconcileAuthTests(unittest.TestCase):
    def test_force_without_auth_is_rejected(self):
        with configured_client() as client, patch.object(
            app_module, "reconcile_registration"
        ) as reconcile:
            response = client.post(
                "/api/proofs/reconcile", json={"txHash": TX_HASH, "force": True}
            )
        self.assertIn(response.status_code, (401, 403))
        reconcile.assert_not_called()

    def test_force_is_rejected_when_no_operator_key_exists(self):
        with client_with() as client, patch.object(
            app_module, "reconcile_registration"
        ) as reconcile:
            response = client.post(
                "/api/proofs/reconcile", json={"txHash": TX_HASH, "force": True}
            )
        self.assertEqual(response.status_code, 403)
        reconcile.assert_not_called()

    def test_scoped_key_cannot_override_confirmation_depth(self):
        with configured_client() as client, patch.object(
            app_module, "reconcile_pending_registrations"
        ) as reconcile:
            response = client.post(
                "/api/proofs/reconcile",
                json={"minConfirmations": 1},
                headers=bearer(TOKEN_A),
            )
        self.assertEqual(response.status_code, 403)
        reconcile.assert_not_called()

    def test_default_reconcile_still_works_without_auth(self):
        report = {"ok": True, "summary": {}, "minConfirmations": 1, "results": []}
        with configured_client() as client, patch.object(
            app_module, "reconcile_pending_registrations", return_value=report
        ):
            response = client.post("/api/proofs/reconcile", json={})
        self.assertEqual(response.status_code, 200)

    def test_operator_can_force_reconcile(self):
        row = {"id": 4, "proof_id": PROOF_ID, "tx_hash": TX_HASH, "tx_status": "confirmed"}
        with configured_client() as client, patch.object(
            app_module, "list_registrations_by_tx_hash", return_value=[row]
        ), patch.object(
            app_module,
            "reconcile_registration",
            return_value={"status": "failed", "updated": True},
        ) as reconcile:
            response = client.post(
                "/api/proofs/reconcile",
                json={"txHash": TX_HASH, "force": True},
                headers=bearer(LEGACY_TOKEN),
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(reconcile.call_args.kwargs["event_id"], 4)
        self.assertTrue(reconcile.call_args.kwargs["force"])


if __name__ == "__main__":
    unittest.main()
