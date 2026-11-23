"""Focused coverage for proof-registration idempotency.

Covers:
- SQL parameter alignment for upsert_register_event (boundary / regression)
- Request-layer decorator status replay and no-DB passthrough
- Semantic idempotency key derivation (positive / negative)
"""

from __future__ import annotations

import ast
import inspect
import re
import unittest
from unittest.mock import MagicMock, patch

from db import make_idempotency_key, upsert_register_event
import idempotency as idem_mod


class UpsertRegisterSqlAlignmentTest(unittest.TestCase):
    """Regression: INSERT placeholders must match column list (was 14 vs 16)."""

    def test_upsert_register_event_values_match_columns(self) -> None:
        source = inspect.getsource(upsert_register_event)
        cols_match = re.search(r"insert into proof_events\s*\(([^)]+)\)", source, re.I | re.S)
        vals_match = re.search(r"values\s*\(([^)]+)\)", source, re.I | re.S)
        self.assertIsNotNone(cols_match)
        self.assertIsNotNone(vals_match)
        columns = [c.strip() for c in cols_match.group(1).split(",") if c.strip()]
        placeholders = vals_match.group(1).count("%s")
        self.assertEqual(len(columns), placeholders)
        self.assertIn("idempotency_key", columns)
        self.assertIn("claimed_capture_time", columns)
        self.assertEqual(len(columns), 16)


class IdempotencyKeyTest(unittest.TestCase):
    def test_positive_deterministic(self) -> None:
        a = make_idempotency_key("aa" * 32, "bb" * 32, "cc" * 32)
        b = make_idempotency_key("aa" * 32, "bb" * 32, "cc" * 32)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)

    def test_negative_differs_on_proof_id(self) -> None:
        a = make_idempotency_key("aa" * 32, "bb" * 32, None)
        b = make_idempotency_key("aa" * 32, "ff" * 32, None)
        self.assertNotEqual(a, b)

    def test_boundary_none_tx_equals_empty(self) -> None:
        self.assertEqual(
            make_idempotency_key("aa" * 32, "bb" * 32, None),
            make_idempotency_key("aa" * 32, "bb" * 32, ""),
        )


class IdempotentDecoratorTest(unittest.TestCase):
    def test_no_db_passthrough(self) -> None:
        calls = []

        @idem_mod.idempotent("register")
        def view():
            calls.append(1)
            return {"ok": True}, 201

        with patch.object(idem_mod, "_db_available", return_value=False):
            result = view()
        self.assertEqual(result, ({"ok": True}, 201))
        self.assertEqual(calls, [1])

    def test_completed_replay_preserves_status(self) -> None:
        @idem_mod.idempotent("register")
        def view():
            raise AssertionError("handler must not run on replay")

        stored = {
            "status": "COMPLETED",
            "response_payload": {
                "status": 201,
                "body": {"ok": True, "created": True, "db_event": {"id": 7}},
            },
        }
        with patch.object(idem_mod, "_db_available", return_value=True), patch.object(
            idem_mod, "_canonical_digest", return_value="abc"
        ), patch.object(idem_mod, "get_idempotency_record", return_value=stored):
            # jsonify needs an app context
            from app import app

            with app.app_context():
                result = view()
        self.assertIsInstance(result, tuple)
        response, status = result
        self.assertEqual(status, 201)
        self.assertEqual(response.get_json()["db_event"]["id"], 7)

    def test_pending_returns_409(self) -> None:
        @idem_mod.idempotent("register")
        def view():
            raise AssertionError("handler must not run while pending")

        with patch.object(idem_mod, "_db_available", return_value=True), patch.object(
            idem_mod, "_canonical_digest", return_value="abc"
        ), patch.object(
            idem_mod, "get_idempotency_record", return_value={"status": "PENDING"}
        ):
            from app import app

            with app.app_context():
                result = view()
        response, status = result
        self.assertEqual(status, 409)
        self.assertIn("duplicate", response.get_json()["error"])

    def test_extract_preserves_201_from_tuple(self) -> None:
        from flask import jsonify
        from app import app

        with app.app_context():
            body, code = idem_mod._extract_response_parts((jsonify({"ok": True}), 201))
        self.assertEqual(code, 201)
        self.assertEqual(body, {"ok": True})


if __name__ == "__main__":
    unittest.main()


class TierIdempotencyBindingTest(unittest.TestCase):
    """Focused coverage for identity tier binding in registration idempotency."""

    def _make_flask_app(self):
        from flask import Flask, jsonify

        flask_app = Flask(__name__)
        jobs_enqueued: list[dict] = []

        @flask_app.post("/api/proofs/register")
        @idem_mod.idempotent("register")
        def register_view():
            from flask import request

            payload = request.get_json(silent=True) or {}
            jobs_enqueued.append(
                {"proof_id": payload.get("proofId"), "tier": payload.get("tier")}
            )
            return jsonify({"ok": True, "created": True, "tier": payload.get("tier")}), 201

        return flask_app, jobs_enqueued

    def test_canonical_digest_includes_identity_tier(self) -> None:
        from flask import Flask

        flask_app = Flask(__name__)
        body_silent = {"videoHash": "aa" * 32, "proofId": "bb" * 32, "tier": "silent"}
        body_seal = {"videoHash": "aa" * 32, "proofId": "bb" * 32, "tier": "seal"}

        with flask_app.test_request_context("/api/proofs/register", method="POST", json=body_silent):
            d_silent = idem_mod._canonical_digest()
        with flask_app.test_request_context("/api/proofs/register", method="POST", json=body_seal):
            d_seal = idem_mod._canonical_digest()

        self.assertNotEqual(d_silent, d_seal)

    def test_reused_registration_key_with_changed_tier_returns_409_without_new_job(self) -> None:
        flask_app, jobs_enqueued = self._make_flask_app()
        store: dict[tuple[str, str], dict] = {}
        next_id = [1]

        def fake_get(digest: str, request_type: str):
            return store.get((digest, request_type))

        def fake_create(digest: str, request_type: str, expires_at=None):
            key = (digest, request_type)
            if key in store:
                return store[key]["id"], store[key]["status"]
            rid = next_id[0]
            next_id[0] += 1
            store[key] = {"id": rid, "status": "PENDING", "response_payload": None}
            return rid, "PENDING"

        def fake_store_response(record_id: int, payload: dict):
            for rec in store.values():
                if rec["id"] == record_id:
                    rec["status"] = "COMPLETED"
                    rec["response_payload"] = payload

        base_payload = {"videoHash": "aa" * 32, "proofId": "bb" * 32, "tier": "silent"}
        changed_tier_payload = {"videoHash": "aa" * 32, "proofId": "bb" * 32, "tier": "seal"}

        with patch.object(idem_mod, "_db_available", return_value=True), patch.object(
            idem_mod, "get_idempotency_record", side_effect=fake_get
        ), patch.object(
            idem_mod, "create_idempotency_record", side_effect=fake_create
        ), patch.object(
            idem_mod, "store_response", side_effect=fake_store_response
        ):
            client = flask_app.test_client()

            # 1. First registration succeeds and creates one job.
            r1 = client.post(
                "/api/proofs/register",
                json=base_payload,
                headers={"Idempotency-Key": "reg-key-001"},
            )
            self.assertEqual(r1.status_code, 201)
            self.assertEqual(len(jobs_enqueued), 1)

            # 2. Exact retry with same key and same tier replays 201 without creating a new job.
            r2 = client.post(
                "/api/proofs/register",
                json=base_payload,
                headers={"Idempotency-Key": "reg-key-001"},
            )
            self.assertEqual(r2.status_code, 201)
            self.assertEqual(r2.get_json()["tier"], "silent")
            self.assertEqual(len(jobs_enqueued), 1)

            # 3. Reusing the same key with a changed tier returns 409 without creating a new job.
            r3 = client.post(
                "/api/proofs/register",
                json=changed_tier_payload,
                headers={"Idempotency-Key": "reg-key-001"},
            )
            self.assertEqual(r3.status_code, 409)
            self.assertEqual(r3.get_json()["conflict_field"], "tier")
            self.assertIn("conflict", r3.get_json()["error"])
            self.assertEqual(len(jobs_enqueued), 1)

    def test_boundary_reused_key_trimmed_header_and_missing_tier_conflicts(self) -> None:
        flask_app, jobs_enqueued = self._make_flask_app()
        store: dict[tuple[str, str], dict] = {}
        next_id = [1]

        def fake_get(digest: str, request_type: str):
            return store.get((digest, request_type))

        def fake_create(digest: str, request_type: str, expires_at=None):
            key = (digest, request_type)
            if key in store:
                return store[key]["id"], store[key]["status"]
            rid = next_id[0]
            next_id[0] += 1
            store[key] = {"id": rid, "status": "PENDING", "response_payload": None}
            return rid, "PENDING"

        def fake_store_response(record_id: int, payload: dict):
            for rec in store.values():
                if rec["id"] == record_id:
                    rec["status"] = "COMPLETED"
                    rec["response_payload"] = payload

        with patch.object(idem_mod, "_db_available", return_value=True), patch.object(
            idem_mod, "get_idempotency_record", side_effect=fake_get
        ), patch.object(
            idem_mod, "create_idempotency_record", side_effect=fake_create
        ), patch.object(
            idem_mod, "store_response", side_effect=fake_store_response
        ):
            client = flask_app.test_client()

            r1 = client.post(
                "/api/proofs/register",
                json={"videoHash": "aa" * 32, "proofId": "bb" * 32, "tier": "source"},
                headers={"Idempotency-Key": "  reg-key-002  "},
            )
            self.assertEqual(r1.status_code, 201)
            self.assertEqual(len(jobs_enqueued), 1)

            # Omitting tier on the same key must conflict on tier and not enqueue another job.
            r2 = client.post(
                "/api/proofs/register",
                json={"videoHash": "aa" * 32, "proofId": "bb" * 32},
                headers={"Idempotency-Key": "reg-key-002"},
            )
            self.assertEqual(r2.status_code, 409)
            self.assertEqual(r2.get_json()["conflict_field"], "tier")
            self.assertEqual(len(jobs_enqueued), 1)
