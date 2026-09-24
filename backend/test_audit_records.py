"""Focused tests for structured privacy-safe audit records (issue #284)."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from audit_records import (
    ALLOWED_ACTIONS,
    AUDIT_RECORD_SCHEMA_VERSION,
    OUTCOME_DENIED,
    OUTCOME_DEPENDENCY_FAILURE,
    OUTCOME_MALFORMED,
    OUTCOME_OK,
    OUTCOME_OVERSIZED,
    OUTCOME_UNSUPPORTED,
    AuditRecordError,
    action_from_route,
    build_audit_record,
    clear_audit_ring,
    outcome_from_http_status,
    recent_audit_records,
    record_audit,
    sanitize_audit_details,
)
from logging_utils import REDACTED_VALUE


class TestSanitizeAuditDetails(unittest.TestCase):
    def test_redacts_secrets_media_witness_keys(self):
        details = {
            "video": b"FAKE_MEDIA_BYTES",
            "credential_secret": "super-secret-value",
            "nullifier_secret": "n" * 32,
            "witness": {"assignment": [1, 2, 3]},
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\nABC\n-----END RSA PRIVATE KEY-----",
            "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.aa.bb",
            "route": "/api/proofs",
            "video_hash": "a" * 64,
        }
        cleaned = sanitize_audit_details(details)
        blob = json.dumps(cleaned)
        self.assertNotIn("super-secret-value", blob)
        self.assertNotIn("FAKE_MEDIA_BYTES", blob)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", blob)
        self.assertNotIn("Bearer eyJ", blob)
        self.assertEqual(cleaned["credential_secret"], REDACTED_VALUE)
        self.assertEqual(cleaned["witness"], REDACTED_VALUE)
        self.assertEqual(cleaned["video"], REDACTED_VALUE)
        self.assertEqual(cleaned["route"], "/api/proofs")
        self.assertEqual(cleaned["video_hash"], "a" * 64)

    def test_oversized_details_become_digest_stub(self):
        huge = {"note": "x" * 20_000}
        cleaned = sanitize_audit_details(huge)
        self.assertEqual(cleaned.get("_truncated"), "oversized")
        self.assertIn("_digest", cleaned)
        self.assertNotIn("xxxx", json.dumps(cleaned)[50:])  # stub, not full payload


class TestBuildAuditRecord(unittest.TestCase):
    def setUp(self):
        clear_audit_ring()

    def test_positive_build(self):
        record = build_audit_record(
            action="proof.register",
            outcome=OUTCOME_OK,
            request_id="req-1",
            resource_type="proof",
            resource_id="proof-abc",
            details={"tier": "silent_witness", "proof": "SHOULD_REDACT"},
        )
        self.assertEqual(record.schema_version, AUDIT_RECORD_SCHEMA_VERSION)
        self.assertEqual(record.action, "proof.register")
        self.assertEqual(record.details["proof"], REDACTED_VALUE)
        self.assertEqual(len(record.details_digest or ""), 64)

    def test_unsupported_action(self):
        with self.assertRaises(AuditRecordError) as ctx:
            build_audit_record(action="evil.exfiltrate")
        self.assertEqual(ctx.exception.code, OUTCOME_UNSUPPORTED)

    def test_malformed_action(self):
        with self.assertRaises(AuditRecordError) as ctx:
            build_audit_record(action="")
        self.assertEqual(ctx.exception.code, OUTCOME_MALFORMED)

    def test_oversized_sets_outcome(self):
        record = build_audit_record(
            action="http.request",
            details={"blob_note": "y" * 20_000},
        )
        self.assertEqual(record.outcome, OUTCOME_OVERSIZED)
        self.assertEqual(record.details.get("_truncated"), "oversized")


class TestRecordAudit(unittest.TestCase):
    def setUp(self):
        clear_audit_ring()

    def test_record_audit_never_raises_on_bad_action(self):
        payload = record_audit(action="not.allowed", persist=False)
        self.assertIn(payload["outcome"], {OUTCOME_UNSUPPORTED, OUTCOME_MALFORMED})
        self.assertEqual(payload["schema_version"], AUDIT_RECORD_SCHEMA_VERSION)

    def test_record_audit_soft_persist_failure(self):
        with patch("db.insert_audit_record", side_effect=RuntimeError("db down")):
            payload = record_audit(
                action="proof.verify",
                outcome=OUTCOME_OK,
                persist=True,
            )
        self.assertEqual(payload["action"], "proof.verify")
        recent = recent_audit_records(10)
        actions = [r["action"] for r in recent]
        self.assertIn("proof.verify", actions)
        self.assertIn("system.dependency_failure", actions)

    def test_ring_buffer_records(self):
        record_audit(action="media.embed", persist=False)
        record_audit(action="media.extract", persist=False)
        recent = recent_audit_records(5)
        self.assertGreaterEqual(len(recent), 2)
        self.assertTrue(all(r["action"] in ALLOWED_ACTIONS for r in recent))


class TestHttpMapping(unittest.TestCase):
    def test_outcome_from_status(self):
        self.assertEqual(outcome_from_http_status(200), OUTCOME_OK)
        self.assertEqual(outcome_from_http_status(401), OUTCOME_DENIED)
        self.assertEqual(outcome_from_http_status(413), OUTCOME_OVERSIZED)
        self.assertEqual(outcome_from_http_status(422), OUTCOME_MALFORMED)
        self.assertEqual(outcome_from_http_status(500), OUTCOME_DEPENDENCY_FAILURE)

    def test_action_from_route(self):
        self.assertEqual(action_from_route("POST", "/api/proofs/register"), "proof.register")
        self.assertEqual(action_from_route("POST", "/api/embed"), "media.embed")
        self.assertEqual(action_from_route("GET", "/api/audit-records"), "audit.query")


if __name__ == "__main__":
    unittest.main()
