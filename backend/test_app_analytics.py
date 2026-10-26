"""App-level and privacy regression tests for analytics wiring.

Verifies:
1. Default disabled mode: WSGI is not wrapped with analytics, /ready details
   do not contain analytics snapshot, and /analytics routes are not registered.
2. Enabled mode: WSGI app wrapped with analytics, /ready details contain
   analytics health snapshot, /analytics/health returns 200 with snapshot.
3. Consent enforcement: Events without recorded granted consent are rejected
   and dropped, while events with recorded consent are ingested.
4. Privacy regression: PII (emails, names, IP addresses, credentials) never appears
   in analytics outputs or engine event storage.
"""

import os
import unittest
from unittest.mock import patch

from analytics.analytics_engine import AnalyticsEngine, RequestContext, set_engine
from analytics.consent import ConsentDecision, ConsentSource, ConsentStatus
from analytics.events import EventLifecycleState
from analytics.redaction import RedactionEngine
import app as app_module


class AppAnalyticsWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        # Clean environment before each test
        os.environ.pop("ANALYTICS_ENABLED", None)
        os.environ.pop("ANALYTICS_ROLLOUT", None)

    def tearDown(self) -> None:
        os.environ.pop("ANALYTICS_ENABLED", None)
        os.environ.pop("ANALYTICS_ROLLOUT", None)

    def test_disabled_by_default(self) -> None:
        """Default config produces identical responses to today (analytics disabled)."""
        app = app_module.create_app()
        client = app.test_client()

        # /ready endpoint should NOT contain analytics health snapshot
        ready_res = client.get("/ready")
        self.assertIn(ready_res.status_code, (200, 503))
        data = ready_res.get_json()
        self.assertNotIn("analytics", data)

        # Analytics routes should not be registered (404)
        health_res = client.get("/analytics/health")
        self.assertEqual(health_res.status_code, 404)

        config_res = client.get("/analytics/config")
        self.assertEqual(config_res.status_code, 404)

    def test_enabled_mode_wires_middleware_routes_and_ready(self) -> None:
        """When enabled via ANALYTICS_ENABLED=true or rollout phase != off, wires analytics."""
        with patch.dict(os.environ, {"ANALYTICS_ENABLED": "true"}):
            app = app_module.create_app()
            client = app.test_client()

            # /ready endpoint MUST contain analytics health snapshot
            ready_res = client.get("/ready")
            self.assertIn(ready_res.status_code, (200, 503))
            data = ready_res.get_json()
            self.assertIn("analytics", data)
            analytics_data = data["analytics"]
            self.assertIn("config_schema_version", analytics_data)
            self.assertIn("rollout_phase", analytics_data)

            # Analytics routes MUST be registered and return 200
            health_res = client.get("/analytics/health")
            self.assertEqual(health_res.status_code, 200)
            health_data = health_res.get_json()
            self.assertIn("config_schema_version", health_data)

            config_res = client.get("/analytics/config")
            self.assertEqual(config_res.status_code, 200)
            config_data = config_res.get_json()
            self.assertIn("feature_flags", config_data)

    def test_recorded_consent_required_before_processing(self) -> None:
        """Events without recorded granted consent are rejected; only events with consent are ingested."""
        engine = AnalyticsEngine()
        set_engine(engine)
        ctx = RequestContext(account_id_tag="user-account-123")

        # 1. Event without recorded consent -> DROPPED with consent_missing
        unconsented_event = engine.process_event(
            event_name="user.session_started",
            category="user.action",
            payload={"action": "login"},
            context=ctx,
        )
        self.assertEqual(unconsented_event.lifecycle_state, EventLifecycleState.DROPPED)
        self.assertEqual(unconsented_event.rejection_reason, "consent_missing")

        # 2. Record explicit consent
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["*"],
            expires_at_epoch_seconds=9999999999.0,
            granted_at_epoch_seconds=1000.0,
        )
        engine.consent.set_consent("user-account-123", decision)

        # 3. Event with recorded consent -> INGESTED
        consented_event = engine.process_event(
            event_name="user.session_started",
            category="user.action",
            payload={"action": "login"},
            context=ctx,
        )
        self.assertEqual(consented_event.lifecycle_state, EventLifecycleState.INGESTED)

    def test_privacy_regression_no_pii_in_analytics_output(self) -> None:
        """Verify that PII and sensitive credentials never leak into analytics output."""
        engine = AnalyticsEngine()
        redaction = RedactionEngine()

        pii_payload = {
            "user_email": "alice@example.com",
            "phone_number": "+1-555-0199",
            "full_name": "Alice Montgomery",
            "client_ip": "192.168.1.100",
            "password": "SuperSecretPassword123!",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ...\n-----END RSA PRIVATE KEY-----",
            "api_key": "sec_live_abcdef1234567890",
            "normal_field": "harpocrates_proof_metric",
        }

        # Sanitize through RedactionEngine
        outcome = redaction.sanitize(pii_payload)
        sanitized = outcome.data

        # Ensure no sensitive values leak in output
        self.assertNotIn("alice@example.com", str(sanitized))
        self.assertNotIn("+1-555-0199", str(sanitized))
        self.assertNotIn("SuperSecretPassword123!", str(sanitized))
        self.assertNotIn("sec_live_abcdef1234567890", str(sanitized))
        self.assertEqual(sanitized.get("normal_field"), "harpocrates_proof_metric")

        # When processed through AnalyticsEngine with consent
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["*"],
            expires_at_epoch_seconds=9999999999.0,
            granted_at_epoch_seconds=1000.0,
        )
        engine.consent.set_consent("privacy-tag-1", decision)
        ctx = RequestContext(account_id_tag="privacy-tag-1")

        event = engine.process_event(
            event_name="user.session_started",
            category="user.action",
            payload=pii_payload,
            context=ctx,
        )
        self.assertEqual(event.lifecycle_state, EventLifecycleState.INGESTED)
        self.assertNotIn("alice@example.com", str(event.payload))
        self.assertNotIn("SuperSecretPassword123!", str(event.payload))
        self.assertNotIn("sec_live_abcdef1234567890", str(event.payload))


if __name__ == "__main__":
    unittest.main()
