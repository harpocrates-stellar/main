"""Unit tests for privacy-safe backend trace fields."""

from __future__ import annotations

import json
import unittest

from trace_fields import (
    TRACE_FIELDS_SCHEMA_VERSION,
    assert_trace_fields_privacy_safe,
    build_trace_fields,
    format_traceparent,
    merge_trace_into_event,
    normalize_opaque_id,
    parse_traceparent,
    sanitize_endpoint_pattern,
    versioned_domain_tag,
)


class NormalizeOpaqueIdTests(unittest.TestCase):
    def test_accepts_simple_ids(self) -> None:
        self.assertEqual(normalize_opaque_id("req-abc_123"), "req-abc_123")
        self.assertEqual(normalize_opaque_id("  corr:1  "), "corr:1")

    def test_rejects_empty_oversized_and_secret_shaped(self) -> None:
        self.assertIsNone(normalize_opaque_id(""))
        self.assertIsNone(normalize_opaque_id(None))
        self.assertIsNone(normalize_opaque_id("x" * 200))
        self.assertIsNone(normalize_opaque_id("eyJhbGciOiJIUzI1NiJ9.payload.sig"))
        self.assertIsNone(normalize_opaque_id("-----BEGIN PRIVATE KEY-----"))
        self.assertIsNone(normalize_opaque_id("has space"))


class TraceparentTests(unittest.TestCase):
    def test_parses_valid_traceparent(self) -> None:
        parsed = parse_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        )
        self.assertEqual(parsed["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(parsed["span_id"], "00f067aa0ba902b7")
        self.assertEqual(parsed["trace_flags"], "01")

    def test_rejects_malformed_unsupported_and_zero_ids(self) -> None:
        self.assertIsNone(parse_traceparent(""))
        self.assertIsNone(parse_traceparent("01-" + "a" * 32 + "-" + "b" * 16 + "-01"))
        self.assertIsNone(parse_traceparent("00-" + "0" * 32 + "-" + "b" * 16 + "-01"))
        self.assertIsNone(parse_traceparent("not-a-traceparent"))
        self.assertIsNone(parse_traceparent("00-short-00f067aa0ba902b7-01"))


class SanitizeEndpointTests(unittest.TestCase):
    def test_replaces_identifier_segments(self) -> None:
        self.assertEqual(
            sanitize_endpoint_pattern(
                "/api/schemas/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            "/api/schemas/{id}",
        )
        self.assertEqual(
            sanitize_endpoint_pattern("/api/workspace/1234567/status"),
            "/api/workspace/{id}/status",
        )
        self.assertEqual(sanitize_endpoint_pattern("/health"), "/health")


class BuildTraceFieldsTests(unittest.TestCase):
    def test_builds_from_request_id_when_no_trace_headers(self) -> None:
        fields = build_trace_fields(
            {},
            request_id="req-test-1",
            method="GET",
            route="/health",
            path="/health",
        )
        self.assertEqual(fields["trace_schema"], TRACE_FIELDS_SCHEMA_VERSION)
        self.assertEqual(fields["request_id"], "req-test-1")
        self.assertEqual(fields["correlation_id"], "req-test-1")
        self.assertEqual(len(fields["trace_id"]), 32)
        self.assertEqual(len(fields["span_id"]), 16)
        self.assertEqual(fields["endpoint_pattern"], "/health")
        self.assertEqual(fields["request_id_tag"], versioned_domain_tag("req-test-1"))
        assert_trace_fields_privacy_safe(fields)

    def test_inherits_w3c_traceparent_and_creates_child_span(self) -> None:
        headers = {
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "X-Correlation-ID": "corr-99",
        }
        fields = build_trace_fields(
            headers,
            request_id="req-from-header",
            method="POST",
            route="/api/stego/embed",
            path="/api/stego/embed",
        )
        self.assertEqual(fields["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(fields["parent_span_id"], "00f067aa0ba902b7")
        self.assertNotEqual(fields["span_id"], "00f067aa0ba902b7")
        self.assertEqual(fields["correlation_id"], "corr-99")
        tp = format_traceparent(fields)
        self.assertTrue(tp.startswith("00-4bf92f3577b34da6a3ce929d0e0e4736-"))
        assert_trace_fields_privacy_safe(fields)

    def test_ignores_oversized_and_jwt_shaped_headers(self) -> None:
        headers = {
            "X-Trace-ID": "x" * 300,
            "X-Correlation-ID": "eyJhbGciOiJIUzI1NiJ9.abc.def",
        }
        fields = build_trace_fields(headers, request_id="fallback-id", path="/health")
        self.assertEqual(fields["request_id"], "fallback-id")
        self.assertEqual(fields["correlation_id"], "fallback-id")
        self.assertEqual(len(fields["trace_id"]), 32)

    def test_merge_drops_identifier_bearing_path(self) -> None:
        trace = build_trace_fields(
            {},
            request_id="r1",
            path="/api/schemas/" + ("ab" * 32),
            route="/api/schemas/<schema_hash>",
        )
        event = merge_trace_into_event(
            {"event": "request", "path": "/api/schemas/" + ("ab" * 32), "status": 200},
            trace,
        )
        self.assertEqual(event["event"], "request")
        self.assertEqual(event["request_id"], "r1")
        self.assertIn("trace_id", event)
        self.assertIn("endpoint_pattern", event)
        self.assertNotIn("path", event)
        assert_trace_fields_privacy_safe(
            {k: v for k, v in event.items() if k not in {"event", "status"}}
        )

    def test_merge_preserves_safe_path_when_equal_to_pattern(self) -> None:
        trace = build_trace_fields({}, request_id="r2", path="/health", route="/health")
        event = merge_trace_into_event(
            {"event": "request", "path": "/health", "status": 200},
            trace,
        )
        self.assertEqual(event["path"], "/health")


class TraceFieldsFlaskIntegrationTests(unittest.TestCase):
    """Exercise create_app wiring without network or real media."""

    def setUp(self) -> None:
        import app as app_module

        self.app_module = app_module
        self.app = app_module.create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_response_echoes_privacy_safe_trace_headers(self) -> None:
        response = self.client.get(
            "/health",
            headers={
                "X-Request-ID": "req-trace-1",
                "X-Correlation-ID": "corr-trace-1",
                "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Request-ID"], "req-trace-1")
        self.assertEqual(response.headers["X-Correlation-ID"], "corr-trace-1")
        self.assertEqual(
            response.headers["X-Trace-ID"], "4bf92f3577b34da6a3ce929d0e0e4736"
        )
        self.assertTrue(response.headers["traceparent"].startswith(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-"
        ))
        body = response.get_json()
        self.assertEqual(body["request_id"], "req-trace-1")
        self.assertIn("trace_id", body)
        self.assertEqual(body["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736")

    def test_request_log_includes_privacy_safe_trace_fields(self) -> None:
        with self.assertLogs("harpocrates.requests", level="INFO") as logs:
            response = self.client.get(
                "/health",
                headers={
                    "X-Request-ID": "req-test-1",
                    "X-Correlation-ID": "corr-77",
                },
            )
        self.assertEqual(response.status_code, 200)
        event = json.loads(logs.output[0].split(":", 2)[2])
        self.assertEqual(event["event"], "request")
        self.assertEqual(event["request_id"], "req-test-1")
        self.assertEqual(event["correlation_id"], "corr-77")
        self.assertEqual(event["trace_schema"], TRACE_FIELDS_SCHEMA_VERSION)
        self.assertIn("trace_id", event)
        self.assertIn("span_id", event)
        self.assertIn("endpoint_pattern", event)
        self.assertNotIn("authorization", event)
        self.assertNotIn("proof", event)
        # Ensure secrets were not smuggled into the log payload.
        dumped = json.dumps(event)
        self.assertNotIn("credentialSecret", dumped)
        self.assertNotIn("nullifierSecret", dumped)


if __name__ == "__main__":
    unittest.main()
