"""Focused tests for OpenTelemetry context, links, and privacy boundaries."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.sampling import TraceIdRatioBased
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from tracing import (
    begin_request_span,
    finish_request_span,
    job_trace_context,
    traced_job,
    span,
    validate_otlp_endpoint,
    validate_sample_ratio,
)


class TracingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.exporter = InMemorySpanExporter()
        self.provider = TracerProvider(sampler=TraceIdRatioBased(1.0))
        self.provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.tracer = self.provider.get_tracer("test.tracing")

    def tearDown(self) -> None:
        self.provider.shutdown()

    def test_request_span_uses_valid_w3c_parent(self) -> None:
        request_span = begin_request_span(
            {
                "traceparent": (
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-"
                    "00f067aa0ba902b7-01"
                )
            },
            method="POST",
            route="/api/stego/embed",
            request_id="request-123",
            tracer=self.tracer,
        )
        finish_request_span(request_span, status_code=202)

        [finished] = self.exporter.get_finished_spans()
        self.assertEqual(finished.context.trace_id, int("4bf92f3577b34da6a3ce929d0e0e4736", 16))
        self.assertEqual(finished.parent.span_id, int("00f067aa0ba902b7", 16))
        self.assertEqual(finished.attributes["http.route"], "/api/stego/embed")
        self.assertEqual(finished.attributes["http.response.status_code"], 202)
        self.assertNotIn("http.url", finished.attributes)
        self.assertNotIn("harpocrates.request.id", finished.attributes)

    def test_flask_request_exports_privacy_bounded_server_span(self) -> None:
        import app as app_module

        application = app_module.create_app()
        application.config["TESTING"] = True
        client = application.test_client()

        with patch.object(
            app_module,
            "begin_request_span",
            side_effect=lambda headers, **kwargs: begin_request_span(
                headers, **kwargs, tracer=self.tracer
            ),
        ):
            response = client.get(
                "/health?credentialSecret=not-for-export",
                headers={"X-Request-ID": "credentialSecret"},
            )

        self.assertEqual(response.status_code, 200)
        [finished] = self.exporter.get_finished_spans()
        self.assertEqual(finished.name, "HTTP GET /health")
        self.assertNotIn("http.url", finished.attributes)
        self.assertNotIn("url.query", finished.attributes)
        self.assertNotIn("harpocrates.request.id", finished.attributes)
        self.assertNotIn("credentialSecret", repr(finished))
        self.assertNotIn("not-for-export", repr(finished))

    def test_invalid_traceparent_is_not_trusted(self) -> None:
        request_span = begin_request_span(
            {"traceparent": "00-" + "0" * 32 + "-" + "b" * 16 + "-01"},
            method="GET",
            route="/health",
            request_id="request-456",
            tracer=self.tracer,
        )
        finish_request_span(request_span, status_code=200)

        [finished] = self.exporter.get_finished_spans()
        self.assertNotEqual(finished.context.trace_id, 0)
        self.assertIsNone(finished.parent)

    def test_worker_span_links_to_request_without_parenting_to_it(self) -> None:
        with span("request.operation", tracer=self.tracer):
            trace_context = job_trace_context()
        self.assertEqual(set(trace_context), {"traceparent"})

        @traced_job("job.proof.noir", tracer=self.tracer)
        def execute(job):
            return job["payload"]["marker"]

        self.assertEqual(
            execute(
                {
                    "_trace_context": trace_context,
                    "payload": {"marker": "done", "credential_secret": "must-not-be-copied"},
                }
            ),
            "done",
        )

        request_span, worker_span = self.exporter.get_finished_spans()
        self.assertIsNone(worker_span.parent)
        self.assertEqual(len(worker_span.links), 1)
        self.assertEqual(worker_span.links[0].context.trace_id, request_span.context.trace_id)
        self.assertEqual(worker_span.links[0].context.span_id, request_span.context.span_id)
        self.assertNotIn("credential_secret", worker_span.attributes)

    def test_enqueue_keeps_trace_context_outside_job_payload(self) -> None:
        import db

        payload = {"credential_secret": "secret-value", "video_hash": "evidence-hash"}
        with span("request.register", tracer=self.tracer):
            job_id = db.enqueue_job("verify_tx", payload)

        job = db.get_job(job_id)
        self.assertEqual(job["payload"], payload)
        self.assertEqual(set(job["_trace_context"]), {"traceparent"})
        self.assertNotIn("credential_secret", job["_trace_context"])
        self.assertNotIn("video_hash", job["_trace_context"])

    def test_exception_messages_are_not_recorded(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "credentialSecret=secret-value"):
            with span("proof.noir.generate", tracer=self.tracer):
                raise RuntimeError("credentialSecret=secret-value")

        [finished] = self.exporter.get_finished_spans()
        self.assertEqual(finished.attributes["error.type"], "RuntimeError")
        self.assertEqual(finished.events, ())
        self.assertNotIn("secret-value", repr(finished))

    def test_exporter_configuration_is_bounded(self) -> None:
        self.assertEqual(
            validate_otlp_endpoint("https://collector.example/v1/traces"),
            "https://collector.example/v1/traces",
        )
        self.assertEqual(validate_sample_ratio(0.25), 0.25)
        with self.assertRaises(ValueError):
            validate_otlp_endpoint("https://user:password@collector.example/v1/traces")
        with self.assertRaises(ValueError):
            validate_sample_ratio(1.1)
        with self.assertRaises(ValueError):
            validate_sample_ratio(float("nan"))


if __name__ == "__main__":
    unittest.main()
