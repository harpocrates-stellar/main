"""Privacy-bounded OpenTelemetry tracing for the backend."""

from __future__ import annotations

import math
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Iterator, Mapping, TypeVar
from urllib.parse import urlparse

from opentelemetry import context as otel_context
from opentelemetry import propagate, trace
from opentelemetry.context import Context, Token
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.sampling import TraceIdRatioBased
from opentelemetry.trace import Link, Span, Status, StatusCode, Tracer
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

from trace_fields import parse_traceparent

DEFAULT_OTLP_BATCH_SIZE = 256
DEFAULT_OTLP_QUEUE_SIZE = 2048

_provider: TracerProvider | None = None
_provider_config: tuple[str, str, float, float] | None = None
T = TypeVar("T", bound=Callable[..., Any])


@dataclass
class RequestSpan:
    span: Span
    token: Token[Context]
    finished: bool = False


def validate_otlp_endpoint(endpoint: str) -> str:
    """Accept only plain HTTP(S) collector endpoints without embedded credentials."""
    parsed = urlparse(endpoint.strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT must be an HTTP(S) URL without credentials")
    return endpoint.strip()


def validate_sample_ratio(value: float) -> float:
    ratio = float(value)
    if not math.isfinite(ratio) or ratio < 0.0 or ratio > 1.0:
        raise ValueError("OTEL_TRACES_SAMPLER_ARG must be between 0 and 1")
    return ratio


def configure_tracing(
    *,
    enabled: bool,
    service_name: str,
    endpoint: str | None,
    sample_ratio: float,
    export_timeout_seconds: float,
    service_version: str,
) -> bool:
    """Configure one bounded OTLP provider for this process; safe to call per app."""
    global _provider, _provider_config
    if not enabled:
        return False
    if not service_name or len(service_name) > 128:
        raise ValueError("OTEL_SERVICE_NAME must contain 1 to 128 characters")
    if endpoint is None:
        raise ValueError("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is required when tracing is enabled")
    safe_endpoint = validate_otlp_endpoint(endpoint)
    ratio = validate_sample_ratio(sample_ratio)
    timeout = float(export_timeout_seconds)
    if not math.isfinite(timeout) or timeout <= 0.0 or timeout > 60.0:
        raise ValueError("OTEL_EXPORT_TIMEOUT_SECONDS must be greater than 0 and at most 60")

    configuration = (service_name, safe_endpoint, ratio, timeout)
    if _provider is not None:
        if _provider_config != configuration:
            raise RuntimeError("OpenTelemetry provider was already configured differently")
        return True

    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": service_name,
                "service.version": service_version,
            }
        ),
        sampler=TraceIdRatioBased(ratio),
    )
    exporter = OTLPSpanExporter(endpoint=safe_endpoint, timeout=timeout)
    provider.add_span_processor(
        BatchSpanProcessor(
            exporter,
            max_queue_size=DEFAULT_OTLP_QUEUE_SIZE,
            max_export_batch_size=DEFAULT_OTLP_BATCH_SIZE,
            export_timeout_millis=int(timeout * 1000),
        )
    )
    trace.set_tracer_provider(provider)
    _provider = provider
    _provider_config = configuration
    return True


def begin_request_span(
    headers: Mapping[str, Any],
    *,
    method: str,
    route: str,
    request_id: str,
    tracer: Tracer | None = None,
) -> RequestSpan:
    """Start a server span, accepting only a valid W3C traceparent as its parent."""
    raw_parent = headers.get("traceparent")
    parent = parse_traceparent(raw_parent)
    parent_context = (
        propagate.extract({"traceparent": raw_parent}) if parent is not None else Context()
    )
    span = (tracer or trace.get_tracer("harpocrates.backend")).start_span(
        f"HTTP {method.upper()} {route}",
        context=parent_context,
        attributes={
            "http.request.method": method.upper(),
            "http.route": route,
        },
    )
    token = otel_context.attach(trace.set_span_in_context(span, parent_context))
    return RequestSpan(span=span, token=token)


def finish_request_span(
    request_span: RequestSpan | None,
    *,
    status_code: int,
    error: BaseException | None = None,
) -> None:
    """End a request span once, recording only bounded status/type information."""
    if request_span is None or request_span.finished:
        return
    request_span.finished = True
    span = request_span.span
    span.set_attribute("http.response.status_code", int(status_code))
    if error is not None:
        span.set_attribute("error.type", type(error).__name__[:64])
    if status_code >= 500 or error is not None:
        span.set_status(Status(StatusCode.ERROR))
    otel_context.detach(request_span.token)
    span.end()


def current_traceparent() -> str | None:
    """Serialize the active span context for an internal asynchronous handoff."""
    span_context = trace.get_current_span().get_span_context()
    if not span_context.is_valid:
        return None
    return (
        f"00-{span_context.trace_id:032x}-{span_context.span_id:016x}-"
        f"{int(span_context.trace_flags):02x}"
    )


@contextmanager
def span(
    name: str,
    *,
    attributes: Mapping[str, Any] | None = None,
    links: tuple[Link, ...] | list[Link] = (),
    tracer: Tracer | None = None,
) -> Iterator[Span]:
    """Create a child span without recording exception messages or stack traces."""
    with (tracer or trace.get_tracer("harpocrates.backend")).start_as_current_span(
        name,
        attributes=dict(attributes or {}),
        links=list(links),
        record_exception=False,
        set_status_on_exception=False,
    ) as active_span:
        try:
            yield active_span
        except Exception as exc:
            active_span.set_attribute("error.type", type(exc).__name__[:64])
            active_span.set_status(Status(StatusCode.ERROR))
            raise


def linked_span(
    name: str,
    trace_context: object,
    *,
    attributes: Mapping[str, Any] | None = None,
    tracer: Tracer | None = None,
) -> AbstractContextManager[Span]:
    """Create a new root span linked to the valid parent carried by a queued job."""
    parent = None
    if isinstance(trace_context, Mapping):
        candidate = parse_traceparent(trace_context.get("traceparent"))
        if candidate is not None:
            from opentelemetry.trace import SpanContext, TraceFlags, TraceState

            parent = SpanContext(
                trace_id=int(candidate["trace_id"], 16),
                span_id=int(candidate["span_id"], 16),
                is_remote=True,
                trace_flags=TraceFlags(int(candidate["trace_flags"], 16)),
                trace_state=TraceState(),
            )
    links = [Link(parent)] if parent is not None else []
    return _linked_span_context(name, links, attributes, tracer)


@contextmanager
def _linked_span_context(
    name: str,
    links: list[Link],
    attributes: Mapping[str, Any] | None,
    tracer: Tracer | None,
) -> Iterator[Span]:
    with span(name, attributes=attributes, links=links, tracer=tracer) as active_span:
        yield active_span


def traced(name: str, *, attributes: Mapping[str, Any] | None = None) -> Callable[[T], T]:
    """Decorate a bounded operation with a semantic span."""
    def decorate(function: T) -> T:
        @wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            with span(name, attributes=attributes):
                return function(*args, **kwargs)

        return wrapped  # type: ignore[return-value]

    return decorate


def traced_job(name: str, *, tracer: Tracer | None = None) -> Callable[[T], T]:
    """Decorate a worker operation using a span link from its queued trace context."""
    def decorate(function: T) -> T:
        @wraps(function)
        def wrapped(job: Mapping[str, Any], *args: Any, **kwargs: Any) -> Any:
            with linked_span(
                name,
                job.get("_trace_context"),
                attributes={"harpocrates.job.type": name.rsplit(".", 1)[-1]},
                tracer=tracer,
            ):
                return function(job, *args, **kwargs)

        return wrapped  # type: ignore[return-value]

    return decorate


def job_trace_context() -> dict[str, str] | None:
    """Return the minimal W3C context allowed in internal queued-job metadata."""
    traceparent = current_traceparent()
    return {"traceparent": traceparent} if traceparent is not None else None


def shutdown_tracing() -> None:
    """Flush and shut down the configured exporter with a strict time bound."""
    provider = _provider
    if provider is not None:
        provider.shutdown()
