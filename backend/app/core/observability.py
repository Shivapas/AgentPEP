"""Prometheus metrics and OpenTelemetry tracing setup."""

from prometheus_client import Counter, Histogram, make_asgi_app
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from app.core.config import settings

# --- Prometheus Metrics ---

INTERCEPT_REQUESTS = Counter(
    "agentpep_intercept_requests_total",
    "Total intercept API requests",
    ["decision"],
)

INTERCEPT_LATENCY = Histogram(
    "agentpep_intercept_latency_seconds",
    "Intercept API evaluation latency",
    buckets=[0.001, 0.005, 0.01, 0.015, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)

POLICY_EVALUATIONS = Counter(
    "agentpep_policy_evaluations_total",
    "Total policy evaluations by result",
    ["result"],
)


def get_metrics_app():  # type: ignore[no-untyped-def]
    """Return a Prometheus ASGI app to mount at /metrics."""
    return make_asgi_app()


# --- OpenTelemetry Tracing ---


def setup_tracing(app):  # type: ignore[no-untyped-def]
    """Configure OpenTelemetry tracing for the FastAPI app."""
    resource = Resource.create(
        {
            "service.name": settings.app_name,
            "service.version": settings.app_version,
        }
    )

    provider = TracerProvider(resource=resource)

    if settings.otlp_endpoint:
        exporter = OTLPSpanExporter(endpoint=settings.otlp_endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(exporter))

    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app)

    return provider
