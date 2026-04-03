"""Prometheus metrics, OpenTelemetry tracing, and structured logging setup (Sprint 26)."""

from prometheus_client import Counter, Gauge, Histogram, make_asgi_app
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from app.core.config import settings

# --- Prometheus Metrics ---

# Legacy counters (kept for backward compatibility)
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

# --- Sprint 26 (APEP-204): Enhanced Prometheus Metrics ---

DECISION_TOTAL = Counter(
    "agentpep_decision_total",
    "Total policy decisions broken down by decision outcome, agent, and tool",
    ["decision", "agent_id", "tool_name"],
)

DECISION_LATENCY = Histogram(
    "agentpep_decision_latency_seconds",
    "Policy decision latency histograms by agent and tool",
    ["agent_id", "tool_name"],
    buckets=[0.001, 0.005, 0.01, 0.015, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 1.0],
)

TAINT_EVENT_TOTAL = Counter(
    "agentpep_taint_event_total",
    "Total taint lifecycle events by event type",
    ["event_type"],
)

ESCALATION_BACKLOG = Gauge(
    "agentpep_escalation_backlog",
    "Number of pending escalation decisions awaiting human review",
)

SECURITY_ALERT_TOTAL = Counter(
    "agentpep_security_alert_total",
    "Total security alerts by alert type and severity",
    ["alert_type", "severity"],
)

AUDIT_WRITE_TOTAL = Counter(
    "agentpep_audit_write_total",
    "Total audit log write operations",
    ["status"],
)

AUDIT_WRITE_LATENCY = Histogram(
    "agentpep_audit_write_latency_seconds",
    "Latency of audit log writes to MongoDB",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5],
)


def get_metrics_app():  # type: ignore[no-untyped-def]
    """Return a Prometheus ASGI app to mount at /metrics."""
    return make_asgi_app()


# --- OpenTelemetry Tracing ---

_tracer_provider: TracerProvider | None = None


def setup_tracing(app):  # type: ignore[no-untyped-def]
    """Configure OpenTelemetry tracing for the FastAPI app."""
    global _tracer_provider

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
    _tracer_provider = provider
    FastAPIInstrumentor.instrument_app(app)

    return provider


def get_tracer(name: str) -> trace.Tracer:
    """Get a named tracer from the global TracerProvider."""
    return trace.get_tracer(name, settings.app_version)
