"""Prometheus metrics, OpenTelemetry tracing, and structured logging setup (Sprint 26)."""

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import Counter, Gauge, Histogram, make_asgi_app

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


# Sprint 23 — Performance metrics (APEP-180/183/184/186)

RULE_CACHE_HITS = Counter(
    "agentpep_rule_cache_hits_total",
    "Rule cache hit count by tier",
    ["tier"],  # l1, l2_redis, miss
)

AUDIT_LOG_QUEUE_SIZE = Histogram(
    "agentpep_audit_log_queue_size",
    "Async audit log queue depth at flush time",
    buckets=[1, 5, 10, 25, 50, 100, 250, 500],
)

TAINT_GRAPH_EVICTIONS = Counter(
    "agentpep_taint_graph_evictions_total",
    "Taint graph LRU node evictions",
)

RISK_SCORE_HISTOGRAM = Histogram(
    "agentpep_risk_score",
    "Computed risk scores for intercept decisions",
    buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
)

ADAPTIVE_TIMEOUT = Histogram(
    "agentpep_adaptive_timeout_seconds",
    "Adaptive timeout value selected per request",
    buckets=[1.0, 2.0, 3.0, 5.0, 10.0],
)


# --- Sprint 36 (APEP-291): New capability metrics ---

TRUST_DEGRADATION_EVENTS = Counter(
    "agentpep_trust_degradation_events_total",
    "Total trust degradation events by reason and session lock status",
    ["reason", "locked"],
)

HASH_CHAIN_VERIFICATIONS = Counter(
    "agentpep_hash_chain_verifications_total",
    "Total hash chain verification attempts by result",
    ["result"],  # valid, tampered
)

HASH_CHAIN_ENTRIES = Counter(
    "agentpep_hash_chain_entries_total",
    "Total hash chain entries appended",
)

DEFER_DECISIONS = Counter(
    "agentpep_defer_decisions_total",
    "Total DEFER decisions by condition and resolution",
    ["condition", "resolution"],
)

STEP_UP_CHALLENGES = Counter(
    "agentpep_step_up_challenges_total",
    "Total STEP_UP challenges by status",
    ["status"],  # PENDING, VERIFIED, FAILED, EXPIRED
)

POLICY_CONFLICTS_DETECTED = Counter(
    "agentpep_policy_conflicts_detected_total",
    "Total policy conflicts detected by severity",
    ["severity"],
)

TENANT_ISOLATION_VIOLATIONS = Counter(
    "agentpep_tenant_isolation_violations_total",
    "Total tenant isolation violations",
    ["source_tenant", "resource_type"],
)

TRUST_CEILING_HISTOGRAM = Histogram(
    "agentpep_trust_ceiling",
    "Current trust ceiling distribution across sessions",
    buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
)

CONFLICT_SCAN_DURATION = Histogram(
    "agentpep_conflict_scan_duration_seconds",
    "Duration of policy conflict scans",
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)


# --- Sprint 45 (APEP-360): DLP Pre-Scan Metrics ---

DLP_SCAN_TOTAL = Counter(
    "agentpep_dlp_scan_total",
    "Total DLP pre-scan operations by result and pattern type",
    ["result", "pattern_type"],  # result: hit, miss, error; pattern_type: API_KEY, TOKEN, etc.
)

DLP_SCAN_LATENCY = Histogram(
    "agentpep_dlp_scan_latency_seconds",
    "DLP pre-scan latency in seconds",
    buckets=[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5],
)

DLP_FINDINGS_TOTAL = Counter(
    "agentpep_dlp_findings_total",
    "Total DLP findings by severity and pattern type",
    ["severity", "pattern_type"],
)

DLP_CACHE_HITS = Counter(
    "agentpep_dlp_cache_hits_total",
    "DLP pre-scan cache hit/miss count",
    ["result"],  # hit, miss
)

DLP_RISK_ELEVATIONS = Counter(
    "agentpep_dlp_risk_elevations_total",
    "Total risk score elevations triggered by DLP findings",
)

DLP_TAINT_ASSIGNMENTS = Counter(
    "agentpep_dlp_taint_assignments_total",
    "Total taint assignments triggered by DLP findings",
    ["taint_level"],  # QUARANTINE, UNTRUSTED
)

DLP_PATTERN_RELOADS = Counter(
    "agentpep_dlp_pattern_reloads_total",
    "Total DLP pattern hot-reload operations",
    ["status"],  # success, error
)

# --- Sprint 46 (APEP-364..371): Fetch Proxy & Response Injection Scanner ---

FETCH_PROXY_REQUESTS = Counter(
    "agentpep_fetch_proxy_requests_total",
    "Total fetch proxy requests by status",
    ["status"],  # ALLOWED, BLOCKED, QUARANTINED, SANITIZED
)

FETCH_PROXY_LATENCY = Histogram(
    "agentpep_fetch_proxy_latency_seconds",
    "Fetch proxy request latency",
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
)

RESPONSE_INJECTION_DETECTIONS = Counter(
    "agentpep_response_injection_detections_total",
    "Total response injection detections by severity",
    ["severity"],
)

RESPONSE_NORMALIZER_CHANGES = Counter(
    "agentpep_response_normalizer_changes_total",
    "Total character changes by normalization pass",
    ["pass_name"],
)

RESPONSE_DLP_HITS = Counter(
    "agentpep_response_dlp_hits_total",
    "Total DLP hits on fetched response bodies",
)

FETCH_AUTO_TAINT = Counter(
    "agentpep_fetch_auto_taint_total",
    "Total auto-taint assignments from fetch proxy",
    ["taint_level"],
)


# --- Sprint 49 (APEP-394): Chain Detection Metrics ---

CHAIN_DETECTION_TOTAL = Counter(
    "agentpep_chain_detection_total",
    "Total chain detection scans by result",
    ["result"],  # detected, clean
)

CHAIN_DETECTION_LATENCY = Histogram(
    "agentpep_chain_detection_latency_seconds",
    "Chain detection scan latency",
    buckets=[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5],
)

CHAIN_MATCHES_TOTAL = Counter(
    "agentpep_chain_matches_total",
    "Total chain pattern matches by category and severity",
    ["category", "severity"],
)

CHAIN_ESCALATIONS_TOTAL = Counter(
    "agentpep_chain_escalations_total",
    "Total chain detection escalations by priority",
    ["priority"],
)

CHAIN_ACTIONS_TOTAL = Counter(
    "agentpep_chain_actions_total",
    "Total chain detection actions taken",
    ["action"],  # ALERT, ESCALATE, DENY, LOG_ONLY
)

CHAIN_PATTERNS_ACTIVE = Gauge(
    "agentpep_chain_patterns_active",
    "Number of active chain detection patterns",
)


# --- Sprint 51 (APEP-410): TFN Prometheus Metrics ---

TFN_NETWORK_EVENTS_TOTAL = Counter(
    "agentpep_tfn_network_events_total",
    "Total TFN network events by event type and severity",
    ["event_type", "severity"],
)

TFN_BUNDLE_LOADS_TOTAL = Counter(
    "agentpep_tfn_bundle_loads_total",
    "Total rule bundle load operations by status",
    ["status"],  # success, failed, invalid_signature
)

TFN_BUNDLE_RULES_ACTIVE = Gauge(
    "agentpep_tfn_bundle_rules_active",
    "Number of active rules from loaded bundles",
)

TFN_BUNDLES_ACTIVE = Gauge(
    "agentpep_tfn_bundles_active",
    "Number of active rule bundles",
)

TFN_ASSESSMENT_TOTAL = Counter(
    "agentpep_tfn_assessment_total",
    "Total security assessment runs",
    ["grade"],
)

TFN_ASSESSMENT_SCORE = Histogram(
    "agentpep_tfn_assessment_score",
    "Security assessment overall score distribution",
    buckets=[0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
)

TFN_ASSESSMENT_LATENCY = Histogram(
    "agentpep_tfn_assessment_latency_seconds",
    "Security assessment execution latency",
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

TFN_ASSESSMENT_FINDINGS = Counter(
    "agentpep_tfn_assessment_findings_total",
    "Total security assessment findings by category and severity",
    ["category", "severity"],
)

TFN_MITRE_TAGS_TOTAL = Counter(
    "agentpep_tfn_mitre_tags_total",
    "Total MITRE ATT&CK technique tags applied to events",
    ["technique_id"],
)

TFN_KILL_SWITCH_ACTIVATIONS = Counter(
    "agentpep_tfn_kill_switch_activations_total",
    "Total kill switch activations by source",
    ["source"],
)

TFN_SENTINEL_FINDINGS_TOTAL = Counter(
    "agentpep_tfn_sentinel_findings_total",
    "Total filesystem sentinel findings by event type and severity",
    ["event_type", "severity"],
)

TFN_THREAT_SCORE_HISTOGRAM = Histogram(
    "agentpep_tfn_threat_score",
    "Adaptive threat score distribution across sessions",
    buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
)

TFN_URL_SCAN_TOTAL = Counter(
    "agentpep_tfn_url_scan_total",
    "Total URL scans by result",
    ["result"],  # allowed, blocked
)

TFN_URL_SCAN_LATENCY = Histogram(
    "agentpep_tfn_url_scan_latency_seconds",
    "URL scan latency (11-layer pipeline)",
    buckets=[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5],
)


# --- Sprint 53 (APEP-427): ONNX Semantic Classifier Metrics ---

ONNX_INFERENCE_TOTAL = Counter(
    "agentpep_onnx_inference_total",
    "Total ONNX semantic classifier inference calls by verdict",
    ["verdict"],  # CLEAN, SUSPICIOUS, MALICIOUS
)

ONNX_INFERENCE_LATENCY = Histogram(
    "agentpep_onnx_inference_latency_seconds",
    "ONNX semantic classifier per-sample inference latency",
    buckets=[0.001, 0.005, 0.01, 0.016, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)

ONNX_FALLBACK_TOTAL = Counter(
    "agentpep_onnx_fallback_total",
    "Total ONNX fallback invocations (model unavailable)",
)

ONNX_MODEL_STATUS = Gauge(
    "agentpep_onnx_model_status",
    "ONNX model readiness (1=READY, 0=NOT_READY)",
)

ONNX_BATCH_TOTAL = Counter(
    "agentpep_onnx_batch_total",
    "Total ONNX batch inference jobs by status",
    ["status"],  # COMPLETED, FAILED
)

ONNX_BATCH_LATENCY = Histogram(
    "agentpep_onnx_batch_latency_seconds",
    "ONNX batch inference total latency",
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

ONNX_BATCH_SIZE = Histogram(
    "agentpep_onnx_batch_size",
    "Number of texts per batch inference request",
    buckets=[1, 5, 10, 25, 50, 100, 250, 500],
)

ONNX_CHUNKS_PER_INPUT = Histogram(
    "agentpep_onnx_chunks_per_input",
    "Number of text chunks per classification input",
    buckets=[1, 2, 3, 4, 5, 10, 20],
)

ONNX_SCORE_HISTOGRAM = Histogram(
    "agentpep_onnx_score",
    "ONNX injection probability score distribution",
    buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
)

ONNX_BENCHMARK_F1 = Gauge(
    "agentpep_onnx_benchmark_f1",
    "Latest ONNX benchmark F1 score by dataset and scan mode",
    ["dataset", "scan_mode"],
)

# --- Sprint 54 (APEP-428/430/431/432): CIS Scanner Metrics ---

CIS_REPO_SCAN_TOTAL = Counter(
    "agentpep_cis_repo_scan_total",
    "Total pre-session repository scans by verdict",
    ["verdict"],  # CLEAN, SUSPICIOUS, MALICIOUS
)

CIS_REPO_SCAN_LATENCY = Histogram(
    "agentpep_cis_repo_scan_latency_seconds",
    "Pre-session repository scan latency",
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

CIS_FILE_SCAN_TOTAL = Counter(
    "agentpep_cis_file_scan_total",
    "Total individual file scans by verdict and instruction-file status",
    ["verdict", "is_instruction"],
)

CIS_SESSION_SCAN_TOTAL = Counter(
    "agentpep_cis_session_scan_total",
    "Total scan-on-session-start invocations by allowed status",
    ["session_allowed"],
)

CIS_POST_TOOL_SCAN_TOTAL = Counter(
    "agentpep_cis_post_tool_scan_total",
    "Total PostToolUse auto-scans by verdict and escalation status",
    ["verdict", "escalated"],
)

CIS_INSTRUCTION_FILE_TOTAL = Counter(
    "agentpep_cis_instruction_file_total",
    "Total agent instruction files detected by type",
    ["file_type"],  # CLAUDE.md, .cursorrules, AGENTS.md, etc.
)

CIS_FINDINGS_TOTAL = Counter(
    "agentpep_cis_findings_total",
    "Total CIS findings by severity and scanner",
    ["severity", "scanner"],
)

# --- Sprint 55 (APEP-436..443): CaMeL SEQ Rules, Bridge & Self-Protection ---

SEQ_RULES_TRIGGERED_TOTAL = Counter(
    "agentpep_seq_rules_triggered_total",
    "Total CaMeL-lite SEQ rules triggered by rule_id and severity",
    ["rule_id", "severity"],
)

SEQ_DETECTION_LATENCY = Histogram(
    "agentpep_seq_detection_latency_seconds",
    "CaMeL SEQ rule evaluation latency",
    buckets=[0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1],
)

SEQ_MARKERS_PLACED_TOTAL = Counter(
    "agentpep_seq_markers_placed_total",
    "Total session markers placed by marker type",
    ["marker_type"],
)

TOOLTRUST_BRIDGE_TOTAL = Counter(
    "agentpep_tooltrust_bridge_total",
    "Total ToolTrust bridge scans by decision",
    ["decision"],
)

TOOLTRUST_BRIDGE_LATENCY = Histogram(
    "agentpep_tooltrust_bridge_latency_seconds",
    "ToolTrust bridge scan latency",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25],
)

CIS_VERDICT_TAINT_TOTAL = Counter(
    "agentpep_cis_verdict_taint_total",
    "Total CIS verdicts applied as taint by verdict and taint_level",
    ["verdict", "taint_level"],
)

SELF_PROTECTION_BLOCKED_TOTAL = Counter(
    "agentpep_self_protection_blocked_total",
    "Total agent-initiated policy modifications blocked by operation",
    ["operation", "caller_type"],
)

PROTECTED_PATH_BLOCKED_TOTAL = Counter(
    "agentpep_protected_path_blocked_total",
    "Total protected path operations blocked by pattern and operation",
    ["pattern_id", "operation"],
)


# --- Sprint 56 (APEP-444/445/448/449): YOLO Mode & Session Risk Metrics ---

CIS_YOLO_DETECTIONS = Counter(
    "agentpep_cis_yolo_detections_total",
    "Total YOLO mode detections by source and signal type",
    ["source", "signal_type"],
)

CIS_YOLO_ACTIVE_SESSIONS = Gauge(
    "agentpep_cis_yolo_active_sessions",
    "Number of sessions currently flagged as YOLO mode",
)

CIS_SESSION_CONFIG_CHANGES = Counter(
    "agentpep_cis_session_config_changes_total",
    "Total per-session scan mode configuration changes",
    ["scan_mode", "set_by"],
)

CIS_SESSION_RISK_MULTIPLIER = Histogram(
    "agentpep_cis_session_risk_multiplier",
    "Distribution of session risk multipliers applied",
    buckets=[1.0, 1.25, 1.5, 2.0, 2.5, 3.0, 5.0, 10.0],
)

CIS_COMPLIANCE_EXPORTS = Counter(
    "agentpep_cis_compliance_exports_total",
    "Total CIS compliance export operations by template and format",
    ["template", "format"],
)

CIS_SCAN_MODE_USAGE = Counter(
    "agentpep_cis_scan_mode_usage_total",
    "Total scans by effective scan mode",
    ["scan_mode"],
)

CIS_YOLO_PROPAGATION_LATENCY = Histogram(
    "agentpep_cis_yolo_propagation_latency_seconds",
    "Latency of YOLO flag propagation operations",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5],
)

CIS_DASHBOARD_QUERIES = Counter(
    "agentpep_cis_dashboard_queries_total",
    "Total CIS dashboard data queries",
    ["widget"],
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
        # Only allow insecure OTLP in debug mode to prevent unencrypted telemetry in production
        exporter = OTLPSpanExporter(
            endpoint=settings.otlp_endpoint, insecure=settings.debug
        )
        provider.add_span_processor(BatchSpanProcessor(exporter))

    trace.set_tracer_provider(provider)
    _tracer_provider = provider
    FastAPIInstrumentor.instrument_app(app)

    return provider


def get_tracer(name: str) -> trace.Tracer:
    """Get a named tracer from the global TracerProvider."""
    return trace.get_tracer(name, settings.app_version)
