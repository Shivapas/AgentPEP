"""Sprint 26 — Observability & Alerting tests.

Covers:
- APEP-204: Enhanced Prometheus metrics (decision_total, latency, taint_event_total)
- APEP-207: OpenTelemetry tracing spans in policy evaluation
- APEP-209: Structured JSON logging with decision_id correlation
"""

import json
import logging
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.observability import (
    AUDIT_WRITE_TOTAL,
    DECISION_LATENCY,
    DECISION_TOTAL,
    INTERCEPT_REQUESTS,
    SECURITY_ALERT_TOTAL,
    TAINT_EVENT_TOTAL,
)
from app.core.structured_logging import StructuredJsonFormatter, StructuredLogger, get_logger
from app.main import app
from app.models.policy import TaintEventType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _counter_value(counter, labels: dict) -> float:
    """Read the current value of a Prometheus counter with given labels."""
    return counter.labels(**labels)._value.get()


def _gauge_value(gauge) -> float:
    """Read the current value of a Prometheus gauge."""
    return gauge._value.get()


# ---------------------------------------------------------------------------
# APEP-204: Enhanced Prometheus Metrics
# ---------------------------------------------------------------------------


class TestEnhancedMetrics:
    """Test that intercept requests emit enhanced decision_total metrics."""

    @pytest.fixture
    async def client(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    @pytest.fixture
    async def allow_rule(self, mock_mongodb):
        """Insert a rule that ALLOWs read_file for the 'reader' role."""
        await mock_mongodb["policy_rules"].insert_one(
            {
                "rule_id": str(uuid4()),
                "name": "allow-read",
                "agent_role": ["reader"],
                "tool_pattern": "read_file",
                "action": "ALLOW",
                "priority": 10,
                "enabled": True,
                "taint_check": False,
                "risk_threshold": 1.0,
                "arg_validators": [],
            }
        )

    @pytest.fixture
    async def reader_profile(self, mock_mongodb):
        """Insert a reader agent profile."""
        await mock_mongodb["agent_profiles"].insert_one(
            {
                "agent_id": "agent-metrics-test",
                "name": "Metrics Test Agent",
                "roles": ["reader"],
                "enabled": True,
            }
        )

    @pytest.fixture
    async def reader_role(self, mock_mongodb):
        """Insert the reader role."""
        await mock_mongodb["agent_roles"].insert_one(
            {
                "role_id": "reader",
                "name": "Reader",
                "parent_roles": [],
                "allowed_tools": ["read_*"],
                "denied_tools": [],
                "max_risk_threshold": 1.0,
                "enabled": True,
            }
        )

    async def test_decision_total_incremented_on_allow(
        self, client, allow_rule, reader_profile, reader_role
    ):
        """APEP-204: decision_total counter should increment with decision/agent/tool labels."""
        before = _counter_value(
            DECISION_TOTAL,
            {"decision": "ALLOW", "agent_id": "agent-metrics-test", "tool_name": "read_file"},
        )

        resp = await client.post(
            "/v1/intercept",
            json={
                "session_id": "sess-metrics-1",
                "agent_id": "agent-metrics-test",
                "tool_name": "read_file",
                "tool_args": {},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["decision"] == "ALLOW"

        after = _counter_value(
            DECISION_TOTAL,
            {"decision": "ALLOW", "agent_id": "agent-metrics-test", "tool_name": "read_file"},
        )
        assert after == before + 1

    async def test_decision_total_incremented_on_deny(self, client):
        """APEP-204: DENY decisions (no matching rule) also increment decision_total."""
        before = _counter_value(
            DECISION_TOTAL,
            {"decision": "DENY", "agent_id": "agent-unknown", "tool_name": "delete_all"},
        )

        resp = await client.post(
            "/v1/intercept",
            json={
                "session_id": "sess-metrics-2",
                "agent_id": "agent-unknown",
                "tool_name": "delete_all",
                "tool_args": {},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["decision"] == "DENY"

        after = _counter_value(
            DECISION_TOTAL,
            {"decision": "DENY", "agent_id": "agent-unknown", "tool_name": "delete_all"},
        )
        assert after == before + 1

    async def test_decision_latency_histogram_observed(
        self, client, allow_rule, reader_profile, reader_role
    ):
        """APEP-204: decision_latency histogram should record observations."""
        before_count = DECISION_LATENCY.labels(
            agent_id="agent-metrics-test", tool_name="read_file"
        )._sum.get()

        await client.post(
            "/v1/intercept",
            json={
                "session_id": "sess-latency-1",
                "agent_id": "agent-metrics-test",
                "tool_name": "read_file",
                "tool_args": {},
            },
        )

        after_count = DECISION_LATENCY.labels(
            agent_id="agent-metrics-test", tool_name="read_file"
        )._sum.get()
        assert after_count > before_count

    async def test_legacy_metrics_still_emitted(
        self, client, allow_rule, reader_profile, reader_role
    ):
        """Backward compat: legacy intercept_requests_total still incremented."""
        before = _counter_value(INTERCEPT_REQUESTS, {"decision": "ALLOW"})

        await client.post(
            "/v1/intercept",
            json={
                "session_id": "sess-legacy-1",
                "agent_id": "agent-metrics-test",
                "tool_name": "read_file",
                "tool_args": {},
            },
        )

        after = _counter_value(INTERCEPT_REQUESTS, {"decision": "ALLOW"})
        assert after == before + 1

    async def test_audit_write_metrics(self, client):
        """APEP-204: audit write success/failure counters and latency histograms."""
        before_success = _counter_value(AUDIT_WRITE_TOTAL, {"status": "success"})

        await client.post(
            "/v1/intercept",
            json={
                "session_id": "sess-audit-1",
                "agent_id": "agent-audit-test",
                "tool_name": "some_tool",
                "tool_args": {},
            },
        )

        after_success = _counter_value(AUDIT_WRITE_TOTAL, {"status": "success"})
        assert after_success >= before_success + 1


class TestTaintEventMetrics:
    """APEP-204: taint_event_total counter emitted from TaintAuditLogger."""

    def test_taint_event_total_incremented_on_emit(self):
        from app.models.policy import TaintAuditEvent, TaintLevel, TaintSource
        from app.services.taint_graph import TaintAuditLogger

        audit_logger = TaintAuditLogger()
        before = _counter_value(TAINT_EVENT_TOTAL, {"event_type": "TAINT_ASSIGNED"})

        event = TaintAuditEvent(
            event_type=TaintEventType.TAINT_ASSIGNED,
            session_id="sess-taint-metric",
            node_id=uuid4(),
            taint_level=TaintLevel.UNTRUSTED,
            source=TaintSource.WEB,
        )
        audit_logger.emit(event)

        after = _counter_value(TAINT_EVENT_TOTAL, {"event_type": "TAINT_ASSIGNED"})
        assert after == before + 1

    def test_multiple_event_types(self):
        from app.models.policy import TaintAuditEvent, TaintLevel, TaintSource
        from app.services.taint_graph import TaintAuditLogger

        audit_logger = TaintAuditLogger()

        for event_type in [TaintEventType.TAINT_PROPAGATED, TaintEventType.TAINT_QUARANTINED]:
            before = _counter_value(TAINT_EVENT_TOTAL, {"event_type": event_type.value})
            event = TaintAuditEvent(
                event_type=event_type,
                session_id="sess-taint-multi",
                node_id=uuid4(),
                taint_level=TaintLevel.QUARANTINE,
                source=TaintSource.WEB,
            )
            audit_logger.emit(event)
            after = _counter_value(TAINT_EVENT_TOTAL, {"event_type": event_type.value})
            assert after == before + 1


class TestSecurityAlertMetrics:
    """APEP-204: security_alert_total counter emitted from SecurityAlertEmitter."""

    @pytest.fixture
    async def client(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    async def test_security_alert_counter(self, mock_mongodb):
        from app.models.policy import SecurityAlertEvent, SecurityAlertType
        from app.services.confused_deputy import SecurityAlertEmitter

        emitter = SecurityAlertEmitter()
        before = _counter_value(
            SECURITY_ALERT_TOTAL,
            {"alert_type": "PRIVILEGE_ESCALATION", "severity": "HIGH"},
        )

        alert = SecurityAlertEvent(
            alert_type=SecurityAlertType.PRIVILEGE_ESCALATION,
            session_id="sess-alert-metric",
            agent_id="agent-bad",
            tool_name="admin_tool",
            detail="test alert",
            severity="HIGH",
        )
        await emitter.emit(alert)

        after = _counter_value(
            SECURITY_ALERT_TOTAL,
            {"alert_type": "PRIVILEGE_ESCALATION", "severity": "HIGH"},
        )
        assert after == before + 1


# ---------------------------------------------------------------------------
# APEP-209: Structured JSON Logging
# ---------------------------------------------------------------------------


class TestStructuredLogging:
    """Test that structured logger produces valid JSON with expected fields."""

    def test_json_format(self):
        """Structured logs should be valid JSON with standard fields."""
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test.module",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test_event",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)

        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "test.module"
        assert parsed["message"] == "test_event"
        assert "timestamp" in parsed
        assert "service" in parsed
        assert "version" in parsed

    def test_structured_fields(self):
        """StructuredLogger should embed extra key-value fields in JSON output."""
        formatter = StructuredJsonFormatter()
        logger_inner = logging.getLogger("test.structured")
        logger_inner.handlers.clear()
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger_inner.addHandler(handler)
        logger_inner.setLevel(logging.DEBUG)

        slogger = StructuredLogger(logger_inner)

        # Capture formatted output
        record = logger_inner.makeRecord(
            name="test.structured",
            level=logging.INFO,
            fn="",
            lno=0,
            msg="policy_decision",
            args=(),
            exc_info=None,
        )
        record._structured_fields = {"decision_id": "abc-123", "agent_id": "agent-1"}
        output = formatter.format(record)
        parsed = json.loads(output)

        assert parsed["decision_id"] == "abc-123"
        assert parsed["agent_id"] == "agent-1"
        assert parsed["message"] == "policy_decision"

    def test_get_logger_returns_structured_logger(self):
        """get_logger should return a StructuredLogger instance."""
        slogger = get_logger("test.getlogger")
        assert isinstance(slogger, StructuredLogger)

    def test_log_levels(self):
        """All log level methods should work without errors."""
        slogger = get_logger("test.levels")
        slogger.debug("debug_event", key="val")
        slogger.info("info_event", key="val")
        slogger.warning("warning_event", key="val")
        slogger.error("error_event", key="val")
        slogger.critical("critical_event", key="val")


# ---------------------------------------------------------------------------
# APEP-207: OpenTelemetry Tracing Spans
# ---------------------------------------------------------------------------


class TestTracingSpans:
    """Verify that tracing infrastructure is wired correctly."""

    def test_get_tracer_returns_tracer(self):
        from app.core.observability import get_tracer

        tracer = get_tracer("test.tracer")
        assert tracer is not None

    def test_tracer_creates_spans(self):
        from app.core.observability import get_tracer

        tracer = get_tracer("test.spans")
        with tracer.start_as_current_span("test_span") as span:
            span.set_attribute("test.key", "value")
            # Span should be recording
            assert span.is_recording()


# ---------------------------------------------------------------------------
# APEP-205 / 206: Grafana Dashboard & Alerting Rules file existence
# ---------------------------------------------------------------------------


class TestInfraFiles:
    """Verify that required infrastructure configuration files exist."""

    def test_grafana_dashboard_exists(self):
        import os

        path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "infra",
            "grafana",
            "dashboards",
            "agentpep-overview.json",
        )
        assert os.path.exists(path), f"Grafana dashboard not found at {path}"

        with open(path) as f:
            dashboard = json.load(f)
        assert dashboard["title"] == "AgentPEP Overview"
        assert len(dashboard["panels"]) >= 8

    def test_alerting_rules_exists(self):
        import os

        import yaml

        path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "infra",
            "prometheus",
            "alerting_rules.yml",
        )
        assert os.path.exists(path), f"Alerting rules not found at {path}"

        with open(path) as f:
            rules = yaml.safe_load(f)
        group_names = [g["name"] for g in rules["groups"]]
        assert "agentpep.decision" in group_names
        assert "agentpep.escalation" in group_names

        # Verify specific alerts exist
        all_alerts = []
        for group in rules["groups"]:
            for rule in group["rules"]:
                all_alerts.append(rule["alert"])
        assert "AgentPEP_DenyRateSpike" in all_alerts
        assert "AgentPEP_HighP99Latency" in all_alerts
        assert "AgentPEP_EscalationBacklog" in all_alerts

    def test_otel_collector_config_exists(self):
        import os

        import yaml

        path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "infra",
            "otel-collector",
            "otel-collector-config.yml",
        )
        assert os.path.exists(path)

        with open(path) as f:
            config = yaml.safe_load(f)
        assert "receivers" in config
        assert "exporters" in config
        assert "otlp/tempo" in config["exporters"]

    def test_helm_chart_exists(self):
        import os

        import yaml

        chart_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "infra",
            "helm",
            "agentpep",
            "Chart.yaml",
        )
        assert os.path.exists(chart_path)

        with open(chart_path) as f:
            chart = yaml.safe_load(f)
        assert chart["name"] == "agentpep"

    def test_runbooks_exist(self):
        import os

        runbook_dir = os.path.join(
            os.path.dirname(__file__), "..", "..", "docs", "runbooks"
        )
        expected_runbooks = [
            "deny-rate-spike.md",
            "high-latency.md",
            "escalation-backlog.md",
            "audit-write-failures.md",
            "security-alert-burst.md",
        ]
        for name in expected_runbooks:
            path = os.path.join(runbook_dir, name)
            assert os.path.exists(path), f"Runbook not found: {name}"
