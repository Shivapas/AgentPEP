"""Kafka producer — publishes every audit decision to the agentpep.decisions topic.

Sprint 10 — APEP-083: Kafka topic mirror for audit decisions.
"""

import json
import logging

from app.core.config import settings
from app.models.policy import AuditDecision

logger = logging.getLogger(__name__)


class KafkaDecisionProducer:
    """Publishes audit decisions to a Kafka topic.

    Wraps aiokafka AIOKafkaProducer. When Kafka is disabled or unavailable,
    operations are silently skipped so the decision pipeline is never blocked.
    """

    def __init__(self) -> None:
        self._producer = None
        self._started: bool = False

    async def start(self) -> None:
        """Initialize and start the Kafka producer."""
        if not settings.kafka_enabled:
            logger.info("Kafka disabled — skipping producer start")
            return

        try:
            from aiokafka import AIOKafkaProducer

            self._producer = AIOKafkaProducer(
                bootstrap_servers=settings.kafka_bootstrap_servers,
                acks=settings.kafka_producer_acks,
                retry_backoff_ms=200,
                max_request_size=1_048_576,
                value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
            )
            await self._producer.start()
            self._started = True
            logger.info(
                "Kafka producer started — topic=%s servers=%s",
                settings.kafka_decisions_topic,
                settings.kafka_bootstrap_servers,
            )
        except ImportError:
            logger.warning(
                "aiokafka not installed — Kafka producer disabled. "
                "Install aiokafka to enable Kafka integration."
            )
        except Exception:
            logger.exception("Failed to start Kafka producer")

    async def publish_decision(self, audit: AuditDecision) -> bool:
        """Publish an audit decision to the Kafka decisions topic.

        Returns True if published successfully, False otherwise.
        Publishing failures never block the decision pipeline.
        """
        if not self._started or self._producer is None:
            return False

        try:
            record = audit.model_dump(mode="json")
            await self._producer.send_and_wait(
                topic=settings.kafka_decisions_topic,
                key=str(audit.decision_id),
                value=record,
            )
            return True
        except Exception:
            logger.exception("Failed to publish audit decision %s to Kafka", audit.decision_id)
            return False

    async def stop(self) -> None:
        """Flush and stop the Kafka producer."""
        if self._producer is not None and self._started:
            try:
                await self._producer.stop()
            except Exception:
                logger.exception("Error stopping Kafka producer")
            finally:
                self._started = False
                self._producer = None

    # ------------------------------------------------------------------
    # Sprint 41 — APEP-S41.7: Checkpoint escalation events
    # ------------------------------------------------------------------

    async def publish_checkpoint_escalation(
        self,
        *,
        plan_id: str,
        session_id: str,
        agent_id: str,
        tool_name: str,
        matched_pattern: str,
        match_reason: str,
        human_intent: str = "",
    ) -> bool:
        """Publish a checkpoint escalation event to the checkpoint topic.

        Emitted whenever a requires_checkpoint pattern triggers ESCALATE.
        Consumers can use this for real-time alerting, dashboards, or
        compliance logging.
        """
        if not self._started or self._producer is None:
            return False

        topic = getattr(
            settings,
            "kafka_checkpoint_topic",
            "agentpep.checkpoint_escalations",
        )

        event = {
            "event_type": "CHECKPOINT_ESCALATION",
            "plan_id": plan_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "matched_pattern": matched_pattern,
            "match_reason": match_reason,
            "human_intent": human_intent,
        }

        try:
            await self._producer.send_and_wait(
                topic=topic,
                key=plan_id,
                value=event,
            )
            return True
        except Exception:
            logger.exception(
                "Failed to publish checkpoint escalation for plan %s",
                plan_id,
            )
            return False

    # ------------------------------------------------------------------
    # Sprint 43 — APEP-342.e: Pattern library events
    # ------------------------------------------------------------------

    async def publish_scope_simulation(
        self,
        *,
        tool_name: str,
        effective_decision: str,
        scope_patterns: list[str],
        checkpoint_patterns: list[str],
        plan_id: str = "",
    ) -> bool:
        """Publish a scope simulation event for pipeline observability.

        Emitted by the scope simulator API endpoint so that downstream
        consumers can track scope evaluation patterns and build analytics.
        """
        if not self._started or self._producer is None:
            return False

        topic = getattr(
            settings,
            "kafka_scope_topic",
            "agentpep.scope_simulations",
        )

        event = {
            "event_type": "SCOPE_SIMULATION",
            "tool_name": tool_name,
            "effective_decision": effective_decision,
            "scope_patterns": scope_patterns,
            "checkpoint_patterns": checkpoint_patterns,
            "plan_id": plan_id,
        }

        try:
            await self._producer.send_and_wait(
                topic=topic,
                key=plan_id or tool_name,
                value=event,
            )
            return True
        except Exception:
            logger.exception(
                "Failed to publish scope simulation event for tool %s",
                tool_name,
            )
            return False

    # ------------------------------------------------------------------
    # Sprint 44 — APEP-348: Network DLP events
    # ------------------------------------------------------------------

    async def publish_network_event(self, event: dict) -> bool:
        """Publish a network scan event to the agentpep.network topic.

        Used by NetworkDLPScanner, URLScanner, and SSRFGuard to emit
        DLP_HIT, SSRF_BLOCKED, and other network security events.
        """
        if not self._started or self._producer is None:
            return False

        topic = getattr(
            settings,
            "kafka_network_topic",
            "agentpep.network",
        )

        try:
            key = event.get("session_id", event.get("event_id", ""))
            await self._producer.send_and_wait(
                topic=topic,
                key=str(key),
                value=event,
            )
            return True
        except Exception:
            logger.exception("Failed to publish network event")
            return False

    # ------------------------------------------------------------------
    # Sprint 46 — APEP-364: Fetch proxy events
    # ------------------------------------------------------------------

    async def publish_fetch_event(self, event: dict) -> bool:
        """Publish a fetch proxy event to the agentpep.fetch topic.

        Used by FetchProxyService to emit FETCH_ALLOWED, FETCH_BLOCKED,
        INJECTION_DETECTED, DLP_HIT, and QUARANTINE_APPLIED events.
        """
        if not self._started or self._producer is None:
            return False

        topic = getattr(
            settings,
            "kafka_fetch_topic",
            "agentpep.fetch",
        )

        try:
            key = event.get("session_id", event.get("event_id", ""))
            await self._producer.send_and_wait(
                topic=topic,
                key=str(key),
                value=event,
            )
            return True
        except Exception:
            logger.exception("Failed to publish fetch proxy event")
            return False

    # ------------------------------------------------------------------
    # Sprint 49 — APEP-394: Chain detection events
    # ------------------------------------------------------------------

    async def publish_chain_detection(self, event: dict) -> bool:
        """Publish a chain detection event to the agentpep.chain_detection topic.

        Used by ToolCallChainDetector to emit CHAIN_DETECTED and
        CHAIN_ESCALATED events for real-time alerting and dashboards.
        """
        if not self._started or self._producer is None:
            return False

        topic = getattr(
            settings,
            "kafka_chain_detection_topic",
            "agentpep.chain_detection",
        )

        try:
            key = event.get("session_id", event.get("event_id", ""))
            await self._producer.send_and_wait(
                topic=topic,
                key=str(key),
                value=event,
            )
            return True
        except Exception:
            logger.exception("Failed to publish chain detection event")
            return False

    async def publish_chain_event(
        self,
        *,
        event_type: str,
        pattern_id: str = "",
        pattern_name: str = "",
        session_id: str = "",
        agent_id: str = "",
        severity: str = "",
        category: str = "",
        risk_boost: float = 0.0,
        matched_tools: list[str] | None = None,
        escalation_id: str = "",
    ) -> bool:
        """Publish a chain management event (create/update/delete pattern)."""
        if not self._started or self._producer is None:
            return False

        topic = getattr(
            settings,
            "kafka_chain_detection_topic",
            "agentpep.chain_detection",
        )

        event = {
            "event_type": event_type,
            "pattern_id": pattern_id,
            "pattern_name": pattern_name,
            "session_id": session_id,
            "agent_id": agent_id,
            "severity": severity,
            "category": category,
            "risk_boost": risk_boost,
            "matched_tools": matched_tools or [],
            "escalation_id": escalation_id,
        }

        try:
            await self._producer.send_and_wait(
                topic=topic,
                key=pattern_id or session_id or "",
                value=event,
            )
            return True
        except Exception:
            logger.exception("Failed to publish chain event")
            return False

    @property
    def is_running(self) -> bool:
        return self._started


# Module-level singleton
kafka_producer = KafkaDecisionProducer()
