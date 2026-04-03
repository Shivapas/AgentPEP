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

    @property
    def is_running(self) -> bool:
        return self._started


# Module-level singleton
kafka_producer = KafkaDecisionProducer()
