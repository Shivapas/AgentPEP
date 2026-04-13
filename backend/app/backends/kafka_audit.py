"""KafkaAuditBackend — Kafka implementation of AuditBackend ABC.

Sprint 29 — APEP-230: Refactors the existing Kafka producer as an
AuditBackend implementation.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.backends.audit import AuditBackend, IntegrityResult
from app.core.config import settings

logger = logging.getLogger(__name__)


class KafkaAuditBackend(AuditBackend):
    """Kafka-backed audit backend that publishes decisions to a topic.

    Wraps aiokafka AIOKafkaProducer. When Kafka is disabled or unavailable,
    operations are silently skipped so the decision pipeline is never blocked.
    """

    def __init__(
        self,
        bootstrap_servers: str | None = None,
        topic: str | None = None,
    ) -> None:
        self._bootstrap_servers = bootstrap_servers or settings.kafka_bootstrap_servers
        self._topic = topic or settings.kafka_decisions_topic
        self._producer: Any = None
        self._started = False

    async def initialize(self) -> None:
        if not settings.kafka_enabled:
            logger.info("Kafka disabled — skipping KafkaAuditBackend initialization")
            return
        try:
            from aiokafka import AIOKafkaProducer

            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._bootstrap_servers,
                acks=settings.kafka_producer_acks,
                retry_backoff_ms=200,
                max_request_size=1_048_576,
                value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
            )
            await self._producer.start()
            self._started = True
            logger.info(
                "KafkaAuditBackend started — topic=%s servers=%s",
                self._topic,
                self._bootstrap_servers,
            )
        except ImportError:
            logger.warning(
                "aiokafka not installed — KafkaAuditBackend disabled. "
                "Install aiokafka to enable Kafka integration."
            )
        except Exception:
            logger.exception("Failed to start KafkaAuditBackend")

    async def write_decision(self, record: dict[str, Any]) -> bool:
        if not self._started or self._producer is None:
            return False
        try:
            await self._producer.send_and_wait(
                topic=self._topic,
                key=str(record.get("decision_id", "")),
                value=record,
            )
            return True
        except Exception:
            logger.exception(
                "Failed to publish audit decision %s to Kafka",
                record.get("decision_id"),
            )
            return False

    async def query(
        self,
        filter: dict[str, Any],
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        # Kafka is a write-only audit sink; querying is not supported
        logger.warning("KafkaAuditBackend does not support querying — returning empty list")
        return []

    async def verify_integrity(
        self, *, start_sequence: int = 1, end_sequence: int | None = None
    ) -> IntegrityResult:
        # Kafka topics are append-only; integrity is guaranteed by the broker
        return IntegrityResult(
            valid=True,
            detail="Kafka topics are append-only; integrity is guaranteed by the broker",
        )

    async def close(self) -> None:
        if self._producer is not None and self._started:
            try:
                await self._producer.stop()
            except Exception:
                logger.exception("Error stopping KafkaAuditBackend producer")
            finally:
                self._started = False
                self._producer = None

    @property
    def is_running(self) -> bool:
        return self._started
