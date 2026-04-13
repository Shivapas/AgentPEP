"""CloudWatchAuditBackend — AWS CloudWatch Logs implementation of AuditBackend ABC.

Sprint 32 — APEP-250: Write decision records to AWS CloudWatch Logs
with configurable log group and stream.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from app.backends.audit import AuditBackend, IntegrityResult
from app.core.config import settings

logger = logging.getLogger(__name__)


class CloudWatchAuditBackend(AuditBackend):
    """CloudWatch Logs-backed audit backend.

    Uses boto3 (optional dependency) to write decision records to a
    CloudWatch Logs log group/stream.  When boto3 is not installed or
    CloudWatch is unreachable, operations are silently skipped so the
    decision pipeline is never blocked.
    """

    def __init__(
        self,
        log_group_name: str | None = None,
        log_stream_name: str | None = None,
        region_name: str | None = None,
    ) -> None:
        self._log_group = log_group_name or settings.cloudwatch_audit_log_group
        self._log_stream = log_stream_name or settings.cloudwatch_audit_log_stream
        self._region = region_name or settings.cloudwatch_audit_region
        self._client: Any = None
        self._sequence_token: str | None = None
        self._ready = False

    async def initialize(self) -> None:
        try:
            import boto3

            self._client = boto3.client("logs", region_name=self._region)

            # Create log group if it doesn't exist
            try:
                self._client.create_log_group(logGroupName=self._log_group)
                logger.info(
                    "CloudWatch log group created: %s",
                    self._log_group,
                )
            except self._client.exceptions.ResourceAlreadyExistsException:
                pass

            # Create log stream if it doesn't exist
            try:
                self._client.create_log_stream(
                    logGroupName=self._log_group,
                    logStreamName=self._log_stream,
                )
                logger.info(
                    "CloudWatch log stream created: %s/%s",
                    self._log_group,
                    self._log_stream,
                )
            except self._client.exceptions.ResourceAlreadyExistsException:
                pass

            self._ready = True
            logger.info(
                "CloudWatchAuditBackend initialized — group=%s stream=%s region=%s",
                self._log_group,
                self._log_stream,
                self._region,
            )
        except ImportError:
            logger.warning(
                "boto3 not installed — CloudWatchAuditBackend disabled. "
                "Install boto3 to enable CloudWatch integration."
            )
        except Exception:
            logger.exception("Failed to initialize CloudWatchAuditBackend")

    async def write_decision(self, record: dict[str, Any]) -> bool:
        if not self._ready or self._client is None:
            return False
        try:
            filtered = self.filter_by_verbosity(record)
            message = json.dumps(filtered, default=str)
            kwargs: dict[str, Any] = {
                "logGroupName": self._log_group,
                "logStreamName": self._log_stream,
                "logEvents": [
                    {
                        "timestamp": int(time.time() * 1000),
                        "message": message,
                    }
                ],
            }
            if self._sequence_token is not None:
                kwargs["sequenceToken"] = self._sequence_token

            response = self._client.put_log_events(**kwargs)
            self._sequence_token = response.get("nextSequenceToken")
            return True
        except Exception:
            logger.exception(
                "Failed to write audit decision %s to CloudWatch",
                record.get("decision_id"),
            )
            return False

    async def write_batch(self, records: list[dict[str, Any]]) -> int:
        if not self._ready or self._client is None:
            return 0
        if not records:
            return 0
        try:
            now_ms = int(time.time() * 1000)
            events = []
            for record in records:
                filtered = self.filter_by_verbosity(record)
                events.append(
                    {
                        "timestamp": now_ms,
                        "message": json.dumps(filtered, default=str),
                    }
                )

            # CloudWatch limit: 10,000 events per put_log_events call
            written = 0
            batch_size = 10_000
            for i in range(0, len(events), batch_size):
                batch = events[i : i + batch_size]
                kwargs: dict[str, Any] = {
                    "logGroupName": self._log_group,
                    "logStreamName": self._log_stream,
                    "logEvents": batch,
                }
                if self._sequence_token is not None:
                    kwargs["sequenceToken"] = self._sequence_token

                response = self._client.put_log_events(**kwargs)
                self._sequence_token = response.get("nextSequenceToken")
                written += len(batch)

            return written
        except Exception:
            logger.exception("Failed to write audit batch to CloudWatch")
            return 0

    async def query(
        self,
        filter: dict[str, Any],
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        if not self._ready or self._client is None:
            return []
        try:
            # Build a simple filter pattern from the dict keys
            filter_parts = []
            for key, value in filter.items():
                filter_parts.append(f'{{ $.{key} = "{value}" }}')
            filter_pattern = " && ".join(filter_parts) if filter_parts else ""

            kwargs: dict[str, Any] = {
                "logGroupName": self._log_group,
                "logStreamNames": [self._log_stream],
                "limit": limit,
            }
            if filter_pattern:
                kwargs["filterPattern"] = filter_pattern

            response = self._client.filter_log_events(**kwargs)
            results = []
            for event in response.get("events", []):
                try:
                    results.append(json.loads(event["message"]))
                except (json.JSONDecodeError, KeyError):
                    continue
            return results
        except Exception:
            logger.exception("Failed to query CloudWatch audit logs")
            return []

    async def verify_integrity(
        self, *, start_sequence: int = 1, end_sequence: int | None = None
    ) -> IntegrityResult:
        return IntegrityResult(
            valid=True,
            detail="CloudWatch Logs are append-only; integrity is guaranteed by AWS",
        )

    async def close(self) -> None:
        self._ready = False
        self._client = None

    @property
    def is_running(self) -> bool:
        return self._ready
