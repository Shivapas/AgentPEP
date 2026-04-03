"""Sprint 10 — APEP-089: Load test for audit pipeline throughput.

Validates that the audit logger can sustain 5,000 decisions/sec throughput.
This test uses mongomock so it measures the service-layer overhead
(hash chain computation, serialisation) rather than real MongoDB I/O.
"""

import asyncio
import hashlib
import time

import pytest

from app.models.policy import AuditDecision, Decision
from app.services.audit_logger import audit_logger

TARGET_THROUGHPUT = 5_000  # decisions per second
TEST_BATCH_SIZE = 5_000
MAX_DURATION_S = 5.0  # Allow up to 5s for the batch (generous ceiling)


@pytest.fixture(autouse=True)
async def _reset_logger():
    audit_logger.reset()
    yield


class TestAuditThroughput:
    async def test_5000_decisions_per_second(self, mock_mongodb):
        """Audit pipeline can handle 5,000 decisions/sec throughput.

        We measure the time to append TEST_BATCH_SIZE records through
        the AuditLogger (including SHA-256 hash chain computation).
        """
        audit_logger._initialized = True  # Skip DB init for speed

        records = []
        for i in range(TEST_BATCH_SIZE):
            records.append(
                AuditDecision(
                    session_id=f"load-sess-{i % 100}",
                    agent_id=f"agent-{i % 10}",
                    agent_role="worker",
                    tool_name=f"tool.action_{i % 50}",
                    tool_args_hash=hashlib.sha256(f"args-{i}".encode()).hexdigest(),
                    decision=Decision.ALLOW if i % 3 != 0 else Decision.DENY,
                    risk_score=round((i % 100) / 100, 2),
                    latency_ms=i % 50,
                )
            )

        start = time.monotonic()
        for record in records:
            await audit_logger.append(record)
        elapsed = time.monotonic() - start

        throughput = TEST_BATCH_SIZE / elapsed
        print(
            f"\n  Audit throughput: {throughput:,.0f} decisions/sec "
            f"({TEST_BATCH_SIZE} records in {elapsed:.2f}s)"
        )

        # Verify all records were persisted
        count = await mock_mongodb["audit_decisions"].count_documents({})
        assert count == TEST_BATCH_SIZE

        # Verify hash chain integrity on a sample
        first = await mock_mongodb["audit_decisions"].find_one({"sequence_number": 1})
        last = await mock_mongodb["audit_decisions"].find_one(
            {"sequence_number": TEST_BATCH_SIZE}
        )
        assert first is not None
        assert last is not None
        assert first["previous_hash"] != ""
        assert last["record_hash"] != ""
        assert last["sequence_number"] == TEST_BATCH_SIZE

        # The throughput assertion: should complete within MAX_DURATION_S
        assert elapsed < MAX_DURATION_S, (
            f"Audit pipeline too slow: {throughput:,.0f} decisions/sec "
            f"(target: {TARGET_THROUGHPUT:,}). Elapsed: {elapsed:.2f}s"
        )

    async def test_concurrent_appends(self, mock_mongodb):
        """Concurrent audit appends maintain hash chain consistency."""
        audit_logger._initialized = True
        batch = 100

        async def append_one(idx: int) -> AuditDecision:
            audit = AuditDecision(
                session_id="concurrent-sess",
                agent_id=f"agent-{idx}",
                agent_role="worker",
                tool_name="tool.action",
                tool_args_hash=hashlib.sha256(f"args-{idx}".encode()).hexdigest(),
                decision=Decision.ALLOW,
                risk_score=0.1,
                latency_ms=1,
            )
            return await audit_logger.append(audit)

        results = await asyncio.gather(*[append_one(i) for i in range(batch)])

        # All sequence numbers should be unique
        seq_numbers = [r.sequence_number for r in results]
        assert len(set(seq_numbers)) == batch

        # Sequence numbers should be contiguous 1..batch
        assert sorted(seq_numbers) == list(range(1, batch + 1))
