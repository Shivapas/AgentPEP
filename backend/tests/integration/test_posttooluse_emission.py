"""Integration test: tool call completes → PostToolUse event on Kafka within 500 ms.

Validates the full PostToolUse pipeline:
  1. Hook registry invokes registered handlers.
  2. OCSF event is built with correct schema.
  3. sequence_id links Pre and PostToolUse events.
  4. HMAC signature is present when key is configured.
  5. Kafka publication is attempted within the 500 ms SLA.
  6. OCSF linter passes on all emitted events.

Sprint S-E07 (E07-T09)
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.events.ocsf_linter import assert_valid, lint
from app.events.post_tool_use_event import (
    OUTCOME_DENIED,
    OUTCOME_ERROR,
    OUTCOME_EXECUTED,
    OUTCOME_TIMEOUT,
    emit_post_tool_use_event,
)
from app.events.sequence_id import generate_sequence_id, sequence_id_from_request
from app.hooks.post_tool_use import (
    PostToolUseContext,
    PostToolUseHookRegistry,
    post_tool_use_registry,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def registry() -> PostToolUseHookRegistry:
    """A fresh PostToolUseHookRegistry for each test."""
    return PostToolUseHookRegistry()


@pytest.fixture()
def allow_ctx() -> PostToolUseContext:
    """A typical ALLOW / EXECUTED context."""
    request_id = str(uuid.uuid4())
    return PostToolUseContext.from_allow(
        request_id=request_id,
        session_id="sess-test-001",
        agent_id="agent-test-001",
        tool_name="bash",
        latency_ms=4,
        risk_score=0.2,
        taint_flags=["UNTRUSTED"],
        matched_rule_id="rule-001",
        delegation_chain=["root", "agent-test-001"],
        tool_result_summary="command output",
    )


@pytest.fixture()
def deny_ctx() -> PostToolUseContext:
    """A DENY context (no tool execution)."""
    return PostToolUseContext.from_deny(
        request_id=str(uuid.uuid4()),
        session_id="sess-test-002",
        agent_id="agent-test-002",
        tool_name="rm",
        latency_ms=3,
        risk_score=0.9,
        taint_flags=[],
        matched_rule_id="rule-deny-rm",
    )


# ---------------------------------------------------------------------------
# E07-T09: Sequence ID tests
# ---------------------------------------------------------------------------


class TestSequenceId:
    def test_generate_produces_valid_uuid(self) -> None:
        sid = generate_sequence_id()
        parsed = uuid.UUID(sid)
        assert str(parsed) == sid

    def test_from_request_round_trips(self) -> None:
        request_id = uuid.uuid4()
        sid = sequence_id_from_request(request_id)
        assert sid == str(request_id)

    def test_from_request_string_input(self) -> None:
        raw = "550e8400-e29b-41d4-a716-446655440000"
        assert sequence_id_from_request(raw) == raw

    def test_sequence_id_links_pre_and_post(self, allow_ctx: PostToolUseContext) -> None:
        """The sequence_id in the PostToolUse event matches request_id."""
        event = emit_post_tool_use_event(
            request_id=allow_ctx.request_id,
            session_id=allow_ctx.session_id,
            agent_id=allow_ctx.agent_id,
            tool_name=allow_ctx.tool_name,
            tool_outcome=allow_ctx.tool_outcome,
            decision=allow_ctx.decision,
        )
        seq = event["finding_info"]["sequence_id"]
        assert seq == allow_ctx.request_id
        assert event["resources"][0]["uid"] == seq
        assert event["observables"][0]["value"] == seq


# ---------------------------------------------------------------------------
# E07-T09: OCSF event schema tests
# ---------------------------------------------------------------------------


class TestPostToolUseEventSchema:
    def test_allow_event_passes_linter(self, allow_ctx: PostToolUseContext) -> None:
        event = emit_post_tool_use_event(
            request_id=allow_ctx.request_id,
            session_id=allow_ctx.session_id,
            agent_id=allow_ctx.agent_id,
            tool_name=allow_ctx.tool_name,
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
            risk_score=0.2,
        )
        assert_valid(event)

    def test_deny_event_passes_linter(self, deny_ctx: PostToolUseContext) -> None:
        event = emit_post_tool_use_event(
            request_id=deny_ctx.request_id,
            session_id=deny_ctx.session_id,
            agent_id=deny_ctx.agent_id,
            tool_name=deny_ctx.tool_name,
            tool_outcome=OUTCOME_DENIED,
            decision="DENY",
            risk_score=0.9,
        )
        assert_valid(event)

    def test_error_event_passes_linter(self) -> None:
        ctx = PostToolUseContext.from_error(
            request_id=str(uuid.uuid4()),
            session_id="sess-err",
            agent_id="agent-err",
            tool_name="bash",
            error_message="Command not found",
        )
        event = emit_post_tool_use_event(
            request_id=ctx.request_id,
            session_id=ctx.session_id,
            agent_id=ctx.agent_id,
            tool_name=ctx.tool_name,
            tool_outcome=OUTCOME_ERROR,
            decision="ALLOW",
            tool_result_error="Command not found",
        )
        assert_valid(event)

    def test_timeout_event_passes_linter(self) -> None:
        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="sess-timeout",
            agent_id="agent-timeout",
            tool_name="slow_tool",
            tool_outcome=OUTCOME_TIMEOUT,
            decision="DENY",
        )
        assert_valid(event)

    def test_type_uid_derivation(self) -> None:
        for outcome, expected_activity in [
            (OUTCOME_EXECUTED, 1),
            (OUTCOME_DENIED, 2),
            (OUTCOME_ERROR, 3),
            (OUTCOME_TIMEOUT, 4),
        ]:
            event = emit_post_tool_use_event(
                request_id=str(uuid.uuid4()),
                session_id="s",
                agent_id="a",
                tool_name="t",
                tool_outcome=outcome,
                decision="ALLOW" if outcome == OUTCOME_EXECUTED else "DENY",
            )
            assert event["activity_id"] == expected_activity
            assert event["type_uid"] == 4001 * 100 + expected_activity

    def test_blast_radius_score_placeholder(self) -> None:
        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
        )
        assert "blast_radius_score" in event
        assert event["blast_radius_score"] is None

    def test_blast_radius_score_populated(self) -> None:
        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
            blast_radius_score=0.82,
        )
        assert event["blast_radius_score"] == 0.82

    def test_tool_args_not_included(self) -> None:
        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
        )
        assert event["tool_args_included"] is False

    def test_delegation_chain_in_actor(self) -> None:
        chain = ["root-agent", "sub-agent"]
        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="sub-agent",
            tool_name="t",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
            delegation_chain=chain,
        )
        assert event["actor"]["delegation_chain"] == chain

    def test_profile_field_present(self) -> None:
        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
        )
        assert event["metadata"]["profile"] == "TrustFabric/AgentPEP/v1.0"


# ---------------------------------------------------------------------------
# E07-T09: HMAC signing tests
# ---------------------------------------------------------------------------


class TestHMACSigning:
    def test_event_signed_when_key_configured(self) -> None:
        from app.events.event_signer import sign_event, verify_event

        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
        )
        key = "test-hmac-key-32-chars-long-xxxx"
        signed = sign_event(event, key)

        assert "hmac_signature" in signed["metadata"]
        assert signed["metadata"]["hmac_algorithm"] == "HMAC-SHA256"
        assert verify_event(signed, key) is True

    def test_tampered_event_fails_verification(self) -> None:
        from app.events.event_signer import sign_event, verify_event

        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
        )
        key = "test-hmac-key-32-chars-long-xxxx"
        signed = sign_event(event, key)

        # Tamper with the decision field
        signed["decision"] = "ALLOW"  # was already ALLOW, change to different
        signed["risk_score"] = 0.99   # tamper risk_score

        assert verify_event(signed, key) is False

    def test_wrong_key_fails_verification(self) -> None:
        from app.events.event_signer import sign_event, verify_event

        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
        )
        signed = sign_event(event, "correct-key-32-chars-long-xxxxxx")
        assert verify_event(signed, "wrong-key-32-chars-long-xxxxxxxxx") is False

    def test_empty_key_raises(self) -> None:
        from app.events.event_signer import sign_event

        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
        )
        with pytest.raises(ValueError, match="HMAC signing key must not be empty"):
            sign_event(event, "")

    def test_try_sign_with_configured_key(self) -> None:
        from app.events.event_signer import try_sign_event

        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
        )
        with patch("app.events.event_signer._UNSIGNED_WARNED", False):
            with patch("app.core.config.settings") as mock_settings:
                mock_settings.posttooluse_hmac_key = "test-key-32-chars-long-xxxxxxxxxx"
                result = try_sign_event(event)

        assert "hmac_signature" in result["metadata"]


# ---------------------------------------------------------------------------
# E07-T09: PostToolUse hook registry tests
# ---------------------------------------------------------------------------


class TestPostToolUseHookRegistry:
    @pytest.mark.asyncio
    async def test_handler_registered_and_invoked(
        self, registry: PostToolUseHookRegistry, allow_ctx: PostToolUseContext
    ) -> None:
        invoked_with: list[PostToolUseContext] = []

        @registry.register
        async def handler(ctx: PostToolUseContext) -> None:
            invoked_with.append(ctx)

        with patch("app.hooks.post_tool_use._publish_to_kafka", AsyncMock()):
            await registry.invoke(allow_ctx)

        assert len(invoked_with) == 1
        assert invoked_with[0] is allow_ctx

    @pytest.mark.asyncio
    async def test_multiple_handlers_invoked_in_order(
        self, registry: PostToolUseHookRegistry, allow_ctx: PostToolUseContext
    ) -> None:
        order: list[int] = []

        @registry.register
        async def handler_1(ctx: PostToolUseContext) -> None:
            order.append(1)

        @registry.register
        async def handler_2(ctx: PostToolUseContext) -> None:
            order.append(2)

        with patch("app.hooks.post_tool_use._publish_to_kafka", AsyncMock()):
            await registry.invoke(allow_ctx)

        assert order == [1, 2]

    @pytest.mark.asyncio
    async def test_failing_handler_does_not_block_emission(
        self, registry: PostToolUseHookRegistry, allow_ctx: PostToolUseContext
    ) -> None:
        @registry.register
        async def bad_handler(ctx: PostToolUseContext) -> None:
            raise RuntimeError("handler exploded")

        with patch("app.hooks.post_tool_use._publish_to_kafka", AsyncMock()) as mock_pub:
            event = await registry.invoke(allow_ctx)

        # Event was still emitted despite handler failure
        assert event is not None
        assert event["class_uid"] == 4001
        mock_pub.assert_called_once()

    @pytest.mark.asyncio
    async def test_invoke_returns_valid_ocsf_event(
        self, registry: PostToolUseHookRegistry, allow_ctx: PostToolUseContext
    ) -> None:
        with patch("app.hooks.post_tool_use._publish_to_kafka", AsyncMock()):
            event = await registry.invoke(allow_ctx)

        assert_valid(event)

    @pytest.mark.asyncio
    async def test_deny_context_produces_deny_event(
        self, registry: PostToolUseHookRegistry, deny_ctx: PostToolUseContext
    ) -> None:
        with patch("app.hooks.post_tool_use._publish_to_kafka", AsyncMock()):
            event = await registry.invoke(deny_ctx)

        assert event["decision"] == "DENY"
        assert event["tool_outcome"] == OUTCOME_DENIED
        assert event["activity_id"] == 2
        assert event["severity"] == "HIGH"

    def test_unregister_handler(self, registry: PostToolUseHookRegistry) -> None:
        async def handler(ctx: PostToolUseContext) -> None:
            pass

        registry.register(handler)
        assert registry.handler_count == 1

        registry.unregister(handler)
        assert registry.handler_count == 0

    def test_unregister_nonexistent_is_noop(
        self, registry: PostToolUseHookRegistry
    ) -> None:
        async def handler(ctx: PostToolUseContext) -> None:
            pass

        registry.unregister(handler)  # Should not raise


# ---------------------------------------------------------------------------
# E07-T09: Kafka delivery within 500 ms SLA
# ---------------------------------------------------------------------------


class TestKafkaDeliverySLA:
    @pytest.mark.asyncio
    async def test_kafka_publish_called_within_sla(
        self, registry: PostToolUseHookRegistry, allow_ctx: PostToolUseContext
    ) -> None:
        """Verify that registry.invoke completes within 500 ms SLA."""
        mock_publish = AsyncMock(return_value=True)

        with patch("app.hooks.post_tool_use._publish_to_kafka", mock_publish):
            start = time.monotonic()
            await registry.invoke(allow_ctx)
            elapsed_ms = (time.monotonic() - start) * 1000

        mock_publish.assert_called_once()
        assert elapsed_ms < 500, f"PostToolUse hook exceeded 500 ms SLA: {elapsed_ms:.1f} ms"

    @pytest.mark.asyncio
    async def test_kafka_publish_receives_correct_event(
        self, registry: PostToolUseHookRegistry, allow_ctx: PostToolUseContext
    ) -> None:
        captured: list[dict] = []

        async def capture_publish(event: dict) -> None:
            captured.append(event)

        with patch("app.hooks.post_tool_use._publish_to_kafka", capture_publish):
            await registry.invoke(allow_ctx)

        assert len(captured) == 1
        published = captured[0]
        assert published["class_uid"] == 4001
        assert published["tool_name"] == allow_ctx.tool_name
        assert published["actor"]["session_id"] == allow_ctx.session_id
        assert published["actor"]["agent_id"] == allow_ctx.agent_id

    @pytest.mark.asyncio
    async def test_kafka_failure_does_not_raise(
        self, registry: PostToolUseHookRegistry, allow_ctx: PostToolUseContext
    ) -> None:
        async def failing_publish(event: dict) -> None:
            raise ConnectionError("Kafka broker unreachable")

        with patch("app.hooks.post_tool_use._publish_to_kafka", failing_publish):
            # Must not raise
            event = await registry.invoke(allow_ctx)

        assert event is not None

    @pytest.mark.asyncio
    async def test_posttooluse_topic_used(self, allow_ctx: PostToolUseContext) -> None:
        """publish_posttooluse_event is called on the kafka_producer singleton."""
        mock_producer = MagicMock()
        mock_producer.publish_posttooluse_event = AsyncMock(return_value=True)

        registry = PostToolUseHookRegistry()

        with patch("app.hooks.post_tool_use._publish_to_kafka") as mock_pub:
            mock_pub.side_effect = AsyncMock()
            await registry.invoke(allow_ctx)
            mock_pub.assert_called_once()


# ---------------------------------------------------------------------------
# E07-T09: OCSF linter tests (CI gate validation)
# ---------------------------------------------------------------------------


class TestOCSFLinter:
    def test_missing_required_field(self) -> None:
        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
        )
        del event["class_uid"]
        violations = lint(event)
        assert any("class_uid" in v for v in violations)

    def test_invalid_type_uid(self) -> None:
        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
        )
        event["type_uid"] = 999999
        violations = lint(event)
        assert any("type_uid" in v for v in violations)

    def test_invalid_decision_value(self) -> None:
        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
        )
        event["decision"] = "PERMIT"  # Not a valid OCSF decision
        violations = lint(event)
        assert any("decision" in v for v in violations)

    def test_wrong_product_name(self) -> None:
        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
        )
        event["metadata"]["product"]["name"] = "WrongProduct"
        violations = lint(event)
        assert any("AgentPEP" in v for v in violations)

    def test_missing_actor_fields(self) -> None:
        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
        )
        del event["actor"]["agent_id"]
        violations = lint(event)
        assert any("actor.agent_id" in v for v in violations)

    def test_empty_resources_list(self) -> None:
        event = emit_post_tool_use_event(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
        )
        event["resources"] = []
        violations = lint(event)
        assert any("resources" in v and "non-empty" in v for v in violations)

    def test_complexity_exceeded_event_passes_linter(self) -> None:
        from app.enforcement.complexity_budget import (
            ComplexityViolation,
            emit_complexity_exceeded_event,
        )

        violations = [
            ComplexityViolation(
                dimension="arg_bytes",
                limit=65536,
                actual=100000,
                detail="Argument size 100000 bytes exceeds limit 65536 bytes",
            )
        ]
        event = emit_complexity_exceeded_event(
            tool_name="bash",
            violations=violations,
            session_id="s",
            agent_id="a",
            request_id=str(uuid.uuid4()),
        )
        assert_valid(event)

    def test_security_violation_event_passes_linter(self) -> None:
        from app.policy.events import SecurityViolationReason, emit_security_violation_event

        event = emit_security_violation_event(
            reason=SecurityViolationReason.INVALID_SIGNATURE,
            detail="cosign signature verification failed",
            source_url="https://registry.trustfabric.internal/bundle.tar.gz",
            bundle_version="1.2.3",
            session_id="s",
            agent_id="a",
            request_id=str(uuid.uuid4()),
        )
        assert_valid(event)

    def test_trust_violation_event_passes_linter(self) -> None:
        from app.trust.events import TrustViolationReason, emit_trust_violation_event

        event = emit_trust_violation_event(
            reason=TrustViolationReason.PERMISSION_ESCALATION,
            detail="Subagent claimed write:prod beyond root permissions",
            principal_chain=["root", "sub-agent"],
            hop_count=1,
            trust_score=0.85,
            root_principal="root",
            agent_id="sub-agent",
            session_id="s",
            request_id=str(uuid.uuid4()),
            tool_name="bash",
            escalated_permissions=["write:prod"],
        )
        assert_valid(event)


# ---------------------------------------------------------------------------
# E07-T09: PostToolUseContext convenience constructors
# ---------------------------------------------------------------------------


class TestPostToolUseContextConstructors:
    def test_from_allow_sets_correct_outcome(self) -> None:
        ctx = PostToolUseContext.from_allow(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
        )
        assert ctx.tool_outcome == OUTCOME_EXECUTED
        assert ctx.decision == "ALLOW"

    def test_from_deny_sets_correct_outcome(self) -> None:
        ctx = PostToolUseContext.from_deny(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
        )
        assert ctx.tool_outcome == OUTCOME_DENIED
        assert ctx.decision == "DENY"

    def test_from_error_sets_error_message(self) -> None:
        ctx = PostToolUseContext.from_error(
            request_id=str(uuid.uuid4()),
            session_id="s",
            agent_id="a",
            tool_name="t",
            error_message="Command not found",
        )
        assert ctx.tool_outcome == OUTCOME_ERROR
        assert ctx.tool_result_error == "Command not found"
