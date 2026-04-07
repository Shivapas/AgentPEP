"""gRPC Intercept service for AgentPEP.

Provides the same policy evaluation as the REST endpoint but over gRPC.
Uses grpcio for the server implementation with generated protobuf stubs.
"""

import logging
import pathlib

import grpc
from grpc_reflection.v1alpha import reflection

from app.core.config import settings
from app.generated import intercept_pb2, intercept_pb2_grpc
from app.models.policy import Decision, ToolCallRequest
from app.services.policy_evaluator import policy_evaluator

logger = logging.getLogger(__name__)

# Map proto enum to internal Decision enum
_DECISION_TO_PROTO = {
    Decision.ALLOW: intercept_pb2.ALLOW,
    Decision.DENY: intercept_pb2.DENY,
    Decision.ESCALATE: intercept_pb2.ESCALATE,
    Decision.DRY_RUN: intercept_pb2.DRY_RUN,
    Decision.TIMEOUT: intercept_pb2.TIMEOUT,
}


class InterceptServicer(intercept_pb2_grpc.InterceptServiceServicer):
    """gRPC servicer that delegates to the PolicyEvaluator."""

    async def Intercept(  # noqa: N802
        self,
        request: intercept_pb2.ToolCallRequest,
        context: grpc.aio.ServicerContext,
    ) -> intercept_pb2.PolicyDecision:
        """Evaluate a tool call request via gRPC."""
        # Convert proto request to internal model
        tool_call = ToolCallRequest(
            request_id=request.request_id or None,
            session_id=request.session_id,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            tool_args=dict(request.tool_args),
            delegation_chain=list(request.delegation_chain),
            dry_run=request.dry_run,
        )

        # Evaluate using the shared policy evaluator
        result = await policy_evaluator.evaluate(tool_call)

        # Convert response to proto
        return intercept_pb2.PolicyDecision(
            request_id=str(result.request_id),
            decision=_DECISION_TO_PROTO.get(
                result.decision, intercept_pb2.DECISION_UNSPECIFIED
            ),
            matched_rule_id=str(result.matched_rule_id) if result.matched_rule_id else "",
            risk_score=result.risk_score,
            taint_flags=result.taint_flags,
            reason=result.reason,
            escalation_id=str(result.escalation_id) if result.escalation_id else "",
            latency_ms=result.latency_ms,
        )


async def start_grpc_server(port: int = 50051) -> grpc.aio.Server:
    """Start the async gRPC server with optional TLS."""
    server = grpc.aio.server()
    intercept_pb2_grpc.add_InterceptServiceServicer_to_server(
        InterceptServicer(), server
    )

    # Enable server reflection for debugging / grpcurl
    service_names = (
        intercept_pb2.DESCRIPTOR.services_by_name["InterceptService"].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(service_names, server)

    listen_addr = f"[::]:{port}"

    # Use TLS if cert and key paths are configured
    if settings.grpc_tls_cert_path and settings.grpc_tls_key_path:
        cert = pathlib.Path(settings.grpc_tls_cert_path).read_bytes()
        key = pathlib.Path(settings.grpc_tls_key_path).read_bytes()
        credentials = grpc.ssl_server_credentials([(key, cert)])
        server.add_secure_port(listen_addr, credentials)
        logger.info("gRPC InterceptService listening on %s (TLS)", listen_addr)
    else:
        if not settings.debug:
            logger.warning(
                "gRPC server running WITHOUT TLS. Set grpc_tls_cert_path and "
                "grpc_tls_key_path for production use."
            )
        server.add_insecure_port(listen_addr)
        logger.info("gRPC InterceptService listening on %s (insecure)", listen_addr)

    await server.start()
    return server
