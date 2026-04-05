"""AgentPEP SDK — Deterministic authorization for AI agent systems."""

__version__ = "1.0.0"

from agentpep.client import AgentPEPClient
from agentpep.decorator import enforce
from agentpep.models import (
    PolicyDecision,
    PolicyDecisionResponse,
    TaintLevel,
    TaintNodeResponse,
    TaintSource,
    ToolCallRequest,
)
from agentpep.tamper_detection import TamperDetector, tamper_detector

__all__ = [
    "AgentPEPClient",
    "enforce",
    "PolicyDecision",
    "PolicyDecisionResponse",
    "TaintLevel",
    "TaintNodeResponse",
    "TaintSource",
    "ToolCallRequest",
    "TamperDetector",
    "tamper_detector",
]
