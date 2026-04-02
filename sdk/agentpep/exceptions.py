"""AgentPEP SDK exceptions."""


class AgentPEPError(Exception):
    """Base exception for AgentPEP SDK."""


class PolicyDeniedError(AgentPEPError):
    """Raised when a tool call is denied by policy."""

    def __init__(self, tool_name: str, reason: str = "", decision: str = "DENY"):
        self.tool_name = tool_name
        self.reason = reason
        self.decision = decision
        super().__init__(f"Policy {decision} for tool '{tool_name}': {reason}")


class AgentPEPConnectionError(AgentPEPError):
    """Raised when the SDK cannot connect to the AgentPEP server."""


class AgentPEPTimeoutError(AgentPEPError):
    """Raised when a request to AgentPEP times out."""
