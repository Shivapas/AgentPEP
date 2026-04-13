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


class PolicyDeferredError(AgentPEPError):
    """Raised when a tool call is deferred pending review (DEFER decision)."""

    def __init__(
        self,
        tool_name: str,
        reason: str = "",
        defer_timeout_s: int = 60,
    ):
        self.tool_name = tool_name
        self.reason = reason
        self.defer_timeout_s = defer_timeout_s
        super().__init__(
            f"Policy DEFER for tool '{tool_name}': {reason} "
            f"(timeout={defer_timeout_s}s)"
        )


class PolicyModifiedError(AgentPEPError):
    """Raised when tool arguments are modified by policy (MODIFY decision)."""

    def __init__(
        self,
        tool_name: str,
        original_args: dict | None = None,
        modified_args: dict | None = None,
        reason: str = "",
    ):
        self.tool_name = tool_name
        self.original_args = original_args or {}
        self.modified_args = modified_args or {}
        self.reason = reason
        super().__init__(
            f"Policy MODIFY for tool '{tool_name}': {reason}"
        )
