# AgentPEP — CrewAI Integration Guide

## Overview

AgentPEP integrates with [CrewAI](https://docs.crewai.com/) to enforce
authorization policies on tool calls made by crew agents.  Every tool
invocation is checked against the AgentPEP Intercept API before the
underlying tool executes.

Key capabilities:

- **Tool-level enforcement** — wrap any CrewAI `BaseTool` with policy checks
- **Multi-agent role mapping** — map CrewAI agent roles to AgentPEP policy roles
- **Confused-deputy detection** — pass delegation chains for multi-agent validation
- **Batch wrapping** — `wrap_crew_tools()` helper for wrapping entire toolsets

## Installation

```bash
pip install agentpep-sdk[crewai]
```

## Quick Start

### 1. Wrap a Single Tool

```python
from agentpep import AgentPEPClient
from agentpep.integrations.crewai import AgentPEPCrewAITool

client = AgentPEPClient(base_url="http://localhost:8000", api_key="...")

# Wrap a CrewAI tool
safe_tool = AgentPEPCrewAITool(
    wrapped_tool=my_search_tool,
    client=client,
    agent_id="crew-researcher",
)

# Use in a CrewAI agent
researcher = Agent(
    role="Researcher",
    tools=[safe_tool],
    ...
)
```

### 2. Wrap All Tools at Once

```python
from agentpep.integrations.crewai import wrap_crew_tools

raw_tools = [search_tool, file_tool, email_tool]
safe_tools = wrap_crew_tools(
    raw_tools,
    client,
    agent_id="crew-researcher",
    session_id="session-123",
)

researcher = Agent(role="Researcher", tools=safe_tools, ...)
```

## Multi-Agent Role Mapping (APEP-166)

In a CrewAI crew with multiple agents (e.g. Researcher, Writer, Reviewer),
each agent has a different trust level.  Use `CrewAIRoleMapping` to map
CrewAI role strings to AgentPEP policy role identifiers:

```python
from agentpep.integrations.crewai import CrewAIRoleMapping, wrap_crew_tools

role_mapping = CrewAIRoleMapping(
    role_map={
        "Researcher": "crewai-researcher",
        "Writer": "crewai-writer",
        "Reviewer": "crewai-reviewer",
    },
    default_role="crewai-default",
)

# Researcher gets its own policy scope
researcher_tools = wrap_crew_tools(
    raw_tools,
    client,
    agent_id="crew-default",
    role_mapping=role_mapping,
    crewai_role="Researcher",
)

# Writer gets a different policy scope
writer_tools = wrap_crew_tools(
    raw_tools,
    client,
    agent_id="crew-default",
    role_mapping=role_mapping,
    crewai_role="Writer",
)
```

The role mapping resolves the `agent_id` sent to AgentPEP.  Policy rules
can then differentiate between `crewai-researcher` (allowed to search the
web) and `crewai-writer` (allowed to write files but not search).

### Dynamic Registration

```python
role_mapping.register("Editor", "crewai-editor")
print(role_mapping.mappings)
# {"Researcher": "crewai-researcher", "Writer": "crewai-writer", ...}
```

## Confused-Deputy Detection (APEP-167)

When one crew agent delegates work to another, pass the delegation chain
so AgentPEP can validate authority at each hop:

```python
safe_tool = AgentPEPCrewAITool(
    wrapped_tool=file_write_tool,
    client=client,
    agent_id="crew-writer",
    delegation_chain=["crew-manager", "crew-writer"],
)
```

AgentPEP validates that:
1. The first hop has legitimate authority
2. Each hop's granted tools are a subset of the previous hop
3. The chain depth does not exceed the configured maximum

If validation fails, the tool call is denied or escalated.

## Error Handling

```python
from agentpep.exceptions import PolicyDeniedError

try:
    result = safe_tool._run(query="sensitive data")
except PolicyDeniedError as e:
    print(f"Tool '{e.tool_name}' denied: {e.reason}")
    # decision is "DENY" or "ESCALATE"
```

## Configuration Summary

| Parameter | Default | Description |
|-----------|---------|-------------|
| `wrapped_tool` | — | The CrewAI `BaseTool` to wrap |
| `client` | — | `AgentPEPClient` instance |
| `agent_id` | — | Agent ID for policy evaluation |
| `session_id` | `"default"` | Session identifier |
| `role_mapping` | `None` | `CrewAIRoleMapping` for multi-agent crews |
| `crewai_role` | `None` | CrewAI role string (used with `role_mapping`) |
| `delegation_chain` | `None` | Delegation chain for confused-deputy detection |
