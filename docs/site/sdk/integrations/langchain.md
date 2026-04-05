# LangChain Integration

Wrap LangChain tools with AgentPEP policy enforcement.

## Installation

```bash
pip install agentpep-sdk[langchain]
```

## AgentPEPToolWrapper

Wraps any LangChain `BaseTool` to enforce policy before execution:

```python
from agentpep import AgentPEPClient
from agentpep.integrations.langchain import AgentPEPToolWrapper

client = AgentPEPClient(base_url="http://localhost:8000")

# Wrap each tool
safe_tools = [
    AgentPEPToolWrapper(
        wrapped_tool=tool,
        client=client,
        agent_id="lc-agent",
    )
    for tool in raw_tools
]

# Use with any LangChain agent
from langchain.agents import create_react_agent
agent = create_react_agent(llm, safe_tools, prompt)
```

## How It Works

1. When the agent calls a wrapped tool, `AgentPEPToolWrapper` intercepts the call
2. It sends the tool name and arguments to AgentPEP for evaluation
3. If ALLOW: the original tool executes normally
4. If DENY: raises `PolicyDeniedError` (the agent sees the error and can retry differently)

## Custom Tool Name Mapping

```python
wrapper = AgentPEPToolWrapper(
    wrapped_tool=tool,
    client=client,
    agent_id="lc-agent",
    tool_name_override="custom_tool_name",  # Override the tool name sent to AgentPEP
)
```
