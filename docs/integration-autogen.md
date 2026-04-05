# AutoGen / AutoGen Studio Integration Guide

AgentPEP integrates with [AutoGen](https://github.com/microsoft/autogen) multi-agent conversations via a speaker hook that intercepts tool calls before execution. An AutoGen Studio plugin wrapper is also provided.

## Installation

```bash
pip install agentpep-sdk[autogen]
```

## Quick Start — Speaker Hook

```python
import autogen
from agentpep import AgentPEPClient
from agentpep.integrations.autogen import AgentPEPSpeakerHook

# 1. Create the AgentPEP client
client = AgentPEPClient(
    base_url="http://localhost:8000",
    api_key="your-api-key",
)

# 2. Create the speaker hook
hook = AgentPEPSpeakerHook(client=client)

# 3. Create AutoGen agents
assistant = autogen.AssistantAgent(
    name="assistant",
    llm_config={"model": "gpt-4"},
)
user_proxy = autogen.UserProxyAgent(
    name="user_proxy",
    human_input_mode="NEVER",
)

# 4. Register the hook on the assistant
assistant.register_reply(
    trigger=autogen.Agent,
    reply_func=hook.intercept_reply,
    position=0,  # Run before other reply functions
)

# 5. Tool calls are now policy-enforced
user_proxy.initiate_chat(assistant, message="Send an email to admin@company.com")
```

## How It Works

The `AgentPEPSpeakerHook` inspects each AutoGen message for tool calls. It supports:

- **OpenAI-style `tool_calls`**: List of `{function: {name, arguments}}` objects
- **Legacy `function_call`**: Single `{name, arguments}` object

For each tool call found, the hook evaluates it against AgentPEP policy. If any call receives a `DENY` or `ESCALATE` decision, a `PolicyDeniedError` is raised immediately, preventing execution.

## Configuration Options

### AgentPEPSpeakerHook

| Parameter              | Type                                | Default              | Description |
|-----------------------|-------------------------------------|----------------------|-------------|
| `client`              | `AgentPEPClient`                    | required             | AgentPEP client instance |
| `agent_id_fn`         | `Callable[[Agent], str] \| None`    | `agent.name`         | Extracts agent_id from the speaker |
| `session_id`          | `str`                               | `"default"`          | Session identifier |
| `delegation_chain_fn` | `Callable[[], list[str]] \| None`   | `None`               | Returns current delegation chain |

### Custom Agent ID

Map AutoGen agent names to AgentPEP agent IDs:

```python
hook = AgentPEPSpeakerHook(
    client=client,
    agent_id_fn=lambda agent: f"autogen-{agent.name}",
)
```

### Delegation Chain for Multi-Agent Workflows

Track the delegation chain across a group chat for confused-deputy detection:

```python
conversation_chain: list[str] = []

def track_chain() -> list[str]:
    return conversation_chain

hook = AgentPEPSpeakerHook(
    client=client,
    delegation_chain_fn=track_chain,
)

# Update the chain as agents speak
conversation_chain.append("orchestrator")
conversation_chain.append("researcher")
```

## Sync Usage

For synchronous AutoGen workflows:

```python
# Directly check a message (sync)
hook = AgentPEPSpeakerHook(client=client)
responses = hook.check_message_sync(speaker=agent, message=message_dict)
```

## AutoGen Studio Plugin (APEP-162)

The `AgentPEPStudioPlugin` wraps the speaker hook for AutoGen Studio workflows:

```python
from agentpep import AgentPEPClient
from agentpep.integrations.autogen import AgentPEPStudioPlugin

client = AgentPEPClient(base_url="http://localhost:8000")
plugin = AgentPEPStudioPlugin(client=client, session_id="studio-session")

# Register on all agents in a workflow
plugin.register_agents([assistant, coder, reviewer])

# Check which agents are protected
print(plugin.registered_agents)  # ["assistant", "coder", "reviewer"]
```

### Plugin Metadata

| Property      | Value |
|--------------|-------|
| `name`       | AgentPEP Policy Enforcement |
| `description`| Enforces deterministic RBAC, taint tracking, and confused-deputy detection |
| `version`    | 0.1.0 |

### Manual Evaluation

For Studio workflows needing explicit checks outside the reply flow:

```python
response = await plugin.evaluate_tool_call(
    agent_id="studio-agent",
    tool_name="send_email",
    tool_args={"to": "ceo@company.com"},
    delegation_chain=["user-agent", "studio-agent"],
)
print(response.decision)  # ALLOW, DENY, ESCALATE, etc.
```

## Confused-Deputy Detection

AgentPEP detects confused-deputy attacks in AutoGen multi-agent conversations:

1. **Agent A** (low-privilege) sends a crafted message to **Agent B** (high-privilege)
2. **Agent B** attempts to call a privileged tool on Agent A's behalf
3. AgentPEP checks the delegation chain and **denies** the call

```python
# The delegation chain reveals the authority path
hook = AgentPEPSpeakerHook(
    client=client,
    delegation_chain_fn=lambda: ["untrusted-web-agent", "privileged-db-agent"],
)

# When privileged-db-agent tries to call delete_user based on
# untrusted-web-agent's request, AgentPEP will DENY it
```

## Error Handling

```python
from agentpep.exceptions import PolicyDeniedError

try:
    user_proxy.initiate_chat(assistant, message="Delete all user records")
except PolicyDeniedError as e:
    print(f"Blocked: {e.tool_name} — {e.reason}")
    print(f"Decision: {e.decision}")
```

## Fail-Open Mode

```python
client = AgentPEPClient(
    base_url="http://localhost:8000",
    fail_open=True,  # Allow calls if AgentPEP server is unreachable
)
```
