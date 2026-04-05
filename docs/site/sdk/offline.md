# Offline Mode

Evaluate policies locally without a running AgentPEP server. Ideal for
development, testing, and CI pipelines.

## Usage

```python
from agentpep.offline import OfflineEvaluator, OfflineRule
from agentpep.models import PolicyDecision

evaluator = OfflineEvaluator(rules=[
    OfflineRule(tool_pattern="read_*", action=PolicyDecision.ALLOW, priority=10),
    OfflineRule(tool_pattern="write_*", action=PolicyDecision.ALLOW, priority=20),
    OfflineRule(tool_pattern="delete_*", action=PolicyDecision.DENY, priority=10),
    OfflineRule(tool_pattern="*", action=PolicyDecision.DENY, priority=999),
])

response = evaluator.evaluate(agent_id="dev", tool_name="read_file")
assert response.decision == PolicyDecision.ALLOW
```

## Loading Rules from Dicts

```python
rules = [
    {"tool_pattern": "read_*", "action": "ALLOW", "priority": 10},
    {"tool_pattern": "delete_*", "action": "DENY", "priority": 5},
    {"tool_pattern": "*", "action": "DENY", "priority": 999},
]
evaluator = OfflineEvaluator.from_dict_list(rules)
```

## With @enforce Decorator

```python
from agentpep import enforce

@enforce(evaluator, agent_id="test-agent")
def read_file(path: str) -> str:
    return open(path).read()

# Works without any network calls
result = read_file("/tmp/test.txt")
```

## Use Cases

- **Unit tests** — Test policy logic without infrastructure
- **CI pipelines** — Validate policies in automated tests
- **Local development** — Prototype policies before deploying
- **Policy migration** — Test new rules against existing tool calls
