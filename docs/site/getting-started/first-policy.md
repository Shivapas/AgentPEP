# Your First Policy

This guide walks through creating a real-world policy configuration for an
AI agent that handles customer support tasks.

## Scenario

You have a customer support agent that can:

- Read customer records
- Send emails to customers
- Update customer profiles
- **Should never** delete records or access financial data

## Step 1: Define the Default Deny Rule

AgentPEP is deny-by-default, but it's good practice to have an explicit catch-all:

```json
{
  "name": "default-deny-all",
  "agent_role": ["*"],
  "tool_pattern": "*",
  "action": "DENY",
  "priority": 999
}
```

## Step 2: Allow Read Operations

```json
{
  "name": "allow-customer-reads",
  "agent_role": ["support-agent"],
  "tool_pattern": "read_customer_*",
  "action": "ALLOW",
  "priority": 10
}
```

## Step 3: Allow Emails with Domain Restriction

```json
{
  "name": "allow-customer-emails",
  "agent_role": ["support-agent"],
  "tool_pattern": "send_email",
  "action": "ALLOW",
  "priority": 20,
  "arg_validators": [
    {
      "arg_name": "to",
      "regex_pattern": "^[^@]+@(company\\.com|customer-domain\\.com)$"
    }
  ]
}
```

## Step 4: Allow Profile Updates with Risk Check

```json
{
  "name": "allow-profile-updates",
  "agent_role": ["support-agent"],
  "tool_pattern": "update_customer_profile",
  "action": "ALLOW",
  "risk_threshold": 0.5,
  "priority": 30
}
```

## Step 5: Explicitly Block Dangerous Operations

```json
{
  "name": "block-financial-access",
  "agent_role": ["support-agent"],
  "tool_pattern": "*financial*",
  "action": "DENY",
  "priority": 1
}
```

```json
{
  "name": "block-delete-operations",
  "agent_role": ["support-agent"],
  "tool_pattern": "delete_*",
  "action": "DENY",
  "priority": 1
}
```

## Step 6: Escalate Suspicious Patterns

```json
{
  "name": "escalate-bulk-operations",
  "agent_role": ["support-agent"],
  "tool_pattern": "bulk_*",
  "action": "ESCALATE",
  "priority": 5
}
```

## Step 7: Test with Dry Run

Before enforcing, test your policies in dry-run mode:

```python
from agentpep import AgentPEPClient

client = AgentPEPClient(base_url="http://localhost:8000")

# Test each scenario
test_cases = [
    ("read_customer_profile", {"customer_id": "123"}),
    ("send_email", {"to": "user@company.com", "body": "Hi"}),
    ("delete_customer", {"customer_id": "123"}),
    ("access_financial_records", {"account_id": "456"}),
]

for tool_name, args in test_cases:
    resp = client.evaluate_sync(
        agent_id="support-agent",
        tool_name=tool_name,
        tool_args=args,
        dry_run=True,
    )
    print(f"{tool_name}: {resp.decision} (reason: {resp.reason})")
```

Expected output:

```
read_customer_profile: ALLOW (matched: allow-customer-reads)
send_email: ALLOW (matched: allow-customer-emails)
delete_customer: DENY (matched: block-delete-operations)
access_financial_records: DENY (matched: block-financial-access)
```

## Using the Offline Evaluator for Local Testing

```python
from agentpep.offline import OfflineEvaluator, OfflineRule
from agentpep.models import PolicyDecision

evaluator = OfflineEvaluator(rules=[
    OfflineRule(tool_pattern="read_*", action=PolicyDecision.ALLOW, priority=10),
    OfflineRule(tool_pattern="send_email", action=PolicyDecision.ALLOW, priority=20),
    OfflineRule(tool_pattern="delete_*", action=PolicyDecision.DENY, priority=1),
    OfflineRule(tool_pattern="*financial*", action=PolicyDecision.DENY, priority=1),
    OfflineRule(tool_pattern="*", action=PolicyDecision.DENY, priority=999),
])

result = evaluator.evaluate(agent_id="test", tool_name="read_customer_profile")
assert result.decision == PolicyDecision.ALLOW
```
