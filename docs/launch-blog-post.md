# Introducing AgentPEP: Deterministic Authorization for the Age of AI Agents

*Published: April 3, 2026*

---

AI agents are no longer experimental. Enterprises are deploying LLM-powered
systems that autonomously browse the web, query databases, call APIs, write
code, and orchestrate other agents. These agents are making thousands of
decisions per minute — and every one of those decisions is a potential security
event.

The question is no longer "should we deploy AI agents?" but "how do we control
what they do?"

Today, we are releasing **AgentPEP 1.0** — the first deterministic
authorization engine built specifically for AI agent systems.

---

## The Gap in Agent Security

Current approaches to AI agent security fall into two categories, and both have
fundamental limitations:

**Prompt-level guardrails** inspect what goes *into* the LLM. They can filter
obvious malicious prompts, but they cannot prevent a well-crafted prompt
injection from producing a tool call that looks perfectly legitimate. The attack
surface is the LLM itself, and guardrails that operate at the prompt layer share
that attack surface.

**Behavioral monitoring** watches what agents *did* and flags anomalies after
the fact. This is valuable for detection but useless for prevention. By the time
the monitor fires, the database query has already executed, the API call has
already been made, and the data has already been exfiltrated.

What's missing is a **pre-execution enforcement layer** that evaluates every
action *before* it happens, using deterministic logic that cannot be influenced
by the LLM.

---

## How AgentPEP Works

AgentPEP operates at the execution boundary. When an agent decides to call a
tool — read a file, query an API, delegate to another agent — the request
passes through AgentPEP before execution. AgentPEP evaluates the request
against a layered policy stack and returns an explicit ALLOW or DENY decision.

```
LLM Decision → AgentPEP (ALLOW/DENY) → Tool Execution
```

The critical design principle: **AgentPEP never processes LLM output as
instructions.** It evaluates structured metadata — who is calling, what tool,
with what arguments, in what context — against static and risk-adaptive
policies. This means it cannot be bypassed by prompt injection, jailbreaking, or
any other LLM-level attack.

### Four Layers of Protection

1. **Role-Based Access Control:** Define which agents can use which tools, on
   which resources, during which time windows. Policies are expressed in
   conventional, auditable rule definitions — not natural language.

2. **Taint Tracking:** Every piece of data that enters the agent system is
   labeled with its sensitivity classification. As data flows through tool
   calls, taint propagates automatically. Sensitive data cannot cross trust
   boundaries without passing through an explicit sanitisation gate.

3. **Confused-Deputy Detection:** When Agent A asks Agent B to perform an
   action, AgentPEP verifies that the full delegation chain has sufficient
   privileges. This prevents the classic confused-deputy attack where a
   low-privilege agent tricks a high-privilege agent into acting on its behalf.

4. **Risk-Adaptive Scoring:** Static rules are necessary but not sufficient.
   AgentPEP also computes a real-time risk score based on agent reputation,
   request sensitivity, environmental signals, and behavioral patterns. High-risk
   requests can trigger additional approval requirements or outright denial.

---

## Performance That Doesn't Compromise Security

A policy engine is only useful if it's fast enough to sit in the critical path.
AgentPEP is designed for real-time enforcement:

- **3.2 ms** median decision latency (p50)
- **18 ms** tail latency (p99)
- **12,400** decisions per second on a single node
- **97.3%** rule cache hit ratio under production workloads

These numbers mean AgentPEP adds negligible overhead to agent workflows while
providing deterministic security enforcement on every action.

---

## Getting Started

### Python SDK

```bash
pip install agentpep-sdk
```

```python
from agentpep import AgentPEPClient

client = AgentPEPClient(base_url="https://agentpep.example.com")
decision = await client.check(
    agent_id="research-agent",
    tool="database.query",
    resource="customers",
    action="read",
)

if decision.allowed:
    result = await database.query("SELECT * FROM customers")
```

### LangChain Integration

```python
from agentpep.integrations.langchain import AgentPEPToolWrapper

secure_tool = AgentPEPToolWrapper(tool=my_tool, client=client)
agent = initialize_agent(tools=[secure_tool], llm=llm)
```

### LangGraph Integration

```python
from agentpep.integrations.langgraph import agentpep_guardrail_node

graph.add_node("policy_check", agentpep_guardrail_node(client=client))
graph.add_edge("agent_decision", "policy_check")
graph.add_edge("policy_check", "tool_execution")
```

---

## Availability and Pricing

AgentPEP 1.0.0 is available today:

- **Developer tier (free):** Up to 50K decisions/month for evaluation and
  development.
- **Team ($499/mo):** Up to 500K decisions/month with email support.
- **Business ($2,499/mo):** Up to 5M decisions/month with priority support and
  SOC 2 compliance.
- **Enterprise (custom):** Unlimited decisions with dedicated support and
  on-premises deployment options.

AgentPEP is available on **AWS Marketplace** and **GCP Marketplace** with a
30-day free trial on the Business tier.

---

## What's Next

AgentPEP 1.0 is the foundation. Our roadmap includes:

- **Policy editing UI** in the web dashboard (v1.1)
- **Taint graph visualisation** via Grafana plugin
- **Multi-region federation** for global deployments
- **OpenAI and Anthropic agent framework** native integrations
- **Policy-as-code** with Git-based version control and CI/CD integration

We believe that deterministic authorization is table stakes for enterprise AI
agent deployments. As agents become more capable and more autonomous, the need
for hard security boundaries only grows.

AgentPEP is that boundary.

---

**Try AgentPEP today:** Visit the [documentation](docs/sdk-quickstart.md) to
get started, or launch a free trial on AWS Marketplace or GCP Marketplace.

**Questions?** Reach us at sales@trustfabric.example.com.

---

*AgentPEP · TrustFabric Portfolio · © 2026*
