# PRESS RELEASE

## TrustFabric Launches AgentPEP: The First Deterministic Authorization Engine for AI Agent Systems

**FOR IMMEDIATE RELEASE**
**Date:** April 3, 2026

---

**San Francisco, CA** — TrustFabric today announced the general availability of
AgentPEP (Agent Policy Enforcement Point), the first deterministic runtime
authorization engine purpose-built for AI agent systems. AgentPEP provides
enterprises with a hard security boundary that intercepts every AI agent action
and enforces policy decisions that cannot be bypassed by adversarial prompt
engineering.

### The Problem

As enterprises deploy LLM-powered agents that autonomously execute tool calls,
API requests, and inter-agent delegations, existing security approaches fall
short. Prompt inspection gateways operate on LLM inputs and can be circumvented.
Behavioral monitoring systems are reactive and post-hoc. Neither provides the
deterministic, pre-execution enforcement that enterprise security teams require.

### The Solution

AgentPEP sits at the execution boundary — after the LLM decides but before any
action is taken — and evaluates every tool invocation against a layered policy
stack:

- **Role-Based Access Control (RBAC):** Fine-grained permissions scoped to
  agents, tools, resources, and time windows.
- **Taint Tracking:** Session-scoped data flow tracking that prevents sensitive
  data from crossing trust boundaries without explicit sanitisation.
- **Confused-Deputy Detection:** Delegation chain analysis that blocks privilege
  escalation when agents invoke other agents.
- **Risk-Adaptive Scoring:** Dynamic risk assessment that adjusts decisions
  based on real-time context signals.

### Key Metrics

- **Sub-5ms** median decision latency
- **10,000+** policy decisions per second per node
- **99.95%** monthly uptime SLA
- **Zero** false negatives on policy enforcement (deterministic, not
  probabilistic)

### Availability

AgentPEP 1.0.0 is available today on **AWS Marketplace** and **GCP
Marketplace**, with a free Developer tier for evaluation. The open-source Python
SDK supports LangChain, LangGraph, and any custom agent framework via a single
REST or gRPC API call.

### Quotes

> "Enterprise AI teams are deploying agents that can read databases, call APIs,
> and orchestrate other agents — but they're doing it without any deterministic
> security boundary. AgentPEP fills that critical gap."
>
> — *CEO, TrustFabric*

> "We evaluated prompt-level guardrails and behavioural monitoring, but neither
> gave us the hard enforcement guarantees our security team requires. AgentPEP
> is the only solution that operates on structured tool-call metadata rather
> than LLM output, which means it cannot be prompt-injected."
>
> — *CISO, Fortune 500 Financial Services Company*

### About TrustFabric

TrustFabric builds deterministic security infrastructure for AI-native
enterprises. The company's products enforce hard policy boundaries at runtime,
ensuring that AI agent systems operate within defined security, compliance, and
governance constraints.

### Contact

**Media:** press@trustfabric.example.com
**Sales:** sales@trustfabric.example.com
**Website:** https://trustfabric.example.com/agentpep

---

*AgentPEP · TrustFabric Portfolio · © 2026*
