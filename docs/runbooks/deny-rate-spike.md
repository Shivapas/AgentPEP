# Runbook: AgentPEP_DenyRateSpike

**Alert:** `AgentPEP_DenyRateSpike`
**Severity:** Critical
**Team:** Platform

## Symptoms

- The `agentpep_decision_total{decision="DENY"}` rate over 5 minutes exceeds 5× the rolling 1-hour baseline.
- Agents may report widespread tool call failures.
- End-user workflows may stall if agents cannot execute tools.

## Possible Causes

1. **Policy misconfiguration** — a recently deployed rule is overly broad and denying legitimate calls.
2. **Burst of unauthorized tool calls** — an agent or integration is sending tool calls outside its permitted scope.
3. **Attack / prompt injection** — a compromised agent is issuing tool calls that policy correctly blocks.
4. **Role change** — RBAC role updates removed permissions from agents still relying on them.

## Diagnosis Steps

1. **Identify the top agents and tools being denied:**
   ```promql
   topk(10, sum(rate(agentpep_decision_total{decision="DENY"}[5m])) by (agent_id, tool_name))
   ```

2. **Check recent policy rule changes:**
   ```bash
   # Query MongoDB for recently updated rules
   mongosh agentpep --eval 'db.policy_rules.find({updated_at: {$gte: new Date(Date.now() - 3600000)}}).sort({updated_at: -1})'
   ```

3. **Review audit logs for the top denied agent:**
   ```bash
   mongosh agentpep --eval 'db.audit_decisions.find({decision: "DENY"}).sort({timestamp: -1}).limit(20)'
   ```

4. **Check for taint-related denials** (QUARANTINE flags in audit logs).

5. **Check for confused-deputy denials** (reason containing "Confused-deputy check").

## Remediation

- **Policy misconfiguration:** Revert the offending rule or adjust its `tool_pattern` / `agent_role` scope.
- **Unauthorized agent:** Disable the agent profile via `db.agent_profiles.updateOne({agent_id: "<id>"}, {$set: {enabled: false}})`.
- **Attack:** Escalate to the security team. Check security_alerts collection. Consider enabling tighter taint checking.
- **Role change:** Restore the previous RBAC role permissions or update agent profiles to use the correct roles.

## Escalation

If the root cause is unclear after 15 minutes, escalate to the AgentPEP on-call lead.
