# Runbook: AgentPEP_EscalationBacklog

**Alert:** `AgentPEP_EscalationBacklog`
**Severity:** Warning
**Team:** Platform

## Symptoms

- The `agentpep_escalation_backlog` gauge exceeds 10 for more than 5 minutes.
- Tool calls requiring human approval are queueing up.
- Agents waiting on ESCALATE decisions may timeout, degrading user experience.

## Possible Causes

1. **Insufficient human reviewers** — the human-in-the-loop team is understaffed or unavailable.
2. **Taint escalation flood** — many UNTRUSTED taint nodes are triggering escalation on privileged tools.
3. **Confused-deputy escalation flood** — implicit delegation detections are generating ESCALATE decisions.
4. **Policy misconfiguration** — rules are overly conservative, escalating calls that should be ALLOW.

## Diagnosis Steps

1. **Check escalation rate trend:**
   ```promql
   sum(rate(agentpep_decision_total{decision="ESCALATE"}[5m])) by (agent_id, tool_name)
   ```

2. **Review pending escalations in audit log:**
   ```bash
   mongosh agentpep --eval 'db.audit_decisions.find({decision: "ESCALATE"}).sort({timestamp: -1}).limit(20)'
   ```

3. **Check for taint-related escalations** (look for `taint_flags` in audit records).

4. **Check for delegation-related escalations** (look for "Confused-deputy" in reason field).

5. **Verify the escalation review queue is operational** (check the review dashboard or API).

## Remediation

- **Understaffed reviewers:** Page additional on-call reviewers. Consider temporarily relaxing policies for low-risk tool patterns.
- **Taint flood:** Investigate the source of UNTRUSTED data; add sanitisation gates for known-safe transformations.
- **Delegation flood:** Review implicit delegation detection thresholds; whitelist trusted agent pairs.
- **Policy misconfiguration:** Adjust escalation rules — lower the risk threshold or change action to ALLOW for well-understood tools.

## Escalation

If the backlog exceeds 25 or has been above 10 for 30 minutes, escalate to the AgentPEP on-call lead and notify the security team.
