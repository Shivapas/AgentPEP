# Runbook: AgentPEP_SecurityAlertBurst

**Alert:** `AgentPEP_SecurityAlertBurst`
**Severity:** Critical
**Team:** Security

## Symptoms

- More than 1 HIGH/CRITICAL security alert per second sustained over 2 minutes.
- The `agentpep_security_alert_total{severity=~"HIGH|CRITICAL"}` counter is spiking.
- Possible active privilege escalation or confused-deputy attack in progress.

## Possible Causes

1. **Active privilege escalation attack** — a compromised agent is attempting to escalate its permissions through delegation chains.
2. **Confused-deputy exploitation** — an attacker is using one agent to trick another into executing privileged operations.
3. **Misconfigured delegation** — a legitimate integration is generating spurious delegation chain violations.
4. **Injection attack** — prompt injection or tool argument injection triggering quarantine and security alerts.

## Diagnosis Steps

1. **Identify the top agents generating alerts:**
   ```promql
   topk(5, sum(rate(agentpep_security_alert_total{severity=~"HIGH|CRITICAL"}[5m])) by (alert_type))
   ```

2. **Review recent security alerts in MongoDB:**
   ```bash
   mongosh agentpep --eval 'db.security_alerts.find({severity: {$in: ["HIGH", "CRITICAL"]}}).sort({timestamp: -1}).limit(20)'
   ```

3. **Check if a single session is responsible:**
   ```bash
   mongosh agentpep --eval 'db.security_alerts.aggregate([{$match: {severity: {$in: ["HIGH", "CRITICAL"]}}}, {$group: {_id: "$session_id", count: {$sum: 1}}}, {$sort: {count: -1}}, {$limit: 5}])'
   ```

4. **Correlate with taint events** — check if injection signatures are being triggered.

5. **Review the delegation chains** of the offending sessions for unauthorized hops.

## Remediation

- **Active attack:** Immediately disable the compromised agent(s). Revoke API keys for affected tenants. Isolate the session.
- **Confused-deputy:** Add the attacker agent to the denylist. Review and tighten delegation depth limits.
- **Misconfigured delegation:** Fix the integration's delegation chain setup. Whitelist known-safe agent pairs.
- **Injection attack:** Quarantine affected taint nodes. Review and update injection signature library.

## Escalation

This is a security incident. Immediately notify the security on-call lead. If an active attack is confirmed, initiate the incident response process.
