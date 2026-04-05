# Runbook: AgentPEP_AuditWriteFailures

**Alert:** `AgentPEP_AuditWriteFailures`
**Severity:** Critical
**Team:** Platform

## Symptoms

- More than 5% of audit log writes are failing.
- The `agentpep_audit_write_total{status="failure"}` counter is increasing.
- Audit trail integrity is compromised — decisions are being made but not recorded.
- Policy decisions themselves are NOT affected (audit writes are fire-and-forget).

## Possible Causes

1. **MongoDB connectivity loss** — network partition, pod crash, or DNS resolution failure.
2. **MongoDB disk full** — the audit_decisions collection has grown beyond available storage.
3. **MongoDB authentication failure** — credentials rotated or expired.
4. **Write concern timeout** — MongoDB replica set is degraded, writes cannot achieve the required write concern.

## Diagnosis Steps

1. **Check audit write failure rate:**
   ```promql
   sum(rate(agentpep_audit_write_total{status="failure"}[5m])) / sum(rate(agentpep_audit_write_total[5m]))
   ```

2. **Check audit write latency** (spikes indicate MongoDB pressure):
   ```promql
   histogram_quantile(0.99, sum(rate(agentpep_audit_write_latency_seconds_bucket[5m])) by (le))
   ```

3. **Check MongoDB connectivity:**
   ```bash
   kubectl exec -it <mongodb-pod> -- mongosh --eval 'rs.status()'
   ```

4. **Check MongoDB disk usage:**
   ```bash
   kubectl exec -it <mongodb-pod> -- df -h /data/db
   ```

5. **Check backend logs for error details:**
   ```bash
   kubectl logs -l app=agentpep,component=backend --tail=100 | jq 'select(.message == "audit_write_failed")'
   ```

## Remediation

- **Connectivity loss:** Check network policies, DNS, and MongoDB pod status. Restart affected pods.
- **Disk full:** Verify TTL indexes are working (`audit_retention_days`). Manually expire old records if needed. Expand storage.
- **Auth failure:** Update MongoDB credentials in the backend ConfigMap/Secret and restart pods.
- **Write concern:** Repair or replace the degraded MongoDB replica set member.

## Escalation

This is a compliance-critical alert. If writes do not recover within 10 minutes, escalate to both the database team and the compliance officer.
