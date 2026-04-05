# Runbook: AgentPEP_HighP99Latency

**Alert:** `AgentPEP_HighP99Latency`
**Severity:** Warning
**Team:** Platform

## Symptoms

- The 99th percentile decision latency exceeds 100 ms for more than 5 minutes.
- Agents experience slow tool call authorization; timeouts may start occurring.
- The `agentpep_decision_total{decision="TIMEOUT"}` counter may start increasing.

## Possible Causes

1. **MongoDB performance degradation** — slow queries, connection pool exhaustion, or disk I/O bottleneck.
2. **Rule cache miss storm** — the rule cache TTL expired and many concurrent requests hit MongoDB simultaneously.
3. **Complex taint graph** — sessions with deep taint propagation chains cause expensive graph traversals.
4. **Confused-deputy evaluation overhead** — large delegation chains with many hops.
5. **Resource exhaustion** — CPU or memory pressure on the backend pods.

## Diagnosis Steps

1. **Check latency breakdown by tool:**
   ```promql
   histogram_quantile(0.99, sum(rate(agentpep_decision_latency_seconds_bucket[5m])) by (le, tool_name))
   ```

2. **Check audit write latency** (MongoDB health proxy):
   ```promql
   histogram_quantile(0.99, sum(rate(agentpep_audit_write_latency_seconds_bucket[5m])) by (le))
   ```

3. **Check MongoDB metrics:**
   - Connection pool utilization
   - Slow query log (`db.currentOp()`)
   - Disk I/O and replication lag

4. **Check backend pod resource usage:**
   ```bash
   kubectl top pods -l app=agentpep,component=backend
   ```

5. **Check rule cache effectiveness:**
   - If rule_cache TTL is too low, increase it (default: 60s).

## Remediation

- **MongoDB slow:** Scale MongoDB replica set or add read replicas. Check and optimize indexes.
- **Cache miss storm:** Increase rule cache TTL in config (`AGENTPEP_RULE_CACHE_TTL_S`).
- **Taint graph complexity:** Investigate sessions with large graphs; consider enforcing max taint depth.
- **Resource exhaustion:** Scale backend replicas horizontally.

## Escalation

If latency does not drop below 100 ms within 15 minutes of remediation, escalate to the database team.
