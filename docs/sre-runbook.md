# AgentPEP — SRE Runbook & On-Call Rotation

**Version:** 1.0.0
**Last Updated:** April 2026
**Classification:** Internal — Operations

---

## Table of Contents

1. [Service Overview](#1-service-overview)
2. [Architecture](#2-architecture)
3. [On-Call Rotation](#3-on-call-rotation)
4. [Incident Severity Levels](#4-incident-severity-levels)
5. [Alerting Rules](#5-alerting-rules)
6. [Runbook Procedures](#6-runbook-procedures)
7. [Disaster Recovery](#7-disaster-recovery)
8. [Maintenance Procedures](#8-maintenance-procedures)

---

## 1. Service Overview

| Field | Value |
|-------|-------|
| Service Name | AgentPEP Authorization Engine |
| Team | AgentPEP Platform |
| SLA | 99.95% monthly uptime |
| Decision Latency SLA | p99 ≤ 25 ms |
| Critical Dependencies | MongoDB, Kafka |
| Monitoring | Prometheus + Grafana |
| Tracing | OpenTelemetry → Jaeger/Tempo |
| Logging | Structured JSON → Loki/CloudWatch |

### Endpoints

| Endpoint | Port | Protocol | Purpose |
|----------|------|----------|---------|
| `/health` | 8000 | HTTP | Liveness and readiness probes |
| `/v1/intercept` | 8000 | HTTP | Policy decision API |
| `/v1/taint/*` | 8000 | HTTP | Taint tracking API |
| `/metrics` | 8000 | HTTP | Prometheus metrics scrape |
| gRPC intercept | 50051 | gRPC | Binary policy decision API |

---

## 2. Architecture

```
┌─────────────┐      ┌──────────────────┐      ┌──────────┐
│ Agent / SDK  │─────▶│  AgentPEP API    │─────▶│ MongoDB  │
│              │      │  (FastAPI)       │      │          │
└─────────────┘      │  ┌────────────┐  │      └──────────┘
                      │  │ Rule Cache │  │
                      │  └────────────┘  │      ┌──────────┐
                      │  ┌────────────┐  │─────▶│  Kafka   │
                      │  │ Taint Graph│  │      │ (events) │
                      │  └────────────┘  │      └──────────┘
                      └──────────────────┘
                              │
                      ┌───────┴───────┐
                      │  Prometheus   │
                      │  + Grafana    │
                      └───────────────┘
```

---

## 3. On-Call Rotation

### Schedule

| Rotation | Coverage | Duration | Handoff |
|----------|----------|----------|---------|
| Primary | 24/7 | 1 week | Monday 09:00 UTC |
| Secondary | 24/7 | 1 week | Monday 09:00 UTC |
| Escalation | Business hours | Ongoing | N/A |

### Responsibilities

**Primary On-Call:**
- Acknowledge all pages within 5 minutes
- Triage and begin investigation within 15 minutes
- Communicate status updates every 30 minutes during active incidents
- Escalate to secondary if unable to resolve within 1 hour

**Secondary On-Call:**
- Available as backup within 15 minutes
- Join active P0/P1 incidents when escalated
- Cover primary during scheduled breaks

**Escalation Manager:**
- Engaged for all P0 incidents automatically
- Coordinates cross-team response when needed
- Handles external customer communication

### Escalation Path

```
Primary On-Call (5 min ACK)
    └──▶ Secondary On-Call (15 min)
         └──▶ Engineering Lead (30 min)
              └──▶ VP Engineering (P0 only, 1 hr)
```

---

## 4. Incident Severity Levels

| Severity | Definition | Response Time | Resolution Target |
|----------|-----------|---------------|-------------------|
| **P0 — Critical** | Service fully down or data integrity at risk. No policy decisions being made. | ≤ 15 min | ≤ 4 hours |
| **P1 — High** | Degraded performance (p99 > 100 ms) or partial outage affecting > 10% of tenants. | ≤ 30 min | ≤ 8 hours |
| **P2 — Medium** | Non-critical feature degraded. Metrics/tracing gaps. Single tenant impacted. | ≤ 2 hours | ≤ 24 hours |
| **P3 — Low** | Cosmetic issue, documentation gap, or non-urgent improvement. | Next business day | Best effort |

---

## 5. Alerting Rules

### Critical (P0 — pages immediately)

| Alert | Condition | For |
|-------|-----------|-----|
| `AgentPEP_Down` | `up{job="agentpep"} == 0` | 1 min |
| `AgentPEP_HighErrorRate` | `rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05` | 2 min |
| `AgentPEP_MongoDown` | `mongodb_up == 0` | 1 min |
| `AgentPEP_DecisionFailure` | `rate(agentpep_intercept_errors_total[5m]) > 0` and `FAIL_CLOSED` | 1 min |

### Warning (P1 — pages during business hours)

| Alert | Condition | For |
|-------|-----------|-----|
| `AgentPEP_HighLatency` | `histogram_quantile(0.99, rate(agentpep_intercept_duration_seconds_bucket[5m])) > 0.025` | 5 min |
| `AgentPEP_CacheMissHigh` | `agentpep_rule_cache_hit_ratio < 0.90` | 10 min |
| `AgentPEP_MongoSlow` | `mongodb_operation_latency_p99 > 0.050` | 5 min |
| `AgentPEP_KafkaLag` | `kafka_consumer_group_lag > 10000` | 5 min |

### Info (P2 — ticket)

| Alert | Condition | For |
|-------|-----------|-----|
| `AgentPEP_HighMemory` | `process_resident_memory_bytes > 500 * 1024 * 1024` | 15 min |
| `AgentPEP_CertExpiry` | `tls_cert_expiry_seconds < 7 * 86400` | 1 hour |
| `AgentPEP_DiskUsage` | `node_filesystem_avail_bytes / node_filesystem_size_bytes < 0.15` | 10 min |

---

## 6. Runbook Procedures

### 6.1 Service Unresponsive (AgentPEP_Down)

**Symptoms:** Health check failing, 502/503 from load balancer.

**Steps:**
1. Check pod/container status:
   ```bash
   kubectl get pods -l app=agentpep -n production
   docker compose ps backend
   ```
2. Check application logs for crash reason:
   ```bash
   kubectl logs -l app=agentpep --tail=100
   ```
3. If OOM killed, increase memory limit and restart:
   ```bash
   kubectl set resources deployment/agentpep -c backend --limits=memory=1Gi
   kubectl rollout restart deployment/agentpep
   ```
4. If startup failure, check MongoDB connectivity:
   ```bash
   mongosh --eval "db.adminCommand('ping')" $AGENTPEP_MONGODB_URL
   ```
5. If persistent, rollback to last known good version:
   ```bash
   kubectl rollout undo deployment/agentpep
   ```

### 6.2 High Error Rate (AgentPEP_HighErrorRate)

**Symptoms:** 5xx error rate > 5% for 2+ minutes.

**Steps:**
1. Identify error type from logs:
   ```bash
   kubectl logs -l app=agentpep --tail=200 | grep "ERROR"
   ```
2. Check if errors correlate with a recent deployment:
   ```bash
   kubectl rollout history deployment/agentpep
   ```
3. If deployment-related, rollback:
   ```bash
   kubectl rollout undo deployment/agentpep
   ```
4. If MongoDB errors, check connection pool:
   ```bash
   mongosh --eval "db.serverStatus().connections" $AGENTPEP_MONGODB_URL
   ```
5. If Kafka errors, check broker health:
   ```bash
   kafka-broker-api-versions --bootstrap-server $KAFKA_BROKERS
   ```

### 6.3 High Latency (AgentPEP_HighLatency)

**Symptoms:** p99 latency > 25 ms sustained.

**Steps:**
1. Check if rule cache hit ratio has dropped:
   ```bash
   curl -s localhost:8000/metrics | grep agentpep_rule_cache
   ```
2. Check MongoDB query performance:
   ```bash
   mongosh --eval "db.currentOp({'secs_running': {'\$gt': 1}})" $AGENTPEP_MONGODB_URL
   ```
3. Check for CPU throttling:
   ```bash
   kubectl top pods -l app=agentpep
   ```
4. If cache miss rate is high, check if policies were recently bulk-updated
   (cache invalidation storm). Wait for cache warm-up (~60s).
5. If MongoDB slow, check for missing indexes:
   ```bash
   mongosh --eval "db.policies.getIndexes()" $AGENTPEP_MONGODB_URL
   ```

### 6.4 MongoDB Down (AgentPEP_MongoDown)

**Symptoms:** MongoDB connection refused, health check returning 503.

**Steps:**
1. Check MongoDB pod/container status:
   ```bash
   kubectl get pods -l app=mongodb -n production
   ```
2. Check MongoDB logs:
   ```bash
   kubectl logs -l app=mongodb --tail=100
   ```
3. If disk full, expand PVC or clean up old audit logs.
4. If replica set election in progress, wait 30s for new primary.
5. Verify AgentPEP `FAIL_CLOSED` mode is active — all decisions should
   be DENY until MongoDB recovers. This is by design.
6. Once MongoDB recovers, verify AgentPEP reconnects automatically
   (motor driver handles reconnection).

### 6.5 Kafka Consumer Lag (AgentPEP_KafkaLag)

**Symptoms:** Audit events delayed, consumer lag > 10,000.

**Steps:**
1. Check consumer group status:
   ```bash
   kafka-consumer-groups --bootstrap-server $KAFKA_BROKERS \
     --group agentpep-audit --describe
   ```
2. If consumer is stopped, restart the AgentPEP service.
3. If throughput issue, scale consumer instances.
4. Note: Kafka lag does not affect real-time decisions — only audit event
   delivery. This is P2 unless audit compliance requires real-time delivery.

### 6.6 TLS Certificate Expiring (AgentPEP_CertExpiry)

**Symptoms:** Certificate expires in < 7 days.

**Steps:**
1. If using cert-manager, check certificate resource:
   ```bash
   kubectl get certificate -n production
   kubectl describe certificate agentpep-tls -n production
   ```
2. If manual certs, rotate the certificate:
   ```bash
   kubectl create secret tls agentpep-tls \
     --cert=new-cert.pem --key=new-key.pem \
     -n production --dry-run=client -o yaml | kubectl apply -f -
   ```
3. Restart pods to pick up new cert (if not using dynamic reload):
   ```bash
   kubectl rollout restart deployment/agentpep
   ```

---

## 7. Disaster Recovery

### Recovery Objectives

| Metric | Target |
|--------|--------|
| RTO (Recovery Time Objective) | < 1 hour |
| RPO (Recovery Point Objective) | < 5 minutes |

### Backup Strategy

| Component | Method | Frequency | Retention |
|-----------|--------|-----------|-----------|
| MongoDB (policies) | `mongodump` to S3 | Every 6 hours | 30 days |
| MongoDB (audit logs) | Continuous oplog to S3 | Real-time | 90 days hot, 1 year cold |
| Configuration | Git (infrastructure-as-code) | On change | Indefinite |
| Kafka topics | MirrorMaker to DR cluster | Real-time | 7 days |

### Recovery Procedure

1. **Provision infrastructure** from IaC (Terraform/Helm):
   ```bash
   terraform apply -target=module.agentpep_dr
   helm upgrade --install agentpep ./charts/agentpep -f values-dr.yaml
   ```
2. **Restore MongoDB** from latest backup:
   ```bash
   mongorestore --uri=$DR_MONGODB_URL --gzip --archive=s3://backups/latest.gz
   ```
3. **Update DNS** to point to DR cluster.
4. **Verify** health endpoint and run smoke test:
   ```bash
   curl -f https://dr.agentpep.example.com/health
   ```
5. **Notify** stakeholders that failover is complete.

---

## 8. Maintenance Procedures

### Planned Maintenance Window

- **Window:** Sundays 02:00–06:00 UTC
- **Notification:** 72 hours advance notice to customers
- **Procedure:** Rolling restart with zero-downtime deployment

### Deploying a New Version

```bash
# 1. Verify CI pipeline passed
# 2. Deploy to staging first
kubectl set image deployment/agentpep backend=agentpep:$NEW_VERSION -n staging
kubectl rollout status deployment/agentpep -n staging

# 3. Run integration tests against staging
pytest tests/integration/ --base-url=https://staging.agentpep.example.com

# 4. Deploy to production (canary: 10% → 50% → 100%)
kubectl set image deployment/agentpep backend=agentpep:$NEW_VERSION -n production
kubectl rollout status deployment/agentpep -n production

# 5. Monitor for 30 minutes, then mark release stable
```

### Rollback

```bash
kubectl rollout undo deployment/agentpep -n production
kubectl rollout status deployment/agentpep -n production
```

---

*AgentPEP · TrustFabric Portfolio · Confidential · © 2026*
