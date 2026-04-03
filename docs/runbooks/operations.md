# AgentPEP Operations Runbook

## Table of Contents

1. [Installation](#1-installation)
2. [Upgrade](#2-upgrade)
3. [Backup](#3-backup)
4. [Restore](#4-restore)
5. [Scaling](#5-scaling)
6. [Disaster Recovery](#6-disaster-recovery)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. Installation

### Prerequisites

- Kubernetes 1.27+
- Helm 3.12+
- `kubectl` configured with cluster access
- Storage class provisioner (for persistent volumes)
- Minimum cluster resources: 4 CPU, 8 GB RAM

### Standard Installation

```bash
# Add the chart (or use local path)
helm install agentpep ./infra/helm/agentpep \
  --namespace agentpep \
  --create-namespace \
  --wait --timeout 30m
```

### Air-Gapped Installation

```bash
# 1. On a machine with internet access, bundle images
./infra/airgap/bundle-images.sh --output agentpep-images.tar.gz

# 2. Transfer the tarball and chart to the air-gapped environment

# 3. Load images into the private registry
./infra/airgap/load-images.sh \
  --archive agentpep-images.tar.gz \
  --registry registry.internal:5000

# 4. Install with air-gapped values
helm install agentpep ./infra/helm/agentpep \
  --namespace agentpep \
  --create-namespace \
  -f ./infra/airgap/values-airgap.yaml \
  --wait --timeout 30m
```

### Post-Install Validation

```bash
./infra/scripts/validate-install.sh \
  --namespace agentpep \
  --release agentpep
```

---

## 2. Upgrade

### Pre-Upgrade Checklist

1. Review the changelog for breaking changes
2. Create a MongoDB backup (see [Backup](#3-backup))
3. Test the upgrade in a staging environment first

### Rolling Upgrade

```bash
# Check current version
helm list -n agentpep

# Upgrade to new version
helm upgrade agentpep ./infra/helm/agentpep \
  --namespace agentpep \
  --wait --timeout 30m \
  --set api.image.tag=<new-version>

# Validate post-upgrade
./infra/scripts/validate-install.sh \
  --namespace agentpep \
  --release agentpep
```

### Rollback

```bash
# List revision history
helm history agentpep -n agentpep

# Rollback to previous revision
helm rollback agentpep <revision> -n agentpep --wait
```

---

## 3. Backup

### Enable Scheduled Backups

Backups are configured via the Helm chart's `backup` values:

```yaml
backup:
  enabled: true
  schedule: "0 2 * * *"      # Daily at 2 AM
  s3:
    endpoint: "https://s3.amazonaws.com"
    bucket: "agentpep-backups"
    prefix: "mongodb"
    accessKeyId: "<key>"
    secretAccessKey: "<secret>"
  retention:
    days: 30
```

Apply with:

```bash
helm upgrade agentpep ./infra/helm/agentpep \
  -n agentpep -f backup-values.yaml
```

### Manual Backup

```bash
# Get the MongoDB pod name
MONGO_POD=$(kubectl get pods -n agentpep \
  -l app.kubernetes.io/component=mongodb \
  -o jsonpath='{.items[0].metadata.name}')

# Run mongodump
kubectl exec -n agentpep "${MONGO_POD}" -- \
  mongodump --db=agentpep --archive=/tmp/backup.gz --gzip

# Copy the backup locally
kubectl cp "agentpep/${MONGO_POD}:/tmp/backup.gz" ./agentpep-backup.gz
```

### Verify Backup Integrity

```bash
# List contents of the backup archive
mongorestore --archive=./agentpep-backup.gz --gzip --dryRun
```

---

## 4. Restore

### Restore from Backup

```bash
# 1. Copy backup to MongoDB pod
MONGO_POD=$(kubectl get pods -n agentpep \
  -l app.kubernetes.io/component=mongodb \
  -o jsonpath='{.items[0].metadata.name}')

kubectl cp ./agentpep-backup.gz "agentpep/${MONGO_POD}:/tmp/backup.gz"

# 2. Stop the API to prevent writes during restore
kubectl scale deployment agentpep-api -n agentpep --replicas=0

# 3. Restore the database
kubectl exec -n agentpep "${MONGO_POD}" -- \
  mongorestore --db=agentpep --archive=/tmp/backup.gz --gzip --drop

# 4. Restart the API
kubectl scale deployment agentpep-api -n agentpep --replicas=2

# 5. Validate
./infra/scripts/validate-install.sh -n agentpep -r agentpep
```

### Restore from S3

```bash
# Download from S3
aws s3 cp s3://agentpep-backups/mongodb/agentpep-backup-YYYYMMDD-HHMMSS.gz \
  ./agentpep-backup.gz

# Then follow the restore steps above
```

---

## 5. Scaling

### Horizontal Scaling (API)

The HPA automatically scales the API deployment based on requests per second
and CPU utilization. To adjust:

```bash
# Check current HPA status
kubectl get hpa -n agentpep

# Modify scaling parameters
helm upgrade agentpep ./infra/helm/agentpep -n agentpep \
  --set autoscaling.minReplicas=3 \
  --set autoscaling.maxReplicas=20 \
  --set autoscaling.targetRPS=200

# Manual override (temporary)
kubectl scale deployment agentpep-api -n agentpep --replicas=5
```

### Vertical Scaling

Increase resource limits for components under heavy load:

```bash
helm upgrade agentpep ./infra/helm/agentpep -n agentpep \
  --set api.resources.requests.cpu=500m \
  --set api.resources.limits.cpu=2 \
  --set api.resources.limits.memory=1Gi
```

### MongoDB Scaling

For production workloads, consider:

1. Increasing the PVC size (requires storage class that supports volume expansion)
2. Using an external managed MongoDB (Atlas, DocumentDB) by setting `mongodb.enabled=false`
   and configuring `api.env.mongodbUrl`

---

## 6. Disaster Recovery

### Scenario: Complete Cluster Loss

1. Provision a new Kubernetes cluster
2. Load container images (if air-gapped)
3. Install AgentPEP from the Helm chart
4. Restore MongoDB from the latest S3 backup (see [Restore](#4-restore))
5. Run validation checks

### Scenario: MongoDB Data Corruption

1. Scale down the API: `kubectl scale deployment agentpep-api -n agentpep --replicas=0`
2. Delete the corrupted MongoDB PVC
3. Delete and recreate the MongoDB StatefulSet (Helm upgrade)
4. Restore from the latest backup
5. Scale up the API

### Scenario: Single Pod Failure

Kubernetes automatically handles pod restarts. Check:

```bash
kubectl get events -n agentpep --sort-by='.metadata.creationTimestamp'
kubectl describe pod <pod-name> -n agentpep
```

### Recovery Time Objectives

| Scenario | RTO Target | Steps |
|----------|-----------|-------|
| Pod failure | < 2 min | Auto-restart by K8s |
| Node failure | < 5 min | Pod rescheduling |
| Full restore | < 2 hours | Fresh install + restore |

---

## 7. Troubleshooting

### API Not Responding

```bash
# Check pod status
kubectl get pods -n agentpep -l app.kubernetes.io/component=api

# Check logs
kubectl logs -n agentpep -l app.kubernetes.io/component=api --tail=100

# Check events
kubectl get events -n agentpep --field-selector reason=Failed
```

### MongoDB Connection Issues

```bash
# Verify MongoDB is running
kubectl get pods -n agentpep -l app.kubernetes.io/component=mongodb

# Test connectivity from API pod
API_POD=$(kubectl get pods -n agentpep -l app.kubernetes.io/component=api \
  -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n agentpep "${API_POD}" -- \
  python -c "from pymongo import MongoClient; c = MongoClient('mongodb://agentpep-mongodb:27017', serverSelectionTimeoutMS=5000); print(c.server_info())"
```

### Kafka Connection Issues

```bash
# Check Kafka and Zookeeper
kubectl get pods -n agentpep -l app.kubernetes.io/component=kafka
kubectl get pods -n agentpep -l app.kubernetes.io/component=zookeeper

# Check Kafka logs
kubectl logs -n agentpep -l app.kubernetes.io/component=kafka --tail=50
```

### PersistentVolume Issues

```bash
# Check PVC status
kubectl get pvc -n agentpep

# If PVC is stuck in Pending, check events
kubectl describe pvc <pvc-name> -n agentpep

# Common fix: ensure StorageClass exists
kubectl get storageclass
```

### HPA Not Scaling

```bash
# Check HPA status and events
kubectl describe hpa -n agentpep

# Verify metrics-server is running
kubectl get pods -n kube-system -l k8s-app=metrics-server

# Check if custom metrics are available (for RPS-based scaling)
kubectl get --raw /apis/custom.metrics.k8s.io/v1beta1 | jq .
```
