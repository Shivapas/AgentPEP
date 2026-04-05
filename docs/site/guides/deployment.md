# Deployment Guide

Deploy AgentPEP to production on GCP or AWS.

## Architecture Overview

```
                    ┌─────────────┐
                    │  Ingress    │
                    │  (NGINX)    │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
     ┌────────▼───┐  ┌────▼─────┐  ┌──▼───────┐
     │  Backend   │  │ Frontend │  │ Metrics  │
     │  (FastAPI) │  │ (React)  │  │ (/metrics)│
     │  x2 pods   │  │ x1 pod   │  │          │
     └─────┬──────┘  └──────────┘  └──────────┘
           │
     ┌─────▼──────┐
     │  MongoDB   │
     │  ReplicaSet│
     │  (3 nodes) │
     └────────────┘
```

## GCP Deployment (Terraform + Helm)

### Prerequisites

- GCP project with billing enabled
- `gcloud` CLI configured
- `terraform` >= 1.7
- `helm` >= 3.14
- `kubectl` configured

### Step 1: Configure Terraform

```bash
cd infra/terraform/environments/beta
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your project settings
```

### Step 2: Deploy Infrastructure

```bash
terraform init
terraform plan
terraform apply
```

This creates:
- VPC with private subnet
- GKE cluster with autoscaling (2-6 nodes)
- MongoDB replica set (via Helm)
- Per-tenant namespaces with network isolation
- Workload Identity IAM bindings

### Step 3: Configure kubectl

```bash
gcloud container clusters get-credentials agentpep-beta \
  --region us-central1 --project your-project-id
```

### Step 4: Verify

```bash
kubectl get namespaces | grep agentpep
kubectl get pods -n agentpep-tenant-alpha
```

## Tenant Isolation

Each beta tenant gets:

| Resource | Isolation |
|----------|-----------|
| Kubernetes namespace | Separate namespace per tenant |
| MongoDB database | Separate database per tenant |
| Network policy | Ingress/egress restricted to own namespace |
| Resource quota | CPU/memory limits per namespace |
| Service account | GCP Workload Identity per tenant |
| TLS certificate | Per-tenant wildcard cert |

## Local Beta Simulation

Test multi-tenant setup locally:

```bash
cd infra
docker compose -f docker-compose.beta.yml up -d
```

This starts two backend instances (tenant-alpha on port 8001, tenant-bravo on port 8002)
with separate MongoDB databases.

## Production Checklist

- [ ] Enable `AGENTPEP_AUTH_ENABLED=true`
- [ ] Configure mTLS for inter-service communication
- [ ] Set `AGENTPEP_DEFAULT_FAIL_MODE=FAIL_CLOSED`
- [ ] Configure MongoDB authentication
- [ ] Enable Prometheus monitoring
- [ ] Set up OpenTelemetry tracing
- [ ] Configure backup for MongoDB data
- [ ] Set appropriate resource quotas per tenant
- [ ] Configure rate limiting at ingress level
- [ ] Enable audit log retention policies
