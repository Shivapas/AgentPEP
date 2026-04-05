# Beta Customer Onboarding Runbook (APEP-212/213)

## Overview

This runbook guides the onboarding of beta customers onto the AgentPEP platform.
Each customer receives a dedicated tenant namespace with isolated database, API keys,
and policy configuration.

## Pre-Onboarding Checklist

- [ ] Beta environment deployed and healthy (`/health` returns 200)
- [ ] Customer agreement signed (beta terms of service)
- [ ] Dedicated tenant namespace provisioned
- [ ] Customer technical contact identified
- [ ] Integration kick-off call scheduled

## Step 1: Provision Tenant

```bash
# Add tenant to Terraform variables
cd infra/terraform/environments/beta
# Edit terraform.tfvars — add tenant ID to beta_tenants list
terraform plan
terraform apply
```

Verify the namespace was created:
```bash
kubectl get namespace agentpep-<tenant-id>
kubectl get pods -n agentpep-<tenant-id>
```

## Step 2: Generate API Credentials

```bash
# Generate a secure API key for the tenant
API_KEY=$(openssl rand -hex 32)

# Store in Kubernetes secret
kubectl create secret generic agentpep-<tenant-id>-secrets \
  --from-literal=api-key=$API_KEY \
  -n agentpep-<tenant-id>

# Share API key securely with customer (use a secrets manager, not email)
```

## Step 3: Configure Base Policy Rules

Create a starter policy set for the customer. Insert via the API:

```bash
curl -X POST https://<tenant-id>.beta.agentpep.io/v1/rules \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "default-deny-all",
    "agent_role": ["*"],
    "tool_pattern": "*",
    "action": "DENY",
    "priority": 999
  }'

curl -X POST https://<tenant-id>.beta.agentpep.io/v1/rules \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "allow-read-operations",
    "agent_role": ["reader", "writer", "admin"],
    "tool_pattern": "read_*",
    "action": "ALLOW",
    "priority": 10
  }'
```

## Step 4: SDK Integration Support

Walk the customer through SDK installation:

```bash
pip install agentpep-sdk
```

Provide a minimal integration example:

```python
from agentpep import AgentPEPClient, enforce

client = AgentPEPClient(
    base_url="https://<tenant-id>.beta.agentpep.io",
    api_key="<provided-api-key>",
)

@enforce(client=client, agent_id="customer-agent")
async def read_database(query: str) -> dict:
    # This function only executes if policy returns ALLOW
    return await db.execute(query)
```

## Step 5: Policy Authoring Workshop

Schedule a 60-minute workshop covering:

1. **Policy model overview** (15 min) — Rules, roles, priorities, first-match semantics
2. **Hands-on policy authoring** (25 min) — Use the Policy Console to create rules
3. **Taint tracking walkthrough** (10 min) — Label untrusted sources, observe propagation
4. **Q&A and friction logging** (10 min) — Capture issues in the friction tracker

## Step 6: Validate Integration

Run the customer's first real policy evaluation:

```bash
curl -X POST https://<tenant-id>.beta.agentpep.io/v1/intercept \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "onboarding-test",
    "agent_id": "test-agent",
    "tool_name": "read_database",
    "tool_args": {"query": "SELECT 1"}
  }'
```

Expected: `{"decision": "ALLOW", ...}`

## Step 7: Post-Onboarding

- [ ] Customer confirms successful integration
- [ ] Customer can create and manage policy rules
- [ ] Friction points documented in `docs/onboarding/friction-log.md`
- [ ] Follow-up call scheduled for 1 week post-onboarding
- [ ] Customer added to beta Slack channel for support

## Escalation Path

| Issue | Contact | SLA |
|-------|---------|-----|
| API availability | On-call SRE | 30 min |
| Policy authoring help | Solutions Engineer | 4 hours |
| SDK bugs | Engineering (GitHub issue) | 24 hours |
| Security concerns | Security Lead | Immediate |
