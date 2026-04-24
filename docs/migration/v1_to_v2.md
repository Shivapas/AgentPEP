# AgentPEP Operator Migration Guide: v1.x → v2.1

**Document ID:** MIG-001
**Version:** 1.0
**Sprint:** S-E10 (E10-T07)
**Owner:** TrustFabric Product Architecture
**Date:** Q3 2026
**Audience:** Operators, platform engineers, DevOps teams deploying AgentPEP

---

## Overview

The single most significant change in v2.1 is **where policy comes from**. In v1.x, operators managed enforcement rules in local YAML files (`policies/rules.yaml`, `policies/roles.yaml`, etc.). In v2.1, all policy is authored by the AAPM team in APDL, compiled to signed Rego bundles, and delivered to AgentPEP from the AAPM Policy Registry.

You will not need to re-author your existing rules. The AAPM team has translated all standard AgentPEP v1.x rules to APDL. Your migration task is primarily configuration: point AgentPEP at the AAPM Policy Registry and remove or archive your local policy overrides.

**Estimated migration time:** 1–2 hours for a standard deployment.

---

## Prerequisites

Before beginning the migration:

- [ ] Confirm with your AAPM contact that the AAPM Policy Registry is operational for your environment
- [ ] Confirm with your AAPM contact that the `agentpep-core-v1.0.0` bundle (or newer) has been published to your registry instance
- [ ] Confirm you have the AAPM Policy Registry URL for your environment (format: `https://registry.aapm.<your-org>.trustfabric.io/agentpep/policies/`)
- [ ] Confirm webhook endpoint is reachable from the AAPM registry (or confirm polling-only fallback is acceptable for your environment)
- [ ] Run the v1.x rule inventory export (Step 1 below) before removing any local policy files

---

## Step 1: Export Your v1.x Rule Inventory

Before making any changes, export your current policy configuration for your records and to share with the AAPM team if you have custom rules beyond the standard set.

```bash
# List all active policy files
ls policies/

# Export current rules to a timestamped backup
cp -r policies/ policies_backup_$(date +%Y%m%d)/

# If you have any custom rules beyond the standard YAML files,
# export them as an inventory for the AAPM team:
agentpep-sdk policy export --output custom_rules_inventory.yaml
```

**Send the inventory to the AAPM team** if you have rules not in the standard `agentpep-core-v1.0.0` bundle. The AAPM team will translate them to APDL and publish a custom bundle for your organisation.

---

## Step 2: Configure the AAPM Policy Registry

### 2.1 Set the Registry URL

In your AgentPEP server configuration (`config/agentpep.yaml` or environment variable):

```yaml
# agentpep.yaml — v2.1 configuration
policy:
  # New in v2.1: AAPM Policy Registry is the only accepted policy source
  aapm_registry_url: "https://registry.aapm.<your-org>.trustfabric.io/agentpep/policies/"
  # Webhook endpoint AgentPEP exposes for AAPM push notifications
  webhook_listen_path: "/internal/policy/webhook"
  # Polling interval (seconds) — used when webhook is unavailable
  poll_interval_seconds: 60
```

Or via environment variables:

```bash
export AGENTPEP_AAPM_REGISTRY_URL="https://registry.aapm.<your-org>.trustfabric.io/agentpep/policies/"
export AGENTPEP_POLICY_WEBHOOK_PATH="/internal/policy/webhook"
export AGENTPEP_POLICY_POLL_INTERVAL=60
```

### 2.2 Remove Deprecated Policy Configuration

The following configuration keys are **no longer supported** in v2.1 and will be ignored with a startup warning:

```yaml
# REMOVE these from your v1.x configuration:
policy:
  path: "policies/rules.yaml"       # REMOVED — use aapm_registry_url
  rules_file: "policies/rules.yaml" # REMOVED
  roles_file: "policies/roles.yaml" # REMOVED
  risk_file: "policies/risk.yaml"   # REMOVED
  taint_file: "policies/taint.yaml" # REMOVED
```

If these keys are present, AgentPEP v2.1 will log a deprecation warning at startup and **ignore them**. Policy will be loaded exclusively from the AAPM registry.

### 2.3 Verify Environment Variables are Not Set

AgentPEP v2.1 blocks and logs `SECURITY_VIOLATION` if `POLICY_PATH` is set. Ensure it is unset in your deployment:

```bash
# Check if POLICY_PATH is set
echo $POLICY_PATH

# Unset it if present
unset POLICY_PATH
```

In Kubernetes deployments, check your ConfigMaps and Secrets for `POLICY_PATH` references and remove them.

---

## Step 3: Configure Webhook or Polling

AAPM delivers policy updates via webhook push. Polling is the fallback when the webhook is unavailable.

### Option A: Webhook (Recommended)

1. Ensure your AgentPEP deployment's webhook endpoint is reachable from the AAPM registry's IP range
2. Provide your webhook URL to the AAPM team: `https://<your-agentpep-host>/internal/policy/webhook`
3. AAPM will configure the push subscription on their end

**Kubernetes deployment:** Ensure the AgentPEP service exposes the webhook path. The Helm chart includes a `webhookIngress` value:

```yaml
# values.yaml
policy:
  webhook:
    enabled: true
    ingressPath: "/internal/policy/webhook"
```

### Option B: Polling Only

If webhooks are not feasible in your environment (air-gapped, strict ingress rules), polling is automatically active as a fallback. AgentPEP polls the AAPM registry every 60 seconds using an ETag-based conditional GET.

No additional configuration is needed — polling activates automatically when webhooks are not received. To disable webhook receiver entirely:

```yaml
policy:
  webhook:
    enabled: false
```

**Note:** Polling-only deployments will have a maximum policy update latency of 60 seconds vs. near-instant for webhook delivery.

---

## Step 4: Verify the Bundle Loads

Deploy the v2.1 configuration (do not remove local policy files yet) and verify the bundle loads correctly at startup.

### Check Startup Logs

```bash
# Look for successful bundle load on startup
docker logs agentpep-backend | grep "policy_bundle"

# Expected output:
# INFO: Policy bundle loaded successfully — version: agentpep-core-v1.0.0, source: aapm-registry
# INFO: cosign signature verified — key: AAPM_POLICY_PUBLIC_KEY
# INFO: Enforcement active — OPA engine ready
```

### Check the Health Endpoint

```bash
curl -s http://localhost:8000/v1/health | jq '.policy'

# Expected:
# {
#   "status": "ok",
#   "bundle_version": "agentpep-core-v1.0.0",
#   "bundle_source": "aapm-registry",
#   "last_loaded": "2026-07-01T10:00:00Z",
#   "signature_verified": true
# }
```

### Verify Enforcement Decision Logs Include Bundle Version

Make a test tool call evaluation and confirm the enforcement decision log records `policy_bundle_version`:

```bash
curl -s -X POST http://localhost:8000/v1/intercept \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"test","tool_name":"read_file","tool_args":{"path":"/tmp/test"},"session_id":"migration-test"}' \
  | jq '.policy_bundle_version'

# Expected: "agentpep-core-v1.0.0"
```

---

## Step 5: Run Parity Validation

Before decommissioning your local policy files, run the parity validation to confirm the AAPM bundle produces identical decisions to your v1.x rules for your workload.

```bash
cd backend
pytest tests/parity/test_aapm_bundle_parity.py -v
```

If you have custom rules, also run the SDK policy simulator against your test vector library:

```bash
agentpep-sdk simulate --test-vectors your_custom_test_vectors.yaml \
  --compare-mode v1-vs-v2 \
  --report parity_report.json
```

**Do not proceed to Step 6 until parity validation passes with zero divergences.**

If you see divergences, contact the AAPM team — they will investigate whether the bundle needs updating to cover your custom rules.

---

## Step 6: Remove Local Policy Configuration

Once parity is confirmed and the AAPM bundle is active, decommission your local policy files.

```bash
# Archive (do not delete yet — keep for 30 days as rollback reference)
mv policies/ policies_archived_$(date +%Y%m%d)/

# Remove deprecated policy config from agentpep.yaml
# (Remove the 'path:', 'rules_file:', etc. keys documented in Step 2.2)
```

**In Kubernetes:** Remove the `policies/` ConfigMap mount from your deployment. The AAPM registry is the only policy source in v2.1.

---

## Step 7: Update Operator Runbooks

Update your internal runbooks to reflect the new policy lifecycle:

| Old Runbook Step | New Runbook Step |
|---|---|
| Edit `policies/rules.yaml` to add/modify a rule | Raise a Policy Change Request (PCR) in AAPM |
| Restart AgentPEP to reload policy | No restart needed — AAPM publishes bundle → AgentPEP reloads within 60s |
| Roll back a policy change: restore previous YAML | AAPM publishes previous bundle version to registry |
| Emergency rule removal | AAPM publishes deny-all bundle → AgentPEP enforces within 5 minutes |

The AAPM operator runbook for this procedure is at `docs/operations/aapm_policy_source.md`.

---

## Helm Chart Changes (Kubernetes Deployments)

The Helm chart `infra/helm/agentpep/values.yaml` has changed in v2.1:

```yaml
# NEW in v2.1 — required
policy:
  aapm:
    registryUrl: "https://registry.aapm.<your-org>.trustfabric.io/agentpep/policies/"
    webhookEnabled: true
    pollIntervalSeconds: 60

# REMOVED in v2.1 — remove these from your values override
policy:
  localPath: ""          # REMOVED
  configMapName: ""      # REMOVED
```

The `agentpep-policies` ConfigMap (mounted from the `policies/` directory in v1.x) is no longer created by the Helm chart and should be removed from your cluster:

```bash
kubectl delete configmap agentpep-policies -n <your-namespace>
```

---

## Airgap Deployments

For air-gapped environments without direct registry connectivity:

1. Work with AAPM to obtain a signed bundle archive (`agentpep-bundle-<version>.tar.gz`)
2. Use `infra/airgap/load-images.sh` to load the bundle into your internal registry
3. Configure AgentPEP to poll your internal registry mirror URL
4. Confirm the internal registry correctly serves the cosign signature alongside the bundle

See `infra/airgap/values-airgap.yaml` for Helm values configured for airgap operation.

---

## Rollback Procedure

If you need to roll back to v1.x:

1. Redeploy the v1.x container image
2. Restore your archived `policies/` directory
3. Restore the v1.x policy configuration keys (`path:`, `rules_file:`, etc.)

The v1.x and v2.1 enforcement decision log formats are compatible — no database migration is required.

**Note:** Rolling back to v1.x re-introduces the config injection vulnerability class (CVE-2025-59536 pattern). Rollback should only be used as a temporary measure while investigating a v2.1 deployment issue.

---

## Common Migration Issues

### Issue: `PolicySourceViolation` at startup

**Symptom:** Log shows `SECURITY_VIOLATION` event at startup; enforcement defaults to DENY.

**Cause:** `POLICY_PATH` environment variable is still set, or a deprecated policy config key is pointing to a local path.

**Fix:** Unset `POLICY_PATH`; remove deprecated config keys. See Step 2.2 and Step 2.3.

---

### Issue: Bundle not loading — `cosign verification failed`

**Symptom:** Log shows `cosign verification failed` and `SECURITY_VIOLATION` event.

**Cause:** The bundle from the registry does not have a valid cosign signature matching the pinned AAPM public key.

**Fix:** Contact the AAPM team — the bundle may not have been signed with the production key, or the registry is serving a stale/corrupted bundle.

---

### Issue: Parity test divergences for custom rules

**Symptom:** `pytest tests/parity/test_aapm_bundle_parity.py` reports divergences.

**Cause:** Your organisation has custom rules in v1.x that are not yet in the AAPM bundle.

**Fix:** File a policy change request with the AAPM team providing your custom rule inventory (Step 1 output). Do not decommission local policy files until AAPM publishes an updated bundle.

---

### Issue: Webhook not receiving pushes — relying on 60-second polling

**Symptom:** Policy updates take up to 60 seconds to apply.

**Cause:** AAPM's webhook push cannot reach your AgentPEP deployment.

**Fix:** Verify the webhook endpoint is reachable from AAPM's IP range. Check firewall rules, ingress controller configuration, and the `webhookIngress` Helm value. Polling-only operation is acceptable but introduces a 60-second latency on policy updates.

---

## Support

For migration issues:
- **AAPM registry connectivity:** Contact your AAPM team contact
- **AgentPEP deployment issues:** `docs/runbooks/operations.md`
- **Custom rule translation:** Raise an AAPM policy change request with your custom rule inventory

---

*Document Owner: TrustFabric Product Architecture*
*Document ID: MIG-001*
*Related: RELEASE_NOTES_v2.1.md, docs/operations/aapm_policy_source.md, docs/integrations/aapm_agentpep_contract_draft.md*
*Distribution: External — Operator Documentation*
