# AgentPEP — Licensing Model

**Version:** 1.0
**Effective Date:** April 2026

---

## Overview

AgentPEP is licensed on a **per-agent decision volume** model. Pricing is based
on the number of policy decisions (intercept calls) processed per month, with
tiers designed to scale from development teams to large enterprise deployments.

---

## Tier Structure

| Tier | Monthly Decisions | Agents | Support | Price (USD/mo) |
|------|-------------------|--------|---------|----------------|
| **Developer** | Up to 50,000 | Up to 5 | Community / Docs | Free |
| **Team** | Up to 500,000 | Up to 25 | Email (48h SLA) | $499 |
| **Business** | Up to 5,000,000 | Up to 100 | Priority (8h SLA) | $2,499 |
| **Enterprise** | Unlimited | Unlimited | Dedicated (1h SLA) | Custom |

### What Counts as a Decision

A **decision** is a single call to the `/v1/intercept` endpoint (REST or gRPC)
that evaluates a tool invocation against the policy stack and returns an ALLOW
or DENY result. The following do not count against decision volume:

- Health check requests (`/health`)
- Taint label operations (`/v1/taint/label`)
- Metrics scrape requests (`/metrics`)
- SDK-side offline evaluations (no server call)

---

## Tier Details

### Developer (Free)

- Intended for individual developers, prototyping, and evaluation.
- Full feature access (RBAC, taint tracking, confused-deputy detection).
- Community support via documentation and GitHub Discussions.
- Single-tenant, single-region deployment.
- No SLA commitment.

### Team

- For small teams running agents in staging and light production.
- Email support with 48-hour response SLA.
- Multi-tenant support with tenant isolation.
- Access to SDK and all integrations (LangChain, LangGraph).
- 99.9% monthly uptime SLA.

### Business

- For production workloads with compliance requirements.
- Priority support with 8-hour response SLA.
- SOC 2 Type II compliance attestation.
- GDPR data processing addendum included.
- Custom policy templates and onboarding assistance.
- 99.95% monthly uptime SLA.

### Enterprise

- For large-scale, mission-critical deployments.
- Dedicated technical account manager.
- 1-hour response SLA for P0 incidents.
- Custom deployment options: on-premises, private cloud, or managed SaaS.
- Custom audit and compliance integrations.
- Volume discounts and annual billing available.
- 99.99% monthly uptime SLA (negotiable).

---

## Add-Ons

| Add-On | Description | Price |
|--------|-------------|-------|
| **Extended Audit Retention** | Audit log retention beyond 90 days (up to 7 years) | $199/mo |
| **Dedicated Infrastructure** | Single-tenant isolated deployment | $999/mo |
| **Premium Onboarding** | Hands-on integration support (40 hours) | $5,000 one-time |
| **Custom Integrations** | Bespoke agent framework adapters | Custom |

---

## Overage Policy

If a tier's monthly decision limit is exceeded:

1. **Soft limit (up to 120%):** Service continues. Customer is notified and
   invoiced for overage at 1.5x the per-decision rate of the next tier.
2. **Hard limit (above 120%):** Customer is prompted to upgrade. Service
   continues in FAIL_CLOSED mode for decisions beyond the hard limit (new
   requests receive DENY with an `OVER_QUOTA` reason code).

Overage alerts are sent at 80%, 100%, and 120% of the tier limit.

---

## Billing

- **Monthly billing** by default; annual billing available (2 months free).
- Payment via credit card, ACH, or wire transfer.
- Enterprise tier: custom invoicing and PO-based billing.
- All prices in USD. Taxes applied based on jurisdiction.

---

## Free-to-Paid Conversion

The Developer tier is free indefinitely with no credit card required. Upgrading
to a paid tier preserves all existing policies, audit history, and
configuration. No data migration is needed.

---

## Contact

- **Sales:** sales@trustfabric.example.com
- **Licensing questions:** licensing@trustfabric.example.com
- **Enterprise inquiries:** enterprise@trustfabric.example.com

---

*AgentPEP · TrustFabric Portfolio · © 2026*
