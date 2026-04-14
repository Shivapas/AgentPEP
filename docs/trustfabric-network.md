# TrustFabric Network (TFN) Documentation

> **Sprint 51 (APEP-411)** — TrustFabric Network module documentation covering
> architecture, rule bundles, security assessment, MITRE ATT&CK mapping,
> and the Network Events console.

## Overview

TrustFabric Network (TFN) is AgentPEP's network egress security layer,
operating alongside the existing tool-call enforcement engine.  TFN provides:

- **Network DLP** — 46+ patterns detecting API keys, tokens, credentials
- **11-Layer URL Scanner** — phishing, malware, DNS rebinding, SSRF detection
- **Response Injection Scanner** — 6-pass normalisation, 23 injection patterns
- **Fetch Proxy** — HTTP/HTTPS fetch with automatic response scanning
- **Forward Proxy** — CONNECT tunneling for HTTPS traffic
- **WebSocket Proxy** — bidirectional frame scanning
- **MCP Proxy Enhancement** — bidirectional DLP + tool poisoning detection
- **Tool Call Chain Detection** — 10 built-in multi-step attack patterns
- **Kill Switch** — emergency deny-all with 4 independent activation sources
- **Filesystem Sentinel** — file monitoring with DLP scanning
- **Adaptive Threat Score** — session-level threat scoring with signal decay
- **Ed25519-Signed Rule Bundles** — community rule distribution
- **Security Assessment Engine** — config audit + attack simulation + deployment probe
- **MITRE ATT&CK Tagging** — technique ID enrichment on all events
- **Prometheus Metrics** — full observability for all TFN operations

## Architecture

TFN runs within the AgentPEP backend process, sharing services and
infrastructure:

```
┌─────────────────────────────────────────────────────────────────┐
│                  AgentPEP Backend Process                        │
│                                                                  │
│  Port 8888 — Intercept API (existing)                            │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  PolicyEvaluator → RBAC, Taint, Deputy, Risk, Rate Limit │    │
│  │  + TFN DLP Pre-Scan hook: scan tool args before eval      │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Port 8889 — TrustFabric Network                                 │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  /v1/fetch            Fetch proxy + injection scanning    │    │
│  │  /v1/scan             Programmatic scan API               │    │
│  │  /v1/network/assess   Security assessment endpoint        │    │
│  │  /v1/network/bundles  Rule bundle management              │    │
│  │  /v1/network/mitre    MITRE ATT&CK technique map          │    │
│  │  /v1/killswitch       Emergency deny-all                  │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Shared Services                                                 │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  NetworkDLPScanner · ResponseInjectionScanner             │    │
│  │  URLScanner (11 layers) · SSRFGuard · EntropyAnalyzer     │    │
│  │  ToolCallChainDetector · FilesystemSentinel               │    │
│  │  RuleBundleLoader · SecurityAssessmentEngine              │    │
│  │  MitreAttackMapper · AdaptiveThreatScore                  │    │
│  │  session_graph_manager (taint) · kafka_producer           │    │
│  └──────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Rule Bundles (APEP-404/405)

### Format

Rule bundles are YAML files containing a manifest header, optional Ed25519
signature, and a list of detection rules:

```yaml
manifest:
  name: community-dlp-v1
  version: 1.0.0
  author: AgentPEP Community
  description: Community DLP patterns for API key detection
  tags: [dlp, api-keys, community]

signature: <base64-encoded Ed25519 signature>
signing_key_id: community-key-1

rules:
  - rule_id: DLP-COMMUNITY-001
    rule_type: DLP
    pattern: "(?i)sk-[a-z0-9]{48}"
    severity: HIGH
    description: OpenAI API Key
    mitre_technique_id: T1552

  - rule_id: DLP-COMMUNITY-002
    rule_type: DLP
    pattern: "(?i)ghp_[A-Za-z0-9]{36}"
    severity: HIGH
    description: GitHub Personal Access Token
    mitre_technique_id: T1552.001
```

### Rule Types

| Type | Description |
|------|-------------|
| `DLP` | Data Loss Prevention pattern (regex) |
| `INJECTION` | Prompt injection signature |
| `URL_BLOCK` | Domain or URL blocklist entry |
| `CHAIN_PATTERN` | Multi-step attack chain pattern |
| `CUSTOM` | Custom detection rule |

### Bundle Lifecycle

1. **Load** — Parse YAML and validate rules
2. **Verify** — Check Ed25519 signature against trusted keys
3. **Review** — Bundle enters `PENDING_REVIEW` status
4. **Activate** — Rules become effective in the scanning pipeline
5. **Deactivate** — Rules are suspended but bundle remains loaded

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/network/bundles` | List all loaded bundles |
| `POST` | `/v1/network/bundles` | Load a new bundle |
| `GET` | `/v1/network/bundles/{id}` | Get bundle details |
| `POST` | `/v1/network/bundles/{id}/activate` | Activate a bundle |
| `POST` | `/v1/network/bundles/{id}/deactivate` | Deactivate a bundle |
| `DELETE` | `/v1/network/bundles/{id}` | Remove a bundle |

### Ed25519 Signature Verification

Bundles use the same Ed25519 infrastructure as receipt signing (Sprint 32).
To verify bundles:

1. Register trusted public keys via `rule_bundle_loader.register_trusted_key()`
2. Set `verify_signature=true` in the load request
3. The loader computes a canonical JSON representation and verifies the signature

## Security Assessment Engine (APEP-406/407)

### Overview

The security assessment engine provides a `ToolTrust assess`-equivalent
capability with three phases:

1. **Config Audit** — 12-category configuration checklist
2. **Attack Simulation** — DRY_RUN probes of known attack patterns
3. **Deployment Probe** — runtime environment security verification

### Assessment Categories

| Category | Description |
|----------|-------------|
| `DLP_COVERAGE` | DLP pattern count and coverage |
| `INJECTION_PROTECTION` | Injection signature availability |
| `SSRF_PREVENTION` | SSRF guard configuration |
| `RATE_LIMITING` | Global rate limiting status |
| `AUTH_CONFIG` | Authentication and JWT configuration |
| `TAINT_TRACKING` | Taint graph engine availability |
| `KILL_SWITCH` | Kill switch availability and readiness |
| `CHAIN_DETECTION` | Chain detection pattern coverage |
| `FILESYSTEM_SENTINEL` | Filesystem monitoring status |
| `TLS_CONFIG` | TLS/mTLS configuration |
| `AUDIT_INTEGRITY` | Kafka streaming and receipt signing |
| `NETWORK_EGRESS` | Default fail mode and egress policy |

### Scoring

The assessment produces a score from 0-100 with letter grades:

| Grade | Score Range |
|-------|-------------|
| A | 90-100 |
| B | 80-89 |
| C | 70-79 |
| D | 60-69 |
| F | 0-59 |

Deductions per severity:
- **CRITICAL**: -15 points
- **HIGH**: -10 points
- **MEDIUM**: -5 points
- **LOW**: -2 points

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/network/assess` | Run full assessment |
| `POST` | `/v1/network/assess` | Run customised assessment |

## MITRE ATT&CK Mapping (APEP-408)

### Technique Coverage

TFN maps all event types and detection rules to MITRE ATT&CK techniques:

| Event Type | Primary Technique | Description |
|------------|-------------------|-------------|
| `DLP_HIT` | T1552 | Unsecured Credentials |
| `INJECTION_DETECTED` | T1059 | Command and Scripting Interpreter |
| `SSRF_BLOCKED` | T1190 | Exploit Public-Facing Application |
| `CHAIN_DETECTED` | T1119 | Automated Collection |
| `KILL_SWITCH` | T1565 | Data Manipulation |
| `SENTINEL_HIT` | T1552.001 | Credentials In Files |

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/network/mitre` | Full technique map |
| `GET` | `/v1/network/mitre/stats` | Map statistics |

## Network Events Console (APEP-409)

The Policy Console includes a **Network Events** tab accessible at
`/network-events`.  This tab displays:

- **Security Assessment Summary** — overall score, grade, and check counts
- **Rule Bundles** — loaded bundles with status and verification state
- **MITRE ATT&CK Coverage** — technique, event, and rule mapping counts
- **Assessment Findings** — detailed table of all findings with severity,
  category, phase, MITRE technique, and remediation recommendations

## Prometheus Metrics (APEP-410)

Sprint 51 adds the following Prometheus metrics:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `agentpep_tfn_network_events_total` | Counter | event_type, severity | Total TFN network events |
| `agentpep_tfn_bundle_loads_total` | Counter | status | Bundle load operations |
| `agentpep_tfn_bundle_rules_active` | Gauge | — | Active rules from bundles |
| `agentpep_tfn_bundles_active` | Gauge | — | Active bundles |
| `agentpep_tfn_assessment_total` | Counter | grade | Assessment runs by grade |
| `agentpep_tfn_assessment_score` | Histogram | — | Score distribution |
| `agentpep_tfn_assessment_latency_seconds` | Histogram | — | Assessment latency |
| `agentpep_tfn_assessment_findings_total` | Counter | category, severity | Findings count |
| `agentpep_tfn_mitre_tags_total` | Counter | technique_id | MITRE tags applied |
| `agentpep_tfn_kill_switch_activations_total` | Counter | source | Kill switch activations |
| `agentpep_tfn_sentinel_findings_total` | Counter | event_type, severity | Sentinel findings |
| `agentpep_tfn_threat_score` | Histogram | — | Threat score distribution |
| `agentpep_tfn_url_scan_total` | Counter | result | URL scan results |
| `agentpep_tfn_url_scan_latency_seconds` | Histogram | — | URL scan latency |

## Configuration

Sprint 51 adds the following environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTPEP_RULE_BUNDLE_ENABLED` | `true` | Enable rule bundle loading |
| `AGENTPEP_RULE_BUNDLE_AUTO_LOAD_PATHS` | `[]` | Paths to auto-load on startup |
| `AGENTPEP_RULE_BUNDLE_VERIFY_SIGNATURES` | `true` | Require Ed25519 verification |
| `AGENTPEP_SECURITY_ASSESSMENT_ENABLED` | `true` | Enable assessment engine |
| `AGENTPEP_MITRE_ATTACK_MAPPING_ENABLED` | `true` | Enable MITRE technique mapping |

## Dependencies

Sprint 51 reuses existing dependencies:

- **PyNaCl** (optional) — Ed25519 signature verification (same as Sprint 32)
- **PyYAML** — YAML bundle parsing (via `yaml.safe_load`)
- **Prometheus client** — metrics (existing)
- **FastAPI** — API endpoints (existing)
