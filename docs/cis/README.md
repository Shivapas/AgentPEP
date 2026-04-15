# Content Ingestion Security (CIS) Documentation

## Overview

Content Ingestion Security (CIS) is AgentPEP's multi-tier scanning pipeline that
protects AI agent sessions from prompt injection, data exfiltration, and other
content-based attacks. CIS operates at multiple points in the agent lifecycle:

- **Pre-session**: Repository scanning before agent launch
- **Per-request**: Real-time scanning of tool inputs/outputs
- **Post-tool**: Automatic scanning of tool output after execution

## Architecture

### Tier 0: Regex Pattern Library (InjectionSignatureLibrary)

- 204 patterns across 25 categories
- Validated against the Mindgard AI IDE taxonomy
- Sub-millisecond per-text evaluation
- Categories include: prompt_override, role_hijack, system_escape, jailbreak,
  encoding_bypass, indirect_injection, data_exfiltration, DLP patterns, etc.

### Tier 1: ONNX Semantic Classifier

- MiniLM-L6-v2 model optimized for prompt injection detection
- 94.3% F1 score on cross-validated benchmark dataset
- Chunked inference for long texts
- Graceful fallback to Tier 0 when model is unavailable

### Scan Modes

| Mode     | Categories | Use Case |
|----------|-----------|----------|
| STRICT   | All 25    | Instruction files, YOLO sessions, high-risk contexts |
| STANDARD | 22        | Normal tool output scanning |
| LENIENT  | 12        | Documentation, test files, low-risk paths |

## YOLO Mode Detection (Sprint 56)

When an agent session is detected as running in YOLO mode (no human oversight),
CIS automatically:

1. Locks the session scan mode to **STRICT**
2. Applies a **1.5x risk multiplier** to all risk scores
3. Emits audit events and Prometheus metrics
4. Prevents downgrade of scan mode for the session duration

### Detection Sources

- **Environment variables**: `YOLO_MODE`, `AUTO_APPROVE`, `SKIP_CONFIRMATION`, etc.
- **CLI flags**: `--yolo`, `--auto-approve`, `--dangerously-skip-permissions`
- **Prompt signals**: Keywords like "yolo mode", "auto-approve all", etc.
- **Behavioural signals**: Rapid-fire tool calls without human review latency

## Per-Session Scan Configuration (Sprint 56)

Sessions can be individually configured with a specific scan mode:

```python
from app.services.session_scan_config import session_scan_config

# Lock a session to STRICT mode
await session_scan_config.set_mode(
    "session-123",
    "STRICT",
    reason="High-risk operation detected",
    lock=True,
)

# Resolve effective mode (session override wins if more restrictive)
mode = await session_scan_config.resolve_mode("session-123", requested="STANDARD")
# Returns "STRICT"
```

## Compliance Exports (Sprint 56)

CIS findings can be exported in compliance-ready formats:

- **CIS_SECURITY**: Standard security findings report
- **CIS_DPDPA**: Mapped to DPDPA data protection requirements
- **CIS_GDPR**: Mapped to GDPR Article 32 security-of-processing

Export formats: JSON, CSV, PDF

## API Endpoints

### CIS Scanning

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/cis/scan-text` | POST | Scan text through multi-tier pipeline |
| `/v1/cis/scan-repo` | POST | Pre-session repository scan |
| `/v1/cis/scan-file` | POST | Scan individual file |
| `/v1/cis/session-scan` | POST | Scan-on-session-start hook |
| `/v1/cis/post-tool-scan` | POST | PostToolUse auto-scan |
| `/v1/cis/findings` | GET | List recent CIS findings |

### Sprint 56 Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/sprint56/session-config/scan-mode` | POST | Set per-session scan mode |
| `/v1/sprint56/session-config/scan-mode` | GET | Get session scan config |
| `/v1/sprint56/session-config/resolve` | GET | Resolve effective scan mode |
| `/v1/sprint56/yolo/check` | POST | Check and propagate YOLO mode |
| `/v1/sprint56/yolo/propagate` | POST | Explicitly propagate YOLO flag |
| `/v1/sprint56/yolo/status` | GET | Get YOLO status for session |
| `/v1/sprint56/yolo/sessions` | GET | List YOLO-flagged sessions |
| `/v1/sprint56/cis-export` | POST | Export CIS findings (JSON/CSV/PDF) |
| `/v1/sprint56/cis-dashboard` | GET | CIS dashboard data |

## SDK Integration

### YOLO Mode Detection

```python
from agentpep.yolo_detector import detect_yolo_mode

result = detect_yolo_mode()
if result.yolo_detected:
    print(f"YOLO mode active: {result.signals}")
    # Risk multiplier: {result.risk_multiplier}x
```

### CLI Usage

```bash
# Detect YOLO mode from environment
python -m agentpep.yolo_detector

# Detect and propagate to server
python -m agentpep.yolo_detector \
    --session-id sess-123 \
    --propagate \
    --base-url http://localhost:8000
```

## Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `agentpep_cis_yolo_detections_total` | Counter | YOLO mode detections by source |
| `agentpep_cis_yolo_active_sessions` | Gauge | Active YOLO sessions |
| `agentpep_cis_session_config_changes_total` | Counter | Session config changes |
| `agentpep_cis_session_risk_multiplier` | Histogram | Risk multiplier distribution |
| `agentpep_cis_compliance_exports_total` | Counter | Compliance exports by format |
| `agentpep_cis_scan_mode_usage_total` | Counter | Scans by effective mode |
| `agentpep_cis_dashboard_queries_total` | Counter | Dashboard queries |

## Grafana Dashboard

Import the provisioned dashboard from `infra/grafana/dashboards/cis-overview.json`.

Panels include:
- YOLO Session Alerts (stat panel)
- Findings by Severity (pie chart)
- Scan Mode Distribution (bar chart)
- Scanner Tier Performance (time series)
- Risk Multiplier Distribution (histogram)
- Compliance Export Activity (counter)
