"""Application configuration loaded from environment variables."""

import logging

from pydantic_settings import BaseSettings

_config_logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """AgentPEP backend configuration."""

    app_name: str = "AgentPEP"
    app_version: str = "1.0.0"
    debug: bool = False

    # MongoDB
    mongodb_url: str = "mongodb://localhost:27017"
    mongodb_db_name: str = "agentpep"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # Observability
    otlp_endpoint: str = ""
    metrics_enabled: bool = True

    # Policy defaults
    default_fail_mode: str = "FAIL_CLOSED"  # FAIL_OPEN or FAIL_CLOSED
    audit_retention_days: int = 365
    evaluation_timeout_s: float = 5.0  # Timeout for policy evaluation in seconds

    # Rate Limiting (APEP-092 — Sprint 11)
    global_rate_limit_enabled: bool = False
    global_rate_limit_per_second: int = 1000  # Per-tenant decisions/second ceiling

    # Authentication
    auth_enabled: bool = False  # Enable API key authentication
    mtls_enabled: bool = False  # Enable mTLS certificate validation

    # Trusted proxy IPs for X-Forwarded-For header validation
    trusted_proxy_ips: list[str] = []

    # JWT (Console authentication)
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7
    # CORS (APEP-215)
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # gRPC
    grpc_enabled: bool = False
    grpc_port: int = 50051
    grpc_tls_cert_path: str = ""
    grpc_tls_key_path: str = ""

    # Escalation (Sprint 9)
    escalation_timeout_seconds: int = 300  # Default timeout for escalation tickets
    escalation_timeout_action: str = "DENIED"  # DENIED or APPROVED on timeout
    escalation_email_webhook_url: str = ""
    escalation_slack_webhook_url: str = ""
    escalation_slack_channel: str = ""

    # Kafka (Sprint 10 — APEP-083)
    kafka_enabled: bool = False
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_decisions_topic: str = "agentpep.decisions"
    kafka_producer_acks: str = "all"
    kafka_producer_retries: int = 3

    # Audit Engine (Sprint 10)
    audit_capped_collection_size: int = 1_073_741_824  # 1 GB default
    audit_capped_collection_max_docs: int = 10_000_000  # 10M docs max
    # MCP Proxy (Sprint 12)
    mcp_proxy_enabled: bool = False
    mcp_proxy_default_timeout_s: float = 30.0
    # Escalation (Sprint 18)
    escalation_sla_seconds: int = 300  # Default SLA window for escalation tickets
    # Splunk HEC (APEP-175)
    splunk_hec_url: str = ""
    splunk_hec_token: str = ""
    splunk_hec_index: str = "agentpep"

    # Elasticsearch (APEP-176)
    elasticsearch_url: str = ""
    elasticsearch_index: str = "agentpep-decisions"
    elasticsearch_api_key: str = ""

    # Report Scheduler (APEP-177)
    report_scheduler_enabled: bool = False
    report_scheduler_interval_s: float = 300.0
    # Redis (Sprint 23 — APEP-181)
    redis_url: str = "redis://localhost:6379/0"
    redis_enabled: bool = False
    redis_policy_cache_ttl_s: float = 30.0

    # MongoDB connection pool (Sprint 23 — APEP-182)
    mongodb_min_pool_size: int = 10
    mongodb_max_pool_size: int = 100
    mongodb_max_idle_time_ms: int = 30000
    mongodb_connect_timeout_ms: int = 5000
    mongodb_server_selection_timeout_ms: int = 5000

    # Taint graph limits (Sprint 23 — APEP-183)
    taint_graph_max_nodes_per_session: int = 10000

    # Async audit log (Sprint 23 — APEP-184)
    audit_log_batch_size: int = 50
    audit_log_flush_interval_s: float = 1.0

    # Adaptive timeout (Sprint 23 — APEP-186)
    evaluation_timeout_cached_s: float = 2.0
    evaluation_timeout_cold_s: float = 5.0

    # Auth Provider Registry (Sprint 31 — APEP-243)
    auth_provider_default_chain: list[str] = ["apikey"]
    auth_provider_tenant_chains: str = ""  # JSON: {"tenant-id": ["oauth2", "apikey"]}
    oauth2_enabled: bool = False
    saml_enabled: bool = False

    # OAuth2/OIDC (Sprint 31 — APEP-241)
    oauth2_issuer_url: str = ""
    oauth2_audience: str = ""
    oauth2_role_claim_path: str = "realm_access.roles"
    oauth2_jwks_refresh_interval_s: int = 3600
    oauth2_allowed_algorithms: list[str] = ["RS256", "ES256"]

    # SAML (Sprint 31 — APEP-242)
    saml_idp_metadata_url: str = ""
    saml_sp_entity_id: str = ""
    saml_sp_acs_url: str = ""
    saml_role_attribute: str = "Role"
    saml_certificate_path: str = ""

    # Redis Storage Backend (Sprint 31 — APEP-244)
    redis_storage_enabled: bool = False
    redis_storage_url: str = ""
    redis_storage_key_prefix: str = "agentpep"
    redis_storage_default_ttl_s: int = 3600

    # Redis Rate Limiter (Sprint 31 — APEP-245)
    redis_rate_limiter_enabled: bool = False

    # Audit Verbosity (Sprint 32 — APEP-253)
    audit_verbosity: str = "FULL"

    # CloudWatch Audit (Sprint 32 — APEP-250)
    cloudwatch_audit_enabled: bool = False
    cloudwatch_audit_log_group: str = "/agentpep/audit"
    cloudwatch_audit_log_stream: str = "decisions"
    cloudwatch_audit_region: str = "us-east-1"

    # Datadog Audit (Sprint 32 — APEP-251)
    datadog_audit_enabled: bool = False
    datadog_api_key: str = ""
    datadog_site: str = "datadoghq.com"
    datadog_service_name: str = "agentpep"

    # Loki Audit (Sprint 32 — APEP-252)
    loki_audit_enabled: bool = False
    loki_push_url: str = ""
    loki_tenant_id: str = ""

    # PagerDuty (Sprint 32 — APEP-255)
    pagerduty_enabled: bool = False
    pagerduty_routing_key: str = ""

    # Microsoft Teams (Sprint 32 — APEP-255)
    teams_enabled: bool = False
    teams_webhook_url: str = ""

    # Sprint 33 — APEP-259/260/261/264: Feature flags
    memory_access_gate_enabled: bool = False
    context_authority_enabled: bool = False
    defer_default_timeout_s: int = 60

    # Sprint 36 — APEP-285/286/288/290: Feature flags
    hash_chained_context_enabled: bool = False
    trust_degradation_engine_enabled: bool = False
    tenant_isolation_enabled: bool = False

    # Sprint 35 — APEP-276/278/279: Detection feature flags
    tool_combination_detection_enabled: bool = True
    velocity_window_seconds: int = 300
    velocity_z_score_threshold: float = 2.5
    velocity_min_sample_size: int = 10
    echo_detection_enabled: bool = True
    echo_similarity_threshold: float = 0.85
    echo_window_size: int = 20
    adaptive_hardening_enabled: bool = True
    pii_redaction_enabled: bool = True
    pii_redaction_placeholder: str = "[REDACTED]"

    # Receipt Signing (Sprint 32 — APEP-256)
    receipt_signing_enabled: bool = False
    receipt_signing_method: str = "hmac-sha256"  # "ed25519" or "hmac-sha256"
    receipt_signing_key: str = ""  # Base64-encoded private/secret key
    receipt_key_id: str = "default"

    # Sprint 39 — APEP-309: Per-receipt Ed25519 signing
    per_receipt_signing_enabled: bool = False
    per_receipt_signing_key: str = ""  # Base64-encoded Ed25519 private key

    # Sprint 37 — APEP-292..298: MissionPlan
    mission_plan_enabled: bool = False
    mission_plan_signing_method: str = "ed25519"  # "ed25519" or "hmac-sha256"
    mission_plan_signing_key: str = ""  # Base64-encoded private/secret key
    mission_plan_key_id: str = "plan-default"
    mission_plan_expiry_job_enabled: bool = False
    mission_plan_expiry_interval_s: float = 60.0

    # Sprint 44 — APEP-348..355: TFN Network DLP & URL Scanner
    network_dlp_enabled: bool = True
    network_dlp_scan_tool_args: bool = True
    url_scanner_enabled: bool = True
    ssrf_guard_allow_private: bool = False
    ssrf_guard_allow_loopback: bool = False
    domain_rate_limit_default_rps: int = 100
    domain_rate_limit_window_s: int = 60
    domain_data_budget_bytes: int = 10_485_760  # 10 MB
    kafka_network_topic: str = "agentpep.network"

    # Sprint 46 — APEP-364..371: Fetch Proxy & Response Injection Scanner
    fetch_proxy_enabled: bool = True
    fetch_proxy_timeout_s: float = 30.0
    fetch_proxy_max_body_bytes: int = 1_048_576  # 1 MB
    response_normalizer_enabled: bool = True
    response_injection_scanner_enabled: bool = True
    response_dlp_scan_enabled: bool = True
    kafka_fetch_topic: str = "agentpep.fetch"

    # Sprint 45 — APEP-356..363: DLP Pre-Scan Hook
    dlp_pre_scan_enabled: bool = False
    dlp_cache_enabled: bool = True
    dlp_cache_max_size: int = 10_000
    dlp_cache_ttl_s: float = 300.0
    dlp_scan_timeout_s: float = 5.0
    dlp_risk_elevation_enabled: bool = True
    dlp_taint_assignment_enabled: bool = True
    dlp_pattern_reload_interval_s: float = 600.0

    # Sprint 48 — APEP-380..387: MCP Proxy Enhancement
    mcp_dlp_scan_enabled: bool = True
    mcp_poisoning_detection_enabled: bool = True
    mcp_rug_pull_detection_enabled: bool = True
    mcp_dlp_budget_enabled: bool = True
    mcp_dlp_budget_max_findings: int = 10
    mcp_dlp_budget_max_critical: int = 3
    mcp_dlp_budget_max_outbound_bytes: int = 104_857_600  # 100MB
    mcp_dlp_budget_max_inbound_bytes: int = 524_288_000  # 500MB
    mcp_outbound_dlp_block_critical: bool = True
    mcp_outbound_dlp_block_high: bool = False
    mcp_reverse_proxy_enabled: bool = False
    mcp_reverse_proxy_port: int = 8890
    kafka_mcp_security_topic: str = "agentpep.mcp_security"

    # Sprint 49 — APEP-388..395: Tool Call Chain Detection Engine
    chain_detection_enabled: bool = True
    chain_detection_history_limit: int = 100
    chain_detection_default_window_s: int = 600
    kafka_chain_detection_topic: str = "agentpep.chain_detection"

    # Sprint 50 — APEP-396..403: Kill Switch, Filesystem Sentinel & Adaptive Threat Score
    kill_switch_enabled: bool = True
    kill_switch_activated: bool = False  # Config flag activation source (source 4)
    kill_switch_sentinel_path: str = "/tmp/agentpep-killswitch"
    kill_switch_sentinel_poll_s: float = 1.0
    kill_switch_config_poll_s: float = 5.0
    kill_switch_isolated_port_enabled: bool = False
    kill_switch_isolated_port: int = 8890
    kill_switch_isolated_host: str = "127.0.0.1"
    filesystem_sentinel_enabled: bool = True
    filesystem_sentinel_watch_paths: list[str] = ["/tmp", "/var/tmp"]
    filesystem_sentinel_file_patterns: list[str] = ["*.env", "*.key", "*.pem", "*.secret", "*.credentials"]
    filesystem_sentinel_max_scan_bytes: int = 1_048_576
    adaptive_threat_score_enabled: bool = True
    adaptive_threat_score_window_s: int = 600
    adaptive_threat_score_escalation_threshold: float = 0.7
    adaptive_threat_score_deescalation_threshold: float = 0.3

    # Sprint 51 — APEP-404..411: Rule Bundles, Security Assessment & Network Audit Events
    rule_bundle_enabled: bool = True
    rule_bundle_auto_load_paths: list[str] = []
    rule_bundle_verify_signatures: bool = True
    security_assessment_enabled: bool = True
    mitre_attack_mapping_enabled: bool = True

    # Sprint S-E02 — FEATURE-03: Complexity Budget (Evaluation Guarantee Invariant)
    complexity_budget_enabled: bool = True
    # Maximum serialised byte size of tool_args JSON (default 64 KB)
    complexity_budget_max_arg_bytes: int = 65536
    # Maximum shell metacharacter count across all string values
    complexity_budget_max_subcommand_count: int = 10
    # Maximum dict/list nesting depth
    complexity_budget_max_nesting_depth: int = 10
    # Hard evaluation timeout; on expiry → unconditional DENY (no FAIL_OPEN override)
    complexity_budget_eval_timeout_s: float = 5.0

    # Sprint S-E03 — FEATURE-02: Trusted Policy Loader + AAPM Consumer Interface
    policy_loader_enabled: bool = True
    # HTTP timeout for bundle and signature fetches from the AAPM registry
    policy_loader_http_timeout_s: float = 30.0
    # Bundle URL polled as fallback (overrides the default built from base URL)
    policy_registry_bundle_url: str = (
        "https://registry.trustfabric.internal/agentpep/policies/"
        "global/core_enforcement/latest/bundle.tar.gz"
    )
    # Polling interval for the registry pull-polling fallback (seconds)
    policy_poll_interval_s: float = 60.0
    # Tenant identifier reported in enforcement decision events
    policy_tenant_id: str = "global"
    # Logical bundle name reported in enforcement decision events
    policy_bundle_name: str = "core_enforcement"

    # Sprint S-E04 — FEATURE-01: OPA Runtime Engine — Core (PDP)
    pdp_enabled: bool = True
    # Per-evaluation OPA timeout; expiry → unconditional DENY (Evaluation Guarantee Invariant)
    pdp_eval_timeout_s: float = 5.0
    # OPA query entrypoint matching the bundle's package path
    pdp_query: str = "data.agentpep.core.allow"
    # Maximum entries retained in the in-memory enforcement decision ring buffer
    pdp_log_max_entries: int = 10_000

    # Sprint S-E07 — FEATURE-05: PostToolUse Hooks + TrustSOC Integration Contract
    # Kafka topic for PostToolUse OCSF events (TrustSOC consumer reads from here)
    kafka_posttooluse_topic: str = "agentpep.posttooluse.events"
    # HMAC-SHA256 key for tamper-evident PostToolUse event signing.
    # Set via AGENTPEP_POSTTOOLUSE_HMAC_KEY. If unset, events are unsigned
    # (warning logged once). Minimum 32 characters recommended in production.
    posttooluse_hmac_key: str = ""
    # Maximum milliseconds allowed for PostToolUse hook invocation + Kafka publish.
    # Exceeded latency is logged as a warning; the pipeline is never blocked.
    posttooluse_kafka_sla_ms: int = 500

    # Sprint 55 — APEP-436..443: CaMeL SEQ Rules, Layer 3 Bridge & Self-Protection
    camel_seq_enabled: bool = True
    camel_seq_rules_enabled: bool = True
    camel_seq_marker_ttl_s: int = 600
    camel_seq_max_markers_per_session: int = 500
    session_marker_enabled: bool = True
    tooltrust_bridge_enabled: bool = True
    cis_verdict_taint_enabled: bool = True
    self_protection_enabled: bool = True
    protected_path_guard_enabled: bool = True
    seq_dry_run: bool = False  # When True, enforcing SEQ rules log only
    kafka_camel_seq_topic: str = "agentpep.camel_seq"

    model_config = {"env_prefix": "AGENTPEP_"}


settings = Settings()

if settings.jwt_secret == "change-me-in-production":
    if not settings.debug:
        raise RuntimeError(
            "CRITICAL: JWT secret is set to the insecure default value and debug mode is off. "
            "Set AGENTPEP_JWT_SECRET to a strong random string (min 32 characters) "
            "before deploying to production."
        )
    _config_logger.warning(
        "JWT secret is set to the insecure default value. "
        "Set AGENTPEP_JWT_SECRET to a strong random string before deploying to production."
    )
elif len(settings.jwt_secret) < 32:
    _config_logger.warning(
        "JWT secret is shorter than 32 characters. Use a longer secret for production."
    )
