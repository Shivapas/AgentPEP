"""Application configuration loaded from environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """AgentPEP backend configuration."""

    app_name: str = "AgentPEP"
    app_version: str = "0.1.0"
    debug: bool = False

    # MongoDB
    mongodb_url: str = "mongodb://localhost:27017"
    mongodb_db_name: str = "agentpep"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # Observability
    otlp_endpoint: str = "http://localhost:4317"
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

    model_config = {"env_prefix": "AGENTPEP_"}


settings = Settings()
