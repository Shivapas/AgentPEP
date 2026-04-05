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

    model_config = {"env_prefix": "AGENTPEP_"}


settings = Settings()
