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

    # Authentication
    auth_enabled: bool = False  # Enable API key authentication
    mtls_enabled: bool = False  # Enable mTLS certificate validation

    # gRPC
    grpc_enabled: bool = False
    grpc_port: int = 50051

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

    model_config = {"env_prefix": "AGENTPEP_"}


settings = Settings()
