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
