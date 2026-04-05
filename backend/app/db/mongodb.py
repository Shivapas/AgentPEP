"""MongoDB connection management and collection initialization.

Sprint 23 (APEP-182): Connection pooling — the Motor client is configured
with min/max pool sizes, idle timeouts, and connection timeouts for
high-throughput workloads.
"""

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING, IndexModel

from app.core.config import settings

_client: AsyncIOMotorClient | None = None  # type: ignore[type-arg]
_db: AsyncIOMotorDatabase | None = None  # type: ignore[type-arg]


def get_client() -> AsyncIOMotorClient:  # type: ignore[type-arg]
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(
            settings.mongodb_url,
            # APEP-182: Connection pool settings
            minPoolSize=settings.mongodb_min_pool_size,
            maxPoolSize=settings.mongodb_max_pool_size,
            maxIdleTimeMS=settings.mongodb_max_idle_time_ms,
            connectTimeoutMS=settings.mongodb_connect_timeout_ms,
            serverSelectionTimeoutMS=settings.mongodb_server_selection_timeout_ms,
        )
    return _client


def get_database() -> AsyncIOMotorDatabase:  # type: ignore[type-arg]
    global _db
    if _db is None:
        _db = get_client()[settings.mongodb_db_name]
    return _db


async def close_client() -> None:
    global _client, _db
    if _client is not None:
        _client.close()
        _client = None
        _db = None


# --- Collection Names ---

POLICY_RULES = "policy_rules"
TAINT_NODES = "taint_nodes"
AUDIT_DECISIONS = "audit_decisions"
AGENT_PROFILES = "agent_profiles"
AGENT_ROLES = "agent_roles"
API_KEYS = "api_keys"
TAINT_GRAPHS = "taint_graphs"
TAINT_AUDIT_EVENTS = "taint_audit_events"
SECURITY_ALERTS = "security_alerts"
RISK_MODEL_CONFIGS = "risk_model_configs"
ESCALATION_TICKETS = "escalation_tickets"
APPROVER_GROUPS = "approver_groups"
APPROVAL_MEMORY = "approval_memory"
RATE_LIMIT_COUNTERS = "rate_limit_counters"
MCP_PROXY_SESSIONS = "mcp_proxy_sessions"
CONSOLE_USERS = "console_users"
ESCALATION_TICKETS = "escalation_tickets"
COMPLIANCE_REPORTS = "compliance_reports"
REPORT_SCHEDULES = "report_schedules"
AUDIT_HASH_CHAIN = "audit_hash_chain"


async def init_collections() -> None:
    """Create collections and indexes for AgentPEP."""
    db = get_database()

    # Policy Rules
    policy_rules = db[POLICY_RULES]
    await policy_rules.create_indexes(
        [
            IndexModel([("rule_id", ASCENDING)], unique=True),
            IndexModel([("priority", ASCENDING)]),
            IndexModel([("agent_role", ASCENDING)]),
            IndexModel([("tool_pattern", ASCENDING)]),
            IndexModel([("enabled", ASCENDING)]),
        ]
    )

    # Taint Nodes
    taint_nodes = db[TAINT_NODES]
    await taint_nodes.create_indexes(
        [
            IndexModel([("node_id", ASCENDING)], unique=True),
            IndexModel([("session_id", ASCENDING)]),
            IndexModel(
                [("created_at", ASCENDING)],
                expireAfterSeconds=86400 * 7,  # 7-day TTL for taint nodes
            ),
        ]
    )

    # Audit Decisions (Sprint 10 — APEP-081: capped collection)
    existing_collections = await db.list_collection_names()
    if AUDIT_DECISIONS not in existing_collections:
        try:
            await db.create_collection(
                AUDIT_DECISIONS,
                capped=True,
                size=settings.audit_capped_collection_size,
                max=settings.audit_capped_collection_max_docs,
            )
        except Exception:
            pass  # Collection may already exist in non-capped form

    audit_decisions = db[AUDIT_DECISIONS]
    await audit_decisions.create_indexes(
        [
            IndexModel([("decision_id", ASCENDING)], unique=True),
            IndexModel([("session_id", ASCENDING)]),
            IndexModel([("agent_id", ASCENDING)]),
            IndexModel([("tool_name", ASCENDING)]),
            IndexModel([("decision", ASCENDING)]),
            IndexModel([("timestamp", DESCENDING)]),
            # Sprint 10 — APEP-082: hash chain ordering
            IndexModel([("sequence_number", ASCENDING)], unique=True),
            # Sprint 10 — APEP-085: risk score range queries
            IndexModel([("risk_score", ASCENDING)]),
            IndexModel(
                [("timestamp", ASCENDING)],
                expireAfterSeconds=86400 * settings.audit_retention_days,
            ),
        ]
    )

    # Agent Profiles
    agent_profiles = db[AGENT_PROFILES]
    await agent_profiles.create_indexes(
        [
            IndexModel([("agent_id", ASCENDING)], unique=True),
            IndexModel([("roles", ASCENDING)]),
            IndexModel([("enabled", ASCENDING)]),
        ]
    )

    # Agent Roles (RBAC hierarchy)
    agent_roles = db[AGENT_ROLES]
    await agent_roles.create_indexes(
        [
            IndexModel([("role_id", ASCENDING)], unique=True),
            IndexModel([("parent_roles", ASCENDING)]),
            IndexModel([("enabled", ASCENDING)]),
        ]
    )

    # API Keys
    api_keys = db[API_KEYS]
    await api_keys.create_indexes(
        [
            IndexModel([("key", ASCENDING)], unique=True),
            IndexModel([("tenant_id", ASCENDING)]),
            IndexModel([("enabled", ASCENDING)]),
        ]
    )

    # Taint Graphs (APEP-045: forensic inspection)
    taint_graphs = db[TAINT_GRAPHS]
    await taint_graphs.create_indexes(
        [
            IndexModel([("session_id", ASCENDING)], unique=True),
            IndexModel([("created_at", ASCENDING)]),
            IndexModel(
                [("persisted_at", ASCENDING)],
                expireAfterSeconds=86400 * 30,  # 30-day TTL for persisted graphs
            ),
        ]
    )

    # Taint Audit Events (APEP-052)
    taint_audit_events = db[TAINT_AUDIT_EVENTS]
    await taint_audit_events.create_indexes(
        [
            IndexModel([("event_id", ASCENDING)], unique=True),
            IndexModel([("session_id", ASCENDING)]),
            IndexModel([("event_type", ASCENDING)]),
            IndexModel([("agent_id", ASCENDING)]),
            IndexModel(
                [("timestamp", ASCENDING)],
                expireAfterSeconds=86400 * 90,  # 90-day TTL for taint audit events
            ),
        ]
    )

    # Escalation Tickets (Sprint 18 — APEP-143)
    escalation_tickets = db[ESCALATION_TICKETS]
    await escalation_tickets.create_indexes(
        [
            IndexModel([("ticket_id", ASCENDING)], unique=True),
            IndexModel([("session_id", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("tool_name", ASCENDING)]),
            IndexModel([("agent_id", ASCENDING)]),
            IndexModel([("created_at", DESCENDING)]),
            IndexModel(
                [("created_at", ASCENDING)],
                expireAfterSeconds=86400 * 30,  # 30-day TTL
            ),
    # Audit Hash Chain (APEP-191 — Sprint 24)
    audit_hash_chain = db[AUDIT_HASH_CHAIN]
    await audit_hash_chain.create_indexes(
        [
            IndexModel([("sequence", ASCENDING)], unique=True),
            IndexModel([("decision_id", ASCENDING)]),
            IndexModel([("timestamp", DESCENDING)]),
        ]
    )

    # Security Alerts (APEP-059 — Sprint 7)
    security_alerts = db[SECURITY_ALERTS]
    await security_alerts.create_indexes(
        [
            IndexModel([("alert_id", ASCENDING)], unique=True),
            IndexModel([("session_id", ASCENDING)]),
            IndexModel([("alert_type", ASCENDING)]),
            IndexModel([("agent_id", ASCENDING)]),
            IndexModel([("severity", ASCENDING)]),
            IndexModel(
                [("timestamp", ASCENDING)],
                expireAfterSeconds=86400 * 90,  # 90-day TTL for security alerts
            ),
        ]
    )

    # Risk Model Configs (APEP-063 — Sprint 8)
    risk_model_configs = db[RISK_MODEL_CONFIGS]
    await risk_model_configs.create_indexes(
        [
            IndexModel([("model_id", ASCENDING)], unique=True),
            IndexModel([("enabled", ASCENDING)]),
        ]
    )

    # Escalation Tickets (Sprint 9 — APEP-072)
    escalation_tickets = db[ESCALATION_TICKETS]
    await escalation_tickets.create_indexes(
        [
            IndexModel([("ticket_id", ASCENDING)], unique=True),
            IndexModel([("request_id", ASCENDING)]),
            IndexModel([("session_id", ASCENDING)]),
            IndexModel([("agent_id", ASCENDING)]),
            IndexModel([("state", ASCENDING)]),
            IndexModel([("assigned_to", ASCENDING)]),
    # Compliance Reports (Sprint 22 — APEP-172..174)
    compliance_reports = db[COMPLIANCE_REPORTS]
    await compliance_reports.create_indexes(
        [
            IndexModel([("report_id", ASCENDING)], unique=True),
            IndexModel([("report_type", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("created_at", DESCENDING)]),
        ]
    )

    # Approver Groups (Sprint 9 — APEP-076)
    approver_groups = db[APPROVER_GROUPS]
    await approver_groups.create_indexes(
        [
            IndexModel([("group_id", ASCENDING)], unique=True),
            IndexModel([("enabled", ASCENDING)]),
        ]
    )

    # Approval Memory (Sprint 9 — APEP-077)
    approval_memory = db[APPROVAL_MEMORY]
    await approval_memory.create_indexes(
        [
            IndexModel([("entry_id", ASCENDING)], unique=True),
            IndexModel([("agent_id", ASCENDING), ("tool_name", ASCENDING),
                        ("tool_args_hash", ASCENDING)]),
            IndexModel(
                [("created_at", ASCENDING)],
                expireAfterSeconds=86400 * 7,  # 7-day TTL for approval memory
            ),
        ]
    )

    # Rate Limit Counters (APEP-090/091/092 — Sprint 11)
    rate_limit_counters = db[RATE_LIMIT_COUNTERS]
    await rate_limit_counters.create_indexes(
        [
            IndexModel(
                [("key", ASCENDING), ("window_start", ASCENDING)],
                unique=True,
            ),
            IndexModel(
                [("expires_at", ASCENDING)],
                expireAfterSeconds=0,  # TTL: auto-delete when expires_at is reached
            ),
        ]
    )

    # MCP Proxy Sessions (APEP-101 — Sprint 12)
    mcp_proxy_sessions = db[MCP_PROXY_SESSIONS]
    await mcp_proxy_sessions.create_indexes(
        [
            IndexModel([("session_id", ASCENDING)], unique=True),
            IndexModel([("agent_id", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel(
                [("started_at", ASCENDING)],
                expireAfterSeconds=86400 * 30,  # 30-day TTL
            ),
        ]
    )

    # Console Users (APEP-105 — Sprint 13)
    console_users = db[CONSOLE_USERS]
    await console_users.create_indexes(
        [
            IndexModel([("username", ASCENDING)], unique=True),
            IndexModel([("email", ASCENDING)], unique=True),
            IndexModel([("tenant_id", ASCENDING)]),
            IndexModel([("roles", ASCENDING)]),
    # Report Schedules (Sprint 22 — APEP-177)
    report_schedules = db[REPORT_SCHEDULES]
    await report_schedules.create_indexes(
        [
            IndexModel([("schedule_id", ASCENDING)], unique=True),
            IndexModel([("report_type", ASCENDING)]),
            IndexModel([("enabled", ASCENDING)]),
            IndexModel([("next_run_at", ASCENDING)]),
        ]
    )
