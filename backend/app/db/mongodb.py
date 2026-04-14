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
COMPLIANCE_REPORTS = "compliance_reports"
REPORT_SCHEDULES = "report_schedules"
DATA_CLASSIFICATION_RULES = "data_classification_rules"  # Sprint 31 — APEP-246
AUDIT_HASH_CHAIN = "audit_hash_chain"
# Sprint 33 — APEP-261/262/263: Memory access gate
MEMORY_ACCESS_POLICIES = "memory_access_policies"
MEMORY_ENTRIES = "memory_entries"
# Sprint 33 — APEP-264: Context authority tracking
CONTEXT_ENTRIES = "context_entries"
# Sprint 36 — APEP-285..APEP-291
HASH_CHAINED_CONTEXT = "hash_chained_context"
TRUST_DEGRADATION_RECORDS = "trust_degradation_records"
DEFER_DECISIONS = "defer_decisions"
STEP_UP_CHALLENGES = "step_up_challenges"
POLICY_CONFLICTS = "policy_conflicts"
TENANT_ISOLATION_CONFIGS = "tenant_isolation_configs"
TENANT_ISOLATION_VIOLATIONS = "tenant_isolation_violations"
# Sprint 37 — APEP-292..298: MissionPlan
MISSION_PLANS = "mission_plans"
PLAN_SESSION_BINDINGS = "plan_session_bindings"
# Sprint 38 — APEP-300..307: Scope Pattern Language
SCOPE_PATTERNS = "scope_patterns"
# Sprint 39 — APEP-310: Receipt chain tracking
RECEIPT_CHAINS = "receipt_chains"
# Sprint 40 — APEP-321: Budget alert events
PLAN_BUDGET_ALERTS = "plan_budget_alerts"
# Sprint 41 — APEP-326: Plan-scoped checkpoint approval memory
PLAN_CHECKPOINT_APPROVALS = "plan_checkpoint_approvals"
# Sprint 41 — APEP-324/325: Checkpoint escalation history
CHECKPOINT_ESCALATION_HISTORY = "checkpoint_escalation_history"
# Sprint 45 — APEP-356..363: DLP Pre-Scan Hook
DLP_PATTERNS = "dlp_patterns"
DLP_SCAN_RESULTS = "dlp_scan_results"
# Sprint 48 — APEP-380..387: MCP Proxy Enhancement
MCP_DLP_SCAN_RESULTS = "mcp_dlp_scan_results"
MCP_TOOL_POISONING_RESULTS = "mcp_tool_poisoning_results"
MCP_RUG_PULL_DETECTIONS = "mcp_rug_pull_detections"
MCP_SECURITY_EVENTS = "mcp_security_events"
# Sprint 50 — APEP-396..403: Kill Switch, Filesystem Sentinel & Adaptive Threat Score
KILL_SWITCH_ACTIVATIONS = "kill_switch_activations"
SENTINEL_FINDINGS = "sentinel_findings"
ADAPTIVE_THREAT_SCORES = "adaptive_threat_scores"
DEESCALATION_TIMERS = "deescalation_timers"


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
        ]
    )

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
        ]
    )

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

    # Data Classification Rules (Sprint 31 — APEP-246)
    data_classification_rules = db[DATA_CLASSIFICATION_RULES]
    await data_classification_rules.create_indexes(
        [
            IndexModel([("rule_id", ASCENDING)], unique=True),
            IndexModel([("tool_pattern", ASCENDING)]),
            IndexModel([("classification", ASCENDING)]),
            IndexModel([("enabled", ASCENDING)]),
        ]
    )

    # Sprint 36 — APEP-285: Hash-chained context
    hash_chained_context = db[HASH_CHAINED_CONTEXT]
    await hash_chained_context.create_indexes(
        [
            IndexModel([("entry_id", ASCENDING)], unique=True),
            IndexModel(
                [("session_id", ASCENDING), ("sequence_number", ASCENDING)],
                unique=True,
            ),
            IndexModel([("tenant_id", ASCENDING)]),
            IndexModel(
                [("created_at", ASCENDING)],
                expireAfterSeconds=86400 * 30,
            ),
        ]
    )

    # Sprint 36 — APEP-286: Trust degradation records
    trust_degradation_records = db[TRUST_DEGRADATION_RECORDS]
    await trust_degradation_records.create_indexes(
        [
            IndexModel([("session_id", ASCENDING)], unique=True),
            IndexModel([("tenant_id", ASCENDING)]),
            IndexModel([("current_ceiling", ASCENDING)]),
        ]
    )

    # Sprint 36 — APEP-287: Defer decisions
    defer_decisions = db[DEFER_DECISIONS]
    await defer_decisions.create_indexes(
        [
            IndexModel([("defer_id", ASCENDING)], unique=True),
            IndexModel([("session_id", ASCENDING)]),
            IndexModel([("resolved", ASCENDING)]),
            IndexModel([("tenant_id", ASCENDING)]),
            IndexModel(
                [("created_at", ASCENDING)],
                expireAfterSeconds=86400 * 7,
            ),
        ]
    )

    # Sprint 36 — APEP-288: Step-up challenges
    step_up_challenges = db[STEP_UP_CHALLENGES]
    await step_up_challenges.create_indexes(
        [
            IndexModel([("challenge_id", ASCENDING)], unique=True),
            IndexModel([("session_id", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("tenant_id", ASCENDING)]),
            IndexModel(
                [("created_at", ASCENDING)],
                expireAfterSeconds=86400,
            ),
        ]
    )

    # Sprint 36 — APEP-289: Policy conflicts
    policy_conflicts = db[POLICY_CONFLICTS]
    await policy_conflicts.create_indexes(
        [
            IndexModel([("conflict_id", ASCENDING)], unique=True),
            IndexModel([("tenant_id", ASCENDING)]),
            IndexModel([("resolved", ASCENDING)]),
            IndexModel([("severity", ASCENDING)]),
        ]
    )

    # Sprint 36 — APEP-290: Tenant isolation configs
    tenant_isolation_configs = db[TENANT_ISOLATION_CONFIGS]
    await tenant_isolation_configs.create_indexes(
        [
            IndexModel([("tenant_id", ASCENDING)], unique=True),
            IndexModel([("enabled", ASCENDING)]),
        ]
    )

    # Sprint 36 — APEP-290: Tenant isolation violations
    tenant_isolation_violations = db[TENANT_ISOLATION_VIOLATIONS]
    await tenant_isolation_violations.create_indexes(
        [
            IndexModel([("violation_id", ASCENDING)], unique=True),
            IndexModel([("source_tenant_id", ASCENDING)]),
            IndexModel([("target_tenant_id", ASCENDING)]),
            IndexModel(
                [("detected_at", ASCENDING)],
                expireAfterSeconds=86400 * 90,
            ),
        ]
    )

    # Sprint 37 — APEP-292: Mission Plans
    mission_plans = db[MISSION_PLANS]
    await mission_plans.create_indexes(
        [
            IndexModel([("plan_id", ASCENDING)], unique=True),
            IndexModel([("issuer", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("issued_at", DESCENDING)]),
            IndexModel(
                [("issued_at", ASCENDING)],
                expireAfterSeconds=86400 * 90,  # 90-day TTL for plan documents
            ),
        ]
    )

    # Sprint 37 — APEP-297: Plan-Session Bindings
    plan_session_bindings = db[PLAN_SESSION_BINDINGS]
    await plan_session_bindings.create_indexes(
        [
            IndexModel([("binding_id", ASCENDING)], unique=True),
            IndexModel([("plan_id", ASCENDING)]),
            IndexModel(
                [("session_id", ASCENDING), ("active", ASCENDING)],
            ),
            IndexModel(
                [("bound_at", ASCENDING)],
                expireAfterSeconds=86400 * 30,  # 30-day TTL for bindings
            ),
        ]
    )

    # Sprint 38 — APEP-300..307: Scope Patterns
    scope_patterns = db[SCOPE_PATTERNS]
    await scope_patterns.create_indexes(
        [
            IndexModel([("pattern", ASCENDING)], unique=True),
            IndexModel([("verb", ASCENDING)]),
            IndexModel([("namespace", ASCENDING)]),
            IndexModel(
                [("created_at", ASCENDING)],
                expireAfterSeconds=86400 * 90,  # 90-day TTL
            ),
        ]
    )

    # Sprint 40 — APEP-321: Plan budget alerts
    plan_budget_alerts = db[PLAN_BUDGET_ALERTS]
    await plan_budget_alerts.create_indexes(
        [
            IndexModel([("alert_id", ASCENDING)], unique=True),
            IndexModel([("plan_id", ASCENDING)]),
            IndexModel([("alert_level", ASCENDING)]),
            IndexModel([("dimension", ASCENDING)]),
            IndexModel(
                [("timestamp", ASCENDING)],
                expireAfterSeconds=86400 * 30,  # 30-day TTL
            ),
        ]
    )

    # Sprint 39 — APEP-308/310: Receipt chain indexes on audit_decisions
    # plan_id index for plan-scoped receipt retrieval
    await audit_decisions.create_indexes(
        [
            IndexModel([("plan_id", ASCENDING)]),
            IndexModel([("parent_receipt_id", ASCENDING)]),
        ]
    )

    # Sprint 45 — APEP-356..363: DLP Pre-Scan Hook
    dlp_patterns = db[DLP_PATTERNS]
    await dlp_patterns.create_indexes(
        [
            IndexModel([("pattern_id", ASCENDING)], unique=True),
            IndexModel([("enabled", ASCENDING)]),
            IndexModel([("pattern_type", ASCENDING)]),
        ]
    )

    dlp_scan_results = db[DLP_SCAN_RESULTS]
    await dlp_scan_results.create_indexes(
        [
            IndexModel([("session_id", ASCENDING)]),
            IndexModel([("agent_id", ASCENDING)]),
            IndexModel([("created_at", ASCENDING)], expireAfterSeconds=86400 * 7),
        ]
    )

    # Sprint 48 — APEP-380..387: MCP Proxy Enhancement
    mcp_dlp_scans = db[MCP_DLP_SCAN_RESULTS]
    await mcp_dlp_scans.create_indexes(
        [
            IndexModel([("session_id", ASCENDING)]),
            IndexModel([("agent_id", ASCENDING)]),
            IndexModel([("direction", ASCENDING)]),
            IndexModel([("scanned_at", ASCENDING)], expireAfterSeconds=86400 * 30),
        ]
    )

    mcp_poisoning = db[MCP_TOOL_POISONING_RESULTS]
    await mcp_poisoning.create_indexes(
        [
            IndexModel([("session_id", ASCENDING)]),
            IndexModel([("agent_id", ASCENDING)]),
            IndexModel([("scanned_at", ASCENDING)], expireAfterSeconds=86400 * 30),
        ]
    )

    mcp_rug_pulls = db[MCP_RUG_PULL_DETECTIONS]
    await mcp_rug_pulls.create_indexes(
        [
            IndexModel([("session_id", ASCENDING)]),
            IndexModel([("agent_id", ASCENDING)]),
            IndexModel([("detected_at", ASCENDING)], expireAfterSeconds=86400 * 30),
        ]
    )

    mcp_sec_events = db[MCP_SECURITY_EVENTS]
    await mcp_sec_events.create_indexes(
        [
            IndexModel([("session_id", ASCENDING)]),
            IndexModel([("event_type", ASCENDING)]),
            IndexModel([("agent_id", ASCENDING)]),
            IndexModel([("timestamp", ASCENDING)], expireAfterSeconds=86400 * 90),
        ]
    )

    # Sprint 50 — APEP-396: Kill switch activations
    kill_switch_activations = db[KILL_SWITCH_ACTIVATIONS]
    await kill_switch_activations.create_indexes(
        [
            IndexModel([("activation_id", ASCENDING)], unique=True),
            IndexModel([("source", ASCENDING)]),
            IndexModel([("activated_at", DESCENDING)]),
            IndexModel(
                [("activated_at", ASCENDING)],
                expireAfterSeconds=86400 * 90,  # 90-day TTL
            ),
        ]
    )

    # Sprint 50 — APEP-399: Sentinel findings
    sentinel_findings = db[SENTINEL_FINDINGS]
    await sentinel_findings.create_indexes(
        [
            IndexModel([("finding_id", ASCENDING)], unique=True),
            IndexModel([("event_type", ASCENDING)]),
            IndexModel([("severity", ASCENDING)]),
            IndexModel([("file_path", ASCENDING)]),
            IndexModel([("timestamp", DESCENDING)]),
            IndexModel(
                [("timestamp", ASCENDING)],
                expireAfterSeconds=86400 * 30,  # 30-day TTL
            ),
        ]
    )

    # Sprint 50 — APEP-401: Adaptive threat scores
    adaptive_threat_scores = db[ADAPTIVE_THREAT_SCORES]
    await adaptive_threat_scores.create_indexes(
        [
            IndexModel([("session_id", ASCENDING)], unique=True),
            IndexModel([("score", ASCENDING)]),
            IndexModel([("computed_at", DESCENDING)]),
            IndexModel(
                [("computed_at", ASCENDING)],
                expireAfterSeconds=86400 * 7,  # 7-day TTL
            ),
        ]
    )

    # Sprint 50 — APEP-402: De-escalation timers
    deescalation_timers = db[DEESCALATION_TIMERS]
    await deescalation_timers.create_indexes(
        [
            IndexModel([("timer_id", ASCENDING)], unique=True),
            IndexModel([("session_id", ASCENDING)]),
            IndexModel([("state", ASCENDING)]),
            IndexModel(
                [("created_at", ASCENDING)],
                expireAfterSeconds=86400 * 7,  # 7-day TTL
            ),
        ]
    )
