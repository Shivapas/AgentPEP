"""MongoDB connection management and collection initialization."""

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING, IndexModel

from app.core.config import settings

_client: AsyncIOMotorClient | None = None  # type: ignore[type-arg]
_db: AsyncIOMotorDatabase | None = None  # type: ignore[type-arg]


def get_client() -> AsyncIOMotorClient:  # type: ignore[type-arg]
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(settings.mongodb_url)
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

    # Audit Decisions
    audit_decisions = db[AUDIT_DECISIONS]
    await audit_decisions.create_indexes(
        [
            IndexModel([("decision_id", ASCENDING)], unique=True),
            IndexModel([("session_id", ASCENDING)]),
            IndexModel([("agent_id", ASCENDING)]),
            IndexModel([("tool_name", ASCENDING)]),
            IndexModel([("decision", ASCENDING)]),
            IndexModel([("timestamp", DESCENDING)]),
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
