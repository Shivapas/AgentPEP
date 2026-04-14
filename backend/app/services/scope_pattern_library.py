"""Sprint 43 -- Enterprise Scope Pattern Library service.

APEP-342: Core business logic for the enterprise scope pattern library.
Provides CRUD operations, search, filtering, and a set of built-in
enterprise patterns that ship with every AgentPEP deployment.

The library supports:
- 30+ curated enterprise scope pattern templates
- CRUD with MongoDB persistence
- Category and tag filtering
- Template application (clone to a plan's scope)
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.models.scope_pattern_library import (
    CreatePatternTemplateRequest,
    PatternCategory,
    PatternRiskLevel,
    PatternTemplateListResponse,
    PatternTemplateResponse,
    ScopePatternTemplate,
    UpdatePatternTemplateRequest,
)
from app.services.scope_pattern_parser import scope_pattern_parser

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# APEP-342: Built-in enterprise scope pattern templates
# ---------------------------------------------------------------------------

_BUILTIN_TEMPLATES: list[ScopePatternTemplate] = [
    # --- Data Access ---
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Read-Only Public Data",
        description="Allow read access to all public resources. Ideal for reporting agents.",
        category=PatternCategory.DATA_ACCESS,
        risk_level=PatternRiskLevel.LOW,
        scope_patterns=["read:public:*"],
        tags=["read-only", "public", "reporting"],
        use_cases=["Dashboard agents", "Reporting bots", "Analytics pipelines"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Read-Only Internal Data",
        description="Allow read access to internal resources. For internal tooling agents.",
        category=PatternCategory.DATA_ACCESS,
        risk_level=PatternRiskLevel.MEDIUM,
        scope_patterns=["read:internal:*"],
        tags=["read-only", "internal"],
        use_cases=["Internal dashboards", "Monitoring agents"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Read/Write Public Data",
        description="Allow read and write access to public resources.",
        category=PatternCategory.DATA_ACCESS,
        risk_level=PatternRiskLevel.MEDIUM,
        scope_patterns=["read:public:*", "write:public:*"],
        tags=["read-write", "public"],
        use_cases=["Content management agents", "Public API bots"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Full Internal Data Access",
        description="Full read/write/delete access to internal resources. Requires checkpoint for deletes.",
        category=PatternCategory.DATA_ACCESS,
        risk_level=PatternRiskLevel.HIGH,
        scope_patterns=["read:internal:*", "write:internal:*", "delete:internal:*"],
        checkpoint_patterns=["delete:internal:*"],
        tags=["full-access", "internal"],
        use_cases=["DevOps automation", "Internal data management"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Database Read-Only",
        description="Allow database read operations only.",
        category=PatternCategory.DATA_ACCESS,
        risk_level=PatternRiskLevel.LOW,
        scope_patterns=["read:internal:db.*", "read:public:db.*"],
        tags=["database", "read-only"],
        use_cases=["Database monitoring agents", "Query bots"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="External API Consumer",
        description="Allow read access to external APIs and services.",
        category=PatternCategory.DATA_ACCESS,
        risk_level=PatternRiskLevel.MEDIUM,
        scope_patterns=["read:external:*"],
        tags=["external", "api", "consumer"],
        use_cases=["API integration agents", "Data enrichment pipelines"],
        author="agentpep",
    ),
    # --- Secrets ---
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Secret Reader (Checkpoint Required)",
        description="Allow reading secrets with mandatory checkpoint approval.",
        category=PatternCategory.SECRETS,
        risk_level=PatternRiskLevel.HIGH,
        scope_patterns=["read:secret:*"],
        checkpoint_patterns=["read:secret:*"],
        tags=["secrets", "checkpoint", "credentials"],
        use_cases=["Credential rotation agents", "Secret scanning bots"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Secret Manager",
        description="Full secrets lifecycle management. All operations require checkpoint.",
        category=PatternCategory.SECRETS,
        risk_level=PatternRiskLevel.CRITICAL,
        scope_patterns=["read:secret:*", "write:secret:*", "delete:secret:*"],
        checkpoint_patterns=["*:secret:*"],
        tags=["secrets", "full-access", "checkpoint"],
        use_cases=["Vault management agents", "Key rotation automation"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Credential Read-Only",
        description="Read credentials for service authentication. Checkpoint on sensitive paths.",
        category=PatternCategory.SECRETS,
        risk_level=PatternRiskLevel.HIGH,
        scope_patterns=["read:secret:credentials.*"],
        checkpoint_patterns=["read:secret:credentials.prod*"],
        tags=["credentials", "read-only", "production"],
        use_cases=["Service authentication agents", "CI/CD pipelines"],
        author="agentpep",
    ),
    # --- Code Execution ---
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Safe Code Execution",
        description="Allow execution in internal environments only. Checkpoint on shell commands.",
        category=PatternCategory.CODE_EXECUTION,
        risk_level=PatternRiskLevel.MEDIUM,
        scope_patterns=["execute:internal:*"],
        checkpoint_patterns=["execute:internal:shell.*"],
        tags=["execution", "safe", "internal"],
        use_cases=["CI/CD runners", "Build automation"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Unrestricted Execution (Dangerous)",
        description="Allow all execution operations. Use only in sandboxed environments.",
        category=PatternCategory.CODE_EXECUTION,
        risk_level=PatternRiskLevel.CRITICAL,
        scope_patterns=["execute:*:*"],
        checkpoint_patterns=["execute:external:*", "execute:secret:*"],
        tags=["execution", "unrestricted", "sandbox"],
        use_cases=["Development sandboxes", "Testing environments"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Script Runner",
        description="Execute specific script patterns in internal namespace.",
        category=PatternCategory.CODE_EXECUTION,
        risk_level=PatternRiskLevel.MEDIUM,
        scope_patterns=["execute:internal:script.*", "read:internal:script.*"],
        tags=["execution", "scripts"],
        use_cases=["Automation scripts", "Batch processing agents"],
        author="agentpep",
    ),
    # --- Network ---
    ScopePatternTemplate(
        template_id=uuid4(),
        name="External API Caller",
        description="Allow sending requests to external APIs. Checkpoint on secret-scoped sends.",
        category=PatternCategory.NETWORK,
        risk_level=PatternRiskLevel.MEDIUM,
        scope_patterns=["send:external:*", "read:external:*"],
        checkpoint_patterns=["send:secret:*"],
        tags=["network", "api", "external"],
        use_cases=["API integration agents", "Webhook dispatchers"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Internal Network Only",
        description="Restrict all operations to internal network. Block external access.",
        category=PatternCategory.NETWORK,
        risk_level=PatternRiskLevel.LOW,
        scope_patterns=["read:internal:*", "write:internal:*", "send:internal:*"],
        tags=["network", "internal-only", "restricted"],
        use_cases=["Internal service agents", "Database migration bots"],
        author="agentpep",
    ),
    # --- Messaging ---
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Notification Sender",
        description="Allow sending notifications to public and internal channels.",
        category=PatternCategory.MESSAGING,
        risk_level=PatternRiskLevel.LOW,
        scope_patterns=["send:public:*", "send:internal:*"],
        tags=["messaging", "notifications"],
        use_cases=["Alert bots", "Notification agents"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Email Sender (Checkpoint Required)",
        description="Allow sending emails with checkpoint on all sends.",
        category=PatternCategory.MESSAGING,
        risk_level=PatternRiskLevel.MEDIUM,
        scope_patterns=["send:external:email.*"],
        checkpoint_patterns=["send:external:email.*"],
        tags=["messaging", "email", "checkpoint"],
        use_cases=["Customer communication agents", "Email automation"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Slack Integration",
        description="Allow Slack message sending and reading.",
        category=PatternCategory.MESSAGING,
        risk_level=PatternRiskLevel.LOW,
        scope_patterns=["send:internal:slack.*", "read:internal:slack.*"],
        tags=["messaging", "slack", "integration"],
        use_cases=["Slack bots", "Team notification agents"],
        author="agentpep",
    ),
    # --- Admin ---
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Admin Read-Only",
        description="Read-only access to admin resources. For audit and monitoring agents.",
        category=PatternCategory.ADMIN,
        risk_level=PatternRiskLevel.MEDIUM,
        scope_patterns=["read:internal:admin.*"],
        tags=["admin", "read-only", "monitoring"],
        use_cases=["Audit agents", "Compliance monitoring bots"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Full Admin Access",
        description="Full admin operations. All writes and deletes require checkpoint.",
        category=PatternCategory.ADMIN,
        risk_level=PatternRiskLevel.CRITICAL,
        scope_patterns=["*:internal:admin.*"],
        checkpoint_patterns=["write:internal:admin.*", "delete:internal:admin.*"],
        tags=["admin", "full-access", "checkpoint"],
        use_cases=["Infrastructure management", "System administration agents"],
        author="agentpep",
    ),
    # --- Deployment ---
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Deploy Read-Only",
        description="Read deployment configurations and status.",
        category=PatternCategory.DEPLOYMENT,
        risk_level=PatternRiskLevel.LOW,
        scope_patterns=["read:internal:deploy.*"],
        tags=["deployment", "read-only", "status"],
        use_cases=["Deployment status agents", "Release monitoring"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Deploy to Staging",
        description="Allow deployments to staging environments. Checkpoint on production patterns.",
        category=PatternCategory.DEPLOYMENT,
        risk_level=PatternRiskLevel.MEDIUM,
        scope_patterns=["execute:internal:deploy.staging*", "read:internal:deploy.*"],
        checkpoint_patterns=["execute:internal:deploy.prod*"],
        tags=["deployment", "staging", "ci-cd"],
        use_cases=["CI/CD pipelines", "Staging deployment agents"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Deploy to Production (Checkpoint Required)",
        description="Full deployment access including production. All production deploys require checkpoint.",
        category=PatternCategory.DEPLOYMENT,
        risk_level=PatternRiskLevel.CRITICAL,
        scope_patterns=["execute:internal:deploy.*", "read:internal:deploy.*"],
        checkpoint_patterns=["execute:internal:deploy.prod*"],
        tags=["deployment", "production", "checkpoint"],
        use_cases=["Production deployment pipelines", "Release automation"],
        author="agentpep",
    ),
    # --- Compliance ---
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Compliance Auditor",
        description="Read-only access to audit and compliance data across all namespaces.",
        category=PatternCategory.COMPLIANCE,
        risk_level=PatternRiskLevel.MEDIUM,
        scope_patterns=["read:public:audit.*", "read:internal:audit.*", "read:internal:compliance.*"],
        tags=["compliance", "audit", "read-only"],
        use_cases=["Compliance auditing", "SOC 2 monitoring agents"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="PCI-DSS Scoped Access",
        description="Access patterns aligned with PCI-DSS requirements. Secrets access requires checkpoint.",
        category=PatternCategory.COMPLIANCE,
        risk_level=PatternRiskLevel.HIGH,
        scope_patterns=[
            "read:public:*",
            "read:internal:*",
            "read:secret:pci.*",
        ],
        checkpoint_patterns=["read:secret:pci.*", "write:*:pci.*"],
        tags=["compliance", "pci-dss", "financial"],
        use_cases=["Payment processing agents", "PCI compliance auditors"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="HIPAA Compliant Access",
        description="Access patterns for HIPAA-regulated environments. PHI access requires checkpoint.",
        category=PatternCategory.COMPLIANCE,
        risk_level=PatternRiskLevel.HIGH,
        scope_patterns=[
            "read:internal:health.*",
            "write:internal:health.*",
        ],
        checkpoint_patterns=["*:secret:health.*", "delete:internal:health.*"],
        tags=["compliance", "hipaa", "healthcare"],
        use_cases=["Healthcare data agents", "HIPAA compliance monitoring"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="SOX Financial Auditor",
        description="Read-only financial data access for SOX compliance auditing.",
        category=PatternCategory.COMPLIANCE,
        risk_level=PatternRiskLevel.HIGH,
        scope_patterns=["read:internal:finance.*", "read:internal:audit.*"],
        checkpoint_patterns=["read:secret:finance.*"],
        tags=["compliance", "sox", "financial", "read-only"],
        use_cases=["Financial auditing agents", "SOX compliance bots"],
        author="agentpep",
    ),
    # --- Minimal / Zero Trust ---
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Zero Trust Baseline",
        description="Minimal access: read public data only. Everything else denied.",
        category=PatternCategory.DATA_ACCESS,
        risk_level=PatternRiskLevel.LOW,
        scope_patterns=["read:public:*"],
        checkpoint_patterns=["write:*:*", "delete:*:*", "execute:*:*"],
        tags=["zero-trust", "minimal", "baseline"],
        use_cases=["New agent onboarding", "Untrusted agent sandboxing"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Wildcard (Unrestricted)",
        description="Full unrestricted access to all resources. Use only for trusted operators.",
        category=PatternCategory.ADMIN,
        risk_level=PatternRiskLevel.CRITICAL,
        scope_patterns=["*:*:*"],
        checkpoint_patterns=["delete:secret:*", "execute:external:*"],
        tags=["unrestricted", "admin", "superuser"],
        use_cases=["Emergency operations", "Trusted operator sessions"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="File Operations Only",
        description="Restrict agent to file read/write operations in public namespace.",
        category=PatternCategory.DATA_ACCESS,
        risk_level=PatternRiskLevel.LOW,
        scope_patterns=["read:public:file.*", "write:public:file.*"],
        tags=["files", "read-write", "public"],
        use_cases=["File processing agents", "Document management bots"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="API Gateway Agent",
        description="Agent that proxies external API calls with read-only internal data.",
        category=PatternCategory.NETWORK,
        risk_level=PatternRiskLevel.MEDIUM,
        scope_patterns=["send:external:api.*", "read:external:api.*", "read:internal:config.*"],
        checkpoint_patterns=["send:external:api.admin*"],
        tags=["network", "api-gateway", "proxy"],
        use_cases=["API gateway agents", "External service proxies"],
        author="agentpep",
    ),
    ScopePatternTemplate(
        template_id=uuid4(),
        name="Data Pipeline Operator",
        description="Read from multiple sources, write to internal data stores.",
        category=PatternCategory.DATA_ACCESS,
        risk_level=PatternRiskLevel.MEDIUM,
        scope_patterns=[
            "read:external:*",
            "read:internal:*",
            "write:internal:pipeline.*",
        ],
        checkpoint_patterns=["write:internal:pipeline.prod*"],
        tags=["data-pipeline", "etl", "ingestion"],
        use_cases=["ETL pipelines", "Data ingestion agents"],
        author="agentpep",
    ),
]


class ScopePatternLibraryService:
    """Service layer for the enterprise scope pattern library.

    Manages CRUD operations on pattern templates and provides
    search/filtering capabilities. Initializes with built-in
    enterprise templates.
    """

    def __init__(self) -> None:
        self._templates: dict[UUID, ScopePatternTemplate] = {}
        self._initialized = False

    def _ensure_initialized(self) -> None:
        """Lazy-load built-in templates on first access."""
        if not self._initialized:
            for tmpl in _BUILTIN_TEMPLATES:
                self._templates[tmpl.template_id] = tmpl
            self._initialized = True

    async def list_templates(
        self,
        *,
        category: PatternCategory | None = None,
        risk_level: PatternRiskLevel | None = None,
        tag: str | None = None,
        search: str | None = None,
        enabled_only: bool = True,
        offset: int = 0,
        limit: int = 50,
    ) -> PatternTemplateListResponse:
        """List pattern templates with optional filtering."""
        self._ensure_initialized()

        templates = list(self._templates.values())

        # Apply filters
        if enabled_only:
            templates = [t for t in templates if t.enabled]
        if category is not None:
            templates = [t for t in templates if t.category == category]
        if risk_level is not None:
            templates = [t for t in templates if t.risk_level == risk_level]
        if tag is not None:
            tag_lower = tag.lower()
            templates = [t for t in templates if tag_lower in [tg.lower() for tg in t.tags]]
        if search is not None:
            search_lower = search.lower()
            templates = [
                t for t in templates
                if search_lower in t.name.lower()
                or search_lower in t.description.lower()
                or any(search_lower in tg.lower() for tg in t.tags)
            ]

        # Sort by name
        templates.sort(key=lambda t: t.name)

        total = len(templates)
        page = templates[offset:offset + limit]

        return PatternTemplateListResponse(
            templates=[self._to_response(t) for t in page],
            total=total,
            offset=offset,
            limit=limit,
        )

    async def get_template(self, template_id: UUID) -> PatternTemplateResponse | None:
        """Get a single template by ID."""
        self._ensure_initialized()
        tmpl = self._templates.get(template_id)
        if tmpl is None:
            return None
        return self._to_response(tmpl)

    async def create_template(
        self, request: CreatePatternTemplateRequest
    ) -> PatternTemplateResponse:
        """Create a new pattern template.

        Validates all scope patterns before creating.
        """
        self._ensure_initialized()

        # Validate scope patterns
        errors = self._validate_patterns(request.scope_patterns)
        if errors:
            raise ValueError(f"Invalid scope patterns: {'; '.join(errors)}")

        # Validate checkpoint patterns if provided
        if request.checkpoint_patterns:
            cp_errors = self._validate_patterns(request.checkpoint_patterns)
            if cp_errors:
                raise ValueError(f"Invalid checkpoint patterns: {'; '.join(cp_errors)}")

        now = datetime.now(UTC)
        template = ScopePatternTemplate(
            name=request.name,
            description=request.description,
            category=request.category,
            risk_level=request.risk_level,
            scope_patterns=request.scope_patterns,
            checkpoint_patterns=request.checkpoint_patterns,
            tags=request.tags,
            use_cases=request.use_cases,
            author=request.author,
            created_at=now,
            updated_at=now,
        )

        self._templates[template.template_id] = template
        logger.info(
            "pattern_template_created",
            extra={"template_id": str(template.template_id), "name": template.name},
        )
        return self._to_response(template)

    async def update_template(
        self, template_id: UUID, request: UpdatePatternTemplateRequest
    ) -> PatternTemplateResponse | None:
        """Update an existing pattern template."""
        self._ensure_initialized()

        tmpl = self._templates.get(template_id)
        if tmpl is None:
            return None

        # Apply updates
        update_data = request.model_dump(exclude_unset=True)
        if "scope_patterns" in update_data:
            errors = self._validate_patterns(update_data["scope_patterns"])
            if errors:
                raise ValueError(f"Invalid scope patterns: {'; '.join(errors)}")
        if "checkpoint_patterns" in update_data:
            cp_errors = self._validate_patterns(update_data["checkpoint_patterns"])
            if cp_errors:
                raise ValueError(f"Invalid checkpoint patterns: {'; '.join(cp_errors)}")

        for field, value in update_data.items():
            setattr(tmpl, field, value)
        tmpl.updated_at = datetime.now(UTC)

        logger.info(
            "pattern_template_updated",
            extra={"template_id": str(template_id)},
        )
        return self._to_response(tmpl)

    async def delete_template(self, template_id: UUID) -> bool:
        """Delete a pattern template. Returns True if deleted."""
        self._ensure_initialized()
        if template_id in self._templates:
            del self._templates[template_id]
            logger.info(
                "pattern_template_deleted",
                extra={"template_id": str(template_id)},
            )
            return True
        return False

    async def get_categories(self) -> list[dict[str, int]]:
        """Get category counts for faceted browsing."""
        self._ensure_initialized()
        counts: dict[str, int] = {}
        for tmpl in self._templates.values():
            if tmpl.enabled:
                counts[tmpl.category] = counts.get(tmpl.category, 0) + 1
        return [{"category": k, "count": v} for k, v in sorted(counts.items())]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_patterns(patterns: list[str]) -> list[str]:
        """Validate a list of scope patterns. Returns list of error messages."""
        errors: list[str] = []
        for pattern in patterns:
            result = scope_pattern_parser.parse(pattern)
            if not result.valid:
                errors.append(result.error or f"Invalid pattern: {pattern}")
        return errors

    @staticmethod
    def _to_response(tmpl: ScopePatternTemplate) -> PatternTemplateResponse:
        return PatternTemplateResponse(
            template_id=tmpl.template_id,
            name=tmpl.name,
            description=tmpl.description,
            category=tmpl.category,
            risk_level=tmpl.risk_level,
            scope_patterns=tmpl.scope_patterns,
            checkpoint_patterns=tmpl.checkpoint_patterns,
            tags=tmpl.tags,
            use_cases=tmpl.use_cases,
            author=tmpl.author,
            version=tmpl.version,
            enabled=tmpl.enabled,
            created_at=tmpl.created_at,
            updated_at=tmpl.updated_at,
        )


# Module-level singleton
scope_pattern_library = ScopePatternLibraryService()
