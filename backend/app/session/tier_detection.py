"""Deployment tier detection — session-init fingerprinting.

Determines the deployment tier for the current agent session using a
three-level resolution strategy:

  1. Explicit operator configuration (``AGENTPEP_DEPLOYMENT_TIER`` env var
     or ``deployment_tier`` in settings) — highest trust, not overridable
     at runtime.
  2. Runtime environment fingerprinting — known SDK markers and environment
     variables that identify managed or enterprise runtimes.
  3. Default: ``HOMEGROWN`` — most restrictive; applied when the tier is
     ambiguous to satisfy the principle of least privilege.

Valid tiers (matching the AuthorizationRequestBuilder constants):
  ENTERPRISE  — Managed endpoint agents in controlled enterprise environments
                (e.g. corporate Azure/AWS deployments, on-prem air-gapped)
  MANAGED     — SaaS-embedded or platform-managed agents
                (e.g. Salesforce Agentforce, ServiceNow, Workday AI)
  HOMEGROWN   — Custom / homegrown agents; default for unknown environments

Sprint S-E08 (E08-T03)
"""

from __future__ import annotations

import os
from enum import Enum
from typing import Any

from app.core.structured_logging import get_logger

logger = get_logger(__name__)


class DeploymentTier(str, Enum):
    """Deployment tier classification."""

    ENTERPRISE = "ENTERPRISE"
    MANAGED = "MANAGED"
    HOMEGROWN = "HOMEGROWN"


# ---------------------------------------------------------------------------
# Environment fingerprint rules
# ---------------------------------------------------------------------------
# Each rule is a set of environment variable names whose *presence* (with any
# non-empty value) indicates a specific deployment tier.  Rules are evaluated
# in priority order: ENTERPRISE first, then MANAGED.  Any match returns the
# associated tier immediately.

_ENTERPRISE_ENV_MARKERS: frozenset[str] = frozenset(
    {
        # Azure AD / Entra ID managed identity (common in enterprise deployments)
        "AZURE_CLIENT_ID",
        "AZURE_MANAGED_IDENTITY_CLIENT_ID",
        # AWS Managed Identity / IAM Role (ECS, EKS, Lambda with instance role)
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        # GCP Workload Identity (GKE with Workload Identity enabled)
        "GKE_WORKLOAD_IDENTITY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        # Corporate / on-prem agent runtime marker (AgentPEP operator-set)
        "AGENTPEP_ENTERPRISE_RUNTIME",
    }
)

_MANAGED_ENV_MARKERS: frozenset[str] = frozenset(
    {
        # Salesforce Agentforce
        "SF_AGENT_CONTEXT",
        "SALESFORCE_INSTANCE_URL",
        # ServiceNow
        "SN_AGENT_ID",
        "SERVICENOW_INSTANCE",
        # Workday
        "WORKDAY_AGENT_TENANT",
        # Microsoft Copilot / Power Platform
        "POWER_PLATFORM_AGENT",
        # Generic SaaS marker (AgentPEP operator-set)
        "AGENTPEP_SAAS_RUNTIME",
        "AGENTPEP_MANAGED_RUNTIME",
    }
)

# SDK presence fingerprints — module availability implies a known framework.
# These are checked as a secondary signal when env markers are absent.
_ENTERPRISE_SDK_MODULES: frozenset[str] = frozenset(
    {
        "azure.identity",      # Azure Managed Identity SDK
        "boto3",               # AWS SDK (strong signal in enterprise AWS environments)
    }
)

_MANAGED_SDK_MODULES: frozenset[str] = frozenset(
    {
        "simple_salesforce",   # Salesforce SDK
        "pysnow",              # ServiceNow SDK
    }
)


def _env_marker_present(markers: frozenset[str]) -> bool:
    """Return True if any marker in *markers* is set to a non-empty value."""
    return any(os.environ.get(m, "") for m in markers)


def _sdk_present(modules: frozenset[str]) -> bool:
    """Return True if any module in *modules* is importable."""
    import importlib.util

    for m in modules:
        try:
            if importlib.util.find_spec(m) is not None:
                return True
        except (ModuleNotFoundError, ValueError):
            # find_spec raises ModuleNotFoundError for submodules of missing
            # parent packages (e.g. "azure.identity" when "azure" is absent).
            continue
    return False


# ---------------------------------------------------------------------------
# Tier detector
# ---------------------------------------------------------------------------


class TierDetector:
    """Resolves the deployment tier for a session at initialisation time.

    Resolution priority:
    1. Explicit operator configuration (settings or AGENTPEP_DEPLOYMENT_TIER env var)
    2. Environment variable markers
    3. SDK availability fingerprint
    4. Default → HOMEGROWN
    """

    def detect(self, explicit_tier: str = "") -> DeploymentTier:
        """Detect and return the deployment tier.

        Args:
            explicit_tier:  Tier value supplied by the operator (e.g. from the
                            session initialisation request or settings).
                            When non-empty and valid it is used directly without
                            any fingerprinting.

        Returns:
            The resolved DeploymentTier.
        """
        # 1. Explicit operator config (highest trust)
        if explicit_tier:
            normalised = explicit_tier.upper().strip()
            try:
                tier = DeploymentTier(normalised)
                logger.debug(
                    "tier_resolved_explicit",
                    tier=tier.value,
                    explicit_tier=explicit_tier,
                )
                return tier
            except ValueError:
                logger.warning(
                    "tier_explicit_invalid",
                    explicit_tier=explicit_tier,
                    fallback="fingerprint",
                )

        # 1b. Check AGENTPEP_DEPLOYMENT_TIER env var (operator-set)
        env_override = os.environ.get("AGENTPEP_DEPLOYMENT_TIER", "")
        if env_override:
            normalised = env_override.upper().strip()
            try:
                tier = DeploymentTier(normalised)
                logger.debug(
                    "tier_resolved_env_override",
                    tier=tier.value,
                    env_var="AGENTPEP_DEPLOYMENT_TIER",
                )
                return tier
            except ValueError:
                logger.warning(
                    "tier_env_override_invalid",
                    env_value=env_override,
                    fallback="fingerprint",
                )

        # 2. Environment variable markers
        if _env_marker_present(_ENTERPRISE_ENV_MARKERS):
            logger.debug("tier_resolved_env_fingerprint", tier=DeploymentTier.ENTERPRISE.value)
            return DeploymentTier.ENTERPRISE

        if _env_marker_present(_MANAGED_ENV_MARKERS):
            logger.debug("tier_resolved_env_fingerprint", tier=DeploymentTier.MANAGED.value)
            return DeploymentTier.MANAGED

        # 3. SDK availability fingerprint (secondary signal)
        if _sdk_present(_ENTERPRISE_SDK_MODULES):
            logger.debug("tier_resolved_sdk_fingerprint", tier=DeploymentTier.ENTERPRISE.value)
            return DeploymentTier.ENTERPRISE

        if _sdk_present(_MANAGED_SDK_MODULES):
            logger.debug("tier_resolved_sdk_fingerprint", tier=DeploymentTier.MANAGED.value)
            return DeploymentTier.MANAGED

        # 4. Ambiguous — default to HOMEGROWN (most restrictive)
        logger.debug("tier_resolved_default", tier=DeploymentTier.HOMEGROWN.value)
        return DeploymentTier.HOMEGROWN

    def detect_from_settings(self, extra_context: dict[str, Any] | None = None) -> DeploymentTier:
        """Detect tier using the application settings deployment_tier field.

        Args:
            extra_context:  Optional dict carrying a ``"deployment_tier"`` key
                            from the session initialisation payload.
        """
        from app.core.config import settings

        explicit = ""

        # Session-level override takes precedence over global config
        if extra_context and extra_context.get("deployment_tier"):
            explicit = str(extra_context["deployment_tier"])
        else:
            explicit = getattr(settings, "deployment_tier", "")

        return self.detect(explicit_tier=explicit)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

tier_detector = TierDetector()
