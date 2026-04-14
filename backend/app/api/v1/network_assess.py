"""Network Security Assessment & Rule Bundle API — Sprint 51.

APEP-404.d: Rule bundle format endpoints.
APEP-405.d: Rule bundle loader endpoints.
APEP-406.d: Security assessment engine endpoints.
APEP-407.d: GET /v1/network/assess endpoint.
APEP-408:   MITRE ATT&CK technique mapping endpoint.
"""

from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from app.models.rule_bundle import (
    AssessmentCategory,
    AssessmentPhase,
    BundleRuleType,
    BundleStatus,
    RuleBundle,
    RuleBundleListResponse,
    RuleBundleLoadRequest,
    RuleBundleLoadResponse,
    MitreTechniqueMap,
    SecurityAssessmentRequest,
    SecurityAssessmentResult,
)
from app.services.mitre_attack_mapper import mitre_attack_mapper
from app.services.rule_bundle_loader import rule_bundle_loader
from app.services.security_assessment import security_assessment_engine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["network_assess"])


# ---------------------------------------------------------------------------
# APEP-407.d: GET /v1/network/assess — Security Assessment endpoint
# ---------------------------------------------------------------------------


@router.get("/network/assess", response_model=SecurityAssessmentResult)
async def get_network_assessment(
    include_passed: bool = Query(default=True, description="Include passing checks"),
) -> SecurityAssessmentResult:
    """Run a full security assessment and return the scored result.

    This is the ``ToolTrust assess``-equivalent endpoint.  It runs all
    three assessment phases (config audit, attack simulation, deployment
    probe) and returns a graded report with MITRE ATT&CK tags.
    """
    request = SecurityAssessmentRequest(include_passed=include_passed)
    result = await security_assessment_engine.run_assessment(request)
    return result


@router.post("/network/assess", response_model=SecurityAssessmentResult)
async def run_security_assessment(
    request: SecurityAssessmentRequest,
) -> SecurityAssessmentResult:
    """Run a customized security assessment.

    Allows selecting specific phases and categories to assess.
    """
    result = await security_assessment_engine.run_assessment(request)
    return result


# ---------------------------------------------------------------------------
# APEP-404.d / APEP-405.d: Rule Bundle endpoints
# ---------------------------------------------------------------------------


@router.get("/network/bundles", response_model=RuleBundleListResponse)
async def list_rule_bundles(
    status: BundleStatus | None = Query(default=None, description="Filter by bundle status"),
) -> RuleBundleListResponse:
    """List all loaded rule bundles."""
    return rule_bundle_loader.list_bundles(status=status)


@router.post("/network/bundles", response_model=RuleBundleLoadResponse)
async def load_rule_bundle(
    request: RuleBundleLoadRequest,
) -> RuleBundleLoadResponse:
    """Load a rule bundle from YAML content or file path.

    The bundle is parsed, optionally Ed25519-verified, and registered
    in the bundle loader.  Use ``activate=true`` to make the bundle's
    rules effective immediately.
    """
    if request.yaml_content:
        return rule_bundle_loader.load_from_yaml(
            request.yaml_content,
            verify_signature=request.verify_signature,
            activate=request.activate,
        )
    elif request.file_path:
        try:
            return rule_bundle_loader.load_from_file(
                request.file_path,
                verify_signature=request.verify_signature,
                activate=request.activate,
            )
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"File not found: {request.file_path}")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    else:
        raise HTTPException(
            status_code=400,
            detail="Either 'yaml_content' or 'file_path' must be provided",
        )


@router.get("/network/bundles/{bundle_id}", response_model=RuleBundle)
async def get_rule_bundle(bundle_id: UUID) -> RuleBundle:
    """Get a specific rule bundle by ID."""
    bundle = rule_bundle_loader.get_bundle(bundle_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Bundle not found")
    return bundle


@router.post("/network/bundles/{bundle_id}/activate", response_model=RuleBundle)
async def activate_rule_bundle(bundle_id: UUID) -> RuleBundle:
    """Activate a rule bundle, making its rules effective."""
    bundle = rule_bundle_loader.activate_bundle(bundle_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Bundle not found")
    return bundle


@router.post("/network/bundles/{bundle_id}/deactivate", response_model=RuleBundle)
async def deactivate_rule_bundle(bundle_id: UUID) -> RuleBundle:
    """Deactivate a rule bundle, suspending its rules."""
    bundle = rule_bundle_loader.deactivate_bundle(bundle_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Bundle not found")
    return bundle


@router.delete("/network/bundles/{bundle_id}")
async def remove_rule_bundle(bundle_id: UUID) -> dict[str, str]:
    """Remove a rule bundle entirely."""
    removed = rule_bundle_loader.remove_bundle(bundle_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Bundle not found")
    return {"status": "removed", "bundle_id": str(bundle_id)}


@router.get("/network/bundles/stats", response_model=dict)
async def get_bundle_stats() -> dict:
    """Get summary statistics about loaded bundles."""
    return rule_bundle_loader.stats()


# ---------------------------------------------------------------------------
# APEP-408: MITRE ATT&CK Technique Mapping endpoint
# ---------------------------------------------------------------------------


@router.get("/network/mitre", response_model=MitreTechniqueMap)
async def get_mitre_map() -> MitreTechniqueMap:
    """Get the complete MITRE ATT&CK technique map.

    Returns all registered techniques, event-type mappings, and
    rule-specific mappings used to enrich TFN network events.
    """
    return mitre_attack_mapper.get_full_map()


@router.get("/network/mitre/stats")
async def get_mitre_stats() -> dict[str, int]:
    """Get summary statistics about the MITRE ATT&CK technique map."""
    return mitre_attack_mapper.stats()
