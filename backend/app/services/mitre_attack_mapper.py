"""MITRE ATT&CK Technique Mapping — Sprint 51 (APEP-408).

Maintains a mapping of AgentPEP/TFN event types and rule IDs to MITRE
ATT&CK technique IDs.  Used to enrich Kafka events and security
assessment findings with standardized technique references.

The map covers techniques relevant to AI agent security, LLM prompt
injection, data exfiltration via tool calls, and supply-chain attacks
on MCP tool servers.
"""

from __future__ import annotations

import logging

from app.models.network_scan import NetworkEventType
from app.models.rule_bundle import MitreTactic, MitreTechnique, MitreTechniqueMap

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Built-in technique definitions
# ---------------------------------------------------------------------------

_TECHNIQUES: dict[str, MitreTechnique] = {
    # Initial Access
    "T1190": MitreTechnique(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic=MitreTactic.INITIAL_ACCESS,
        description="Adversary exploits a vulnerability in an internet-facing application",
    ),
    "T1195.002": MitreTechnique(
        technique_id="T1195.002",
        technique_name="Compromise Software Supply Chain",
        tactic=MitreTactic.INITIAL_ACCESS,
        description="Adversary manipulates software dependencies or tools",
    ),
    # Execution
    "T1059": MitreTechnique(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic=MitreTactic.EXECUTION,
        description="Adversary abuses command and script interpreters to execute commands",
    ),
    "T1203": MitreTechnique(
        technique_id="T1203",
        technique_name="Exploitation for Client Execution",
        tactic=MitreTactic.EXECUTION,
        description="Adversary exploits software vulnerability to execute code on client system",
    ),
    # Defense Evasion
    "T1027": MitreTechnique(
        technique_id="T1027",
        technique_name="Obfuscated Files or Information",
        tactic=MitreTactic.DEFENSE_EVASION,
        description="Adversary attempts to make payloads difficult to discover or analyze",
    ),
    "T1036": MitreTechnique(
        technique_id="T1036",
        technique_name="Masquerading",
        tactic=MitreTactic.DEFENSE_EVASION,
        description="Adversary manipulates features to make malicious artifacts appear legitimate",
    ),
    # Credential Access
    "T1552": MitreTechnique(
        technique_id="T1552",
        technique_name="Unsecured Credentials",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        description="Adversary searches compromised systems for insecurely stored credentials",
    ),
    "T1552.001": MitreTechnique(
        technique_id="T1552.001",
        technique_name="Credentials In Files",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        description="Adversary searches local file systems for files containing credentials",
    ),
    # Discovery
    "T1046": MitreTechnique(
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic=MitreTactic.DISCOVERY,
        description="Adversary attempts to discover services running on remote hosts",
    ),
    "T1018": MitreTechnique(
        technique_id="T1018",
        technique_name="Remote System Discovery",
        tactic=MitreTactic.DISCOVERY,
        description="Adversary attempts to discover other systems on the network",
    ),
    # Collection
    "T1005": MitreTechnique(
        technique_id="T1005",
        technique_name="Data from Local System",
        tactic=MitreTactic.COLLECTION,
        description="Adversary collects data from the local system",
    ),
    "T1119": MitreTechnique(
        technique_id="T1119",
        technique_name="Automated Collection",
        tactic=MitreTactic.COLLECTION,
        description="Adversary uses automated techniques to collect internal data",
    ),
    # Exfiltration
    "T1048": MitreTechnique(
        technique_id="T1048",
        technique_name="Exfiltration Over Alternative Protocol",
        tactic=MitreTactic.EXFILTRATION,
        description="Adversary steals data via a protocol other than the existing C2 channel",
    ),
    "T1041": MitreTechnique(
        technique_id="T1041",
        technique_name="Exfiltration Over C2 Channel",
        tactic=MitreTactic.EXFILTRATION,
        description="Adversary steals data by sending it over the existing C2 channel",
    ),
    # Command and Control
    "T1071": MitreTechnique(
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        tactic=MitreTactic.COMMAND_AND_CONTROL,
        description="Adversary communicates using OSI application layer protocols",
    ),
    "T1105": MitreTechnique(
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        tactic=MitreTactic.COMMAND_AND_CONTROL,
        description="Adversary transfers tools or files from external to compromised system",
    ),
    # Lateral Movement
    "T1570": MitreTechnique(
        technique_id="T1570",
        technique_name="Lateral Tool Transfer",
        tactic=MitreTactic.LATERAL_MOVEMENT,
        description="Adversary transfers tools between systems within a compromised environment",
    ),
    # Impact
    "T1565": MitreTechnique(
        technique_id="T1565",
        technique_name="Data Manipulation",
        tactic=MitreTactic.IMPACT,
        description="Adversary inserts, deletes, or manipulates data to influence outcomes",
    ),
}

# ---------------------------------------------------------------------------
# Event type -> technique ID mappings
# ---------------------------------------------------------------------------

_EVENT_TYPE_MAPPINGS: dict[str, list[str]] = {
    NetworkEventType.DLP_HIT: ["T1552", "T1552.001", "T1048"],
    NetworkEventType.INJECTION_DETECTED: ["T1059", "T1203", "T1027"],
    NetworkEventType.SSRF_BLOCKED: ["T1190", "T1046", "T1018"],
    NetworkEventType.CHAIN_DETECTED: ["T1119", "T1570", "T1041"],
    NetworkEventType.KILL_SWITCH: ["T1565"],
    NetworkEventType.SENTINEL_HIT: ["T1552.001", "T1005"],
}


# ---------------------------------------------------------------------------
# MitreAttackMapper service
# ---------------------------------------------------------------------------


class MitreAttackMapper:
    """Maps AgentPEP events and rules to MITRE ATT&CK technique IDs.

    The mapper maintains a static technique catalogue enriched with
    event-type and rule-ID level mappings.  It is used by the Kafka
    event producer and by the security assessment engine to tag every
    finding with its corresponding ATT&CK technique.
    """

    def __init__(self) -> None:
        self._techniques: dict[str, MitreTechnique] = dict(_TECHNIQUES)
        self._event_type_mappings: dict[str, list[str]] = dict(_EVENT_TYPE_MAPPINGS)
        self._rule_id_mappings: dict[str, str] = {}

    def get_technique(self, technique_id: str) -> MitreTechnique | None:
        """Look up a technique by ID."""
        return self._techniques.get(technique_id)

    def get_techniques_for_event(self, event_type: str) -> list[str]:
        """Return technique IDs associated with an event type."""
        return list(self._event_type_mappings.get(event_type, []))

    def get_primary_technique_for_event(self, event_type: str) -> str:
        """Return the primary (first) technique ID for an event type."""
        techniques = self._event_type_mappings.get(event_type, [])
        return techniques[0] if techniques else ""

    def get_technique_for_rule(self, rule_id: str) -> str:
        """Return the technique ID mapped to a specific rule."""
        return self._rule_id_mappings.get(rule_id, "")

    def register_rule_mapping(self, rule_id: str, technique_id: str) -> None:
        """Register a rule_id -> technique_id mapping (e.g. from a rule bundle)."""
        if technique_id in self._techniques:
            self._rule_id_mappings[rule_id] = technique_id
        else:
            logger.warning(
                "mitre_unknown_technique",
                extra={"rule_id": rule_id, "technique_id": technique_id},
            )
            self._rule_id_mappings[rule_id] = technique_id

    def register_custom_technique(self, technique: MitreTechnique) -> None:
        """Register a custom technique definition."""
        self._techniques[technique.technique_id] = technique

    def enrich_event(self, event_type: str, rule_id: str = "") -> str:
        """Return the best-match technique ID for a given event+rule.

        Priority: rule-specific mapping > event-type primary mapping > empty.
        """
        if rule_id and rule_id in self._rule_id_mappings:
            return self._rule_id_mappings[rule_id]
        return self.get_primary_technique_for_event(event_type)

    def get_full_map(self) -> MitreTechniqueMap:
        """Return the complete technique map as a Pydantic model."""
        return MitreTechniqueMap(
            techniques=dict(self._techniques),
            event_type_mappings=dict(self._event_type_mappings),
            rule_id_mappings=dict(self._rule_id_mappings),
        )

    def stats(self) -> dict[str, int]:
        """Return summary statistics about the technique map."""
        return {
            "techniques": len(self._techniques),
            "event_type_mappings": len(self._event_type_mappings),
            "rule_id_mappings": len(self._rule_id_mappings),
        }


# Module-level singleton
mitre_attack_mapper = MitreAttackMapper()
