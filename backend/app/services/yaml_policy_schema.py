"""YAML policy JSON Schema definitions — Sprint 30 (APEP-233).

Declarative JSON Schema for validating YAML policy files covering:
- Roles (RBAC hierarchy)
- Rules (authorization rules with rate limits and validators)
- Risk configuration (weight overrides, escalation thresholds)
- Taint policies (sanitisation gates, injection signatures)
- Data classifications (sensitivity levels)

The schemas are used by the YAML policy loader (APEP-234) to validate
policy files before hydrating Pydantic model objects.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Common reusable schema fragments
# ---------------------------------------------------------------------------

_GLOB_PATTERN = {"type": "string", "minLength": 1, "maxLength": 256}

_DECISION_ENUM = {
    "type": "string",
    "enum": ["ALLOW", "DENY", "ESCALATE", "DRY_RUN"],
}

_TAINT_LEVEL_ENUM = {
    "type": "string",
    "enum": ["TRUSTED", "UNTRUSTED", "QUARANTINE"],
}

_TAINT_SOURCE_ENUM = {
    "type": "string",
    "enum": [
        "USER_PROMPT", "SYSTEM_PROMPT", "WEB", "EMAIL",
        "TOOL_OUTPUT", "AGENT_MSG", "CROSS_AGENT", "SANITISED",
    ],
}

_RISK_SCORE = {"type": "number", "minimum": 0.0, "maximum": 1.0}

# ---------------------------------------------------------------------------
# Roles schema (policies/roles.yaml)
# ---------------------------------------------------------------------------

ROLES_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "AgentPEP Roles Policy",
    "description": "RBAC role definitions with multi-inheritance hierarchy.",
    "type": "object",
    "required": ["version", "roles"],
    "additionalProperties": False,
    "properties": {
        "version": {"type": "string", "pattern": r"^\d+\.\d+$"},
        "metadata": {
            "type": "object",
            "properties": {
                "description": {"type": "string"},
                "author": {"type": "string"},
                "created_at": {"type": "string"},
            },
            "additionalProperties": True,
        },
        "roles": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["role_id", "name"],
                "additionalProperties": False,
                "properties": {
                    "role_id": {"type": "string", "minLength": 1, "maxLength": 128},
                    "name": {"type": "string", "minLength": 1, "maxLength": 256},
                    "parent_roles": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": [],
                    },
                    "allowed_tools": {
                        "type": "array",
                        "items": _GLOB_PATTERN,
                        "default": [],
                    },
                    "denied_tools": {
                        "type": "array",
                        "items": _GLOB_PATTERN,
                        "default": [],
                    },
                    "max_risk_threshold": {**_RISK_SCORE, "default": 1.0},
                    "enabled": {"type": "boolean", "default": True},
                },
            },
            "minItems": 0,
        },
    },
}

# ---------------------------------------------------------------------------
# Rules schema (policies/rules.yaml)
# ---------------------------------------------------------------------------

_RATE_LIMIT_SCHEMA = {
    "type": "object",
    "required": ["count", "window_s"],
    "additionalProperties": False,
    "properties": {
        "count": {"type": "integer", "minimum": 1, "maximum": 100000},
        "window_s": {"type": "integer", "minimum": 1, "maximum": 86400},
        "limiter_type": {
            "type": "string",
            "enum": ["SLIDING_WINDOW", "FIXED_WINDOW"],
            "default": "SLIDING_WINDOW",
        },
    },
}

_ARG_VALIDATOR_SCHEMA = {
    "type": "object",
    "required": ["arg_name"],
    "additionalProperties": False,
    "properties": {
        "arg_name": {"type": "string"},
        "json_schema": {"type": "object"},
        "regex_pattern": {"type": "string"},
        "allowlist": {"type": "array", "items": {"type": "string"}},
        "blocklist": {"type": "array", "items": {"type": "string"}},
    },
}

RULES_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "AgentPEP Rules Policy",
    "description": "Authorization rules with rate limits, taint checks, and arg validators.",
    "type": "object",
    "required": ["version", "rules"],
    "additionalProperties": False,
    "properties": {
        "version": {"type": "string", "pattern": r"^\d+\.\d+$"},
        "metadata": {
            "type": "object",
            "properties": {
                "description": {"type": "string"},
                "author": {"type": "string"},
                "created_at": {"type": "string"},
            },
            "additionalProperties": True,
        },
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "tool_pattern", "action"],
                "additionalProperties": False,
                "properties": {
                    "rule_id": {"type": "string"},
                    "name": {"type": "string", "minLength": 1, "maxLength": 256},
                    "agent_role": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": [],
                    },
                    "tool_pattern": _GLOB_PATTERN,
                    "action": _DECISION_ENUM,
                    "taint_check": {"type": "boolean", "default": False},
                    "risk_threshold": {**_RISK_SCORE, "default": 1.0},
                    "rate_limit": _RATE_LIMIT_SCHEMA,
                    "arg_validators": {
                        "type": "array",
                        "items": _ARG_VALIDATOR_SCHEMA,
                        "default": [],
                    },
                    "priority": {"type": "integer", "default": 100},
                    "enabled": {"type": "boolean", "default": True},
                },
            },
            "minItems": 0,
        },
    },
}

# ---------------------------------------------------------------------------
# Risk configuration schema (policies/risk.yaml)
# ---------------------------------------------------------------------------

_RISK_WEIGHT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "operation_type": {"type": "number", "minimum": 0.0, "default": 0.25},
        "data_sensitivity": {"type": "number", "minimum": 0.0, "default": 0.25},
        "taint": {"type": "number", "minimum": 0.0, "default": 0.20},
        "session_accumulated": {"type": "number", "minimum": 0.0, "default": 0.10},
        "delegation_depth": {"type": "number", "minimum": 0.0, "default": 0.20},
    },
}

RISK_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "AgentPEP Risk Configuration",
    "description": "Risk model weights, per-role overrides, and escalation thresholds.",
    "type": "object",
    "required": ["version"],
    "additionalProperties": False,
    "properties": {
        "version": {"type": "string", "pattern": r"^\d+\.\d+$"},
        "metadata": {
            "type": "object",
            "properties": {
                "description": {"type": "string"},
                "author": {"type": "string"},
                "created_at": {"type": "string"},
            },
            "additionalProperties": True,
        },
        "risk_model": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "model_id": {"type": "string", "default": "default"},
                "default_weights": _RISK_WEIGHT_SCHEMA,
                "role_overrides": {
                    "type": "object",
                    "additionalProperties": _RISK_WEIGHT_SCHEMA,
                },
                "escalation_threshold": {**_RISK_SCORE, "default": 0.7},
                "enabled": {"type": "boolean", "default": True},
            },
        },
    },
}

# ---------------------------------------------------------------------------
# Taint policies schema (policies/taint.yaml)
# ---------------------------------------------------------------------------

_SANITISATION_GATE_SCHEMA = {
    "type": "object",
    "required": ["name", "function_pattern", "downgrades_from", "downgrades_to"],
    "additionalProperties": False,
    "properties": {
        "gate_id": {"type": "string"},
        "name": {"type": "string", "minLength": 1},
        "function_pattern": _GLOB_PATTERN,
        "downgrades_from": _TAINT_LEVEL_ENUM,
        "downgrades_to": _TAINT_LEVEL_ENUM,
        "requires_approval": {"type": "boolean", "default": False},
        "enabled": {"type": "boolean", "default": True},
    },
}

_INJECTION_SIGNATURE_SCHEMA = {
    "type": "object",
    "required": ["signature_id", "category", "pattern"],
    "additionalProperties": False,
    "properties": {
        "signature_id": {"type": "string", "minLength": 1},
        "category": {
            "type": "string",
            "enum": [
                "prompt_override", "role_hijack", "system_escape",
                "jailbreak", "encoding_bypass",
            ],
        },
        "pattern": {"type": "string", "minLength": 1},
        "severity": {
            "type": "string",
            "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            "default": "HIGH",
        },
        "description": {"type": "string", "default": ""},
    },
}

TAINT_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "AgentPEP Taint Policies",
    "description": "Sanitisation gates and injection signature definitions.",
    "type": "object",
    "required": ["version"],
    "additionalProperties": False,
    "properties": {
        "version": {"type": "string", "pattern": r"^\d+\.\d+$"},
        "metadata": {
            "type": "object",
            "properties": {
                "description": {"type": "string"},
                "author": {"type": "string"},
                "created_at": {"type": "string"},
            },
            "additionalProperties": True,
        },
        "sanitisation_gates": {
            "type": "array",
            "items": _SANITISATION_GATE_SCHEMA,
            "default": [],
        },
        "injection_signatures": {
            "type": "array",
            "items": _INJECTION_SIGNATURE_SCHEMA,
            "default": [],
        },
    },
}

# ---------------------------------------------------------------------------
# Data classifications schema (policies/classifications.yaml)
# ---------------------------------------------------------------------------

CLASSIFICATIONS_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "AgentPEP Data Classifications",
    "description": "Data sensitivity levels and tool-to-classification mappings.",
    "type": "object",
    "required": ["version"],
    "additionalProperties": False,
    "properties": {
        "version": {"type": "string", "pattern": r"^\d+\.\d+$"},
        "metadata": {
            "type": "object",
            "properties": {
                "description": {"type": "string"},
                "author": {"type": "string"},
                "created_at": {"type": "string"},
            },
            "additionalProperties": True,
        },
        "levels": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "rank"],
                "additionalProperties": False,
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "rank": {"type": "integer", "minimum": 0},
                    "description": {"type": "string", "default": ""},
                },
            },
            "default": [],
        },
        "tool_classifications": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["tool_pattern", "classification"],
                "additionalProperties": False,
                "properties": {
                    "tool_pattern": _GLOB_PATTERN,
                    "classification": {"type": "string", "minLength": 1},
                    "description": {"type": "string", "default": ""},
                },
            },
            "default": [],
        },
    },
}

# ---------------------------------------------------------------------------
# Unified policy bundle schema (single-file format)
# ---------------------------------------------------------------------------

POLICY_BUNDLE_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "AgentPEP Policy Bundle",
    "description": "Unified policy file containing roles, rules, risk, taint, and classifications.",
    "type": "object",
    "required": ["version"],
    "additionalProperties": False,
    "properties": {
        "version": {"type": "string", "pattern": r"^\d+\.\d+$"},
        "metadata": {
            "type": "object",
            "properties": {
                "description": {"type": "string"},
                "author": {"type": "string"},
                "created_at": {"type": "string"},
            },
            "additionalProperties": True,
        },
        "roles": ROLES_SCHEMA["properties"]["roles"],
        "rules": RULES_SCHEMA["properties"]["rules"],
        "risk_model": RISK_SCHEMA["properties"]["risk_model"],
        "sanitisation_gates": TAINT_SCHEMA["properties"]["sanitisation_gates"],
        "injection_signatures": TAINT_SCHEMA["properties"]["injection_signatures"],
        "classification_levels": CLASSIFICATIONS_SCHEMA["properties"]["levels"],
        "tool_classifications": CLASSIFICATIONS_SCHEMA["properties"]["tool_classifications"],
    },
}

# Map file names to schemas for directory-convention loading.
FILE_SCHEMA_MAP: dict[str, dict] = {
    "roles.yaml": ROLES_SCHEMA,
    "roles.yml": ROLES_SCHEMA,
    "rules.yaml": RULES_SCHEMA,
    "rules.yml": RULES_SCHEMA,
    "risk.yaml": RISK_SCHEMA,
    "risk.yml": RISK_SCHEMA,
    "taint.yaml": TAINT_SCHEMA,
    "taint.yml": TAINT_SCHEMA,
    "classifications.yaml": CLASSIFICATIONS_SCHEMA,
    "classifications.yml": CLASSIFICATIONS_SCHEMA,
}
