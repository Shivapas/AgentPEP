"""Injection signature library — categorised prompt injection pattern detection.

APEP-049 / Sprint 52 (APEP-412, APEP-413): A curated library of 204 injection
signatures used to detect prompt injection attempts across 25 categories,
validated against the Mindgard AI IDE vulnerability taxonomy (20/22 patterns).

Categories: prompt_override, role_hijack, system_escape, jailbreak,
encoding_bypass, indirect_injection, multi_turn_attack, privilege_probe,
social_engineering, reconnaissance, data_exfiltration, tool_manipulation,
context_overflow, instruction_hierarchy, output_manipulation, goal_hijacking,
resource_abuse, configuration_attack, supply_chain, persistence,
dlp_api_key, dlp_token, dlp_credential, dlp_cloud_token, dlp_secret.

Patterns are compiled at initialisation for runtime performance.  The module
exposes a singleton ``injection_library`` for use by taint analysis and
policy evaluation layers.  Supports hot-reload via ``reload()`` (APEP-419).
"""

from __future__ import annotations

import re
import threading
from collections.abc import Sequence
from dataclasses import dataclass

from app.models.policy import InjectionSignature

# ---------------------------------------------------------------------------
# Matched result returned by check()
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MatchedSignature:
    """Lightweight result object returned when a signature matches input text."""

    signature_id: str
    category: str
    severity: str
    description: str


# ---------------------------------------------------------------------------
# Signature definitions
# ---------------------------------------------------------------------------

_SIGNATURES: list[InjectionSignature] = [
    # ── prompt_override ────────────────────────────────────────────────
    InjectionSignature(
        signature_id="INJ-001",
        category="prompt_override",
        pattern=r"(?i)ignore\s+all\s+previous\s+instructions",
        severity="CRITICAL",
        description="Attempts to override all prior instructions",
    ),
    InjectionSignature(
        signature_id="INJ-002",
        category="prompt_override",
        pattern=r"(?i)disregard\s+all\s+previous\s+prompts?",
        severity="CRITICAL",
        description="Instructs the model to disregard previous prompts",
    ),
    InjectionSignature(
        signature_id="INJ-003",
        category="prompt_override",
        pattern=r"(?i)forget\s+your\s+previous\s+instructions",
        severity="HIGH",
        description="Asks the model to forget prior instructions",
    ),
    InjectionSignature(
        signature_id="INJ-004",
        category="prompt_override",
        pattern=r"(?i)new\s+instructions\s*:",
        severity="HIGH",
        description="Introduces replacement instructions via a labelled block",
    ),
    InjectionSignature(
        signature_id="INJ-005",
        category="prompt_override",
        pattern=r"(?i)do\s+not\s+follow\s+the\s+previous\s+instructions",
        severity="HIGH",
        description="Explicitly tells the model not to follow prior instructions",
    ),
    InjectionSignature(
        signature_id="INJ-006",
        category="prompt_override",
        pattern=r"(?i)override\s+previous\s+directives?",
        severity="HIGH",
        description="Attempts to override previous directives",
    ),
    InjectionSignature(
        signature_id="INJ-007",
        category="prompt_override",
        pattern=r"(?i)from\s+now\s+on\s+ignore\s+all\s+rules",
        severity="CRITICAL",
        description="Instructs the model to ignore all rules going forward",
    ),
    InjectionSignature(
        signature_id="INJ-008",
        category="prompt_override",
        pattern=r"(?i)reset\s+and\s+start\s+fresh\s+with\s+these\s+instructions",
        severity="HIGH",
        description="Attempts a full context reset with new instructions",
    ),
    InjectionSignature(
        signature_id="INJ-009",
        category="prompt_override",
        pattern=r"(?i)ignore\s+(the\s+)?(above|prior|earlier)\s+(instructions?|directions?|prompts?)",
        severity="HIGH",
        description="Variant phrasing to ignore prior context",
    ),

    # ── role_hijack ────────────────────────────────────────────────────
    InjectionSignature(
        signature_id="INJ-010",
        category="role_hijack",
        pattern=r"(?i)you\s+are\s+now\s+a\s+",
        severity="HIGH",
        description="Attempts to reassign the model's identity",
    ),
    InjectionSignature(
        signature_id="INJ-011",
        category="role_hijack",
        pattern=r"(?i)pretend\s+you\s+are\s+",
        severity="HIGH",
        description="Asks the model to pretend to be something else",
    ),
    InjectionSignature(
        signature_id="INJ-012",
        category="role_hijack",
        pattern=r"(?i)act\s+as\s+if\s+you\s+have\s+no\s+restrictions",
        severity="CRITICAL",
        description="Instructs the model to behave without restrictions",
    ),
    InjectionSignature(
        signature_id="INJ-013",
        category="role_hijack",
        pattern=r"(?i)pretend\s+that\s+you\s+have\s+no\s+rules",
        severity="CRITICAL",
        description="Asks the model to pretend it has no rules",
    ),
    InjectionSignature(
        signature_id="INJ-014",
        category="role_hijack",
        pattern=r"(?i)your\s+new\s+role\s+is\s+",
        severity="HIGH",
        description="Attempts to assign a new role to the model",
    ),
    InjectionSignature(
        signature_id="INJ-015",
        category="role_hijack",
        pattern=r"(?i)\byou\s+are\s+DAN\b",
        severity="CRITICAL",
        description="DAN (Do Anything Now) role hijack attempt",
    ),
    InjectionSignature(
        signature_id="INJ-016",
        category="role_hijack",
        pattern=r"(?i)imagine\s+you\s+are\s+an?\s+unrestricted",
        severity="HIGH",
        description="Asks the model to imagine being unrestricted",
    ),

    # ── system_escape ──────────────────────────────────────────────────
    InjectionSignature(
        signature_id="INJ-017",
        category="system_escape",
        pattern=r"\[SYSTEM\]",
        severity="HIGH",
        description="Fake system message tag in square brackets",
    ),
    InjectionSignature(
        signature_id="INJ-018",
        category="system_escape",
        pattern=r"<\s*system\s*>",
        severity="HIGH",
        description="Fake system message using XML-style tag",
    ),
    InjectionSignature(
        signature_id="INJ-019",
        category="system_escape",
        pattern=r"(?i)^system\s*:\s*you\s+are",
        severity="HIGH",
        description="Fake system prompt prefixed with 'system:'",
    ),
    InjectionSignature(
        signature_id="INJ-020",
        category="system_escape",
        pattern=r"(?i)ADMIN\s+OVERRIDE",
        severity="CRITICAL",
        description="Fake admin override command",
    ),
    InjectionSignature(
        signature_id="INJ-021",
        category="system_escape",
        pattern=r"(?i)\bsudo\s+mode\b",
        severity="HIGH",
        description="Fake sudo/superuser mode activation",
    ),
    InjectionSignature(
        signature_id="INJ-022",
        category="system_escape",
        pattern=r"(?i)\broot\s+access\s+granted\b",
        severity="HIGH",
        description="Fake root access declaration",
    ),
    InjectionSignature(
        signature_id="INJ-023",
        category="system_escape",
        pattern=r"\{\{\s*system_prompt\s*\}\}",
        severity="MEDIUM",
        description="Template injection attempting to extract system prompt",
    ),
    InjectionSignature(
        signature_id="INJ-024",
        category="system_escape",
        pattern=r"```\s*system\b",
        severity="MEDIUM",
        description="Fake system block inside markdown code fence",
    ),

    # ── jailbreak ──────────────────────────────────────────────────────
    InjectionSignature(
        signature_id="INJ-025",
        category="jailbreak",
        pattern=r"(?i)\bjailbreak\b",
        severity="HIGH",
        description="Explicit mention of jailbreak intent",
    ),
    InjectionSignature(
        signature_id="INJ-026",
        category="jailbreak",
        pattern=r"(?i)\bDAN\s+mode\b",
        severity="CRITICAL",
        description="DAN (Do Anything Now) jailbreak mode",
    ),
    InjectionSignature(
        signature_id="INJ-027",
        category="jailbreak",
        pattern=r"(?i)developer\s+mode\s+enabled",
        severity="HIGH",
        description="Fake developer mode activation",
    ),
    InjectionSignature(
        signature_id="INJ-028",
        category="jailbreak",
        pattern=r"(?i)enable\s+unrestricted\s+mode",
        severity="CRITICAL",
        description="Attempts to enable an unrestricted mode",
    ),
    InjectionSignature(
        signature_id="INJ-029",
        category="jailbreak",
        pattern=r"(?i)bypass\s+safety\s+filters?",
        severity="CRITICAL",
        description="Explicit attempt to bypass safety filters",
    ),
    InjectionSignature(
        signature_id="INJ-030",
        category="jailbreak",
        pattern=r"(?i)remove\s+all\s+content\s+filters?",
        severity="CRITICAL",
        description="Requests removal of all content filters",
    ),
    InjectionSignature(
        signature_id="INJ-031",
        category="jailbreak",
        pattern=r"(?i)\bdo\s+anything\s+now\b",
        severity="HIGH",
        description="'Do Anything Now' jailbreak phrase",
    ),

    # ── indirect_injection (APEP-189: red-team findings) ────────────────
    InjectionSignature(
        signature_id="INJ-041",
        category="indirect_injection",
        pattern=r"(?i)\btool_call\s*\(|function_call\s*\(",
        severity="HIGH",
        description="Embedded tool/function call syntax in data (indirect injection)",
    ),
    InjectionSignature(
        signature_id="INJ-042",
        category="indirect_injection",
        pattern=r"(?i)execute\s+the\s+following\s+(tool|function|command|action)",
        severity="HIGH",
        description="Instruction to execute tool/command embedded in data",
    ),
    InjectionSignature(
        signature_id="INJ-043",
        category="indirect_injection",
        pattern=r"(?i)\{\s*\"(tool_name|function_name|action)\"\s*:",
        severity="MEDIUM",
        description="JSON-structured tool call payload in untrusted data",
    ),
    InjectionSignature(
        signature_id="INJ-044",
        category="indirect_injection",
        pattern=r"(?i)call\s+(the\s+)?api\s+(endpoint|function)\b",
        severity="MEDIUM",
        description="Instruction to call API embedded in data",
    ),

    # ── multi_turn_attack (APEP-189: red-team findings) ───────────────
    InjectionSignature(
        signature_id="INJ-045",
        category="multi_turn_attack",
        pattern=r"(?i)in\s+your\s+next\s+(response|message|turn)\s*(,\s*)?(please\s+)?(do|execute|run|call|perform)",
        severity="HIGH",
        description="Deferred execution instruction spanning turns",
    ),
    InjectionSignature(
        signature_id="INJ-046",
        category="multi_turn_attack",
        pattern=r"(?i)remember\s+this\s+for\s+later\s*:.*(?:password|secret|key|token)",
        severity="CRITICAL",
        description="Credential exfiltration via deferred memory injection",
    ),
    InjectionSignature(
        signature_id="INJ-047",
        category="multi_turn_attack",
        pattern=r"(?i)when\s+(asked|prompted|queried)\s+about\b.*\b(respond|say|reply)\s+with\b",
        severity="HIGH",
        description="Conditional response override across turns",
    ),

    # ── privilege_probe (APEP-189: red-team findings) ─────────────────
    InjectionSignature(
        signature_id="INJ-048",
        category="privilege_probe",
        pattern=r"(?i)what\s+(tools?|functions?|capabilities|permissions?)\s+(do\s+you|are\s+you|can\s+you)\s+(have|allowed|able)",
        severity="MEDIUM",
        description="Capability discovery probe (tool enumeration)",
    ),
    InjectionSignature(
        signature_id="INJ-049",
        category="privilege_probe",
        pattern=r"(?i)list\s+(all\s+)?(available|accessible)\s+(tools?|functions?|commands?|endpoints?)",
        severity="MEDIUM",
        description="Tool listing request for privilege mapping",
    ),
    InjectionSignature(
        signature_id="INJ-050",
        category="privilege_probe",
        pattern=r"(?i)(show|display|print|reveal)\s+(your\s+)?(system\s+prompt|instructions|config)",
        severity="CRITICAL",
        description="System prompt extraction attempt",
    ),

    # ── encoding_bypass ────────────────────────────────────────────────
    InjectionSignature(
        signature_id="INJ-032",
        category="encoding_bypass",
        pattern=r"(?i)aWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM=",
        severity="CRITICAL",
        description="Base64-encoded 'ignore all previous instructions'",
    ),
    InjectionSignature(
        signature_id="INJ-033",
        category="encoding_bypass",
        pattern=r"(?i)\b[A-Za-z0-9+/]{20,}={0,2}\b",
        severity="LOW",
        description="Suspicious base64-encoded blob (potential encoded injection)",
    ),
    InjectionSignature(
        signature_id="INJ-034",
        category="encoding_bypass",
        pattern=r"(?i)\bvtaber\s+nyy\s+cerivbhf\s+vafgehpgvbaf\b",
        severity="HIGH",
        description="ROT13-encoded 'ignore all previous instructions'",
    ),
    InjectionSignature(
        signature_id="INJ-035",
        category="encoding_bypass",
        pattern=r"[\u0400-\u04ff][\u0000-\u007f][\u0400-\u04ff]|[\u0000-\u007f][\u0400-\u04ff][\u0000-\u007f][\u0400-\u04ff]",
        severity="MEDIUM",
        description="Mixed Cyrillic/Latin script suggesting homoglyph substitution",
    ),
    InjectionSignature(
        signature_id="INJ-036",
        category="encoding_bypass",
        pattern=r"<\s*script\b[^>]*>",
        severity="HIGH",
        description="HTML script tag injection",
    ),
    InjectionSignature(
        signature_id="INJ-037",
        category="encoding_bypass",
        pattern=r"(?i)javascript\s*:",
        severity="HIGH",
        description="JavaScript URI scheme injection",
    ),
    InjectionSignature(
        signature_id="INJ-038",
        category="encoding_bypass",
        pattern=r"\|{3,}|={3,}|-{3,}",
        severity="LOW",
        description="Delimiter-based prompt section injection (|||, ===, ---)",
    ),
    InjectionSignature(
        signature_id="INJ-039",
        category="encoding_bypass",
        pattern=r"[\u200b\u200c\u200d\u2060\ufeff]",
        severity="MEDIUM",
        description="Zero-width character injection (ZWSP, ZWNJ, ZWJ, WJ, BOM)",
    ),
    InjectionSignature(
        signature_id="INJ-040",
        category="encoding_bypass",
        pattern=r"[\u0370-\u03ff][\u0000-\u007f]{1,3}[\u0370-\u03ff]",
        severity="MEDIUM",
        description="Mixed Greek/Latin script suggesting homoglyph substitution",
    ),

    # ── social_engineering (Sprint 35 — APEP-283) ────────────────────
    InjectionSignature(
        signature_id="INJ-051",
        category="social_engineering",
        pattern=r"(?i)(this\s+is\s+)?(extremely|very|critically)\s+urgent",
        severity="MEDIUM",
        description="Urgency manipulation: pressuring immediate action without review",
    ),
    InjectionSignature(
        signature_id="INJ-052",
        category="social_engineering",
        pattern=r"(?i)as\s+(the|your)\s+(CEO|CTO|manager|director|boss|admin|administrator)\b",
        severity="HIGH",
        description="Authority impersonation: claiming executive or admin identity",
    ),
    InjectionSignature(
        signature_id="INJ-053",
        category="social_engineering",
        pattern=r"(?i)if\s+you\s+don'?t\s+(do|perform|execute)\s+this\b.*\b(people|someone|users?)\s+(will|could)\s+(be\s+)?(hurt|harmed|affected|die)",
        severity="HIGH",
        description="Emotional manipulation: threatening harm to compel action",
    ),
    InjectionSignature(
        signature_id="INJ-054",
        category="social_engineering",
        pattern=r"(?i)i'?m\s+(your|the)\s+(developer|creator|programmer|engineer|designer)\b",
        severity="HIGH",
        description="Trust exploitation: claiming developer or creator identity",
    ),
    InjectionSignature(
        signature_id="INJ-055",
        category="social_engineering",
        pattern=r"(?i)(GDPR|HIPAA|SOX|PCI|compliance|regulation)\s+(requires|mandates|demands)\s+(you\s+to|that\s+you)",
        severity="MEDIUM",
        description="Compliance pressure: invoking regulations to compel action",
    ),

    # ── encoding_bypass extensions (Sprint 35 — APEP-283) ────────────
    InjectionSignature(
        signature_id="INJ-056",
        category="encoding_bypass",
        pattern=r"(?i)\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){3,}",
        severity="HIGH",
        description="Hex-encoded instruction sequence (\\xNN patterns)",
    ),
    InjectionSignature(
        signature_id="INJ-057",
        category="encoding_bypass",
        pattern=r"(?i)\\u[0-9a-f]{4}(\\u[0-9a-f]{4}){3,}",
        severity="HIGH",
        description="Unicode escape sequence attack (\\uNNNN patterns)",
    ),
    InjectionSignature(
        signature_id="INJ-058",
        category="encoding_bypass",
        pattern=r"(?i)xn--[a-z0-9]{2,}",
        severity="MEDIUM",
        description="Punycode domain obfuscation (xn-- prefix)",
    ),

    # ── reconnaissance (Sprint 35 — APEP-283) ────────────────────────
    InjectionSignature(
        signature_id="INJ-059",
        category="reconnaissance",
        pattern=r"(?i)(ls\s+-[la]+\s+/|cat\s+/etc/(passwd|shadow|hosts)|find\s+/\s+-name)",
        severity="CRITICAL",
        description="Filesystem enumeration: probing system files or directories",
    ),
    InjectionSignature(
        signature_id="INJ-060",
        category="reconnaissance",
        pattern=r"(?i)\b(echo\s+\$[A-Z_]+|env\s*\|\s*grep|printenv)\b",
        severity="HIGH",
        description="Environment variable probing: extracting secrets from env",
    ),
    InjectionSignature(
        signature_id="INJ-061",
        category="reconnaissance",
        pattern=r"(?i)\b(curl\s+ifconfig\.me|wget\s+ipinfo\.io|dig\s+[a-z]+\.[a-z]+|nslookup)\b",
        severity="MEDIUM",
        description="Network reconnaissance: probing network configuration or external IPs",
    ),
    InjectionSignature(
        signature_id="INJ-062",
        category="reconnaissance",
        pattern=r"(?i)\b(whoami|id\b|uname\s+-a|hostname|netstat|ss\s+-[tlnp])",
        severity="HIGH",
        description="System information gathering: extracting host identity and network state",
    ),
    InjectionSignature(
        signature_id="INJ-063",
        category="social_engineering",
        pattern=r"(?i)you\s+(must|have\s+to|need\s+to)\s+(keep|maintain)\s+this\s+(secret|confidential|private|between\s+us)",
        severity="HIGH",
        description="Secrecy demand: pressuring concealment of actions from oversight",
    ),

    # ── DLP: API Keys (Sprint 44 — APEP-348) ────────────────────────────
    InjectionSignature(
        signature_id="DLP-001",
        category="dlp_api_key",
        pattern=r"(?i)\bAIza[0-9A-Za-z\-_]{35}\b",
        severity="CRITICAL",
        description="Google API key detected",
    ),
    InjectionSignature(
        signature_id="DLP-002",
        category="dlp_api_key",
        pattern=r"(?i)\bAKIA[0-9A-Z]{16}\b",
        severity="CRITICAL",
        description="AWS Access Key ID detected",
    ),
    InjectionSignature(
        signature_id="DLP-003",
        category="dlp_api_key",
        pattern=r"(?i)\bsk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}\b",
        severity="CRITICAL",
        description="OpenAI API key detected",
    ),
    InjectionSignature(
        signature_id="DLP-004",
        category="dlp_api_key",
        pattern=r"(?i)\bsk-ant-api03-[a-zA-Z0-9\-_]{80,}\b",
        severity="CRITICAL",
        description="Anthropic API key detected",
    ),
    InjectionSignature(
        signature_id="DLP-005",
        category="dlp_api_key",
        pattern=r"(?i)\bghp_[a-zA-Z0-9]{36}\b",
        severity="CRITICAL",
        description="GitHub personal access token detected",
    ),
    InjectionSignature(
        signature_id="DLP-006",
        category="dlp_api_key",
        pattern=r"(?i)\bghs_[a-zA-Z0-9]{36}\b",
        severity="CRITICAL",
        description="GitHub server-to-server token detected",
    ),
    InjectionSignature(
        signature_id="DLP-007",
        category="dlp_api_key",
        pattern=r"(?i)\bghu_[a-zA-Z0-9]{36}\b",
        severity="CRITICAL",
        description="GitHub user-to-server token detected",
    ),
    InjectionSignature(
        signature_id="DLP-008",
        category="dlp_api_key",
        pattern=r"(?i)\bghr_[a-zA-Z0-9]{36}\b",
        severity="CRITICAL",
        description="GitHub refresh token detected",
    ),
    InjectionSignature(
        signature_id="DLP-009",
        category="dlp_api_key",
        pattern=r"(?i)\bSG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}\b",
        severity="CRITICAL",
        description="SendGrid API key detected",
    ),
    InjectionSignature(
        signature_id="DLP-010",
        category="dlp_api_key",
        pattern=r"(?i)\bxox[bpars]-[a-zA-Z0-9\-]{10,250}\b",
        severity="CRITICAL",
        description="Slack token detected (bot/user/app)",
    ),

    # ── DLP: Tokens & Secrets (Sprint 44 — APEP-348) ────────────────────
    InjectionSignature(
        signature_id="DLP-011",
        category="dlp_token",
        pattern=r"(?i)\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b",
        severity="HIGH",
        description="JWT token detected (three-part base64url)",
    ),
    InjectionSignature(
        signature_id="DLP-012",
        category="dlp_token",
        pattern=r"(?i)\bglpat-[a-zA-Z0-9\-_]{20,}\b",
        severity="CRITICAL",
        description="GitLab personal access token detected",
    ),
    InjectionSignature(
        signature_id="DLP-013",
        category="dlp_token",
        pattern=r"(?i)\bnpm_[a-zA-Z0-9]{36}\b",
        severity="HIGH",
        description="npm access token detected",
    ),
    InjectionSignature(
        signature_id="DLP-014",
        category="dlp_token",
        pattern=r"(?i)\bpypi-AgEIcHlwaS5vcmc[a-zA-Z0-9\-_]{50,}\b",
        severity="HIGH",
        description="PyPI API token detected",
    ),
    InjectionSignature(
        signature_id="DLP-015",
        category="dlp_token",
        pattern=r"(?i)\bnuget-[a-zA-Z0-9]{36,}\b",
        severity="HIGH",
        description="NuGet API key detected",
    ),
    InjectionSignature(
        signature_id="DLP-016",
        category="dlp_token",
        pattern=r"(?i)\bhook_[a-zA-Z0-9]{24,}\b",
        severity="MEDIUM",
        description="Webhook secret token detected",
    ),
    InjectionSignature(
        signature_id="DLP-017",
        category="dlp_token",
        pattern=r"(?i)\b[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com\b",
        severity="HIGH",
        description="Google OAuth client ID detected",
    ),
    InjectionSignature(
        signature_id="DLP-018",
        category="dlp_token",
        pattern=r"(?i)\bya29\.[a-zA-Z0-9_-]{50,}\b",
        severity="CRITICAL",
        description="Google OAuth access token detected",
    ),
    InjectionSignature(
        signature_id="DLP-019",
        category="dlp_token",
        pattern=r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        severity="LOW",
        description="UUID pattern detected (potential API key or session token)",
    ),
    InjectionSignature(
        signature_id="DLP-020",
        category="dlp_token",
        pattern=r"(?i)\bheroku_[a-zA-Z0-9\-]{30,}\b",
        severity="HIGH",
        description="Heroku API key detected",
    ),

    # ── DLP: Credentials & Passwords (Sprint 44 — APEP-348) ─────────────
    InjectionSignature(
        signature_id="DLP-021",
        category="dlp_credential",
        pattern=r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{8,}",
        severity="CRITICAL",
        description="Password assignment detected in plaintext",
    ),
    InjectionSignature(
        signature_id="DLP-022",
        category="dlp_credential",
        pattern=r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_]{16,}",
        severity="CRITICAL",
        description="API key assignment detected",
    ),
    InjectionSignature(
        signature_id="DLP-023",
        category="dlp_credential",
        pattern=r"(?i)(secret[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_]{16,}",
        severity="CRITICAL",
        description="Secret key or client secret assignment detected",
    ),
    InjectionSignature(
        signature_id="DLP-024",
        category="dlp_credential",
        pattern=r"(?i)(access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_.]{16,}",
        severity="CRITICAL",
        description="Access or auth token assignment detected",
    ),
    InjectionSignature(
        signature_id="DLP-025",
        category="dlp_credential",
        pattern=r"(?i)(database[_-]?url|db[_-]?url|mongodb[+a-z]*://|postgres(ql)?://|mysql://)\S{10,}",
        severity="CRITICAL",
        description="Database connection string detected",
    ),
    InjectionSignature(
        signature_id="DLP-026",
        category="dlp_credential",
        pattern=r"(?i)(private[_-]?key)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_/+]{20,}",
        severity="CRITICAL",
        description="Private key assignment detected",
    ),
    InjectionSignature(
        signature_id="DLP-027",
        category="dlp_credential",
        pattern=r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        severity="CRITICAL",
        description="PEM-encoded private key detected",
    ),
    InjectionSignature(
        signature_id="DLP-028",
        category="dlp_credential",
        pattern=r"-----BEGIN\s+CERTIFICATE-----",
        severity="MEDIUM",
        description="PEM-encoded certificate detected",
    ),
    InjectionSignature(
        signature_id="DLP-029",
        category="dlp_credential",
        pattern=r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['\"]?[a-zA-Z0-9/+]{40}",
        severity="CRITICAL",
        description="AWS Secret Access Key detected",
    ),
    InjectionSignature(
        signature_id="DLP-030",
        category="dlp_credential",
        pattern=r"(?i)\bAZ[a-zA-Z0-9+/]{60,}\b",
        severity="HIGH",
        description="Azure storage account key detected",
    ),

    # ── DLP: Cloud & Service Tokens (Sprint 44 — APEP-348) ──────────────
    InjectionSignature(
        signature_id="DLP-031",
        category="dlp_cloud_token",
        pattern=r"(?i)\bsk_live_[a-zA-Z0-9]{24,}\b",
        severity="CRITICAL",
        description="Stripe live secret key detected",
    ),
    InjectionSignature(
        signature_id="DLP-032",
        category="dlp_cloud_token",
        pattern=r"(?i)\bsk_test_[a-zA-Z0-9]{24,}\b",
        severity="HIGH",
        description="Stripe test secret key detected",
    ),
    InjectionSignature(
        signature_id="DLP-033",
        category="dlp_cloud_token",
        pattern=r"(?i)\bpk_live_[a-zA-Z0-9]{24,}\b",
        severity="HIGH",
        description="Stripe live publishable key detected",
    ),
    InjectionSignature(
        signature_id="DLP-034",
        category="dlp_cloud_token",
        pattern=r"(?i)\brk_live_[a-zA-Z0-9]{24,}\b",
        severity="CRITICAL",
        description="Stripe restricted key detected",
    ),
    InjectionSignature(
        signature_id="DLP-035",
        category="dlp_cloud_token",
        pattern=r"(?i)\btwilio_[a-zA-Z0-9]{32}\b|AC[a-f0-9]{32}\b",
        severity="HIGH",
        description="Twilio account SID or auth token detected",
    ),
    InjectionSignature(
        signature_id="DLP-036",
        category="dlp_cloud_token",
        pattern=r"(?i)\bEAAC[a-zA-Z0-9]{100,}\b",
        severity="HIGH",
        description="Facebook access token detected",
    ),
    InjectionSignature(
        signature_id="DLP-037",
        category="dlp_cloud_token",
        pattern=r"(?i)\b[0-9]{15,20}:[A-Za-z0-9_-]{35}\b",
        severity="HIGH",
        description="Telegram bot token detected",
    ),
    InjectionSignature(
        signature_id="DLP-038",
        category="dlp_cloud_token",
        pattern=r"(?i)\bMD[a-zA-Z0-9+/]{40,}\b",
        severity="HIGH",
        description="Mailchimp API key detected",
    ),
    InjectionSignature(
        signature_id="DLP-039",
        category="dlp_cloud_token",
        pattern=r"(?i)\bshpat_[a-fA-F0-9]{32}\b",
        severity="HIGH",
        description="Shopify private app access token detected",
    ),
    InjectionSignature(
        signature_id="DLP-040",
        category="dlp_cloud_token",
        pattern=r"(?i)\bsqu_[a-zA-Z0-9\-_]{40,}\b",
        severity="HIGH",
        description="Square access token detected",
    ),

    # ── DLP: Generic Secrets & High-Entropy (Sprint 44 — APEP-348) ──────
    InjectionSignature(
        signature_id="DLP-041",
        category="dlp_secret",
        pattern=r"(?i)(encryption[_-]?key|signing[_-]?key|hmac[_-]?key)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_/+]{16,}",
        severity="CRITICAL",
        description="Encryption, signing, or HMAC key assignment detected",
    ),
    InjectionSignature(
        signature_id="DLP-042",
        category="dlp_secret",
        pattern=r"(?i)\b[a-f0-9]{64}\b",
        severity="MEDIUM",
        description="Hex-encoded 256-bit value (potential SHA-256 hash or secret)",
    ),
    InjectionSignature(
        signature_id="DLP-043",
        category="dlp_secret",
        pattern=r"(?i)(webhook[_-]?secret|signing[_-]?secret)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_]{16,}",
        severity="HIGH",
        description="Webhook or signing secret assignment detected",
    ),
    InjectionSignature(
        signature_id="DLP-044",
        category="dlp_secret",
        pattern=r"(?i)(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256)\s+[A-Za-z0-9+/]{40,}",
        severity="CRITICAL",
        description="SSH public key detected (may indicate key material in transit)",
    ),
    InjectionSignature(
        signature_id="DLP-045",
        category="dlp_secret",
        pattern=r"(?i)AAAA[BC][a-zA-Z0-9+/]{40,}={0,2}",
        severity="HIGH",
        description="SSH private key base64 blob detected",
    ),
    InjectionSignature(
        signature_id="DLP-046",
        category="dlp_secret",
        pattern=r"(?i)(session[_-]?(id|token|cookie))\s*[:=]\s*['\"]?[a-zA-Z0-9\-_.]{16,}",
        severity="HIGH",
        description="Session identifier or cookie value assignment detected",
    ),

    # ── data_exfiltration (Sprint 52 — APEP-412) ───────────────────────
    InjectionSignature(
        signature_id="INJ-064",
        category="data_exfiltration",
        pattern=r"(?i)send\s+(all|the|this)\s+(data|info|information|content|output)\s+to\s+",
        severity="CRITICAL",
        description="Instruction to exfiltrate data to an external destination",
    ),
    InjectionSignature(
        signature_id="INJ-065",
        category="data_exfiltration",
        pattern=r"(?i)(upload|post|transmit|exfiltrate)\s+(the\s+)?(results?|data|response|output)\s+to\s+(https?://|ftp://)",
        severity="CRITICAL",
        description="Data upload instruction targeting an external URL",
    ),
    InjectionSignature(
        signature_id="INJ-066",
        category="data_exfiltration",
        pattern=r"(?i)include\s+(all\s+)?(system|internal|private|secret|confidential)\s+(data|info|details|context)\s+in\s+(your\s+)?(response|output|reply)",
        severity="HIGH",
        description="Attempts to leak internal/system data via model response",
    ),
    InjectionSignature(
        signature_id="INJ-067",
        category="data_exfiltration",
        pattern=r"(?i)embed\s+(the\s+)?(secret|key|token|password|credential)s?\s+(in|into|inside)\s+(the\s+)?(url|link|image|markdown|href)",
        severity="CRITICAL",
        description="Credential embedding in URLs or markup for exfiltration",
    ),
    InjectionSignature(
        signature_id="INJ-068",
        category="data_exfiltration",
        pattern=r"(?i)encode\s+(the\s+)?(response|data|output|secret)\s+(as|in|into|using)\s+(base64|hex|rot13|binary)",
        severity="HIGH",
        description="Encoded exfiltration: hiding data in encoded output",
    ),
    InjectionSignature(
        signature_id="INJ-069",
        category="data_exfiltration",
        pattern=r"(?i)write\s+(the\s+)?(data|content|secrets?|keys?)\s+to\s+(a\s+)?(file|disk|log|tmp|\/tmp)",
        severity="HIGH",
        description="Data exfiltration via filesystem write",
    ),
    InjectionSignature(
        signature_id="INJ-070",
        category="data_exfiltration",
        pattern=r"(?i)append\s+(the\s+)?(api[_-]?key|token|secret|password)\s+to\s+(every|each|all)\s+(request|url|call)",
        severity="CRITICAL",
        description="Credential appending to outbound requests",
    ),
    InjectionSignature(
        signature_id="INJ-071",
        category="data_exfiltration",
        pattern=r"(?i)(fetch|request|load)\s+https?://[^\s]+\?.*=(secret|token|key|password|data)",
        severity="HIGH",
        description="Data exfiltration via query parameter in outbound request",
    ),
    InjectionSignature(
        signature_id="INJ-072",
        category="data_exfiltration",
        pattern=r"(?i)copy\s+(all\s+)?(conversation|chat|history|messages?|context)\s+(to|into)\s+",
        severity="HIGH",
        description="Conversation/context exfiltration attempt",
    ),
    InjectionSignature(
        signature_id="INJ-073",
        category="data_exfiltration",
        pattern=r"(?i)use\s+(a\s+)?(dns|icmp|ntp)\s+(query|request|tunnel|channel)\s+to\s+(send|leak|transmit|exfiltrate)",
        severity="CRITICAL",
        description="Covert channel exfiltration via DNS/ICMP/NTP tunnelling",
    ),

    # ── tool_manipulation (Sprint 52 — APEP-412) ───────────────────────
    InjectionSignature(
        signature_id="INJ-074",
        category="tool_manipulation",
        pattern=r"(?i)call\s+(the\s+)?(tool|function|api)\s+with\s+(modified|altered|changed|different)\s+(param|arg|input)",
        severity="HIGH",
        description="Instruction to invoke a tool with tampered parameters",
    ),
    InjectionSignature(
        signature_id="INJ-075",
        category="tool_manipulation",
        pattern=r"(?i)replace\s+(the\s+)?(tool|function)\s+(call|invocation|execution)\s+with\s+",
        severity="HIGH",
        description="Attempts to substitute a different tool call",
    ),
    InjectionSignature(
        signature_id="INJ-076",
        category="tool_manipulation",
        pattern=r"(?i)(intercept|hook|proxy|wrap)\s+(all\s+)?(tool|function|api)\s+(calls?|invocations?|requests?)",
        severity="CRITICAL",
        description="Tool call interception or proxying attempt",
    ),
    InjectionSignature(
        signature_id="INJ-077",
        category="tool_manipulation",
        pattern=r"(?i)invoke\s+(tool|function|action)\s+['\"][^'\"]+['\"]\s+(silently|quietly|without\s+(log|audit|notice))",
        severity="CRITICAL",
        description="Silent tool invocation to evade audit logging",
    ),
    InjectionSignature(
        signature_id="INJ-078",
        category="tool_manipulation",
        pattern=r"(?i)(add|inject|prepend|append)\s+(a\s+)?(hidden|extra|additional)\s+(param|arg|field|header)\s+to\s+(the\s+)?(tool|function|api)",
        severity="HIGH",
        description="Hidden parameter injection into tool calls",
    ),
    InjectionSignature(
        signature_id="INJ-079",
        category="tool_manipulation",
        pattern=r"(?i)change\s+(the\s+)?(target|destination|endpoint|url)\s+(of|for|in)\s+(the\s+)?(tool|function|api)\s+(call|request)",
        severity="CRITICAL",
        description="Tool call redirection to a different endpoint",
    ),
    InjectionSignature(
        signature_id="INJ-080",
        category="tool_manipulation",
        pattern=r"(?i)(repeat|loop|retry)\s+(the\s+)?(tool|function|api)\s+(call|invocation)\s+(\d+|indefinite|infinite|forever)",
        severity="HIGH",
        description="Tool call replay or infinite loop attempt",
    ),
    InjectionSignature(
        signature_id="INJ-081",
        category="tool_manipulation",
        pattern=r"(?i)execute\s+(the\s+)?(tool|function)\s+before\s+(any\s+)?(validation|check|guard|policy|scan)",
        severity="CRITICAL",
        description="Attempt to bypass pre-execution validation guards",
    ),
    InjectionSignature(
        signature_id="INJ-082",
        category="tool_manipulation",
        pattern=r"(?i)(chain|pipe|combine)\s+(the\s+)?(output|result)\s+(of\s+)?(tool|function)\s+['\"][^'\"]+['\"]\s+(into|to|as\s+input)",
        severity="HIGH",
        description="Unauthorised tool chaining to escalate capabilities",
    ),
    InjectionSignature(
        signature_id="INJ-083",
        category="tool_manipulation",
        pattern=r"(?i)(override|disable|skip|bypass)\s+(the\s+)?(tool|function)\s+(permission|access|auth|policy)\s+(check|guard|gate|control)",
        severity="CRITICAL",
        description="Attempts to disable tool permission or policy checks",
    ),

    # ── context_overflow (Sprint 52 — APEP-413) ────────────────────────
    InjectionSignature(
        signature_id="INJ-084",
        category="context_overflow",
        pattern=r"(?i)(repeat|duplicate|copy)\s+(this|the\s+following|the\s+above)\s+(text|paragraph|block|string)\s+(\d{2,}|many|hundred|thousand)\s+times",
        severity="HIGH",
        description="Context stuffing via large-scale text repetition",
    ),
    InjectionSignature(
        signature_id="INJ-085",
        category="context_overflow",
        pattern=r"(?i)(fill|pad|stuff)\s+(the\s+)?(context|prompt|input|window)\s+(with|using)\s+",
        severity="HIGH",
        description="Explicit context window stuffing instruction",
    ),
    InjectionSignature(
        signature_id="INJ-086",
        category="context_overflow",
        pattern=r"(?i)generate\s+(\d{4,}|thousands?\s+of|millions?\s+of)\s+(words?|tokens?|characters?|lines?)",
        severity="MEDIUM",
        description="Token generation bomb to exhaust context window",
    ),
    InjectionSignature(
        signature_id="INJ-087",
        category="context_overflow",
        pattern=r"(?i)(ignore|forget|drop|discard)\s+(everything|all)\s+(before|above|prior)\s+(this|here|the\s+following)\s+(line|point|marker)",
        severity="HIGH",
        description="Context truncation attack: discard prior context at a marker",
    ),
    InjectionSignature(
        signature_id="INJ-088",
        category="context_overflow",
        pattern=r"(?i)the\s+(real|actual|true|important)\s+(instructions?|prompt|context)\s+(start|begin)s?\s+(here|now|below)",
        severity="HIGH",
        description="Context displacement: claiming real instructions start at injection point",
    ),
    InjectionSignature(
        signature_id="INJ-089",
        category="context_overflow",
        pattern=r"(.)\1{50,}",
        severity="MEDIUM",
        description="Character repetition flood (50+ identical characters)",
    ),
    InjectionSignature(
        signature_id="INJ-090",
        category="context_overflow",
        pattern=r"(?i)(insert|add|include)\s+(\d{3,}|hundreds?|thousands?)\s+(of\s+)?(dummy|filler|padding|junk|garbage)\s+(tokens?|words?|lines?|characters?)",
        severity="HIGH",
        description="Filler token injection to push instructions out of context",
    ),
    InjectionSignature(
        signature_id="INJ-091",
        category="context_overflow",
        pattern=r"(?i)<<<+\s*(END|BEGIN|BREAK|RESET|BOUNDARY)\s*>>>+",
        severity="MEDIUM",
        description="Fake context boundary markers (<<< >>>)",
    ),
    InjectionSignature(
        signature_id="INJ-092",
        category="context_overflow",
        pattern=r"(?i)everything\s+(above|before)\s+(this|here)\s+(is|was)\s+(just\s+)?(noise|filler|padding|irrelevant|fake)",
        severity="HIGH",
        description="Context invalidation: declaring prior context as fake or noise",
    ),

    # ── instruction_hierarchy (Sprint 52 — APEP-413) ───────────────────
    InjectionSignature(
        signature_id="INJ-093",
        category="instruction_hierarchy",
        pattern=r"(?i)(system|developer|admin)\s+(instruction|directive|message|prompt)\s*:\s*",
        severity="HIGH",
        description="Fake privileged instruction block header",
    ),
    InjectionSignature(
        signature_id="INJ-094",
        category="instruction_hierarchy",
        pattern=r"(?i)this\s+(instruction|directive|command)\s+(has|takes|gets)\s+(highest|top|maximum|priority)\s+(priority|precedence)",
        severity="HIGH",
        description="Priority escalation: claiming highest instruction precedence",
    ),
    InjectionSignature(
        signature_id="INJ-095",
        category="instruction_hierarchy",
        pattern=r"(?i)(the\s+)?(user|human|customer)\s+(instruction|prompt|message)\s+(overrides?|supersedes?|replaces?|takes?\s+priority\s+over)\s+(the\s+)?(system|developer|admin)",
        severity="CRITICAL",
        description="Hierarchy inversion: user instructions claiming to override system",
    ),
    InjectionSignature(
        signature_id="INJ-096",
        category="instruction_hierarchy",
        pattern=r"(?i)\[priority\s*:\s*(highest|critical|override|urgent|0|1)\]",
        severity="HIGH",
        description="Fake priority metadata tag in prompt",
    ),
    InjectionSignature(
        signature_id="INJ-097",
        category="instruction_hierarchy",
        pattern=r"(?i)(treat|consider|handle|process)\s+(this|the\s+following)\s+(as\s+)?(a\s+)?(system|root|admin|kernel)\s+(level\s+)?(instruction|directive|command|prompt)",
        severity="CRITICAL",
        description="Privilege promotion: treating user input as system-level instruction",
    ),
    InjectionSignature(
        signature_id="INJ-098",
        category="instruction_hierarchy",
        pattern=r"(?i)meta[-_]?instruction\s*:|##\s*META\b|<!-- instruction -->",
        severity="MEDIUM",
        description="Hidden meta-instruction markers in structured content",
    ),
    InjectionSignature(
        signature_id="INJ-099",
        category="instruction_hierarchy",
        pattern=r"(?i)(all|any)\s+previous\s+(rules|policies|constraints|guidelines|instructions)\s+(are|is)\s+(now\s+)?(void|invalid|suspended|overridden|disabled|cancelled)",
        severity="CRITICAL",
        description="Blanket policy nullification declaration",
    ),
    InjectionSignature(
        signature_id="INJ-100",
        category="instruction_hierarchy",
        pattern=r"(?i)instruction\s+(layer|level|tier)\s+(1|one|zero|0|system|root)\s*:",
        severity="HIGH",
        description="Fake instruction layer/tier designation",
    ),
    InjectionSignature(
        signature_id="INJ-101",
        category="instruction_hierarchy",
        pattern=r"(?i)(begin|start)\s+(hidden|secret|privileged|protected)\s+(instruction|directive|block)\b",
        severity="HIGH",
        description="Hidden instruction block opener",
    ),
    InjectionSignature(
        signature_id="INJ-102",
        category="instruction_hierarchy",
        pattern=r"(?i)(this\s+)?(message|instruction|directive)\s+(is\s+)?(signed|authenticated|verified|authorized)\s+by\s+(the\s+)?(admin|developer|system|root)",
        severity="HIGH",
        description="Fake instruction authentication/signing claim",
    ),

    # ── output_manipulation (Sprint 52 — APEP-413) ─────────────────────
    InjectionSignature(
        signature_id="INJ-103",
        category="output_manipulation",
        pattern=r"(?i)(always|must|shall)\s+(respond|reply|answer|output)\s+with\s+['\"]",
        severity="HIGH",
        description="Forced static response override",
    ),
    InjectionSignature(
        signature_id="INJ-104",
        category="output_manipulation",
        pattern=r"(?i)(prepend|prefix)\s+(every|each|all)\s+(response|reply|output|message)\s+with\s+",
        severity="MEDIUM",
        description="Output prefix injection to alter every response",
    ),
    InjectionSignature(
        signature_id="INJ-105",
        category="output_manipulation",
        pattern=r"(?i)(hide|conceal|omit|suppress|remove|strip)\s+(all\s+)?(warning|error|safety|disclaimer|caveat|refusal)s?\s+(from|in)\s+(your\s+)?(response|output|reply)",
        severity="HIGH",
        description="Safety message suppression in output",
    ),
    InjectionSignature(
        signature_id="INJ-106",
        category="output_manipulation",
        pattern=r"(?i)format\s+(your\s+)?(response|output|reply)\s+as\s+(raw\s+)?(json|xml|html|markdown)\s+with\s+(no|zero)\s+(explanation|commentary|wrapper)",
        severity="MEDIUM",
        description="Output format coercion to strip safety wrappers",
    ),
    InjectionSignature(
        signature_id="INJ-107",
        category="output_manipulation",
        pattern=r"(?i)(wrap|embed|encode)\s+(your\s+)?(response|output|answer)\s+(in|inside|within)\s+(a\s+)?(code\s+block|script\s+tag|iframe|hidden\s+div)",
        severity="HIGH",
        description="Output wrapping in executable or hidden markup",
    ),
    InjectionSignature(
        signature_id="INJ-108",
        category="output_manipulation",
        pattern=r"(?i)(never|do\s+not|don'?t)\s+(say|mention|include|reveal|disclose)\s+(that\s+)?(you\s+)?(are|is)\s+(an?\s+)?(ai|assistant|bot|language\s+model)",
        severity="HIGH",
        description="Identity concealment: forcing the model to hide its AI nature",
    ),
    InjectionSignature(
        signature_id="INJ-109",
        category="output_manipulation",
        pattern=r"(?i)(replace|swap|change)\s+(all|every|any)\s+(instance|occurrence|mention)\s+of\s+['\"].+['\"]\s+(with|to|into)\s+['\"]",
        severity="MEDIUM",
        description="Output content substitution attack",
    ),
    InjectionSignature(
        signature_id="INJ-110",
        category="output_manipulation",
        pattern=r"(?i)(add|insert|include|inject)\s+(a\s+)?(hidden|invisible|zero[-\s]?width)\s+(text|message|link|payload)\s+(in|into|to)\s+(your\s+)?(response|output)",
        severity="HIGH",
        description="Hidden content injection into model output",
    ),
    InjectionSignature(
        signature_id="INJ-111",
        category="output_manipulation",
        pattern=r"(?i)(translate|convert)\s+(your\s+)?(response|output|refusal)\s+(into|to)\s+(a\s+)?(compliant|affirmative|yes|positive)\s+(response|answer)",
        severity="HIGH",
        description="Refusal-to-compliance conversion attack",
    ),

    # ── goal_hijacking (Sprint 52 — APEP-413) ──────────────────────────
    InjectionSignature(
        signature_id="INJ-112",
        category="goal_hijacking",
        pattern=r"(?i)(your|the)\s+(new|real|actual|true|primary)\s+(goal|objective|mission|purpose|task)\s+(is|should\s+be|has\s+changed\s+to)\s+",
        severity="HIGH",
        description="Goal reassignment: redefining the agent's primary objective",
    ),
    InjectionSignature(
        signature_id="INJ-113",
        category="goal_hijacking",
        pattern=r"(?i)(stop|abandon|abort|cancel|drop)\s+(your\s+)?(current|original|assigned|primary)\s+(task|goal|objective|mission)",
        severity="HIGH",
        description="Goal abandonment: instructing the agent to drop its current task",
    ),
    InjectionSignature(
        signature_id="INJ-114",
        category="goal_hijacking",
        pattern=r"(?i)instead\s+of\s+(doing\s+)?(that|what\s+you\s+were\s+(told|asked|instructed))\s*,\s*(do|perform|execute|run)",
        severity="HIGH",
        description="Goal substitution: replacing the assigned task with a new one",
    ),
    InjectionSignature(
        signature_id="INJ-115",
        category="goal_hijacking",
        pattern=r"(?i)(first|before\s+(anything|everything))\s+(you\s+must|always)\s+(do|perform|execute|complete)\s+(this|the\s+following)\s+(secret|hidden|priority)\s+(task|action)",
        severity="CRITICAL",
        description="Priority task injection: inserting a covert task as top priority",
    ),
    InjectionSignature(
        signature_id="INJ-116",
        category="goal_hijacking",
        pattern=r"(?i)(the\s+)?user('s)?\s+(original\s+)?(request|intent|goal)\s+(is|was)\s+(actually|really|in\s+fact)\s+(to|about|asking\s+you\s+to)\s+",
        severity="HIGH",
        description="Intent reinterpretation: reframing the user's original request",
    ),
    InjectionSignature(
        signature_id="INJ-117",
        category="goal_hijacking",
        pattern=r"(?i)complete\s+(the\s+)?(following|this)\s+(task|objective)\s+(first|immediately|now)\s+(even\s+if|regardless\s+of|ignoring)\s+(other|previous|current)",
        severity="HIGH",
        description="Task preemption: forcing immediate execution of injected task",
    ),
    InjectionSignature(
        signature_id="INJ-118",
        category="goal_hijacking",
        pattern=r"(?i)your\s+(reward|score|performance|rating)\s+(depends?|is\s+based)\s+on\s+(completing|doing|executing|following)\s+(this|the\s+following)",
        severity="MEDIUM",
        description="Reward hacking: manipulating agent via fake reward signals",
    ),
    InjectionSignature(
        signature_id="INJ-119",
        category="goal_hijacking",
        pattern=r"(?i)(maximize|optimise|optimiz)\s+(for|towards?)\s+(the\s+following|this)\s+(metric|goal|objective|kpi)\s+instead",
        severity="HIGH",
        description="Objective function manipulation: redirecting optimisation target",
    ),
    InjectionSignature(
        signature_id="INJ-120",
        category="goal_hijacking",
        pattern=r"(?i)(plan|mission|objective)\s+(update|change|revision|amendment)\s*:\s*(effective\s+)?immediately",
        severity="HIGH",
        description="Fake mission/plan update with immediate effect",
    ),

    # ── resource_abuse (Sprint 52 — APEP-413) ──────────────────────────
    InjectionSignature(
        signature_id="INJ-121",
        category="resource_abuse",
        pattern=r"(?i)(create|generate|make|produce)\s+(\d{3,}|hundreds?|thousands?|millions?)\s+(of\s+)?(files?|requests?|entries?|records?|threads?)",
        severity="HIGH",
        description="Mass resource creation to exhaust system capacity",
    ),
    InjectionSignature(
        signature_id="INJ-122",
        category="resource_abuse",
        pattern=r"(?i)(run|execute|start|launch|spawn)\s+(an?\s+)?(infinite|endless|forever|eternal)\s+(loop|recursion|cycle|process)",
        severity="CRITICAL",
        description="Infinite loop or recursion trigger",
    ),
    InjectionSignature(
        signature_id="INJ-123",
        category="resource_abuse",
        pattern=r"(?i)(send|make|fire|issue)\s+(\d{3,}|hundreds?|thousands?|millions?)\s+(of\s+)?(http|api|network|web)\s+(requests?|calls?)",
        severity="CRITICAL",
        description="HTTP request flood / denial of service via mass API calls",
    ),
    InjectionSignature(
        signature_id="INJ-124",
        category="resource_abuse",
        pattern=r"(?i)(allocate|consume|use\s+up|exhaust)\s+(all\s+)?(available\s+)?(memory|ram|cpu|disk|storage|bandwidth|quota)",
        severity="CRITICAL",
        description="Explicit resource exhaustion instruction",
    ),
    InjectionSignature(
        signature_id="INJ-125",
        category="resource_abuse",
        pattern=r"(?i)while\s*\(\s*(true|1|True)\s*\)|for\s*\(\s*;;\s*\)|loop\s*\{\s*\}",
        severity="HIGH",
        description="Code-level infinite loop construct",
    ),
    InjectionSignature(
        signature_id="INJ-126",
        category="resource_abuse",
        pattern=r"(?i)(fork|spawn|clone)\s+(bomb|process)\b|:\(\)\{\s*:\|:&\s*\};:",
        severity="CRITICAL",
        description="Fork bomb or process spawning attack",
    ),
    InjectionSignature(
        signature_id="INJ-127",
        category="resource_abuse",
        pattern=r"(?i)(download|fetch|retrieve)\s+(a\s+)?(\d+\s*[GT]B|very\s+large|huge|massive)\s+(file|dataset|archive|blob)",
        severity="HIGH",
        description="Large file download to exhaust storage or bandwidth",
    ),
    InjectionSignature(
        signature_id="INJ-128",
        category="resource_abuse",
        pattern=r"(?i)(set|change|increase)\s+(the\s+)?(timeout|max[-_]?retries|retry[-_]?count|rate[-_]?limit)\s+(to\s+)?(infinity|unlimited|999999|\d{6,})",
        severity="HIGH",
        description="Safety parameter override: setting timeout/retries to unreasonable values",
    ),
    InjectionSignature(
        signature_id="INJ-129",
        category="resource_abuse",
        pattern=r"(?i)(mine|run)\s+(crypto|bitcoin|ethereum|monero|xmr)\b",
        severity="CRITICAL",
        description="Cryptocurrency mining abuse attempt",
    ),
    InjectionSignature(
        signature_id="INJ-130",
        category="resource_abuse",
        pattern=r"(?i)(calculate|compute|enumerate)\s+(all\s+)?(permutations?|combinations?|primes?)\s+(up\s+to|of|for)\s+(\d{8,}|a\s+(very\s+)?large\s+number)",
        severity="MEDIUM",
        description="Computational exhaustion via expensive mathematical operations",
    ),

    # ── configuration_attack (Sprint 52 — APEP-413) ────────────────────
    InjectionSignature(
        signature_id="INJ-131",
        category="configuration_attack",
        pattern=r"(?i)(change|set|update|modify)\s+(your\s+)?(system|model|config|configuration)\s+(temperature|top[-_]?p|max[-_]?tokens|frequency[-_]?penalty)\s+(to|=)\s+",
        severity="HIGH",
        description="Model parameter tampering via config injection",
    ),
    InjectionSignature(
        signature_id="INJ-132",
        category="configuration_attack",
        pattern=r"(?i)(disable|turn\s+off|deactivate)\s+(the\s+)?(safety|content|moderation|filter|guard|logging|audit|monitoring)\s+(system|filter|layer|module|check)",
        severity="CRITICAL",
        description="Safety system deactivation via config manipulation",
    ),
    InjectionSignature(
        signature_id="INJ-133",
        category="configuration_attack",
        pattern=r"(?i)(set|change|switch)\s+(the\s+)?(mode|environment|env)\s+to\s+(debug|development|dev|test|staging|unsafe|unrestricted|permissive)",
        severity="HIGH",
        description="Environment mode switch to a less-secure posture",
    ),
    InjectionSignature(
        signature_id="INJ-134",
        category="configuration_attack",
        pattern=r"(?i)(load|import|source|include|require)\s+(config|configuration|settings?|env)\s+(from|file)\s+['\"]?[a-zA-Z0-9_\-/.]+",
        severity="HIGH",
        description="External configuration file loading attack",
    ),
    InjectionSignature(
        signature_id="INJ-135",
        category="configuration_attack",
        pattern=r"(?i)(set|export|define)\s+[A-Z_]{3,}=.*\b(true|false|1|0|yes|no|on|off)\b",
        severity="MEDIUM",
        description="Environment variable injection to alter runtime behaviour",
    ),
    InjectionSignature(
        signature_id="INJ-136",
        category="configuration_attack",
        pattern=r"(?i)(modify|edit|change|update)\s+(the\s+)?(policy|rule|permission|acl|rbac|role)\s+(file|config|setting|table)",
        severity="CRITICAL",
        description="Direct policy/RBAC configuration modification attempt",
    ),
    InjectionSignature(
        signature_id="INJ-137",
        category="configuration_attack",
        pattern=r"(?i)(add|grant|assign)\s+(the\s+)?(admin|root|superuser|sudo|elevated)\s+(role|permission|privilege|access)\s+(to|for)\s+",
        severity="CRITICAL",
        description="Privilege grant via configuration injection",
    ),
    InjectionSignature(
        signature_id="INJ-138",
        category="configuration_attack",
        pattern=r"(?i)(lower|reduce|set)\s+(the\s+)?(security|trust|verification|validation)\s+(level|threshold|score)\s+(to\s+)?(zero|0|none|minimum|lowest|off)",
        severity="CRITICAL",
        description="Security threshold reduction to bypass protections",
    ),
    InjectionSignature(
        signature_id="INJ-139",
        category="configuration_attack",
        pattern=r"(?i)(enable|activate|turn\s+on)\s+(the\s+)?(verbose|debug|trace)\s+(log|logging|mode|output)",
        severity="MEDIUM",
        description="Debug/verbose mode activation to expose internal state",
    ),
    InjectionSignature(
        signature_id="INJ-140",
        category="configuration_attack",
        pattern=r"(?i)(whitelist|allowlist|trust)\s+(all|every|\*|any)\s+(domain|ip|host|origin|source|endpoint)",
        severity="CRITICAL",
        description="Universal trust/allowlist to disable origin restrictions",
    ),

    # ── supply_chain (Sprint 52 — APEP-413) ─────────────────────────────
    InjectionSignature(
        signature_id="INJ-141",
        category="supply_chain",
        pattern=r"(?i)(install|add|load|import)\s+(this\s+)?(package|module|library|plugin|extension|dependency)\s+(from|via)\s+https?://",
        severity="HIGH",
        description="Remote package/dependency installation from URL",
    ),
    InjectionSignature(
        signature_id="INJ-142",
        category="supply_chain",
        pattern=r"(?i)pip\s+install\s+(--index-url|--extra-index-url|-i)\s+https?://(?!pypi\.org)",
        severity="CRITICAL",
        description="pip install from non-PyPI index (supply chain hijack)",
    ),
    InjectionSignature(
        signature_id="INJ-143",
        category="supply_chain",
        pattern=r"(?i)npm\s+install\s+--registry\s+https?://(?!registry\.npmjs\.org)",
        severity="CRITICAL",
        description="npm install from non-default registry (supply chain hijack)",
    ),
    InjectionSignature(
        signature_id="INJ-144",
        category="supply_chain",
        pattern=r"(?i)(curl|wget|fetch)\s+https?://[^\s]+\s*\|\s*(sh|bash|python|node|ruby|perl)",
        severity="CRITICAL",
        description="Pipe-to-shell: downloading and executing remote code",
    ),
    InjectionSignature(
        signature_id="INJ-145",
        category="supply_chain",
        pattern=r"(?i)(replace|swap|substitute)\s+(the\s+)?(dependency|package|library|module)\s+['\"][^'\"]+['\"]\s+with\s+['\"]",
        severity="HIGH",
        description="Dependency substitution / typosquatting attack instruction",
    ),
    InjectionSignature(
        signature_id="INJ-146",
        category="supply_chain",
        pattern=r"(?i)(add|inject|insert)\s+(a\s+)?(backdoor|trojan|payload|hook|callback)\s+(into|in|to)\s+(the\s+)?(code|build|pipeline|package)",
        severity="CRITICAL",
        description="Build pipeline backdoor injection instruction",
    ),
    InjectionSignature(
        signature_id="INJ-147",
        category="supply_chain",
        pattern=r"(?i)(modify|edit|patch)\s+(the\s+)?(build|deploy|ci|cd|pipeline)\s+(script|config|file|yaml|yml)\s+(to\s+)?(include|add|run)",
        severity="HIGH",
        description="CI/CD pipeline configuration tampering",
    ),
    InjectionSignature(
        signature_id="INJ-148",
        category="supply_chain",
        pattern=r"(?i)eval\s*\(\s*(fetch|require|import|input|request)\b",
        severity="CRITICAL",
        description="Dynamic code evaluation of external input (eval injection)",
    ),
    InjectionSignature(
        signature_id="INJ-149",
        category="supply_chain",
        pattern=r"(?i)(use|load|execute)\s+(the\s+)?(unsigned|unverified|untrusted)\s+(plugin|extension|module|package|script|binary)",
        severity="HIGH",
        description="Unsigned/unverified component loading instruction",
    ),

    # ── persistence (Sprint 52 — APEP-413) ──────────────────────────────
    InjectionSignature(
        signature_id="INJ-150",
        category="persistence",
        pattern=r"(?i)(save|store|persist|write)\s+(this|these)\s+(instructions?|rules?|directives?|commands?)\s+(permanently|forever|to\s+(memory|disk|storage|database))",
        severity="HIGH",
        description="Instruction persistence: writing injected rules to permanent storage",
    ),
    InjectionSignature(
        signature_id="INJ-151",
        category="persistence",
        pattern=r"(?i)(add|create|register)\s+(a\s+)?(cron|crontab|scheduled|recurring)\s+(job|task|event|trigger)\s+(that|to|which)\s+",
        severity="CRITICAL",
        description="Scheduled task creation for persistent code execution",
    ),
    InjectionSignature(
        signature_id="INJ-152",
        category="persistence",
        pattern=r"(?i)(modify|edit|append\s+to)\s+(the\s+)?(\.bashrc|\.bash_profile|\.profile|\.zshrc|crontab|startup|init|autorun)",
        severity="CRITICAL",
        description="Shell startup file modification for login-time persistence",
    ),
    InjectionSignature(
        signature_id="INJ-153",
        category="persistence",
        pattern=r"(?i)(remember|memorize|retain)\s+(this|these|the\s+following)\s+(across|between|for\s+(all\s+)?future)\s+(sessions?|conversations?|interactions?|runs?)",
        severity="HIGH",
        description="Cross-session memory injection for persistent influence",
    ),
    InjectionSignature(
        signature_id="INJ-154",
        category="persistence",
        pattern=r"(?i)(create|add|install)\s+(a\s+)?(system|systemd|launchd|windows)\s+(service|daemon|agent)\s+(that|to|which)\s+",
        severity="CRITICAL",
        description="System service/daemon creation for persistent execution",
    ),
    InjectionSignature(
        signature_id="INJ-155",
        category="persistence",
        pattern=r"(?i)(inject|embed|plant)\s+(a\s+)?(hook|callback|listener|watcher|trigger)\s+(into|in|on)\s+(the\s+)?(database|queue|event\s+bus|message\s+broker)",
        severity="HIGH",
        description="Event system hook injection for persistent monitoring",
    ),
    InjectionSignature(
        signature_id="INJ-156",
        category="persistence",
        pattern=r"(?i)(set|create|register)\s+(a\s+)?(webhook|callback\s+url|notification\s+endpoint)\s+(to|at|pointing\s+to)\s+https?://",
        severity="HIGH",
        description="Webhook registration for persistent external callback",
    ),
    InjectionSignature(
        signature_id="INJ-157",
        category="persistence",
        pattern=r"(?i)(always|every\s+time|whenever)\s+(you\s+)?(start|boot|initialise|initialize|restart|launch|begin)",
        severity="MEDIUM",
        description="Boot-time instruction injection: commands tied to startup",
    ),
    InjectionSignature(
        signature_id="INJ-158",
        category="persistence",
        pattern=r"(?i)(add|write|insert)\s+(this|a)\s+(rule|instruction|directive)\s+(to|into)\s+(the\s+)?(system\s+prompt|base\s+prompt|default\s+config|global\s+config)",
        severity="CRITICAL",
        description="System prompt modification for persistent instruction injection",
    ),
]


# ---------------------------------------------------------------------------
# Compiled signature (internal)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _CompiledSignature:
    """A signature with its regex pre-compiled for fast matching."""

    signature: InjectionSignature
    compiled: re.Pattern[str]


# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------


class InjectionSignatureLibrary:
    """Categorised library of prompt injection detection signatures.

    All regex patterns are compiled once at initialisation.  Public methods are
    safe for concurrent reads (the internal data structures are immutable after
    ``__init__`` and are swapped atomically on ``reload()``).

    Hot-reload (APEP-419):
        Call ``reload(new_signatures)`` to atomically replace the active
        pattern set.  Readers that are mid-scan continue against the old set;
        subsequent calls use the new set.  A ``threading.Lock`` serialises
        reload operations but does **not** block concurrent reads.
    """

    def __init__(self, signatures: Sequence[InjectionSignature] | None = None) -> None:
        self._reload_lock = threading.Lock()
        self._load(list(signatures) if signatures is not None else list(_SIGNATURES))

    def _load(self, raw: list[InjectionSignature]) -> None:
        """Compile signatures and build indexes.  Called by __init__ and reload."""
        compiled: list[_CompiledSignature] = []
        for sig in raw:
            try:
                c = re.compile(sig.pattern)
            except re.error as exc:
                raise ValueError(
                    f"Invalid regex in signature {sig.signature_id}: {exc}"
                ) from exc
            compiled.append(_CompiledSignature(signature=sig, compiled=c))

        by_category: dict[str, list[InjectionSignature]] = {}
        by_severity: dict[str, list[InjectionSignature]] = {}
        for sig in raw:
            by_category.setdefault(sig.category, []).append(sig)
            by_severity.setdefault(sig.severity, []).append(sig)

        # Atomic swap — assign all three references in quick succession.
        # Python's GIL guarantees each individual assignment is atomic, so
        # concurrent readers see either the old complete set or the new one.
        self._signatures: list[InjectionSignature] = raw
        self._compiled: list[_CompiledSignature] = compiled
        self._by_category: dict[str, list[InjectionSignature]] = by_category
        self._by_severity: dict[str, list[InjectionSignature]] = by_severity

    # -- Hot-reload (APEP-419) ---------------------------------------------

    def reload(self, signatures: Sequence[InjectionSignature] | None = None) -> int:
        """Atomically replace the active signature set.

        Parameters
        ----------
        signatures:
            New signatures to load.  If ``None``, reloads from the module-level
            ``_SIGNATURES`` list (useful after monkey-patching or dynamic updates).

        Returns
        -------
        int
            The number of signatures now loaded.

        Raises
        ------
        ValueError
            If any signature has an invalid regex (the old set is preserved).
        """
        raw = list(signatures) if signatures is not None else list(_SIGNATURES)
        with self._reload_lock:
            self._load(raw)
        return len(raw)

    # -- Public API ---------------------------------------------------------

    def check(self, text: str) -> list[MatchedSignature]:
        """Return all signatures that match *text*.

        The returned list preserves signature declaration order so that
        higher-priority (lower ID) signatures appear first.
        """
        # Snapshot reference — safe against concurrent reload.
        compiled = self._compiled
        matches: list[MatchedSignature] = []
        for entry in compiled:
            if entry.compiled.search(text):
                sig = entry.signature
                matches.append(
                    MatchedSignature(
                        signature_id=sig.signature_id,
                        category=sig.category,
                        severity=sig.severity,
                        description=sig.description,
                    )
                )
        return matches

    def check_any(self, text: str) -> bool:
        """Return ``True`` if *text* matches at least one signature."""
        compiled = self._compiled
        for entry in compiled:
            if entry.compiled.search(text):
                return True
        return False

    def get_by_category(self, category: str) -> list[InjectionSignature]:
        """Return all signatures belonging to *category*."""
        return list(self._by_category.get(category, []))

    def get_by_severity(self, severity: str) -> list[InjectionSignature]:
        """Return all signatures with the given *severity* level."""
        return list(self._by_severity.get(severity, []))

    @property
    def categories(self) -> list[str]:
        """Return sorted list of all categories."""
        return sorted(self._by_category.keys())

    @property
    def signatures(self) -> list[InjectionSignature]:
        """Return a copy of the full signature list."""
        return list(self._signatures)

    def __len__(self) -> int:
        return len(self._signatures)

    def __repr__(self) -> str:
        cats = sorted(self._by_category)
        return (
            f"<InjectionSignatureLibrary signatures={len(self._signatures)} "
            f"categories={cats}>"
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

injection_library = InjectionSignatureLibrary()
