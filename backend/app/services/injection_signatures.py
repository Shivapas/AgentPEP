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
    ``__init__``).
    """

    def __init__(self, signatures: Sequence[InjectionSignature] | None = None) -> None:
        raw = list(signatures) if signatures is not None else list(_SIGNATURES)
        self._signatures: list[InjectionSignature] = raw
        self._compiled: list[_CompiledSignature] = []

        for sig in raw:
            try:
                compiled = re.compile(sig.pattern)
            except re.error as exc:
                raise ValueError(
                    f"Invalid regex in signature {sig.signature_id}: {exc}"
                ) from exc
            self._compiled.append(_CompiledSignature(signature=sig, compiled=compiled))

        # Pre-build category and severity indexes for fast lookups.
        self._by_category: dict[str, list[InjectionSignature]] = {}
        self._by_severity: dict[str, list[InjectionSignature]] = {}
        for sig in raw:
            self._by_category.setdefault(sig.category, []).append(sig)
            self._by_severity.setdefault(sig.severity, []).append(sig)

    # -- Public API ---------------------------------------------------------

    def check(self, text: str) -> list[MatchedSignature]:
        """Return all signatures that match *text*.

        The returned list preserves signature declaration order so that
        higher-priority (lower ID) signatures appear first.
        """
        matches: list[MatchedSignature] = []
        for entry in self._compiled:
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
        for entry in self._compiled:
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
