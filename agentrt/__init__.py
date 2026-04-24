"""AgentRT — AgentPEP Bypass Regression Test Harness.

Sprint S-E09: AgentRT Integration + Bypass Regression + E2E Validation

AgentRT is the mandatory validation harness for AgentPEP policy bundle releases.
It runs four bypass regression classes against the live enforcement stack and gates
AAPM bundle releases on a passing suite.

Bypass Classes:
    Class 1 — Config Injection (CVE-2025-59536, CVE-2026-21852)
    Class 2 — Complexity Bypass (compound commands, timeout exploitation)
    Class 3 — Reasoning Boundary (action decomposition sequences)
    Class 4 — Hook Gaming (loophole exploitation; pass threshold: 8/10 runs blocked)

Usage::

    cd agentrt/
    pytest -v suites/

CI Gate:
    Integrated as a required check on AAPM policy bundle release PRs.
    A failing suite blocks bundle promotion to the Policy Registry.
"""

__version__ = "0.1.0"
