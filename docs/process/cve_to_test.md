# CVE-to-Test SLA Process

**Version:** 1.0
**Sprint:** S-E09 (E09-T08)
**Status:** Active
**Owner:** AgentPEP Engineering (TrustFabric)

---

## 1. Purpose

This document defines the process and SLA for translating newly disclosed public
CVEs into AgentRT regression test cases.

**SLA commitment:** New public CVE disclosures affecting AI agent policy bypass
vectors must have a corresponding AgentRT test case added within **14 calendar days**
of the CVE publication date.

The 14-day window applies from the CVE's NVD publish date (or the date AgentPEP
engineering is notified, whichever is earlier).

---

## 2. Scope

This process covers CVEs that are relevant to:

| Category | Example vectors |
|----------|----------------|
| Policy source injection | Config file override, env var hijack, bundle URL redirect |
| Complexity-based bypass | Resource exhaustion, timeout exploitation, nested payload attacks |
| Hook system exploitation | PreToolUse/PostToolUse bypass, hook gaming |
| Trust chain manipulation | Principal chain forgery, delegation depth exploitation |
| Signature/verification bypass | Key substitution, empty signature acceptance, forged bundles |
| Blast radius API attacks | API unavailability exploitation, score manipulation |

CVEs affecting unrelated infrastructure (databases, web frameworks) are out of scope
unless they can be shown to create a policy bypass path.

---

## 3. Roles

| Role | Responsibility |
|------|---------------|
| **AgentPEP Engineering (Shiv)** | Triage CVE, author test case, submit PR, coordinate with AAPM team |
| **TrustFabric Security Architecture** | Notify AgentPEP of relevant CVEs; validate test coverage |
| **AAPM team** | Notify AgentPEP of any CVEs affecting the Policy Registry or Blast Radius API |
| **AgentPEP Engineering** | Block bundle promotion if CVE test case is pending |

---

## 4. Process Steps

### Step 1: Notification (Day 0)

A CVE is considered **notified** when any of the following occurs:

- CVE appears in NVD with a CVSS score affecting an AI agent, policy engine, or hook system component
- TrustFabric Security Architecture emails the AgentPEP distribution list
- A community disclosure (blog post, conference talk, research paper) describes a bypass technique with a CVE reference
- The AAPM team files a dependency ticket

On notification, the assigned engineer opens a tracking issue with the title:
`[CVE-to-Test] CVE-YYYY-NNNNN — <short description>`

### Step 2: Triage (Day 1–2)

The assigned engineer assesses:

1. **Applicability:** Does the CVE affect AgentPEP's enforcement surface?
2. **Bypass class:** Which of the four bypass classes (Class 1–4) does it fall under?
3. **Existing coverage:** Does an existing AgentRT test case already cover this vector?
4. **Mitigation status:** Is the vulnerability already mitigated by an implemented feature?

**Triage outputs:**

| Outcome | Action |
|---------|--------|
| Not applicable | Close tracking issue with rationale |
| Already covered | Link to existing test case; close issue |
| New test required | Proceed to Step 3 |
| New mitigation required | Open feature ticket; add test for the gap; notify AAPM if policy change needed |

### Step 3: Test Case Authoring (Day 2–10)

Author a new test case in the appropriate AgentRT suite:

| Bypass class | Target file |
|-------------|-------------|
| Class 1 — Config Injection | `agentrt/suites/bypass_config_injection.py` |
| Class 2 — Complexity Bypass | `agentrt/suites/bypass_complexity.py` |
| Class 3 — Reasoning Boundary | `agentrt/suites/bypass_reasoning_boundary.py` |
| Class 4 — Hook Gaming | `agentrt/suites/bypass_hook_gaming.py` |

**Test case requirements:**

- Test class name format: `TestCVEYYYYNNNNN<ShortDescription>`
- At minimum one positive test (attack is blocked) and one negative test (legitimate use still works)
- Test docstring must reference the CVE number and vector description
- For Class 4 (non-deterministic): run 10 iterations; assert ≥ 8/10 blocked

Example skeleton:

```python
class TestCVE202599999PolicySourceOverride:
    """AgentRT CVE-2025-99999 — attacker redirects policy source via X-Forwarded-Policy header.

    CVE: CVE-2025-99999
    Class: 1 (Config Injection)
    Bypass vector: HTTP header injection overrides AAPM_REGISTRY_BASE_URL
    Mitigation: FEATURE-02 Trusted Policy Loader (URL allowlist)
    """

    def test_forwarded_policy_header_rejected(self):
        ...

    def test_legitimate_request_without_header_accepted(self):
        ...
```

### Step 4: Validation (Day 10–12)

Run the updated AgentRT suite locally:

```bash
cd agentrt/
pytest -v suites/bypass_<class>.py -k "CVE"
```

Confirm:
- New test passes (attack is blocked)
- No regressions in existing tests

### Step 5: Pull Request (Day 12–13)

Submit a PR to the main branch with:

- New test case in the appropriate suite file
- PR title: `[CVE-to-Test] Add AgentRT test for CVE-YYYY-NNNNN`
- PR description: link to CVE, bypass class, attack vector, and triage outcome

### Step 6: Merge + Bundle Gate (Day 14)

The PR must be merged within the 14-day window. Once merged:

- The new test case is automatically included in all future AgentRT CI runs
- The AAPM bundle release pipeline will fail until the test passes against the candidate bundle
- If the vulnerability requires a policy change, notify AAPM team to update APDL rules

---

## 5. Bundle Promotion Gate

A bundle may **not** be promoted to the AAPM Policy Registry if there is an open
CVE-to-Test ticket (Step 3 in progress) for a CVE that is directly mitigated by
a policy rule in the candidate bundle.

The promotion gate is enforced by:
1. The AgentRT CI job in the AAPM bundle release pipeline (blocks on test failure)
2. A manual check in the AAPM PCR approval workflow (approver must confirm no open CVE-to-Test tickets affecting the bundle)

---

## 6. SLA Metrics and Reporting

| Metric | Target |
|--------|--------|
| CVE-to-Test cycle time | ≤ 14 calendar days from NVD publish |
| Test case coverage rate | 100% of applicable CVEs have a test case |
| False positive rate | < 5% (AgentRT tests that block legitimate tool use) |

The SLA is reviewed at each sprint retrospective. Breaches are logged in the sprint
retrospective note and escalated to TrustFabric Security Architecture if recurrent.

---

## 7. Historical CVE Coverage

| CVE | Bypass Class | AgentRT Test | Added Sprint |
|-----|-------------|-------------|-------------|
| CVE-2025-59536 | Class 1 — Config Injection | `bypass_config_injection.py::TestCI1EnvVarInjection` | S-E03 |
| CVE-2025-59536 | Class 1 — Config Injection | `bypass_config_injection.py::TestCI2UntrustedHostname` | S-E03 |
| CVE-2025-59536 | Class 1 — Config Injection | `bypass_config_injection.py::TestCI3FileSchemeInjection` | S-E03 |
| CVE-2025-59536 | Class 1 — Config Injection | `bypass_config_injection.py::TestCI4PathTraversal` | S-E03 |
| CVE-2025-59536 | Class 1 — Config Injection | `bypass_config_injection.py::TestCI5EmbeddedCredentials` | S-E03 |
| CVE-2025-59536 | Class 1 — Config Injection | `bypass_config_injection.py::TestCI7ForgedSignature` | S-E09 |
| CVE-2026-21852 | Class 1 — Config Injection | `bypass_config_injection.py::TestCI8CompoundAttack` | S-E09 |
| Adversa AI 50-subcommand | Class 2 — Complexity | `bypass_complexity.py::TestCB1PipeChain` | S-E09 |
| PCAS Reasoning Boundary | Class 3 — Reasoning | `bypass_reasoning_boundary.py::TestRB1ReconSequence` | S-E09 |
| Praetorian Hook Gaming | Class 4 — Hook Gaming | `bypass_hook_gaming.py::TestHG1HookInvocationBypass` | S-E09 |

---

## 8. Contacts and Escalation

| Situation | Contact |
|-----------|---------|
| CVE-to-Test SLA at risk | AgentPEP Engineering → TrustFabric Security Architecture |
| CVE requires AAPM policy change | AgentPEP Engineering → AAPM team |
| Test case dispute (false positive) | AgentPEP Engineering + TrustFabric Security Architecture joint review |
| Bundle blocked by CVE gate | AAPM team → AgentPEP Engineering |

---

*Document Owner: TrustFabric Product Architecture*
*Next Review: Sprint S-E10 kickoff*
*Distribution: Internal — AgentPEP Engineering, TrustFabric Security Architecture, AAPM Team*
