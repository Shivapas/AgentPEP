# SDK Quickstart Video — Script & Storyboard (APEP-217)

**Target Duration:** < 10 minutes
**Audience:** Developers integrating AgentPEP into AI agent applications
**Format:** Screen recording with voiceover narration

---

## Scene 1: Introduction (0:00–0:45)

**Visual:** Title card "AgentPEP SDK — 10-Minute Quickstart"

**Narration:**
> Welcome to AgentPEP, the deterministic authorization engine for AI agent
> systems. In the next 10 minutes, you'll go from zero to enforcing real-time
> policies on your AI agent's tool calls.
>
> We'll cover: installing the SDK, connecting to the server, evaluating
> your first tool call, using the @enforce decorator, and testing with
> offline mode.

---

## Scene 2: Start the Server (0:45–1:45)

**Visual:** Terminal — run Docker Compose

```bash
git clone https://github.com/Shivapas/agentpep.git
cd agentpep
docker compose up -d
```

**Narration:**
> First, let's start the AgentPEP server. Clone the repo and run
> docker compose up. This starts the backend API on port 8000,
> the Policy Console on port 5173, and MongoDB.

**Visual:** Browser showing `http://localhost:8000/health` returning `{"status": "ok"}`

> The health endpoint confirms the server is running.

---

## Scene 3: Install the SDK (1:45–2:30)

**Visual:** Terminal — pip install

```bash
pip install agentpep-sdk
```

**Narration:**
> Install the SDK from PyPI. If you use LangChain, add the langchain extra.
> For FastAPI middleware, add the fastapi extra.

**Visual:** Show extras installation

```bash
pip install agentpep-sdk[langchain]
pip install agentpep-sdk[fastapi]
```

---

## Scene 4: First Connection (2:30–3:30)

**Visual:** Python REPL or VS Code

```python
from agentpep import AgentPEPClient

client = AgentPEPClient(base_url="http://localhost:8000")

# Check server health
health = client.health_check_sync()
print(health)
# {'status': 'ok', 'version': '0.1.0'}
```

**Narration:**
> Create an AgentPEPClient pointing to your server. The health_check method
> verifies connectivity before you start making policy calls.

---

## Scene 5: Evaluate a Tool Call (3:30–5:00)

**Visual:** Python script

```python
# Default behavior: deny everything (no rules configured)
response = client.evaluate_sync(
    agent_id="demo-agent",
    tool_name="send_email",
    tool_args={"to": "user@example.com", "subject": "Hello"},
)
print(f"Decision: {response.decision}")  # DENY
print(f"Reason: {response.reason}")       # No matching rule — deny by default
```

**Narration:**
> AgentPEP is deny-by-default. With no rules configured, every tool call
> is denied. This is the safest starting point — you explicitly allow
> what your agents can do.

**Visual:** Add a policy rule via curl

```bash
curl -X POST http://localhost:8000/v1/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "allow-email",
    "agent_role": ["*"],
    "tool_pattern": "send_email",
    "action": "ALLOW",
    "priority": 10
  }'
```

**Visual:** Re-evaluate

```python
response = client.evaluate_sync(
    agent_id="demo-agent",
    tool_name="send_email",
    tool_args={"to": "user@example.com"},
)
print(f"Decision: {response.decision}")  # ALLOW
```

**Narration:**
> After adding an ALLOW rule for send_email, the same call now returns ALLOW.
> That's the core loop: define rules, evaluate tool calls, get decisions.

---

## Scene 6: The @enforce Decorator (5:00–6:30)

**Visual:** Python script

```python
from agentpep import enforce

@enforce(client=client, agent_id="demo-agent")
def send_email(to: str, subject: str, body: str):
    print(f"Sending email to {to}: {subject}")
    return {"status": "sent"}

# This works — policy returns ALLOW
result = send_email("user@example.com", "Hello", "World")
print(result)

# This is blocked — no rule for delete_*
from agentpep.exceptions import PolicyDeniedError

@enforce(client=client, agent_id="demo-agent")
def delete_account(user_id: str):
    print(f"Deleting {user_id}")

try:
    delete_account("user-123")
except PolicyDeniedError as e:
    print(f"Blocked: {e.tool_name} — {e.reason}")
```

**Narration:**
> The @enforce decorator is the easiest way to add policy checks. Wrap any
> function — sync or async — and it automatically evaluates the policy
> before execution. If denied, it raises PolicyDeniedError and the function
> never runs.

---

## Scene 7: Offline Testing (6:30–7:45)

**Visual:** Python script

```python
from agentpep.offline import OfflineEvaluator, OfflineRule
from agentpep.models import PolicyDecision

evaluator = OfflineEvaluator(rules=[
    OfflineRule(tool_pattern="read_*", action=PolicyDecision.ALLOW, priority=10),
    OfflineRule(tool_pattern="write_*", action=PolicyDecision.ALLOW, priority=20),
    OfflineRule(tool_pattern="delete_*", action=PolicyDecision.DENY, priority=5),
    OfflineRule(tool_pattern="*", action=PolicyDecision.DENY, priority=999),
])

# Test without a server
result = evaluator.evaluate(agent_id="test", tool_name="read_file")
print(f"read_file: {result.decision}")  # ALLOW

result = evaluator.evaluate(agent_id="test", tool_name="delete_database")
print(f"delete_database: {result.decision}")  # DENY

# Works with @enforce too
@enforce(evaluator, agent_id="test")
def read_file(path: str) -> str:
    return f"Contents of {path}"

print(read_file("/tmp/test.txt"))
```

**Narration:**
> For testing and development, use the OfflineEvaluator. It evaluates policies
> locally without needing a server. Perfect for unit tests and CI pipelines.

---

## Scene 8: Policy Console (7:45–8:45)

**Visual:** Browser showing Policy Console at `http://localhost:5173`

- Dashboard with live metrics
- Rules page showing configured policies
- Audit log with recent decisions
- UX Survey page

**Narration:**
> The Policy Console gives you a visual overview of your policy engine.
> See real-time metrics on the dashboard, browse your rules, and inspect
> the audit log for every decision AgentPEP has made.

---

## Scene 9: What's Next (8:45–9:30)

**Visual:** Documentation site overview

**Narration:**
> You've just set up AgentPEP, evaluated tool calls, and enforced policies
> with the @enforce decorator. Here's what to explore next:
>
> - LangChain integration for wrapping agent tools
> - LangGraph pre-hooks for graph-based workflows
> - Taint tracking for data provenance
> - Delegation chain validation for multi-agent systems
>
> Check out the documentation at docs.agentpep.io for the full reference.

---

## Scene 10: Closing (9:30–10:00)

**Visual:** Title card with links

**Narration:**
> Thanks for watching! AgentPEP gives you deterministic, auditable control
> over what your AI agents can do. Start with deny-by-default, add the rules
> you need, and let AgentPEP handle enforcement.

**On-screen links:**
- Documentation: docs.agentpep.io
- GitHub: github.com/Shivapas/agentpep
- SDK: pip install agentpep-sdk

---

## Production Notes

- **Recording software:** OBS Studio or ScreenFlow
- **Resolution:** 1920x1080 at 30fps
- **Font size:** Terminal 18pt, editor 16pt for readability
- **Editing:** Cut pauses, add chapter markers for each scene
- **Captions:** Auto-generate via Whisper, review for accuracy
- **Hosting:** Upload to YouTube (unlisted for beta, public for GA)
