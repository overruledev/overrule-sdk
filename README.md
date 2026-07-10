<p align="center">
  <img src="https://img.shields.io/badge/Overrule-Runtime%20AI%20Governance%20SDK-6366f1?style=for-the-badge&logoColor=white" alt="Overrule SDK" />
</p>

<h1 align="center">Overrule</h1>

<p align="center">
  <strong>Don't ship AI you can't govern.</strong>
</p>

<p align="center">
  Runtime policy enforcement for LLM applications — intercept every call, enforce policies, block violations, and ship structured audit events to your cloud dashboard. One SDK. Sub-millisecond. EU AI Act ready.
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#how-it-works">Architecture</a> &bull;
  <a href="#api-reference">API</a> &bull;
  <a href="#performance">Performance</a> &bull;
  <a href="#development">Development</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/overrule/"><img src="https://img.shields.io/pypi/v/overrule?style=flat-square&color=6366f1&labelColor=1e1e2e" /></a>
  <a href="https://pypi.org/project/overrule/"><img src="https://img.shields.io/pypi/pyversions/overrule?style=flat-square&labelColor=1e1e2e" /></a>
  <a href="https://pypi.org/project/overrule/"><img src="https://img.shields.io/pypi/dm/overrule?style=flat-square&labelColor=1e1e2e" /></a>
  <img src="https://img.shields.io/badge/tests-78_passing-10b981?style=flat-square&labelColor=1e1e2e" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-white?style=flat-square&labelColor=1e1e2e" /></a>
  <a href="https://github.com/overruledev/overrule-python"><img src="https://img.shields.io/github/stars/overruledev/overrule-python?style=flat-square&labelColor=1e1e2e" /></a>
</p>

---

## The Problem

Teams shipping AI to production face:

- **No runtime guardrails** — LLM calls go live unchecked, PII leaks to model providers
- **Invisible AI decisions** — no audit trail of what the model said, what policies applied, or what was blocked
- **Injection vulnerabilities** — prompt injection and SQL injection attacks reach production without detection
- **Compliance theater** — PDF policies and Notion docs that don't actually enforce anything at runtime
- **EU AI Act enforcement** — Articles 13/14/15 require runtime logging, human oversight, and accuracy monitoring starting August 2026. Fines up to €35M / 7% revenue.

Existing solutions are either enterprise GRC platforms ($50k+/yr), manual review processes, or non-existent for actual runtime enforcement.

## The Solution

**Overrule** is a Python SDK that wraps any LLM call with policy enforcement, violation detection, and structured audit events — all in under 1 millisecond.

```python
from overrule import Guard

async with Guard() as guard:
    response = await guard.chat(
        model="gpt-4o",
        messages=[{"role": "user", "content": user_input}],
        policies=["pii-detection", "injection-detection"],
    )
```

That's it. Every call is now scanned for PII and injection attacks, violations are blocked before reaching users, and a structured event is shipped to your cloud dashboard.

---

## Features

### For AI Engineers

| Feature | Description |
|---------|-------------|
| **1-Line Integration** | Wrap any LLM call with `guard.chat()`. Works with OpenAI, Anthropic, any provider. |
| **PII Detection** | Credit cards, SSN, email, phone, IBAN, passport, IPv4 — intercepted at runtime |
| **Injection Detection** | 8 prompt injection + 5 SQL injection patterns blocked before they reach the model |
| **Custom Policies** | Extend `BasePolicy` for domain-specific rules (toxicity, bias, topic restriction) |
| **Multi-Provider** | Same governance across OpenAI, Anthropic — swap providers without touching policy logic |
| **Async + Sync** | `Guard` for async, `SyncGuard` for synchronous — same API surface |
| **Decorator API** | `@guard.protect()` for function-level enforcement |
| **Standalone Evaluation** | `guard.evaluate(text)` to scan content without making an LLM call |

### For Platform Teams

| Feature | Description |
|---------|-------------|
| **Fail-Open Architecture** | SDK errors never crash your application. Governance degrades gracefully. |
| **Circuit Breaker** | Opens after 5 consecutive failures, 30s cooldown, automatic recovery |
| **Bounded Buffer** | 10K event max buffer with graceful shutdown flush |
| **Exponential Backoff** | Jittered retry on transport failures — no thundering herd |
| **Zero Hot-Path Latency** | Policies evaluate locally (<1ms). Telemetry ships async in background. |
| **Cloud Event Streaming** | Every governance decision streamed to Overrule dashboard in real-time |
| **Structured Violations** | Severity-tagged (low/medium/high/critical) with full context and direction |
| **Environment Config** | `OVERRULE_API_KEY`, `OVERRULE_ENDPOINT`, `OVERRULE_FAIL_OPEN` — all env-configurable |

### For Compliance

| Feature | Description |
|---------|-------------|
| **EU AI Act Articles 13/14/15** | Maps directly to logging, oversight, and accuracy requirements |
| **Structured Audit Trail** | Every LLM interaction logged with model, provider, tokens, latency, policies, violations |
| **Exportable Telemetry** | Events in structured format for auditors and regulators |
| **Runtime Enforcement** | Governance is code, not a document. Prove to regulators what's actually enforced. |
| **Cloud Dashboard** | Visual overview at [overrule.dev](https://overrule.dev) — posture score, events, policies |

---

## Quickstart

### Installation

```bash
pip install overrule               # Core SDK
pip install overrule[openai]       # + OpenAI provider
pip install overrule[anthropic]    # + Anthropic provider
pip install overrule[all]          # All providers
```

### Configuration

```bash
export OVERRULE_API_KEY=sk_ovr_your_key_here
export OVERRULE_ENDPOINT=https://overrule.dev/api/v1
export OVERRULE_ENVIRONMENT=production
```

Or programmatic:

```python
from overrule import Guard, GuardConfig

guard = Guard(config=GuardConfig.from_env(api_key="sk_ovr_xxxxx", fail_open=True))
```

### Basic Usage

```python
from overrule import Guard

async with Guard() as guard:
    response = await guard.chat(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello, what's the weather?"}],
        policies=["pii-detection", "injection-detection"],
    )
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OVERRULE_API_KEY` | — | Your API key from [overrule.dev](https://overrule.dev) dashboard |
| `OVERRULE_ENDPOINT` | `https://overrule.dev/api/v1` | Cloud endpoint for event ingestion |
| `OVERRULE_ENVIRONMENT` | `production` | Environment tag on events |
| `OVERRULE_FAIL_OPEN` | `true` | If `true`, SDK errors don't crash your app |
| `OVERRULE_BATCH_SIZE` | `50` | Events batched before flush |
| `OVERRULE_FLUSH_INTERVAL` | `5.0` | Seconds between background flushes |

---

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                      Your Application                        │
│                                                              │
│  response = await guard.chat(model=..., policies=[...])     │
└──────────────────────────────┬──────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │    Overrule Guard    │
                    │                     │
                    │  1. Input policies  │
                    │  2. LLM call        │
                    │  3. Output policies │
                    │  4. Event ship      │
                    └──────────┬──────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
┌─────────▼──────┐  ┌─────────▼──────┐  ┌─────────▼──────┐
│  Policy Engine │  │   LLM Provider │  │  Event Buffer  │
│  (local, <1ms) │  │   (OpenAI /    │  │  (async ship   │
│                │  │    Anthropic)  │  │   to cloud)    │
│  PII Detection │  │                │  │                │
│  Injection Det │  │                │  │  10K bounded   │
│  Custom Rules  │  │                │  │  Backoff retry │
└────────────────┘  └────────────────┘  └───────┬────────┘
                                                │
                                     ┌──────────▼──────────┐
                                     │  Overrule Cloud     │
                                     │  POST /api/v1/events│
                                     │                     │
                                     │  Dashboard, Alerts, │
                                     │  Compliance Reports │
                                     └─────────────────────┘
```

**Key design decisions:**

| Decision | Rationale |
|----------|-----------|
| Policies evaluate locally | Zero network latency on the hot path |
| Telemetry ships async | Your app never waits on governance infrastructure |
| Fail-open by default | A governance SDK that crashes your app is worse than no governance |
| Circuit breaker | 5 failures → open → 30s cooldown → half-open → recover |
| Bounded buffer | Memory-safe: drops oldest events at 10K rather than OOM |

---

## API Reference

### Guard

```python
from overrule import Guard, SyncGuard

# Async (recommended)
async with Guard() as guard:
    response = await guard.chat(model, messages, policies)

# Sync
with SyncGuard() as guard:
    response = guard.chat(model, messages, policies)
```

### `guard.chat()`

Intercept an LLM call with policy enforcement.

```python
response = await guard.chat(
    model="gpt-4o",
    messages=[{"role": "user", "content": "..."}],
    policies=["pii-detection", "injection-detection"],
    provider="openai",  # or "anthropic"
)
```

### `guard.evaluate()`

Standalone content evaluation without making an LLM call.

```python
result = await guard.evaluate(
    "My SSN is 123-45-6789",
    policies=["pii-detection"]
)

result.passed       # False
result.violations   # [Violation(policy_id="pii-detection", pattern="ssn", ...)]
```

### `@guard.protect()`

Decorator for function-level enforcement.

```python
from overrule import Guard, PolicyAction

guard = Guard()

@guard.protect(policies=["injection-detection"], action=PolicyAction.BLOCK)
async def query_database(sql: str) -> str:
    return await db.execute(sql)
```

### `guard.register_policy()`

Register custom policies.

```python
from overrule.policies.base import BasePolicy, PolicyResult
from overrule.models.violation import Violation

class TopicRestriction(BasePolicy):
    policy_id = "topic-restriction"

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        if "medical advice" in content.lower():
            return PolicyResult(
                passed=False,
                violations=[Violation(
                    policy_id=self.policy_id,
                    severity="high",
                    description="Medical advice is restricted",
                )],
            )
        return PolicyResult(passed=True, violations=[])

guard.register_policy(TopicRestriction)
```

### Built-in Policies

| Policy ID | What It Detects |
|-----------|-----------------|
| `pii-detection` | Credit cards, SSN, email, phone, IBAN, passport numbers, IPv4 addresses |
| `injection-detection` | 8 prompt injection patterns + 5 SQL injection patterns |

### Policy Actions

| Action | Behavior |
|--------|----------|
| `PolicyAction.BLOCK` | Raise exception, do not execute LLM call |
| `PolicyAction.LOG` | Log violation, continue execution |
| `PolicyAction.PASS` | Record event, no enforcement |

---

## Performance

| Metric | Value |
|--------|-------|
| Policy evaluation | **<1ms** |
| Network calls on hot path | **0** |
| Buffer capacity | **10,000 events** |
| Flush interval | **5s** (configurable) |
| Test suite | **78 tests passing** |
| Python versions | **3.10 · 3.11 · 3.12 · 3.13 · 3.14** |

---

## Security

- API keys never exposed in `repr()`, `str()`, or serialized output
- PII redaction shows only last 4 characters (no BIN/prefix leakage)
- Content truncation emits a warning when policy evaluation is partial
- Config values are bounds-validated (batch_size, flush_interval, etc.)
- PEP 561 compliant (`py.typed` marker for downstream type checking)
- Fail-open design ensures SDK errors never crash your application
- No secrets in logs — all sensitive values masked in debug output

---

## Project Structure

```
overrule-python/
├── overrule/
│   ├── __init__.py              # Public API (Guard, SyncGuard, PolicyAction)
│   ├── guard.py                 # Core Guard class (async context manager)
│   ├── sync_guard.py            # Synchronous Guard wrapper
│   ├── config.py                # GuardConfig (env + programmatic)
│   ├── circuit_breaker.py       # Circuit breaker (closed/open/half-open)
│   ├── buffer.py                # Bounded event buffer (10K max)
│   ├── transport.py             # HTTP transport (backoff, jitter, retry)
│   ├── models/
│   │   ├── event.py             # Structured governance event
│   │   └── violation.py         # Violation model (policy_id, severity, direction)
│   ├── policies/
│   │   ├── base.py              # BasePolicy abstract class
│   │   ├── pii.py               # PII detection (regex-based)
│   │   └── injection.py         # Prompt + SQL injection detection
│   └── providers/
│       ├── openai.py            # OpenAI provider adapter
│       └── anthropic.py         # Anthropic provider adapter
├── tests/                       # 78 tests (pytest)
├── pyproject.toml               # Build config + dependencies
└── LICENSE                      # MIT
```

---

## Compliance Mapping

| EU AI Act Requirement | Overrule Implementation |
|----------------------|------------------------|
| **Art. 13** — Transparency & logging | Every LLM call logged with model, tokens, latency, policies, violations |
| **Art. 14** — Human oversight | Dashboard shows real-time enforcement stream, violation alerts |
| **Art. 15** — Accuracy & robustness | Policy enforcement prevents degraded/adversarial outputs |
| **Audit evidence** | Structured event export for regulators |
| **Enforcement date** | August 2, 2026 — fines up to €35M / 7% global revenue |

---

## Roadmap

- [x] Core Guard with fail-open architecture
- [x] PII detection policy (credit cards, SSN, email, phone, IBAN, passport, IPv4)
- [x] Injection detection policy (8 prompt injection + 5 SQL injection patterns)
- [x] Async + Sync APIs (`Guard` + `SyncGuard`)
- [x] Multi-provider support (OpenAI + Anthropic)
- [x] Custom policy engine (`BasePolicy` interface)
- [x] Decorator API (`@guard.protect()`)
- [x] Standalone evaluation (`guard.evaluate()`)
- [x] Circuit breaker (5 failures → open → 30s cooldown → recovery)
- [x] Bounded event buffer (10K max, graceful shutdown flush)
- [x] Exponential backoff with jitter on transport failures
- [x] Cloud event streaming (`POST /api/v1/events`)
- [x] Environment-based configuration
- [x] Published on PyPI (`pip install overrule`)
- [x] 78-test suite (pytest)
- [x] PEP 561 compliant (`py.typed`)
- [ ] Streaming interception (token-by-token policy evaluation)
- [ ] LangChain integration (`OverruleCallback`)
- [ ] CrewAI integration (agent-level governance)
- [ ] OpenAI Agents SDK wrapper
- [ ] Rust core for <100μs evaluation
- [ ] Output policy enforcement (response scanning)
- [ ] Policy marketplace (community-contributed policies)

---

## Development

```bash
# Clone
git clone https://github.com/overruledev/overrule-python.git
cd overrule-python

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Lint + type check
ruff check .
mypy overrule/
```

---

## Contributing

We're building in public. Contributions welcome.

```bash
# Fork + clone
git clone https://github.com/yourusername/overrule-python.git

# Create feature branch
git checkout -b feature/your-feature

# Make changes, then
pytest                          # Ensure tests pass
ruff check .                    # Lint
mypy overrule/                  # Type check
git commit -m "feat: your feature description"
git push origin feature/your-feature
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Built for teams shipping AI to production.</strong><br/>
  <sub>Overrule — because governance shouldn't slow you down.</sub>
</p>
