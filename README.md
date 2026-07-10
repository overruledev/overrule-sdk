<div align="center">
<br />
<br />

<img alt="Overrule" src=".github/assets/logo.svg" width="240">

<br />
<br />

### Don't ship AI you can't govern.

Runtime policy enforcement for LLM applications.<br/>
One SDK. Every call intercepted. Full audit trail. EU AI Act ready.

<br />

[![PyPI](https://img.shields.io/pypi/v/overrule?style=flat-square&color=6366f1&labelColor=1e1e2e)](https://pypi.org/project/overrule/)
[![Python](https://img.shields.io/pypi/pyversions/overrule?style=flat-square&labelColor=1e1e2e)](https://pypi.org/project/overrule/)
[![Tests](https://img.shields.io/badge/tests-78_passing-10b981?style=flat-square&labelColor=1e1e2e)](#)
[![License](https://img.shields.io/badge/license-MIT-white?style=flat-square&labelColor=1e1e2e)](LICENSE)
[![GitHub](https://img.shields.io/github/stars/overruledev/overrule-python?style=flat-square&labelColor=1e1e2e)](https://github.com/overruledev/overrule-python)

<br />

[Get Started](#get-started) &nbsp;&nbsp;|&nbsp;&nbsp; [Why Overrule](#why) &nbsp;&nbsp;|&nbsp;&nbsp; [Docs](https://overrule.dev/docs) &nbsp;&nbsp;|&nbsp;&nbsp; [Website](https://overrule.dev)

<br />
<br />

</div>

## Get Started

```bash
pip install overrule[openai]        # OpenAI only
pip install overrule[anthropic]     # Anthropic only
pip install overrule[all]           # Both providers
```

```python
from overrule import Guard

async with Guard() as guard:
    response = await guard.chat(
        model="gpt-4o",
        messages=[{"role": "user", "content": user_input}],
        policies=["pii-detection", "injection-detection"],
    )
```

That's it. Every call is now scanned for PII and injection attacks, violations are blocked before reaching users, and a structured event is shipped to your audit trail.

<br />

## Why

<table>
<tr>
<td width="50%">

**Without Overrule**
```
❌  PII leaks to model providers
❌  No record of what AI decided
❌  Injection attacks reach production
❌  "Trust us" during compliance audits
❌  Governance = a Notion doc
```

</td>
<td width="50%">

**With Overrule**
```
✓  PII intercepted at runtime
✓  Every interaction logged + auditable
✓  8 injection patterns blocked
✓  Structured proof for regulators
✓  Governance = enforced code
```

</td>
</tr>
</table>

<br />

## How It Works

```
Your App ──▶ Guard ──▶ Policy Engine ──▶ LLM Provider
                            │                   │
                            │                   ▼
                        BLOCK / LOG        Response
                            │                   │
                            ▼                   ▼
                     Violation raised     Event shipped (async)
                                                │
                                                ▼
                                        Cloud Dashboard
```

> **Zero latency on the hot path.** Policies evaluate locally in <1ms. Telemetry ships asynchronously in the background. Your application never waits on governance.

<br />

## Features

**Governance**
- Intercept + evaluate every LLM input and output
- Block, log, or pass based on policy outcome
- Structured violation events with full context

**Policies**
- `pii-detection` — credit cards, SSN, email, phone, IBAN, passport, IPv4
- `injection-detection` — 8 prompt injection + 5 SQL injection patterns
- Custom policies via `BasePolicy` — ship your own in minutes

**Production-grade resilience**
- Fail-open by default — SDK errors never crash your application
- Circuit breaker (opens after 5 failures, 30s cooldown)
- Bounded buffer (10K events max), graceful shutdown flush
- Exponential backoff with jitter on transport failures

**Compliance**
- Maps directly to EU AI Act Articles 13, 14, 15
- Exportable telemetry for auditors
- Enforcement begins August 2, 2026 — fines up to €35M / 7% revenue

<br />

## More Examples

<details>
<summary><strong>Protect any function with a decorator</strong></summary>

```python
from overrule import Guard, PolicyAction

guard = Guard()

@guard.protect(policies=["injection-detection"], action=PolicyAction.BLOCK)
async def query_database(sql: str) -> str:
    return await db.execute(sql)
```

</details>

<details>
<summary><strong>Synchronous API</strong></summary>

```python
from overrule import SyncGuard

with SyncGuard() as guard:
    response = guard.chat(model="gpt-4o", messages=messages)
```

</details>

<details>
<summary><strong>Standalone evaluation (no LLM call)</strong></summary>

```python
result = await guard.evaluate("My SSN is 123-45-6789", policies=["pii-detection"])

result.passed       # False
result.violations   # [Violation(policy_id="pii-detection", pattern="ssn", ...)]
```

</details>

<details>
<summary><strong>Multi-provider support</strong></summary>

```python
# OpenAI
await guard.chat(model="gpt-4o", messages=[...], provider="openai")

# Anthropic
await guard.chat(model="claude-sonnet-4-20250514", messages=[...], provider="anthropic")
```

Same governance. Same audit trail. Swap providers without touching policy logic.

</details>

<details>
<summary><strong>Custom policy</strong></summary>

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

</details>

<details>
<summary><strong>Configuration</strong></summary>

```bash
OVERRULE_API_KEY=sk_ovr_xxxxx
OVERRULE_ENDPOINT=https://overrule.dev/api/v1
OVERRULE_ENVIRONMENT=production
OVERRULE_FAIL_OPEN=true
OVERRULE_BATCH_SIZE=50
OVERRULE_FLUSH_INTERVAL=5.0
```

Or programmatic:

```python
guard = Guard(config=GuardConfig.from_env(api_key="sk_ovr_xxxxx", fail_open=True))
```

</details>

<br />

## Performance

| | |
|---|---|
| Policy evaluation | **<1ms** |
| Network calls on hot path | **0** |
| Buffer capacity | **10,000 events** |
| Test suite | **78 tests passing** |
| Python | **3.10 · 3.11 · 3.12 · 3.13 · 3.14** |

<br />

## Security

- API keys are never exposed in `repr()`, `str()`, or serialized output
- PII redaction shows only last 4 characters (no BIN/prefix leakage)
- Content truncation emits a warning when policy evaluation is partial
- Config values are bounds-validated (batch_size, flush_interval, etc.)
- PEP 561 compliant (`py.typed` marker for downstream type checking)
- Fail-open design ensures SDK errors never crash your application

<br />

## Roadmap

- [x] Core Guard with fail-open architecture
- [x] PII + Injection detection policies
- [x] Async + Sync APIs
- [x] Multi-provider (OpenAI + Anthropic)
- [x] Custom policy engine
- [x] Cloud dashboard with real-time enforcement data
- [x] Event ingestion API (`POST /api/v1/events`)
- [ ] Streaming interception
- [ ] LangChain / CrewAI / OpenAI Agents SDK integrations
- [ ] Rust core for <100μs evaluation

<br />

## Development

```bash
git clone https://github.com/overruledev/overrule-python.git && cd overrule-python
pip install -e ".[dev]"
pytest && ruff check . && mypy overrule/
```

<br />

## License

MIT

<br />

<div align="center">

<br />

**[overrule.dev](https://overrule.dev)**

<sub>Built for teams shipping AI to production.</sub>

<br />
<br />

</div>
