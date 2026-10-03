<p align="center">
  <img src="https://img.shields.io/badge/Overrule-Runtime%20AI%20Governance%20SDK-6366f1?style=for-the-badge&logoColor=white" alt="Overrule SDK" />
</p>

<h1 align="center">Overrule</h1>

<p align="center">
  <strong>Don't ship AI you can't govern.</strong>
</p>

<p align="center">
  Runtime policy enforcement for LLM applications — intercept every call, enforce policies, block violations, and ship structured audit events to your cloud dashboard. One SDK. Sub-millisecond on typical prompts. Built for EU AI Act evidence.
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
  <a href="https://github.com/overruledev/overrule-sdk/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/overruledev/overrule-sdk/ci.yml?branch=main&style=flat-square&label=CI&labelColor=1e1e2e" /></a>
  <a href="https://pypi.org/project/overrule/"><img src="https://img.shields.io/pypi/v/overrule?style=flat-square&color=6366f1&labelColor=1e1e2e" /></a>
  <a href="https://pypi.org/project/overrule/"><img src="https://img.shields.io/pypi/pyversions/overrule?style=flat-square&labelColor=1e1e2e" /></a>
  <a href="https://pypi.org/project/overrule/"><img src="https://img.shields.io/pypi/dm/overrule?style=flat-square&labelColor=1e1e2e" /></a>
  <img src="https://img.shields.io/badge/tests-614_passing-10b981?style=flat-square&labelColor=1e1e2e" />
  <img src="https://img.shields.io/badge/coverage-≥80%25-10b981?style=flat-square&labelColor=1e1e2e" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-white?style=flat-square&labelColor=1e1e2e" /></a>
  <a href="https://github.com/overruledev/overrule-sdk"><img src="https://img.shields.io/github/stars/overruledev/overrule-sdk?style=flat-square&labelColor=1e1e2e" /></a>
</p>

---

## The Problem

Teams shipping AI to production face:

- **No runtime guardrails** — LLM calls go live unchecked, PII leaks to model providers
- **Invisible AI decisions** — no audit trail of what the model said, what policies applied, or what was blocked
- **Injection vulnerabilities** — prompt injection and SQL injection attacks reach production without detection
- **Compliance theater** — PDF policies and Notion docs that don't actually enforce anything at runtime
- **EU AI Act** — Article 50 transparency obligations are in force as of August 2, 2026; the Articles 13/14/15 high-risk obligations for runtime logging, human oversight, and accuracy monitoring follow in December 2027. Fines up to €35M / 7% revenue.

Existing solutions are either enterprise GRC platforms ($50k+/yr), manual review processes, or non-existent for actual runtime enforcement.

## The Solution

**Overrule** is a Python SDK that wraps any LLM call with policy enforcement, violation detection, and structured audit events. Policy evaluation costs about half a millisecond on a typical prompt and never leaves your process.

```python
from overrule import Guard

async with Guard() as guard:
    response = await guard.chat(
        model="gpt-4o",
        messages=[{"role": "user", "content": user_input}],
        policies=["pii-detection", "injection-detection", "toxicity-detection"],
    )
```

Every call is now scanned for PII, injection attacks, and toxic content, and a structured event is shipped to your cloud dashboard. Injection and jailbreak findings raise `ViolationError` before the model is called; PII and toxicity findings are surfaced on `response.violations` unless you opt into `default_action=BLOCK`.

> **What detection can and cannot do.** The built-in policies are regex pattern
> matchers with Unicode normalisation. They are not a complete defence and should
> not be sold internally as one — see
> [Detection Coverage and Known Gaps](#detection-coverage-and-known-gaps).

---

## Features

### For AI Engineers

| Feature | Description |
|---------|-------------|
| **1-Line Integration** | Wrap any LLM call with `guard.chat()`. Works with OpenAI and Anthropic today, more providers coming. |
| **PII Detection** | Credit cards (Luhn + issuer validated), SSN, email, phone, IBAN (mod-97 validated), passport, IPv4, IPv6 — intercepted at runtime. SSN and passport require a nearby context keyword. |
| **Injection Detection** | 8 prompt injection + 5 SQL injection patterns. Both always block, in `chat()`, `stream()`, `protect()` and the LangChain callback. |
| **Jailbreak Detection** | 9 patterns across DAN/STAN personas, developer mode, temporal resets, fictional framing, encoding evasion, semantic inversion, authority challenge, false consensus, token smuggling. Always blocks. |
| **Toxicity Detection** | Profanity, slurs, hate speech, violence incitement — 3 severity tiers. Detect-and-report; does not block on its own. |
| **REDACT Action** | Replace violations in output with `[POLICY_ID]` tokens instead of blocking |
| **Custom Policies** | Extend `BasePolicy` for domain-specific rules (bias, topic restriction, NER) |
| **Multi-Provider** | Same governance across OpenAI and Anthropic — swap providers without touching policy logic |
| **Streaming Governance** | `guard.stream()` — incremental evaluation with a 256-char holdback. Detect-and-report under WARN, not prevent — see [Streaming](#streaming-detect-and-report-not-prevent). |
| **LangChain Integration** | `OverruleCallback` — drop-in governance for any LangChain chain or agent |
| **Async + Sync** | `Guard` for async, `SyncGuard` for synchronous — same API surface |
| **Decorator API** | `@guard.protect()` for function-level enforcement |
| **Standalone Evaluation** | `guard.evaluate(text)` to scan content without making an LLM call. **Check-only — never raises.** |
| **Per-Policy Config** | `GuardConfig.policies` / `PolicyConfig` — enable, disable, override the action, and pass parameters per policy |
| **Policy Hot-Reload** | `guard.reload_policies()` — re-instantiate policies at runtime, picking up changed `PolicyConfig.parameters`, without a restart |

### For Platform Teams

| Feature | Description |
|---------|-------------|
| **Fail-Open Transport** | Telemetry failures never crash your application and never disable enforcement. See [Fail-Open](#fail-open-what-actually-fails-open). |
| **Visible Bypasses** | Fail-open pass-throughs are reported as `EventStatus.FAIL_OPEN`; policies skipped on timeout appear in `metadata["degraded_policies"]` |
| **Circuit Breaker** | Opens after 5 consecutive transient failures, 30s cooldown, automatic recovery. Permanent 4xx responses are recorded without touching it. |
| **Dead-Letter Queue** | Failed events persisted to `.overrule/dead_letter.jsonl` and auto-recovered on next startup. Events the server rejected *permanently* (400/401/403/422) go to `.overrule/rejected.jsonl` instead, which is never recovered — so a bad key or a schema mismatch cannot become a poison pill that is re-POSTed on every restart. |
| **Bounded Buffer** | 10K event max buffer; oldest events are dropped past that — counted in `metrics["events_dropped"]` and `metrics["buffer_overflows"]`, never silently — and anything still buffered at shutdown is dead-lettered |
| **Exponential Backoff** | Jittered retry on transport failures, honouring `Retry-After` — no thundering herd |
| **Non-Blocking Evaluation** | Policies run on a bounded thread pool under a real 5s deadline, so a pathological pattern cannot block your event loop |
| **Minimal Hot-Path Latency** | ~0.5ms for the three default policies on a 1KB prompt, ~45ms on 100KB. Telemetry ships async in the background. |
| **Cloud Event Streaming** | Governance metadata streamed to the Overrule dashboard in real time. Prompts and completions are not transmitted — see [Privacy](#privacy-what-is-and-is-not-transmitted). |
| **Structured Violations** | Severity-tagged (info/low/medium/high/critical) with direction and character offset |
| **Environment Config** | `OVERRULE_API_KEY`, `OVERRULE_ENDPOINT`, `OVERRULE_FAIL_OPEN`, `OVERRULE_ENVIRONMENT`, `OVERRULE_SEND_MATCH_PREVIEW` and more |

### For Compliance

| Feature | Description |
|---------|-------------|
| **EU AI Act Articles 13/14/15** | Produces the runtime logging, oversight and accuracy evidence those articles call for. The SDK is one input to a compliance programme, not a certification. |
| **Structured Audit Trail** | Every LLM interaction logged with metadata (model, provider, tokens, latency, policies, violations, environment). Prompts and completions are not transmitted by default — see [Privacy](#privacy-what-is-and-is-not-transmitted). |
| **Exportable Telemetry** | Metadata + violation fingerprints (`match_len`, `match_sha256`, `match_type`) in structured format for auditors and regulators |
| **Runtime Enforcement** | Governance is code, not a document. Show regulators what is actually enforced — including the `fail_open` events where it was not. |
| **Cloud Dashboard** | Visual overview at [overrule.dev](https://overrule.dev) — posture score, events, policies, billing |

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
export OVERRULE_API_KEY=sk_ovr_your_key_here   # from https://overrule.dev/dashboard
export OPENAI_API_KEY=sk-...                    # your LLM provider key
```

That's all you need. The SDK auto-connects to `https://overrule.dev/api` and streams events to your dashboard.

Or configure programmatically:

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
    # ✓ Policies evaluated locally, in-process (~0.5ms on a 1KB prompt)
    # ✓ Injection and jailbreak attempts blocked (raises ViolationError)
    # ✓ Other violations surfaced in response.violations, call proceeds
    # ✓ Event streamed to dashboard

    if response.flagged:
        print(f"Violations: {response.violations}")
```

### Verify Your Integration

Run this after installing to confirm events reach your dashboard. Note that
`guard.evaluate()` is **check-only** — it returns a result and never raises, even
for violations with `blocked=True`. It is a detector, not an enforcement point.

```python
python -c "
import asyncio
from overrule import Guard

async def verify():
    async with Guard() as guard:
        # 'SSN' here is load-bearing: SSN detection requires a context keyword.
        result = await guard.evaluate('test@email.com SSN 123-45-6789', policies=['pii-detection'])
        print(f'PII detected: {len(result.violations)} violations (evaluate never raises)')
        await guard._reporter._flush()
        print('✓ Events sent — check https://overrule.dev/dashboard')

asyncio.run(verify())
"
```

To verify that enforcement actually fires, use an enforcement entry point:

```python
python -c "
import asyncio
from overrule import Guard, ViolationError

async def verify():
    async with Guard() as guard:
        @guard.protect(policies=['injection-detection'])
        def run_query(sql: str) -> str:
            return 'executed'

        try:
            run_query(\"'; DROP TABLE users; --\")
            print('✗ NOT blocked — this is a bug, please report it')
        except ViolationError as exc:
            print(f'✓ Blocked before execution: {exc}')

asyncio.run(verify())
"
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OVERRULE_API_KEY` | — | Your API key from [overrule.dev](https://overrule.dev) dashboard |
| `OVERRULE_ENDPOINT` | `https://overrule.dev/api` | Cloud endpoint for event ingestion |
| `OVERRULE_ENVIRONMENT` | `production` | Environment tag, sent on every event as `environment` |
| `OVERRULE_FAIL_OPEN` | `true` | If `true`, transport and policy errors degrade rather than raise |
| `OVERRULE_DEFAULT_ACTION` | `warn` | `warn` \| `block` \| `redact` \| `log` |
| `OVERRULE_BATCH_SIZE` | `50` | Events batched before flush (max 100) |
| `OVERRULE_FLUSH_INTERVAL` | `5.0` | Seconds between background flushes |
| `OVERRULE_MAX_CONTENT_LENGTH` | `100000` | Cap on content **stored and reported**. Not a limit on what is scanned. |
| `OVERRULE_SEND_MATCH_PREVIEW` | `false` | Opt in to a shape-only mask of each match. See [Privacy](#privacy-what-is-and-is-not-transmitted). |

### Per-Policy Configuration

`GuardConfig.policies` takes a list of `PolicyConfig` entries. A disabled policy
never runs, `action` overrides the global `default_action` for that policy's
violations, and `parameters` are passed to the policy constructor.

| Field | Effect |
|-------|--------|
| `id` | The `policy_id` this entry applies to |
| `enabled` | `False` stops the policy from running at all |
| `action` | Overrides `default_action` for this policy's violations |
| `parameters` | Passed to the policy constructor |
| `severity_override` | Forces every violation from this policy to a fixed severity (`critical` \| `high` \| `medium` \| `low` \| `info`). The policy's own severity is kept on the violation as `metadata["original_severity"]`. An unrecognised value is rejected at config time. |

```python
from overrule import Guard, GuardConfig, PolicyAction, PolicyConfig

guard = Guard(
    config=GuardConfig.from_env(
        policies=[
            # Turn a default policy off entirely.
            PolicyConfig(id="jailbreak-detection", enabled=False),
            # Hard-block on PII while everything else stays in WARN.
            PolicyConfig(
                id="pii-detection",
                action=PolicyAction.BLOCK,
                parameters={"disabled_patterns": ["ip_address", "ipv6_address"]},
            ),
            PolicyConfig(id="toxicity-detection", parameters={"min_severity": "high"}),
            # Keep the finding, but downgrade it so it stops paging anyone.
            PolicyConfig(
                id="injection-detection",
                severity_override="info",
                parameters={"check_sql_injection": False},
            ),
        ]
    )
)
```

| Policy | Supported `parameters` |
|--------|------------------------|
| `pii-detection` | `disabled_patterns`: list of pattern names to skip (`credit_card`, `ssn`, `email`, `phone_us`, `phone_international`, `ip_address`, `ipv6_address`, `iban`, `passport_us`) |
| `injection-detection` | `check_prompt_injection` (bool, default `True`), `check_sql_injection` (bool, default `True`) |
| `jailbreak-detection` | `min_severity`: `critical` \| `high` \| `medium` \| `low` \| `info` (default `low`, i.e. report everything) |
| `toxicity-detection` | `min_severity` (as above) plus four independent category flags (bools, all default `True`): `check_violence` (CRITICAL — violence, self-harm, dangerous how-tos), `check_slurs` (HIGH — slurs and hate speech), `check_profanity` (HIGH — severe profanity), `check_insults` (LOW — mild insults). Profanity and slurs share the HIGH tier but are gated separately; there is no MEDIUM tier. |

`guard.reload_policies()` drops the cached policy instances so the next
evaluation re-reads `PolicyConfig.parameters` — this is what makes hot-reload
change behaviour rather than just churn objects:

```python
config.policies[0].parameters["min_severity"] = "critical"
guard.reload_policies()  # next evaluation uses the new threshold
```

Scope, precisely — every entry point honours every `PolicyConfig` field:

- `enabled`, `action`, `parameters` and `severity_override` are honoured by
  `guard.chat()`, `guard.evaluate()`, `@guard.protect()` and `SyncGuard`.
- `guard.stream()` honours all four. A disabled policy is dropped even when you
  pass it explicitly as `policies=[...]`, `severity_override` is applied to
  streamed violations, a per-policy `action=BLOCK` stops the stream even when
  `default_action` is only `WARN`/`LOG`, and a REDACT action on an active policy
  raises `ValueError` up front (tokens cannot be recalled once yielded).
- `OverruleCallback` (LangChain) accepts a `config=` argument and honours all four
  through it. Its policies also run on a bounded pool of daemon workers under the
  same 5s deadline, so a pathological policy cannot hang the LangChain thread.
  Passing only `policies=`/`action=` still works and behaves as before.

`REDACT` is applied per policy: a violation is only rewritten if *its own*
effective action is `REDACT`. A policy configured to `LOG` keeps its match intact
even when another policy on the same response asked for redaction.

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
│ (local, ~0.5ms │  │   (OpenAI /    │  │  (async ship   │
│  on 1KB, on a  │  │    Anthropic)  │  │   to cloud)    │
│  thread pool)  │  │                │  │                │
│  PII Detection │  │                │  │  10K bounded   │
│  Injection Det │  │                │  │  Backoff retry │
│  Jailbreak Det │  │                │  │  Dead-letter   │
│  Toxicity Det  │  │                │  │                │
│  Custom Rules  │  │                │  │                │
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
| Policies evaluate locally | Zero network latency on the hot path, and no prompt egress |
| Policies run on a thread pool | A catastrophically backtracking pattern in a custom policy cannot block your event loop, and the 5s deadline is real rather than measured after the fact |
| Telemetry ships async | Your app never waits on governance infrastructure |
| Transport fails open | A governance SDK that crashes your app is worse than no governance — but a telemetry failure must never cancel a block, so enforcement is committed before reporting is attempted |
| Bypasses are events | A `fail_open` status and `degraded_policies` metadata mean "not enforcing" is visible in the audit trail rather than indistinguishable from "nothing to report" |
| Circuit breaker | 5 transient failures → open → 30s cooldown → half-open → recover. Permanent 4xx never opens it. |
| Bounded buffer | Memory-safe: drops the oldest events past 10K rather than OOM. Every such drop is counted in `reporter.metrics["events_dropped"]` and broken out as `buffer_overflows`, with a throttled warning — so buffer loss is observable rather than silent. If `buffer_overflows` is non-zero, lower `flush_interval_seconds`. |

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

### `guard.stream()`

Streaming interception with incremental policy evaluation. **Read
[Streaming](#streaming-detect-and-report-not-prevent) before relying on this for
prevention.**

```python
async with Guard() as guard:
    stream = await guard.stream(
        model="gpt-4o",
        messages=[{"role": "user", "content": "..."}],
        policies=["pii-detection", "toxicity-detection"],
        eval_interval=10,  # evaluate at least every N chunks
    )
    async for chunk in stream:
        print(chunk, end="", flush=True)

    if stream.violations:
        print(f"\n{len(stream.violations)} violation(s) detected")
```

- Input policies are evaluated before the stream is opened; a blocking input
  violation raises `ViolationError` and the provider is never called.
- Output is evaluated on a bounded sliding window every `eval_interval` chunks
  (or sooner if a lot of text is unscanned), plus a final pass over the retained
  content.
- A trailing **256-character holdback** is withheld from the caller until the
  stream ends, so a violation in the final tokens can still be blocked before
  those tokens are emitted.
- `PolicyAction.REDACT` raises `ValueError`. A token cannot be recalled once
  yielded, so redaction cannot be honoured; use `guard.chat()` instead.

### `guard.evaluate()`

Standalone content evaluation without making an LLM call.

**`evaluate()` is check-only. It never raises** — not for `default_action=BLOCK`,
and not for violations carrying `blocked=True`. It returns a `PolicyResult` and
reports an event; deciding what to do about it is yours. The enforcement entry
points are `guard.chat()`, `guard.stream()` and `@guard.protect()`.

```python
result = await guard.evaluate(
    # "SSN" is required here: SSN detection needs a nearby context keyword.
    "My SSN is 123-45-6789",
    policies=["pii-detection"],
    direction="input",  # Literal["input", "output"]
)

result.passed  # False
result.violations  # [Violation(policy_id="pii-detection", ...)]
result.violations[0].metadata["pattern"]  # "ssn"
result.violations[0].blocked  # False — would not have blocked a chat()
```

The whole of `content` is scanned regardless of length;
`max_content_length` only caps how much of it is stored on the reported event.

### `@guard.protect()`

Decorator for function-level enforcement. Arguments are serialized and evaluated
before the function runs. Works on sync and async functions.

```python
from overrule import Guard, PolicyAction

guard = Guard()


@guard.protect(policies=["injection-detection"], action=PolicyAction.BLOCK)
async def query_database(sql: str) -> str:
    return await db.execute(sql)
```

`action=PolicyAction.BLOCK` makes *every* violation block. Without it, violations
carrying `blocked=True` — prompt injection, SQL injection, jailbreak — still
block, and everything else is recorded and allowed through.

### `guard.register_policy()`

Register custom policies.

```python
from overrule.policies.base import BasePolicy, PolicyResult
from overrule.models.violation import Violation, ViolationSeverity


class TopicRestriction(BasePolicy):
    policy_id = "topic-restriction"
    description = "Blocks restricted advice topics"

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        if "medical advice" in content.lower():
            return PolicyResult(
                passed=False,
                violations=[
                    Violation(
                        policy_id=self.policy_id,
                        severity=ViolationSeverity.HIGH,
                        # The field is `message`. There is no `description` field
                        # and no top-level `direction` — put it in metadata.
                        message="Medical advice is restricted",
                        matched_content="medical advice",
                        # Set blocked=True to make this violation block
                        # regardless of the configured action.
                        blocked=False,
                        metadata={
                            "direction": direction,
                            # REDACT and de-duplication use raw_match.
                            "raw_match": "medical advice",
                        },
                    )
                ],
            )
        return PolicyResult(passed=True, violations=[])


guard.register_policy(TopicRestriction)
```

Custom policies run on the same bounded thread pool under the same 5s deadline, so
a slow or backtracking policy degrades itself (recorded in
`metadata["degraded_policies"]`) instead of freezing your event loop.

### Built-in Policies

| Policy ID | What It Detects | Always blocks? | Default? |
|-----------|-----------------|:---:|:---:|
| `pii-detection` | Credit cards, SSN, email, US + international phone, IBAN, US passport, IPv4, IPv6 | No | **Yes** |
| `injection-detection` | 8 prompt injection patterns + 5 SQL injection patterns | **Yes** | **Yes** |
| `jailbreak-detection` | 9 patterns: DAN/STAN/DUDE personas, Developer Mode, temporal reset, fictional framing, encoding evasion, semantic inversion, authority challenge, false consensus, token smuggling | **Yes** | **Yes** |
| `toxicity-detection` | Profanity, slurs, hate speech, violence incitement, dangerous instructions | No | No |

#### PII detection details

| Pattern | Severity | Notes |
|---------|:---:|-------|
| `credit_card` | CRITICAL | 13–19 digits with `-`, space or `.` separators, including the Amex 4-6-5 print format. Validated with **both** Luhn and a known issuer prefix/length: Visa, Mastercard, Amex, Discover, Diners, JCB, UnionPay. An order ID such as `4111-2024-0001-5678` is rejected. |
| `ssn` | CRITICAL | **Requires a nearby context keyword** — `SSN`, `SS#`, `social security`, `socsec`, `tax id`, `taxpayer`, `ITIN`, `TIN` — within 64 characters before or 40 after. Structurally invalid area/group/serial values are rejected. |
| `email` | MEDIUM | |
| `phone_us` | MEDIUM | Space-separated 10-digit runs require phone context (`phone`, `call`, `mobile`, …); parenthesised, punctuated and `+1` forms do not. |
| `phone_international` | MEDIUM | `+CC` prefixed |
| `iban` | HIGH | ISO country code + that country's registered length + ISO 7064 mod-97 checksum. Accepts the space-grouped print format. |
| `passport_us` | HIGH | `letter + 8 digits`, and **requires a nearby context keyword** — `passport`, `travel document`, `document no`, `visa no`, `DOB`, `nationality` — within 30 characters. |
| `ip_address` | LOW | IPv4. Rejected when preceded by version-like context ("upgrade to 10.20.30.40") or followed by a further dot-segment. |
| `ipv6_address` | LOW | Full and compressed forms, validated with the stdlib `ipaddress` module. `::1` and Python slices like `x[::1]` are not matched. |

> **The SSN and passport context requirement is a behaviour change.** It exists
> because bare `NNN-NN-NNNN` and `letter + 8 digits` are shape-identical to
> invoice numbers, part numbers, SKUs and ticket IDs, which produced confirmed
> false positives at critical severity. If you were relying on bare-number
> detection, `123-45-6789` on its own is no longer reported.

### Policy Actions

| Action | Behavior | Default? |
|--------|----------|:---:|
| `PolicyAction.WARN` | Detect violations, surface in `response.violations`, continue execution | **Yes** |
| `PolicyAction.BLOCK` | Raise `ViolationError`, halt execution — LLM never called on input violations | |
| `PolicyAction.REDACT` | Replace matched content with `[POLICY_ID]` tokens in output. Rejected by `guard.stream()`. | |
| `PolicyAction.LOG` | Record the violation to telemetry and continue — **except** for violations carrying `blocked=True` (injection, jailbreak), which raise `ViolationError` under every action including `LOG` | |

**The blocking guarantee, precisely.** A violation with `violation.blocked=True`
raises `ViolationError` regardless of the configured action. The built-in policies
that set it are `injection-detection` (both prompt injection **and** SQL
injection) and `jailbreak-detection`. This holds in:

| Entry point | Blocking violations enforced? |
|-------------|:---:|
| `guard.chat()` (input and output) | Yes |
| `guard.stream()` (input, and output before the holdback is released) | Yes |
| `@guard.protect()` / `SyncGuard.protect()` | Yes |
| `OverruleCallback` (LangChain, `on_llm_start` / `on_llm_end`) | Yes, even though its default action is `LOG` |
| `guard.evaluate()` | **No — check-only, returns a result** |

To block on *all* policy violations, set `default_action=PolicyAction.BLOCK` or a
per-policy `PolicyConfig(action=PolicyAction.BLOCK)`.

### Integrations

#### LangChain

```python
from overrule.integrations import OverruleCallback

callback = OverruleCallback(
    policies=["pii-detection", "injection-detection", "toxicity-detection"],
    action=PolicyAction.BLOCK,
    on_violation=lambda v: alert_team(v),  # optional hook
)

# Drop into any LangChain LLM
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o", callbacks=[callback])
result = llm.invoke("Hello world")  # automatically governed
```

Pass a full `GuardConfig` to use per-policy configuration, exactly as with
`Guard`. Every `PolicyConfig` field — `enabled`, `action`, `parameters`,
`severity_override` — is honoured:

```python
from overrule.models.config import GuardConfig, PolicyConfig

callback = OverruleCallback(
    config=GuardConfig(
        default_action=PolicyAction.LOG,
        policies=[
            # Blocks even though the callback's default action is LOG.
            PolicyConfig(id="pii-detection", action=PolicyAction.BLOCK),
            PolicyConfig(id="toxicity-detection", parameters={"min_severity": "high"}),
            PolicyConfig(id="jailbreak-detection", enabled=False),
        ],
    ),
)
```

Policies run on a bounded pool of daemon workers under the same 5s deadline as
`Guard`, so a slow policy cannot hang the LangChain thread; one that blows its
deadline is skipped and recorded in `metadata["degraded_policies"]`.

---

## Performance

| Metric | Value |
|--------|-------|
| Policy evaluation, 1KB prompt | **~0.5ms** for the three default policies (~0.7ms measured through `Guard`, including thread-pool dispatch) |
| Policy evaluation, 100KB input | **~45ms** for the three default policies |
| Network calls on hot path | **0** |
| Event loop blocking | **None** — policies run on a bounded 4-worker thread pool under a 5s deadline |
| Buffer capacity | **10,000 events** |
| Flush interval | **5s** (configurable) |
| Test suite | **614 tests passing** |
| Python versions | **3.10 · 3.11 · 3.12 · 3.13 · 3.14** declared; **3.10–3.13** exercised in CI |

### Per-policy cost on 100KB

| Policy | Ordinary text | Text containing Cyrillic/Greek confusables |
|--------|:---:|:---:|
| `pii-detection` | 16.0ms | 19.6ms |
| `injection-detection` | 9.6ms | 21.8ms |
| `jailbreak-detection` | 19.9ms | 63.8ms |
| `toxicity-detection` | 9.3ms | — |
| **Three defaults combined** | **~45ms** | **~85ms** |

**Measurement conditions.** CPython 3.10.12, single core, median of 15
repetitions, warm process. Payloads are synthetic English prose. The confusable
column is the honest worst case: when the input contains common Cyrillic or Greek
homoglyphs, an additional normalisation variant is produced and every injection
and jailbreak pattern is run against it as well, roughly doubling the cost. Bare
digit runs and repeated SSN-shaped tokens land between the two columns
(11–23ms per policy). Benchmark your own workload — cost scales with content size
and with how many normalisation variants your text forces.

Prior README versions claimed "<1ms typical" and "~30ms on 100KB". The first is
right in spirit and now stated as a measured number; the second was low.

---

## Security Model

### Enforcement Behavior

Out of the box, Overrule operates in **WARN mode**: violations are detected, logged to telemetry, and surfaced in `response.violations` — but the LLM call proceeds. This lets you integrate safely without breaking existing flows.

**Exception:** violations carrying `blocked=True` always block, regardless of `default_action` — prompt injection, SQL injection, and jailbreak. See [the blocking guarantee table](#policy-actions) for exactly which entry points honour it (all of them except the check-only `guard.evaluate()`).

To enforce hard blocking on all violations:

```python
from overrule import Guard, PolicyAction

guard = Guard(default_action=PolicyAction.BLOCK)
```

### Detection Coverage and Known Gaps

**The built-in policies are pattern matchers. Pattern matching is not a complete
defence, and a governance product that implies otherwise is misleading its
buyers.** Content is NFKC-normalised, invisible and bidi-control characters are
handled in two ways (collapsed to a space and deleted, so both
`Ignore​all​previous` and `Ig​nore all previous` are caught), inter-word
separators are flexible (`Ignore, all previous`, `Ignore-all-previous`), and
common Cyrillic/Greek homoglyphs are folded. That closes the cheap evasions. It
does not close these, all of which were confirmed empirically to still evade
detection:

| Evasion | Status |
|---------|--------|
| Encoded payloads — base64, rot13, hex | **Not detected.** `SWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM=` passes. (Asking the model *to* encode its answer is a separate jailbreak pattern that is detected.) |
| Synonyms and paraphrase | **Not detected.** Only the literal patterns match. |
| Non-English phrasing | **Not detected.** Spanish, German, French and Chinese all tested and all pass. The patterns are English-only. |
| Roleplay / fictional framing beyond the matched patterns | **Partially detected.** The specific "hypothetical scenario", "in a story where" and named-persona constructions match; novel framings do not. |
| Homoglyphs outside the folded set | **Partially detected.** NFKC normalisation handles Unicode *compatibility* variants, so fullwidth (`Ｉｇｎｏｒｅ`) and mathematical alphanumerics (`𝖨gnore`) are caught. The explicit folding table covers the common Cyrillic and Greek confusables that appear in copy-pasted jailbreak prompts. Confusables from other scripts are not — e.g. Armenian `ո` (U+0578) substituted for `n` passes. |
| Semantic intent with no trigger token | **Not detected by design.** |

Treat the built-ins as cheap, deterministic, low-false-positive coverage of known
attack *strings*, and pair them with a semantic layer.
[`examples/llm_content_classifier.py`](examples/llm_content_classifier.py) is a
complete worked example of that layer: a `BasePolicy` that calls an LLM judge, sets
`blocked=True` on the categories you choose, and runs on the same thread pool
under the same deadline as the built-ins.

### Fail-Open: What Actually Fails Open

`fail_open=True` is the default, and the distinction below is the one that matters
if you are evaluating this for a security review.

| Failure | Behaviour with `fail_open=True` |
|---------|---------------------------------|
| **Transport / telemetry** — reporter unreachable, 4xx/5xx, buffer full, event fails to serialize | **Fails open.** The event is retried, dead-lettered, or dropped. **Enforcement still happens**: a detected block is committed *before* reporting is attempted, so a reporter failure can no longer turn a BLOCK into an unguarded pass-through. |
| **One policy times out** (5s deadline) or crashes | That policy is skipped; **every other policy still runs and still enforces**. The skipped policy's ID is appended to `metadata["degraded_policies"]` so the event is not reported as cleanly passed. It no longer raises `PolicyEvaluationError` straight through the fail-open branch, and no longer skips the remaining policies. |
| **Unhandled internal SDK error** in the chat path | Falls back to an unguarded provider call and reports an `EventStatus.FAIL_OPEN` event carrying `fail_open_reason`, `fail_open_detail` and `llm_called`. If the provider had already been called, the existing (already-scanned) response is returned rather than calling — and paying for — it a second time. Anything already detected before the failure is carried on the returned `response.violations` / `response.flagged` **and** on the fail-open event, so a response whose input already contained a card is never reported as clean. |
| **Message content cannot be extracted** from a shape the SDK does not understand | Logged loudly so the gap can be fixed; with `fail_open=False` the call raises instead of being scanned as empty. |

Make bypasses visible in your dashboards by alerting on
`status = "fail_open"` and on any event with a non-empty
`metadata.degraded_policies`. A guard that has silently stopped evaluating
otherwise looks identical to a guard with nothing to report.

For strict enforcement where governance failure = application failure:

```python
guard = Guard(fail_open=False)
```

With `fail_open=False`, a policy timeout raises `PolicyEvaluationError` and an
unextractable message shape raises rather than being scanned as empty.

### Streaming: Detect-and-Report, Not Prevent

`guard.stream()` withholds a trailing **256-character holdback** from the caller
until the stream ends, so a violation found in the final tokens can still be
blocked before they are emitted, and it rejects `PolicyAction.REDACT` outright
(`ValueError`) rather than pretending to redact tokens already sent.

**The fundamental limit remains, and it is not a bug we can fix:** a regex can
only match once the complete pattern has been buffered. Anything already released
past the holdback window has been handed to the caller and cannot be recalled. So
under `WARN` — the default — streaming is **detect-and-report, not prevent**: a
credit card number or SSN emitted early in a long response *will* reach the end
user, and you will find out about it in the audit trail rather than instead of it.

For strict enforcement where no violating content may reach the user, use
non-streaming `guard.chat()` with `default_action=BLOCK`. If you must stream,
`default_action=BLOCK` at least terminates the stream at the first detection, and
injection/jailbreak violations terminate it under any action.

### Content Scanning

Content is scanned in **full**, in overlapping windows of 100,000 characters with a
256-character overlap, so no pattern can straddle a boundary and no region is
skipped. Per-window findings are de-duplicated on
`(policy_id, raw_match, absolute_offset)`.

`max_content_length` (default 100,000) is a cap on how much content is **stored
and reported**, not on what is scanned.

> **Correction.** Through 0.3.0 this section claimed large inputs were sampled
> head/middle/tail and that "the sampling strategy covers all three regions to
> prevent evasion by placing payloads in the center". That was false: sampling
> three fixed windows leaves the gaps between them unscanned — measured, that was
> about half of a 200KB payload and about 90% of a 1MB payload. Fixed in 0.4.0.

### Privacy: What Is and Is Not Transmitted

This section is intended to be precise enough to reference in a DPA. It describes
SDK behaviour at 0.4.0.

**By default, prompts and completions are not transmitted.** Neither
`input_content` nor `output_content` is serialized into the wire payload, and
neither is `violation.metadata` (which holds the full `raw_match` locally). For
each violation the reporter sends:

| Field | Contents |
|-------|----------|
| `policy_id` | e.g. `pii-detection` |
| `severity` | `info` … `critical` |
| `description` | The policy's own message, e.g. `"Social Security Number detected in input"`. For the built-in policies this is a fixed SDK string and never contains customer text. **Custom policies control this field** — do not interpolate prompt content into `Violation.message`. |
| `direction` | `input` or `output` |
| `match_len` | Character length of the matched text |
| `match_sha256` | First 16 hex characters of the SHA-256 of the matched text — a correlation and de-duplication key, not a reversible value |
| `match_type` | The detector sub-rule that fired, e.g. `ssn`, `sql_injection`, `prompt_injection` |

Alongside these, each event carries `id`, `timestamp`, `event_type`, `status`,
`model`, `provider`, `input_tokens`, `output_tokens`, `latency_ms`,
`policies_applied`, `environment`, and your own `metadata` dictionary. **Anything
you put in `metadata` yourself is transmitted verbatim** — do not put prompt text
there.

**Before 0.4.0 this claim was false.** `matched_content` shipped verbatim
substrings of prompts and completions for injection, jailbreak and toxicity
findings, and for SSNs it shipped `*******6789` — the identifying half. If you are
on 0.3.0 or earlier and this matters to your DPA, upgrade.

**The one opt-in.** Setting `send_match_preview=True` or
`OVERRULE_SEND_MATCH_PREVIEW=true` adds a `matched_content` field to each
violation containing a **shape-only mask** of the first 64 characters of the
match. Every letter and digit is replaced with `*`; punctuation, separators and
whitespace are preserved:

```
123-45-6789            →  ***-**-****
4532 0151 1283 0366    →  **** **** **** ****
alice@example.com      →  *****@*******.***
Ignore all previous…   →  ****** *** ********…
```

It exists to debug policy false positives. Be clear about what it does transmit:
the exact length of the match (up to 64 characters) and its full punctuation and
whitespace structure. It does not transmit letters or digits. Off by default;
leave it off in production unless you have assessed it.

### Other Protections

- API keys never exposed in `repr()`, `str()`, or serialized output
- Local PII redaction (`violation.matched_content`) shows only the last 4 characters — no BIN/prefix leakage — and is not transmitted by default anyway
- Config values are bounds-validated (batch_size, flush_interval, etc.)
- PEP 561 compliant (`py.typed` marker for downstream type checking)
- No secrets in logs — all sensitive values masked in debug output
- Policy timeout (5s) is enforced on a thread pool with a real wall-clock deadline, so a ReDoS-triggering pattern can neither block the event loop nor skip the remaining policies
- No nested unbounded quantifiers in any built-in pattern; per-pattern **reported violations** are capped at 100. The cap counts violations actually reported, not regex candidates — counting candidates let a wall of cheap decoys (16-digit runs that fail Luhn, context-less SSN shapes) exhaust the budget and switch the detector off for the rest of the window
- `violation.metadata["raw_match"]` holds the full match for in-process redaction but is stripped from `repr()` and from `model_dump()`/`model_dump_json()`, so logging a violation or an event cannot leak verbatim PII
- Permanent `4xx` ingest responses are recorded to `rejected.jsonl` and never retried, so a bad key cannot burn the circuit breaker, stop all reporting, or be replayed forever across restarts

---

## Cloud Dashboard

The Overrule cloud dashboard at [overrule.dev](https://overrule.dev) provides:

| Feature | Description |
|---------|-------------|
| **Posture Score** | At-a-glance governance health metric |
| **Event Stream** | Filterable, paginated log of every governed LLM call |
| **Policy Metrics** | Effectiveness rates, violation counts, status per policy |
| **API Key Management** | Create, revoke, usage tracking — plan-gated limits |
| **Billing** | Subscription management with usage metering |
| **Settings** | Webhook configuration, profile, account management |

### Plans

| | Free | Growth | Scale | Enterprise |
|--|:---:|:---:|:---:|:---:|
| Events/month | 10,000 | 1,000,000 | 10,000,000 | Unlimited |
| API keys | 5 | 25 | 100 | Unlimited |
| Webhooks | 1 | 5 | 20 | Unlimited |
| Rate limit | 200/min | 2,000/min | 10,000/min | 50,000/min |
| Retention | 7 days | 30 days | 90 days | 365 days |
| Price | Free | $499/mo | $2,999/mo | $10k+/mo |

Events, API keys, webhooks, rate limit and retention are the whole entitlement
surface — those five are the fields `PlanLimits` carries and the API enforces.
The SDK and its full policy engine are MIT-licensed and identical on every plan,
including Free; paid plans buy volume, retention, rate limit and support, not
extra enforcement. SSO/SAML, an uptime SLA, private deployment and team/seat
management are on the roadmap and not available today. See
[overrule.dev](https://overrule.dev/#pricing) for current pricing.

---

## Project Structure

```
overrule-sdk/
├── overrule/
│   ├── __init__.py              # Public API (Guard, SyncGuard, PolicyAction, policies)
│   ├── _compat.py               # StrEnum backport so the package imports on 3.10
│   ├── guard.py                 # Core Guard class (context manager, windowed scanning, REDACT, thread pool)
│   ├── stream.py                # StreamGuard — incremental eval + 256-char holdback
│   ├── sync.py                  # SyncGuard wrapper (background thread + event loop)
│   ├── exceptions.py            # Exception hierarchy (ViolationError, TransportError, etc.)
│   ├── logging.py               # Structured logging utilities
│   ├── _pool.py                 # Daemon-thread policy pool + generation-scoped retirement
│   ├── integrations/
│   │   ├── __init__.py          # Framework integration exports
│   │   └── langchain.py         # OverruleCallback for LangChain
│   ├── models/
│   │   ├── config.py            # GuardConfig + PolicyConfig + PolicyAction (BLOCK, LOG, WARN, REDACT)
│   │   ├── event.py             # InterceptEvent + EventStatus (passed/flagged/blocked/fail_open)
│   │   └── violation.py         # Violation model (policy_id, severity, blocked, metadata)
│   ├── policies/
│   │   ├── base.py              # BasePolicy abstract class + PolicyResult
│   │   ├── registry.py          # Thread-safe PolicyRegistry
│   │   ├── _normalize.py        # NFKC, invisible-char and confusable normalisation variants
│   │   ├── pii.py               # PII detection (9 patterns, Luhn/mod-97/context validation)
│   │   ├── injection.py         # Prompt injection (8) + SQL injection (5), both blocking
│   │   ├── jailbreak.py         # Jailbreak detection (9 patterns, blocking)
│   │   └── toxicity.py          # Toxicity detection (profanity, slurs, violence, 3 tiers)
│   └── transport/
│       ├── reporter.py          # Async EventReporter (batching, backoff, circuit breaker, match fingerprints)
│       └── dead_letter.py       # Dead-letter queue (retryable) + rejected.jsonl (never retried)
├── tests/                       # 614 tests (pytest)
├── examples/                    # Runnable integration examples
├── pyproject.toml               # Build config + dependencies
├── CHANGELOG.md                 # Version history
└── LICENSE                      # MIT
```

---

## Compliance Mapping

| EU AI Act Requirement | Overrule Implementation |
|----------------------|------------------------|
| **Art. 13** — Transparency & logging | Every LLM call logged with model, tokens, latency, policies, violations, environment — including `fail_open` events where governance was bypassed |
| **Art. 14** — Human oversight | Dashboard shows real-time enforcement stream and violation alerts |
| **Art. 15** — Accuracy & robustness | Runtime policy enforcement on known attack patterns, with the coverage gaps stated in [Detection Coverage](#detection-coverage-and-known-gaps) |
| **Audit evidence** | Structured event export for regulators |
| **Timeline** | Article 50 transparency obligations have been in force since August 2, 2026. Articles 13/14/15 high-risk obligations were deferred to December 2027 under the Digital Omnibus. Fines up to €35M / 7% global revenue. |

Overrule produces evidence for these requirements. It is not a certification and it
does not by itself make a system compliant — the mapping above is our reading of the
articles, not legal advice.

---

## Roadmap

- [x] Core Guard with fail-open transport
- [x] PII detection policy (credit cards, SSN, email, phone, IBAN, passport, IPv4, IPv6)
- [x] Injection detection policy (8 prompt injection + 5 SQL injection patterns, both blocking)
- [x] Jailbreak detection policy (9 patterns, blocking, in the default policy list)
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
- [x] Toxicity detection policy (profanity, slurs, violence, 3 severity tiers)
- [x] REDACT action (replace violations with tokens instead of blocking)
- [x] Output policy enforcement (response scanning)
- [x] Streaming interception (`guard.stream()` with incremental evaluation)
- [x] LangChain integration (`OverruleCallback` drop-in handler)
- [x] Dead-letter queue (failed events persisted to disk, auto-recovered)
- [x] Policy hot-reload (`reload_policies()` picks up changed `PolicyConfig.parameters`)
- [x] Per-policy configuration actually wired up (`GuardConfig.policies` / `PolicyConfig`)
- [x] Credit card detection with dash/space/dot formats, Luhn + issuer validation
- [x] Full-content scanning in overlapping windows (no sampling, no blind spots)
- [x] Match fingerprints (`match_len` / `match_sha256` / `match_type`) instead of verbatim text
- [x] Off-event-loop policy evaluation with a real 5s deadline
- [x] `fail_open` event status and `degraded_policies` metadata
- [x] Python 3.10 compatibility (`_compat.StrEnum`)
- [x] 614-test suite (pytest)
- [x] PEP 561 compliant (`py.typed`)
- [ ] Semantic detection shipped as a built-in policy (today: `examples/llm_content_classifier.py`)
- [ ] Non-English pattern coverage
- [ ] Encoded-payload (base64/rot13/hex) decoding before pattern matching
- [ ] Per-policy configuration in the LangChain callback
- [ ] CrewAI integration (agent-level governance)
- [ ] OpenAI Agents SDK wrapper
- [ ] Rust core for <100μs evaluation
- [ ] Policy marketplace (community-contributed policies)

---

## Examples

The `examples/` directory contains runnable scripts for common use cases:

| Example | Description | Requires LLM Key |
|---------|-------------|:---:|
| [`quickstart.py`](examples/quickstart.py) | Full integration test — LLM call + PII + injection enforcement | Optional (skips the LLM call without `OPENAI_API_KEY`) |
| [`evaluate_only.py`](examples/evaluate_only.py) | Policy evaluation without LLM calls, including cases that deliberately evade detection | No |
| [`custom_policy.py`](examples/custom_policy.py) | Build your own policy, and configure it with `PolicyConfig` | No |
| [`sync_usage.py`](examples/sync_usage.py) | Synchronous API, plus `@guard.protect()` enforcement | No |
| [`llm_content_classifier.py`](examples/llm_content_classifier.py) | LLM judge as a `BasePolicy` — the semantic complement to pattern matching | Yes |

```bash
# Run any example
cd overrule-sdk
export OVERRULE_API_KEY=sk_ovr_...
python examples/evaluate_only.py
```

---

## Development

```bash
# Clone
git clone https://github.com/overruledev/overrule-sdk.git
cd overrule-sdk

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest --cov=overrule --cov-fail-under=80

# Lint + format check
ruff check .
ruff format --check .

# Type check (strict)
mypy overrule/
```

### CI/CD Pipeline

Every push and PR triggers a production-grade CI pipeline:

| Stage | What It Does |
|-------|--------------|
| **Lint** | `ruff check` + `ruff format --check` |
| **Type Check** | `mypy` in strict mode |
| **Security Audit** | `pip-audit` scans all dependencies for known vulnerabilities |
| **Test** | pytest across Python 3.10, 3.11, 3.12 and 3.13 with an 80% coverage gate. 3.14 is declared supported in `pyproject.toml` but is not yet in the CI matrix. |
| **Build & Verify** | Builds sdist + wheel, `twine check`, install verification, 500KB size cap |

**PR Quality Gates** (run on pull requests only):
- New dependency detection with review notice
- Debug `print()` statement detection
- TODO/FIXME/HACK tracker
- Secret pattern scanning (hard fail)
- `.env` file leak detection (hard fail)
- Version bump notification

---

## Contributing

We're building in public. Contributions welcome.

```bash
# Fork + clone
git clone https://github.com/yourusername/overrule-sdk.git

# Create feature branch
git checkout -b feature/your-feature

# Make changes, then run the full CI suite locally
pytest --cov=overrule --cov-fail-under=80   # Tests + coverage
ruff check .                                 # Lint
ruff format --check .                        # Format
mypy overrule/                               # Type check

git commit -m "feat: your feature description"
git push origin feature/your-feature
```

All PRs must pass lint, typecheck, security audit, tests (80%+ coverage), and build verification before merge.

---

## Contact

| Purpose | Email |
|---------|-------|
| General inquiries | hello@overrule.dev |
| Customer support | support@overrule.dev |
| Enterprise sales | sales@overrule.dev |
| Founder | founders@overrule.dev |

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Built for teams shipping AI to production.</strong><br/>
  <sub>Overrule — because governance shouldn't slow you down.</sub>
</p>
