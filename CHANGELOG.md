# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-12

### Added

- **Streaming interception** (`guard.stream()`) — token-by-token policy evaluation for streaming LLM responses with configurable eval interval
- **LangChain integration** (`OverruleCallback`) — drop-in callback handler for automatic governance on any LangChain chain, agent, or LLM call
- **Dead-letter queue** — failed events persisted to disk (`.overrule/dead_letter.jsonl`), auto-recovered on next startup
- **Policy hot-reload** (`guard.reload_policies()`) — re-instantiate policy instances at runtime without restarting
- **Toxicity detection policy** (`toxicity-detection`) — detects profanity, slurs, hate speech, violence incitement, and dangerous instructions across 3 severity tiers
- **REDACT policy action** — violations in LLM output are replaced with `[POLICY_ID]` tokens instead of blocking the response
- `StreamGuard` async iterator with incremental evaluation and final full-pass
- `guard.unregister_policy()` for dynamic policy management
- `ToxicityPolicy` exported from `overrule.policies` and registered as built-in
- PII policy now stores `raw_match` in violation metadata for accurate content redaction

### Changed

- `PolicyAction` enum: added `REDACT` alongside `BLOCK`, `LOG`, `WARN`
- Credit card detection now matches dash-separated and space-separated formats
- SDK version bumped to 0.2.0
- Test suite expanded to 137 tests

### Fixed

- Credit card regex now correctly detects `4111-1111-1111-1111` and `4111 1111 1111 1111` formats (previously only matched continuous digits)

## [0.1.1] - 2026-07-12

### Fixed

- **Critical:** Default endpoint corrected from `https://api.overrule.dev` to `https://overrule.dev/api` — events now reach the dashboard correctly
- GitHub repository URL aligned to `overruledev/overrule-sdk`

### Added

- `examples/` directory with 4 runnable scripts (quickstart, evaluate-only, custom policy, sync usage)
- "Verify Your Integration" section in README for instant feedback
- Explicit `OPENAI_API_KEY` mention in quickstart configuration

## [0.1.0] - 2026-07-09

### Added

- Core `Guard` class with async context manager and fail-open error handling
- `SyncGuard` for synchronous applications (background thread with dedicated event loop)
- PII detection policy (credit cards, SSN, email, phone, IPv4, IBAN, passport)
- Injection detection policy (8 prompt injection + 5 SQL injection patterns)
- Thread-safe `PolicyRegistry` with custom policy support via `BasePolicy` ABC
- Async batched `EventReporter` with exponential backoff, circuit breaker, bounded buffer
- `OVERRULE_*` environment variable configuration (12-factor compatible)
- Multi-provider LLM support (OpenAI + Anthropic) with cached async clients
- `@guard.protect()` decorator for tool/function governance
- `guard.evaluate()` for standalone content checking
- Content truncation (100K char limit)
- Graceful shutdown with `atexit` flush hook
- Full type annotations with `py.typed` marker (PEP 561)
- 78 unit tests with full coverage of policies, transport, and lifecycle
