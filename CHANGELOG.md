# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- Async batched `EventReporter` with exponential backoff, circuit breaker, dead-letter drop
- `OVERRULE_*` environment variable configuration (12-factor compatible)
- Multi-provider LLM support (OpenAI + Anthropic) with cached async clients
- `@guard.protect()` decorator for tool/function governance
- `guard.evaluate()` for standalone content checking
- Content truncation (100K char limit)
- Graceful shutdown with `atexit` flush hook
- Full type annotations with `py.typed` marker (PEP 561)
- 78 unit tests with full coverage of policies, transport, and lifecycle
