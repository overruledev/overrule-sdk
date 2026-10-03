# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-08-04

A correctness and privacy release. Several things this SDK previously *documented*
were not true of the code; the code now matches the claim, and the claims that were
wrong are corrected below rather than quietly dropped.

### Breaking Changes

- **Prompts and completions no longer leave your infrastructure by default.** The
  reported violation payload no longer contains `matched_content`. Each violation
  now ships `match_len`, `match_sha256` (first 16 hex chars of the SHA-256 of the
  match) and `match_type` (the detector sub-rule, e.g. `ssn`, `sql_injection`).
  Dashboards and pipelines that read `matched_content` must switch to
  `match_sha256` for correlation. Set `send_match_preview=True` /
  `OVERRULE_SEND_MATCH_PREVIEW=true` to additionally receive a shape-only mask
  (see Added).
- **SQL injection and jailbreak violations now block everywhere.** Previously
  `@guard.protect()` ignored `violation.blocked` entirely (so
  `'; DROP TABLE users; --'` executed), SQL injection never set `blocked=True` at
  all, and the LangChain callback never blocked because its default action is
  `LOG`. All three now raise `ViolationError`. Code that relied on injection or
  jailbreak findings being advisory will start seeing exceptions.
- **`Guard.evaluate()` narrowed its `direction` parameter** to
  `Literal["input", "output"]`. Any other string is now a type error (and was
  never handled meaningfully).
- **`PolicyAction.REDACT` is rejected by `guard.stream()`.** It raises
  `ValueError` instead of silently failing to redact tokens that have already
  been yielded. Use `guard.chat()` for REDACT.
- **`GuardConfig.policies` is now honoured** — every field: `PolicyConfig.enabled`,
  `PolicyConfig.action`, `PolicyConfig.parameters` and
  `PolicyConfig.severity_override`. These were dead configuration:
  `PolicyConfig(id="pii-detection", enabled=False)` still ran PII detection, and
  `parameters` never reached the policy. Existing configs that were being ignored
  will now change behaviour — audit them before upgrading.
- **`PolicyConfig.severity_override` is implemented.** It forces every violation
  from that policy to a fixed severity, on `evaluate()`, `chat()`, `@protect()`,
  `SyncGuard` and `stream()` alike. The severity the policy itself assigned is kept
  on the violation as `metadata["original_severity"]`, so the override is auditable
  rather than silently rewriting history; no `original_severity` key is added when
  the override is absent or already matches. An unrecognised value is rejected at
  config time. Previously the field was accepted by the model and read by no code,
  so a config that set it silently had no effect.
- **`guard.stream()` honours `PolicyConfig(enabled=False)`.** `StreamGuard` called
  the registry with no enabled-check, so a policy the customer had explicitly
  switched off still ran against streamed output. `Guard._default_policies` is
  filtered at init, which hid this unless the caller passed an explicit
  `policies=[...]` to `stream()`. Disabled policies are now also dropped from the
  `policies_applied` list on the reported event, so it reflects what actually ran.
- **`ContentTooLargeError` removed** from `overrule.exceptions` and `__all__`. It
  was never raised; the truncation-based content cap it existed for was replaced
  by full-content chunked scanning.
- **`GuardConfig.async_reporting` and `GuardConfig.redact_on_block` removed.**
  Both were documented but read by no code. Reporting has always been
  asynchronous; redaction is controlled by `PolicyAction.REDACT`.
- **`max_content_length` no longer limits what is scanned.** It is now purely a
  cap on how much content is stored and reported. Policy evaluation always covers
  the whole payload.

### Added

- Full-content scanning in overlapping windows: `SCAN_CHUNK_SIZE` of 100,000
  characters with a 256-character overlap, so no pattern can straddle a boundary
  and nothing is sampled or skipped. Per-window violations are de-duplicated on
  `(policy_id, raw_match, absolute_offset)` where the offset within the window can
  be determined, and on an occurrence ordinal where it cannot (a match found via a
  normalisation variant is not present verbatim in the window).
- `send_match_preview` / `OVERRULE_SEND_MATCH_PREVIEW` (default `False`): an
  explicit opt-in that adds a `matched_content` field containing a shape-only
  mask of the first 64 characters of the match — every letter and digit is
  replaced with `*`, while punctuation, separators and whitespace are preserved
  (`123-45-6789` becomes `***-**-****`). It is for debugging false positives, and
  it does transmit the match's length and punctuation structure.
- `EventStatus.FAIL_OPEN`: fail-open pass-throughs are now reported as their own
  status instead of being invisible, so a guard that has silently stopped
  enforcing is distinguishable from a healthy one. Carries
  `metadata["fail_open_reason"]`, `metadata["fail_open_detail"]` and
  `metadata["llm_called"]`.
- `metadata["degraded_policies"]`: the IDs of policies skipped because they blew
  their deadline or crashed, so an only-partially-evaluated event is no longer
  reported as cleanly passed.
- `overrule/_compat.py` with a `StrEnum` backport, so the package actually
  imports on Python 3.10 (`enum.StrEnum` is 3.11+; every declared 3.10 install
  previously failed at import).
- Streaming holdback: `guard.stream()` withholds a trailing 256-character window
  from the caller until the stream ends, so a violation in the final tokens can
  still be acted on before they are emitted.
- `PolicyConfig.action` as a per-policy override of the global `default_action`.
- IPv6 detection in `pii-detection`, validated with the stdlib `ipaddress`
  module.
- Credit card coverage extended to Diners, JCB and UnionPay, the Amex 4-6-5 print
  format, dot separators, and 13/19-digit cards — all validated with Luhn *and* a
  known issuer prefix/length.
- IBAN validation now checks the ISO country code, that country's registered
  length, and the ISO 7064 mod-97 checksum.
- Unicode normalisation for injection and jailbreak detection: NFKC, two
  zero-width handling variants, and folding of common Cyrillic/Greek confusables.
  Detection remains pattern based — base64/rot13/hex payloads, paraphrase,
  synonyms, non-English phrasing and confusables outside the folding table still
  evade it, as documented in the README's "Detection Coverage and Known Gaps".
- `OVERRULE_ENVIRONMENT` is now actually transmitted on events. The variable was
  documented, but no such field existed on the wire and the server discarded it.
- Test suite expanded to 614 tests.

### Fixed

- **Buffer overflow was the one event-loss path invisible in metrics.** The send
  buffer is a `deque(maxlen=10_000)`, whose `.append()` silently evicts the oldest
  entry once full, without touching `events_dropped`. Sustained loss was therefore
  invisible in `reporter.metrics`, which is why the "zero event loss" claim was
  withdrawn. Eviction is now detected before it happens and counted in
  `events_dropped`, broken out separately as `buffer_overflows`, and warned about
  at most once per 60s (an unthrottled warning on a saturated buffer becomes its
  own outage). Drop-oldest is kept deliberately — under backpressure the newest
  governance events are the useful ones — and `metrics` now documents that
  `events_dropped` covers *every* loss path: permanent 4xx, retry exhaustion,
  serialisation failure and overflow.
- **Toxicity `check_*` flags gated the wrong tiers.** `check_slurs` gated the HIGH
  tier containing *both* profanity and slurs, while `check_profanity` gated the LOW
  tier of mild insults — so `check_profanity=False`, a documented public parameter,
  did not turn off profanity detection. Each flag now gates exactly the category it
  names: `check_violence` (CRITICAL), `check_slurs` (HIGH, slurs and hate speech),
  `check_profanity` (HIGH, severe profanity), `check_insults` (LOW, mild insults).
  Defaults are all `True` and unchanged, so this only alters behaviour if you set
  one to `False`; use `check_insults=False` for what `check_profanity=False` used
  to do. Profanity and slurs still share the HIGH tier — there is deliberately no
  MEDIUM tier — they are simply gated independently.
- **Privacy leak in telemetry.** `matched_content` shipped verbatim substrings of
  prompts and completions for injection, jailbreak and toxicity findings, and
  `*******6789` — the identifying half — for SSNs. Nothing in the payload now
  contains customer text unless `send_match_preview` is explicitly enabled.
- **Truncation blind spots.** The head/middle/tail sampling introduced in 0.3.0
  left roughly 50% of a 200KB payload and 90% of a 1MB payload unscanned. See the
  0.3.0 correction note below.
- **Policy timeouts did not time anything out.** The 5s budget was measured after
  `policy.evaluate()` returned, so a catastrophically backtracking pattern blocked
  the entire asyncio event loop (measured at 12.7s) and then raised
  `PolicyEvaluationError` ahead of the fail-open branch, skipping every remaining
  policy. Policies now run on a bounded thread pool under a real wall-clock
  deadline; a policy that blows it is skipped and recorded in
  `degraded_policies`.
- **Telemetry failures disabled enforcement.** A reporter error on the block path
  discarded an already-detected BLOCK and passed the call through unguarded — and
  re-invoked the provider, billing the customer twice. Enforcement is now
  committed before telemetry is attempted, and the fail-open path never calls the
  LLM a second time.
- **`@guard.protect()` did not enforce.** It ignored `violation.blocked`
  completely.
- **The LangChain callback did not enforce or report correctly.** Blocking
  violations now block regardless of `action`, an audit event is recorded before
  the exception is raised, and the reporter runs on a background loop that
  outlives the callback instead of a throwaway loop that left the flush task
  pending on a closed loop.
- **Message content extraction missed most real shapes.** Multimodal content
  blocks, Anthropic-style lists and several other message shapes extracted `""`,
  so nothing was scanned and the call was reported as `passed`.
- **SSN and US passport false positives.** `NNN-NN-NNNN` and `letter + 8 digits`
  are shape-identical to invoice numbers, part numbers, SKUs and ticket IDs, all
  of which were being reported as critical PII. Both detectors now require a
  nearby context keyword (`SSN`, `social security`, `taxpayer`, `passport`,
  `travel document`, …). **Callers relying on bare-number detection must know
  this**: `123-45-6789` with no supporting text is no longer reported.
- Space-separated 10-digit runs likewise now require phone context, and
  IPv4-shaped strings are rejected when preceded by version-like context
  ("upgrade to 10.20.30.40").
- 4xx ingest responses are no longer retried. A 401 or a 422 was retried three
  times, burned the circuit breaker (5 failures → 30s open → all reporting stops)
  and only then dead-lettered. Permanent statuses (400/401/403/422) are now
  dead-lettered immediately and do not touch the circuit breaker. The server's
  `{error, code, details}` body is parsed and logged — nothing read it before,
  which is why a schema-mismatch 422 was invisible in production.
- Events under the retry cap are no longer discarded at process exit;
  `stop()` persists everything still buffered to the dead-letter queue.
- Wire-contract fixes that previously 422'd whole batches of up to 50 events:
  unset optionals are omitted rather than sent as JSON `null`, a legitimate
  `latency_ms` of `0.0` survives, `violation.direction` is clamped to
  `input`/`output`, `event.id` is a canonical dashed UUID (the bare 32-char hex
  form was rejected), `timestamp` is sent so events are not all stamped at ingest
  time, and policy/violation lists are truncated to the server's limits.
- REDACT replaces every occurrence of a match using the full `raw_match` rather
  than the truncated `matched_content`, so the tail of a long match is no longer
  left in the response. BLOCK is evaluated before REDACT, so a violation that
  demands blocking is not quietly redacted instead.

### Fixed — regressions introduced by this release's own fix pass

An independent review of the changes above found the following. All were reproduced
before being fixed, and each now has a regression test that fails without the fix.

- **Governance applied to `messages[0]` only for pydantic message objects.**
  `_collect_text`'s cycle guard was a `set[int]` keyed on `id(node)`. `model_dump()`
  returns a fresh dict that is freed as soon as the recursive call returns, and
  CPython immediately reuses the address — so from the second message onwards the id
  was already "seen" and the message was skipped entirely. Anyone passing OpenAI-SDK
  message objects, LangChain `BaseMessage`s or any pydantic message model had
  everything after the first message silently unscanned; with
  `default_action=BLOCK`, a card in `messages[1]` was **not blocked**. Plain dicts
  were unaffected, and `_extract_input_checked` could not catch it because the
  extracted text was non-empty. The guard now holds a strong reference to every node
  it records. Also affected `_extract_output_parts` with pydantic content blocks.
- **100 decoys disabled PII detection for the rest of the window.** The
  per-pattern cap counted regex *candidates*, including ones `_refine_match`
  rejects. 100 repetitions of a 16-digit run that fails Luhn (~1.7KB) exhausted the
  budget, after which a real card or SSN in the same window was not reported at all.
  The cap now counts **reported violations**; a separate, deliberately loose
  candidate bound keeps pathological input cheap without letting decoys crowd out a
  real match. `toxicity.py` used the same idiom without a refine step (so it was
  safe) and has been aligned.
- **`stream()` ignored per-policy `PolicyConfig.action`.**
  `_blocking_violations` tested only the global `default_action`, so
  `default_action=WARN` plus `PolicyConfig(id="pii-detection", action=BLOCK)`
  blocked on `chat()` but streamed the card verbatim — while `StreamGuard`'s
  docstring promised per-policy config was honoured "exactly as on `chat()`".
- **Permanent 4xx rejections became an infinite poison-pill loop.** They were
  written to the recoverable dead-letter file while `start()` calls
  `recover()` unconditionally, so every restart re-POSTed the same rejected batch,
  got the same 401/422, wrote it back to disk and re-counted `events_dropped` —
  forever. Worse than the bug it replaced, which dropped them once. Permanently
  rejected events now go to `.overrule/rejected.jsonl`, which `recover()` never
  reads; they are retained for inspection but never retried.
- **Fail-open after the LLM call reported `flagged=False` / `violations=[]`
  despite detected violations.** Everything found before the failure was discarded,
  so a response whose input already contained a card came back looking clean. Any
  post-LLM helper failure reached this. Violations found so far are now threaded
  through to both the returned `ChatResponse` and the `FAIL_OPEN` event.
- **A REDACT policy redacted other policies' matches.** All output violations were
  handed to `_apply_redaction` as soon as any one of them wanted redaction, so a
  policy explicitly configured to `LOG` had its match rewritten too. Redaction is
  now scoped to violations whose own effective action is `REDACT`.
- **Buffered events were lost for any garbage-collected `Guard`.** The registry
  held only weakrefs and `_atexit_flush` skipped a dead ref with no log at all, so
  the most idiomatic usage — a `Guard` created inside `async def main()` and driven
  by `asyncio.run(main())` — lost its unsent events silently, contradicting
  `stop()`'s documented promise. A module-level `Guard` worked fine, which is why it
  went unnoticed. The reporter of a collected `Guard` that still holds events is now
  retained (bounded, and released by `shutdown()`) so `atexit` can persist them, and
  `stop()` no longer aborts its dead-letter drain when the loop its flush task
  belonged to has already closed.
- **Credit-card matcher: one false positive and one miss.** `IMEI 490154203237518`
  was reported as a Visa, because the first 13 digits pass Luhn as a 13-digit Visa;
  a run that only validates at 13 digits is now rejected when more digits follow it.
  And `_refine_card` only tried runs anchored at the first digit, so
  `id=004111111111111111` was **not detected at all**; the window start is now slid
  across the run. All 13 legitimate card formats still work, and
  `4111-2024-0001-5678` is still rejected.
- **Policy pool retirement leaked threads and could not be reclaimed.** Once four
  runs were stuck, the "all workers stuck" condition stayed satisfied and *every*
  subsequent timeout churned out another four-worker pool; the workers were
  non-daemon, so both `concurrent.futures`' atexit hook and `threading._shutdown`
  joined them and a genuinely stuck policy meant the process never exited at all.
  Orphan tracking is now scoped to the pool generation a run was scheduled against
  (each pool retires exactly once), and workers are daemon threads
  (`overrule/_pool.py`), so exit is unconditional. `StreamGuard` now reports its
  timed-out runs back to the owning `Guard` — previously streaming timeouts starved
  the shared pool invisibly and never retrieved `future.exception()` — and re-fetches
  the pool per evaluation instead of caching it, which used to leave it raising
  `RuntimeError: cannot schedule new futures after shutdown` after any retirement.
  Availability after starvation is unchanged (a healthy policy still runs in ~1ms).
- **`metadata["raw_match"]` leaked verbatim through `repr()` and
  `model_dump_json()`.** The wire payload was clean, but pydantic's default repr
  prints `metadata`, so `print(response.violations)` emitted full untruncated PII
  while `matched_content` on the same object was deliberately masked. `Violation`
  now has a `__repr__` mirroring `__str__`, and a field serializer strips the raw
  match from `model_dump()`/`model_dump_json()` — including when nested inside an
  `InterceptEvent`. The value is unchanged in-process, so redaction still works.
- **`_active_guards` grew without bound.** It was pruned only inside `shutdown()`,
  so 60 short-lived `Guard`s left 60 dead weakrefs. Entries are now removed by the
  weakref callback.
- **Normalised-variant matches were under-counted.** When a match came from a
  folded or zero-width-stripped variant it is not present verbatim in the window, so
  `window.find(raw)` returned -1, every violation in the window got
  `offset == base`, and the `(policy_id, raw, offset)` de-duplication key collapsed
  them to **one violation per 100_000-character window** (measured 11 for a
  confusable-dense 1MB input, against ~100 per window for the ASCII equivalent).
  Telemetry only — enforcement was unaffected, since injection/jailbreak set
  `blocked=True` — but it made a saturated detector look quiet. An occurrence
  ordinal is now used when the offset is unknown.
- **LangChain integration missed the concurrency and configuration work.**
  `OverruleCallback` called `registry.resolve()`, which passes `parameters=None`, and
  read none of `enabled`, `severity_override` or `action` — so the "every
  `PolicyConfig` field is now honoured" claim above did not hold for it. It now takes
  a `config=` argument and honours all four, and runs policies on a bounded daemon
  pool under the same 5s deadline instead of inline with no deadline (a slow policy
  blocked the LangChain thread indefinitely). Skipped policies are recorded in
  `metadata["degraded_policies"]`, as on `Guard`. Relatedly, `SyncGuard.protect`
  skipped `_active_policies()`, so a disabled policy still appeared in
  `policies_applied`.
- **Tests that could not fail.** `test_pydantic_style_object` used a single
  one-element list, so N=1 could never expose the extraction bug it was written to
  cover. The scan-cost test asserted `< 5_000ms` against a ~40-90ms budget (58x
  slack, enough to pass a 50x regression) and is now bounded at 1_000ms with a
  companion linear-scaling assertion. A `filler()` docstring claimed a single
  character run causes "quadratic backtracking" — measured scaling is x2.01, i.e.
  linear — and the stale claim steered tests away from the shapes that matter. A
  tautological `EventStatus("fail_open") is EventStatus.FAIL_OPEN` assertion was
  replaced with one that checks the bypass is distinguishable from a clean pass. The
  post-LLM fail-open test asserted response content but not `flagged`/`violations`,
  which is exactly how that regression survived.

### Changed

- `jailbreak-detection` joins `pii-detection` and `injection-detection` in the
  default policy list for the LangChain callback, matching `Guard`.
- `OverruleCallback` accepts `config: GuardConfig`. `action` and `fail_open` now
  default to `None` and fall back to the config (and then to `LOG`/`True`, the
  previous defaults), so existing keyword usage is unchanged.
- Policy workers are daemon threads, so a policy stuck in customer code can no
  longer delay interpreter exit. A stuck worker is still unreclaimable — Python
  threads cannot be interrupted — but it no longer blocks the process.
- Policy evaluation runs off the event loop on a bounded 4-worker thread pool.
  Workers stuck in customer policy code are detected and the pool is retired and
  replaced rather than starving evaluation.
- Measured performance after these changes: ~0.5ms for the three default policies
  on a 1KB prompt (~0.7ms measured through `Guard`, including thread-pool
  dispatch), and ~45ms on 100KB of ordinary text — pii 16.0ms, injection 9.6ms,
  jailbreak 19.9ms, toxicity 9.3ms. Content containing Cyrillic/Greek confusables
  costs roughly double, because an extra normalisation variant is scanned (~85ms
  for the three defaults on 100KB). Cost is linear in input length (measured x2.01
  per doubling); the worst realistic 1MB payload is ~0.9s, roughly 6x under the 5s
  per-policy deadline. An earlier suspicion that the patterns were quadratic, and
  that padding could silently disable a policy by blowing the deadline, was
  investigated and does not reproduce. The `SCAN_CHUNK_SIZE` comment in `guard.py`
  still claimed "~40ms per 100_000 chars" from before confusable folding and
  candidate validation; corrected.
- SDK version bumped to 0.4.0.

### Correction to the 0.3.0 entry

The 0.3.0 notes below claim that head/middle/tail sampling "eliminates evasion via
center-of-payload placement", and the README claimed the sampling "covers all three
regions to prevent evasion". **Both statements were false.** Sampling three fixed
windows leaves the gaps between them unscanned: measured blind ranges of
33303–83333 and 116637–166666 for a 200KB input, i.e. about half of a 200KB
payload and about 90% of a 1MB payload. The 0.3.0 text is left in place as
published; 0.4.0 replaces sampling with full overlapping-window scanning.

The 0.3.0 claim of "140 tests" and the 0.2.0 claim of "137 tests" were also both
in the changelog while the README badge said 137 and the README performance table
said 140. The actual count at 0.4.0 is 614.

## [0.3.0] - 2026-07-15

### Breaking Changes

- **Default action changed from `LOG` to `WARN`** — violations are now surfaced in `response.violations` and `response.flagged` instead of being silently logged. Set `default_action=PolicyAction.LOG` to restore previous behavior.
- **Jailbreak detection added to defaults** — `Guard()` now applies `pii-detection`, `injection-detection`, and `jailbreak-detection` by default. Pass explicit `default_policies` to opt out.
- **Prompt injection and jailbreak violations now always block** — these set `violation.blocked=True`, triggering `ViolationError` regardless of `default_action`.

### Added

- `JailbreakPolicy` exported from public API and wired into default policy list
- `response.violations` and `response.flagged` on `ChatResponse` — violations always visible to caller
- `_should_warn()` method on Guard for WARN-mode behavior
- Policy timeout (5s) — prevents ReDoS from triggering fail-open bypass
- Content truncation now samples head + middle + tail (was head + tail only) — eliminates evasion via center-of-payload placement
- "Security Model" section in README documenting enforcement behavior, fail-open, streaming limitations
- `examples/llm_content_classifier.py` — LLM-based semantic policy using gpt-4o-mini as a judge
- StreamGuard docstring documents token-recall limitation
- Test suite expanded to 140 tests

### Fixed

- Truncation blind spot: content placed in the middle of large payloads (>100KB) now scanned
- Injection detection sets `blocked=True` — per-violation block override now actually fires
- Jailbreak detection sets `blocked=True` — same enforcement as injection

### Changed

- SDK version bumped to 0.3.0

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
