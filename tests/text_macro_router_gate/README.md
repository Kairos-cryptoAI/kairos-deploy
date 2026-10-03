# Text / Macro / Router / Review / Risk engineering composition

This additive package is an opt-in **OFFLINE_ENGINEERING_FIXTURE**. It never
changes the historical release gate or a strategy/evaluator frozen for research.
All readiness remains false and `STRATEGY_POLICY=REJECT_ALL`. A synthetic test
label `ALLOW` is not a prediction, alpha result, venue qualification or permission
to send an order.

The real installed producer and domain paths are:

1. `EventFreshnessFilter` → `SentimentExtractor` → `RouterService` event-time
   ingestion and candidate routing through the actual `InMemoryBus`.
2. `CandidateReviewBrain` preserves immutable intent, chooses the normal/conflict
   workload, validates ALLOW/VETO/DEFER and applies its material-conflict guard.
3. `ShockDetector` → `build_macro_context` → `MacroStrategist` produces a separate
   allocation constraint. Macro is **not** an input invented for Router.
4. `PaperRiskPipeline` evaluates those same review/allocation objects with
   synthetic account/venue facts. Default empty PAPER allowlist and explicitly
   rejected research sleeve mean every such risk result is rejected, quantity
   zero. The immutable 0.25% per-trade / 1% aggregate ceilings remain enforced;
   high review priority or 20x Macro output cannot raise them.

Only remote model responses are fixed, strict-schema gateway doubles. No provider
client, external feed, DB, Redis, EVEDEX client, operator configuration or secrets
are constructed/read. Network calls and real gateway construction are blocked.
Raw news is synthetic at `fixture.invalid`; fixture timestamps/identities are
not historical event observations. Macro reception timestamps are explicitly
normalized in the test, not evidence about the service clock.

Scenarios cover bull/range/crash, schedule/shock context, opposing news, separate
Macro/strategy conflict, stale/future news, stale Macro, refusal/failure/deadline,
duplicate delivery, local fallback, ALLOW/VETO/DEFER, intent immutability and
risk-cap refusal. These are composition/contract tests, **not a production
adaptive evaluator** and not an economic or long-running trading campaign.
The actual durable adaptive scheduler/three-arm journal requires a separate
isolated DB proof; this package deliberately does not mock it into a PASS.

Default invocation is strict pinned non-editable installed-wheel verification:

```powershell
uv sync --locked --offline --no-editable
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
```

An explicit `--source-checkout-preliminary` permits an operator-arranged source
checkout import for development only. Its report says
`PRELIMINARY_SOURCE_ONLY; installed-wheel-qualified=false`; it does **not** count
as the final installed proof. Missing packages do not become skips/PASS.

The additional `composition-native.yml` hosted CI workflow installs nine exact
non-editable Kairos packages, including the real Strategy generator. Its explicitly
selected `--native-composition` target uses fresh isolated PG16/Redis services,
a UUID4 database and the `CONTROLLED_RUNTIME` profile (not the primary schema).
Only an unprivileged runtime role may enter the real durable service handlers;
the synthetic no-login operator placeholder grants no ARM or trading authority.
It tests actual `TextScoutsService.poll_once`, `MacroService.restore_history/run_once`,
Router and CandidateReview handlers, and PAPER Risk recovery/input/review handlers.
Macro reception timestamps are not normalized or overwritten in this native target.
Router/review logical clocks remain explicitly injected engineering fixture clocks;
this target is not a production end-to-end latency or causal news-arrival proof.

The native target covers ALLOW/VETO/DEFER, opposing news/conflict guard, stale-news
filtering, bearish/failure Macro constraints, genuine immutable generator intents
and natural NO_INTENT. Real PostgreSQL inbox/outbox and Redis transport IDs prove
committed ACK-loss reclaim, duplicate delivery and fresh-component restart: no
additional review provider call or duplicate risk output. Macro's own persisted
allocation is replayed byte-identically after restart. An advisory proposal on the
research topic cannot create a Risk decision or order. All entries remain refused
by the actual default empty strategy allowlist and missing operator authority.

External news/model/account/venue inputs are explicitly fixture-only. The model
double has zero cost and does not qualify real provider budget START/adoption or
continuous shadow operation. This proof does **not** establish no-resend after an
uncommitted provider call, persistent Text dedup after restart, real feeds, source
quality, execution/venue round trips, alpha, PAPER_QUALIFIED or LIVE readiness.
Native output contains only fixed failure class/phase; tracebacks, locals, raw
driver/provider errors and captured logs are withheld. Native cannot be combined
with `--source-checkout-preliminary`; default tests still deny all network access.
An exact one-test, zero-skip XML validator must pass after the native target.

Locked acquisition and isolated current-source runner integration are
reviewed/publication steps owned by the parent workflow. Do not add this proof
to the historical `release_gate`, change its old pins, or launch a new default
BuildKit builder to qualify it.
