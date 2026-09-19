# Isolated Risk → Redis/PostgreSQL → Execution release gate

This is a test-only harness, **not an EVEDEX DEV qualification or trading launcher**.
Local preparation does not start Docker. Local execution remains paused until
the operator verifies the coordinated Docker-data relocation. The separate
`release-gate.yml` workflow uses a fresh GitHub-hosted VM; it never connects to
the operator's Docker engine, databases, secret files or migration volumes.
No production service, credential, research fixture, strategy or public contract
is modified by this directory.

## Scope of evidence

The gate uses the exact published, non-editable Git installations pinned in
`pyproject.toml` and `uv.lock`: Core `91cd95c`, Persistence `526c30f`, Strategy
Engine `6a16440`, Router `053e90b`, LLM `d824343`, Aggregator `cef4928`, Risk
`a10649c`, and Execution `73122e8`. It checks Git provenance **and actual imported
module paths** against each installed distribution in `site-packages`. `PYTHONPATH`
contains only this harness and the tests from the exact Execution commit; it does
not contain a production source checkout.

The intended test path is:

1. A hermetic contract test runs one deterministic closed Binance 1m-bar stream
   through the real Strategy generator, Router policy, Aggregator review boundary,
   PAPER Risk policy and PAPER Execution rejection boundary. Its local gateway always
   fails rather than calling an LLM, so the review must be `DEFER`, Risk must reject
   the frozen strategy, and Execution must return without touching a venue or creating
   even synthetic secret files.
2. An explicitly synthetic, hash-chained 24-hour receipt fixture is checked by
   the real session repository. The real bounded session and arm transactions
   stage the review and bound canary allocation in the durable outbox.
3. The real `RiskService.run()` restores persisted reservations and runs its
   normal Redis consumers. Account and venue inputs arrive over the actual bus.
   Its real `PaperRiskCoordinator` computes the decision; the test does **not**
   inject a pre-approved risk decision.
4. The real `DurableMessageBus`, PostgreSQL inbox/outbox, and Redis Streams carry
   the decision to the actual Execution initialization/decision-consumer path.
   The actual engine uses the real arm, session, final-dispatch admission, journal
   and recovery repositories. Only the venue adapter is synthetic. The full
   `ExecutionService.run()` and sidecar network loops are deliberately not run.
5. A thin real-Redis transport observer checks from a separate database
   connection that Risk decisions/lifecycle facts and inbox completion are
   committed **before** Redis ACK. It then injects one lost execution ACK.
6. Fresh Risk and Execution service instances recover from the durable state.
   Only that synthetic pending Redis message is aged to exercise the unchanged
   production reclaim threshold. Reclaim and new-ID duplicate deliveries must
   not produce a second decision, entry or dispatch claim.
7. Admission is stopped. Existing protection and timeout recovery continue even
   when the restarted engine has no scope file. The final trade must be flat,
   effects resolved, inboxes completed, outboxes published, and checked Redis
   pending lists empty.

Technical canary sizing uses the exact arm-bound allocation (1x, 0.25% weight and
99.75% reserve); this does not assert that an external Macro stream controls that
canary. The receipt, market book, fills and account are synthetic. The gate proves
the fail-closed Strategy/Router/Aggregator/Risk/Execution path for the current frozen
candidate; it does not prove a successful LLM approval, Macro allocation service,
venue authenticity, liquidity, slippage, profitability, five-symbol scenario coverage
or genuine 24-hour/7-day gates. Paid LLM/X APIs and real exchange calls are absent.

Redis persistence is deliberately disabled and PostgreSQL uses tmpfs. This gate
proves **application-service restart and commit-before-ACK semantics while the
database/Redis processes remain alive**, not host power-loss recovery or durable
data-service/container restart. Separate persistent-volume recovery drills and
real DEV qualification remain necessary. A passing result never sets
`PAPER_QUALIFIED`, `ALPHA_READY` or `LIVE_READY`.

## Isolation and execution policy

- New project: `kairos-release-gate-20260919-r3`; exact database:
  `kairos_execution_test_202609190003`.
- Internal, unshared network; no host ports, host mounts, existing volumes,
  external networks, `.env`, inherited secrets or production credentials.
- Public synthetic credentials exist only in this test configuration.
- Exact DSN opt-in and actual `current_database()` are checked before migration
  on **every** real service pool. The observer additionally requires an empty
  public schema before the first migration; Redis must be empty before seeding.
- Existing test data is not cleaned, deleted or silently reused. A failed run
  preserves its evidence for inspection; there is no automatic `down -v` or
  unconditional container cleanup in the harness. A repeated run against a
  previously used database fails closed, even when that database has no trades.

Hermetic policy tests (no network/data service) can be run on Windows with the
existing locked Python environment and an explicit test-file selector:

```powershell
cd D:\Kairos\kairos-deploy\tests\release_gate
uv run --locked python -m pytest -q -p no:cacheprovider test_policy.py test_witness.py test_full_path.py
```

After approval and verifying that no prior resources carry this project's name,
the isolated Linux gate can be invoked from the deploy repository:

```powershell
docker compose -p kairos-release-gate-20260919-r3 -f tests/release_gate/compose.yml build gate
docker compose -p kairos-release-gate-20260919-r3 -f tests/release_gate/compose.yml up -d --wait --wait-timeout 90 timescaledb redis
docker compose -p kairos-release-gate-20260919-r3 -f tests/release_gate/compose.yml run --no-deps -T gate
```

Capture the full output and exact image/revision identities before inspecting or
removing any test resource. Do not use `--abort-on-container-exit`: stopping the
tmpfs data services destroys their in-memory data before failure inspection.
The local command is one finite test, not a retry/restart loop.

CI runs the hermetic policy suite on Windows and Linux, then one actual pipeline
test on a separate hosted Ubuntu VM. Its runtime wait is capped at 180 seconds,
and the complete job at 25 minutes. Each Docker command names only the isolated
project and test Compose file. Logs, image identities and a synthetic PostgreSQL
dump are uploaded before hosted-runner disposal. That dump is diagnostic evidence,
not a successful restore drill. There is no host-wide cleanup or `down -v`.
The legacy deploy `unittest` job does not discover these pytest integration checks.
