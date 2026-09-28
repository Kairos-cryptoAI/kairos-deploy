# Full-path simulator gate

`docker-compose.sim-full-path.yml` is a disposable proof of one causal path:

```text
sealed closed bars -> strategy -> router -> deterministic local review
  -> SIM-only risk -> durable simulator controller
```

It uses only fixed fixtures, an internal temporary PostgreSQL database, and
installed immutable source revisions. The review gateway is a zero-cost local
test double; it does not create a client, reserve a budget, or contact a
provider.

The gate also persists one typed LLM proposal into the simulator-only
append-only proposal ledger, verifies exact replay idempotency, and proves that
the proposal alone creates neither a risk decision nor a command. It does not
connect a proposal consumer to the strategy or execution pipeline.

Two additional local scenarios pair the independent LLM hypothesis with a
deterministic pure-generator strategy evaluation in the simulator-only research ledger. One
uses a sealed, flat five-symbol tape where the generator emits `NO_INTENT` but
the synthetic LLM proposes a long bias. The other records a short LLM bias
opposite an existing long strategy intent. Both preserve the disagreement
without creating an admission, risk decision, trade, or command; the ordinary
strategy path still requires its separate review and risk gates. The local
evaluation receipts and model responses are deterministic fixtures, not a
production warmup/decision-scheduler proof, historical A/B result, or evidence of alpha.
The gate also creates a local synthetic completion receipt and verifies that
its response was observed before the pair clock. It never invokes an LLM. The
SIM pair ledger does not yet store or independently replay the strategy
evaluation and provider-attempt source receipts; these fixtures cannot be used
as a sealed blind-campaign denominator.

After the fixture tape is sealed, the gate reads the strategy's closed-bar
history back from the bounded persistence page API and requires replay to
produce the byte-identical intent. This verifies durable historical replay;
the fixture is still synthetic and does not qualify a live market-data
recorder or a strategy.

Every outcome is `SIMULATED`. This gate has no credentials, external endpoints,
or durable host storage. It cannot change readiness flags, qualify a strategy,
or authorize a venue action.

The `20260928-r1` project identity is the next current-source snapshot;
artifacts from the earlier `r1` identity remain historical evidence and are not
rewritten.

Before a local run, validate the manifest and rendered Compose model:

```powershell
python scripts/validate_sim_full_path_deployment.py
docker compose --env-file tests/sim_full_path_gate/empty.env -p kairos-sim-full-path-gate-20260928-r1 -f docker-compose.sim-full-path.yml config --format json > compose-sim-full-path.json
python scripts/validate_sim_full_path_deployment.py --compose-json compose-sim-full-path.json --dockerfile tests/sim_full_path_gate/Dockerfile
```

Run only after confirming the exact project label has no existing containers,
networks, or volumes. The CI workflow captures synthetic logs and a database
dump as evidence before the hosted runner is discarded.
