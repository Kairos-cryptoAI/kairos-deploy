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
its response was observed before the pair clock. It never invokes an LLM.
Those legacy pair fixtures do not independently store or replay the strategy
evaluation and provider-attempt source receipts; they remain geometry-only
evidence and cannot be used as a sealed blind-campaign denominator.

Separate independent-source cases now compose the existing
`ResearchEvidenceRepository` and `ResearchProposalCoordinator` against the
disposable PostgreSQL database. They bind the roster to the actual sealed tape,
installed Strategy source-tree/config fingerprints, and exact saved decision
bar. A fresh generator run uses only DB-replayed bars up to the decision clock;
its actual intent or no-intent output is saved as an independent evaluation
receipt. A deterministic local proposal double can respond only after the
durable START is committed, and its references resolve to independently stored
source bytes. Both the wait/long-bias and long/short-bias cases preserve the
conflict without creating risk decisions, admissions, trades, commands, or
results. Late source observations and unknown source/evaluator hashes are
rejected before local dispatch. Restart replays the exact START/terminal/sample
without another response or reservation. Other arms are explicitly
`NOT_CALLED`, not fabricated review outcomes.

The resulting source-qualified seal is only
`INDEPENDENT_SOURCE_REPLAY_ONLY`; economic qualification, PAPER qualification,
and LIVE orders remain false. Its source/evaluation/attempt receipt roster
hashes are verified separately. Synthetic token usage and price-table amounts
exercise budget validation in an in-memory double only: they are neither paid
API calls nor mutations of the real provider-spend ledger. This is not a
production scheduler, real-feed recorder, completed matched A/B campaign, or
sealed scientific pass.

The adaptive-protocol case additionally registers one fixed
`ResearchObservationScheduleV1` and its exact three-arm
`AdaptiveCandidateProtocolV1` through the SIM-only Persistence repositories.
Each arm result carries the digest of its frozen arm, and the coverage seal
records both the schedule and candidate-protocol digests. The fixture marks
LLM arms `NOT_CALLED`; provider/model strings only identify the preregistered
candidate and are never used to construct a provider client. The test checks
that sealing leaves SIM risk decisions, admissions, trades, commands, results,
and all readiness fields unchanged. This proves storage and identity linkage,
not model quality, an outcome comparison, or authorization.

After the fixture tape is sealed, the gate reads the strategy's closed-bar
history back from the bounded persistence page API and requires replay to
produce the byte-identical intent. This verifies durable historical replay;
the fixture is still synthetic and does not qualify a live market-data
recorder or a strategy.

The additional exit cases use the same real Strategy -> Router -> local review
-> SIM risk -> durable controller path for target, timeout, and absence of a
fresh exit book. They persist the exit command before logical arrival, restart
the database connection/controller, and recover only that prepared command.
The timeout fixture retains the existing 72-hour exit plan and supplies every
intervening flat synthetic minute using the replay clock; it does not wait 72
hours or modify Trial 15. Target/timeout fills require the saved causal book.
With no fresh exit book the old entry book is stale, so no synthetic exit fill
is produced and the position remains honestly `UNRESOLVED`. Duplicate closed
bars/recovery preserve the terminal receipt, three lifecycle events, exactly
two commands and one result; source and readiness gates remain unchanged.

Every outcome is `SIMULATED`. This gate has no credentials, external endpoints,
or durable host storage. It cannot change readiness flags, qualify a strategy,
or authorize a venue action.

The `20260928-r4` project identity is this current-source snapshot;
artifacts from earlier `r1` and `r2` identities remain historical evidence
and are not rewritten.

Before a local run, validate the manifest and rendered Compose model:

```powershell
python scripts/validate_sim_full_path_deployment.py
docker compose --env-file tests/sim_full_path_gate/empty.env -p kairos-sim-full-path-gate-20260928-r4 -f docker-compose.sim-full-path.yml config --format json > compose-sim-full-path.json
python scripts/validate_sim_full_path_deployment.py --compose-json compose-sim-full-path.json --dockerfile tests/sim_full_path_gate/Dockerfile
```

Run only after confirming the exact project label has no existing containers,
networks, or volumes. The CI workflow captures synthetic logs and a database
dump as evidence before the hosted runner is discarded.
