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

Every outcome is `SIMULATED`. This gate has no credentials, external endpoints,
or durable host storage. It cannot change readiness flags, qualify a strategy,
or authorize a venue action.

The `20260920-r2` project identity is a new current-source snapshot; artifacts
from the earlier `r1` identity remain historical evidence and are not rewritten.

Before a local run, validate the manifest and rendered Compose model:

```powershell
python scripts/validate_sim_full_path_deployment.py
docker compose --env-file tests/sim_full_path_gate/empty.env -p kairos-sim-full-path-gate-20260920-r2 -f docker-compose.sim-full-path.yml config --format json > compose-sim-full-path.json
python scripts/validate_sim_full_path_deployment.py --compose-json compose-sim-full-path.json --dockerfile tests/sim_full_path_gate/Dockerfile
```

Run only after confirming the exact project label has no existing containers,
networks, or volumes. The CI workflow captures synthetic logs and a database
dump as evidence before the hosted runner is discarded.
