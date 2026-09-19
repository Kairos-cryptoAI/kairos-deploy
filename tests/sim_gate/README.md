# Isolated simulator gate

`docker-compose.sim.yml` is a disposable, offline development gate. It creates
one temporary TimescaleDB database and Redis instance in `tmpfs`, then runs the
durable simulator controller against sealed fixture bars and book frames.

It has no EVEDEX, PAPER, LIVE, LLM, feed, or secret configuration. All results
are `SIMULATED`; this gate cannot alter `PAPER_QUALIFIED`, `ALPHA_READY`, or
`LIVE_READY`.

Before a local run, validate the manifest and render the exact Compose model:

```powershell
python scripts/validate_sim_deployment.py
docker compose --env-file tests/sim_gate/empty.env -p kairos-sim -f docker-compose.sim.yml config --format json > compose-sim.json
python scripts/validate_sim_deployment.py --compose-json compose-sim.json --dockerfile tests/sim_gate/Dockerfile
```

Only run it after confirming that no Docker resource with the
`com.docker.compose.project=kairos-sim` label already exists. The GitHub
workflow makes that check before it starts the temporary services.
