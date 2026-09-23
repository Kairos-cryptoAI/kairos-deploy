# Current-source REJECT_ALL gate

This is a single-process, deterministic evidence gate for the source set in
`../../current-release-gate.sources.lock.json`. It is deliberately not a trading,
venue, provider, simulator, or research-runner workflow.

The test passes a fixed closed-bar fixture through Strategy, Router, Aggregator,
Risk and Execution. Its local review double fails, so the required result is
`DEFER` followed by deterministic `REJECT_ALL`, zero venue access and zero effects.
That proves the current source identity preserves the prohibition; it does not
measure alpha, authorize an exchange, or replace EVEDEX DEV qualification.

The runtime container is read-only, uses one internal-only Compose network, has no
ports, volumes, secrets, `.env`, database, Redis, provider configuration or real
credentials. Docker may fetch immutable public Git revisions only while building.
The bundled `source-lock.json` is verified byte-for-byte against the canonical root
lock before build and again by the static gate.

The `20260923-r2` project identity is the next source snapshot; artifacts from
the earlier `r1` identity remain historical evidence and are not rewritten.

Run the static checks from `D:\Kairos\kairos-deploy`:

```powershell
python scripts/validate_current_release_gate.py
docker compose -p kairos-current-release-gate-20260923-r2 -f docker-compose.current-release-gate.yml config --quiet
```

The Docker test is a one-shot operation only after confirming the Compose project
has no existing resources:

```powershell
docker compose -p kairos-current-release-gate-20260923-r2 -f docker-compose.current-release-gate.yml build gate
docker compose -p kairos-current-release-gate-20260923-r2 -f docker-compose.current-release-gate.yml up --no-deps gate
```

Do not reuse this project name for PAPER, research data or a long-running service.
