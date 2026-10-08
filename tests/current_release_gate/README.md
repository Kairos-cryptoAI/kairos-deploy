# Current-source REJECT_ALL gate

This is a single-process, deterministic evidence gate for the source set in
`../../current-release-gate.sources.lock.json`. It is deliberately not a trading,
venue, provider, simulator, or research-runner workflow.

The test passes a fixed closed-bar fixture through Strategy, Router, Aggregator,
Risk and Execution. Its local review double fails, so the required result is
`DEFER` followed by deterministic `REJECT_ALL`, zero venue access and zero effects.
That proves the current source identity preserves the prohibition; it does not
measure alpha, authorize an exchange, or replace EVEDEX DEV qualification.

A separate refusal case generates a real `adaptive_pullback_range_v1` candidate
from a synthetic causal tape with the installed Strategy adapter. It traverses
Router, local failing review, Risk and Execution and must retain zero quantity,
zero venue access and zero effects. This proves isolation of the new candidate,
not its profitability or enrollment in a research campaign.

This refusal fixture deliberately calls the explicit legacy engineering review
API; it does not qualify the new mandatory context service. The separate
`text_macro_router_gate` tests cover the new immutable causal context boundary.

The runtime container is read-only, uses one internal-only Compose network, has no
ports, volumes, secrets, `.env`, database, Redis, provider configuration or real
credentials. Docker may fetch immutable public Git revisions only while building.
The bundled `source-lock.json` is verified byte-for-byte against the canonical root
lock before build and again by the static gate.

The `20261008-r8` project identity is this source snapshot; artifacts from
earlier `r1`, `r2`, `20260928-r4`, `20261006-r5`, `20261006-r6` and `20261006-r7` identities remain historical evidence and
are not rewritten.

Run the static checks from `D:\Kairos\kairos-deploy`:

```powershell
python scripts/validate_current_release_gate.py
docker compose --env-file tests/sim_full_path_gate/empty.env -p kairos-current-release-gate-20261008-r8 -f docker-compose.current-release-gate.yml config --quiet
```

The Docker test is a one-shot operation only after confirming the Compose project
has no existing resources:

```powershell
docker compose --env-file tests/sim_full_path_gate/empty.env -p kairos-current-release-gate-20261008-r8 -f docker-compose.current-release-gate.yml build gate
docker compose --env-file tests/sim_full_path_gate/empty.env -p kairos-current-release-gate-20261008-r8 -f docker-compose.current-release-gate.yml up --no-deps gate
```

Do not reuse this project name for PAPER, research data or a long-running service.
