# kairos-deploy

Reproducible, secure-by-default Docker Compose deployment for the Kairos trading
system. Application images are built from reviewed Git commits and each service's
committed `uv.lock`; infrastructure images use immutable tag-plus-digest references.

## What is deployed

| Container | Responsibility | External access |
| --- | --- | --- |
| Redis 8.2.8 | Authenticated Redis Streams bus | None; internal `bus` network only |
| TimescaleDB | Audit/time-series storage schema | None; internal `data` network only |
| Quant/Text Scouts | Market and text inputs | Outbound provider access only |
| Router/Aggregator/Macro/Risk | Decision and safety pipeline | No host ports |
| Execution Engine | EVEDEX execution and account reconciliation | Outbound EVEDEX access only |
| Prometheus/Grafana | Local monitoring | Loopback-only `127.0.0.1` ports |

The source-of-truth revisions are in `sources.lock.json` and are repeated in
`docker-compose.yml` so Docker Compose can resolve each remote named build context.
CI verifies that both files agree and that every remote revision contains Python 3.11,
uv 0.12.3, the expected `kairos-core`/`kairos-llm` Git pins, and a committed lockfile.

## Secret boundaries

`.env` is used by Compose only for interpolation. There is deliberately no `env_file`:
each container receives an explicit allow-list.

- Text Scouts: DeepSeek plus optional Bright Data/Reddit credentials.
- Aggregator: DeepSeek and OpenAI.
- Macro Strategist: OpenAI only.
- Execution Engine: EVEDEX JWT and private key only; its image installs the `evedex`
  optional dependency.
- Quant, Router, Risk, Prometheus, and Grafana never receive LLM or exchange secrets.
- Redis receives its raw password, while clients receive only an authenticated URL.
- PostgreSQL and Grafana credentials are scoped to their own containers.

Compose requires the EVEDEX JWT/private key even while `KAIROS_DRY_RUN=true`. This is an
intentional production-like preflight: a later switch to live mode cannot start with an
incomplete authentication configuration. For an isolated developer dry-run without real
credentials, use clearly synthetic values with the valid shapes documented in
`.env.example`; never reuse them in a live environment.

Environment variables are not a dedicated secret store and can be visible to a host
administrator through container inspection. For production, protect the `.env` file with
host permissions and migrate these values to your orchestrator's secret mechanism before
granting untrusted users Docker access.

## Safety invariants

- Redis and TimescaleDB do not publish host ports.
- Redis requires authentication and exposes an authenticated healthcheck; every Python
  service waits for it to become healthy.
- Redis is pinned to 8.2.8 because `kairos-core` acknowledges stream entries with
  `XACKDEL ref_policy=ACKED`, an 8.2 feature. Downgrading Redis breaks the event ACK path.
- Application containers run as UID/GID `10001`, use read-only root filesystems, drop all
  Linux capabilities, and enable `no-new-privileges`.
- The Risk Manager hard-codes `KAIROS_REQUIRE_RECONCILED_ACCOUNT=true` and
  `KAIROS_REQUIRE_STRATEGIC_ALLOCATION=true` in Compose. These settings cannot be weakened
  through `.env`.
- Execution publishes a full `AccountSnapshot` every 15 seconds by default. Risk accepts
  only reconciled snapshots fresher than 60 seconds; validation enforces that the publish
  cadence is below the freshness window.
- `KAIROS_DRY_RUN=true` is the default, but dry-run is not a substitute for reviewing the
  rendered configuration before startup.

## Windows / PowerShell quick start

Requirements: Docker Desktop with Docker Compose 2.17+ (remote named contexts) and Python
3.11+. Docker BuildKit must be enabled. Docker itself is intentionally not required for the
static validator.

```powershell
Set-Location D:\Kairos\kairos-deploy
Copy-Item .env.example .env

# Replace every placeholder, then verify secret strength and all source pins.
python scripts\validate_deployment.py --env-file .env --verify-remote

# Render and inspect exactly what Compose will send to containers.
docker compose --env-file .env -f docker-compose.yml config --quiet
docker compose --env-file .env -f docker-compose.yml config

# Build and start only after both checks pass.
docker compose --env-file .env -f docker-compose.yml build --pull
docker compose --env-file .env -f docker-compose.yml up --detach
```

On Unix-like hosts, `make validate` uses `.env.example` for secret-free static checks;
the guarded `make preflight`, `make build`, and `make up` targets use the real `.env`.
The old `make clone` flow was removed: local sibling worktrees could be dirty
or on unreviewed branches, while remote full-SHA contexts make image inputs explicit and
reproducible.

## Updating an application revision

1. Review and merge/sign the service repository change, including its `uv.lock`.
2. Replace the full 40-character SHA in both `sources.lock.json` and the matching
   `build.additional_contexts.service` / `SOURCE_REVISION` entries in Compose.
3. Run:

```powershell
python scripts\validate_deployment.py --verify-remote
docker compose --env-file .env.example -f docker-compose.yml config --format json |
  Set-Content -Encoding utf8 .compose.resolved.json
python scripts\validate_deployment.py --compose-json .compose.resolved.json
Remove-Item -LiteralPath .compose.resolved.json
```

4. Build with `--pull` and test in dry-run before considering live execution.

## Operations

```powershell
docker compose --env-file .env -f docker-compose.yml ps
docker compose --env-file .env -f docker-compose.yml logs --follow --tail=100
docker compose --env-file .env -f docker-compose.yml down
```

Grafana is available at `http://127.0.0.1:3000` and Prometheus at
`http://127.0.0.1:9090` unless their loopback ports are changed. No service endpoint is
intentionally exposed to other hosts; add a reviewed authenticated reverse proxy instead of
changing bindings to `0.0.0.0`.

The supplied Prometheus scrape targets are forward-looking: current services include shared
metrics definitions but do not yet start the HTTP metrics server in their service lifecycle.
Prometheus therefore runs correctly but its Kairos targets remain down until that runtime
wiring is implemented in the service repositories.

## Validation coverage and limits

GitHub Actions runs the validator/tests on Python 3.11 and 3.14 across Linux and Windows,
then performs source-pin verification, Compose rendering/security validation, Dockerfile
linting, and a Buildx build of all seven application images. Locally,
`scripts/validate_deployment.py` and the unit tests require only the Python standard library;
Compose rendering needs the Compose CLI but not a running daemon.

Static checks cannot prove exchange credentials, provider credentials, outbound firewall
policy, durable backup/restore, or real Docker runtime behavior. A live deployment still
requires secret-store integration, host hardening, volume backups, resource limits, alerting,
and staged dry-run/canary verification.

Part of [Kairos](https://github.com/Kairos-cryptoAI/kairos). MIT licensed.
