# kairos-deploy

Reproducible, fail-closed Docker Compose deployment for Kairos. Application images are
built from reviewed full Git SHAs and committed `uv.lock` files; infrastructure images
are pinned by tag and digest.

## Runtime topology

| Container | Responsibility | External access |
| --- | --- | --- |
| Redis 8.2.8 | Authenticated durable Streams transport | Internal `bus` only |
| TimescaleDB | Inbox/outbox, audit, snapshots, execution journal | Internal `data` only |
| Seven application services | Signal-to-execution pipeline | Allow-listed egress only |
| Ops exporter | Read-only durable state and Redis health metrics | Loopback port 9108 |
| Prometheus/Grafana | Alerts and dashboards | Loopback ports 9090/3000 |

Every application service mounts authenticated Redis and PostgreSQL URLs as Docker
secret files. It waits for both stores, migrates the same durable schema, records inbound
processing, commits state and outbound messages atomically, and only then acknowledges
the Redis delivery. Execution additionally journals venue mutations before submission and
reconciles unresolved effects before accepting new risk.

The immutable source inventory is [`sources.lock.json`](sources.lock.json). CI verifies
the matching remote commit, Python/uv pins, dependency SHAs, lockfile, package path, and
entry point before building each image.

## Secrets and live boundary

`.env` contains only non-secret Compose interpolation. Secret values are one-value files
under the ignored `secrets/` directory and are loaded by the container entrypoint without
appearing in `docker inspect` environment metadata.

```powershell
Set-Location D:\Kairos\kairos-deploy
Copy-Item .env.example .env
python scripts\provision_secrets.py --initialize-infrastructure
python scripts\provision_secrets.py --prompt deepseek_api_key --prompt openai_api_key --prompt x_bearer_token
python scripts\provision_secrets.py
```

An existing local labelled provider file can be imported without placing secret values on the
command line or printing them. Only explicitly selected labels are accepted, destination files
are created exclusively, and unknown lines are ignored:

```powershell
python scripts\provision_secrets.py `
  --import-labelled-file C:\path\to\API.txt `
  --import-name deepseek_api_key `
  --import-name openai_api_key `
  --import-name x_bearer_token
```

The base Compose file is always dry-run and does not mount EVEDEX credentials. Live mode
is a separate [`docker-compose.live.yml`](docker-compose.live.yml) overlay. To prepare it,
store the credentials through the non-echoing prompt, then run:

```powershell
python scripts\provision_secrets.py --prompt evedex_jwt --prompt evedex_private_key
python scripts\provision_secrets.py --live
docker compose --env-file .env -f docker-compose.yml -f docker-compose.live.yml config --quiet
```

Do not start that overlay until authenticated EVEDEX qualification, basis/liquidity
observation, LLM/feed qualification, dry-run soak, backup, and recovery gates all pass.
Local Docker secret files improve scope and inspection safety but are not an encrypted
enterprise vault; a remote deployment should provide the same `/run/secrets/*` contract
from its managed KMS/Vault/Swarm/Kubernetes secret backend.

## Build and dry-run

Requirements: Docker Desktop with Compose 2.17+ and Python 3.11+.

```powershell
python scripts\validate_deployment.py --env-file .env --verify-remote
docker compose --env-file .env -f docker-compose.yml config --format json |
  Set-Content -Encoding utf8 .compose.resolved.json
python scripts\validate_deployment.py --compose-json .compose.resolved.json
docker compose --env-file .env -f docker-compose.yml build --pull
docker compose --env-file .env -f docker-compose.yml up --detach
```

Safety invariants include read-only application roots, UID/GID 10001, no Linux
capabilities, `no-new-privileges`, internal Redis/Timescale networks, loopback-only
operations ports, authenticated Redis health checks, bounded logs, reconciliation and
strategic-allocation gates, and EVEDEX credentials absent from base execution.

## Qualification tools

These tools never place orders and always emit `live_orders_allowed=false`:

- `kairos-evedex-qualify`: public market/auth/account/reconciliation/rate-limit semantics.
- `kairos-venue-compare`: timestamped Binance-versus-EVEDEX basis, spread, depth, and
  executable-slippage samples.
- `kairos-llm-qualify`: workload/model resolution, structured-output quality, latency,
  token usage, quotas, availability, and modeled cost.
- `kairos-feed-qualify`: feed availability/freshness/latency; metered Bright Data probing
  requires a separate explicit flag.

Credentials are accepted from file paths by those CLIs. Keep full reports outside Git;
commit only reviewed redacted summaries if needed.

## Monitoring and reconnect soak

The ops exporter exposes only aggregate durable state: Redis availability, inbox/outbox
failures and backlog, oldest pending age, and unresolved execution effects. Prometheus
loads [`monitoring/alerts.yml`](monitoring/alerts.yml); Grafana is provisioned with the
internal Prometheus datasource.

```powershell
python scripts\soak_reconnect.py `
  --metrics-url http://127.0.0.1:9108/metrics `
  --duration-s 1800 --interval-s 5 `
  --restart-at-s 300 --restart-redis `
  --compose-project kairos --env-file .env `
  --report reports/soak-reconnect.json
```

Redis restart is never implicit: both `--restart-at-s` and `--restart-redis` are required.
The report fails if Redis does not recover or any terminal durable failure counter is
non-zero. A 30-minute local pass is a staging check, not proof of production reliability;
use a substantially longer soak before capital is enabled.

## Backup and recovery drill

Backups use PostgreSQL custom format and a SHA-256 manifest. Recovery is always into a
new random `kairos_restore_drill_*` database, validates all migrations and critical
durable tables, then drops only that drill database.

```powershell
$manifest = scripts\Backup-Kairos.ps1 -ComposeProject kairos
scripts\Test-Recovery.ps1 -ManifestPath $manifest -ComposeProject kairos
```

Copy backup plus manifest to encrypted off-host storage under a separate retention policy.
The local script does not itself provide encryption, scheduling, or remote replication.

## Known qualification boundary

Static checks and synthetic tests cannot validate real provider credentials or guarantee
exchange behavior. As of the checked-in operational work, public EVEDEX discovery and a
short cross-venue sample pass, while authenticated EVEDEX, paid LLM calls, fresh feed
availability, provider quotas, and longer-duration soak still require the operator's real
credentials and elapsed observation time. Until those reports pass, dry-run/shadow is the
maximum permitted state; live orders remain prohibited independently of strategy results.

Part of [Kairos](https://github.com/Kairos-cryptoAI/kairos). MIT licensed.
