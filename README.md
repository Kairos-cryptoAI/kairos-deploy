# kairos-deploy

Reproducible, fail-closed Docker Compose deployment for Kairos. Application images are
built from reviewed full Git SHAs and committed `uv.lock` files; infrastructure images
are pinned by tag and digest.

## Recovering an offline Binance bar gap

Use `scripts/Invoke-LongGapRecovery.ps1` only for `kairos-paper-gate`, with its
explicit `-EnvFile`, a closed UTC `-EndExclusiveMs` and `-MaximumBars` (at most
150000), and the exact `-ExpectedDatabaseName`. Stop quant, strategy, risk and any execution/canary consumers first,
preserve a new PostgreSQL backup, and build the manifest-pinned quant image.
The wrapper refuses any active non-infrastructure service or stale image.
`-ValidateOnly` checks these conditions without launching data repair.
For a resumable bounded increment, pass `-MaximumAppendBars` no greater than
`-MaximumBars` and retain the same fixed end boundary for each invocation.

Before an original database is repaired, run the backup through
`Test-Recovery.ps1 -RuntimePreflight`.  It restores only a disposable drill clone,
checks the exact offline `001`--`012` migration profile, five contiguous Binance
bar prefixes, inbox/outbox identity and advisory leases, then emits a sanitized
receipt beside the immutable backup.  An expired outbox lease is recorded rather
than silently cleared: it blocks restarting read-only consumers, but does not
permit a dispatcher or any trading service to start during the offline repair.

The actual job uses only the existing infrastructure secrets and public Binance
REST. It verifies a contiguous persisted prefix and two identical REST responses
per page, then writes through an isolated atomic audit/outbox writer. The writer
requires exactly migrations `001` through `012`, never performs a migration or
starts Redis/outbox dispatch, and holds the migration guard plus the shared
PostgreSQL producer lease. No strategy, venue order, paid API, secret import or
cursor deletion is performed. Output records start, per-symbol progress/retrieval
time and completion/failure. Run long jobs in a hidden supervised process with
preserved stdout/stderr.

After completion, independently verify bar continuity and pending outbox state
before restarting only the previously stopped read-only services. Do not count
retrospective recovery as uninterrupted uptime or a 24-hour DEV qualification.
`scripts/Test-LongGapRecovery.ps1` checks offline preflight; the separate Docker
integration harness requires an explicitly disposable `kairos_gap_drill_*`
database, seeds its exact `001`--`012` profile outside the writer, and validates
commit-before-ACK recovery, deduplication and the exclusive offline-writer lease.

## Exact offline outbox reconciliation

An expired outbox lease is not a licence to restart a dispatcher or replay a
queue. [`docker-compose.outbox-reconciliation.yml`](docker-compose.outbox-reconciliation.yml)
is an entirely separate, profile-only recovery tool. A normal `docker compose up`
starts neither of its services. The default `offline-outbox-inspect` profile sees
only a supplied internal PostgreSQL network and opens a read-only transaction for
one fully specified row. It writes a redacted, SHA-256-bound inspection receipt;
it never sends to Redis.

The distinct `offline-outbox-apply` profile is not a bulk repair mechanism. Its
wrapper, [`Invoke-OfflineOutboxReconciliation.ps1`](scripts/Invoke-OfflineOutboxReconciliation.ps1),
requires a supplied exact expectation containing every immutable row field, a
fresh receipt (maximum five minutes), its exact SHA-256, a detached signature by
the reviewed local GPG signer, and an explicit `-ArmApply`. Before it can attach
the one-shot container, it verifies that the supplied Docker-internal data and
bus networks contain only TimescaleDB and Redis, and that every producer,
consumer, collector and execution service is stopped. The runner calls the
version-pinned persistence exact-row API once only. A transport or ACK ambiguity
ends as `PUBLISH_OUTCOME_UNKNOWN`; it is quarantined by persistence and is never
retried by the wrapper.

This repository contains no row-specific authority, including no default outbox
ID. The profile has no egress network, no ports, no volume, no background
dispatcher, and no EVEDEX, provider or general PAPER secrets. It is unexecuted
engineering support until a future independently authorized recovery procedure.

## Signed bounded outbox drain

[`docker-compose.outbox-drain.yml`](docker-compose.outbox-drain.yml) is a
separate recovery-only tool for the backlog *after* an expired lease has been
resolved by the exact-row procedure above. It cannot run against the historical
`001`--`012` recovery profile: the inspector requires the explicitly reviewed
`001`--`018` schema, including the durable `PUBLISHING` and
`PUBLISH_OUTCOME_UNKNOWN` states. Reaching that profile therefore requires a
separate backuped, reviewed migration window; the drain never runs migrations.

Its v1 scope is intentionally narrow: only the precommitted
`kairos-quant-scouts` prefix on `kairos.market.closed_bar.v1`, at most 100 rows
and 300 seconds per signed plan. The read-only inspector records a redacted,
ordered exact prefix. Apply requires its fresh (five-minute), detached-GPG-signed
receipt, exact file SHA-256, and `-ArmApply`. Each row becomes durable
`PUBLISHING` before one Redis publish attempt. A Redis timeout, cancellation, or
database ACK uncertainty becomes `PUBLISH_OUTCOME_UNKNOWN` and ends the whole
run; no wrapper retry or ordinary dispatcher is permitted.

The acceptance receipt proves only Redis submission and durable ACK for the
signed prefix. It is not evidence that downstream services processed the bars,
does not restart consumers, and cannot change PAPER, alpha, or LIVE readiness.

## Runtime topology

| Container | Responsibility | External access |
| --- | --- | --- |
| Redis 8.2.8 | Authenticated durable Streams transport | Internal `bus` only |
| TimescaleDB | Inbox/outbox, audit, snapshots, execution journal | Internal `data` only |
| Eight application services | Shared Strategy Engine plus signal-to-execution pipeline | Allow-listed egress only |
| Ops exporter | Read-only durable state and Redis health metrics | Internal; optional verified loopback |
| Prometheus/Grafana | Alerts and dashboards | Internal; optional verified loopback |

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

The base Compose file explicitly selects `TradingMode=DRY_RUN` and does not mount EVEDEX
credentials. [`docker-compose.live.yml`](docker-compose.live.yml) is deliberately inert: it
only selects `TradingMode=LIVE`, which the pinned runtime rejects at startup. Static LIVE JWT
or private-key provisioning is retired, and the validator rejects those mounts and bindings.
The file therefore documents and tests the fail-closed boundary; it is not a launch recipe:

```powershell
docker compose --env-file .env -f docker-compose.yml -f docker-compose.live.yml config --format json |
  Set-Content -Encoding utf8 .compose.live.resolved.json
python scripts\validate_deployment.py --compose-json .compose.live.resolved.json --live
```

Do not start that overlay. A future LIVE design requires a separate readiness review and a
managed KMS/Vault signing boundary after authenticated EVEDEX qualification,
basis/liquidity observation, LLM/feed qualification, PAPER soak, backup, and recovery gates
all pass. Local Docker secret files are reserved for DEV PAPER and provider qualification;
they are not an encrypted enterprise vault.

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
capabilities, `no-new-privileges`, internal Redis/Timescale networks, internal Compose
metrics access (and loopback-only ports when an engine actually publishes them),
authenticated Redis health checks, bounded logs, reconciliation and strategic-allocation
gates, and EVEDEX credentials absent from base execution.

## Qualification tools

These tools never place orders and always emit `live_orders_allowed=false`:

- `kairos-evedex-qualify`: public market/auth/account/reconciliation/rate-limit semantics.
- `kairos-venue-compare`: timestamped Binance-versus-EVEDEX basis, spread, depth, and
  executable-slippage samples.
- `kairos-llm-qualify`: workload/model resolution, structured-output quality, latency,
  token usage, quotas, availability, and modeled cost. Route selection and a
  preflight cost ceiling prevent a diagnostic retry from recalling models that
  already passed.
- `kairos-feed-qualify`: feed availability/freshness/latency; official X reads
  require a separate explicit flag and hard per-run cost cap.

Credentials are accepted from file paths by those CLIs. Keep full reports outside Git;
commit only reviewed redacted summaries if needed.

The X qualification allocation is hard-capped at `$2`. DeepSeek and OpenAI shadow
calls use provider-wide PostgreSQL ledgers capped at `$1` and `$12` respectively
across Text Scouts, Aggregator and Macro; these are not separate per-service budgets.
The remaining funded balances are deliberately outside this qualification authority.

## Isolated EVEDEX DEV PAPER

`docker-compose.paper.yml` is a separate `kairos-paper` project with its own Redis,
TimescaleDB, volumes and secret names. It starts no Text Scouts, Router, Aggregator,
Macro or paid API client. Strategy Engine is pinned to an empty strategy allow-list,
so `ALPHA_READY=false` remains a hard `REJECT_ALL` boundary. The only pre-alpha
mutation path is the one-shot, manually armed `technical-canary@1` controller.

Prepare a dedicated interpolation file and secret directory without editing or
mounting the original labelled provider file:

```powershell
Copy-Item .env.paper.example .env.paper
python scripts\provision_secrets.py --secrets-dir secrets-paper --initialize-infrastructure
python scripts\provision_secrets.py --secrets-dir secrets-paper `
  --import-labelled-file C:\path\to\API.txt `
  --import-name evedex_dev_api_key --import-name evedex_dev_private_key
python scripts\provision_secrets.py --secrets-dir secrets-paper --paper
```

Set only the dedicated local and remote DEV account identities in `.env.paper`, then
validate the full profile (including the normally inactive canary controller) and start
the read-only observation topology:

```powershell
docker compose --profile canary --env-file .env.paper -f docker-compose.paper.yml config --format json |
  Set-Content -Encoding utf8 .compose.paper.resolved.json
python scripts\validate_paper_deployment.py --compose-json .compose.paper.resolved.json `
  --env-file .env.paper --verify-remote
docker compose --env-file .env.paper -f docker-compose.paper.yml up --detach
```

The absence of `--profile canary` from `up` is intentional. A preview is non-mutating;
publication requires both flags and the exact phrase, and creates at most one bounded
candidate for the selected symbol:

```powershell
docker compose --env-file .env.paper -f docker-compose.paper.yml run --rm `
  canary-controller kairos-paper-canary --symbol BTCUSDT --side LONG

docker compose --env-file .env.paper -f docker-compose.paper.yml run --rm `
  canary-controller kairos-paper-canary --symbol BTCUSDT --side LONG `
  --publish --arm "ARM EVEDEX DEV PAPER CANARY"
```

Do not publish the second command until the 24-hour read-only gate passes. Complete the
five protected round trips and required stop/target/timeout/cancel/restart coverage. The
acceptance evaluator reads one repeatable, read-only TimescaleDB snapshot and writes only a
sanitized report; its `PASS` is required before the seven-day PAPER soak:

```powershell
python scripts\paper_canary_acceptance.py `
  --account-id kairos-paper-dev-01 `
  --compose-file docker-compose.paper.yml --env-file .env.paper
```

These are elapsed operational gates; successful builds or synthetic tests do not satisfy
them and never enable `LIVE`.

```powershell
python scripts\soak_reconnect.py --paper `
  --metrics-via-compose `
  --duration-s 86400 --interval-s 5 --minimum-availability 0.99 `
  --compose-project kairos-paper --compose-file docker-compose.paper.yml `
  --env-file .env.paper --report reports/paper-read-only-24h.json
```

The rolling 24-hour evidence window may mature during this same observation. The final
sample must satisfy every PAPER gate, while any observed irreversible integrity failure
(gap, dead letter, failed effect, unprotected trade, unsafe mutation configuration or
budget overrun) remains terminal for the run.

## Monitoring and reconnect soak

The ops exporter exposes only aggregate durable state: Redis availability, inbox/outbox
failures and backlog, oldest pending age, and unresolved execution effects. Base DRY_RUN
Prometheus loads [`monitoring/alerts.base.yml`](monitoring/alerts.base.yml); isolated PAPER
loads the stricter [`monitoring/alerts.yml`](monitoring/alerts.yml). Grafana is provisioned
with the internal Prometheus datasource.

```powershell
python scripts\soak_reconnect.py `
  --metrics-via-compose `
  --duration-s 1800 --interval-s 5 `
  --restart-at-s 300 --restart-redis `
  --compose-project kairos --env-file .env `
  --report reports/soak-reconnect.json
```

Redis restart is never implicit: both `--restart-at-s` and `--restart-redis` are required.
The report fails if Redis does not recover or any terminal durable failure counter is
non-zero. A 30-minute local pass is a staging check, not proof of production reliability;
use a substantially longer soak before capital is enabled.

The Compose metrics transport is the qualification default on Docker Desktop. Docker does
not expose published ports from containers attached only to internal bridge networks on
that platform. Reading the exporter with `docker compose exec` preserves the internal
network boundary. `--metrics-url` remains available for engines where a verified loopback
publication is reachable; never make the observability networks externally routable just
to satisfy the probe.

## Backup and recovery drill

Backups use PostgreSQL custom format and a SHA-256 manifest. Recovery is always into a
new random `kairos_restore_drill_*` database, validates all migrations and critical
durable tables, then drops only that drill database.

```powershell
$manifest = scripts\Backup-Kairos.ps1 -ComposeProject kairos
scripts\Test-Recovery.ps1 -ManifestPath $manifest -ComposeProject kairos
```

For the isolated PAPER project, both the project and database identity are explicit and
must match the integrity manifest:

```powershell
$manifest = scripts\Backup-Kairos.ps1 -ComposeProject kairos-paper-gate `
  -ComposeFile docker-compose.paper.yml -EnvFile ..\runtime\paper-gate\.env.paper -Database kairos
scripts\Test-Recovery.ps1 -ManifestPath $manifest -ComposeProject kairos-paper-gate `
  -ComposeFile docker-compose.paper.yml -EnvFile ..\runtime\paper-gate\.env.paper -Database kairos `
  -RuntimePreflight
```

The preflight receipt must be a PASS before `Invoke-LongGapRecovery.ps1` is
considered.  It is a recovery fact, not a read-only uptime receipt or a PAPER
qualification: no application service may be restarted until pending/expired
outbox effects have separately been reconciled.

Copy backup plus manifest to encrypted off-host storage under a separate retention policy.
The local script does not itself provide encryption, scheduling, or remote replication.

## Known qualification boundary

Static checks and synthetic tests cannot validate real provider credentials or guarantee
exchange behavior. The checked-in state contains no authenticated canary result and no
completed elapsed gate, so read-only observation is the current maximum permitted state.
After the 24-hour read-only gate passes, an operator may manually arm one bounded technical
canary on EVEDEX DEV; this permission does not enable an alpha strategy. Paid LLM/feed
qualification and the seven-day soak remain separate pending gates. LIVE and real-funds
orders remain prohibited independently of canary or strategy results.

Part of [Kairos](https://github.com/Kairos-cryptoAI/kairos). MIT licensed.
