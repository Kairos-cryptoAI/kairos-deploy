[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,
    [string]$ComposeProject = "kairos",
    [string]$ComposeFile = "docker-compose.yml",
    [string]$EnvFile = ".env",
    [string]$Database = "kairos",
    [string]$DatabaseUser = "kairos"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$manifestFile = (Resolve-Path -LiteralPath $ManifestPath).Path
$manifest = Get-Content -Raw -LiteralPath $manifestFile | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $manifest.sha256 -notmatch '^[0-9a-f]{64}$') {
    throw "Unsupported or malformed backup manifest"
}
if ($manifest.compose_project -ne $ComposeProject) {
    throw "Backup manifest belongs to Compose project $($manifest.compose_project), not $ComposeProject"
}
if ($manifest.database -ne $Database) {
    throw "Backup manifest belongs to database $($manifest.database), not $Database"
}
if ($null -eq $manifest.checkpoints) {
    throw "Backup manifest lacks durable data checkpoints"
}
$dump = (Resolve-Path -LiteralPath (Join-Path (Split-Path -Parent $manifestFile) $manifest.file)).Path
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $dump).Hash.ToLowerInvariant()
if ($hash -ne $manifest.sha256 -or (Get-Item -LiteralPath $dump).Length -ne $manifest.bytes) {
    throw "Backup file does not match its manifest"
}
$composePath = (Resolve-Path -LiteralPath (Join-Path $root $ComposeFile)).Path
$envPath = (Resolve-Path -LiteralPath (Join-Path $root $EnvFile)).Path
$compose = @("compose", "-p", $ComposeProject, "--env-file", $envPath, "-f", $composePath)
$container = (& docker @compose ps -q timescaledb).Trim()
if ($LASTEXITCODE -ne 0 -or $container -notmatch '^[0-9a-f]{64}$') {
    throw "A single running TimescaleDB container is required"
}
$labelJson = (& docker inspect --format '{{json .Config.Labels}}' $container).Trim()
if ($LASTEXITCODE -ne 0 -or -not $labelJson) {
    throw "Could not inspect the TimescaleDB Compose labels"
}
$actualProject = ($labelJson | ConvertFrom-Json).'com.docker.compose.project'
if ($actualProject -ne $ComposeProject) {
    throw "Resolved container does not belong to Compose project $ComposeProject"
}

$suffix = ([guid]::NewGuid().ToString("N")).Substring(0, 12)
$drillDatabase = "kairos_restore_drill_$suffix"
$containerDump = "/tmp/kairos-restore-$suffix.dump"
try {
    & docker exec $container createdb --username=$DatabaseUser $drillDatabase
    if ($LASTEXITCODE -ne 0) { throw "Could not create isolated drill database" }
    & docker exec $container psql --username=$DatabaseUser --dbname=$drillDatabase --set=ON_ERROR_STOP=1 --command="CREATE EXTENSION IF NOT EXISTS timescaledb;"
    if ($LASTEXITCODE -ne 0) { throw "Could not initialize TimescaleDB in the drill database" }
    & docker exec $container psql --username=$DatabaseUser --dbname=$drillDatabase --set=ON_ERROR_STOP=1 --command="SELECT timescaledb_pre_restore();"
    if ($LASTEXITCODE -ne 0) { throw "Could not enter TimescaleDB restore mode" }
    & docker cp $dump "${container}:$containerDump"
    if ($LASTEXITCODE -ne 0) { throw "Could not copy backup into the database container" }
    & docker exec $container pg_restore --exit-on-error --no-owner --no-privileges --username=$DatabaseUser --dbname=$drillDatabase $containerDump
    if ($LASTEXITCODE -ne 0) { throw "pg_restore failed" }
    & docker exec $container psql --username=$DatabaseUser --dbname=$drillDatabase --set=ON_ERROR_STOP=1 --command="SELECT timescaledb_post_restore();"
    if ($LASTEXITCODE -ne 0) { throw "Could not leave TimescaleDB restore mode" }

    $migrationCount = (& docker exec $container psql --username=$DatabaseUser --dbname=$drillDatabase --tuples-only --no-align --command="SELECT count(*) FROM schema_migrations;").Trim()
    if ($LASTEXITCODE -ne 0 -or [int]$migrationCount -lt 11) {
        throw "Restored database does not contain all durable-runtime migrations"
    }
    $requiredTables = @(
        "event_audit",
        "message_inbox",
        "message_outbox",
        "account_snapshots",
        "position_snapshots",
        "source_cursors",
        "source_usage_reservations",
        "execution_effects",
        "execution_effect_events",
        "execution_trades",
        "execution_trade_events",
        "execution_recovery_state",
        "account_equity_state",
        "public_execution_events",
        "paper_canary_arms",
        "execution_runtime_health",
        "execution_mutation_budget_scopes",
        "execution_mutation_reservations"
    )
    $tableValues = ($requiredTables | ForEach-Object { "(to_regclass('$_'))" }) -join ","
    $tableQuery = "SELECT count(*) FROM (VALUES $tableValues) AS required(name) WHERE name IS NOT NULL;"
    $tableCount = (& docker exec $container psql --username=$DatabaseUser --dbname=$drillDatabase --tuples-only --no-align --command=$tableQuery).Trim()
    if ($LASTEXITCODE -ne 0 -or [int]$tableCount -ne $requiredTables.Count) {
        throw "Restored database is missing PAPER durable-runtime tables"
    }
    $checkpointTables = @(
        "event_audit",
        "message_inbox",
        "message_outbox",
        "execution_orders",
        "account_snapshots",
        "position_snapshots",
        "source_cursors",
        "source_usage_reservations",
        "execution_effects",
        "execution_effect_events",
        "execution_trades",
        "execution_trade_events",
        "execution_recovery_state",
        "public_execution_events",
        "account_equity_state",
        "paper_canary_arms",
        "execution_runtime_health",
        "execution_mutation_budget_scopes",
        "execution_mutation_reservations"
    )
    foreach ($table in $checkpointTables) {
        $expected = $manifest.checkpoints.$table
        if ($null -eq $expected -or [long]$expected -lt 0) {
            throw "Backup manifest has no valid checkpoint for $table"
        }
        $actual = (& docker exec $container psql --username=$DatabaseUser --dbname=$drillDatabase --tuples-only --no-align --command="SELECT count(*) FROM $table;").Trim()
        if ($LASTEXITCODE -ne 0 -or $actual -notmatch '^\d+$' -or [long]$actual -ne [long]$expected) {
            throw "Restored row count differs for $table"
        }
    }
    $expectedSequence = $manifest.checkpoints.public_execution_events_max_sequence
    $actualSequence = (& docker exec $container psql --username=$DatabaseUser --dbname=$drillDatabase --tuples-only --no-align --command="SELECT COALESCE(max(event_seq),0) FROM public_execution_events;").Trim()
    if ($null -eq $expectedSequence -or $LASTEXITCODE -ne 0 -or $actualSequence -notmatch '^\d+$' -or [long]$actualSequence -ne [long]$expectedSequence) {
        throw "Restored public execution sequence differs from the backup manifest"
    }
    Write-Output "Recovery drill passed for $($manifest.file): $migrationCount migrations, $tableCount critical tables"
}
finally {
    & docker exec --user=root $container rm -f -- $containerDump 2>$null | Out-Null
    & docker exec $container dropdb --if-exists --force --username=$DatabaseUser $drillDatabase 2>$null | Out-Null
}
