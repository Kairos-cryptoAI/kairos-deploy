[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,
    [string]$ComposeProject = "kairos",
    [string]$ComposeFile = "docker-compose.yml",
    [string]$EnvFile = ".env",
    [string]$DatabaseUser = "kairos"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$manifestFile = (Resolve-Path -LiteralPath $ManifestPath).Path
$manifest = Get-Content -Raw -LiteralPath $manifestFile | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $manifest.sha256 -notmatch '^[0-9a-f]{64}$') {
    throw "Unsupported or malformed backup manifest"
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
$actualProject = (& docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}' $container).Trim()
if ($LASTEXITCODE -ne 0 -or $actualProject -ne $ComposeProject) {
    throw "Resolved container does not belong to Compose project $ComposeProject"
}

$suffix = ([guid]::NewGuid().ToString("N")).Substring(0, 12)
$drillDatabase = "kairos_restore_drill_$suffix"
$containerDump = "/tmp/kairos-restore-$suffix.dump"
try {
    & docker exec $container createdb --username=$DatabaseUser $drillDatabase
    if ($LASTEXITCODE -ne 0) { throw "Could not create isolated drill database" }
    & docker cp $dump "${container}:$containerDump"
    if ($LASTEXITCODE -ne 0) { throw "Could not copy backup into the database container" }
    & docker exec $container pg_restore --exit-on-error --no-owner --no-privileges --username=$DatabaseUser --dbname=$drillDatabase $containerDump
    if ($LASTEXITCODE -ne 0) { throw "pg_restore failed" }

    $migrationCount = (& docker exec $container psql --username=$DatabaseUser --dbname=$drillDatabase --tuples-only --no-align --command="SELECT count(*) FROM schema_migrations;").Trim()
    if ($LASTEXITCODE -ne 0 -or [int]$migrationCount -lt 4) {
        throw "Restored database does not contain all durable-runtime migrations"
    }
    $tableCount = (& docker exec $container psql --username=$DatabaseUser --dbname=$drillDatabase --tuples-only --no-align --command="SELECT count(*) FROM (VALUES (to_regclass('event_audit')), (to_regclass('message_inbox')), (to_regclass('message_outbox')), (to_regclass('execution_effects'))) AS required(name) WHERE name IS NOT NULL;").Trim()
    if ($LASTEXITCODE -ne 0 -or [int]$tableCount -ne 4) {
        throw "Restored database is missing durable-runtime tables"
    }
    Write-Output "Recovery drill passed for $($manifest.file): $migrationCount migrations, $tableCount critical tables"
}
finally {
    & docker exec $container rm -f -- $containerDump 2>$null | Out-Null
    & docker exec $container dropdb --if-exists --force --username=$DatabaseUser $drillDatabase 2>$null | Out-Null
}
