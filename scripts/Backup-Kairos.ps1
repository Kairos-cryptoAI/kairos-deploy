[CmdletBinding()]
param(
    [string]$ComposeProject = "kairos",
    [string]$ComposeFile = "docker-compose.yml",
    [string]$EnvFile = ".env",
    [string]$OutputDirectory = "backups",
    [string]$Database = "kairos",
    [string]$DatabaseUser = "kairos"
)

$ErrorActionPreference = "Stop"
if ($ComposeProject -notmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$') {
    throw "ComposeProject contains unsupported filename characters"
}
$root = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$composePath = (Resolve-Path -LiteralPath (Join-Path $root $ComposeFile)).Path
$envPath = (Resolve-Path -LiteralPath (Join-Path $root $EnvFile)).Path
$backupRoot = Join-Path $root $OutputDirectory
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
$backupRoot = (Resolve-Path -LiteralPath $backupRoot).Path
if (-not $backupRoot.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Backup output must remain inside the deployment repository"
}

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
function Get-DatabaseCheckpoints {
    $result = [ordered]@{}
    foreach ($table in $checkpointTables) {
        $value = (& docker exec $container psql --username=$DatabaseUser --dbname=$Database --tuples-only --no-align --command="SELECT count(*) FROM $table;").Trim()
        if ($LASTEXITCODE -ne 0 -or $value -notmatch '^\d+$') {
            throw "Could not read backup checkpoint for $table"
        }
        $result[$table] = [long]$value
    }
    $sequence = (& docker exec $container psql --username=$DatabaseUser --dbname=$Database --tuples-only --no-align --command="SELECT COALESCE(max(event_seq),0) FROM public_execution_events;").Trim()
    if ($LASTEXITCODE -ne 0 -or $sequence -notmatch '^\d+$') {
        throw "Could not read public execution sequence checkpoint"
    }
    $result["public_execution_events_max_sequence"] = [long]$sequence
    return $result
}

$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$name = "$ComposeProject-$stamp.dump"
$containerDump = "/tmp/$name"
$localDump = Join-Path $backupRoot $name
$checkpointsBefore = Get-DatabaseCheckpoints
try {
    & docker exec $container pg_dump --format=custom --no-owner --no-privileges --username=$DatabaseUser --dbname=$Database --file=$containerDump
    if ($LASTEXITCODE -ne 0) { throw "pg_dump failed" }
    & docker cp "${container}:$containerDump" $localDump
    if ($LASTEXITCODE -ne 0) { throw "docker cp failed" }
}
finally {
    & docker exec $container rm -f -- $containerDump 2>$null | Out-Null
}

$checkpointsAfter = Get-DatabaseCheckpoints
foreach ($checkpointName in $checkpointsBefore.Keys) {
    if ($checkpointsBefore[$checkpointName] -ne $checkpointsAfter[$checkpointName]) {
        throw "Database changed during backup checkpoint $checkpointName; retry from a quiesced PAPER session"
    }
}
$criticalRows = ($checkpointTables | ForEach-Object { [long]$checkpointsAfter[$_] } | Measure-Object -Sum).Sum
if ([long]$criticalRows -lt 1) {
    throw "Refusing to qualify an empty backup without durable runtime facts"
}

$item = Get-Item -LiteralPath $localDump
$manifest = [ordered]@{
    schema_version = 1
    created_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    compose_project = $ComposeProject
    database = $Database
    file = $item.Name
    bytes = $item.Length
    sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash.ToLowerInvariant()
    checkpoints = $checkpointsAfter
}
$manifestPath = "$localDump.json"
$manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding utf8
Write-Output $manifestPath
