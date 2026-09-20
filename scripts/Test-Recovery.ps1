[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,
    [string]$ComposeProject = "kairos",
    [string]$ComposeFile = "docker-compose.yml",
    [string]$EnvFile = ".env",
    [string]$Database = "kairos",
    [string]$DatabaseUser = "kairos",
    [switch]$RuntimePreflight,
    [string]$ReceiptPath
)

$ErrorActionPreference = "Stop"

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [System.IO.File]::OpenRead($Path)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
        $algorithm.Dispose()
    }
}

$root = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$manifestFile = (Resolve-Path -LiteralPath $ManifestPath).Path
$manifest = Get-Content -Raw -LiteralPath $manifestFile | ConvertFrom-Json
$manifestSha256 = Get-FileSha256 -Path $manifestFile
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
$hash = Get-FileSha256 -Path $dump
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

function Assert-OffLineRecoveryIsolation {
    $allowed = @("redis", "timescaledb", "ops-exporter", "prometheus", "grafana")
    $running = @(& docker @compose ps --status running --services)
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect running Compose services"
    }
    $unexpected = @($running | Where-Object { $_ -notin $allowed })
    if ($unexpected.Count -gt 0) {
        throw "Runtime recovery preflight requires all producer and consumer services to be stopped"
    }
    if ($running -notcontains "redis" -or $running -notcontains "timescaledb") {
        throw "Runtime recovery preflight requires isolated Redis and TimescaleDB"
    }
    return @($running | Sort-Object)
}

function Invoke-DatabaseLines {
    param(
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)][string]$Query
    )

    $lines = @(& docker exec $container psql --username=$DatabaseUser --dbname=$DatabaseName --tuples-only --no-align --set=ON_ERROR_STOP=1 --command=$Query)
    if ($LASTEXITCODE -ne 0) {
        throw "Read-only runtime recovery query failed"
    }
    return @($lines | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
}

function Assert-CheckpointMatchesManifest {
    param(
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)]$CheckpointManifest
    )

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
        $expected = $CheckpointManifest.$table
        if ($null -eq $expected -or [long]$expected -lt 0) {
            throw "Backup manifest has no valid checkpoint for $table"
        }
        $actual = @(Invoke-DatabaseLines -DatabaseName $DatabaseName -Query "SELECT count(*) FROM $table;")
        if ($actual.Count -ne 1 -or $actual[0] -notmatch '^\d+$' -or [long]$actual[0] -ne [long]$expected) {
            throw "Database checkpoint differs from the backup manifest for $table"
        }
    }
    $expectedSequence = $CheckpointManifest.public_execution_events_max_sequence
    $actualSequence = @(Invoke-DatabaseLines -DatabaseName $DatabaseName -Query "SELECT COALESCE(max(event_seq),0) FROM public_execution_events;")
    if ($null -eq $expectedSequence -or $actualSequence.Count -ne 1 -or
        $actualSequence[0] -notmatch '^\d+$' -or [long]$actualSequence[0] -ne [long]$expectedSequence) {
        throw "Database public execution sequence differs from the backup manifest"
    }
}

function Get-RuntimeRecoveryReceipt {
    param([Parameter(Mandatory = $true)][string]$DatabaseName)

    $expectedMigrations = @(
        "001_audit_and_idempotency.sql",
        "002_durable_runtime.sql",
        "003_execution_effect_journal.sql",
        "004_execution_recovery_delay.sql",
        "005_source_state_and_usage.sql",
        "006_paper_trade_lifecycle.sql",
        "007_execution_runtime_health.sql",
        "008_public_execution_events.sql",
        "009_paper_canary_arms.sql",
        "010_runtime_compensation_reserve.sql",
        "011_execution_mutation_budget.sql",
        "012_outbox_producer_order.sql"
    )
    $actualMigrations = @(Invoke-DatabaseLines -DatabaseName $DatabaseName -Query "SELECT version FROM schema_migrations ORDER BY version;")
    if ((Compare-Object -ReferenceObject $expectedMigrations -DifferenceObject $actualMigrations)) {
        throw "Runtime recovery clone does not match the exact 001--012 recovery schema profile"
    }

    $requiredTables = @(
        "event_audit", "message_inbox", "message_outbox", "source_cursors",
        "execution_effects", "execution_trades", "execution_recovery_state"
    )
    foreach ($table in $requiredTables) {
        $present = @(Invoke-DatabaseLines -DatabaseName $DatabaseName -Query "SELECT to_regclass('$table') IS NOT NULL;")
        if ($present.Count -ne 1 -or $present[0] -ne "t") {
            throw "Runtime recovery clone is missing $table"
        }
    }

    $barRows = @(Invoke-DatabaseLines -DatabaseName $DatabaseName -Query @"
WITH bars AS (
    SELECT payload->>'symbol' AS symbol,
           (payload->>'open_time_ms')::bigint AS open_time_ms,
           lag((payload->>'open_time_ms')::bigint) OVER (
               PARTITION BY payload->>'symbol'
               ORDER BY (payload->>'open_time_ms')::bigint
           ) AS prior_open_time_ms
    FROM event_audit
    WHERE topic='kairos.market.closed_bar.v1'
      AND source='kairos-quant-scouts'
      AND payload->>'venue'='BINANCE_UM'
)
SELECT symbol || '|' || count(*) || '|' || min(open_time_ms) || '|' || max(open_time_ms) || '|' ||
       count(*) FILTER (WHERE prior_open_time_ms IS NOT NULL AND open_time_ms-prior_open_time_ms<>60000)
FROM bars GROUP BY symbol ORDER BY symbol;
"@)
    $expectedSymbols = @("BNBUSDT", "BTCUSDT", "ETHUSDT", "SOLUSDT", "XRPUSDT")
    $barCoverage = [ordered]@{}
    foreach ($row in $barRows) {
        $parts = $row.Split('|')
        if ($parts.Count -ne 5 -or $parts[0] -notin $expectedSymbols -or
            @($parts[1..4] | Where-Object { $_ -notmatch '^\d+$' }).Count -gt 0) {
            throw "Runtime recovery bar coverage receipt is malformed"
        }
        if ([long]$parts[1] -lt 1 -or [long]$parts[4] -ne 0) {
            throw "Runtime recovery bars are not a contiguous prefix"
        }
        $barCoverage[$parts[0]] = [ordered]@{
            count = [long]$parts[1]
            first_open_time_ms = [long]$parts[2]
            last_open_time_ms = [long]$parts[3]
        }
    }
    if ((Compare-Object -ReferenceObject $expectedSymbols -DifferenceObject @($barCoverage.Keys))) {
        throw "Runtime recovery requires an authoritative contiguous anchor for all five symbols"
    }

    $inbox = @(Invoke-DatabaseLines -DatabaseName $DatabaseName -Query @"
SELECT count(*) FILTER (WHERE status='FAILED') || '|' ||
       count(*) FILTER (WHERE status='PROCESSING') || '|' ||
       count(*) FILTER (WHERE status='PROCESSING' AND lease_until <= now())
FROM message_inbox;
"@)
    $outbox = @(Invoke-DatabaseLines -DatabaseName $DatabaseName -Query @"
SELECT count(*) FILTER (WHERE published_at IS NULL AND dead_lettered_at IS NULL) || '|' ||
       count(*) FILTER (WHERE dead_lettered_at IS NOT NULL) || '|' ||
       count(*) FILTER (WHERE published_at IS NULL AND lease_until IS NOT NULL AND lease_until > now()) || '|' ||
       count(*) FILTER (WHERE published_at IS NULL AND lease_until IS NOT NULL AND lease_until <= now()) || '|' ||
       (SELECT count(*) FROM (SELECT message_id FROM event_audit GROUP BY message_id HAVING count(*)>1) duplicate_audit) || '|' ||
       (SELECT count(*) FROM (SELECT message_id FROM message_outbox GROUP BY message_id HAVING count(*)>1) duplicate_outbox) || '|' ||
       (SELECT count(*) FROM message_outbox o LEFT JOIN event_audit a ON a.message_id=o.message_id WHERE a.message_id IS NULL)
FROM message_outbox;
"@)
    if ($inbox.Count -ne 1 -or $outbox.Count -ne 1) {
        throw "Runtime recovery inbox or outbox receipt is malformed"
    }
    $inboxValues = $inbox[0].Split('|')
    $outboxValues = $outbox[0].Split('|')
    if ($inboxValues.Count -ne 3 -or $outboxValues.Count -ne 7 -or
        @($inboxValues + $outboxValues | Where-Object { $_ -notmatch '^\d+$' }).Count -gt 0) {
        throw "Runtime recovery inbox or outbox receipt has non-numeric facts"
    }
    if ([long]$inboxValues[0] -ne 0 -or [long]$inboxValues[1] -ne 0 -or
        [long]$outboxValues[1] -ne 0 -or [long]$outboxValues[2] -ne 0 -or
        [long]$outboxValues[4] -ne 0 -or [long]$outboxValues[5] -ne 0 -or [long]$outboxValues[6] -ne 0) {
        throw "Runtime recovery clone has inconsistent inbox or outbox state"
    }

    $schemaLock = @(Invoke-DatabaseLines -DatabaseName $DatabaseName -Query @"
WITH acquired AS (SELECT pg_try_advisory_lock(4907627681104115019) AS value)
SELECT value::text || '|' || pg_advisory_unlock(4907627681104115019)::text FROM acquired;
"@)
    $producerLock = @(Invoke-DatabaseLines -DatabaseName $DatabaseName -Query @"
WITH acquired AS (SELECT pg_try_advisory_lock(hashtextextended('closed-bar-producer:kairos-quant-scouts',0)) AS value)
SELECT value::text || '|' || pg_advisory_unlock(hashtextextended('closed-bar-producer:kairos-quant-scouts',0))::text FROM acquired;
"@)
    if ($schemaLock.Count -ne 1 -or $producerLock.Count -ne 1 -or
        $schemaLock[0] -ne "true|true" -or $producerLock[0] -ne "true|true") {
        throw "Runtime recovery clone advisory lease preflight failed"
    }

    $executionFacts = @(Invoke-DatabaseLines -DatabaseName $DatabaseName -Query @"
SELECT (SELECT count(*) FROM execution_effects) || '|' ||
       (SELECT count(*) FROM execution_trades) || '|' ||
       (SELECT count(*) FROM execution_recovery_state);
"@)
    if ($executionFacts.Count -ne 1 -or $executionFacts[0].Split('|').Count -ne 3) {
        throw "Runtime recovery execution-journal receipt is malformed"
    }
    $executionValues = $executionFacts[0].Split('|')
    if (@($executionValues | Where-Object { $_ -notmatch '^\d+$' }).Count -gt 0) {
        throw "Runtime recovery execution-journal receipt has non-numeric facts"
    }

    return [ordered]@{
        schema_version = 1
        recovery_profile = "offline-closed-bar-v1"
        result = "PASS"
        migrations = $actualMigrations
        bars = $barCoverage
        inbox = [ordered]@{
            failed = [long]$inboxValues[0]
            processing = [long]$inboxValues[1]
            expired_processing = [long]$inboxValues[2]
        }
        outbox = [ordered]@{
            pending = [long]$outboxValues[0]
            dead_lettered = [long]$outboxValues[1]
            active_leases = [long]$outboxValues[2]
            expired_leases = [long]$outboxValues[3]
            duplicate_audit_ids = [long]$outboxValues[4]
            duplicate_outbox_ids = [long]$outboxValues[5]
            outbox_without_audit = [long]$outboxValues[6]
            read_only_consumer_restart_permitted = ([long]$outboxValues[3] -eq 0)
        }
        execution_journal = [ordered]@{
            effects = [long]$executionValues[0]
            trades = [long]$executionValues[1]
            recovery_states = [long]$executionValues[2]
        }
        offline_bar_recovery_permitted = $true
    }
}

$runningServices = $null
if ($RuntimePreflight) {
    $runningServices = Assert-OffLineRecoveryIsolation
    Assert-CheckpointMatchesManifest -DatabaseName $Database -CheckpointManifest $manifest.checkpoints
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
    if ($RuntimePreflight) {
        $receipt = Get-RuntimeRecoveryReceipt -DatabaseName $drillDatabase
        $receipt.compose_project = $ComposeProject
        $receipt.database = $Database
        $receipt.backup_sha256 = $manifest.sha256
        # Bind the recovery proof to the exact manifest bytes, not only to a
        # dump SHA that may appear in a separately regenerated manifest.
        $receipt.backup_manifest_sha256 = $manifestSha256
        $receipt.running_services = $runningServices
        $receipt.created_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        if ([string]::IsNullOrWhiteSpace($ReceiptPath)) {
            $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
            $ReceiptPath = Join-Path (Split-Path -Parent $manifestFile) "runtime-recovery-preflight-$stamp.json"
        }
        $receiptFullPath = [System.IO.Path]::GetFullPath($ReceiptPath)
        $manifestDirectory = [System.IO.Path]::GetFullPath((Split-Path -Parent $manifestFile))
        if (-not $receiptFullPath.StartsWith($manifestDirectory + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Runtime recovery receipt must remain beside the immutable backup manifest"
        }
        if (Test-Path -LiteralPath $receiptFullPath) {
            throw "Runtime recovery receipt already exists"
        }
        $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptFullPath -Encoding utf8
        Write-Output "Runtime recovery preflight passed: $receiptFullPath"
    }
    Write-Output "Recovery drill passed for $($manifest.file): $migrationCount migrations, $tableCount critical tables"
}
finally {
    & docker exec --user=root $container rm -f -- $containerDump 2>$null | Out-Null
    & docker exec $container dropdb --if-exists --force --username=$DatabaseUser $drillDatabase 2>$null | Out-Null
}
