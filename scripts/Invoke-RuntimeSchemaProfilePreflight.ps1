<#
.SYNOPSIS
    Proves the runtime-only 001--012 -> 001--016,018 migration profile on a
    disposable clone.

.DESCRIPTION
    This is deliberately a new tool, separate from the historical full
    001--018 clone preflight.  It restores only a verified dump into generated
    Docker volumes, applies an explicitly pinned runtime profile, and proves
    that no simulator relations or migration 017 exist on that clone.

    It never starts a Compose project, reads a secret, opens the original
    database, or authorizes an original-database migration.  A PASS receipt is
    schema evidence only.  The later legacy-outbox inspection and quarantine
    clone rehearsal remain mandatory before any source-side action.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [Parameter(Mandatory = $true)]
    [string]$RecoveryReceiptPath,

    [Parameter(Mandatory = $true)]
    [string]$MigrationRunnerImage,

    [Parameter(Mandatory = $true)]
    [ValidateSet("CLONE_ONLY_RUNTIME_SCHEMA_PROFILE_PREFLIGHT")]
    [string]$Confirmation,

    [string]$ReceiptPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ExpectedPersistenceRepository = "https://github.com/Kairos-cryptoAI/kairos-persistence"
$ExpectedPersistenceRevision = "1ca8bf38d265ece7a95f749a268075549f80c043"
$ExpectedTimescaleImage = "timescale/timescaledb:2.29.1-pg16@sha256:252a443e2936039b83dd8da1373d01e59e932d1054fa6adf1bc061f1d56ae60a"
$ExpectedSourceComposeProject = "kairos-paper-gate"
$ExpectedSourceDatabase = "kairos"
$MaximumBackupAge = [TimeSpan]::FromHours(2)
$SchemaAdvisoryLock = "4907627681104115019"
$CloneScope = "clone-only-runtime-schema-profile-preflight"
$CloneDatabaseUser = "kairos_runtime_upgrade"
$ExpectedMigrationRunnerUser = "10001:10001"
# The canonical public 001--012 catalog inventory on the pinned TimescaleDB
# image.  Migration rows alone cannot detect out-of-band source DDL.
$ExpectedLegacySchemaFingerprint = "7c4c103c09badbe1a60a4fcc8d11e2119a3ece0c52e1145d69a0fc2a11be59de"

$LegacyMigrations = @(
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
$RuntimeMigrationSuffix = @(
    "013_campaign_source_budgets.sql",
    "014_bounded_canary_sessions.sql",
    "015_canary_dispatch_claims.sql",
    "016_global_canary_session_guard.sql",
    "018_offline_outbox_reconciliation.sql"
)
# The package inventory has both profiles.  The runner must expose this exact
# reviewed catalog, but only RuntimeMigrationSuffix is ever copied into a
# runtime clone.  017 is intentionally absent from TargetMigrations.
$AllPackageMigrations = @(
    $LegacyMigrations + @(
        "013_campaign_source_budgets.sql",
        "014_bounded_canary_sessions.sql",
        "015_canary_dispatch_claims.sql",
        "016_global_canary_session_guard.sql",
        "017_simulator_journal.sql",
        "018_offline_outbox_reconciliation.sql"
    )
)
$TargetMigrations = @($LegacyMigrations + $RuntimeMigrationSuffix)

# SHA-256 values are from Raw Git-blob bytes at ExpectedPersistenceRevision.  Host
# line-ending conversion is not part of this trust boundary.
$MigrationSha256 = [ordered]@{
    "001_audit_and_idempotency.sql" = "e1bd549846225dbbf627b5204edb8298d39f10c856aa22ba570ee1b14d68bccb"
    "002_durable_runtime.sql" = "19f65eb325579fb0b5820c1ac3e4869e776af7b63248681b9803ca6d5a9d9739"
    "003_execution_effect_journal.sql" = "dd1fb9ef84375890d675bfdda3bf87ff0715e4c7f08bb0ac89e9967668d249df"
    "004_execution_recovery_delay.sql" = "5a68a639316d3fdd530e86e6c1747e1924d618d427097bc2d481760a811744fa"
    "005_source_state_and_usage.sql" = "f9d2cdb7bde828591c796158791eb8670e3b868aa40fc618cbbc06fa98b3e83c"
    "006_paper_trade_lifecycle.sql" = "57d32944c98d84d9870dc7cd11630e542ae7038f45721f515d98f31291309393"
    "007_execution_runtime_health.sql" = "24bf34bc82fe6e9f7a7217795600ac414df24f6b7c6da756243a697bf9defc57"
    "008_public_execution_events.sql" = "0adc1093b350ccb55049c5f8065e8a315cff1bac36f309e09984122608b3ea40"
    "009_paper_canary_arms.sql" = "c457ba2e1aacfec2b7810abd0cfbe4ef82cb5b132513ac3a9b6f759df7a2969a"
    "010_runtime_compensation_reserve.sql" = "8f960c0a34cc855549b45c89d81c8e46760de90e3acfeb3216fc5444aaef4190"
    "011_execution_mutation_budget.sql" = "b407a8089132b4f12cf692d5c04b0bcda0cc3022d0e1afb36dc7da27260a312f"
    "012_outbox_producer_order.sql" = "53abce1864959c0dade0afea57daf2486a58c0d94ceebf6c0fee0797019328e8"
    "013_campaign_source_budgets.sql" = "9fbf3aa02ebdc77174061b9f7969e1d2a0114bdf3881b0e6fc646b38857f4c77"
    "014_bounded_canary_sessions.sql" = "0809635fe32c1ee9b7dbe977e8b52b0291e34fe8a9b5faa32c866c021f000af4"
    "015_canary_dispatch_claims.sql" = "e78204aa7164194d68052a93e83d608dcac3da8b18fdd3a8b00288b58d78ac4c"
    "016_global_canary_session_guard.sql" = "c3a36bf1ecda579a4281e7c09b5cfcb809874ed30691a079c40737a86711cc73"
    "017_simulator_journal.sql" = "d7d1fe54e6993cd24d79626d3a15546c55f3909a8cba43b1891392a27f6d027e"
    "018_offline_outbox_reconciliation.sql" = "f2d5db9e6810c2715acb8c804b97f4c4779d44ef2ff7851956c5bb482a8f9347"
}

$CheckpointTables = @(
    "event_audit", "message_inbox", "message_outbox", "execution_orders",
    "account_snapshots", "position_snapshots", "source_cursors",
    "source_usage_reservations", "execution_effects", "execution_effect_events",
    "execution_trades", "execution_trade_events", "execution_recovery_state",
    "public_execution_events", "account_equity_state", "paper_canary_arms",
    "execution_runtime_health", "execution_mutation_budget_scopes",
    "execution_mutation_reservations"
)
$RuntimeRelations = @(
    "campaign_source_budgets", "paper_canary_database_identity", "paper_readonly_runs",
    "paper_readonly_samples", "paper_readonly_receipts", "paper_canary_sessions",
    "paper_canary_attempts", "paper_canary_dispatch_claims"
)
$RuntimeIndexes = @(
    "source_usage_campaign_idx", "paper_canary_one_active_remote_account",
    "paper_canary_one_outstanding_attempt", "paper_canary_one_active_project",
    "message_outbox_reconciliation_pending_idx"
)

function Assert-ExactStringArray {
    param(
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $actualArray = @($Actual | ForEach-Object { [string]$_ })
    if ($actualArray.Count -ne $Expected.Count) {
        throw "$Description is not the required exact profile"
    }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if ($Expected[$index] -cne $actualArray[$index]) {
            throw "$Description is not the required exact profile"
        }
    }
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($algorithm.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

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

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

function Invoke-DockerProbe {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$IncludeStderr
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = if ($IncludeStderr) { @(& docker @Arguments 2>&1) } else { @(& docker @Arguments 2>$null) }
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    return [pscustomobject]@{ output = $output; exit_code = [int]$exitCode }
}

function ConvertTo-Base64PythonCommand {
    param([Parameter(Mandatory = $true)][string]$Content)

    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Content))
    $encodedBytes = @([System.Text.Encoding]::ASCII.GetBytes($encoded) | ForEach-Object { [int]$_ }) -join ","
    return "exec(__import__(chr(98)+chr(97)+chr(115)+chr(101)+chr(54)+chr(52)).b64decode(bytes(($encodedBytes))))"
}

function Get-RequiredProperty {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        throw "$Description lacks required field $Name"
    }
    return $property.Value
}

function Get-ExplicitUtcTimestamp {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Description
    )

    # ConvertFrom-Json materializes ISO-8601 Z values as DateTime.  Preserve
    # UTC kind rather than round-tripping through a host-local string.
    $rawTimestamp = Get-RequiredProperty -Object $Object -Name $Name -Description $Description
    $timestamp = [DateTimeOffset]::MinValue
    if ($rawTimestamp -is [DateTime]) {
        if ($rawTimestamp.Kind -ne [DateTimeKind]::Utc) {
            throw "$Description $Name must be an explicit UTC timestamp"
        }
        $timestamp = [DateTimeOffset]::new($rawTimestamp)
    }
    elseif ($rawTimestamp -is [DateTimeOffset]) {
        if ($rawTimestamp.Offset -ne [TimeSpan]::Zero) {
            throw "$Description $Name must be an explicit UTC timestamp"
        }
        $timestamp = $rawTimestamp
    }
    elseif (-not [DateTimeOffset]::TryParse(
        [string]$rawTimestamp,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$timestamp
    ) -or $timestamp.Offset -ne [TimeSpan]::Zero) {
        throw "$Description has an invalid $Name"
    }
    return $timestamp.ToUniversalTime()
}

function Get-RequiredNatural {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $value = Get-RequiredProperty -Object $Object -Name $Name -Description $Description
    if ([string]$value -notmatch '^\d+$') {
        throw "$Description $Name must be a non-negative integer"
    }
    return [long]$value
}

function Get-CheckpointDigest {
    param([Parameter(Mandatory = $true)]$Checkpoints)

    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($table in $CheckpointTables + @("public_execution_events_max_sequence")) {
        $value = Get-RequiredNatural -Object $Checkpoints -Name $table -Description "Backup manifest checkpoint"
        [void]$parts.Add("$table=$value")
    }
    return Get-Sha256Hex -Bytes ([System.Text.Encoding]::UTF8.GetBytes(($parts -join "`n")))
}

function Get-VerifiedTimescaleJobOwners {
    param([Parameter(Mandatory = $true)]$Manifest)

    $property = $Manifest.PSObject.Properties["timescaledb_bgw_owners"]
    if ($null -eq $property -or $null -eq $property.Value) {
        throw "Backup manifest lacks TimescaleDB background-job owner provenance"
    }
    $owners = @($property.Value | ForEach-Object { [string]$_ })
    if (@($owners | Where-Object { $_ -notmatch '^[A-Za-z_][A-Za-z0-9_]{0,62}$' }).Count -ne 0) {
        throw "Backup manifest has an unsafe TimescaleDB background-job owner"
    }
    if (@($owners | Sort-Object -Unique).Count -ne $owners.Count) {
        throw "Backup manifest repeats a TimescaleDB background-job owner"
    }
    return @($owners | Sort-Object)
}

function Get-VerifiedInput {
    param(
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)]$Receipt,
        [Parameter(Mandatory = $true)][string]$ManifestSha256
    )

    if ($Manifest.schema_version -ne 1 -or [string]$Manifest.sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$Manifest.file -notmatch '^[A-Za-z0-9_.-]+\.dump$' -or [string]$Manifest.bytes -notmatch '^\d+$') {
        throw "Unsupported or malformed backup manifest"
    }
    if ($Manifest.compose_project -cne $ExpectedSourceComposeProject -or $Manifest.database -cne $ExpectedSourceDatabase) {
        throw "Backup manifest must identify the isolated $ExpectedSourceComposeProject/$ExpectedSourceDatabase runtime"
    }
    if ($null -eq $Manifest.checkpoints) {
        throw "Backup manifest lacks durable data checkpoints"
    }
    if ($Receipt.schema_version -ne 1 -or $Receipt.result -ne "PASS" -or
        $Receipt.recovery_profile -ne "offline-closed-bar-v1" -or
        $Receipt.backup_sha256 -ne $Manifest.sha256 -or
        $Receipt.backup_manifest_sha256 -ne $ManifestSha256 -or
        $Receipt.compose_project -ne $Manifest.compose_project -or $Receipt.database -ne $Manifest.database) {
        throw "Recovery receipt does not prove this exact verified source backup"
    }
    Assert-ExactStringArray -Expected $LegacyMigrations -Actual @($Receipt.migrations) -Description "Recovery receipt migration profile"
    $backupCreatedAt = Get-ExplicitUtcTimestamp -Object $Manifest -Name "created_at_utc" -Description "Backup manifest"
    $receiptCreatedAt = Get-ExplicitUtcTimestamp -Object $Receipt -Name "created_at_utc" -Description "Recovery receipt"
    $now = [DateTimeOffset]::UtcNow
    $tolerance = [TimeSpan]::FromMinutes(5)
    if (($now - $backupCreatedAt) -gt $MaximumBackupAge -or $backupCreatedAt -gt ($now + $tolerance)) {
        throw "Backup manifest is not a fresh two-hour runtime snapshot"
    }
    if (($now - $receiptCreatedAt) -gt $MaximumBackupAge -or $receiptCreatedAt -gt ($now + $tolerance)) {
        throw "Recovery receipt is not a fresh two-hour runtime verification"
    }
    if ($receiptCreatedAt -lt ($backupCreatedAt - $tolerance)) {
        throw "Recovery receipt predates the verified backup manifest"
    }
    $inbox = Get-RequiredProperty -Object $Receipt -Name "inbox" -Description "Recovery receipt"
    $outbox = Get-RequiredProperty -Object $Receipt -Name "outbox" -Description "Recovery receipt"
    $facts = [ordered]@{
        inbox_failed = Get-RequiredNatural -Object $inbox -Name "failed" -Description "Recovery inbox"
        inbox_processing = Get-RequiredNatural -Object $inbox -Name "processing" -Description "Recovery inbox"
        inbox_expired_processing = Get-RequiredNatural -Object $inbox -Name "expired_processing" -Description "Recovery inbox"
        outbox_pending = Get-RequiredNatural -Object $outbox -Name "pending" -Description "Recovery outbox"
        outbox_active_leases = Get-RequiredNatural -Object $outbox -Name "active_leases" -Description "Recovery outbox"
        outbox_expired_leases = Get-RequiredNatural -Object $outbox -Name "expired_leases" -Description "Recovery outbox"
        outbox_dead_lettered = Get-RequiredNatural -Object $outbox -Name "dead_lettered" -Description "Recovery outbox"
        outbox_duplicate_audit_ids = Get-RequiredNatural -Object $outbox -Name "duplicate_audit_ids" -Description "Recovery outbox"
        outbox_duplicate_outbox_ids = Get-RequiredNatural -Object $outbox -Name "duplicate_outbox_ids" -Description "Recovery outbox"
        outbox_without_audit = Get-RequiredNatural -Object $outbox -Name "outbox_without_audit" -Description "Recovery outbox"
        read_only_consumer_restart_permitted = (Get-RequiredProperty -Object $outbox -Name "read_only_consumer_restart_permitted" -Description "Recovery outbox")
        offline_bar_recovery_permitted = (Get-RequiredProperty -Object $Receipt -Name "offline_bar_recovery_permitted" -Description "Recovery receipt")
    }
    if ($facts.read_only_consumer_restart_permitted -isnot [bool] -or $facts.offline_bar_recovery_permitted -isnot [bool]) {
        throw "Recovery receipt restart facts must be Boolean"
    }
    return [ordered]@{
        backup_created_at_utc = $backupCreatedAt.ToString("o")
        recovery_receipt_created_at_utc = $receiptCreatedAt.ToString("o")
        recovery_facts = $facts
        timescaledb_bgw_owners = Get-VerifiedTimescaleJobOwners -Manifest $Manifest
    }
}

function Assert-CloneDatabaseName {
    param([Parameter(Mandatory = $true)][string]$DatabaseName)

    if ($DatabaseName -notmatch '^kairos_runtime_profile_(?:restore_)?drill_[0-9a-f]{12}$') {
        throw "Refusing a database name outside the generated runtime-profile drill namespace"
    }
}

function Assert-CloneVolumeIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Volume,
        [Parameter(Mandatory = $true)][string]$Suffix
    )

    $inspection = Invoke-DockerProbe -Arguments @("volume", "inspect", "--format", "{{json .Labels}}", $Volume)
    $json = (($inspection.output | Select-Object -Last 1) -as [string]).Trim()
    if ($inspection.exit_code -ne 0 -or -not $json) { throw "Could not inspect isolated clone volume" }
    $labels = $json | ConvertFrom-Json
    if ($labels.'com.kairos.scope' -ne $CloneScope -or $labels.'com.kairos.drill' -ne $Suffix) {
        throw "Isolated clone volume identity labels do not match this drill"
    }
}

function Assert-CloneContainerIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DataVolume,
        [Parameter(Mandatory = $true)][string]$StageVolume,
        [Parameter(Mandatory = $true)][string]$Suffix
    )

    $labelProbe = Invoke-DockerProbe -Arguments @("inspect", "--format", "{{json .Config.Labels}}", $Container)
    $labelJson = (($labelProbe.output | Select-Object -Last 1) -as [string]).Trim()
    if ($labelProbe.exit_code -ne 0 -or -not $labelJson) { throw "Could not inspect isolated clone container" }
    $labels = $labelJson | ConvertFrom-Json
    if ($labels.'com.kairos.scope' -ne $CloneScope -or $labels.'com.kairos.drill' -ne $Suffix) {
        throw "Isolated clone container identity labels do not match this drill"
    }
    $networkProbe = Invoke-DockerProbe -Arguments @("inspect", "--format", "{{.HostConfig.NetworkMode}}", $Container)
    $networkMode = (($networkProbe.output | Select-Object -Last 1) -as [string]).Trim()
    if ($networkProbe.exit_code -ne 0 -or $networkMode -ne "none") {
        throw "Clone container must have no network"
    }
    $mountProbe = Invoke-DockerProbe -Arguments @("inspect", "--format", "{{json .Mounts}}", $Container)
    $mountJson = (($mountProbe.output | Select-Object -Last 1) -as [string]).Trim()
    if ($mountProbe.exit_code -ne 0 -or -not $mountJson) { throw "Could not inspect clone container mounts" }
    $mounts = @($mountJson | ConvertFrom-Json | ForEach-Object { $_ })
    $expected = @(
        [pscustomobject]@{ destination = "/var/lib/postgresql/data"; volume = $DataVolume },
        [pscustomobject]@{ destination = "/kairos-stage"; volume = $StageVolume }
    )
    if ($mounts.Count -ne $expected.Count) { throw "Clone container must use exactly its disposable data and staging volumes" }
    foreach ($item in $expected) {
        $actual = @($mounts | Where-Object { $_.Destination -eq $item.destination })
        if ($actual.Count -ne 1 -or $actual[0].Type -ne "volume" -or $actual[0].Name -ne $item.volume) {
            throw "Clone container mounts do not match this generated drill"
        }
    }
}

function Wait-CloneDatabaseReady {
    param([Parameter(Mandatory = $true)][string]$Container)

    $successes = 0
    for ($attempt = 1; $attempt -le 60; $attempt++) {
        $probe = Invoke-DockerProbe -Arguments @(
            "exec", $Container, "psql", "--username=$CloneDatabaseUser", "--dbname=postgres",
            "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1", "--command=SELECT 1;"
        )
        $values = @($probe.output | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
        if ($probe.exit_code -eq 0 -and $values -contains "1") {
            $successes++
            if ($successes -ge 3) { return }
        }
        else { $successes = 0 }
        Start-Sleep -Seconds 2
    }
    throw "Isolated clone database did not become stable within 120 seconds"
}

function Invoke-CloneDatabaseLines {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)][string]$Query
    )

    Assert-CloneDatabaseName -DatabaseName $DatabaseName
    $result = Invoke-DockerProbe -Arguments @(
        "exec", $Container, "psql", "--username=$CloneDatabaseUser", "--dbname=$DatabaseName",
        "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1", "--command=$Query"
    )
    if ($result.exit_code -ne 0) { throw "Clone-only database query failed" }
    return @($result.output | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
}

function Get-CloneMigrations {
    param([Parameter(Mandatory = $true)][string]$Container, [Parameter(Mandatory = $true)][string]$DatabaseName)
    return @(Invoke-CloneDatabaseLines -Container $Container -DatabaseName $DatabaseName -Query "SELECT version FROM schema_migrations ORDER BY version;")
}

function Assert-CloneMigrationProfile {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Description
    )
    Assert-ExactStringArray -Expected $Expected -Actual (Get-CloneMigrations -Container $Container -DatabaseName $DatabaseName) -Description $Description
}

function Assert-ManifestCheckpoints {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)]$Checkpoints
    )

    foreach ($table in $CheckpointTables) {
        $expected = Get-RequiredNatural -Object $Checkpoints -Name $table -Description "Backup manifest checkpoint"
        $actual = @(Invoke-CloneDatabaseLines -Container $Container -DatabaseName $DatabaseName -Query "SELECT count(*) FROM $table;")
        if ($actual.Count -ne 1 -or $actual[0] -notmatch '^\d+$' -or [long]$actual[0] -ne $expected) {
            throw "Clone checkpoint differs from the verified backup for $table"
        }
    }
    $expectedSequence = Get-RequiredNatural -Object $Checkpoints -Name "public_execution_events_max_sequence" -Description "Backup manifest checkpoint"
    $actualSequence = @(Invoke-CloneDatabaseLines -Container $Container -DatabaseName $DatabaseName -Query "SELECT COALESCE(max(event_seq),0) FROM public_execution_events;")
    if ($actualSequence.Count -ne 1 -or $actualSequence[0] -notmatch '^\d+$' -or [long]$actualSequence[0] -ne $expectedSequence) {
        throw "Clone public execution sequence differs from the verified backup"
    }
}

function ConvertTo-SqlTextArray {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Values)
    return "ARRAY[" + (($Values | ForEach-Object { "'$($_.Replace("'", "''"))'" }) -join ",") + "]::text[]"
}

function Get-LegacySchemaFingerprint {
    param([Parameter(Mandatory = $true)][string]$Container, [Parameter(Mandatory = $true)][string]$DatabaseName)

    $query = @"
WITH inventory AS (
    SELECT 'extension|' || e.extname || '|' || e.extversion AS item FROM pg_extension e WHERE e.extname='timescaledb'
    UNION ALL
    SELECT 'relation|' || c.relkind::text || '|' || c.relname || '|' || CASE WHEN c.relkind IN ('v','m') THEN md5(pg_get_viewdef(c.oid, true)) ELSE '' END
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')
    UNION ALL
    SELECT 'column|' || c.relname || '|' || a.attnum::text || '|' || a.attname || '|' || format_type(a.atttypid, a.atttypmod) || '|' || a.attnotnull::text || '|' || a.attidentity::text || '|' || a.attgenerated::text || '|' || COALESCE(md5(pg_get_expr(ad.adbin, ad.adrelid, true)), '') || '|' || COALESCE(coll.collname, '')
    FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum LEFT JOIN pg_collation coll ON coll.oid=a.attcollation
    WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f') AND a.attnum > 0 AND NOT a.attisdropped
    UNION ALL
    SELECT 'constraint|' || c.relname || '|' || con.conname || '|' || con.contype::text || '|' || md5(pg_get_constraintdef(con.oid, true))
    FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
    UNION ALL
    SELECT 'index|' || t.relname || '|' || i.relname || '|' || x.indisunique::text || '|' || x.indisprimary::text || '|' || x.indisvalid::text || '|' || md5(pg_get_indexdef(i.oid))
    FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid JOIN pg_class t ON t.oid=x.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public'
    UNION ALL
    SELECT 'trigger|' || c.relname || '|' || tg.tgname || '|' || md5(pg_get_triggerdef(tg.oid, true))
    FROM pg_trigger tg JOIN pg_class c ON c.oid=tg.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT tg.tgisinternal
    UNION ALL
    SELECT 'sequence|' || c.relname || '|' || s.seqstart::text || '|' || s.seqincrement::text || '|' || s.seqmin::text || '|' || s.seqmax::text || '|' || s.seqcache::text || '|' || s.seqcycle::text
    FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
    UNION ALL
    SELECT 'type|' || t.typtype::text || '|' || t.typname || '|' || COALESCE(format_type(t.typbasetype, t.typtypmod), '')
    FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' AND t.typtype IN ('b','c','d','e','r')
)
SELECT COALESCE(string_agg(item, E'\\n' ORDER BY item), '') FROM inventory;
"@
    $result = @(Invoke-CloneDatabaseLines -Container $Container -DatabaseName $DatabaseName -Query $query)
    if ($result.Count -gt 1) { throw "Legacy schema fingerprint is malformed" }
    $text = if ($result.Count -eq 1) { $result[0] } else { "" }
    return Get-Sha256Hex -Bytes ([System.Text.Encoding]::UTF8.GetBytes($text))
}

function Assert-VettedLegacySchemaShape {
    param([Parameter(Mandatory = $true)][string]$Container, [Parameter(Mandatory = $true)][string]$DatabaseName)
    $actual = Get-LegacySchemaFingerprint -Container $Container -DatabaseName $DatabaseName
    if ($actual -cne $ExpectedLegacySchemaFingerprint) {
        throw "Clone legacy 001--012 schema fingerprint differs from the pinned profile (expected $ExpectedLegacySchemaFingerprint; observed $actual)"
    }
    return $actual
}

function Get-RuntimeObjectCounts {
    param([Parameter(Mandatory = $true)][string]$Container, [Parameter(Mandatory = $true)][string]$DatabaseName)

    $relations = ConvertTo-SqlTextArray -Values $RuntimeRelations
    $indexes = ConvertTo-SqlTextArray -Values $RuntimeIndexes
    $query = @"
SELECT
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname = ANY($relations)) || '|' ||
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname LIKE 'sim\_%' ESCAPE '\') || '|' ||
  (SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='message_outbox' AND column_name IN ('reconciliation_state','reconciliation_id','reconciliation_started_at','reconciliation_outcome_at')) || '|' ||
  (SELECT count(*) FROM pg_constraint WHERE conrelid='public.message_outbox'::regclass AND conname IN ('message_outbox_reconciliation_state','message_outbox_reconciliation_identity')) || '|' ||
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='i' AND c.relname = ANY($indexes));
"@
    $rows = @(Invoke-CloneDatabaseLines -Container $Container -DatabaseName $DatabaseName -Query $query)
    if ($rows.Count -ne 1) { throw "Runtime object receipt is malformed" }
    $values = $rows[0].Split('|')
    if ($values.Count -ne 5 -or @($values | Where-Object { $_ -notmatch '^\d+$' }).Count -ne 0) {
        throw "Runtime object receipt has non-numeric values"
    }
    return [ordered]@{
        runtime_relations = [long]$values[0]
        simulator_relations = [long]$values[1]
        reconciliation_columns = [long]$values[2]
        reconciliation_constraints = [long]$values[3]
        runtime_indexes = [long]$values[4]
    }
}

function Assert-RuntimeObjects {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)][bool]$Present
    )

    $actual = Get-RuntimeObjectCounts -Container $Container -DatabaseName $DatabaseName
    $expected = if ($Present) {
        [ordered]@{
            runtime_relations = [long]$RuntimeRelations.Count
            simulator_relations = 0L
            reconciliation_columns = 4L
            reconciliation_constraints = 2L
            runtime_indexes = [long]$RuntimeIndexes.Count
        }
    }
    else {
        [ordered]@{ runtime_relations = 0L; simulator_relations = 0L; reconciliation_columns = 0L; reconciliation_constraints = 0L; runtime_indexes = 0L }
    }
    foreach ($name in $expected.Keys) {
        if ($actual[$name] -ne $expected[$name]) {
            $state = if ($Present) { "missing or malformed" } else { "contains post-baseline or simulator residue" }
            throw "Clone $state runtime profile objects ($name)"
        }
    }
    return $actual
}

function Assert-VettedRuntimeSchemaShape {
    param([Parameter(Mandatory = $true)][string]$Container, [Parameter(Mandatory = $true)][string]$DatabaseName)

    $relations = ConvertTo-SqlTextArray -Values $RuntimeRelations
    $query = @"
WITH relation_check AS (
    SELECT count(*) = $($RuntimeRelations.Count) AND bool_and(c.relkind='r') AS value
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname = ANY($relations)
), sim_check AS (
    SELECT count(*) = 0 AS value FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname LIKE 'sim\_%' ESCAPE '\'
), column_check AS (
    SELECT count(*) = 4 AND bool_and(
        (column_name='reconciliation_state' AND data_type='text' AND is_nullable='NO' AND COALESCE(column_default,'') LIKE '%NONE%') OR
        (column_name='reconciliation_id' AND data_type='text' AND is_nullable='YES') OR
        (column_name='reconciliation_started_at' AND data_type='timestamp with time zone' AND is_nullable='YES') OR
        (column_name='reconciliation_outcome_at' AND data_type='timestamp with time zone' AND is_nullable='YES')
    ) AS value FROM information_schema.columns WHERE table_schema='public' AND table_name='message_outbox' AND column_name IN ('reconciliation_state','reconciliation_id','reconciliation_started_at','reconciliation_outcome_at')
), constraint_check AS (
    SELECT count(*) = 2 AND bool_and(
        (conname='message_outbox_reconciliation_state' AND contype='c' AND position('PUBLISH_OUTCOME_UNKNOWN' IN pg_get_constraintdef(oid, true)) > 0) OR
        (conname='message_outbox_reconciliation_identity' AND contype='c' AND position('reconciliation_id' IN pg_get_constraintdef(oid, true)) > 0)
    ) AS value FROM pg_constraint WHERE conrelid='public.message_outbox'::regclass AND conname IN ('message_outbox_reconciliation_state','message_outbox_reconciliation_identity')
), index_check AS (
    SELECT count(*) = 5 AND bool_and(
        (i.relname='source_usage_campaign_idx' AND t.relname='source_usage_reservations' AND position('source, status' IN pg_get_indexdef(i.oid)) > 0) OR
        (i.relname='paper_canary_one_active_remote_account' AND t.relname='paper_canary_sessions' AND position('remote_account_id' IN pg_get_indexdef(i.oid)) > 0) OR
        (i.relname='paper_canary_one_outstanding_attempt' AND t.relname='paper_canary_attempts' AND position('session_id' IN pg_get_indexdef(i.oid)) > 0) OR
        (i.relname='paper_canary_one_active_project' AND t.relname='paper_canary_sessions' AND position('scope' IN pg_get_indexdef(i.oid)) > 0) OR
        (i.relname='message_outbox_reconciliation_pending_idx' AND t.relname='message_outbox' AND position('reconciliation_state, id' IN pg_get_indexdef(i.oid)) > 0 AND position('published_at IS NULL' IN pg_get_indexdef(i.oid)) > 0)
    ) AS value FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid JOIN pg_class t ON t.oid=x.indrelid
    WHERE i.relname IN ('source_usage_campaign_idx','paper_canary_one_active_remote_account','paper_canary_one_outstanding_attempt','paper_canary_one_active_project','message_outbox_reconciliation_pending_idx') AND x.indisvalid
)
SELECT relation_check.value::text || '|' || sim_check.value::text || '|' || column_check.value::text || '|' || constraint_check.value::text || '|' || index_check.value::text FROM relation_check CROSS JOIN sim_check CROSS JOIN column_check CROSS JOIN constraint_check CROSS JOIN index_check;
"@
    $rows = @(Invoke-CloneDatabaseLines -Container $Container -DatabaseName $DatabaseName -Query $query)
    if ($rows.Count -ne 1 -or @($rows[0].Split('|') | Where-Object { $_ -cne 'true' }).Count -ne 0) {
        throw "Clone post-baseline schema differs from the vetted runtime-only 013--016,018 structure"
    }
    return [ordered]@{ relation_kinds = $true; simulator_absent = $true; reconciliation_columns = $true; reconciliation_constraints = $true; indexes = $true }
}

function Get-RuntimeSchemaFingerprint {
    param([Parameter(Mandatory = $true)][string]$Container, [Parameter(Mandatory = $true)][string]$DatabaseName)

    $relations = ConvertTo-SqlTextArray -Values $RuntimeRelations
    $indexes = ConvertTo-SqlTextArray -Values $RuntimeIndexes
    $query = @"
WITH inventory AS (
    SELECT 'relation|' || c.relname || '|' || c.relkind::text AS item FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname = ANY($relations)
    UNION ALL SELECT 'column|' || column_name || '|' || data_type || '|' || is_nullable || '|' || COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema='public' AND table_name='message_outbox' AND column_name IN ('reconciliation_state','reconciliation_id','reconciliation_started_at','reconciliation_outcome_at')
    UNION ALL SELECT 'constraint|' || conname || '|' || pg_get_constraintdef(oid, true) FROM pg_constraint WHERE conrelid='public.message_outbox'::regclass AND conname IN ('message_outbox_reconciliation_state','message_outbox_reconciliation_identity')
    UNION ALL SELECT 'index|' || c.relname || '|' || pg_get_indexdef(c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='i' AND c.relname = ANY($indexes)
    UNION ALL SELECT 'simulator_relations|' || count(*)::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname LIKE 'sim\_%' ESCAPE '\'
)
SELECT COALESCE(string_agg(item, E'\\n' ORDER BY item), '') FROM inventory;
"@
    $rows = @(Invoke-CloneDatabaseLines -Container $Container -DatabaseName $DatabaseName -Query $query)
    if ($rows.Count -gt 1) { throw "Runtime schema fingerprint is malformed" }
    $text = if ($rows.Count -eq 1) { $rows[0] } else { "" }
    return Get-Sha256Hex -Bytes ([System.Text.Encoding]::UTF8.GetBytes($text))
}

function Assert-CloneDdlPreconditions {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)][string]$Suffix
    )

    Assert-CloneDatabaseName -DatabaseName $DatabaseName
    if ($Suffix -notmatch '^[0-9a-f]{12}$') { throw "Clone DDL probe suffix is malformed" }
    $probeTable = "kairos_runtime_profile_probe_$Suffix"
    $query = @"
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
SELECT pg_advisory_xact_lock($SchemaAdvisoryLock);
SELECT gen_random_uuid();
CREATE TABLE public.$probeTable (id UUID NOT NULL DEFAULT gen_random_uuid());
DROP TABLE public.$probeTable;
ROLLBACK;
"@
    $result = Invoke-DockerProbe -Arguments @("exec", $Container, "psql", "--username=$CloneDatabaseUser", "--dbname=$DatabaseName", "--set=ON_ERROR_STOP=1", "--quiet", "--command=$query")
    if ($result.exit_code -ne 0) { throw "Clone does not satisfy UUID, advisory-lock, and DDL preconditions" }
    return [ordered]@{ uuid_function = $true; advisory_lock = $true; ddl_transaction = $true; target_role_permissions = "NOT_VERIFIED_CLONE_ONLY" }
}

function Ensure-TimescaleJobOwners {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Owners
    )

    # ``pg_dump --no-owner`` does not rewrite the owner column in TimescaleDB's
    # internal bgw_job data.  Restore only needs these names to exist.  Create
    # no-login, non-privileged placeholders in the disposable clone; this does
    # not authenticate to, mutate, or reveal any source runtime role.
    $ownerArray = ConvertTo-SqlTextArray -Values $Owners
    $query = @"
DO `$owners`$
DECLARE owner_name text;
BEGIN
    FOREACH owner_name IN ARRAY $ownerArray LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = owner_name) THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', owner_name);
        END IF;
    END LOOP;
END
`$owners`$;
"@
    $result = Invoke-DockerProbe -Arguments @("exec", $Container, "psql", "--username=$CloneDatabaseUser", "--dbname=postgres", "--set=ON_ERROR_STOP=1", "--command=$query") -IncludeStderr
    if ($result.exit_code -ne 0) { throw "Could not create no-login TimescaleDB background-job owner placeholders in clone" }
    return @($Owners)
}

function Restore-VerifiedDump {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)][string]$DumpPathInContainer
    )

    Assert-CloneDatabaseName -DatabaseName $DatabaseName
    if ($DumpPathInContainer -notmatch '^/kairos-stage/[A-Za-z0-9_.-]+\.dump$') { throw "Refusing a dump path outside this generated clone drill" }
    foreach ($step in @(
        [pscustomobject]@{ description = "create generated clone database"; arguments = @("exec", $Container, "createdb", "--username=$CloneDatabaseUser", $DatabaseName) },
        [pscustomobject]@{ description = "initialize TimescaleDB in generated clone"; arguments = @("exec", $Container, "psql", "--username=$CloneDatabaseUser", "--dbname=$DatabaseName", "--set=ON_ERROR_STOP=1", "--command=CREATE EXTENSION IF NOT EXISTS timescaledb;") },
        [pscustomobject]@{ description = "enter TimescaleDB restore mode in generated clone"; arguments = @("exec", $Container, "psql", "--username=$CloneDatabaseUser", "--dbname=$DatabaseName", "--set=ON_ERROR_STOP=1", "--command=SELECT timescaledb_pre_restore();") },
        [pscustomobject]@{ description = "restore verified source backup into generated clone"; arguments = @("exec", $Container, "pg_restore", "--exit-on-error", "--no-owner", "--no-privileges", "--username=$CloneDatabaseUser", "--dbname=$DatabaseName", $DumpPathInContainer) },
        [pscustomobject]@{ description = "leave TimescaleDB restore mode in generated clone"; arguments = @("exec", $Container, "psql", "--username=$CloneDatabaseUser", "--dbname=$DatabaseName", "--set=ON_ERROR_STOP=1", "--command=SELECT timescaledb_post_restore();") }
    )) {
        $result = Invoke-DockerProbe -Arguments $step.arguments -IncludeStderr
        if ($result.exit_code -ne 0) {
            $diagnostic = (($result.output | ForEach-Object { [string]$_ } | Select-Object -First 3) -join " ").Trim()
            if ($diagnostic.Length -gt 600) { $diagnostic = $diagnostic.Substring(0, 600) }
            throw "Could not $($step.description): $diagnostic"
        }
    }
}

function Get-PinnedMigrationSource {
    param(
        [Parameter(Mandatory = $true)][string]$Image,
        [Parameter(Mandatory = $true)][string]$ProbeContainer,
        [Parameter(Mandatory = $true)][string]$Suffix
    )

    if ($Image -notmatch '^.+@sha256:[0-9a-f]{64}$') { throw "Migration runner image must be an immutable repository@sha256 digest" }
    $imageProbe = Invoke-DockerProbe -Arguments @("image", "inspect", "--format", "{{json .RepoDigests}}", $Image)
    if ($imageProbe.exit_code -ne 0) { throw "Could not inspect migration runner image digest" }
    $repoDigestsJson = (($imageProbe.output | Select-Object -Last 1) -as [string]).Trim()
    if (-not $repoDigestsJson) { throw "Migration runner image has no resolved repository digest" }
    try { $repoDigests = @($repoDigestsJson | ConvertFrom-Json | ForEach-Object { [string]$_ }) }
    catch { throw "Migration runner image repository digest inventory is malformed" }
    # Docker may unpack a platform-specific manifest from the supplied immutable
    # multi-platform index without adding that index reference to the local
    # RepoDigests list.  The supplied ``repository@sha256`` is still resolved by
    # ``docker image inspect`` above; require at least one immutable local
    # repository digest and bind the selected platform image by package bytes
    # and source labels below.
    if ($repoDigests.Count -lt 1 -or @($repoDigests | Where-Object { $_ -notmatch '^.+@sha256:[0-9a-f]{64}$' }).Count -ne 0) {
        throw "Migration runner image lacks a resolved immutable repository digest"
    }
    $labelsProbe = Invoke-DockerProbe -Arguments @("image", "inspect", "--format", "{{json .Config.Labels}}", $Image)
    $labelsJson = (($labelsProbe.output | Select-Object -Last 1) -as [string]).Trim()
    if ($labelsProbe.exit_code -ne 0 -or -not $labelsJson) { throw "Could not inspect migration runner image labels" }
    $labels = $labelsJson | ConvertFrom-Json
    if ($labels.'org.opencontainers.image.source' -ne $ExpectedPersistenceRepository -or $labels.'org.opencontainers.image.revision' -ne $ExpectedPersistenceRevision) {
        throw "Migration runner image does not identify the reviewed persistence source revision"
    }
    $userProbe = Invoke-DockerProbe -Arguments @("image", "inspect", "--format", "{{.Config.User}}", $Image)
    $runnerUser = (($userProbe.output | Select-Object -Last 1) -as [string]).Trim()
    if ($userProbe.exit_code -ne 0 -or $runnerUser -ne $ExpectedMigrationRunnerUser) { throw "Migration runner image must run as the reviewed unprivileged user" }
    $probeCode = @'
import hashlib
import json
from importlib.resources import files
root = files("kairos_persistence").joinpath("migrations")
items = []
for entry in sorted(root.iterdir(), key=lambda item: item.name):
    if entry.name.endswith(".sql") and len(entry.name) >= 8 and entry.name[:3].isdigit():
        items.append({"name": entry.name, "sha256": hashlib.sha256(entry.read_bytes()).hexdigest()})
print(json.dumps({"migration_directory": str(root), "migrations": items}, sort_keys=True, separators=(",", ":")))
'@
    $command = ConvertTo-Base64PythonCommand -Content $probeCode
    $created = Invoke-DockerProbe -Arguments @(
        "create", "--name", $ProbeContainer, "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--pids-limit", "32", "--memory", "128m", "--cpus", "0.25", "--user", $ExpectedMigrationRunnerUser,
        "--label", "com.kairos.scope=$CloneScope", "--label", "com.kairos.drill=$Suffix", "--entrypoint", "python", $Image, "-c", $command
    )
    $probeId = (($created.output | Select-Object -Last 1) -as [string]).Trim()
    if ($created.exit_code -ne 0 -or $probeId -notmatch '^[0-9a-f]{64}$') { throw "Could not create isolated migration-runner probe" }
    $output = Invoke-DockerProbe -Arguments @("start", "-a", $probeId)
    $text = ($output.output -join "`n").Trim()
    if ($output.exit_code -ne 0 -or -not $text) { throw "Pinned migration-runner probe failed" }
    try { $probe = $text | ConvertFrom-Json } catch { throw "Pinned migration-runner probe did not produce JSON" }
    $sourcePath = [string]$probe.migration_directory
    if ($sourcePath -notmatch '^/[A-Za-z0-9_./-]+$' -or $sourcePath.Contains("..")) { throw "Pinned migration-runner reported an unsafe migration directory" }
    $entries = @($probe.migrations)
    Assert-ExactStringArray -Expected $AllPackageMigrations -Actual @($entries | ForEach-Object { [string]$_.name }) -Description "Pinned migration-runner package inventory"
    foreach ($entry in $entries) {
        $name = [string]$entry.name
        if ([string]$entry.sha256 -ne $MigrationSha256[$name]) { throw "Pinned migration-runner byte hash differs for $name" }
    }
    return [ordered]@{ container_id = $probeId; migration_directory = $sourcePath }
}

function Copy-PinnedRuntimeMigrations {
    param(
        [Parameter(Mandatory = $true)][string]$RunnerContainer,
        [Parameter(Mandatory = $true)][string]$SourceDirectory,
        [Parameter(Mandatory = $true)][string]$CloneContainer,
        [Parameter(Mandatory = $true)][string]$TargetDirectory
    )

    if ($TargetDirectory -notmatch '^/kairos-stage/runtime-migrations$') { throw "Refusing a migration target outside this generated clone drill" }
    $mkdir = Invoke-DockerProbe -Arguments @("exec", "--user=root", $CloneContainer, "mkdir", "-p", "--", $TargetDirectory)
    if ($mkdir.exit_code -ne 0) { throw "Could not create clone-only runtime migration directory" }
    foreach ($migration in $RuntimeMigrationSuffix) {
        $hostTransfer = [System.IO.Path]::GetTempFileName()
        try {
            Remove-Item -LiteralPath $hostTransfer -Force -ErrorAction Stop
            $copyOut = Invoke-DockerProbe -Arguments @("cp", "${RunnerContainer}:$SourceDirectory/$migration", $hostTransfer)
            if ($copyOut.exit_code -ne 0) { throw "Could not export pinned runtime migration $migration" }
            if ((Get-FileSha256 -Path $hostTransfer) -ne $MigrationSha256[$migration]) { throw "Exported runtime migration byte hash differs for $migration" }
            $copyIn = Invoke-DockerProbe -Arguments @("cp", $hostTransfer, "${CloneContainer}:$TargetDirectory/$migration")
            if ($copyIn.exit_code -ne 0) { throw "Could not copy pinned runtime migration $migration into clone" }
            $checksum = Invoke-DockerProbe -Arguments @("exec", "--user=root", $CloneContainer, "sha256sum", "--", "$TargetDirectory/$migration")
            if ($checksum.exit_code -ne 0 -or (($checksum.output -join "`n") -notmatch "^$($MigrationSha256[$migration])\s")) { throw "Copied runtime migration byte hash differs for $migration" }
        }
        finally {
            Remove-Item -LiteralPath $hostTransfer -Force -ErrorAction SilentlyContinue
        }
    }
}

function New-PinnedRuntimeMigrationSql {
    param([Parameter(Mandatory = $true)][string[]]$ExpectedBefore, [Parameter(Mandatory = $true)][string]$TargetDirectory)

    $before = ConvertTo-SqlTextArray -Values $ExpectedBefore
    $after = ConvertTo-SqlTextArray -Values $TargetMigrations
    $lines = [System.Collections.Generic.List[string]]::new()
    [void]$lines.Add("SET LOCAL lock_timeout = '5s';")
    [void]$lines.Add("SET LOCAL statement_timeout = '120s';")
    [void]$lines.Add("SELECT pg_advisory_xact_lock($SchemaAdvisoryLock);")
    [void]$lines.Add(@"
DO `$upgrade`$
DECLARE actual text[];
BEGIN
    SELECT COALESCE(array_agg(version ORDER BY version), ARRAY[]::text[]) INTO actual FROM schema_migrations;
    IF actual IS DISTINCT FROM $before THEN
        RAISE EXCEPTION 'clone migration profile is not the exact runtime preflight baseline';
    END IF;
END
`$upgrade`$;
"@)
    foreach ($migration in $RuntimeMigrationSuffix) {
        $number = $migration.Substring(0, 3)
        [void]$lines.Add("SELECT CASE WHEN EXISTS (SELECT 1 FROM schema_migrations WHERE version='$migration') THEN 'false' ELSE 'true' END AS apply_$number \gset")
        [void]$lines.Add("\if :apply_$number")
        [void]$lines.Add("\i $TargetDirectory/$migration")
        [void]$lines.Add("INSERT INTO schema_migrations(version) VALUES ('$migration');")
        [void]$lines.Add("\endif")
    }
    [void]$lines.Add(@"
DO `$upgrade`$
DECLARE actual text[];
BEGIN
    SELECT COALESCE(array_agg(version ORDER BY version), ARRAY[]::text[]) INTO actual FROM schema_migrations;
    IF actual IS DISTINCT FROM $after THEN
        RAISE EXCEPTION 'clone migration profile is not exact 001--016,018 after pinned runtime runner';
    END IF;
END
`$upgrade`$;
"@)
    return ($lines -join "`n") + "`n"
}

function Invoke-PinnedRuntimeMigrationRunner {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)][string]$TargetDirectory,
        [Parameter(Mandatory = $true)][string[]]$ExpectedBefore
    )

    Assert-CloneDatabaseName -DatabaseName $DatabaseName
    $localRunner = [System.IO.Path]::GetTempFileName()
    $containerRunner = "$TargetDirectory/$([System.IO.Path]::GetFileName($localRunner))"
    try {
        Write-Utf8NoBom -Path $localRunner -Content (New-PinnedRuntimeMigrationSql -ExpectedBefore $ExpectedBefore -TargetDirectory $TargetDirectory)
        $copy = Invoke-DockerProbe -Arguments @("cp", $localRunner, "${Container}:$TargetDirectory/")
        if ($copy.exit_code -ne 0) { throw "Could not copy runtime migration runner into clone" }
        $run = Invoke-DockerProbe -Arguments @("exec", $Container, "psql", "--username=$CloneDatabaseUser", "--dbname=$DatabaseName", "--set=ON_ERROR_STOP=1", "--single-transaction", "--file=$containerRunner")
        if ($run.exit_code -ne 0) { throw "Pinned runtime migration runner failed on clone-only database" }
    }
    finally {
        Remove-Item -LiteralPath $localRunner -Force -ErrorAction SilentlyContinue
        Invoke-DockerProbe -Arguments @("exec", "--user=root", $Container, "rm", "-f", "--", $containerRunner) | Out-Null
    }
}

function Remove-CloneOnlyResources {
    param(
        [string]$RunnerContainer, [string]$CloneContainer, [string]$CloneVolume,
        [string]$StageVolume, [string]$UpgradeDrillDatabase, [string]$RestoreDrillDatabase,
        [string]$Suffix
    )

    $errors = [System.Collections.Generic.List[string]]::new()
    if ($RunnerContainer) {
        $labels = Invoke-DockerProbe -Arguments @("inspect", "--format", "{{json .Config.Labels}}", $RunnerContainer)
        $json = (($labels.output | Select-Object -Last 1) -as [string]).Trim()
        if ($labels.exit_code -eq 0 -and $json) {
            $parsed = $json | ConvertFrom-Json
            if ($parsed.'com.kairos.scope' -eq $CloneScope -and $parsed.'com.kairos.drill' -eq $Suffix) {
                if ((Invoke-DockerProbe -Arguments @("rm", "-f", $RunnerContainer)).exit_code -ne 0) { [void]$errors.Add("could not remove migration-runner probe") }
            }
            else { [void]$errors.Add("refused to remove a probe with mismatched labels") }
        }
    }
    if ($CloneContainer) {
        $exists = Invoke-DockerProbe -Arguments @("inspect", "--format", "{{.Id}}", $CloneContainer)
        if ($exists.exit_code -eq 0) {
            try {
                Assert-CloneContainerIdentity -Container $CloneContainer -DataVolume $CloneVolume -StageVolume $StageVolume -Suffix $Suffix
                $running = Invoke-DockerProbe -Arguments @("inspect", "--format", "{{.State.Running}}", $CloneContainer)
                if ((($running.output | Select-Object -Last 1) -as [string]).Trim() -eq "true") {
                    foreach ($database in @($UpgradeDrillDatabase, $RestoreDrillDatabase)) {
                        Assert-CloneDatabaseName -DatabaseName $database
                        if ((Invoke-DockerProbe -Arguments @("exec", $CloneContainer, "dropdb", "--if-exists", "--force", "--username=$CloneDatabaseUser", $database)).exit_code -ne 0) { [void]$errors.Add("could not drop generated clone database") }
                    }
                }
                if ((Invoke-DockerProbe -Arguments @("rm", "-f", $CloneContainer)).exit_code -ne 0) { [void]$errors.Add("could not remove isolated clone container") }
            }
            catch { [void]$errors.Add($_.Exception.Message) }
        }
    }
    foreach ($volume in @($StageVolume, $CloneVolume)) {
        if (-not $volume) { continue }
        $exists = Invoke-DockerProbe -Arguments @("volume", "inspect", "--format", "{{.Name}}", $volume)
        if ($exists.exit_code -ne 0) { continue }
        try {
            Assert-CloneVolumeIdentity -Volume $volume -Suffix $Suffix
            if ((Invoke-DockerProbe -Arguments @("volume", "rm", $volume)).exit_code -ne 0) { [void]$errors.Add("could not remove isolated clone volume") }
        }
        catch { [void]$errors.Add($_.Exception.Message) }
    }
    if ($errors.Count -gt 0) { throw ("Runtime-profile clone cleanup failed: " + ($errors -join "; ")) }
}

$manifestFile = (Resolve-Path -LiteralPath $ManifestPath).Path
$receiptFile = (Resolve-Path -LiteralPath $RecoveryReceiptPath).Path
$manifest = Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
$recoveryReceipt = Get-Content -LiteralPath $receiptFile -Raw | ConvertFrom-Json
$manifestHash = Get-FileSha256 -Path $manifestFile
$verifiedInput = Get-VerifiedInput -Manifest $manifest -Receipt $recoveryReceipt -ManifestSha256 $manifestHash
$dump = (Resolve-Path -LiteralPath (Join-Path (Split-Path -Parent $manifestFile) $manifest.file)).Path
$dumpItem = Get-Item -LiteralPath $dump
if ((Get-FileSha256 -Path $dump) -ne $manifest.sha256 -or $dumpItem.Length -ne [long]$manifest.bytes) {
    throw "Backup dump does not match its manifest"
}
$checkpointDigest = Get-CheckpointDigest -Checkpoints $manifest.checkpoints
$receiptHash = Get-FileSha256 -Path $receiptFile

$suffix = ([guid]::NewGuid().ToString("N")).Substring(0, 12)
$cloneContainer = "kairos-runtime-schema-profile-preflight-$suffix"
$cloneVolume = "kairos-runtime-schema-profile-data-$suffix"
$cloneStageVolume = "kairos-runtime-schema-profile-stage-$suffix"
$runnerProbe = "kairos-runtime-schema-profile-runner-$suffix"
$upgradeDrillDatabase = "kairos_runtime_profile_drill_$suffix"
$restoreDrillDatabase = "kairos_runtime_profile_restore_drill_$suffix"
$stageDirectory = "/kairos-stage"
$inputDump = "$stageDirectory/$([System.IO.Path]::GetFileName($dump))"
$upgradedDump = "$stageDirectory/kairos-runtime-profile-$suffix.dump"
$migrationDirectory = "$stageDirectory/runtime-migrations"
Assert-CloneDatabaseName -DatabaseName $upgradeDrillDatabase
Assert-CloneDatabaseName -DatabaseName $restoreDrillDatabase

$passwordBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($passwordBytes)
$ephemeralPassword = [Convert]::ToBase64String($passwordBytes)
$runnerProbeId = $null
$receipt = $null
$operationError = $null
try {
    foreach ($volume in @($cloneVolume, $cloneStageVolume)) {
        $create = Invoke-DockerProbe -Arguments @("volume", "create", "--label", "com.kairos.scope=$CloneScope", "--label", "com.kairos.drill=$suffix", $volume)
        if ($create.exit_code -ne 0) { throw "Could not create isolated clone volume" }
        Assert-CloneVolumeIdentity -Volume $volume -Suffix $suffix
    }
    $createClone = Invoke-DockerProbe -Arguments @(
        "create", "--name", $cloneContainer, "--network", "none", "--memory", "2g", "--cpus", "2", "--pids-limit", "256",
        "--label", "com.kairos.scope=$CloneScope", "--label", "com.kairos.drill=$suffix",
        "--mount", "type=volume,src=$cloneVolume,dst=/var/lib/postgresql/data",
        "--mount", "type=volume,src=$cloneStageVolume,dst=$stageDirectory",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=256m",
        "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,noexec,mode=1777,size=16m",
        "--env", "POSTGRES_USER=$CloneDatabaseUser", "--env", "POSTGRES_DB=postgres", "--env", "POSTGRES_PASSWORD=$ephemeralPassword", $ExpectedTimescaleImage
    )
    if ($createClone.exit_code -ne 0) { throw "Could not create isolated clone container" }
    Assert-CloneContainerIdentity -Container $cloneContainer -DataVolume $cloneVolume -StageVolume $cloneStageVolume -Suffix $suffix
    if ((Invoke-DockerProbe -Arguments @("start", $cloneContainer)).exit_code -ne 0) { throw "Could not start isolated clone container" }
    Wait-CloneDatabaseReady -Container $cloneContainer
    $timescaleJobOwners = Ensure-TimescaleJobOwners -Container $cloneContainer -Owners $verifiedInput.timescaledb_bgw_owners

    $runnerProbeId = $runnerProbe
    $pinnedSource = Get-PinnedMigrationSource -Image $MigrationRunnerImage -ProbeContainer $runnerProbe -Suffix $suffix
    $runnerProbeId = [string]$pinnedSource.container_id
    if ((Invoke-DockerProbe -Arguments @("cp", $dump, "${cloneContainer}:$stageDirectory/")).exit_code -ne 0) { throw "Could not copy verified source backup into isolated clone" }
    $staged = Invoke-DockerProbe -Arguments @("exec", "--user=root", $cloneContainer, "test", "-f", $inputDump)
    if ($staged.exit_code -ne 0) { throw "Verified source backup is missing from the clone staging volume" }
    Restore-VerifiedDump -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -DumpPathInContainer $inputDump
    Assert-CloneMigrationProfile -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Expected $LegacyMigrations -Description "Restored source clone"
    $legacyFingerprint = Assert-VettedLegacySchemaShape -Container $cloneContainer -DatabaseName $upgradeDrillDatabase
    $preconditions = Assert-CloneDdlPreconditions -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Suffix $suffix
    Assert-ManifestCheckpoints -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Checkpoints $manifest.checkpoints
    $absence = Assert-RuntimeObjects -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Present $false

    Copy-PinnedRuntimeMigrations -RunnerContainer $runnerProbeId -SourceDirectory $pinnedSource.migration_directory -CloneContainer $cloneContainer -TargetDirectory $migrationDirectory
    Invoke-PinnedRuntimeMigrationRunner -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -TargetDirectory $migrationDirectory -ExpectedBefore $LegacyMigrations
    Assert-CloneMigrationProfile -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Expected $TargetMigrations -Description "First pinned runtime clone migration pass"
    $postUpgradeObjects = Assert-RuntimeObjects -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Present $true
    $shape = Assert-VettedRuntimeSchemaShape -Container $cloneContainer -DatabaseName $upgradeDrillDatabase
    Assert-ManifestCheckpoints -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Checkpoints $manifest.checkpoints
    $firstFingerprint = Get-RuntimeSchemaFingerprint -Container $cloneContainer -DatabaseName $upgradeDrillDatabase

    Invoke-PinnedRuntimeMigrationRunner -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -TargetDirectory $migrationDirectory -ExpectedBefore $TargetMigrations
    Assert-CloneMigrationProfile -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Expected $TargetMigrations -Description "Second pinned runtime clone migration pass"
    Assert-RuntimeObjects -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Present $true | Out-Null
    $secondFingerprint = Get-RuntimeSchemaFingerprint -Container $cloneContainer -DatabaseName $upgradeDrillDatabase
    if ($firstFingerprint -ne $secondFingerprint) { throw "Second pinned runtime clone migration pass changed the runtime schema fingerprint" }

    $dumpClone = Invoke-DockerProbe -Arguments @("exec", $cloneContainer, "pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--username=$CloneDatabaseUser", "--dbname=$upgradeDrillDatabase", "--file=$upgradedDump")
    if ($dumpClone.exit_code -ne 0) { throw "Could not create upgraded runtime clone restore-drill backup" }
    Restore-VerifiedDump -Container $cloneContainer -DatabaseName $restoreDrillDatabase -DumpPathInContainer $upgradedDump
    Assert-CloneMigrationProfile -Container $cloneContainer -DatabaseName $restoreDrillDatabase -Expected $TargetMigrations -Description "Restored upgraded runtime clone drill"
    Assert-RuntimeObjects -Container $cloneContainer -DatabaseName $restoreDrillDatabase -Present $true | Out-Null
    Assert-VettedRuntimeSchemaShape -Container $cloneContainer -DatabaseName $restoreDrillDatabase | Out-Null
    Assert-ManifestCheckpoints -Container $cloneContainer -DatabaseName $restoreDrillDatabase -Checkpoints $manifest.checkpoints
    $restoreFingerprint = Get-RuntimeSchemaFingerprint -Container $cloneContainer -DatabaseName $restoreDrillDatabase
    if ($restoreFingerprint -ne $firstFingerprint) { throw "Restored runtime clone schema fingerprint differs from the upgraded source clone" }
    if ((Get-FileSha256 -Path $dump) -ne $manifest.sha256 -or (Get-Item -LiteralPath $dump).Length -ne [long]$manifest.bytes) { throw "Verified source backup changed during clone-only preflight" }

    $receipt = [ordered]@{
        schema_version = 1
        classification = "CLONE_ONLY_RUNTIME_SCHEMA_PROFILE_PREFLIGHT"
        result = "PASS_CLONE_ONLY"
        created_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        readiness = [ordered]@{ paper_qualified = $false; alpha_ready = $false; live_ready = $false; strategy_policy = "REJECT_ALL" }
        source_backup = [ordered]@{
            sha256 = $manifest.sha256
            bytes = [long]$manifest.bytes
            manifest_sha256 = $manifestHash
            recovery_receipt_sha256 = $receiptHash
            checkpoint_sha256 = $checkpointDigest
            legacy_schema_fingerprint_sha256 = $legacyFingerprint
            source_database = $manifest.database
            source_compose_project = $manifest.compose_project
            backup_created_at_utc = $verifiedInput.backup_created_at_utc
            recovery_receipt_created_at_utc = $verifiedInput.recovery_receipt_created_at_utc
            recovery_facts = $verifiedInput.recovery_facts
            timescaledb_bgw_owners = $verifiedInput.timescaledb_bgw_owners
        }
        migration_runner = [ordered]@{
            persistence_repository = $ExpectedPersistenceRepository
            persistence_revision = $ExpectedPersistenceRevision
            image_digest = $MigrationRunnerImage
            package_inventory = $AllPackageMigrations
            exact_runtime_profile = $TargetMigrations
            excluded_simulator_migration = "017_simulator_journal.sql"
            migration_sha256 = $MigrationSha256
        }
        clone = [ordered]@{
            isolated = $true
            original_runtime_contacted = $false
            redis_contacted = $false
            publisher_contacted = $false
            timescaledb_bgw_owner_placeholders = $timescaleJobOwners
            unique_drill_databases = 2
            pre_upgrade_runtime_objects = $absence
            post_upgrade_runtime_objects = $postUpgradeObjects
            simulator_relations_present = $false
            preconditions = $preconditions
            vetted_runtime_shape = $shape
        }
        idempotency = [ordered]@{
            first_pass_migration_count = [long]$TargetMigrations.Count
            second_pass_migration_count = [long]$TargetMigrations.Count
            first_pass_schema_fingerprint_sha256 = $firstFingerprint
            second_pass_schema_fingerprint_sha256 = $secondFingerprint
            unchanged = $true
        }
        restore_drill = [ordered]@{ target_profile = $TargetMigrations; schema_fingerprint_sha256 = $restoreFingerprint; passed = $true }
        original_migration = [ordered]@{
            authorized = $false
            target_ddl_permissions_verified = $false
            required_next_gate = "SEPARATE_LEGACY_OUTBOX_QUARANTINE_CLONE_REHEARSAL"
            runtime_profile_only = $true
            simulator_journal_on_runtime_clone = "ABSENT_AND_FORBIDDEN"
        }
        assertions = @(
            "no original database migration occurred",
            "no runtime service, volume, network, or secret was mounted",
            "migration runner package inventory was pinned to reviewed raw Git-blob bytes",
            "only 001--016,018 was copied into the runtime clone",
            "simulator migration 017 and sim_* relations are absent from the runtime clone",
            "clone DDL capability does not prove original target-role permission",
            "schema evidence does not grant PAPER, alpha, simulator, or LIVE readiness"
        )
    }
}
catch {
    $operationError = $_
}
finally {
    try {
        Remove-CloneOnlyResources -RunnerContainer $runnerProbeId -CloneContainer $cloneContainer -CloneVolume $cloneVolume -StageVolume $cloneStageVolume -UpgradeDrillDatabase $upgradeDrillDatabase -RestoreDrillDatabase $restoreDrillDatabase -Suffix $suffix
    }
    catch {
        if ($null -eq $operationError) { $operationError = $_ }
        else { Write-Error "Runtime-profile clone cleanup failure after preflight failure: $($_.Exception.Message)" }
    }
}

if ($null -ne $operationError) { throw $operationError }
if ($null -eq $receipt) { throw "Runtime-profile clone preflight did not create a receipt" }
if ([string]::IsNullOrWhiteSpace($ReceiptPath)) {
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $ReceiptPath = Join-Path (Split-Path -Parent $manifestFile) "runtime-schema-profile-preflight-$stamp.json"
}
$receiptFullPath = [System.IO.Path]::GetFullPath($ReceiptPath)
$manifestDirectory = [System.IO.Path]::GetFullPath((Split-Path -Parent $manifestFile))
if (-not $receiptFullPath.StartsWith($manifestDirectory + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Runtime-profile preflight receipt must remain beside the immutable backup manifest"
}
if (Test-Path -LiteralPath $receiptFullPath) { throw "Runtime-profile preflight receipt already exists" }
Write-Utf8NoBom -Path $receiptFullPath -Content ($receipt | ConvertTo-Json -Depth 12)
Write-Output "Runtime-only clone schema-profile preflight passed: $receiptFullPath"
