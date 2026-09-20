<#
.SYNOPSIS
    Performs a clone-only 001--012 to 001--018 schema-upgrade preflight.

.DESCRIPTION
    This is an operator-only recovery drill.  It never joins a Compose project,
    reads a runtime secret, mounts a runtime volume, or opens the source
    database.  Instead it verifies a backup manifest and its prior, read-only
    001--012 recovery receipt, then restores that dump into a newly-created,
    isolated TimescaleDB container.  DDL is applied only to generated drill
    database names in that isolated container.

    The migration image is intentionally supplied as an immutable OCI digest.
    The image must carry source/revision labels for the reviewed persistence
    revision and must contain exactly the migration bytes pinned below.  The
    generic persistence migration entrypoint is deliberately not used: it would apply a
    future migration outside this preflight's 001--018 boundary.

    The tool drops only its two generated drill databases and its uniquely
    labelled disposable container/two volumes.  It never has a parameter that can
    name a source database or retain a clone.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [Parameter(Mandatory = $true)]
    [string]$BaselineReceiptPath,

    [Parameter(Mandatory = $true)]
    [string]$MigrationRunnerImage,

    [Parameter(Mandatory = $true)]
    [ValidateSet("CLONE_ONLY_SCHEMA_UPGRADE_PREFLIGHT")]
    [string]$Confirmation,

    [string]$ReceiptPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ExpectedPersistenceRepository = "https://github.com/Kairos-cryptoAI/kairos-persistence"
$ExpectedPersistenceRevision = "9219e5ef46c748703d949b324d84f6814ba0f196"
$ExpectedTimescaleImage = "timescale/timescaledb:2.29.1-pg16@sha256:252a443e2936039b83dd8da1373d01e59e932d1054fa6adf1bc061f1d56ae60a"
$ExpectedSourceComposeProject = "kairos-paper-gate"
$ExpectedSourceDatabase = "kairos"
$MaximumBackupAge = [TimeSpan]::FromHours(2)
$SchemaAdvisoryLock = "4907627681104115019"
$CloneScope = "clone-only-schema-upgrade-preflight"
$CloneDatabaseUser = "kairos_upgrade"
$ExpectedMigrationRunnerUser = "10001:10001"
# SHA-256 of the canonical public 001--012 schema inventory restored from the
# pinned migration bytes with the exact TimescaleDB image above.  Migration rows
# and row-count checkpoints alone cannot prove that a legacy dump has not had
# out-of-band DDL applied before this clone-only drill.
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
$TargetMigrations = @(
    $LegacyMigrations + @(
        "013_campaign_source_budgets.sql",
        "014_bounded_canary_sessions.sql",
        "015_canary_dispatch_claims.sql",
        "016_global_canary_session_guard.sql",
        "017_simulator_journal.sql",
        "018_offline_outbox_reconciliation.sql"
    )
)

# Raw Git-blob bytes from the immutable persistence revision above.  A runner
# image may contain no additional migrations and must provide these exact
# bytes; Windows working-tree line-ending conversion is not part of this trust
# boundary.
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

$PostBaselineRelations = @(
    "campaign_source_budgets",
    "paper_canary_database_identity",
    "paper_readonly_runs",
    "paper_readonly_samples",
    "paper_readonly_receipts",
    "paper_canary_sessions",
    "paper_canary_attempts",
    "paper_canary_dispatch_claims",
    "sim_tapes",
    "sim_closed_bars",
    "sim_book_frames",
    "sim_sessions",
    "sim_risk_decisions",
    "sim_admissions",
    "sim_trades",
    "sim_commands",
    "sim_command_receipts",
    "sim_liquidity_states",
    "sim_trade_events",
    "sim_results",
    "sim_session_receipts"
)
$PostBaselineColumns = @(
    "reconciliation_state",
    "reconciliation_id",
    "reconciliation_started_at",
    "reconciliation_outcome_at"
)
$PostBaselineConstraints = @(
    "message_outbox_reconciliation_state",
    "message_outbox_reconciliation_identity"
)
$PostBaselineIndexes = @(
    "source_usage_campaign_idx",
    "paper_canary_one_active_remote_account",
    "paper_canary_one_outstanding_attempt",
    "paper_canary_one_active_project",
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

    # Some constrained Windows PowerShell hosts do not expose Get-FileHash.
    # Hash the exact on-disk bytes through .NET so this immutable-input gate
    # behaves identically under Windows PowerShell and pwsh.
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

    # -Encoding utf8NoBOM exists in PowerShell 7 but not Windows PowerShell
    # 5.1.  The .NET writer keeps this operator tool compatible with both.
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

function Invoke-DockerProbe {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    # Windows PowerShell 5.1 treats a non-zero native probe as terminating
    # under ErrorActionPreference=Stop even with stderr redirected.  Use this
    # only for expected readiness/existence probes; callers inspect exit_code.
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& docker @Arguments 2>$null)
        $exitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousErrorActionPreference }
    return [pscustomobject]@{ output = $output; exit_code = [int]$exitCode }
}

function ConvertTo-Base64PythonCommand {
    param([Parameter(Mandatory = $true)][string]$Content)

    # Windows PowerShell's legacy native-command argument marshalling can strip
    # quote characters embedded in a multiline ``python -c`` program.  Pass the
    # reviewed program as Base64 and construct the decoder name/string literals
    # with ``chr`` so the native argument itself contains no quotes to rewrite.
    # The decoded content is still the exact code declared by the caller.
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Content))
    # A Base64 token cannot be used bare in Python source (it would be parsed
    # as an identifier).  Encode its ASCII bytes as integers so the final
    # argument remains quote-free all the way through Windows PowerShell.
    $encodedBytes = @([System.Text.Encoding]::ASCII.GetBytes($encoded) | ForEach-Object { [int]$_ }) -join ","
    return "exec(__import__(chr(98)+chr(97)+chr(115)+chr(101)+chr(54)+chr(52)).b64decode(bytes(($encodedBytes))))"
}

function Get-CheckpointDigest {
    param([Parameter(Mandatory = $true)]$Checkpoints)

    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($table in $CheckpointTables + @("public_execution_events_max_sequence")) {
        $value = $Checkpoints.$table
        if ($null -eq $value -or [string]$value -notmatch '^\d+$') {
            throw "Backup manifest has no non-negative checkpoint for $table"
        }
        [void]$parts.Add("$table=$([long]$value)")
    }
    return Get-Sha256Hex -Bytes ([System.Text.Encoding]::UTF8.GetBytes(($parts -join "`n")))
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

function Assert-CleanBaselineReceipt {
    param([Parameter(Mandatory = $true)]$Receipt)

    $inbox = Get-RequiredProperty -Object $Receipt -Name "inbox" -Description "Baseline receipt"
    $outbox = Get-RequiredProperty -Object $Receipt -Name "outbox" -Description "Baseline receipt"
    $zeroFacts = @(
        @{ object = $inbox; name = "failed"; description = "Baseline inbox" },
        @{ object = $inbox; name = "processing"; description = "Baseline inbox" },
        @{ object = $inbox; name = "expired_processing"; description = "Baseline inbox" },
        @{ object = $outbox; name = "active_leases"; description = "Baseline outbox" },
        @{ object = $outbox; name = "expired_leases"; description = "Baseline outbox" },
        @{ object = $outbox; name = "duplicate_audit_ids"; description = "Baseline outbox" },
        @{ object = $outbox; name = "duplicate_outbox_ids"; description = "Baseline outbox" },
        @{ object = $outbox; name = "outbox_without_audit"; description = "Baseline outbox" }
    )
    foreach ($fact in $zeroFacts) {
        $value = Get-RequiredProperty -Object $fact.object -Name $fact.name -Description $fact.description
        if ([string]$value -notmatch '^\d+$' -or [long]$value -ne 0) {
            throw "$($fact.description) is not clean: $($fact.name) must equal zero"
        }
    }
    if ((Get-RequiredProperty -Object $outbox -Name "read_only_consumer_restart_permitted" -Description "Baseline outbox") -ne $true) {
        throw "Baseline outbox does not permit a read-only consumer restart"
    }
    if ((Get-RequiredProperty -Object $Receipt -Name "offline_bar_recovery_permitted" -Description "Baseline receipt") -ne $true) {
        throw "Baseline receipt does not permit offline bar recovery"
    }
}

function Get-ExplicitUtcTimestamp {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Description
    )

    # ConvertFrom-Json materializes an ISO-8601 Z value as DateTime.  Casting
    # it back to string first loses its UTC kind on a non-UTC host, making a
    # fresh backup appear several hours old.  Preserve and require its UTC
    # provenance instead.
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

function Get-FreshVerifiedBaseline {
    param(
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)]$Receipt,
        [Parameter(Mandatory = $true)][string]$ManifestSha256
    )

    if ($Manifest.compose_project -cne $ExpectedSourceComposeProject -or $Manifest.database -cne $ExpectedSourceDatabase) {
        throw "Backup manifest must identify the isolated $ExpectedSourceComposeProject/$ExpectedSourceDatabase runtime"
    }
    if ($Receipt.compose_project -cne $ExpectedSourceComposeProject -or $Receipt.database -cne $ExpectedSourceDatabase) {
        throw "Baseline receipt must identify the isolated $ExpectedSourceComposeProject/$ExpectedSourceDatabase runtime"
    }
    if ((Get-RequiredProperty -Object $Receipt -Name "backup_manifest_sha256" -Description "Baseline receipt") -cne $ManifestSha256) {
        throw "Baseline receipt does not bind the exact backup manifest bytes"
    }
    $createdAt = Get-ExplicitUtcTimestamp -Object $Manifest -Name "created_at_utc" -Description "Backup manifest"
    $receiptCreatedAt = Get-ExplicitUtcTimestamp -Object $Receipt -Name "created_at_utc" -Description "Baseline receipt"
    $now = [DateTimeOffset]::UtcNow
    $age = $now - $createdAt
    $receiptAge = $now - $receiptCreatedAt
    $clockTolerance = [TimeSpan]::FromMinutes(5)
    if ($age.TotalSeconds -lt -$clockTolerance.TotalSeconds -or $age -gt $MaximumBackupAge) {
        throw "Backup manifest is not a fresh two-hour runtime snapshot"
    }
    if ($receiptAge.TotalSeconds -lt -$clockTolerance.TotalSeconds -or $receiptAge -gt $MaximumBackupAge) {
        throw "Baseline receipt is not a fresh two-hour runtime verification"
    }
    if ($receiptCreatedAt -lt ($createdAt - $clockTolerance)) {
        throw "Baseline receipt predates the verified backup manifest"
    }
    Assert-CleanBaselineReceipt -Receipt $Receipt
    return $createdAt.ToUniversalTime().ToString("o")
}

function ConvertTo-SqlTextArray {
    param([Parameter(Mandatory = $true)][string[]]$Values)

    $quoted = $Values | ForEach-Object { "'$($_.Replace("'", "''"))'" }
    return "ARRAY[" + ($quoted -join ",") + "]::text[]"
}

function Assert-CloneDatabaseName {
    param([Parameter(Mandatory = $true)][string]$DatabaseName)

    if ($DatabaseName -notmatch '^kairos_schema_upgrade_(?:restore_)?drill_[0-9a-f]{12}$') {
        throw "Refusing a database name outside the generated clone-only drill namespace"
    }
}

function Assert-CloneContainerIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DataVolume,
        [Parameter(Mandatory = $true)][string]$StageVolume,
        [Parameter(Mandatory = $true)][string]$Suffix
    )

    $labelInspection = Invoke-DockerProbe -Arguments @("inspect", "--format", "{{json .Config.Labels}}", $Container)
    $labelsJson = (($labelInspection.output | Select-Object -Last 1) -as [string]).Trim()
    if ($labelInspection.exit_code -ne 0 -or -not $labelsJson) {
        throw "Could not inspect the isolated clone container"
    }
    $labels = $labelsJson | ConvertFrom-Json
    if ($labels.'com.kairos.scope' -ne $CloneScope -or $labels.'com.kairos.drill' -ne $Suffix) {
        throw "Isolated clone container identity labels do not match this drill"
    }
    $networkInspection = Invoke-DockerProbe -Arguments @("inspect", "--format", "{{.HostConfig.NetworkMode}}", $Container)
    $networkMode = (($networkInspection.output | Select-Object -Last 1) -as [string]).Trim()
    if ($networkInspection.exit_code -ne 0 -or $networkMode -ne "none") {
        throw "Clone container must have no network"
    }
    $mountInspection = Invoke-DockerProbe -Arguments @("inspect", "--format", "{{json .Mounts}}", $Container)
    $mountsJson = (($mountInspection.output | Select-Object -Last 1) -as [string]).Trim()
    if ($mountInspection.exit_code -ne 0 -or -not $mountsJson) {
        throw "Could not inspect clone container mounts"
    }
    # Windows PowerShell preserves a JSON array as one pipeline object; flatten
    # it before enforcing the exact two generated volume mounts.
    $mounts = @($mountsJson | ConvertFrom-Json | ForEach-Object { $_ })
    $expectedMounts = @(
        [pscustomobject]@{ destination = "/var/lib/postgresql/data"; volume = $DataVolume },
        [pscustomobject]@{ destination = "/kairos-stage"; volume = $StageVolume }
    )
    if ($mounts.Count -ne $expectedMounts.Count) {
        throw "Clone container must use exactly its own disposable data and staging volumes"
    }
    foreach ($expectedMount in $expectedMounts) {
        $actualMount = @($mounts | Where-Object { $_.Destination -eq $expectedMount.destination })
        if ($actualMount.Count -ne 1 -or $actualMount[0].Type -ne "volume" -or $actualMount[0].Name -ne $expectedMount.volume) {
            throw "Clone container mounts do not match its generated disposable volumes"
        }
    }
}

function Assert-CloneVolumeIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Volume,
        [Parameter(Mandatory = $true)][string]$Suffix
    )

    $labelInspection = Invoke-DockerProbe -Arguments @("volume", "inspect", "--format", "{{json .Labels}}", $Volume)
    $labelsJson = (($labelInspection.output | Select-Object -Last 1) -as [string]).Trim()
    if ($labelInspection.exit_code -ne 0 -or -not $labelsJson) {
        throw "Could not inspect the isolated clone volume"
    }
    $labels = $labelsJson | ConvertFrom-Json
    if ($labels.'com.kairos.scope' -ne $CloneScope -or $labels.'com.kairos.drill' -ne $Suffix) {
        throw "Clone volume identity labels do not match this drill"
    }
}

function Wait-CloneDatabaseReady {
    param([Parameter(Mandatory = $true)][string]$Container)

    # The image entrypoint may expose a temporary postmaster during initdb.
    # Require stable authenticated SQL readiness before any restore work.
    $consecutiveSqlProbes = 0
    for ($attempt = 1; $attempt -le 60; $attempt++) {
        $containerInspection = Invoke-DockerProbe -Arguments @("inspect", "--format", "{{.State.Running}}", $Container)
        $running = (($containerInspection.output | Select-Object -Last 1) -as [string]).Trim()
        $inspectExitCode = $containerInspection.exit_code
        if ($inspectExitCode -ne 0 -or $running -cne "true") {
            throw "Isolated clone database stopped before it became stable"
        }
        $logResult = Invoke-DockerProbe -Arguments @("logs", $Container)
        if ($logResult.exit_code -ne 0 -or $logResult.output -notcontains "PostgreSQL init process complete; ready for start up.") {
            $consecutiveSqlProbes = 0
            Start-Sleep -Seconds 2
            continue
        }
        $probeResult = Invoke-DockerProbe -Arguments @(
            "exec", $Container, "psql", "--username=$CloneDatabaseUser", "--dbname=postgres",
            "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1", "--command=SELECT 1;"
        )
        $probe = $probeResult.output
        $probeExitCode = $probeResult.exit_code
        $probeValues = @($probe | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
        if ($probeExitCode -eq 0 -and $probeValues -contains "1") {
            $consecutiveSqlProbes++
            if ($consecutiveSqlProbes -ge 3) { return }
            Start-Sleep -Seconds 2
            continue
        }
        else {
            $consecutiveSqlProbes = 0
        }
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
    $lines = @(& docker exec $Container psql --username=$CloneDatabaseUser --dbname=$DatabaseName `
        --tuples-only --no-align --set=ON_ERROR_STOP=1 --command=$Query)
    if ($LASTEXITCODE -ne 0) {
        throw "Clone-only database query failed"
    }
    return @($lines | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
}

function Get-CloneMigrations {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName
    )

    return @(Invoke-CloneDatabaseLines -Container $Container -DatabaseName $DatabaseName `
        -Query "SELECT version FROM schema_migrations ORDER BY version;")
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

    Assert-CloneDatabaseName -DatabaseName $DatabaseName
    foreach ($table in $CheckpointTables) {
        $expected = $Checkpoints.$table
        if ($null -eq $expected -or [string]$expected -notmatch '^\d+$') {
            throw "Backup manifest has no valid checkpoint for $table"
        }
        $actual = @(Invoke-CloneDatabaseLines -Container $Container -DatabaseName $DatabaseName -Query "SELECT count(*) FROM $table;")
        if ($actual.Count -ne 1 -or $actual[0] -notmatch '^\d+$' -or [long]$actual[0] -ne [long]$expected) {
            throw "Clone checkpoint differs from the verified backup for $table"
        }
    }
    $expectedSequence = $Checkpoints.public_execution_events_max_sequence
    $actualSequence = @(Invoke-CloneDatabaseLines -Container $Container -DatabaseName $DatabaseName `
        -Query "SELECT COALESCE(max(event_seq),0) FROM public_execution_events;")
    if ($null -eq $expectedSequence -or $actualSequence.Count -ne 1 -or $actualSequence[0] -notmatch '^\d+$' -or
        [long]$actualSequence[0] -ne [long]$expectedSequence) {
        throw "Clone public execution sequence differs from the verified backup"
    }
}

function Get-PostBaselineObjectCounts {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName
    )

    $relations = ConvertTo-SqlTextArray -Values $PostBaselineRelations
    $columns = ConvertTo-SqlTextArray -Values $PostBaselineColumns
    $constraints = ConvertTo-SqlTextArray -Values $PostBaselineConstraints
    $indexes = ConvertTo-SqlTextArray -Values $PostBaselineIndexes
    $query = @"
SELECT
    (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relname = ANY($relations)) || '|' ||
    (SELECT count(*) FROM information_schema.columns
      WHERE table_schema='public' AND table_name='message_outbox' AND column_name = ANY($columns)) || '|' ||
    (SELECT count(*) FROM pg_constraint
      WHERE conrelid='public.message_outbox'::regclass AND conname = ANY($constraints)) || '|' ||
    (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relkind='i' AND c.relname = ANY($indexes));
"@
    $result = @(Invoke-CloneDatabaseLines -Container $Container -DatabaseName $DatabaseName -Query $query)
    if ($result.Count -ne 1) { throw "Post-baseline object receipt is malformed" }
    $values = $result[0].Split('|')
    if ($values.Count -ne 4 -or @($values | Where-Object { $_ -notmatch '^\d+$' }).Count -ne 0) {
        throw "Post-baseline object receipt has non-numeric values"
    }
    return [ordered]@{
        relations = [long]$values[0]
        columns = [long]$values[1]
        constraints = [long]$values[2]
        indexes = [long]$values[3]
    }
}

function Assert-PostBaselineObjects {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)][bool]$Present
    )

    $counts = Get-PostBaselineObjectCounts -Container $Container -DatabaseName $DatabaseName
    $expected = if ($Present) {
        [ordered]@{
            relations = [long]$PostBaselineRelations.Count
            columns = [long]$PostBaselineColumns.Count
            constraints = [long]$PostBaselineConstraints.Count
            indexes = [long]$PostBaselineIndexes.Count
        }
    }
    else {
        [ordered]@{ relations = 0L; columns = 0L; constraints = 0L; indexes = 0L }
    }
    foreach ($name in $expected.Keys) {
        if ($counts[$name] -ne $expected[$name]) {
            $state = if ($Present) { "missing or malformed" } else { "contains out-of-band" }
            throw "Clone $state post-baseline schema objects ($name)"
        }
    }
    return $counts
}

function Get-LegacySchemaFingerprint {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName
    )

    # Keep catalog identifiers and SQL definitions in the inventory, but reduce
    # free-form definitions to hashes so psql always returns one exact row.  The
    # outer SHA-256 is the reviewed schema profile; the inner md5 values merely
    # make catalog text safe to aggregate without transport-dependent newlines.
    $query = @"
WITH inventory AS (
    SELECT 'extension|' || e.extname || '|' || e.extversion AS item
    FROM pg_extension e
    WHERE e.extname='timescaledb'
    UNION ALL
    SELECT 'relation|' || c.relkind::text || '|' || c.relname || '|' ||
           CASE WHEN c.relkind IN ('v','m') THEN md5(pg_get_viewdef(c.oid, true)) ELSE '' END
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')
    UNION ALL
    SELECT 'column|' || c.relname || '|' || a.attnum::text || '|' || a.attname || '|' ||
           format_type(a.atttypid, a.atttypmod) || '|' || a.attnotnull::text || '|' ||
            a.attidentity::text || '|' || a.attgenerated::text || '|' ||
           COALESCE(md5(pg_get_expr(ad.adbin, ad.adrelid, true)), '') || '|' ||
           COALESCE(coll.collname, '')
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    LEFT JOIN pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum
    LEFT JOIN pg_collation coll ON coll.oid=a.attcollation
    WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')
      AND a.attnum > 0 AND NOT a.attisdropped
    UNION ALL
    SELECT 'constraint|' || c.relname || '|' || con.conname || '|' || con.contype::text || '|' ||
           md5(pg_get_constraintdef(con.oid, true))
    FROM pg_constraint con
    JOIN pg_class c ON c.oid=con.conrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public'
    UNION ALL
    SELECT 'index|' || t.relname || '|' || i.relname || '|' || x.indisunique::text || '|' ||
           x.indisprimary::text || '|' || x.indisvalid::text || '|' || md5(pg_get_indexdef(i.oid))
    FROM pg_index x
    JOIN pg_class i ON i.oid=x.indexrelid
    JOIN pg_class t ON t.oid=x.indrelid
    JOIN pg_namespace n ON n.oid=t.relnamespace
    WHERE n.nspname='public'
    UNION ALL
    SELECT 'trigger|' || c.relname || '|' || tg.tgname || '|' || md5(pg_get_triggerdef(tg.oid, true))
    FROM pg_trigger tg
    JOIN pg_class c ON c.oid=tg.tgrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND NOT tg.tgisinternal
    UNION ALL
    SELECT 'sequence|' || c.relname || '|' || s.seqstart::text || '|' || s.seqincrement::text || '|' ||
           s.seqmin::text || '|' || s.seqmax::text || '|' || s.seqcache::text || '|' || s.seqcycle::text
    FROM pg_sequence s
    JOIN pg_class c ON c.oid=s.seqrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public'
    UNION ALL
    SELECT 'type|' || t.typtype::text || '|' || t.typname || '|' ||
           COALESCE(format_type(t.typbasetype, t.typtypmod), '')
    FROM pg_type t
    JOIN pg_namespace n ON n.oid=t.typnamespace
    WHERE n.nspname='public' AND t.typtype IN ('b','c','d','e','r')
)
SELECT COALESCE(string_agg(item, E'\\n' ORDER BY item), '') FROM inventory;
"@
    $result = @(Invoke-CloneDatabaseLines -Container $Container -DatabaseName $DatabaseName -Query $query)
    if ($result.Count -gt 1) { throw "Legacy schema fingerprint is malformed" }
    $text = if ($result.Count -eq 1) { $result[0] } else { "" }
    return Get-Sha256Hex -Bytes ([System.Text.Encoding]::UTF8.GetBytes($text))
}

function Assert-VettedLegacySchemaShape {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName
    )

    $actual = Get-LegacySchemaFingerprint -Container $Container -DatabaseName $DatabaseName
    if ($actual -cne $ExpectedLegacySchemaFingerprint) {
        throw "Clone legacy 001--012 schema fingerprint differs from the pinned profile (expected $ExpectedLegacySchemaFingerprint; observed $actual)"
    }
    return $actual
}

function Get-PostBaselineSchemaFingerprint {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName
    )

    $relations = ConvertTo-SqlTextArray -Values $PostBaselineRelations
    $columns = ConvertTo-SqlTextArray -Values $PostBaselineColumns
    $constraints = ConvertTo-SqlTextArray -Values $PostBaselineConstraints
    $indexes = ConvertTo-SqlTextArray -Values $PostBaselineIndexes
    $query = @"
WITH inventory AS (
    SELECT 'relation|' || c.relname || '|' || c.relkind::text AS item
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname = ANY($relations)
    UNION ALL
    SELECT 'column|' || column_name || '|' || data_type || '|' || is_nullable || '|' || COALESCE(column_default,'')
    FROM information_schema.columns
    WHERE table_schema='public' AND table_name='message_outbox' AND column_name = ANY($columns)
    UNION ALL
    SELECT 'constraint|' || conname || '|' || pg_get_constraintdef(oid, true)
    FROM pg_constraint
    WHERE conrelid='public.message_outbox'::regclass AND conname = ANY($constraints)
    UNION ALL
    SELECT 'index|' || c.relname || '|' || pg_get_indexdef(c.oid)
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relkind='i' AND c.relname = ANY($indexes)
)
SELECT COALESCE(string_agg(item, E'\\n' ORDER BY item), '') FROM inventory;
"@
    $result = @(Invoke-CloneDatabaseLines -Container $Container -DatabaseName $DatabaseName -Query $query)
    if ($result.Count -gt 1) { throw "Post-baseline schema fingerprint is malformed" }
    $text = if ($result.Count -eq 1) { $result[0] } else { "" }
    return Get-Sha256Hex -Bytes ([System.Text.Encoding]::UTF8.GetBytes($text))
}

function Assert-VettedPostBaselineSchemaShape {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName
    )

    $relations = ConvertTo-SqlTextArray -Values $PostBaselineRelations
    $query = @"
WITH relation_check AS (
    SELECT count(*) = $($PostBaselineRelations.Count) AS value
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname = ANY($relations) AND c.relkind='r'
), column_check AS (
    SELECT count(*) = 4 AND bool_and(
        (column_name='reconciliation_state' AND data_type='text' AND is_nullable='NO' AND COALESCE(column_default,'') LIKE '%NONE%') OR
        (column_name='reconciliation_id' AND data_type='text' AND is_nullable='YES') OR
        (column_name='reconciliation_started_at' AND data_type='timestamp with time zone' AND is_nullable='YES') OR
        (column_name='reconciliation_outcome_at' AND data_type='timestamp with time zone' AND is_nullable='YES')
    ) AS value
    FROM information_schema.columns
    WHERE table_schema='public' AND table_name='message_outbox'
      AND column_name IN ('reconciliation_state','reconciliation_id','reconciliation_started_at','reconciliation_outcome_at')
), constraint_check AS (
    SELECT count(*) = 2 AND bool_and(
        (conname='message_outbox_reconciliation_state' AND contype='c'
          AND position('reconciliation_state' IN pg_get_constraintdef(oid, true)) > 0
          AND position('PUBLISH_OUTCOME_UNKNOWN' IN pg_get_constraintdef(oid, true)) > 0) OR
        (conname='message_outbox_reconciliation_identity' AND contype='c'
          AND position('reconciliation_id' IN pg_get_constraintdef(oid, true)) > 0
          AND position('NONE' IN pg_get_constraintdef(oid, true)) > 0)
    ) AS value
    FROM pg_constraint
    WHERE conrelid='public.message_outbox'::regclass
      AND conname IN ('message_outbox_reconciliation_state','message_outbox_reconciliation_identity')
), index_check AS (
    SELECT count(*) = 5 AND bool_and(
        (i.relname='source_usage_campaign_idx' AND t.relname='source_usage_reservations'
          AND position('source, status' IN pg_get_indexdef(i.oid)) > 0) OR
        (i.relname='paper_canary_one_active_remote_account' AND t.relname='paper_canary_sessions'
          AND position('remote_account_id' IN pg_get_indexdef(i.oid)) > 0) OR
        (i.relname='paper_canary_one_outstanding_attempt' AND t.relname='paper_canary_attempts'
          AND position('session_id' IN pg_get_indexdef(i.oid)) > 0) OR
        (i.relname='paper_canary_one_active_project' AND t.relname='paper_canary_sessions'
          AND position('scope' IN pg_get_indexdef(i.oid)) > 0) OR
        (i.relname='message_outbox_reconciliation_pending_idx' AND t.relname='message_outbox'
          AND position('reconciliation_state, id' IN pg_get_indexdef(i.oid)) > 0
          AND position('published_at IS NULL' IN pg_get_indexdef(i.oid)) > 0)
    ) AS value
    FROM pg_index x
    JOIN pg_class i ON i.oid=x.indexrelid
    JOIN pg_class t ON t.oid=x.indrelid
    WHERE i.relname IN ('source_usage_campaign_idx','paper_canary_one_active_remote_account',
                        'paper_canary_one_outstanding_attempt','paper_canary_one_active_project',
                        'message_outbox_reconciliation_pending_idx') AND x.indisvalid
)
SELECT relation_check.value::text || '|' || column_check.value::text || '|' ||
       constraint_check.value::text || '|' || index_check.value::text
FROM relation_check CROSS JOIN column_check CROSS JOIN constraint_check CROSS JOIN index_check;
"@
    $result = @(Invoke-CloneDatabaseLines -Container $Container -DatabaseName $DatabaseName -Query $query)
    if ($result.Count -ne 1) { throw "Vetted post-baseline schema receipt is malformed" }
    $facts = $result[0].Split('|')
    if ($facts.Count -ne 4 -or @($facts | Where-Object { $_ -cne 'true' }).Count -ne 0) {
        throw "Clone post-baseline schema differs from the vetted 013--018 structure"
    }
    return [ordered]@{
        relation_kinds = $true
        reconciliation_columns = $true
        reconciliation_constraints = $true
        indexes = $true
    }
}

function Assert-CloneDdlPreconditions {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)][string]$Suffix
    )

    Assert-CloneDatabaseName -DatabaseName $DatabaseName
    if ($Suffix -notmatch '^[0-9a-f]{12}$') { throw "Clone DDL probe suffix is malformed" }
    $probeTable = "kairos_schema_upgrade_probe_$Suffix"
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
    & docker exec $Container psql --username=$CloneDatabaseUser --dbname=$DatabaseName --set=ON_ERROR_STOP=1 `
        --quiet --command=$query | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Clone does not satisfy the required UUID, advisory-lock, and DDL preconditions"
    }
    return [ordered]@{
        uuid_function = $true
        advisory_lock = $true
        ddl_transaction = $true
        target_role_permissions = "NOT_VERIFIED_CLONE_ONLY"
    }
}

function Restore-VerifiedDump {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)][string]$DumpPathInContainer
    )

    Assert-CloneDatabaseName -DatabaseName $DatabaseName
    if ($DumpPathInContainer -notmatch '^/kairos-stage/[A-Za-z0-9_.-]+\.dump$') {
        throw "Refusing a dump path outside this generated clone drill"
    }
    & docker exec $Container createdb --username=$CloneDatabaseUser $DatabaseName
    if ($LASTEXITCODE -ne 0) { throw "Could not create generated clone drill database" }
    & docker exec $Container psql --username=$CloneDatabaseUser --dbname=$DatabaseName --set=ON_ERROR_STOP=1 `
        --command="CREATE EXTENSION IF NOT EXISTS timescaledb;"
    if ($LASTEXITCODE -ne 0) { throw "Could not initialize TimescaleDB in generated clone drill" }
    & docker exec $Container psql --username=$CloneDatabaseUser --dbname=$DatabaseName --set=ON_ERROR_STOP=1 `
        --command="SELECT timescaledb_pre_restore();"
    if ($LASTEXITCODE -ne 0) { throw "Could not enter TimescaleDB restore mode in generated clone drill" }
    & docker exec $Container pg_restore --exit-on-error --no-owner --no-privileges --username=$CloneDatabaseUser `
        --dbname=$DatabaseName $DumpPathInContainer
    if ($LASTEXITCODE -ne 0) { throw "pg_restore failed in generated clone drill" }
    & docker exec $Container psql --username=$CloneDatabaseUser --dbname=$DatabaseName --set=ON_ERROR_STOP=1 `
        --command="SELECT timescaledb_post_restore();"
    if ($LASTEXITCODE -ne 0) { throw "Could not leave TimescaleDB restore mode in generated clone drill" }
}

function Get-PinnedMigrationSource {
    param(
        [Parameter(Mandatory = $true)][string]$Image,
        [Parameter(Mandatory = $true)][string]$ProbeContainer,
        [Parameter(Mandatory = $true)][string]$Suffix
    )

    if ($Image -notmatch '^.+@sha256:[0-9a-f]{64}$') {
        throw "Migration runner image must be an immutable repository@sha256 digest"
    }
    $repoDigestsJson = (& docker image inspect --format '{{json .RepoDigests}}' $Image).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $repoDigestsJson) { throw "Could not inspect migration runner image digest" }
    $repoDigests = @($repoDigestsJson | ConvertFrom-Json)
    if ($repoDigests.Count -eq 0 -or @($repoDigests | Where-Object { $_ -notmatch '^.+@sha256:[0-9a-f]{64}$' }).Count -gt 0) {
        throw "Migration runner image has malformed local immutable digest metadata"
    }
    if ($repoDigests -notcontains $Image) {
        # A multi-platform OCI index can be addressed by its immutable index
        # digest while Docker records only the selected platform manifest under
        # RepoDigests.  The caller-supplied reference is still digest-only and
        # this exact reference has already been resolved by docker image
        # inspect; labels plus byte-for-byte migration checks remain mandatory.
        $resolvedImageId = (& docker image inspect --format '{{.Id}}' $Image).Trim()
        if ($LASTEXITCODE -ne 0 -or $resolvedImageId -notmatch '^sha256:[0-9a-f]{64}$') {
            throw "Migration runner immutable image reference did not resolve to a local image ID"
        }
    }
    $labelsJson = (& docker image inspect --format '{{json .Config.Labels}}' $Image).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $labelsJson) { throw "Could not inspect migration runner image labels" }
    $labels = $labelsJson | ConvertFrom-Json
    if ($labels.'org.opencontainers.image.source' -ne $ExpectedPersistenceRepository -or
        $labels.'org.opencontainers.image.revision' -ne $ExpectedPersistenceRevision) {
        throw "Migration runner image does not identify the reviewed persistence source revision"
    }
    $runnerUser = (& docker image inspect --format '{{.Config.User}}' $Image).Trim()
    if ($LASTEXITCODE -ne 0 -or $runnerUser -ne $ExpectedMigrationRunnerUser) {
        throw "Migration runner image must run as the reviewed unprivileged user"
    }

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
    $probeCommand = ConvertTo-Base64PythonCommand -Content $probeCode
    $probeId = (& docker create --name $ProbeContainer --network none --read-only --cap-drop ALL `
        --security-opt no-new-privileges:true --pids-limit 32 --memory 128m --cpus 0.25 --user $ExpectedMigrationRunnerUser `
        --label "com.kairos.scope=$CloneScope" --label "com.kairos.drill=$Suffix" `
        --entrypoint python $Image -c $probeCommand).Trim()
    if ($LASTEXITCODE -ne 0 -or $probeId -notmatch '^[0-9a-f]{64}$') {
        throw "Could not create isolated migration-runner probe"
    }
    $output = ((& docker start -a $probeId) -join "`n").Trim()
    if ($LASTEXITCODE -ne 0 -or -not $output) { throw "Pinned migration-runner probe failed" }
    try { $probe = $output | ConvertFrom-Json } catch { throw "Pinned migration-runner probe did not produce JSON" }
    $sourcePath = [string]$probe.migration_directory
    if ($sourcePath -notmatch '^/[A-Za-z0-9_./-]+$' -or $sourcePath.Contains("..")) {
        throw "Pinned migration-runner reported an unsafe migration directory"
    }
    $entries = @($probe.migrations)
    Assert-ExactStringArray -Expected $TargetMigrations -Actual @($entries | ForEach-Object { [string]$_.name }) `
        -Description "Pinned migration-runner migration inventory"
    foreach ($entry in $entries) {
        $name = [string]$entry.name
        if ([string]$entry.sha256 -ne $MigrationSha256[$name]) {
            throw "Pinned migration-runner byte hash differs for $name (expected $($MigrationSha256[$name]); observed $([string]$entry.sha256))"
        }
    }
    return [ordered]@{ container_id = $probeId; migration_directory = $sourcePath }
}

function Copy-PinnedTargetMigrations {
    param(
        [Parameter(Mandatory = $true)][string]$RunnerContainer,
        [Parameter(Mandatory = $true)][string]$SourceDirectory,
        [Parameter(Mandatory = $true)][string]$CloneContainer,
        [Parameter(Mandatory = $true)][string]$TargetDirectory
    )

    if ($TargetDirectory -notmatch '^/kairos-stage/migrations$') {
        throw "Refusing a migration target outside this generated clone drill"
    }
    & docker exec --user=root $CloneContainer mkdir -p -- $TargetDirectory
    if ($LASTEXITCODE -ne 0) { throw "Could not create clone-only migration directory" }
    foreach ($migration in $TargetMigrations | Select-Object -Skip $LegacyMigrations.Count) {
        $source = "${RunnerContainer}:$SourceDirectory/$migration"
        # Docker Desktop does not support container-to-container docker cp.
        # Use a uniquely generated host transfer file, verify its bytes, and
        # copy it only into this clone's disposable staging volume.
        $hostTransfer = [System.IO.Path]::GetTempFileName()
        try {
            Remove-Item -LiteralPath $hostTransfer -Force -ErrorAction Stop
            & docker cp $source $hostTransfer
            if ($LASTEXITCODE -ne 0) { throw "Could not export pinned migration $migration from the isolated runner" }
            $hostHash = Get-FileSha256 -Path $hostTransfer
            if ($hostHash -ne $MigrationSha256[$migration]) {
                throw "Exported pinned migration byte hash differs for $migration"
            }
            # The target is a generated disposable volume, not tmpfs: Docker
            # Desktop reliably preserves copied bytes there.
            & docker cp $hostTransfer "${CloneContainer}:$TargetDirectory/$migration"
            if ($LASTEXITCODE -ne 0) { throw "Could not copy pinned migration $migration into clone-only container" }
            $actual = (& docker exec --user=root $CloneContainer sha256sum -- "$TargetDirectory/$migration").Trim()
            if ($LASTEXITCODE -ne 0 -or $actual -notmatch "^$($MigrationSha256[$migration])\s") {
                throw "Copied pinned migration byte hash differs for $migration"
            }
        }
        finally {
            Remove-Item -LiteralPath $hostTransfer -Force -ErrorAction SilentlyContinue
        }
    }
}

function New-PinnedMigrationSql {
    param(
        [Parameter(Mandatory = $true)][string[]]$ExpectedBefore,
        [Parameter(Mandatory = $true)][string]$TargetDirectory
    )

    $expectedBeforeSql = ConvertTo-SqlTextArray -Values $ExpectedBefore
    $expectedAfterSql = ConvertTo-SqlTextArray -Values $TargetMigrations
    $lines = [System.Collections.Generic.List[string]]::new()
    [void]$lines.Add("SET LOCAL lock_timeout = '5s';")
    [void]$lines.Add("SET LOCAL statement_timeout = '120s';")
    [void]$lines.Add("SELECT pg_advisory_xact_lock($SchemaAdvisoryLock);")
    [void]$lines.Add("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now());")
    [void]$lines.Add(@"
DO `$upgrade`$
DECLARE actual text[];
BEGIN
    SELECT COALESCE(array_agg(version ORDER BY version), ARRAY[]::text[]) INTO actual FROM schema_migrations;
    IF actual IS DISTINCT FROM $expectedBeforeSql THEN
        RAISE EXCEPTION 'clone migration profile is not the required exact preflight profile';
    END IF;
END
`$upgrade`$;
"@)
    foreach ($migration in $TargetMigrations | Select-Object -Skip $LegacyMigrations.Count) {
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
    IF actual IS DISTINCT FROM $expectedAfterSql THEN
        RAISE EXCEPTION 'clone migration profile is not exact 001--018 after pinned runner';
    END IF;
END
`$upgrade`$;
"@)
    return ($lines -join "`n") + "`n"
}

function Invoke-PinnedMigrationRunner {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [Parameter(Mandatory = $true)][string]$TargetDirectory,
        [Parameter(Mandatory = $true)][string[]]$ExpectedBefore,
        [Parameter(Mandatory = $true)][string]$Suffix,
        [Parameter(Mandatory = $true)][int]$Pass
    )

    Assert-CloneDatabaseName -DatabaseName $DatabaseName
    $localRunnerFile = [System.IO.Path]::GetTempFileName()
    $containerRunnerFile = "$TargetDirectory/$([System.IO.Path]::GetFileName($localRunnerFile))"
    try {
        Write-Utf8NoBom -Path $localRunnerFile -Content (New-PinnedMigrationSql `
            -ExpectedBefore $ExpectedBefore -TargetDirectory $TargetDirectory)
        & docker cp $localRunnerFile "${Container}:$TargetDirectory/"
        if ($LASTEXITCODE -ne 0) { throw "Could not copy pinned migration runner into clone-only container" }
        & docker exec --user=root $Container test -f $containerRunnerFile
        if ($LASTEXITCODE -ne 0) { throw "Copied pinned migration runner is missing from the clone staging volume" }
        & docker exec $Container psql --username=$CloneDatabaseUser --dbname=$DatabaseName --set=ON_ERROR_STOP=1 `
            --single-transaction --file=$containerRunnerFile
        if ($LASTEXITCODE -ne 0) { throw "Pinned migration runner failed on clone-only database" }
    }
    finally {
        Remove-Item -LiteralPath $localRunnerFile -Force -ErrorAction SilentlyContinue
        & docker exec --user=root $Container rm -f -- $containerRunnerFile 2>$null | Out-Null
    }
}

function Remove-CloneOnlyResources {
    param(
        [string]$RunnerContainer,
        [string]$CloneContainer,
        [string]$CloneVolume,
        [string]$StageVolume,
        [string]$UpgradeDrillDatabase,
        [string]$RestoreDrillDatabase,
        [string]$Suffix
    )

    $cleanupErrors = [System.Collections.Generic.List[string]]::new()
    if ($RunnerContainer) {
        $runnerLabelsJson = (& docker inspect --format '{{json .Config.Labels}}' $RunnerContainer 2>$null).Trim()
        if ($LASTEXITCODE -eq 0 -and $runnerLabelsJson) {
            $runnerLabels = $runnerLabelsJson | ConvertFrom-Json
            if ($runnerLabels.'com.kairos.scope' -eq $CloneScope -and $runnerLabels.'com.kairos.drill' -eq $Suffix) {
                $runnerRemoval = Invoke-DockerProbe -Arguments @("rm", "-f", $RunnerContainer)
                if ($runnerRemoval.exit_code -ne 0) { [void]$cleanupErrors.Add("could not remove isolated migration-runner probe") }
            }
            else { [void]$cleanupErrors.Add("refused to remove a migration-runner probe with mismatched labels") }
        }
    }
    if ($CloneContainer) {
        $cloneExists = (& docker inspect --format '{{.Id}}' $CloneContainer 2>$null).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $cloneExists) {
            $CloneContainer = $null
        }
    }
    if ($CloneContainer) {
        try {
            Assert-CloneContainerIdentity -Container $CloneContainer -DataVolume $CloneVolume -StageVolume $StageVolume -Suffix $Suffix
            $cloneRunning = (& docker inspect --format '{{.State.Running}}' $CloneContainer).Trim()
            if ($LASTEXITCODE -ne 0) { throw "Could not inspect isolated clone container state" }
            if ($cloneRunning -eq "true") {
                foreach ($drillDatabase in @($UpgradeDrillDatabase, $RestoreDrillDatabase)) {
                    Assert-CloneDatabaseName -DatabaseName $drillDatabase
                    $drop = Invoke-DockerProbe -Arguments @("exec", $CloneContainer, "dropdb", "--if-exists", "--force", "--username=$CloneDatabaseUser", $drillDatabase)
                    if ($drop.exit_code -ne 0) { [void]$cleanupErrors.Add("could not drop generated clone drill database") }
                }
            }
            $cloneRemoval = Invoke-DockerProbe -Arguments @("rm", "-f", $CloneContainer)
            if ($cloneRemoval.exit_code -ne 0) {
                [void]$cleanupErrors.Add("could not remove isolated clone container")
            }
            else {
                $remainingClone = Invoke-DockerProbe -Arguments @("inspect", "--format", "{{.Id}}", $CloneContainer)
                if ($remainingClone.exit_code -eq 0) { [void]$cleanupErrors.Add("isolated clone container remained after removal") }
            }
        }
        catch { [void]$cleanupErrors.Add($_.Exception.Message) }
    }
    foreach ($volume in @($StageVolume, $CloneVolume)) {
        if (-not $volume) { continue }
        $volumeExists = (& docker volume inspect --format '{{.Name}}' $volume 2>$null).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $volumeExists) { continue }
        try {
            Assert-CloneVolumeIdentity -Volume $volume -Suffix $Suffix
            $volumeRemoval = Invoke-DockerProbe -Arguments @("volume", "rm", $volume)
            if ($volumeRemoval.exit_code -ne 0) { [void]$cleanupErrors.Add("could not remove isolated clone disposable volume") }
        }
        catch { [void]$cleanupErrors.Add($_.Exception.Message) }
    }
    if ($cleanupErrors.Count -gt 0) {
        throw ("Clone-only cleanup failed: " + ($cleanupErrors -join "; "))
    }
}

$manifestFile = (Resolve-Path -LiteralPath $ManifestPath).Path
$baselineReceiptFile = (Resolve-Path -LiteralPath $BaselineReceiptPath).Path
$manifest = Get-Content -Raw -LiteralPath $manifestFile | ConvertFrom-Json
$baselineReceipt = Get-Content -Raw -LiteralPath $baselineReceiptFile | ConvertFrom-Json
$manifestHash = Get-FileSha256 -Path $manifestFile
if ($manifest.schema_version -ne 1 -or [string]$manifest.sha256 -notmatch '^[0-9a-f]{64}$' -or
    [string]$manifest.file -notmatch '^[A-Za-z0-9_.-]+\.dump$' -or [string]$manifest.bytes -notmatch '^\d+$') {
    throw "Unsupported or malformed backup manifest"
}
if ($manifest.compose_project -cne $ExpectedSourceComposeProject -or $manifest.database -cne $ExpectedSourceDatabase) {
    throw "Backup manifest must identify the isolated $ExpectedSourceComposeProject/$ExpectedSourceDatabase runtime"
}
if ($null -eq $manifest.checkpoints) { throw "Backup manifest lacks durable data checkpoints" }
if ($baselineReceipt.schema_version -ne 1 -or $baselineReceipt.result -ne "PASS" -or
    $baselineReceipt.recovery_profile -ne "offline-closed-bar-v1" -or
    $baselineReceipt.backup_sha256 -ne $manifest.sha256 -or
    $baselineReceipt.backup_manifest_sha256 -ne $manifestHash -or
    $baselineReceipt.database -ne $manifest.database -or
    $baselineReceipt.compose_project -ne $manifest.compose_project) {
    throw "Baseline receipt does not prove this exact verified source backup"
}
Assert-ExactStringArray -Expected $LegacyMigrations -Actual @($baselineReceipt.migrations) `
    -Description "Baseline receipt migration profile"
$backupCreatedAt = Get-FreshVerifiedBaseline -Manifest $manifest -Receipt $baselineReceipt -ManifestSha256 $manifestHash

$dump = (Resolve-Path -LiteralPath (Join-Path (Split-Path -Parent $manifestFile) $manifest.file)).Path
$dumpItem = Get-Item -LiteralPath $dump
$dumpHash = Get-FileSha256 -Path $dump
if ($dumpHash -ne $manifest.sha256 -or $dumpItem.Length -ne [long]$manifest.bytes) {
    throw "Backup dump does not match its manifest"
}
$checkpointDigest = Get-CheckpointDigest -Checkpoints $manifest.checkpoints
$baselineReceiptHash = Get-FileSha256 -Path $baselineReceiptFile

$suffix = ([guid]::NewGuid().ToString("N")).Substring(0, 12)
$cloneContainer = "kairos-schema-upgrade-preflight-$suffix"
$cloneVolume = "kairos-schema-upgrade-preflight-data-$suffix"
$cloneStageVolume = "kairos-schema-upgrade-preflight-stage-$suffix"
$runnerProbe = "kairos-schema-upgrade-runner-probe-$suffix"
$upgradeDrillDatabase = "kairos_schema_upgrade_drill_$suffix"
$restoreDrillDatabase = "kairos_schema_upgrade_restore_drill_$suffix"
$containerStageDirectory = "/kairos-stage"
$containerInputDump = "$containerStageDirectory/$([System.IO.Path]::GetFileName($dump))"
$containerUpgradeDump = "$containerStageDirectory/kairos-schema-upgrade-$suffix.upgraded.dump"
$containerMigrationDirectory = "$containerStageDirectory/migrations"
Assert-CloneDatabaseName -DatabaseName $upgradeDrillDatabase
Assert-CloneDatabaseName -DatabaseName $restoreDrillDatabase

$ephemeralPasswordBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($ephemeralPasswordBytes)
$ephemeralPassword = [Convert]::ToBase64String($ephemeralPasswordBytes)
$runnerProbeId = $null
$receipt = $null
$operationError = $null
try {
    # The source database is never queried or mounted.  The only persistent
    # input is the verified custom dump copied into this isolated container.
    & docker volume create --label "com.kairos.scope=$CloneScope" --label "com.kairos.drill=$suffix" $cloneVolume | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not create isolated clone volume" }
    Assert-CloneVolumeIdentity -Volume $cloneVolume -Suffix $suffix
    & docker volume create --label "com.kairos.scope=$CloneScope" --label "com.kairos.drill=$suffix" $cloneStageVolume | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not create isolated clone staging volume" }
    Assert-CloneVolumeIdentity -Volume $cloneStageVolume -Suffix $suffix
    $cloneId = (& docker create --name $cloneContainer --network none --memory 2g --cpus 2 --pids-limit 256 `
        --label "com.kairos.scope=$CloneScope" --label "com.kairos.drill=$suffix" `
        --mount "type=volume,src=$cloneVolume,dst=/var/lib/postgresql/data" `
        --mount "type=volume,src=$cloneStageVolume,dst=$containerStageDirectory" `
        --tmpfs "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=256m" `
        --tmpfs "/var/run/postgresql:rw,nosuid,nodev,noexec,mode=1777,size=16m" `
        --env "POSTGRES_USER=$CloneDatabaseUser" --env "POSTGRES_DB=postgres" --env "POSTGRES_PASSWORD=$ephemeralPassword" `
        $ExpectedTimescaleImage).Trim()
    if ($LASTEXITCODE -ne 0 -or $cloneId -notmatch '^[0-9a-f]{64}$') { throw "Could not create isolated clone container" }
    Assert-CloneContainerIdentity -Container $cloneContainer -DataVolume $cloneVolume -StageVolume $cloneStageVolume -Suffix $suffix
    & docker start $cloneContainer | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not start isolated clone container" }
    Wait-CloneDatabaseReady -Container $cloneContainer

    # Track the generated name before the probe begins so a partial probe is
    # still removed if image validation or its no-network process fails.
    $runnerProbeId = $runnerProbe
    $pinnedSource = Get-PinnedMigrationSource -Image $MigrationRunnerImage -ProbeContainer $runnerProbe -Suffix $suffix
    $runnerProbeId = [string]$pinnedSource.container_id
    & docker cp $dump "${cloneContainer}:$containerStageDirectory/"
    if ($LASTEXITCODE -ne 0) { throw "Could not copy verified source backup into isolated clone" }
    & docker exec --user=root $cloneContainer test -f $containerInputDump
    if ($LASTEXITCODE -ne 0) { throw "Verified source backup is missing from the clone staging volume" }
    Restore-VerifiedDump -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -DumpPathInContainer $containerInputDump
    Assert-CloneMigrationProfile -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Expected $LegacyMigrations `
        -Description "Restored source clone"
    $legacyFingerprint = Assert-VettedLegacySchemaShape -Container $cloneContainer -DatabaseName $upgradeDrillDatabase
    $clonePreconditions = Assert-CloneDdlPreconditions -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Suffix $suffix
    Assert-ManifestCheckpoints -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Checkpoints $manifest.checkpoints
    $absence = Assert-PostBaselineObjects -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Present $false

    Copy-PinnedTargetMigrations -RunnerContainer $runnerProbeId -SourceDirectory $pinnedSource.migration_directory `
        -CloneContainer $cloneContainer -TargetDirectory $containerMigrationDirectory
    Invoke-PinnedMigrationRunner -Container $cloneContainer -DatabaseName $upgradeDrillDatabase `
        -TargetDirectory $containerMigrationDirectory -ExpectedBefore $LegacyMigrations -Suffix $suffix -Pass 1
    Assert-CloneMigrationProfile -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Expected $TargetMigrations `
        -Description "First pinned clone migration pass"
    $postUpgradeObjects = Assert-PostBaselineObjects -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Present $true
    $vettedShape = Assert-VettedPostBaselineSchemaShape -Container $cloneContainer -DatabaseName $upgradeDrillDatabase
    Assert-ManifestCheckpoints -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Checkpoints $manifest.checkpoints
    $firstFingerprint = Get-PostBaselineSchemaFingerprint -Container $cloneContainer -DatabaseName $upgradeDrillDatabase

    Invoke-PinnedMigrationRunner -Container $cloneContainer -DatabaseName $upgradeDrillDatabase `
        -TargetDirectory $containerMigrationDirectory -ExpectedBefore $TargetMigrations -Suffix $suffix -Pass 2
    Assert-CloneMigrationProfile -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Expected $TargetMigrations `
        -Description "Second pinned clone migration pass"
    Assert-PostBaselineObjects -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Present $true | Out-Null
    Assert-ManifestCheckpoints -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Checkpoints $manifest.checkpoints
    $secondFingerprint = Get-PostBaselineSchemaFingerprint -Container $cloneContainer -DatabaseName $upgradeDrillDatabase
    if ($firstFingerprint -ne $secondFingerprint) {
        throw "Second pinned clone migration pass changed the post-baseline schema fingerprint"
    }

    & docker exec $cloneContainer pg_dump --format=custom --no-owner --no-privileges --username=$CloneDatabaseUser `
        --dbname=$upgradeDrillDatabase --file=$containerUpgradeDump
    if ($LASTEXITCODE -ne 0) { throw "Could not create upgraded clone restore-drill backup" }
    Restore-VerifiedDump -Container $cloneContainer -DatabaseName $restoreDrillDatabase -DumpPathInContainer $containerUpgradeDump
    Assert-CloneMigrationProfile -Container $cloneContainer -DatabaseName $restoreDrillDatabase -Expected $TargetMigrations `
        -Description "Restored upgraded clone drill"
    Assert-PostBaselineObjects -Container $cloneContainer -DatabaseName $restoreDrillDatabase -Present $true | Out-Null
    Assert-VettedPostBaselineSchemaShape -Container $cloneContainer -DatabaseName $restoreDrillDatabase | Out-Null
    Assert-ManifestCheckpoints -Container $cloneContainer -DatabaseName $restoreDrillDatabase -Checkpoints $manifest.checkpoints
    $restoreFingerprint = Get-PostBaselineSchemaFingerprint -Container $cloneContainer -DatabaseName $restoreDrillDatabase
    if ($restoreFingerprint -ne $firstFingerprint) {
        throw "Restored upgraded clone schema fingerprint differs from the upgraded source clone"
    }

    $inputAfterHash = Get-FileSha256 -Path $dump
    $inputAfterBytes = (Get-Item -LiteralPath $dump).Length
    if ($inputAfterHash -ne $manifest.sha256 -or $inputAfterBytes -ne [long]$manifest.bytes) {
        throw "Verified source backup changed during clone-only preflight"
    }
    $receipt = [ordered]@{
        schema_version = 1
        classification = "CLONE_ONLY_SCHEMA_UPGRADE_PREFLIGHT"
        result = "PASS_CLONE_ONLY"
        created_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        readiness = [ordered]@{
            paper_qualified = $false
            alpha_ready = $false
            live_ready = $false
            strategy_policy = "REJECT_ALL"
        }
        source_backup = [ordered]@{
            sha256 = $manifest.sha256
            bytes = [long]$manifest.bytes
            manifest_sha256 = $manifestHash
            baseline_receipt_sha256 = $baselineReceiptHash
            legacy_checkpoint_sha256 = $checkpointDigest
            legacy_schema_fingerprint_sha256 = $legacyFingerprint
            source_database = $manifest.database
            source_compose_project = $manifest.compose_project
            created_at_utc = $backupCreatedAt
            maximum_age_hours = [long]$MaximumBackupAge.TotalHours
        }
        migration_runner = [ordered]@{
            persistence_repository = $ExpectedPersistenceRepository
            persistence_revision = $ExpectedPersistenceRevision
            image_digest = $MigrationRunnerImage
            migration_sha256 = $MigrationSha256
            exact_target_profile = $TargetMigrations
        }
        clone = [ordered]@{
            isolated = $true
            original_runtime_contacted = $false
            unique_drill_databases = 2
            source_profile = $LegacyMigrations
            pre_upgrade_post_baseline_objects = $absence
            post_upgrade_post_baseline_objects = $postUpgradeObjects
            preconditions = $clonePreconditions
            vetted_schema_shape = $vettedShape
        }
        idempotency = [ordered]@{
            first_pass_migration_count = [long]$TargetMigrations.Count
            second_pass_migration_count = [long]$TargetMigrations.Count
            first_pass_schema_fingerprint_sha256 = $firstFingerprint
            second_pass_schema_fingerprint_sha256 = $secondFingerprint
            unchanged = $true
        }
        restore_drill = [ordered]@{
            target_profile = $TargetMigrations
            checkpoint_sha256 = $checkpointDigest
            schema_fingerprint_sha256 = $restoreFingerprint
            passed = $true
        }
        original_migration = [ordered]@{
            authorized = $false
            target_ddl_permissions_verified = $false
            required_next_gate = "SEPARATE_READ_ONLY_TARGET_ROLE_PREFLIGHT"
            simulator_journal_on_runtime_clone = "TESTED_ONLY_ARCHITECTURE_DECISION_UNRESOLVED"
        }
        assertions = @(
            "no original database migration occurred",
            "no runtime service, volume, network, or secret was mounted",
            "migration runner was limited to exact 001--018 bytes",
            "clone DDL capability does not prove original target-role permission",
            "simulator journal was tested only in a clone and does not authorize a runtime schema change",
            "SIMULATED schema does not grant PAPER, alpha, or LIVE readiness"
        )
    }
}
catch {
    $operationError = $_
}
finally {
    try {
        Remove-CloneOnlyResources -RunnerContainer $runnerProbeId -CloneContainer $cloneContainer -CloneVolume $cloneVolume `
        -StageVolume $cloneStageVolume -UpgradeDrillDatabase $upgradeDrillDatabase -RestoreDrillDatabase $restoreDrillDatabase -Suffix $suffix
    }
    catch {
        if ($null -eq $operationError) { $operationError = $_ }
        else { Write-Error "Clone-only cleanup failure after preflight failure: $($_.Exception.Message)" }
    }
}

if ($null -ne $operationError) { throw $operationError }
if ($null -eq $receipt) { throw "Clone-only schema-upgrade preflight did not create a receipt" }
if ([string]::IsNullOrWhiteSpace($ReceiptPath)) {
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $ReceiptPath = Join-Path (Split-Path -Parent $manifestFile) "schema-upgrade-preflight-$stamp.json"
}
$receiptFullPath = [System.IO.Path]::GetFullPath($ReceiptPath)
$manifestDirectory = [System.IO.Path]::GetFullPath((Split-Path -Parent $manifestFile))
if (-not $receiptFullPath.StartsWith($manifestDirectory + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Schema-upgrade preflight receipt must remain beside the immutable backup manifest"
}
if (Test-Path -LiteralPath $receiptFullPath) { throw "Schema-upgrade preflight receipt already exists" }
Write-Utf8NoBom -Path $receiptFullPath -Content ($receipt | ConvertTo-Json -Depth 10)
Write-Output "Clone-only schema-upgrade preflight passed: $receiptFullPath"
