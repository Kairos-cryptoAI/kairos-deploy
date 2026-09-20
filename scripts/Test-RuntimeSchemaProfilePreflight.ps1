<#
.SYNOPSIS
    Runs a synthetic Docker integration drill for the runtime-only schema
    profile preflight.

.DESCRIPTION
    The harness creates an empty 001--012 custom dump in its own labelled,
    no-network TimescaleDB container.  It builds a migration-only runner from
    the exact local persistence Git object, exposes that runner through a
    temporary loopback-only registry so Docker records an immutable digest,
    and invokes Invoke-RuntimeSchemaProfilePreflight.ps1.

    It never names, mounts, queries, or starts the real PAPER runtime.  The
    generated manifest calls the fixture kairos-paper-gate/kairos only to
    exercise the preflight's immutable input contract; no real backup or
    secret is read.  All objects are suffix-labelled and removed before return.
#>

[CmdletBinding()]
param(
    [string]$PersistenceSource = "D:\Kairos\kairos-persistence",
    [string]$PreflightScript,
    [string]$PythonBaseImage = "python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3",
    [string]$RegistryImage = "registry:2"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($PreflightScript)) {
    $PreflightScript = Join-Path $PSScriptRoot "Invoke-RuntimeSchemaProfilePreflight.ps1"
}
$ExpectedPersistenceRepository = "https://github.com/Kairos-cryptoAI/kairos-persistence"
$ExpectedPersistenceRevision = "1ca8bf38d265ece7a95f749a268075549f80c043"
$ExpectedTimescaleImage = "timescale/timescaledb:2.29.1-pg16@sha256:252a443e2936039b83dd8da1373d01e59e932d1054fa6adf1bc061f1d56ae60a"
$HarnessScope = "synthetic-runtime-schema-profile-harness"
$BootstrapUser = "kairos_runtime_fixture"
$RunnerUser = "10001:10001"
$LegacyMigrations = @(
    "001_audit_and_idempotency.sql", "002_durable_runtime.sql", "003_execution_effect_journal.sql",
    "004_execution_recovery_delay.sql", "005_source_state_and_usage.sql", "006_paper_trade_lifecycle.sql",
    "007_execution_runtime_health.sql", "008_public_execution_events.sql", "009_paper_canary_arms.sql",
    "010_runtime_compensation_reserve.sql", "011_execution_mutation_budget.sql", "012_outbox_producer_order.sql"
)
$CheckpointTables = @(
    "event_audit", "message_inbox", "message_outbox", "execution_orders", "account_snapshots",
    "position_snapshots", "source_cursors", "source_usage_reservations", "execution_effects",
    "execution_effect_events", "execution_trades", "execution_trade_events", "execution_recovery_state",
    "public_execution_events", "account_equity_state", "paper_canary_arms", "execution_runtime_health",
    "execution_mutation_budget_scopes", "execution_mutation_reservations"
)

function Invoke-DockerQuiet {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& docker @Arguments 2>$null)
        $exitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previous }
    return [pscustomobject]@{ output = $output; exit_code = [int]$exitCode }
}

function Assert-DockerSuccess {
    param([Parameter(Mandatory = $true)]$Result, [Parameter(Mandatory = $true)][string]$Description)
    if ($Result.exit_code -ne 0) { throw "$Description (Docker exit code $($Result.exit_code))" }
}

function Assert-LocalImage {
    param([Parameter(Mandatory = $true)][string]$Image)
    $inspection = Invoke-DockerQuiet -Arguments @("image", "inspect", $Image)
    if ($inspection.exit_code -ne 0) { throw "Required local image is unavailable: $Image" }
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace("-", "").ToLowerInvariant() }
    finally { $stream.Dispose(); $algorithm.Dispose() }
}

function Write-Utf8NoBom {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

function New-SyntheticPassword {
    $bytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return [Convert]::ToBase64String($bytes)
}

function Get-RandomLoopbackPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally { $listener.Stop() }
}

function Wait-Postgres {
    param([Parameter(Mandatory = $true)][string]$Container)
    for ($attempt = 1; $attempt -le 60; $attempt++) {
        $probe = Invoke-DockerQuiet -Arguments @("exec", $Container, "psql", "--username=$BootstrapUser", "--dbname=postgres", "--tuples-only", "--no-align", "--command=SELECT 1;")
        if ($probe.exit_code -eq 0 -and (@($probe.output | ForEach-Object { $_.Trim() }) -contains "1")) { return }
        Start-Sleep -Seconds 2
    }
    throw "Synthetic TimescaleDB did not become ready"
}

function Wait-Registry {
    param([Parameter(Mandatory = $true)][int]$Port)
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        try {
            $client = [Net.Sockets.TcpClient]::new()
            $task = $client.ConnectAsync([Net.IPAddress]::Loopback, $Port)
            if ($task.Wait(500) -and $client.Connected) { $client.Dispose(); return }
            $client.Dispose()
        }
        catch { }
        Start-Sleep -Milliseconds 250
    }
    throw "Temporary loopback registry did not become ready"
}

function Get-Labels {
    param([Parameter(Mandatory = $true)][ValidateSet("container", "volume", "image")][string]$Kind, [Parameter(Mandatory = $true)][string]$Name)
    $format = if ($Kind -eq "volume") { "{{json .Labels}}" } else { "{{json .Config.Labels}}" }
    $result = Invoke-DockerQuiet -Arguments @($Kind, "inspect", "--format", $format, $Name)
    if ($result.exit_code -ne 0) { return $null }
    $raw = (($result.output | Select-Object -Last 1) -as [string]).Trim()
    if (-not $raw -or $raw -eq "null") { throw "Unlabelled synthetic $Kind cannot be removed: $Name" }
    return $raw | ConvertFrom-Json
}

function Assert-ScopedLabels {
    param([Parameter(Mandatory = $true)]$Labels, [Parameter(Mandatory = $true)][string]$Suffix)
    if ($Labels.'com.kairos.scope' -ne $HarnessScope -or $Labels.'com.kairos.drill' -ne $Suffix) {
        throw "Refusing to remove a synthetic object with mismatched labels"
    }
}

function Remove-ScopedContainer {
    param([string]$Name, [Parameter(Mandatory = $true)][string]$Suffix)
    if (-not $Name) { return }
    $labels = Get-Labels -Kind "container" -Name $Name
    if ($null -eq $labels) { return }
    Assert-ScopedLabels -Labels $labels -Suffix $Suffix
    Assert-DockerSuccess -Result (Invoke-DockerQuiet -Arguments @("rm", "-f", $Name)) -Description "Could not remove synthetic container"
}

function Remove-ScopedVolume {
    param([string]$Name, [Parameter(Mandatory = $true)][string]$Suffix)
    if (-not $Name) { return }
    $labels = Get-Labels -Kind "volume" -Name $Name
    if ($null -eq $labels) { return }
    Assert-ScopedLabels -Labels $labels -Suffix $Suffix
    Assert-DockerSuccess -Result (Invoke-DockerQuiet -Arguments @("volume", "rm", $Name)) -Description "Could not remove synthetic volume"
}

function Remove-ScopedImageTag {
    param([string]$Name, [Parameter(Mandatory = $true)][string]$Suffix)
    if (-not $Name) { return }
    $labels = Get-Labels -Kind "image" -Name $Name
    if ($null -eq $labels) { return }
    Assert-ScopedLabels -Labels $labels -Suffix $Suffix
    Assert-DockerSuccess -Result (Invoke-DockerQuiet -Arguments @("image", "rm", "-f", $Name)) -Description "Could not remove synthetic runner image tag"
}

if (-not (Test-Path -LiteralPath $PreflightScript -PathType Leaf)) { throw "Runtime profile preflight script is missing" }
if (-not (Test-Path -LiteralPath $PersistenceSource -PathType Container)) { throw "Persistence source is missing" }
foreach ($image in @($PythonBaseImage, $RegistryImage, $ExpectedTimescaleImage)) { Assert-LocalImage -Image $image }
$persistenceStatus = @(& git -C $PersistenceSource status --porcelain=v1)
if ($LASTEXITCODE -ne 0 -or $persistenceStatus.Count -ne 0) { throw "Persistence source must be a clean checkout" }
$persistenceHead = ((& git -C $PersistenceSource rev-parse $ExpectedPersistenceRevision) | Select-Object -Last 1).Trim()
if ($LASTEXITCODE -ne 0 -or $persistenceHead -ne $ExpectedPersistenceRevision) { throw "Pinned persistence revision is unavailable" }

$suffix = ([Guid]::NewGuid().ToString("N")).Substring(0, 12)
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) "kairos-runtime-profile-harness-$suffix"
$bootstrapContainer = "kairos-runtime-profile-bootstrap-$suffix"
$bootstrapVolume = "kairos-runtime-profile-bootstrap-data-$suffix"
$registryContainer = "kairos-runtime-profile-registry-$suffix"
$runnerProbe = "kairos-runtime-profile-harness-runner-$suffix"
$buildTag = "kairos-runtime-profile-runner-${suffix}:local"
$registryPort = Get-RandomLoopbackPort
$registryRepository = "127.0.0.1:$registryPort/kairos-runtime-profile-runner-$suffix"
$registryTag = "${registryRepository}:immutable"
$bootstrapDatabase = "kairos_runtime_profile_fixture_$suffix"
$runnerDigest = $null
$operationError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()

try {
    New-Item -ItemType Directory -Path $tempRoot -ErrorAction Stop | Out-Null
    $context = Join-Path $tempRoot "context"
    $snapshot = Join-Path $context "persistence"
    $importDirectory = Join-Path $tempRoot "import"
    $exportDirectory = Join-Path $tempRoot "export"
    New-Item -ItemType Directory -Path $context, $importDirectory, $exportDirectory -ErrorAction Stop | Out-Null
    $archive = Join-Path $tempRoot "persistence.zip"
    & git -C $PersistenceSource -c core.autocrlf=false -c core.eol=lf archive --format=zip --output=$archive $ExpectedPersistenceRevision
    if ($LASTEXITCODE -ne 0) { throw "Could not archive the pinned persistence source" }
    Expand-Archive -LiteralPath $archive -DestinationPath $snapshot -Force
    if (-not (Test-Path -LiteralPath (Join-Path $snapshot "kairos_persistence\migrations\018_offline_outbox_reconciliation.sql") -PathType Leaf)) { throw "Pinned source archive is incomplete" }
    Write-Utf8NoBom -Path (Join-Path $context "runner-init.py") -Content '"""Minimal migration resource package for an isolated test."""'
    Write-Utf8NoBom -Path (Join-Path $context "Dockerfile") -Content @"
FROM $PythonBaseImage
RUN groupadd --gid 10001 kairos_runner && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin kairos_runner
COPY persistence/kairos_persistence/migrations /opt/kairos_persistence/migrations
COPY runner-init.py /opt/kairos_persistence/__init__.py
RUN chown -R 10001:10001 /opt/kairos_persistence
ENV PYTHONPATH=/opt PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
"@
    & docker build --pull=false --network=none --label "com.kairos.scope=$HarnessScope" --label "com.kairos.drill=$suffix" `
        --label "org.opencontainers.image.source=$ExpectedPersistenceRepository" --label "org.opencontainers.image.revision=$ExpectedPersistenceRevision" `
        --file (Join-Path $context "Dockerfile") --tag $buildTag $context | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Could not build synthetic immutable migration runner" }

    & docker run -d --name $registryContainer --network bridge --read-only --tmpfs "/var/lib/registry:rw,nosuid,nodev,noexec,size=128m" `
        --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=16m" --publish "127.0.0.1:${registryPort}:5000" `
        --label "com.kairos.scope=$HarnessScope" --label "com.kairos.drill=$suffix" $RegistryImage | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not start temporary loopback registry" }
    Wait-Registry -Port $registryPort
    & docker tag $buildTag $registryTag
    if ($LASTEXITCODE -ne 0) { throw "Could not tag synthetic migration runner" }
    $pushOutput = @(& docker push $registryTag 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Could not push synthetic migration runner to loopback registry" }
    $match = [regex]::Match(($pushOutput -join "`n"), 'digest:\s*(sha256:[0-9a-f]{64})')
    if (-not $match.Success) { throw "Loopback registry did not return a runner digest" }
    $runnerDigest = "$registryRepository@$($match.Groups[1].Value)"
    & docker pull $runnerDigest | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not load synthetic immutable runner digest" }

    $bootstrapPassword = New-SyntheticPassword
    Assert-DockerSuccess -Result (Invoke-DockerQuiet -Arguments @("volume", "create", "--label", "com.kairos.scope=$HarnessScope", "--label", "com.kairos.drill=$suffix", $bootstrapVolume)) -Description "Could not create synthetic bootstrap volume"
    & docker create --name $bootstrapContainer --network none --memory 2g --cpus 2 --pids-limit 256 `
        --label "com.kairos.scope=$HarnessScope" --label "com.kairos.drill=$suffix" `
        --mount "type=volume,src=$bootstrapVolume,dst=/var/lib/postgresql/data" `
        --mount "type=bind,src=$importDirectory,dst=/kairos-import,readonly" --mount "type=bind,src=$exportDirectory,dst=/kairos-export" `
        --tmpfs "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=256m" --tmpfs "/var/run/postgresql:rw,nosuid,nodev,noexec,mode=1777,size=16m" `
        --env "POSTGRES_USER=$BootstrapUser" --env "POSTGRES_DB=postgres" --env "POSTGRES_PASSWORD=$bootstrapPassword" $ExpectedTimescaleImage | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not create synthetic legacy database" }
    Assert-DockerSuccess -Result (Invoke-DockerQuiet -Arguments @("start", $bootstrapContainer)) -Description "Could not start synthetic legacy database"
    Wait-Postgres -Container $bootstrapContainer
    Assert-DockerSuccess -Result (Invoke-DockerQuiet -Arguments @("create", "--name", $runnerProbe, "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--user", $RunnerUser, "--label", "com.kairos.scope=$HarnessScope", "--label", "com.kairos.drill=$suffix", "--entrypoint", "sh", $runnerDigest, "-c", "printf /opt/kairos_persistence/migrations")) -Description "Could not create synthetic runner probe"
    $migrationDirectory = ((Invoke-DockerQuiet -Arguments @("start", "-a", $runnerProbe)).output | Select-Object -Last 1).Trim()
    if ($migrationDirectory -ne "/opt/kairos_persistence/migrations") { throw "Synthetic runner probe returned an unsafe migration directory" }
    foreach ($migration in $LegacyMigrations) {
        $target = Join-Path $importDirectory $migration
        Assert-DockerSuccess -Result (Invoke-DockerQuiet -Arguments @("cp", "${runnerProbe}:$migrationDirectory/$migration", $target)) -Description "Could not export synthetic legacy migration"
    }
    $legacyRunner = [Collections.Generic.List[string]]::new()
    [void]$legacyRunner.Add("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now());")
    foreach ($migration in $LegacyMigrations) { [void]$legacyRunner.Add("\i /kairos-import/$migration"); [void]$legacyRunner.Add("INSERT INTO schema_migrations(version) VALUES ('$migration');") }
    $legacyRunnerPath = Join-Path $importDirectory "bootstrap-$suffix.sql"
    Write-Utf8NoBom -Path $legacyRunnerPath -Content (($legacyRunner -join "`n") + "`n")
    Assert-DockerSuccess -Result (Invoke-DockerQuiet -Arguments @("exec", $bootstrapContainer, "createdb", "--username=$BootstrapUser", $bootstrapDatabase)) -Description "Could not create synthetic legacy fixture database"
    Assert-DockerSuccess -Result (Invoke-DockerQuiet -Arguments @("exec", $bootstrapContainer, "psql", "--username=$BootstrapUser", "--dbname=$bootstrapDatabase", "--set=ON_ERROR_STOP=1", "--single-transaction", "--file=/kairos-import/$([IO.Path]::GetFileName($legacyRunnerPath))")) -Description "Could not apply synthetic exact 001--012 profile"
    $fixtureDumpName = "synthetic-kairos-paper-gate-$suffix.dump"
    Assert-DockerSuccess -Result (Invoke-DockerQuiet -Arguments @("exec", $bootstrapContainer, "pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--username=$BootstrapUser", "--dbname=$bootstrapDatabase", "--file=/kairos-export/$fixtureDumpName")) -Description "Could not create synthetic legacy dump"
    $dumpPath = Join-Path $exportDirectory $fixtureDumpName
    if (-not (Test-Path -LiteralPath $dumpPath -PathType Leaf)) { throw "Synthetic custom dump was not exported" }
    $checkpoints = [ordered]@{}
    foreach ($table in $CheckpointTables) { $checkpoints[$table] = 0 }
    $checkpoints["public_execution_events_max_sequence"] = 0
    $createdAt = (Get-Date).ToUniversalTime().ToString("o")
    $dumpItem = Get-Item -LiteralPath $dumpPath
    $manifest = [ordered]@{ schema_version = 1; created_at_utc = $createdAt; compose_project = "kairos-paper-gate"; database = "kairos"; file = $fixtureDumpName; bytes = [long]$dumpItem.Length; sha256 = (Get-FileSha256 -Path $dumpPath); checkpoints = $checkpoints; timescaledb_bgw_owners = @($BootstrapUser) }
    $manifestPath = Join-Path $exportDirectory "synthetic-runtime-schema-profile-$suffix.dump.json"
    Write-Utf8NoBom -Path $manifestPath -Content ($manifest | ConvertTo-Json -Depth 8)
    $receipt = [ordered]@{
        schema_version = 1; recovery_profile = "offline-closed-bar-v1"; result = "PASS"; created_at_utc = $createdAt;
        migrations = $LegacyMigrations; compose_project = "kairos-paper-gate"; database = "kairos";
        backup_sha256 = $manifest.sha256; backup_manifest_sha256 = (Get-FileSha256 -Path $manifestPath);
        inbox = [ordered]@{ failed = 0; processing = 0; expired_processing = 0 };
        outbox = [ordered]@{ pending = 7; active_leases = 0; expired_leases = 1; dead_lettered = 0; duplicate_audit_ids = 0; duplicate_outbox_ids = 0; outbox_without_audit = 0; read_only_consumer_restart_permitted = $false };
        offline_bar_recovery_permitted = $true
    }
    $receiptPath = Join-Path $exportDirectory "synthetic-runtime-recovery-$suffix.json"
    Write-Utf8NoBom -Path $receiptPath -Content ($receipt | ConvertTo-Json -Depth 8)
    $outputReceipt = Join-Path $exportDirectory "synthetic-runtime-profile-result-$suffix.json"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PreflightScript -ManifestPath $manifestPath -RecoveryReceiptPath $receiptPath -MigrationRunnerImage $runnerDigest -Confirmation CLONE_ONLY_RUNTIME_SCHEMA_PROFILE_PREFLIGHT -ReceiptPath $outputReceipt | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Runtime-only clone schema-profile preflight rejected its synthetic fixture" }
    $result = Get-Content -LiteralPath $outputReceipt -Raw | ConvertFrom-Json
    $placeholders = @($result.clone.timescaledb_bgw_owner_placeholders | ForEach-Object { [string]$_ })
    if ($result.result -ne "PASS_CLONE_ONLY" -or $result.migration_runner.persistence_revision -ne $ExpectedPersistenceRevision -or $result.migration_runner.excluded_simulator_migration -ne "017_simulator_journal.sql" -or $result.clone.simulator_relations_present -ne $false -or $result.original_migration.authorized -ne $false -or $result.source_backup.recovery_facts.outbox_expired_leases -ne 1 -or $placeholders.Count -ne 1 -or $placeholders[0] -ne $BootstrapUser) {
        throw "Synthetic runtime profile receipt does not preserve the required safety facts"
    }
    if (@($result.migration_runner.exact_runtime_profile) -contains "017_simulator_journal.sql") { throw "Synthetic runtime clone receipt includes simulator migration 017" }
    if ((Get-FileSha256 -Path $dumpPath) -ne $manifest.sha256) { throw "Synthetic source dump changed during runtime-profile preflight" }
    Write-Output "Synthetic runtime-only schema-profile preflight integration passed."
}
catch { $operationError = $_ }
finally {
    foreach ($action in @(
        { Remove-ScopedContainer -Name $runnerProbe -Suffix $suffix },
        { Remove-ScopedContainer -Name $bootstrapContainer -Suffix $suffix },
        { Remove-ScopedContainer -Name $registryContainer -Suffix $suffix },
        { Remove-ScopedVolume -Name $bootstrapVolume -Suffix $suffix },
        { Remove-ScopedImageTag -Name $registryTag -Suffix $suffix },
        { Remove-ScopedImageTag -Name $buildTag -Suffix $suffix }
    )) {
        try { & $action } catch { [void]$cleanupErrors.Add($_.Exception.Message) }
    }
    if (Test-Path -LiteralPath $tempRoot) {
        if ($tempRoot -notmatch 'kairos-runtime-profile-harness-[0-9a-f]{12}$') { [void]$cleanupErrors.Add("refused to remove unexpected synthetic harness directory") }
        else { try { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop } catch { [void]$cleanupErrors.Add("could not remove synthetic harness directory") } }
    }
}
if ($cleanupErrors.Count -gt 0) {
    $cleanupMessage = "Synthetic runtime profile harness cleanup failed: " + ($cleanupErrors -join "; ")
    Write-Output $cleanupMessage
    throw $cleanupMessage
}
if ($null -ne $operationError) {
    Write-Output ("Synthetic runtime profile harness failed: " + $operationError.Exception.Message)
    throw $operationError
}
