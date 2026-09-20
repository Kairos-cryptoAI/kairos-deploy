<#
.SYNOPSIS
    Runs a synthetic, isolated Docker integration drill for the clone-only
    schema-upgrade preflight.

.DESCRIPTION
    This is deliberately not an operator command for the PAPER runtime.  It
    builds a minimal migration-only runner from the exact local, clean
    kairos-persistence Git object, bootstraps an empty legacy 001--012 custom
    dump, and gives that synthetic backup to Invoke-SchemaUpgradePreflight.ps1.

    It never calls Docker Compose, reads a secret, looks below the source-code
    repositories, names a real runtime database, or mounts a runtime volume.
    Every object it creates has both a unique suffix and the labels checked by
    cleanup.  The Timescale bootstrap and all runner probes use `--network
    none`. A short-lived loopback-only local registry is the one required
    exception: Docker needs a registry protocol exchange to record a RepoDigest,
    which the preflight intentionally requires. Docker Desktop does not publish
    host ports from an internal network, so the registry uses the ordinary
    bridge with no mounted secrets, no upstream configuration, and a host
    binding restricted to 127.0.0.1. It is removed before this command returns.

    The harness is intentionally self-contained and makes no attempt to run a
    real backup, restore a real backup, or authorize a target migration.
#>

[CmdletBinding()]
param(
    [string]$PersistenceSource = "D:\Kairos\kairos-persistence",

    [string]$PreflightScript,

    # Both images must already be present locally.  The harness never pulls an
    # image because an integration test must not silently acquire network input.
    [string]$PythonBaseImage = "python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3",

    # The local registry image is likewise preload-only; absence is a test
    # failure rather than permission to pull mutable infrastructure input.
    [string]$RegistryImage = "registry:2"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Windows PowerShell does not initialize $PSScriptRoot soon enough for a
# parameter default expression in every invocation mode.  Resolve the sibling
# only after this file itself is executing.
if ([string]::IsNullOrWhiteSpace($PreflightScript)) {
    if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        throw "Synthetic preflight harness cannot resolve its script directory"
    }
    $PreflightScript = Join-Path $PSScriptRoot "Invoke-SchemaUpgradePreflight.ps1"
}

$ExpectedPersistenceRepository = "https://github.com/Kairos-cryptoAI/kairos-persistence"
$ExpectedPersistenceRevision = "9219e5ef46c748703d949b324d84f6814ba0f196"
$ExpectedTimescaleImage = "timescale/timescaledb:2.29.1-pg16@sha256:252a443e2936039b83dd8da1373d01e59e932d1054fa6adf1bc061f1d56ae60a"
$HarnessScope = "synthetic-schema-upgrade-preflight-harness"
$BootstrapUser = "kairos_upgrade"
$ExpectedRunnerUser = "10001:10001"
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

function Assert-DockerSuccess {
    param([Parameter(Mandatory = $true)][string]$Description)

    if ($LASTEXITCODE -ne 0) {
        throw "$Description (Docker exit code $LASTEXITCODE)"
    }
}

function Invoke-DockerQuiet {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    # Windows PowerShell 5.1 converts a non-zero native command into a
    # terminating NativeCommandError when ErrorActionPreference is Stop, even
    # if stderr is redirected.  Callers use this helper only for expected
    # existence/readiness probes and examine the captured exit code explicitly.
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& docker @Arguments 2>$null)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    return [pscustomobject]@{
        output = $output
        exit_code = [int]$exitCode
    }
}

function Assert-LocalImage {
    param([Parameter(Mandatory = $true)][string]$Image)

    $inspection = Invoke-DockerQuiet -Arguments @("image", "inspect", $Image)
    if ($inspection.exit_code -ne 0) {
        throw "Required local image is unavailable: $Image. Preload it explicitly; this harness never pulls images."
    }
}

function Get-ObjectLabels {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("container", "volume", "image")][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $format = if ($Kind -in @("container", "image")) { '{{json .Config.Labels}}' } else { '{{json .Labels}}' }
    $inspection = Invoke-DockerQuiet -Arguments @($Kind, "inspect", "--format", $format, $Name)
    if ($inspection.exit_code -ne 0) {
        return $null
    }
    $raw = $inspection.output
    $text = (($raw | Select-Object -Last 1) -as [string]).Trim()
    if ([string]::IsNullOrWhiteSpace($text) -or $text -eq "null") {
        throw "Refusing an unlabelled $Kind during synthetic harness cleanup: $Name"
    }
    try {
        return ($text | ConvertFrom-Json)
    }
    catch {
        throw "Could not parse $Kind labels during synthetic harness cleanup: $Name"
    }
}

function Assert-Labels {
    param(
        [Parameter(Mandatory = $true)]$Labels,
        [Parameter(Mandatory = $true)][string]$Scope,
        [Parameter(Mandatory = $true)][string]$Suffix,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $scopeProperty = $Labels.PSObject.Properties["com.kairos.scope"]
    $drillProperty = $Labels.PSObject.Properties["com.kairos.drill"]
    if ($null -eq $scopeProperty -or $null -eq $drillProperty -or
        $scopeProperty.Value -cne $Scope -or $drillProperty.Value -cne $Suffix) {
        throw "Refusing to remove $Description with mismatched synthetic-harness labels"
    }
}

function Remove-CheckedContainer {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Scope,
        [Parameter(Mandatory = $true)][string]$Suffix
    )

    $labels = Get-ObjectLabels -Kind container -Name $Name
    if ($null -eq $labels) { return }
    Assert-Labels -Labels $labels -Scope $Scope -Suffix $Suffix -Description "container $Name"
    & docker rm -f $Name 2>$null | Out-Null
    Assert-DockerSuccess -Description "Could not remove checked synthetic container $Name"
}

function Remove-CheckedVolume {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Scope,
        [Parameter(Mandatory = $true)][string]$Suffix
    )

    $labels = Get-ObjectLabels -Kind volume -Name $Name
    if ($null -eq $labels) { return }
    Assert-Labels -Labels $labels -Scope $Scope -Suffix $Suffix -Description "volume $Name"
    & docker volume rm $Name 2>$null | Out-Null
    Assert-DockerSuccess -Description "Could not remove checked synthetic volume $Name"
}

function Remove-CheckedImage {
    param(
        [Parameter(Mandatory = $true)][string]$Reference,
        [Parameter(Mandatory = $true)][string]$Suffix
    )

    # docker image inspect accepts an OCI repository@digest reference even
    # when docker image rm cannot remove by that reference. Resolve the exact
    # local content ID first, then recheck its labels before removal.
    $inspection = Invoke-DockerQuiet -Arguments @("image", "inspect", "--format", "{{.Id}}", $Reference)
    $imageId = (($inspection.output | Select-Object -Last 1) -as [string]).Trim()
    if ($inspection.exit_code -ne 0 -or $imageId -notmatch '^sha256:[0-9a-f]{64}$') { return }
    $labels = Get-ObjectLabels -Kind image -Name $imageId
    if ($null -eq $labels) { return }
    Assert-Labels -Labels $labels -Scope $HarnessScope -Suffix $Suffix -Description "image $Reference"
    & docker image rm -f $imageId 2>$null | Out-Null
    Assert-DockerSuccess -Description "Could not remove checked synthetic runner image $Reference"
}

function Get-RandomLocalPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Wait-ContainerPostgres {
    param([Parameter(Mandatory = $true)][string]$Container)

    # The official entrypoint briefly exposes an initialization postmaster
    # before it stops that process and starts the final server.  pg_isready
    # alone can succeed during that handoff, so require three successful
    # authenticated SQL probes separated in time before creating the legacy
    # fixture database.
    $consecutiveSqlProbes = 0
    for ($attempt = 1; $attempt -le 60; $attempt++) {
        $containerInspection = Invoke-DockerQuiet -Arguments @("inspect", "--format", "{{.State.Running}}", $Container)
        $running = (($containerInspection.output | Select-Object -Last 1) -as [string]).Trim()
        $inspectExitCode = $containerInspection.exit_code
        if ($inspectExitCode -ne 0 -or $running -cne "true") {
            throw "Synthetic bootstrap TimescaleDB stopped before it became stable"
        }

        # The image first runs an initialization postmaster, then stops it
        # after timescaledb-tune and starts the final server.  The final log
        # marker is required in addition to authenticated probes so the next
        # bootstrap DDL cannot race that handoff.
        # The image emits harmless init warnings (for example, unavailable
        # locales) on stderr.  Suppress only that transport stream: the
        # authoritative completion marker is emitted on stdout.
        $logResult = Invoke-DockerQuiet -Arguments @("logs", $Container)
        $entrypointLog = $logResult.output
        $entrypointExitCode = $logResult.exit_code
        if ($entrypointExitCode -ne 0 -or $entrypointLog -notcontains "PostgreSQL init process complete; ready for start up.") {
            $consecutiveSqlProbes = 0
            Start-Sleep -Seconds 2
            continue
        }

        $probeResult = Invoke-DockerQuiet -Arguments @(
            "exec", $Container, "psql", "--username=$BootstrapUser", "--dbname=postgres",
            "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1", "--command=SELECT 1;"
        )
        $probe = $probeResult.output
        $probeExitCode = $probeResult.exit_code
        $probeValues = @($probe | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
        if ($probeExitCode -eq 0 -and $probeValues -contains "1") {
            $consecutiveSqlProbes++
            if ($consecutiveSqlProbes -ge 3) { return }
            # A successful probe during the entrypoint's initialization
            # postmaster is not enough: observe it across the handoff.
            Start-Sleep -Seconds 2
            continue
        }
        else {
            $consecutiveSqlProbes = 0
        }
        Start-Sleep -Seconds 2
    }
    throw "Synthetic bootstrap TimescaleDB did not become stable within 120 seconds"
}

function Wait-LocalRegistry {
    param([Parameter(Mandatory = $true)][int]$Port)

    for ($attempt = 1; $attempt -le 30; $attempt++) {
        try {
            # Windows PowerShell's Invoke-WebRequest can keep its response
            # stream open under a non-interactive redirected host.  Use the
            # underlying no-proxy HTTP request and always close the response.
            $request = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$Port/v2/")
            $request.Proxy = $null
            $request.Timeout = 2000
            $request.ReadWriteTimeout = 2000
            $response = $request.GetResponse()
            try {
                if ([int]$response.StatusCode -eq 200) { return }
            }
            finally {
                $response.Close()
            }
        }
        catch {
            # The endpoint is intentionally local-only and is expected to take
            # a moment to start.  Do not fall back to any external registry.
        }
        Start-Sleep -Seconds 1
    }
    throw "Temporary loopback-only Docker registry did not become ready"
}

function New-SyntheticPassword {
    $bytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return [Convert]::ToBase64String($bytes)
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
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

function Assert-CleanImmutablePersistenceSource {
    param([Parameter(Mandatory = $true)][string]$Source)

    $sourcePath = (Resolve-Path -LiteralPath $Source).Path
    $gitDirectory = Join-Path $sourcePath ".git"
    if (-not (Test-Path -LiteralPath $gitDirectory -PathType Container)) {
        throw "Synthetic runner source is not a Git checkout: $sourcePath"
    }
    $remote = ((& git -C $sourcePath remote get-url origin) | Select-Object -Last 1).Trim()
    if ($LASTEXITCODE -ne 0 -or ($remote -cne $ExpectedPersistenceRepository -and
        $remote -cne "$ExpectedPersistenceRepository.git")) {
        throw "Synthetic runner source does not identify the reviewed persistence repository"
    }
    $object = ((& git -C $sourcePath rev-parse "$ExpectedPersistenceRevision^{commit}") | Select-Object -Last 1).Trim()
    if ($LASTEXITCODE -ne 0 -or $object -cne $ExpectedPersistenceRevision) {
        throw "Synthetic runner source does not contain persistence revision $ExpectedPersistenceRevision"
    }
    $status = @(& git -C $sourcePath status --porcelain --untracked-files=all)
    if ($LASTEXITCODE -ne 0 -or $status.Count -ne 0) {
        throw "Synthetic runner source must be clean; it is not safe to build from a working tree"
    }
    return $sourcePath
}

function Assert-ExactLegacyMigrations {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$DatabaseName
    )

    $actual = @(& docker exec $Container psql --username=$BootstrapUser --dbname=$DatabaseName `
        --tuples-only --no-align --set=ON_ERROR_STOP=1 --command="SELECT version FROM schema_migrations ORDER BY version;")
    Assert-DockerSuccess -Description "Could not inspect synthetic legacy migration profile"
    $actual = @($actual | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
    if ($actual.Count -ne $LegacyMigrations.Count) {
        throw "Synthetic legacy bootstrap did not create the exact 001--012 migration profile"
    }
    for ($index = 0; $index -lt $LegacyMigrations.Count; $index++) {
        if ($actual[$index] -cne $LegacyMigrations[$index]) {
            throw "Synthetic legacy bootstrap did not create the exact 001--012 migration profile"
        }
    }
}

function Assert-SyntheticReceipt {
    param([Parameter(Mandatory = $true)][string]$Path)

    $receipt = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    if ($receipt.result -cne "PASS_CLONE_ONLY" -or $receipt.classification -cne "CLONE_ONLY_SCHEMA_UPGRADE_PREFLIGHT") {
        throw "Synthetic clone-only preflight did not issue PASS_CLONE_ONLY"
    }
    if ($receipt.clone.isolated -ne $true -or $receipt.clone.original_runtime_contacted -ne $false -or
        $receipt.original_migration.authorized -ne $false) {
        throw "Synthetic clone-only receipt violates runtime isolation or authorization policy"
    }
    if ($receipt.readiness.paper_qualified -ne $false -or $receipt.readiness.alpha_ready -ne $false -or
        $receipt.readiness.live_ready -ne $false -or $receipt.readiness.strategy_policy -cne "REJECT_ALL") {
        throw "Synthetic clone-only receipt must not change readiness"
    }
    if ($receipt.idempotency.unchanged -ne $true -or
        $receipt.idempotency.first_pass_migration_count -ne 18 -or
        $receipt.idempotency.second_pass_migration_count -ne 18 -or
        $receipt.restore_drill.passed -ne $true -or
        @($receipt.restore_drill.target_profile).Count -ne 18) {
        throw "Synthetic clone-only receipt does not prove idempotency and restore coverage"
    }
}

if (-not (Test-Path -LiteralPath $PreflightScript -PathType Leaf)) {
    throw "Clone-only preflight script is unavailable: $PreflightScript"
}
Assert-LocalImage -Image $PythonBaseImage
Assert-LocalImage -Image $RegistryImage
Assert-LocalImage -Image $ExpectedTimescaleImage
$persistencePath = Assert-CleanImmutablePersistenceSource -Source $PersistenceSource

$suffix = ([guid]::NewGuid().ToString("N")).Substring(0, 12)
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "kairos-schema-upgrade-harness-$suffix"
$tempParent = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$tempRootFull = [System.IO.Path]::GetFullPath($tempRoot)
if (-not $tempRootFull.StartsWith($tempParent, [System.StringComparison]::OrdinalIgnoreCase) -or
    $tempRootFull -notmatch 'kairos-schema-upgrade-harness-[0-9a-f]{12}$') {
    throw "Refusing a synthetic harness temporary path outside the generated TEMP namespace"
}

$bootstrapContainer = "kairos-schema-upgrade-bootstrap-$suffix"
$bootstrapVolume = "kairos-schema-upgrade-bootstrap-data-$suffix"
$runnerProbe = "kairos-schema-upgrade-harness-runner-$suffix"
$registryContainer = "kairos-schema-upgrade-registry-$suffix"
$buildTag = "kairos-schema-upgrade-runner-${suffix}:local"
$registryPort = Get-RandomLocalPort
$registryRepository = "127.0.0.1:$registryPort/kairos-schema-upgrade-runner-$suffix"
$registryTag = "${registryRepository}:immutable"
$bootstrapDatabase = "kairos_schema_upgrade_bootstrap_$suffix"
$bootstrapDumpInContainer = "/kairos-export/synthetic-kairos-paper-gate-$suffix.dump"
$bootstrapMigrationDirectory = "/kairos-import"
$bootstrapRunnerInContainer = "/kairos-import/bootstrap-legacy-$suffix.sql"
$runnerDigest = $null
$operationError = $null
$cleanupErrors = [System.Collections.Generic.List[string]]::new()

try {
    New-Item -ItemType Directory -Path $tempRootFull -ErrorAction Stop | Out-Null
    $context = Join-Path $tempRootFull "context"
    $snapshot = Join-Path $context "persistence"
    $bootstrapImportDirectory = Join-Path $tempRootFull "bootstrap-import"
    $bootstrapExportDirectory = Join-Path $tempRootFull "bootstrap-export"
    New-Item -ItemType Directory -Path $context -ErrorAction Stop | Out-Null
    New-Item -ItemType Directory -Path $bootstrapImportDirectory -ErrorAction Stop | Out-Null
    New-Item -ItemType Directory -Path $bootstrapExportDirectory -ErrorAction Stop | Out-Null
    $archive = Join-Path $tempRootFull "persistence-$ExpectedPersistenceRevision.zip"
    # The host Git installation may globally enable core.autocrlf.  Archive
    # the committed blob bytes with explicit LF settings: migration hashes are
    # part of the preflight trust boundary and must not depend on Windows
    # checkout conversion.
    & git -C $persistencePath -c core.autocrlf=false -c core.eol=lf archive --format=zip --output=$archive $ExpectedPersistenceRevision
    if ($LASTEXITCODE -ne 0) { throw "Could not create immutable persistence source archive" }
    Expand-Archive -LiteralPath $archive -DestinationPath $snapshot -Force
    if (-not (Test-Path -LiteralPath (Join-Path $snapshot "kairos_persistence\migrations\018_offline_outbox_reconciliation.sql") -PathType Leaf)) {
        throw "Immutable persistence archive lacks the required 001--018 migration source"
    }

    $runnerInit = Join-Path $context "runner-init.py"
    $dockerfile = Join-Path $context "Dockerfile"
    Write-Utf8NoBom -Path $runnerInit -Content "`"`"`"Minimal migration-only runner package for an isolated Kairos drill.`"`"`"`n"
    Write-Utf8NoBom -Path $dockerfile -Content @"
FROM $PythonBaseImage
RUN groupadd --gid 10001 kairos_runner \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin kairos_runner
COPY persistence/kairos_persistence/migrations /opt/kairos_persistence/migrations
COPY runner-init.py /opt/kairos_persistence/__init__.py
RUN chown -R 10001:10001 /opt/kairos_persistence
ENV PYTHONPATH=/opt PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
"@
    & docker build --pull=false --network=none `
        --label "com.kairos.scope=$HarnessScope" --label "com.kairos.drill=$suffix" `
        --label "org.opencontainers.image.source=$ExpectedPersistenceRepository" `
        --label "org.opencontainers.image.revision=$ExpectedPersistenceRevision" `
        --file $dockerfile --tag $buildTag $context | Out-Host
    Assert-DockerSuccess -Description "Could not build the no-network immutable migration runner"

    # Docker exposes an image digest as RepoDigests only after a registry exchange.
    # Docker Desktop cannot publish host ports from an internal network. This
    # bridge-connected registry has no credentials or upstream and publishes
    # only to the local loopback endpoint used by this harness.
    & docker run -d --name $registryContainer --network bridge --read-only `
        --tmpfs "/var/lib/registry:rw,nosuid,nodev,noexec,size=128m" `
        --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=16m" `
        --publish "127.0.0.1:${registryPort}:5000" `
        --label "com.kairos.scope=$HarnessScope" --label "com.kairos.drill=$suffix" `
        $RegistryImage | Out-Null
    Assert-DockerSuccess -Description "Could not start the temporary loopback registry"
    Wait-LocalRegistry -Port $registryPort
    & docker tag $buildTag $registryTag
    Assert-DockerSuccess -Description "Could not tag the immutable migration runner for the temporary registry"
    $pushOutput = @(& docker push $registryTag 2>&1)
    Assert-DockerSuccess -Description "Could not push the immutable migration runner to the temporary local registry"
    $digestMatch = [regex]::Match(($pushOutput -join "`n"), 'digest:\s*(sha256:[0-9a-f]{64})')
    if (-not $digestMatch.Success) {
        throw "Temporary registry did not report an immutable runner digest"
    }
    $runnerDigest = "$registryRepository@$($digestMatch.Groups[1].Value)"
    & docker pull $runnerDigest | Out-Null
    Assert-DockerSuccess -Description "Could not load the immutable local-registry runner digest"
    $repoDigests = (& docker image inspect --format '{{json .RepoDigests}}' $runnerDigest)
    Assert-DockerSuccess -Description "Could not inspect immutable local-registry runner metadata"
    $resolvedRepoDigests = @((($repoDigests | Select-Object -Last 1) | ConvertFrom-Json))
    if ($resolvedRepoDigests.Count -eq 0 -or
        @($resolvedRepoDigests | Where-Object { $_ -notmatch '^.+@sha256:[0-9a-f]{64}$' }).Count -gt 0) {
        throw "Local migration runner metadata does not retain an immutable RepoDigest"
    }

    # Use a no-network, independently-labelled TimescaleDB only to create an
    # empty historical 001--012 custom dump.  It is not a clone of any runtime.
    $bootstrapPassword = New-SyntheticPassword
    & docker volume create --label "com.kairos.scope=$HarnessScope" --label "com.kairos.drill=$suffix" $bootstrapVolume | Out-Null
    Assert-DockerSuccess -Description "Could not create the synthetic bootstrap volume"
    & docker create --name $bootstrapContainer --network none --memory 2g --cpus 2 --pids-limit 256 `
        --label "com.kairos.scope=$HarnessScope" --label "com.kairos.drill=$suffix" `
        --mount "type=volume,src=$bootstrapVolume,dst=/var/lib/postgresql/data" `
        --mount "type=bind,src=$bootstrapImportDirectory,dst=/kairos-import,readonly" `
        --mount "type=bind,src=$bootstrapExportDirectory,dst=/kairos-export" `
        --tmpfs "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=256m" `
        --tmpfs "/var/run/postgresql:rw,nosuid,nodev,noexec,mode=1777,size=16m" `
        --env "POSTGRES_USER=$BootstrapUser" --env "POSTGRES_DB=postgres" --env "POSTGRES_PASSWORD=$bootstrapPassword" `
        $ExpectedTimescaleImage | Out-Null
    Assert-DockerSuccess -Description "Could not create the synthetic no-network bootstrap database"
    & docker start $bootstrapContainer | Out-Null
    Assert-DockerSuccess -Description "Could not start the synthetic no-network bootstrap database"
    Wait-ContainerPostgres -Container $bootstrapContainer

    # A stopped, no-network migration package probe supplies the immutable SQL
    # files to the disposable bootstrap database; it has no database credential.
    $probeCode = "from importlib.resources import files; print(files('kairos_persistence').joinpath('migrations'))"
    & docker create --name $runnerProbe --network none --read-only --cap-drop ALL `
        --security-opt no-new-privileges:true --pids-limit 32 --memory 128m --cpus 0.25 --user $ExpectedRunnerUser `
        --label "com.kairos.scope=$HarnessScope" --label "com.kairos.drill=$suffix" `
        --entrypoint python $runnerDigest -c $probeCode | Out-Null
    Assert-DockerSuccess -Description "Could not create the synthetic no-network migration probe"
    $migrationDirectory = ((& docker start -a $runnerProbe) | Select-Object -Last 1).Trim()
    Assert-DockerSuccess -Description "Synthetic no-network migration probe failed"
    if ($migrationDirectory -cne "/opt/kairos_persistence/migrations") {
        throw "Synthetic migration probe returned an unexpected migration directory"
    }
    # Docker Desktop does not reliably copy files into a tmpfs through
    # docker cp.  The synthetic bootstrap instead receives a read-only bind
    # of its own generated import directory; it contains only immutable
    # migration bytes and the generated fixture runner, never runtime data or
    # secrets.
    $hostMigrationDirectory = $bootstrapImportDirectory
    foreach ($migration in $LegacyMigrations) {
        $hostMigration = Join-Path $hostMigrationDirectory $migration
        & docker cp "${runnerProbe}:$migrationDirectory/$migration" $hostMigration
        Assert-DockerSuccess -Description "Could not export immutable legacy migration $migration from the synthetic runner"
        if (-not (Test-Path -LiteralPath $hostMigration -PathType Leaf)) {
            throw "Synthetic host import is missing immutable legacy migration $migration"
        }
    }
    $legacySql = [System.Collections.Generic.List[string]]::new()
    [void]$legacySql.Add("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now());")
    foreach ($migration in $LegacyMigrations) {
        [void]$legacySql.Add("\i $bootstrapMigrationDirectory/$migration")
        [void]$legacySql.Add("INSERT INTO schema_migrations(version) VALUES ('$migration');")
    }
    $legacySqlPath = Join-Path $bootstrapImportDirectory "bootstrap-legacy-$suffix.sql"
    Write-Utf8NoBom -Path $legacySqlPath -Content (($legacySql -join "`n") + "`n")
    & docker exec $bootstrapContainer createdb --username=$BootstrapUser $bootstrapDatabase
    Assert-DockerSuccess -Description "Could not create synthetic legacy bootstrap database"
    if (-not (Test-Path -LiteralPath $legacySqlPath -PathType Leaf)) {
        throw "Synthetic host import is missing the generated legacy migration runner"
    }
    & docker exec $bootstrapContainer psql --username=$BootstrapUser --dbname=$bootstrapDatabase --set=ON_ERROR_STOP=1 `
        --single-transaction --file=$bootstrapRunnerInContainer | Out-Host
    Assert-DockerSuccess -Description "Could not apply synthetic exact legacy migration profile"
    Assert-ExactLegacyMigrations -Container $bootstrapContainer -DatabaseName $bootstrapDatabase
    & docker exec $bootstrapContainer pg_dump --format=custom --no-owner --no-privileges --username=$BootstrapUser `
        --dbname=$bootstrapDatabase --file=$bootstrapDumpInContainer
    Assert-DockerSuccess -Description "Could not create synthetic legacy custom dump"
    $dumpPath = Join-Path $bootstrapExportDirectory "synthetic-kairos-paper-gate-$suffix.dump"
    if (-not (Test-Path -LiteralPath $dumpPath -PathType Leaf)) {
        throw "Synthetic host export is missing the generated legacy custom dump"
    }

    $dumpItem = Get-Item -LiteralPath $dumpPath
    $dumpSha256 = Get-FileSha256 -Path $dumpPath
    $checkpoints = [ordered]@{}
    foreach ($table in $CheckpointTables) { $checkpoints[$table] = 0 }
    $checkpoints["public_execution_events_max_sequence"] = 0
    $createdAt = (Get-Date).ToUniversalTime().ToString("o")
    # The production preflight resolves the immutable dump relative to its
    # manifest.  Keep the synthetic pair together in the generated export
    # directory so this harness exercises the real input contract.
    $manifestPath = Join-Path $bootstrapExportDirectory "synthetic-kairos-paper-gate-$suffix.dump.json"
    $baselineReceiptPath = Join-Path $bootstrapExportDirectory "synthetic-runtime-recovery-$suffix.json"
    $manifest = [ordered]@{
        schema_version = 1
        created_at_utc = $createdAt
        compose_project = "kairos-paper-gate"
        database = "kairos"
        file = [System.IO.Path]::GetFileName($dumpPath)
        bytes = [long]$dumpItem.Length
        sha256 = $dumpSha256
        checkpoints = $checkpoints
    }
    Write-Utf8NoBom -Path $manifestPath -Content ($manifest | ConvertTo-Json -Depth 8)
    $manifestSha256 = Get-FileSha256 -Path $manifestPath
    $baselineReceipt = [ordered]@{
        schema_version = 1
        recovery_profile = "offline-closed-bar-v1"
        result = "PASS"
        migrations = $LegacyMigrations
        inbox = [ordered]@{ failed = 0; processing = 0; expired_processing = 0 }
        outbox = [ordered]@{
            active_leases = 0
            expired_leases = 0
            duplicate_audit_ids = 0
            duplicate_outbox_ids = 0
            outbox_without_audit = 0
            read_only_consumer_restart_permitted = $true
        }
        offline_bar_recovery_permitted = $true
        compose_project = "kairos-paper-gate"
        database = "kairos"
        backup_sha256 = $dumpSha256
        backup_manifest_sha256 = $manifestSha256
        created_at_utc = $createdAt
    }
    Write-Utf8NoBom -Path $baselineReceiptPath -Content ($baselineReceipt | ConvertTo-Json -Depth 8)
    $cloneReceiptPath = Join-Path $bootstrapExportDirectory "synthetic-schema-upgrade-preflight-$suffix.json"
    & $PreflightScript -ManifestPath $manifestPath -BaselineReceiptPath $baselineReceiptPath `
        -MigrationRunnerImage $runnerDigest -Confirmation "CLONE_ONLY_SCHEMA_UPGRADE_PREFLIGHT" `
        -ReceiptPath $cloneReceiptPath | Out-Host
    Assert-SyntheticReceipt -Path $cloneReceiptPath
    Write-Output "Synthetic clone-only schema-upgrade preflight integration passed: $cloneReceiptPath"
}
catch {
    $operationError = $_
}
finally {
    # The preflight owns a separately generated suffix and cleans it in its own
    # finally block before control returns here.  Do not guess that suffix or
    # enumerate its label scope: after a hard process termination an operator
    # must audit those separately labelled resources, rather than let this
    # harness risk deleting a different interrupted preflight drill.
    foreach ($entry in @(
        @{ name = $runnerProbe; scope = $HarnessScope },
        @{ name = $bootstrapContainer; scope = $HarnessScope },
        @{ name = $registryContainer; scope = $HarnessScope }
    )) {
        try { Remove-CheckedContainer -Name $entry.name -Scope $entry.scope -Suffix $suffix }
        catch { [void]$cleanupErrors.Add($_.Exception.Message) }
    }
    foreach ($entry in @(
        @{ name = $bootstrapVolume; scope = $HarnessScope }
    )) {
        try { Remove-CheckedVolume -Name $entry.name -Scope $entry.scope -Suffix $suffix }
        catch { [void]$cleanupErrors.Add($_.Exception.Message) }
    }
    foreach ($reference in @($runnerDigest, $registryTag, $buildTag) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) {
        try { Remove-CheckedImage -Reference $reference -Suffix $suffix }
        catch { [void]$cleanupErrors.Add($_.Exception.Message) }
    }
    if (Test-Path -LiteralPath $tempRootFull) {
        try {
            if ($tempRootFull -notmatch 'kairos-schema-upgrade-harness-[0-9a-f]{12}$' -or
                -not $tempRootFull.StartsWith($tempParent, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing to remove a temporary directory outside this generated harness namespace"
            }
            Remove-Item -LiteralPath $tempRootFull -Recurse -Force
        }
        catch { [void]$cleanupErrors.Add($_.Exception.Message) }
    }
}

if ($null -ne $operationError) {
    if ($cleanupErrors.Count -gt 0) {
        throw "$($operationError.Exception.Message) Cleanup also failed: $($cleanupErrors -join '; ')"
    }
    throw $operationError
}
if ($cleanupErrors.Count -gt 0) {
    throw "Synthetic schema-upgrade preflight cleanup failed: $($cleanupErrors -join '; ')"
}
