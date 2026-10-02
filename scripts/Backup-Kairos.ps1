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

function Assert-BackupDirectoryBoundary {
    param([string]$Root, [string]$Candidate)

    $separator = [System.IO.Path]::DirectorySeparatorChar
    $rootPath = [System.IO.Path]::GetFullPath($Root).TrimEnd($separator)
    $candidatePath = [System.IO.Path]::GetFullPath($Candidate).TrimEnd($separator)
    $comparison = [System.StringComparison]::Ordinal
    if ($separator -eq '\') { $comparison = [System.StringComparison]::OrdinalIgnoreCase }
    if (-not [string]::Equals($candidatePath, $rootPath, $comparison) -and
        -not $candidatePath.StartsWith($rootPath + $separator, $comparison)) {
        throw "Backup output must remain inside the deployment repository"
    }
}

function Resolve-BackupExistingDirectory {
    param([string]$Path)

    # Resolve-Path alone preserves Windows junction spellings. Follow every
    # existing ancestor's link target, including links in a parent directory.
    $resolved = [System.IO.Path]::GetFullPath($Path)
    for ($hop = 0; $hop -lt 32; $hop++) {
        $cursor = $resolved
        $followed = $false
        while ($cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if (-not $item.PSIsContainer) { throw "Backup ancestor must be a directory" }
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                $targets = @($item.Target)
                if ($targets.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$targets[0])) {
                    throw "Backup ancestor has an unsupported reparse target"
                }
                $target = [string]$targets[0]
                if (-not [System.IO.Path]::IsPathRooted($target)) {
                    $target = [System.IO.Path]::Combine($item.Parent.FullName, $target)
                }
                $suffix = $resolved.Substring($cursor.Length).TrimStart([char[]]@('\', '/'))
                $resolved = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($target, $suffix))
                $followed = $true
                break
            }
            $cursor = [System.IO.Path]::GetDirectoryName($cursor)
        }
        if (-not $followed) { return (Resolve-Path -LiteralPath $resolved -ErrorAction Stop).ProviderPath }
    }
    throw "Backup ancestor reparse chain is cyclic or too deep"
}

function Initialize-BackupDirectory {
    param([string]$Root, [string]$OutputPath)

    $rootPath = [System.IO.Path]::GetFullPath($Root)
    $candidate = $OutputPath
    if (-not [System.IO.Path]::IsPathRooted($candidate)) {
        $candidate = [System.IO.Path]::Combine($rootPath, $candidate)
    }
    $candidate = [System.IO.Path]::GetFullPath($candidate)
    Assert-BackupDirectoryBoundary -Root $rootPath -Candidate $candidate

    # Verify the closest existing ancestor before creating any missing child.
    # Object-not-found is expected; permission and other lookup errors fail closed.
    $ancestor = $candidate
    $suffix = [System.Collections.Generic.List[string]]::new()
    while ($true) {
        $existing = $null
        try {
            $existing = Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
            if ($null -ne $existing) { break }
        }
        catch {
            if ($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound) { throw }
        }
        # Windows PowerShell 5.1 can return no item instead of ObjectNotFound
        # for a missing literal path containing brackets.
        $suffix.Insert(0, [System.IO.Path]::GetFileName($ancestor))
        $ancestor = [System.IO.Path]::GetDirectoryName($ancestor)
        if (-not $ancestor) { throw "Backup directory has no existing ancestor" }
    }
    if (-not $existing.PSIsContainer) { throw "Backup ancestor must be a directory" }
    $canonicalRoot = Resolve-BackupExistingDirectory -Path $rootPath
    $canonicalCandidate = Resolve-BackupExistingDirectory -Path $ancestor
    foreach ($part in $suffix) { $canonicalCandidate = [System.IO.Path]::Combine($canonicalCandidate, $part) }
    Assert-BackupDirectoryBoundary -Root $canonicalRoot -Candidate $canonicalCandidate
    [System.IO.Directory]::CreateDirectory($canonicalCandidate) | Out-Null
    $created = Resolve-BackupExistingDirectory -Path $canonicalCandidate
    Assert-BackupDirectoryBoundary -Root $canonicalRoot -Candidate $created
    return $created
}

if ($ComposeProject -notmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$') {
    throw "ComposeProject contains unsupported filename characters"
}
$root = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$composePath = (Resolve-Path -LiteralPath (Join-Path $root $ComposeFile)).Path
$envPath = (Resolve-Path -LiteralPath (Join-Path $root $EnvFile)).Path
$backupRoot = Initialize-BackupDirectory -Root $root -OutputPath $OutputDirectory

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

function Get-TimescaleBackgroundJobOwners {
    # ``pg_dump --no-owner`` retains the owner column in TimescaleDB's internal
    # bgw_job data.  A clone must create no-login placeholders for these exact,
    # non-secret identifiers before pg_restore; record them beside the dump so
    # a future clone never guesses from an old runtime environment.
    $owners = @(& docker exec $container psql --username=$DatabaseUser --dbname=$Database --tuples-only --no-align `
        --set=ON_ERROR_STOP=1 --command="SELECT owner FROM _timescaledb_config.bgw_job GROUP BY owner ORDER BY owner;" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read TimescaleDB background-job owner provenance"
    }
    if (@($owners | Where-Object { $_ -notmatch '^[A-Za-z_][A-Za-z0-9_]{0,62}$' }).Count -ne 0) {
        throw "TimescaleDB background-job owner is not a safe PostgreSQL identifier"
    }
    if (@($owners | Sort-Object -Unique).Count -ne $owners.Count) {
        throw "TimescaleDB background-job owner provenance is not unique"
    }
    return @($owners)
}

$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$name = "$ComposeProject-$stamp.dump"
$containerDump = "/tmp/$name"
$localDump = Join-Path $backupRoot $name
$checkpointsBefore = Get-DatabaseCheckpoints
$backgroundJobOwnersBefore = Get-TimescaleBackgroundJobOwners
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
$backgroundJobOwnersAfter = Get-TimescaleBackgroundJobOwners
foreach ($checkpointName in $checkpointsBefore.Keys) {
    if ($checkpointsBefore[$checkpointName] -ne $checkpointsAfter[$checkpointName]) {
        throw "Database changed during backup checkpoint $checkpointName; retry from a quiesced PAPER session"
    }
}
if ((Compare-Object -ReferenceObject $backgroundJobOwnersBefore -DifferenceObject $backgroundJobOwnersAfter)) {
    throw "TimescaleDB background-job owner provenance changed during backup; retry from a quiesced PAPER session"
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
    sha256 = Get-FileSha256 -Path $item.FullName
    checkpoints = $checkpointsAfter
    # PowerShell unwraps a single returned owner; the manifest contract always
    # requires an array so a one-owner backup can pass strict clone validation.
    timescaledb_bgw_owners = @($backgroundJobOwnersAfter)
}
$manifestPath = "$localDump.json"
$manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding utf8
Write-Output $manifestPath
