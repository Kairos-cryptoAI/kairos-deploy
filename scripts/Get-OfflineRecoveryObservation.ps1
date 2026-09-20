<#!
.SYNOPSIS
    Reports the observed state of a bounded offline Binance recovery without
    changing the recovery, its status file, or the source database.

.DESCRIPTION
    A hidden supervisor can exit after its recovery child has emitted a terminal
    JSON event, leaving the operator's initial status file as RUNNING.  This
    observer deliberately does not "repair" that file.  It binds a read-only
    observation to its SHA-256, checks whether the recorded supervisor PID still
    exists, and recognizes only the final JSON event in the preserved stdout.

    COMPLETED_UNVERIFIED is not a recovery acceptance.  It means only that the
    recorded process is absent and its preserved stdout ended in COMPLETED.  A
    fresh backup, recovery preflight, continuity check, and outbox
    reconciliation remain mandatory before any consumer can be restarted.

    The script prints a redacted JSON observation and never prints command
    lines, environment values, logs, credentials, or database data.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$StatusPath,

    [ValidateRange(1, 4096)]
    [int]$TailLines = 512
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Get-RequiredString([object]$Object, [string]$Name) {
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)) {
        throw "Recovery status is missing required non-empty $Name."
    }
    return ([string]$property.Value).Trim()
}

function Get-TerminalLogEvent([string]$Path, [int]$Count) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    $terminal = $null
    foreach ($line in (Get-Content -LiteralPath $Path -Tail $Count)) {
        $trimmed = $line.Trim()
        if (-not $trimmed.StartsWith('{')) {
            continue
        }
        try {
            $event = $trimmed | ConvertFrom-Json -ErrorAction Stop
        } catch {
            continue
        }
        $stateProperty = $event.PSObject.Properties['state']
        if ($null -eq $stateProperty) {
            continue
        }
        $state = ([string]$stateProperty.Value).Trim().ToUpperInvariant()
        if ($state -notin @('COMPLETED', 'FAILED')) {
            continue
        }
        $observedProperty = $event.PSObject.Properties['observed_at_utc']
        $terminal = [ordered]@{
            state = $state
            observed_at_utc = if ($null -eq $observedProperty) { $null } else { [string]$observedProperty.Value }
        }
    }
    return $terminal
}

$resolvedStatusPath = (Resolve-Path -LiteralPath $StatusPath -ErrorAction Stop).Path
$rawStatus = Get-Content -LiteralPath $resolvedStatusPath -Raw -ErrorAction Stop
try {
    $status = $rawStatus | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw 'Recovery status is not valid JSON.'
}

$reportedState = (Get-RequiredString $status 'state').ToUpperInvariant()
if ($reportedState -notin @('RUNNING', 'COMPLETED', 'FAILED')) {
    throw "Recovery status has unsupported state $reportedState."
}
$processIdText = Get-RequiredString $status 'process_id'
try {
    $processId = [int]$processIdText
} catch {
    throw 'Recovery status process_id is not an integer.'
}
if ($processId -le 0) {
    throw 'Recovery status process_id must be positive.'
}
$startedAt = [DateTimeOffset]::Parse((Get-RequiredString $status 'started_at_utc')).ToUniversalTime()
$stdoutPath = Get-RequiredString $status 'stdout'

$process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue
$processState = 'ABSENT'
if ($null -ne $process) {
    $processState = 'PRESENT'
    if (-not [string]::IsNullOrWhiteSpace([string]$process.CreationDate)) {
        $createdAt = [System.Management.ManagementDateTimeConverter]::ToDateTime($process.CreationDate).ToUniversalTime()
        if ($createdAt -lt $startedAt.UtcDateTime.AddMinutes(-5)) {
            $processState = 'PID_REUSED_OR_STALE'
        }
    }
}

$terminal = Get-TerminalLogEvent -Path $stdoutPath -Count $TailLines
if ($processState -eq 'PRESENT') {
    $derivedState = 'RUNNING'
    $nextAction = 'OBSERVE_ONLY'
} elseif ($processState -eq 'PID_REUSED_OR_STALE') {
    $derivedState = 'ORPHANED_UNKNOWN'
    $nextAction = 'PRESERVE_LOGS_AND_DIAGNOSE_BEFORE_ANY_RECOVERY_ACTION'
} elseif ($null -ne $terminal -and $terminal.state -eq 'COMPLETED') {
    $derivedState = 'COMPLETED_UNVERIFIED'
    $nextAction = 'FRESH_BACKUP_AND_CLONE_ONLY_CONTINUITY_OUTBOX_RECONCILIATION_REQUIRED'
} elseif ($null -ne $terminal -and $terminal.state -eq 'FAILED') {
    $derivedState = 'FAILED_UNVERIFIED'
    $nextAction = 'PRESERVE_LOGS_AND_DIAGNOSE_BEFORE_ANY_RECOVERY_ACTION'
} else {
    $derivedState = 'ORPHANED_UNKNOWN'
    $nextAction = 'PRESERVE_LOGS_AND_DIAGNOSE_BEFORE_ANY_RECOVERY_ACTION'
}

[ordered]@{
    schema_version = 'kairos.offline-recovery-observation.v1'
    observed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    source_status = [ordered]@{
        path = $resolvedStatusPath
        sha256 = Get-Sha256 $resolvedStatusPath
        reported_state = $reportedState
        supervisor_pid = $processId
        started_at_utc = $startedAt.ToString('o')
    }
    supervisor = [ordered]@{
        state = $processState
    }
    terminal_stdout_event = $terminal
    derived_state = $derivedState
    next_action = $nextAction
    source_status_mutated = $false
    permissions = [ordered]@{
        restart_consumers = $false
        source_database_mutation = $false
        outbox_publish = $false
        paper = $false
        live = $false
    }
} | ConvertTo-Json -Depth 6
