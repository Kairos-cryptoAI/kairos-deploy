$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$observer = Join-Path $PSScriptRoot 'Get-OfflineRecoveryObservation.ps1'
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('kairos-offline-recovery-observation-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null

function Write-Fixture([string]$Name, [string[]]$LogLines) {
    $stdout = Join-Path $temporaryRoot "$Name.out.log"
    $status = Join-Path $temporaryRoot "$Name.status.json"
    [System.IO.File]::WriteAllLines($stdout, $LogLines, [System.Text.UTF8Encoding]::new($false))
    $document = [ordered]@{
        schema_version = 1
        process_id = 2147480000
        started_at_utc = '2026-09-19T15:50:51.6731501Z'
        state = 'RUNNING'
        stdout = $stdout
        stderr = (Join-Path $temporaryRoot "$Name.err.log")
    } | ConvertTo-Json
    [System.IO.File]::WriteAllText($status, $document, [System.Text.UTF8Encoding]::new($false))
    return $status
}

try {
    $complete = Write-Fixture -Name 'complete' -LogLines @(
        '{"state":"PROGRESS","observed_at_utc":"2026-09-19T16:55:27Z"}',
        '{"state":"COMPLETED","observed_at_utc":"2026-09-19T16:55:32Z"}'
    )
    $before = (Get-FileHash -Algorithm SHA256 -LiteralPath $complete).Hash
    $stdoutBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $temporaryRoot 'complete.out.log')).Hash
    $completeResult = (& $observer -StatusPath $complete | ConvertFrom-Json)
    $after = (Get-FileHash -Algorithm SHA256 -LiteralPath $complete).Hash
    $completeObservedAt = ([DateTimeOffset]$completeResult.terminal_stdout_event.observed_at_utc).
        ToUniversalTime().ToString('o')
    if ($completeResult.derived_state -ne 'COMPLETED_UNVERIFIED' -or
        $completeResult.next_action -ne 'FRESH_BACKUP_AND_CLONE_ONLY_CONTINUITY_OUTBOX_RECONCILIATION_REQUIRED' -or
        $completeResult.source_status_mutated -ne $false -or
        $completeResult.permissions.restart_consumers -ne $false -or
        $completeResult.terminal_stdout_event.timestamp_valid -ne $true -or
        $completeObservedAt -ne '2026-09-19T16:55:32.0000000+00:00' -or
        $completeResult.source_stdout.stable_during_observation -ne $true -or
        $completeResult.source_stdout.sha256 -ne $stdoutBefore -or
        $before -ne $after) {
        throw 'Completed stale-status observation did not remain fail-closed and read-only.'
    }

    $failed = Write-Fixture -Name 'failed' -LogLines @(
        '{"state":"FAILED","observed_at_utc":"2026-09-19T16:55:32Z"}'
    )
    $failedResult = (& $observer -StatusPath $failed | ConvertFrom-Json)
    if ($failedResult.derived_state -ne 'FAILED_UNVERIFIED' -or
        $failedResult.permissions.source_database_mutation -ne $false) {
        throw 'Failed stale-status observation did not remain fail-closed.'
    }

    $unknown = Write-Fixture -Name 'unknown' -LogLines @('not a JSON event')
    $unknownResult = (& $observer -StatusPath $unknown | ConvertFrom-Json)
    if ($unknownResult.derived_state -ne 'ORPHANED_UNKNOWN' -or
        $unknownResult.terminal_stdout_event -ne $null) {
        throw 'Missing terminal event was not classified as unknown.'
    }

    $malformedTerminal = Write-Fixture -Name 'malformed-terminal' -LogLines @(
        '{"state":"COMPLETED","observed_at_utc":"not-a-timestamp"}'
    )
    $malformedTerminalResult = (& $observer -StatusPath $malformedTerminal | ConvertFrom-Json)
    if ($malformedTerminalResult.derived_state -ne 'ORPHANED_UNKNOWN' -or
        $malformedTerminalResult.terminal_stdout_event.timestamp_valid -ne $false -or
        $malformedTerminalResult.permissions.restart_consumers -ne $false) {
        throw 'Malformed terminal timestamp escaped the fail-closed observer.'
    }

    $invalid = Join-Path $temporaryRoot 'invalid.status.json'
    [System.IO.File]::WriteAllText($invalid, '{"state":"RUNNING"}', [System.Text.UTF8Encoding]::new($false))
    $rejected = $false
    try { & $observer -StatusPath $invalid | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Malformed status was accepted.' }

    Write-Output 'PASS: offline recovery observation is read-only and fail-closed.'
} finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}
