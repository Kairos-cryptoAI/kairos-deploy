[CmdletBinding()]
param(
    [ValidateSet('kairos-paper-gate')][string]$ComposeProject = 'kairos-paper-gate',
    [Parameter(Mandatory)][string]$EnvFile,
    [Parameter(Mandatory)][long]$EndExclusiveMs,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z_][A-Za-z0-9_-]{0,62}$')][string]$ExpectedDatabaseName,
    [ValidateRange(1, 150000)][int]$MaximumBars = 150000,
    [ValidateRange(1, 150000)][int]$MaximumAppendBars,
    [switch]$ValidateOnly
)
$ErrorActionPreference = 'Stop'

if ($PSBoundParameters.ContainsKey('MaximumAppendBars') -and $MaximumAppendBars -gt $MaximumBars) {
    throw 'MaximumAppendBars cannot exceed MaximumBars.'
}

function Assert-RecoveryIsolation([string[]]$RunningServices) {
    $allowed = @('redis', 'timescaledb', 'ops-exporter', 'prometheus', 'grafana')
    if (@($RunningServices | Where-Object { $_ -notin $allowed }).Count) {
        throw 'Stop quant and all trading/strategy consumers before offline bar repair.'
    }
    if ('redis' -notin $RunningServices -or 'timescaledb' -notin $RunningServices) {
        throw 'The isolated Redis and TimescaleDB must be running.'
    }
}

$root = Split-Path $PSScriptRoot -Parent
$composeFile = Join-Path $root 'docker-compose.paper.yml'
$envPath = (Resolve-Path -LiteralPath $EnvFile).Path
$nowMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
if ($EndExclusiveMs -le 0 -or $EndExclusiveMs % 60000 -ne 0 -or $EndExclusiveMs -gt $nowMs - 5000) {
    throw 'Recovery end must be an already closed UTC minute boundary.'
}
$compose = @('compose', '-p', $ComposeProject, '--env-file', $envPath, '-f', $composeFile)
$running = @(& docker @compose ps --status running --services)
if ($LASTEXITCODE -ne 0) { throw 'Could not inspect isolated project services.' }
Assert-RecoveryIsolation $running
$manifest = Get-Content -LiteralPath (Join-Path $root 'paper.sources.lock.json') -Raw | ConvertFrom-Json
$expected = $manifest.services.'quant-scouts'.revision
if ($expected -notmatch '^[0-9a-f]{40}$') { throw 'Missing pinned quant source revision.' }
$imageName = $ComposeProject + '-quant-scouts'
$labels = & docker image inspect $imageName --format '{{json .Config.Labels}}'
if ($LASTEXITCODE -ne 0) { throw 'Build the pinned quant recovery image first.' }
$actual = ($labels | ConvertFrom-Json).'org.opencontainers.image.revision'
if ($actual -ne $expected) { throw 'Quant image does not match the pinned manifest.' }
if ($ValidateOnly) { Write-Output 'Recovery isolation, deadline and pinned image checks passed.'; return }
$name = 'kairos-gap-recovery-' + [Guid]::NewGuid().ToString('N')
Write-Output ('Recovery container: ' + $name)
$recoveryArguments = @(
    '--end-exclusive-ms', $EndExclusiveMs,
    '--maximum-bars', $MaximumBars,
    '--expected-database-name', $ExpectedDatabaseName
)
if ($PSBoundParameters.ContainsKey('MaximumAppendBars')) {
    $recoveryArguments += @('--maximum-append-bars', $MaximumAppendBars)
}
$recoveryArguments += '--offline-consumers-confirmed'
& docker @compose run --rm --no-deps -T --name $name quant-scouts python -m kairos_quant.long_gap_recovery @recoveryArguments
if ($LASTEXITCODE -ne 0) { throw 'Bar recovery failed; preserve logs and resume only after diagnosis.' }
Write-Output 'Bar recovery completed. Validate durable continuity before restarting read-only consumers.'
