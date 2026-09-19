$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'Invoke-LongGapRecovery.ps1'), [ref]$tokens, [ref]$errors)
if ($errors) { throw 'Recovery wrapper syntax failed.' }
$node = $ast.Find({ param($item) $item -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -eq 'Assert-RecoveryIsolation' }, $true)
. ([scriptblock]::Create($node.Extent.Text))
Assert-RecoveryIsolation @('redis', 'timescaledb', 'prometheus')
foreach ($service in @('quant-scouts', 'strategy-engine', 'risk-manager', 'execution-engine', 'canary-controller', 'unexpected')) {
    $rejected = $false
    try { Assert-RecoveryIsolation @('redis', 'timescaledb', $service) } catch { $rejected = $true }
    if (-not $rejected) { throw 'An active producer/consumer escaped the offline gate.' }
}
$rejected = $false
try { Assert-RecoveryIsolation @('redis') } catch { $rejected = $true }
if (-not $rejected) { throw 'Missing database escaped preflight.' }

$recoveryScript = Join-Path $PSScriptRoot 'Invoke-LongGapRecovery.ps1'
$temporaryEnv = [System.IO.Path]::GetTempFileName()
$dockerCalls = [System.Collections.Generic.List[psobject]]::new()
$invalidCapRejected = $false
$dockerCallCountBeforeInvalidCap = $null
$expectedRevision = (Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\\paper.sources.lock.json') -Raw | ConvertFrom-Json).
    services.'quant-scouts'.revision
function global:docker {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $dockerCalls.Add([pscustomobject]@{ Arguments = @($Arguments) })
    $global:LASTEXITCODE = 0
    if ($Arguments -contains 'ps') {
        Write-Output 'redis'
        Write-Output 'timescaledb'
        return
    }
    if ($Arguments.Count -ge 2 -and $Arguments[0] -eq 'image' -and $Arguments[1] -eq 'inspect') {
        Write-Output ('{"org.opencontainers.image.revision":"' + $expectedRevision + '"}')
        return
    }
    if ($Arguments -contains 'run') { return }
    throw 'Unexpected Docker command in recovery-wrapper test.'
}
try {
    $endExclusiveMs = ([math]::Floor([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 60000) - 1) * 60000
    & $recoveryScript -EnvFile $temporaryEnv -EndExclusiveMs $endExclusiveMs -MaximumBars 10 -MaximumAppendBars 7 -ExpectedDatabaseName 'kairos_gate'
    $dockerCallCountBeforeInvalidCap = $dockerCalls.Count
    try {
        & $recoveryScript -EnvFile $temporaryEnv -EndExclusiveMs $endExclusiveMs -MaximumBars 6 -MaximumAppendBars 7 -ExpectedDatabaseName 'kairos_gate'
    } catch {
        $invalidCapRejected = $_.Exception.Message -like '*MaximumAppendBars cannot exceed MaximumBars*'
    }
} finally {
    Remove-Item -LiteralPath $temporaryEnv -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath Function:\global:docker -Force -ErrorAction SilentlyContinue
}
$runCommand = ($dockerCalls | Where-Object { $_.Arguments -contains 'run' } | Select-Object -Last 1).Arguments
$nameIndex = [Array]::IndexOf($runCommand, '--expected-database-name')
if ($nameIndex -lt 0 -or $runCommand[$nameIndex + 1] -ne 'kairos_gate') {
    throw 'Recovery wrapper did not forward the exact expected database name.'
}
$capIndex = [Array]::IndexOf($runCommand, '--maximum-append-bars')
if ($capIndex -lt 0 -or $runCommand[$capIndex + 1] -ne '7') {
    throw 'Recovery wrapper did not forward the bounded append limit.'
}
if (-not $invalidCapRejected -or $dockerCalls.Count -ne $dockerCallCountBeforeInvalidCap) {
    throw 'Recovery wrapper accepted an append limit beyond the total bar budget.'
}
Write-Output 'PASS: offline recovery rejects active consumers and missing infrastructure.'
