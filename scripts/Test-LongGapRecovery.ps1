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
Write-Output 'PASS: offline recovery rejects active consumers and missing infrastructure.'
