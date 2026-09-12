#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^S-1-5-21-\d+-\d+-\d+-\d+$')]
    [string]$OperatorSid,
    [Parameter(Mandatory)]
    [ValidateSet('D:\Kairos\runtime\paper-gate\secrets', 'D:\Kairos\runtime\shadow-gate\secrets', 'D:\Kairos\kairos-deploy\secrets-paper')]
    [string]$SecretDirectory
)

$ErrorActionPreference = 'Stop'
$root = Get-Item -LiteralPath $SecretDirectory -Force
if (-not $root.PSIsContainer -or $root.FullName -ne $SecretDirectory) { throw 'Unexpected secret directory.' }
$items = @($root) + @(Get-ChildItem -LiteralPath $SecretDirectory -Force -Recurse)
foreach ($item in $items) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refusing a reparse point in the secret tree.' }
    if ($item.FullName -ne $SecretDirectory -and -not $item.FullName.StartsWith($SecretDirectory + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Path escaped the selected directory.' }
}
$before = @($items | ForEach-Object { @{ path = $_.FullName; sddl = (Get-Acl -LiteralPath $_.FullName).Sddl } })
if (-not $PSCmdlet.ShouldProcess($SecretDirectory, 'Restore access to the current operator SID; preserve secret contents and existing administrator access')) { return }
$receiptRoot = 'D:\Kairos\runtime\access-recovery'
New-Item -ItemType Directory -Path $receiptRoot -Force | Out-Null
$receipt = Join-Path $receiptRoot ((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N') + '.json')
[IO.File]::WriteAllText($receipt, (@{ directory = $SecretDirectory; operator_sid = $OperatorSid; previous_acls = $before } | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
# Imported secret files deliberately have protected inheritance. A directory's
# inheritable OI/CI grant does not add an effective ACE to those existing files.
& icacls.exe $SecretDirectory /grant:r ('*' + $OperatorSid + ':F') /T /C /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Secret access restoration failed; inspect the saved ACL receipt.' }
& icacls.exe $SecretDirectory /grant:r ('*' + $OperatorSid + ':(OI)(CI)F') /C /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Secret directory inheritance restoration failed; inspect the saved ACL receipt.' }
& icacls.exe $SecretDirectory /setowner ('*' + $OperatorSid) /T /C /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Secret ownership restoration failed; inspect the saved ACL receipt.' }
Write-Output ('Restored scoped access. Previous ACLs: ' + $receipt)
