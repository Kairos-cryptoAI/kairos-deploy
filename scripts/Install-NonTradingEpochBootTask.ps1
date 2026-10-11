[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BindingPath,

    [Parameter(Mandatory = $true)]
    [string]$BindingSha256,

    [Parameter(Mandatory = $true)]
    [string]$PythonPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ExpectedOwner = '69893dc7b7c647f49967387e7efca9fb'
$ExpectedScope = 'kairos-nontrading-runtime-epoch-boot-v1'
$ExpectedRepo = 'D:\Kairos\kairos-deploy'
$ExpectedRuntimeRoot = 'D:\Kairos\runtime\epoch-boot-20261011'
$ExpectedEntryScript = 'scripts/runtime_epoch_boot.py'
$ExpectedLauncherScript = 'scripts/Invoke-NonTradingEpochBoot.ps1'
$TaskName = 'Kairos-NonTradingEpoch-69893dc7b7c6-Boot'

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [System.IO.File]::OpenRead($Path)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
        $algorithm.Dispose()
    }
}

function Resolve-RepoSourcePath {
    param([Parameter(Mandatory = $true)][string]$RelativePath, [Parameter(Mandatory = $true)][string]$RepoRoot)

    if ([System.IO.Path]::IsPathRooted($RelativePath) -or $RelativePath -match '(^|[\\/])\.\.([\\/]|$)' -or $RelativePath -match '^[A-Za-z]:') {
        throw 'Binding source path is not a safe repository-relative path'
    }
    $candidate = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($RepoRoot, $RelativePath.Replace('/', '\')))
    if (-not $candidate.StartsWith($RepoRoot.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Binding source path escapes the pinned repository'
    }
    $repoPrefix = $RepoRoot.TrimEnd('\') + '\'
    $cursor = $candidate
    while ($cursor.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Pinned source path contains a reparse point'
        }
        $cursor = [System.IO.Path]::GetDirectoryName($cursor)
    }
    return $candidate
}

function Assert-NoSecretLikePropertyNames {
    param([Parameter(Mandatory = $true)]$Value)

    if ($null -eq $Value) { return }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        foreach ($property in $Value.PSObject.Properties) {
            if ($property.Name -match '(?i)(secret|token|password|credential|api.?key|private.?key|signing.?key)') {
                throw 'Binding contains a forbidden secret-like field'
            }
            if ($property.Name -in @('inputs', 'source_files')) {
                # These maps are separately constrained to approved path=>SHA-256 entries.
                continue
            }
            Assert-NoSecretLikePropertyNames -Value $property.Value
        }
    }
    elseif ($Value -is [System.Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            if ([string]$key -match '(?i)(secret|token|password|credential|api.?key|private.?key|signing.?key)') {
                throw 'Binding contains a forbidden secret-like field'
            }
            Assert-NoSecretLikePropertyNames -Value $Value[$key]
        }
    }
    elseif ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        foreach ($entry in $Value) { Assert-NoSecretLikePropertyNames -Value $entry }
    }
}

function Assert-InstallBinding {
    param([string]$Path, [string]$ExpectedHash, [string]$ExpectedPython)

    if ($ExpectedHash -notmatch '^[0-9a-fA-F]{64}$') { throw 'Binding SHA-256 is malformed' }
    if (-not [System.IO.Path]::IsPathRooted($Path) -or -not [System.IO.Path]::IsPathRooted($ExpectedPython)) { throw 'Binding and Python paths must be absolute' }
    $fullBindingPath = [System.IO.Path]::GetFullPath($Path)
    $runtimePrefix = $ExpectedRuntimeRoot.TrimEnd('\') + '\'
    if (-not $fullBindingPath.StartsWith($runtimePrefix, [System.StringComparison]::OrdinalIgnoreCase) -or [System.IO.Path]::GetFileName($fullBindingPath) -cne 'binding.json') {
        throw 'Binding must be the owner-specific runtime binding.json'
    }
    if (-not (Test-Path -LiteralPath $fullBindingPath -PathType Leaf)) { throw 'Immutable binding is unavailable' }
    $bindingItem = Get-Item -LiteralPath $fullBindingPath -Force -ErrorAction Stop
    if (($bindingItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Immutable binding must not be a reparse point' }
    $repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
    if (-not [string]::Equals([System.IO.Path]::GetFullPath($repoRoot).TrimEnd('\'), $ExpectedRepo, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Installer is not running from the pinned Kairos repository'
    }
    if (-not [string]::Equals((Get-Sha256Hex -Path $fullBindingPath), $ExpectedHash, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Binding hash does not match the requested immutable binding'
    }
    $binding = [System.IO.File]::ReadAllText($fullBindingPath, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
    if ($binding.schema_version -ne 1 -or $binding.owner -cne $ExpectedOwner -or $binding.scope -cne $ExpectedScope -or
        -not [string]::Equals([System.IO.Path]::GetFullPath([string]$binding.repo).TrimEnd('\'), $ExpectedRepo, [System.StringComparison]::OrdinalIgnoreCase) -or
        $binding.entry_script -cne $ExpectedEntryScript -or $binding.launcher_script -cne $ExpectedLauncherScript) {
        throw 'Binding identity or scope is not the authorized non-trading epoch'
    }
    if (-not [string]::Equals([System.IO.Path]::GetFullPath([string]$binding.python_path), [System.IO.Path]::GetFullPath($ExpectedPython), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Python path does not match the immutable binding'
    }
    if ($binding.revision -notmatch '^[0-9a-fA-F]{40}$') { throw 'Binding revision is malformed' }
    if ($binding.parent_receipt_sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Parent receipt hash is malformed' }
    foreach ($containerName in @('pg', 'redis', 'serve')) {
        if ([string]$binding.containers.$containerName -notmatch '^[0-9a-fA-F]{64}$') { throw 'Pinned container image digest is malformed' }
    }
    if ($null -eq $binding.inputs -or $binding.inputs -isnot [System.Management.Automation.PSCustomObject]) { throw 'Binding input inventory is missing' }
    foreach ($inputPath in $binding.inputs.PSObject.Properties.Name) {
        if (-not [System.IO.Path]::IsPathRooted($inputPath) -or [string]$binding.inputs.$inputPath -notmatch '^[0-9a-fA-F]{64}$') {
            throw 'Binding input inventory is malformed'
        }
    }
    if ($null -eq $binding.source_files -or $binding.source_files -isnot [System.Management.Automation.PSCustomObject]) { throw 'Binding source_files inventory is missing' }
    $sourceNames = @($binding.source_files.PSObject.Properties.Name)
    if ($sourceNames.Count -lt 2 -or $sourceNames -notcontains $ExpectedEntryScript -or $sourceNames -notcontains $ExpectedLauncherScript) {
        throw 'Binding source_files inventory does not pin the entry point and launcher'
    }
    foreach ($sourceName in $sourceNames) {
        if ($sourceName -notmatch '^scripts/[A-Za-z0-9_./-]+$') { throw 'Binding source path is malformed' }
        $sourceHash = [string]$binding.source_files.$sourceName
        if ($sourceHash -notmatch '^[0-9a-fA-F]{64}$') { throw 'Binding source hash is malformed' }
        $sourcePath = Resolve-RepoSourcePath -RelativePath $sourceName -RepoRoot $repoRoot
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) { throw 'Pinned source file is unavailable' }
        if (-not [string]::Equals((Get-Sha256Hex -Path $sourcePath), $sourceHash, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Pinned source file hash does not match the immutable binding'
        }
    }
    Assert-NoSecretLikePropertyNames -Value $binding
    return [pscustomobject]@{ BindingPath = $fullBindingPath; RepoRoot = $repoRoot }
}

function ConvertTo-WindowsCommandLineArgument {
    param([Parameter(Mandatory = $true)][string]$Value)

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (2 * $slashes + 1)))
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) { [void]$builder.Append(('\' * $slashes)); $slashes = 0 }
        [void]$builder.Append($character)
    }
    if ($slashes -gt 0) { [void]$builder.Append(('\' * (2 * $slashes))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Test-EquivalentTask {
    param($Task, [string]$PowerShellPath, [string]$Arguments, [string]$WorkingDirectory, [string]$UserName)

    if (@($Task.Actions).Count -ne 1 -or @($Task.Triggers).Count -ne 1) { return $false }
    $action = $Task.Actions[0]
    $trigger = $Task.Triggers[0]
    $settings = $Task.Settings
    $principal = $Task.Principal
    return (
        [string]::Equals([string]$action.Execute, $PowerShellPath, [System.StringComparison]::OrdinalIgnoreCase) -and
        [string]$action.Arguments -ceq $Arguments -and [string]$action.WorkingDirectory -ceq $WorkingDirectory -and
        $trigger.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' -and [string]$trigger.UserId -ieq $UserName -and [string]$trigger.Delay -eq 'PT30S' -and
        [string]$principal.UserId -ieq $UserName -and [string]$principal.LogonType -eq 'Interactive' -and [string]$principal.RunLevel -eq 'Limited' -and
        [string]$settings.ExecutionTimeLimit -eq 'PT1H15M' -and [string]$settings.MultipleInstances -eq 'IgnoreNew' -and
        [int]$settings.RestartCount -eq 0 -and [bool]$settings.Hidden -and -not [bool]$settings.StartWhenAvailable
    )
}

try {
    $validated = Assert-InstallBinding -Path $BindingPath -ExpectedHash $BindingSha256 -ExpectedPython $PythonPath
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userName = $identity.Name
    $powerShellPath = (Get-Command -Name powershell.exe -CommandType Application -ErrorAction Stop).Source
    $launcherPath = Join-Path $validated.RepoRoot $ExpectedLauncherScript
    $arguments = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
        '-File', (ConvertTo-WindowsCommandLineArgument -Value $launcherPath),
        '-BindingPath', (ConvertTo-WindowsCommandLineArgument -Value $validated.BindingPath),
        '-BindingSha256', (ConvertTo-WindowsCommandLineArgument -Value $BindingSha256.ToLowerInvariant()),
        '-PythonPath', (ConvertTo-WindowsCommandLineArgument -Value ([System.IO.Path]::GetFullPath($PythonPath)))
    ) -join ' '
    $action = New-ScheduledTaskAction -Execute $powerShellPath -Argument $arguments -WorkingDirectory $validated.RepoRoot
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userName
    $trigger.Delay = 'PT30S'
    $principal = New-ScheduledTaskPrincipal -UserId $userName -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 75) -MultipleInstances IgnoreNew -RestartCount 0 -Hidden

    $existing = $null
    try {
        $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    }
    catch {
        if ($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound) { throw 'Could not safely inspect an existing scheduled task' }
    }
    if ($null -ne $existing) {
        if (Test-EquivalentTask -Task $existing -PowerShellPath $powerShellPath -Arguments $arguments -WorkingDirectory $validated.RepoRoot -UserName $userName) {
            Write-Output 'Kairos non-trading epoch boot task is already installed with the exact guarded definition.'
            exit 0
        }
        throw 'A task with the reserved name already exists and is not the exact authorized definition'
    }

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'Guarded logon launcher for the authorized non-trading runtime epoch.' -ErrorAction Stop | Out-Null
    Write-Output 'Installed the current-user, interactive, non-elevated Kairos non-trading epoch boot task.'
}
catch {
    Write-Error 'Non-trading epoch boot task installation stopped by a fail-closed guard.' -ErrorAction Continue
    exit 1
}
