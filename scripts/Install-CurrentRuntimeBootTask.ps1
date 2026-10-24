[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Receipt,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ReceiptSha256,
    [Parameter(Mandatory)][string]$Signature,
    [Parameter(Mandatory)][string]$HostAcceptanceReport,
    [string]$Python = 'C:/Users/loval/AppData/Roaming/uv/python/cpython-3.11.15-windows-x86_64-none/python.exe',
    [switch]$Execute
)

# Install only after the new owner has passed native admission. Never rewrite
# an older task, arm trading, restart a resource, or start this task on install.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$windowsPrincipal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $windowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Elevated inventory access is required; no task or runtime was changed'
}
$repo = 'D:\Kairos\kairos-deploy'
$root = 'D:\Kairos\runtime\current-runtime-20261024'
$git = 'C:\Program Files\Git\cmd\git.exe'
$fingerprint = '40AF365C6682B73D056A6A274DBFF6B65BE9F827'

function Assert-RegularFile([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'A regular non-reparse file is required'
    }
    return $item.FullName
}

$receiptPath = Assert-RegularFile $Receipt
$signaturePath = Assert-RegularFile $Signature
$pythonPath = Assert-RegularFile $Python
$pythonwPath = Assert-RegularFile (Join-Path (Split-Path $pythonPath -Parent) 'pythonw.exe')
if ((Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ReceiptSha256) {
    throw 'Receipt digest differs from the admitted value'
}
$receiptValue = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
$owner = [string]$receiptValue.owner
if ($owner -cnotmatch '^[0-9a-f]{32}$' -or
    [IO.Path]::GetFullPath($receiptPath) -cne (Join-Path $root "run-$owner\current-runtime-receipt.json")) {
    throw 'Exact current owner receipt path is required'
}
$head = (& $git -C $repo rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Source identity check failed' }
$origin = (& $git -C $repo rev-parse origin/main).Trim()
$branch = (& $git -C $repo branch --show-current).Trim()
$dirty = @(& $git -C $repo status --porcelain)
$signed = (& $git -C $repo -c 'gpg.program=C:/Program Files/Git/usr/bin/gpg.exe' log -1 '--format=%G? %GF').Trim()
if ($LASTEXITCODE -ne 0 -or $head -cne $origin -or $branch -cne 'main' -or
    $dirty.Count -ne 0 -or $signed -cne "G $fingerprint" -or
    $head -cne [string]$receiptValue.source_profile.deploy_revision) {
    throw 'Clean signed exact current source is required'
}
$boot = Join-Path $repo 'scripts\runtime_epoch_current_boot.py'
$cli = @($boot, '--receipt', $receiptPath, '--receipt-sha256', $ReceiptSha256, '--signature', $signaturePath)
# This invocation is read-only: ALREADY_RUNNING requires fresh native status.
$planBootstrap = "import runpy,sys;sys.path.insert(0,r'$repo/scripts');sys.argv=sys.argv[1:];runpy.run_path(sys.argv[0],run_name='__main__')"
$planText = & $pythonPath -I -B -c $planBootstrap @cli
if ($LASTEXITCODE -ne 0) { throw 'Current owner read-only boot admission failed' }
$plan = $planText | ConvertFrom-Json
if ($plan.state -cne 'ALREADY_RUNNING' -or $plan.owner -cne $owner -or $plan.starts -ne 0) {
    throw 'A currently healthy admitted owner is required before task installation'
}
$taskName = 'Kairos-CurrentRuntime-' + $owner.Substring(0, 12) + '-Boot'
$hostReportPath = [IO.Path]::GetFullPath($HostAcceptanceReport)
if ($hostReportPath -cnotmatch '^D:\\Kairos\\runtime\\prod-runtime-inputs-20261024\\host-acceptance-[0-9a-f]{32}\\acceptance\.report\.json$') {
    throw 'Exact create-only host acceptance report path is required'
}
if (-not $Execute) {
    [ordered]@{state='PLAN_ONLY'; task_name=$taskName; owner=$owner; task_started=$false; trading_started=$false} | ConvertTo-Json -Compress
    return
}
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'Existing task retained unchanged; explicit review is required'
}
$bindingPath = Join-Path (Split-Path $receiptPath -Parent) 'windows-boot-binding.json'
if (Test-Path -LiteralPath $bindingPath) { throw 'Existing boot binding retained unchanged' }
$scriptsPath = Join-Path $repo 'scripts'
$hashes = [ordered]@{}
foreach ($file in Get-ChildItem -LiteralPath $scriptsPath -Filter '*.py' -File | Sort-Object Name) {
    if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Source links are refused' }
    $hashes[$file.Name] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
$binding = [ordered]@{
    schema='kairos.current-runtime-windows-boot.v1'; owner=$owner; deploy_revision=$head
    scripts=$scriptsPath; script_hashes=$hashes; pythonw=$pythonwPath
    pythonw_sha256=(Get-FileHash -LiteralPath $pythonwPath -Algorithm SHA256).Hash.ToLowerInvariant()
    argv=@($cli) + @('--execute'); trading_started=$false
    host_acceptance_report=$hostReportPath; receipt_sha256=$ReceiptSha256
}
$bytes = [Text.UTF8Encoding]::new($false).GetBytes(($binding | ConvertTo-Json -Depth 8 -Compress))
$stream = [IO.File]::Open($bindingPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
$bindingHash = (Get-FileHash -LiteralPath $bindingPath -Algorithm SHA256).Hash.ToLowerInvariant()
# Isolated pythonw shows no console. The scheduler-pinned inline bootstrap
# checks its binding, interpreter and complete sibling-module inventory BEFORE
# importing any workspace code. Unknown/failed latches are owned by the adapter.
$bootstrap = "import hashlib,json,pathlib,runpy,sys;p=pathlib.Path('$($bindingPath.Replace('\','/'))');assert not p.is_symlink() and p.stat().st_size<65536;r=p.read_bytes();assert hashlib.sha256(r).hexdigest()=='$bindingHash';b=json.loads(r);s=pathlib.Path(b['scripts']);w=pathlib.Path(b['pythonw']);assert not w.is_symlink() and hashlib.sha256(w.read_bytes()).hexdigest()==b['pythonw_sha256'];fs=list(s.glob('*.py'));assert {f.name for f in fs}==set(b['script_hashes']);assert all(not f.is_symlink() and hashlib.sha256(f.read_bytes()).hexdigest()==b['script_hashes'][f.name] for f in fs);sys.path.insert(0,str(s));import runtime_epoch_current_boot as guard;guard.require_host_acceptance(pathlib.Path(b['host_acceptance_report']),b['owner'],b['receipt_sha256'],b['deploy_revision']);sys.argv=b['argv'];runpy.run_path(sys.argv[0],run_name='__main__')"
$arguments = '-I -B -c "' + $bootstrap + '"'
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute $pythonwPath -Argument $arguments -WorkingDirectory $repo
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$trigger.Delay = 'PT2M'
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 155) -MultipleInstances IgnoreNew -RestartCount 0 -Hidden
$settings.StartWhenAvailable = $false
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Signed current-source isolated non-trading epoch. No retries, no trading, no legacy resources.' | Out-Null
$registered = Get-ScheduledTask -TaskName $taskName
if ($registered.Actions.Count -ne 1 -or $registered.Actions[0].Execute -cne $pythonwPath -or
    $registered.Actions[0].Arguments -cne $arguments -or $registered.Settings.MultipleInstances -ne 'IgnoreNew' -or
    $registered.Settings.RestartCount -ne 0 -or -not $registered.Settings.Hidden) {
    throw 'Installed task projection differs; do not start it'
}
[ordered]@{state='INSTALLED_NOT_STARTED'; task_name=$taskName; owner=$owner; binding=$bindingPath; binding_sha256=$bindingHash; trading_started=$false} | ConvertTo-Json -Compress
