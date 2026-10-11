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
$MaximumDockerWait = [TimeSpan]::FromMinutes(10)
$DockerProbeTimeoutMilliseconds = 10000
$MaximumExecution = [TimeSpan]::FromHours(1)

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

function Assert-AbsoluteFilePath {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Description)

    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        throw "$Description must be absolute"
    }
}

function Resolve-RepoSourcePath {
    param([Parameter(Mandatory = $true)][string]$RelativePath, [Parameter(Mandatory = $true)][string]$RepoRoot)

    if ([System.IO.Path]::IsPathRooted($RelativePath) -or $RelativePath -match '(^|[\\/])\.\.([\\/]|$)' -or $RelativePath -match '^[A-Za-z]:') {
        throw 'Binding source path is not a safe repository-relative path'
    }
    $normalized = $RelativePath.Replace('/', '\')
    $candidate = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($RepoRoot, $normalized))
    $repoPrefix = $RepoRoot.TrimEnd('\') + '\'
    if (-not $candidate.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Binding source path escapes the pinned repository'
    }
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

function Assert-CurrentBinding {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedHash,
        [Parameter(Mandatory = $true)][string]$ExpectedPython
    )

    if ($ExpectedHash -notmatch '^[0-9a-fA-F]{64}$') { throw 'Binding SHA-256 is malformed' }
    Assert-AbsoluteFilePath -Path $Path -Description 'Binding path'
    Assert-AbsoluteFilePath -Path $ExpectedPython -Description 'Python path'
    $fullBindingPath = [System.IO.Path]::GetFullPath($Path)
    $runtimePrefix = $ExpectedRuntimeRoot.TrimEnd('\') + '\'
    if (-not $fullBindingPath.StartsWith($runtimePrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
        [System.IO.Path]::GetFileName($fullBindingPath) -cne 'binding.json') {
        throw 'Binding must be the owner-specific runtime binding.json'
    }
    if (-not (Test-Path -LiteralPath $fullBindingPath -PathType Leaf)) { throw 'Immutable binding is unavailable' }
    $bindingItem = Get-Item -LiteralPath $fullBindingPath -Force -ErrorAction Stop
    if (($bindingItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Immutable binding must not be a reparse point' }
    $repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
    if (-not [string]::Equals([System.IO.Path]::GetFullPath($repoRoot).TrimEnd('\'), $ExpectedRepo, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Launcher is not running from the pinned Kairos repository'
    }
    $bindingHash = Get-Sha256Hex -Path $fullBindingPath
    if (-not [string]::Equals($bindingHash, $ExpectedHash, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Binding hash does not match the requested immutable binding'
    }

    $binding = [System.IO.File]::ReadAllText($fullBindingPath, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
    if ($binding.schema_version -ne 1 -or $binding.owner -cne $ExpectedOwner -or $binding.scope -cne $ExpectedScope -or
        -not [string]::Equals([System.IO.Path]::GetFullPath([string]$binding.repo).TrimEnd('\'), $ExpectedRepo, [System.StringComparison]::OrdinalIgnoreCase) -or
        $binding.entry_script -cne $ExpectedEntryScript -or
        $binding.launcher_script -cne $ExpectedLauncherScript) {
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
    if ($null -eq $binding.source_files -or $binding.source_files -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'Binding source_files inventory is missing'
    }
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
    return [pscustomobject]@{ RepoRoot = $repoRoot; EntryPath = (Join-Path $repoRoot $ExpectedEntryScript) }
}

function Get-HostBootUtcTicks {
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    if ($null -eq $operatingSystem.LastBootUpTime) { throw 'Host boot time is unavailable' }
    $bootUtc = ([DateTime]$operatingSystem.LastBootUpTime).ToUniversalTime()
    return [string]$bootUtc.Ticks
}

function Wait-ForDockerDesktopLinuxEngine {
    $deadline = [DateTime]::UtcNow + $MaximumDockerWait
    do {
        $pipe = $null
        try {
            $pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', 'dockerDesktopLinuxEngine', [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
            $probeDeadline = [DateTime]::UtcNow.AddMilliseconds([Math]::Min($DockerProbeTimeoutMilliseconds, ($deadline - [DateTime]::UtcNow).TotalMilliseconds))
            $remaining = [int][Math]::Max(1, ($probeDeadline - [DateTime]::UtcNow).TotalMilliseconds)
            $pipe.Connect($remaining)
            $request = [System.Text.Encoding]::ASCII.GetBytes("GET /_ping HTTP/1.1`r`nHost: docker`r`nConnection: close`r`n`r`n")
            Write-BoundedPipeBytes -Pipe $pipe -Buffer $request -ProbeDeadlineUtc $probeDeadline

            $responseBudget = 4096
            $statusLine = Read-BoundedPipeHttpLine -Pipe $pipe -RemainingBytes ([ref]$responseBudget) -ProbeDeadlineUtc $probeDeadline
            if ($statusLine -notmatch '^HTTP/1\.[01] 200(?:\s+OK)?$') { throw [System.IO.IOException]::new('Docker engine did not return HTTP 200') }
            $contentLength = $null
            $chunked = $false
            while ($true) {
                $headerLine = Read-BoundedPipeHttpLine -Pipe $pipe -RemainingBytes ([ref]$responseBudget) -ProbeDeadlineUtc $probeDeadline
                if ($null -eq $headerLine) { throw [System.IO.IOException]::new('Docker engine returned an incomplete HTTP header') }
                if ($headerLine -eq '') { break }
                if ($headerLine -match '(?i)^Content-Length:\s*(\d+)\s*$') { $contentLength = [int]$Matches[1] }
                if ($headerLine -match '(?i)^Transfer-Encoding:\s*chunked\s*$') { $chunked = $true }
            }
            if ($chunked) {
                $chunkSize = Read-BoundedPipeHttpLine -Pipe $pipe -RemainingBytes ([ref]$responseBudget) -ProbeDeadlineUtc $probeDeadline
                if ($chunkSize -notmatch '^2(?:;[^\r\n]*)?$') { throw [System.IO.IOException]::new('Docker engine readiness chunk size was not the expected bounded size') }
                $body = Read-BoundedPipeBytes -Pipe $pipe -Count 2 -ProbeDeadlineUtc $probeDeadline -RemainingBytes ([ref]$responseBudget)
                if ((Read-BoundedPipeHttpLine -Pipe $pipe -RemainingBytes ([ref]$responseBudget) -ProbeDeadlineUtc $probeDeadline) -cne '') { throw [System.IO.IOException]::new('Docker engine readiness chunk terminator was malformed') }
                if ((Read-BoundedPipeHttpLine -Pipe $pipe -RemainingBytes ([ref]$responseBudget) -ProbeDeadlineUtc $probeDeadline) -cne '0') { throw [System.IO.IOException]::new('Docker engine readiness chunk terminator was missing') }
                if ((Read-BoundedPipeHttpLine -Pipe $pipe -RemainingBytes ([ref]$responseBudget) -ProbeDeadlineUtc $probeDeadline) -cne '') { throw [System.IO.IOException]::new('Docker engine readiness trailer was unexpected') }
            }
            else {
                if ($contentLength -ne 2 -or $responseBudget -lt $contentLength) { throw [System.IO.IOException]::new('Docker engine readiness response exceeded its expected shape') }
                $body = Read-BoundedPipeBytes -Pipe $pipe -Count $contentLength -ProbeDeadlineUtc $probeDeadline -RemainingBytes ([ref]$responseBudget)
            }
            if ([System.Text.Encoding]::ASCII.GetString($body) -cne 'OK') { throw [System.IO.IOException]::new('Docker engine readiness body was not OK') }
            return
        }
        catch [System.TimeoutException] {
            # A single probe is bounded. Continue only while the total startup budget remains.
        }
        catch [System.IO.IOException] {
            # Docker Desktop may be restarting its engine; no settings or services are changed here.
        }
        catch [System.UnauthorizedAccessException] {
            throw 'Docker Desktop Linux engine pipe is not accessible to the current user'
        }
        finally {
            if ($null -ne $pipe) { $pipe.Dispose() }
        }
        $remainingSeconds = ($deadline - [DateTime]::UtcNow).TotalSeconds
        if ($remainingSeconds -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Min(5000, [Math]::Ceiling($remainingSeconds * 1000))) }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Docker Desktop Linux engine did not become available within the bounded startup window'
}

function Get-RemainingProbeMilliseconds {
    param([Parameter(Mandatory = $true)][DateTime]$ProbeDeadlineUtc)

    $remaining = [int][Math]::Floor(($ProbeDeadlineUtc - [DateTime]::UtcNow).TotalMilliseconds)
    if ($remaining -le 0) { throw [System.TimeoutException]::new('Docker engine HTTP probe timed out') }
    return $remaining
}

function Read-BoundedPipeBytes {
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Pipe,
        [Parameter(Mandatory = $true)][ValidateRange(1, 4096)][int]$Count,
        [Parameter(Mandatory = $true)][DateTime]$ProbeDeadlineUtc,
        [ref]$RemainingBytes
    )

    if ($null -ne $RemainingBytes -and $Count -gt $RemainingBytes.Value) { throw [System.IO.IOException]::new('Docker engine response exceeded the bounded byte budget') }
    $buffer = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $operation = $Pipe.BeginRead($buffer, $offset, $Count - $offset, $null, $null)
        try {
            $remaining = Get-RemainingProbeMilliseconds -ProbeDeadlineUtc $ProbeDeadlineUtc
            if (-not $operation.AsyncWaitHandle.WaitOne($remaining)) {
                $Pipe.Dispose()
                throw [System.TimeoutException]::new('Docker engine HTTP read timed out')
            }
            $read = $Pipe.EndRead($operation)
            if ($read -le 0) { throw [System.IO.IOException]::new('Docker engine returned an incomplete HTTP response') }
            if ($null -ne $RemainingBytes) {
                if ($read -gt $RemainingBytes.Value) { throw [System.IO.IOException]::new('Docker engine response exceeded the bounded byte budget') }
                $RemainingBytes.Value = [int]$RemainingBytes.Value - $read
            }
            $offset += $read
        }
        finally {
            $operation.AsyncWaitHandle.Dispose()
        }
    }
    return ,$buffer
}

function Write-BoundedPipeBytes {
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Pipe,
        [Parameter(Mandatory = $true)][byte[]]$Buffer,
        [Parameter(Mandatory = $true)][DateTime]$ProbeDeadlineUtc
    )

    $operation = $Pipe.BeginWrite($Buffer, 0, $Buffer.Length, $null, $null)
    try {
        $remaining = Get-RemainingProbeMilliseconds -ProbeDeadlineUtc $ProbeDeadlineUtc
        if (-not $operation.AsyncWaitHandle.WaitOne($remaining)) {
            $Pipe.Dispose()
            throw [System.TimeoutException]::new('Docker engine HTTP write timed out')
        }
        $Pipe.EndWrite($operation)
    }
    finally {
        $operation.AsyncWaitHandle.Dispose()
    }
}

function Read-BoundedPipeHttpLine {
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Pipe,
        [Parameter(Mandatory = $true)][ref]$RemainingBytes,
        [Parameter(Mandatory = $true)][DateTime]$ProbeDeadlineUtc
    )

    $line = [System.Text.StringBuilder]::new()
    while ($RemainingBytes.Value -gt 0) {
        $byte = Read-BoundedPipeBytes -Pipe $Pipe -Count 1 -ProbeDeadlineUtc $ProbeDeadlineUtc -RemainingBytes $RemainingBytes
        $value = [int]$byte[0]
        if ($value -eq 10) { return $line.ToString() }
        if ($value -ne 13) { [void]$line.Append([char]$value) }
    }
    throw [System.IO.IOException]::new('Docker engine HTTP response exceeded the bounded header size')
}

function ConvertTo-WindowsCommandLineArgument {
    param([Parameter(Mandatory = $true)][string]$Value)

    # Quote according to the Windows C runtime rules used by native programs.
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $slashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (2 * $slashes + 1)))
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) {
            [void]$builder.Append(('\' * $slashes))
            $slashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($slashes -gt 0) { [void]$builder.Append(('\' * (2 * $slashes))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

if (-not ('KairosEpochBootProcessJob' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class KairosEpochBootProcessJob {
    public sealed class LaunchResult {
        public IntPtr ProcessHandle;
        public IntPtr JobHandle;
        public uint ProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes {
        public int Length;
        public IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo {
        public int Size;
        public string Reserved;
        public string Desktop;
        public string Title;
        public uint X;
        public uint Y;
        public uint XSize;
        public uint YSize;
        public uint XCountChars;
        public uint YCountChars;
        public uint FillAttribute;
        public uint Flags;
        public short ShowWindow;
        public short Reserved2Length;
        public IntPtr Reserved2;
        public IntPtr StdInput;
        public IntPtr StdOutput;
        public IntPtr StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation {
        public IntPtr Process;
        public IntPtr Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimitInformation {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimitInformation {
        public BasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int informationClass, ref ExtendedLimitInformation information, uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFile(string name, uint access, uint share, ref SecurityAttributes attributes, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateProcessW")]
    private static extern bool CreateProcess(string application, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string currentDirectory, ref StartupInfo startup, out ProcessInformation process);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private static IntPtr CreateKillOnClose() {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        ExtendedLimitInformation information = new ExtendedLimitInformation();
        information.BasicLimitInformation.LimitFlags = 0x00002000;
        if (!SetInformationJobObject(job, 9, ref information, (uint)Marshal.SizeOf(typeof(ExtendedLimitInformation)))) {
            int error = Marshal.GetLastWin32Error();
            CloseHandle(job);
            throw new Win32Exception(error);
        }
        return job;
    }

    public static LaunchResult StartSuspendedInKillOnCloseJob(string application, string commandLine, string workingDirectory) {
        IntPtr job = CreateKillOnClose();
        IntPtr nulInput = IntPtr.Zero;
        IntPtr nulOutput = IntPtr.Zero;
        ProcessInformation process = new ProcessInformation();
        bool created = false;
        try {
            SecurityAttributes security = new SecurityAttributes();
            security.Length = Marshal.SizeOf(typeof(SecurityAttributes));
            security.InheritHandle = true;
            nulInput = CreateFile("NUL", 0x80000000, 3, ref security, 3, 0x80, IntPtr.Zero);
            nulOutput = CreateFile("NUL", 0x40000000, 3, ref security, 3, 0x80, IntPtr.Zero);
            if (nulInput == new IntPtr(-1) || nulOutput == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
            StartupInfo startup = new StartupInfo();
            startup.Size = Marshal.SizeOf(typeof(StartupInfo));
            startup.Flags = 0x00000100;
            startup.StdInput = nulInput;
            startup.StdOutput = nulOutput;
            startup.StdError = nulOutput;
            if (!CreateProcess(application, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero, true, 0x00000004 | 0x08000000, IntPtr.Zero, workingDirectory, ref startup, out process)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            created = true;
            CloseHandle(nulInput); nulInput = IntPtr.Zero;
            CloseHandle(nulOutput); nulOutput = IntPtr.Zero;
            if (!AssignProcessToJobObject(job, process.Process)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (ResumeThread(process.Thread) == 0xFFFFFFFF) throw new Win32Exception(Marshal.GetLastWin32Error());
            CloseHandle(process.Thread); process.Thread = IntPtr.Zero;
            return new LaunchResult { ProcessHandle = process.Process, JobHandle = job, ProcessId = process.ProcessId };
        }
        catch {
            if (created) TerminateProcess(process.Process, 1);
            if (process.Thread != IntPtr.Zero) CloseHandle(process.Thread);
            if (process.Process != IntPtr.Zero) CloseHandle(process.Process);
            CloseHandle(job);
            throw;
        }
        finally {
            if (nulInput != IntPtr.Zero && nulInput != new IntPtr(-1)) CloseHandle(nulInput);
            if (nulOutput != IntPtr.Zero && nulOutput != new IntPtr(-1)) CloseHandle(nulOutput);
        }
    }

    public static bool WaitForExit(IntPtr process, uint milliseconds) {
        uint result = WaitForSingleObject(process, milliseconds);
        if (result == 0) return true;
        if (result == 258) return false;
        throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public static uint ExitCode(IntPtr process) {
        uint code;
        if (!GetExitCodeProcess(process, out code)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return code;
    }

    public static void TerminateJob(IntPtr job, uint exitCode) {
        if (job != IntPtr.Zero && !TerminateJobObject(job, exitCode)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public static void Close(IntPtr handle) {
        if (handle != IntPtr.Zero) CloseHandle(handle);
    }
}
'@ -ErrorAction Stop
}

function Invoke-BoundedPython {
    param(
        [Parameter(Mandatory = $true)][string]$Interpreter,
        [Parameter(Mandatory = $true)][string]$Entry,
        [Parameter(Mandatory = $true)][string]$Binding,
        [Parameter(Mandatory = $true)][string]$BindingHash,
        [Parameter(Mandatory = $true)][string]$HostBootId,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    $arguments = @(
        $Entry,
        '--execute',
        '--binding', $Binding,
        '--binding-sha256', $BindingHash,
        '--boot-id', $HostBootId
    )
    $commandLine = (@((ConvertTo-WindowsCommandLineArgument -Value $Interpreter)) + @($arguments | ForEach-Object { ConvertTo-WindowsCommandLineArgument -Value ([string]$_) })) -join ' '
    $launch = $null
    try {
        # CreateProcess starts suspended; assignment happens before Python can import or spawn children.
        $launch = [KairosEpochBootProcessJob]::StartSuspendedInKillOnCloseJob($Interpreter, $commandLine, $WorkingDirectory)
        if (-not [KairosEpochBootProcessJob]::WaitForExit($launch.ProcessHandle, [uint32]$MaximumExecution.TotalMilliseconds)) {
            [KairosEpochBootProcessJob]::TerminateJob($launch.JobHandle, 1)
            [void][KairosEpochBootProcessJob]::WaitForExit($launch.ProcessHandle, 5000)
            throw 'Epoch boot exceeded its finite one-hour execution limit'
        }
        if ([KairosEpochBootProcessJob]::ExitCode($launch.ProcessHandle) -ne 0) { throw 'Pinned epoch boot entry point returned a failure status' }
    }
    finally {
        if ($null -ne $launch) {
            [KairosEpochBootProcessJob]::Close($launch.JobHandle)
            [KairosEpochBootProcessJob]::Close($launch.ProcessHandle)
        }
    }
}

try {
    $validated = Assert-CurrentBinding -Path $BindingPath -ExpectedHash $BindingSha256 -ExpectedPython $PythonPath
    $bootId = Get-HostBootUtcTicks
    if ($bootId -notmatch '^\d+$') { throw 'Host boot identifier is malformed' }
    Wait-ForDockerDesktopLinuxEngine

    Invoke-BoundedPython -Interpreter $PythonPath -Entry $validated.EntryPath -Binding ([System.IO.Path]::GetFullPath($BindingPath)) `
        -BindingHash $BindingSha256.ToLowerInvariant() -HostBootId $bootId -WorkingDirectory $validated.RepoRoot
}
catch {
    # Avoid emitting native output, binding contents, or exception details into task history.
    Write-Error 'Non-trading epoch boot stopped by a fail-closed guard.' -ErrorAction Continue
    exit 1
}
