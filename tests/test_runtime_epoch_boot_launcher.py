"""Offline contract tests for the guarded Windows epoch-boot wrapper."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = REPO_ROOT / "scripts" / "Invoke-NonTradingEpochBoot.ps1"
INSTALLER = REPO_ROOT / "scripts" / "Install-NonTradingEpochBootTask.ps1"


class RuntimeEpochBootLauncherTests(unittest.TestCase):
    def test_r2_uses_a_separate_task_and_requires_explicit_matching_generation(
        self,
    ) -> None:
        for path in (LAUNCHER, INSTALLER):
            with self.subTest(script=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertIn(
                    "[ValidateSet('original', 'r2', 'r4', 'r5', 'r6', 'r7', 'r7dns')]", source
                )
                self.assertIn("$Generation = 'original'", source)
                self.assertIn("epoch-boot-r2-20261012", source)
                self.assertIn("kairos-nontrading-runtime-epoch-boot-r2-v1", source)
                self.assertIn("$binding.PSObject.Properties['generation']", source)
                self.assertIn("$Generation -cne 'original'", source)
                self.assertIn("$generationProperty.Value -cne $Generation", source)
        self.assertIn(
            "Kairos-NonTradingEpoch-69893dc7b7c6-Boot-R2", INSTALLER.read_text()
        )
        self.assertIn("'-Generation'", INSTALLER.read_text())
        self.assertIn("'--generation', $Generation", LAUNCHER.read_text())

    def test_r4_uses_its_own_root_scope_and_task_without_changing_default(self):
        for path in (LAUNCHER, INSTALLER):
            with self.subTest(script=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertIn(
                    "[ValidateSet('original', 'r2', 'r4', 'r5', 'r6', 'r7', 'r7dns')]", source
                )
                self.assertIn("$Generation = 'original'", source)
                self.assertIn("epoch-boot-r4-20261012", source)
                self.assertIn("kairos-nontrading-runtime-epoch-boot-r4-v1", source)
                self.assertIn("$binding.PSObject.Properties['generation']", source)
                self.assertIn("$generationProperty.Value -cne $Generation", source)
        installer = INSTALLER.read_text(encoding="utf-8")
        launcher = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("Kairos-NonTradingEpoch-69893dc7b7c6-Boot-R4", installer)
        self.assertIn("'-Generation'", installer)
        self.assertIn("'--generation', $Generation", launcher)
        self.assertIsNone(
            re.search(r"Register-ScheduledTask[^\r\n]*-Force", installer, re.IGNORECASE)
        )

    def test_r5_has_separate_root_scope_and_task_without_changing_default(self):
        for path in (LAUNCHER, INSTALLER):
            with self.subTest(script=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertIn(
                    "[ValidateSet('original', 'r2', 'r4', 'r5', 'r6', 'r7', 'r7dns')]", source
                )
                self.assertIn("$Generation = 'original'", source)
                self.assertIn("epoch-boot-r5-20261012", source)
                self.assertIn("kairos-nontrading-runtime-epoch-boot-r5-v1", source)
                self.assertIn("$generationProperty.Value -cne $Generation", source)
        self.assertIn(
            "Kairos-NonTradingEpoch-69893dc7b7c6-Boot-R5", INSTALLER.read_text()
        )
        self.assertIn("'-Generation'", INSTALLER.read_text())
        self.assertIn("'--generation', $Generation", LAUNCHER.read_text())

    def test_r6_has_distinct_scope_and_task_with_default_and_matching_guards(self):
        for path in (LAUNCHER, INSTALLER):
            with self.subTest(script=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertIn(
                    "[ValidateSet('original', 'r2', 'r4', 'r5', 'r6', 'r7', 'r7dns')]", source
                )
                self.assertIn("$Generation = 'original'", source)
                self.assertIn("epoch-boot-r6-20261012", source)
                self.assertIn("kairos-nontrading-runtime-epoch-boot-r6-v1", source)
                self.assertIn("$generationProperty.Value -cne $Generation", source)
        self.assertIn(
            "Kairos-NonTradingEpoch-69893dc7b7c6-Boot-R6", INSTALLER.read_text()
        )

    def test_r7_uses_accepted_generation_root_scope_and_unique_task(self):
        for path in (LAUNCHER, INSTALLER):
            with self.subTest(script=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertIn(
                    "[ValidateSet('original', 'r2', 'r4', 'r5', 'r6', 'r7', 'r7dns')]",
                    source,
                )
                self.assertIn("$Generation = 'original'", source)
                self.assertIn("epoch-boot-r7-20261013", source)
                self.assertIn("kairos-nontrading-runtime-epoch-boot-r7-v1", source)
                self.assertIn("$binding.PSObject.Properties['generation']", source)
                self.assertIn("$generationProperty.Value -cne $Generation", source)
        installer = INSTALLER.read_text(encoding="utf-8")
        launcher = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("Kairos-NonTradingEpoch-69893dc7b7c6-Boot-R7", installer)
        self.assertIn("'-Generation'", installer)
        self.assertIn("'--generation', $Generation", launcher)
        self.assertIsNone(
            re.search(r"Register-ScheduledTask[^\r\n]*-Force", installer, re.IGNORECASE)
        )

    def test_r7dns_has_a_distinct_opt_in_root_scope_and_task(self):
        for path in (LAUNCHER, INSTALLER):
            with self.subTest(script=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertIn(
                    "[ValidateSet('original', 'r2', 'r4', 'r5', 'r6', 'r7', 'r7dns')]",
                    source,
                )
                self.assertIn("$Generation = 'original'", source)
                self.assertIn("epoch-boot-r7dns-20261015", source)
                self.assertIn("kairos-nontrading-runtime-epoch-boot-r7dns-v1", source)
                self.assertIn("$generationProperty.Value -cne $Generation", source)
        installer = INSTALLER.read_text(encoding="utf-8")
        launcher = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("Kairos-NonTradingEpoch-69893dc7b7c6-Boot-R7-DNS", installer)
        self.assertIn("'-Generation'", installer)
        self.assertIn("'--generation', $Generation", launcher)
        self.assertIsNone(
            re.search(r"Register-ScheduledTask[^\r\n]*-Force", installer, re.IGNORECASE)
        )

    def test_native_job_launches_python_with_exact_quoted_arguments(self) -> None:
        if os.name != "nt":
            self.skipTest("Native suspended Windows process/job requires Windows")
        executable = shutil.which("powershell") or shutil.which("pwsh")
        if executable is None:
            self.skipTest("PowerShell is not installed")
        from scripts import runtime_epoch_boot as boot

        interpreter = boot.PYTHON if boot.PYTHON.is_file() else Path(sys.executable)
        expected = ["space value", 'embedded"quote', "trailing\\path\\\\"]
        probe = "import sys; raise SystemExit(sys.argv[1:] != " + repr(expected) + ")"
        arguments = ["-I", "-c", probe, *expected]
        quoted = ",".join("'" + value.replace("'", "''") + "'" for value in arguments)
        command = (
            "$ErrorActionPreference='Stop'; $tokens=$null; $errors=$null; "
            f"$ast=[Management.Automation.Language.Parser]::ParseFile('{LAUNCHER.as_posix()}',"
            "[ref]$tokens,[ref]$errors); "
            "$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] "
            "-and $node.Name -eq 'ConvertTo-WindowsCommandLineArgument'},$false) "
            "| ForEach-Object {Invoke-Expression $_.Extent.Text}; "
            "$typeBlock=@($ast.EndBlock.Statements | Where-Object "
            "{$_.Extent.Text.StartsWith(\"if (-not ('KairosEpochBootProcessJob'\")}); "
            "if($typeBlock.Count -ne 1){throw 'Exact native type required'}; "
            "Invoke-Expression $typeBlock[0].Extent.Text; "
            f"$application='{interpreter.as_posix()}'; $probeArguments=@({quoted}); "
            "$commandLine=(@((ConvertTo-WindowsCommandLineArgument -Value $application))+"
            "@($probeArguments | ForEach-Object {ConvertTo-WindowsCommandLineArgument -Value $_})) -join ' '; "
            "$launch=$null; try { "
            "$launch=[KairosEpochBootProcessJob]::StartSuspendedInKillOnCloseJob("
            f"$application,$commandLine,'{REPO_ROOT.as_posix()}'); "
            "if(-not [KairosEpochBootProcessJob]::WaitForExit($launch.ProcessHandle,10000)){"
            "[KairosEpochBootProcessJob]::TerminateJob($launch.JobHandle,1);throw 'Bounded native probe timeout'}; "
            "if([KairosEpochBootProcessJob]::ExitCode($launch.ProcessHandle) -ne 0){throw 'Native argv mismatch'}; "
            "Write-Output 'NATIVE_PYTHON_QUOTED_ARGV_PASS' "
            "} finally {if($null -ne $launch){[KairosEpochBootProcessJob]::Close($launch.JobHandle);"
            "[KairosEpochBootProcessJob]::Close($launch.ProcessHandle)}}"
        )
        result = subprocess.run(
            [
                executable,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("NATIVE_PYTHON_QUOTED_ARGV_PASS", result.stdout)

    def test_launcher_is_scoped_to_the_single_authorized_epoch(self) -> None:
        source = LAUNCHER.read_text(encoding="utf-8")

        self.assertIn("69893dc7b7c647f49967387e7efca9fb", source)
        self.assertIn("kairos-nontrading-runtime-epoch-boot-v1", source)
        self.assertIn("D:\\Kairos\\runtime\\epoch-boot-20261011", source)
        self.assertIn("--execute", source)
        self.assertIn("--binding-sha256", source)
        self.assertIn("--boot-id", source)
        self.assertIn("ReadAllText", source)
        self.assertIn("source_files", source)
        self.assertNotIn("Get-Content -LiteralPath $inputPath", source)

    def test_launcher_waits_for_the_existing_engine_and_never_starts_docker(
        self,
    ) -> None:
        source = LAUNCHER.read_text(encoding="utf-8")

        self.assertIn("dockerDesktopLinuxEngine", source)
        self.assertIn("GET /_ping HTTP/1.1", source)
        self.assertIn("HTTP/1\\.[01] 200", source)
        self.assertIn("-cne 'OK'", source)
        self.assertIn("Transfer-Encoding:\\s*chunked", source)
        self.assertIn("responseBudget = 4096", source)
        self.assertIn("BeginRead", source)
        self.assertIn("BeginWrite", source)
        self.assertIn("AsyncWaitHandle.WaitOne", source)
        self.assertNotIn("ReadTimeout =", source)
        self.assertNotIn("WriteTimeout =", source)
        self.assertIn("MaximumDockerWait = [TimeSpan]::FromMinutes(10)", source)
        self.assertIn("FromMinutes(10)", source)
        self.assertIn("Connect($remaining)", source)
        self.assertIn("Docker Desktop Linux engine", source)
        self.assertIn("CreateKillOnClose", source)
        self.assertIn("AssignProcessToJobObject", source)
        self.assertNotIn("Start-Process", source)
        self.assertIsNone(re.search(r"&\s*docker(?:\.exe)?\b", source, re.IGNORECASE))

    def test_installer_is_logon_only_and_does_not_start_or_replace_other_tasks(
        self,
    ) -> None:
        source = INSTALLER.read_text(encoding="utf-8")

        self.assertIn("Kairos-NonTradingEpoch-69893dc7b7c6-Boot", source)
        self.assertIn("New-ScheduledTaskTrigger -AtLogOn", source)
        self.assertIn("PT30S", source)
        self.assertIn("Interactive", source)
        self.assertIn("Limited", source)
        self.assertIn("IgnoreNew", source)
        self.assertIn("PT1H15M", source)
        self.assertIn("RestartCount 0", source)
        self.assertIn("Register-ScheduledTask", source)
        self.assertNotIn("Start-ScheduledTask", source)
        self.assertIsNone(
            re.search(r"Register-ScheduledTask[^\r\n]*-Force", source, re.IGNORECASE)
        )
        self.assertNotIn("-RunLevel Highest", source)

    def test_powershell_scripts_parse_offline(self) -> None:
        executable = shutil.which("pwsh") or shutil.which("powershell")
        if executable is None:
            self.skipTest(
                "PowerShell is not installed; static offline contract checks still run"
            )

        for script in (LAUNCHER, INSTALLER):
            with self.subTest(script=script.name):
                parser_command = (
                    "$tokens = $null; $errors = $null; "
                    f"[System.Management.Automation.Language.Parser]::ParseFile('{script.as_posix()}', "
                    "[ref]$tokens, [ref]$errors) | Out-Null; "
                    "if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Output $_.Message }; exit 1 }"
                )
                result = subprocess.run(
                    [
                        executable,
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        parser_command,
                    ],
                    cwd=REPO_ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                    env={**os.environ, "POWERSHELL_TELEMETRY_OPTOUT": "1"},
                    timeout=15,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_windows_task_user_aliases_normalize_to_sid_but_other_drift_is_refused(
        self,
    ) -> None:
        if os.name != "nt":
            self.skipTest("Windows account SID translation requires Windows")
        executable = shutil.which("powershell") or shutil.which("pwsh")
        if executable is None:
            self.skipTest("PowerShell is not installed")
        command = (
            "$tokens=$null; $errors=$null; "
            f"$ast=[System.Management.Automation.Language.Parser]::ParseFile('{INSTALLER.as_posix()}',"
            "[ref]$tokens,[ref]$errors); "
            "$ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] "
            "-and $node.Name -in @('Test-SameWindowsAccount','Test-EquivalentTask')},$false) "
            "| ForEach-Object {Invoke-Expression $_.Extent.Text}; "
            "$identity=[Security.Principal.WindowsIdentity]::GetCurrent(); "
            "$task=[pscustomobject]@{Actions=@([pscustomobject]@{Execute='powershell.exe';Arguments='safe';WorkingDirectory='repo'}); "
            "Triggers=@([pscustomobject]@{CimClass=[pscustomobject]@{CimClassName='MSFT_TaskLogonTrigger'};UserId=$identity.Name;Delay='PT30S'}); "
            "Principal=[pscustomobject]@{UserId=$identity.Name;LogonType='Interactive';RunLevel='Limited'}; "
            "Settings=[pscustomobject]@{ExecutionTimeLimit='PT1H15M';MultipleInstances='IgnoreNew';RestartCount=0;Hidden=$true;StartWhenAvailable=$false}}; "
            "function Assert-TaskMatch([bool]$Expected) { "
            "if ((Test-EquivalentTask -Task $task -PowerShellPath 'powershell.exe' -Arguments 'safe' "
            "-WorkingDirectory 'repo' -UserName $identity.Name) -ne $Expected) {throw 'Task equivalence mismatch'} }; "
            "$aliases=@($identity.Name,$identity.User.Value,$identity.Name.Split('\\')[-1]); "
            "foreach($alias in $aliases){$task.Principal.UserId=$alias;$task.Triggers[0].UserId=$alias;Assert-TaskMatch $true}; "
            "$task.Principal.UserId='S-1-5-18';Assert-TaskMatch $false;$task.Principal.UserId=$identity.Name; "
            "$task.Principal.RunLevel='Highest';Assert-TaskMatch $false;$task.Principal.RunLevel='Limited'; "
            "$task.Settings.RestartCount=1;Assert-TaskMatch $false;$task.Settings.RestartCount=0; "
            "$task.Settings.MultipleInstances='Parallel';Assert-TaskMatch $false;$task.Settings.MultipleInstances='IgnoreNew'; "
            "$task.Settings.StartWhenAvailable=$true;Assert-TaskMatch $false;$task.Settings.StartWhenAvailable=$false; "
            "$task.Actions[0].Arguments='changed';Assert-TaskMatch $false; "
            "Write-Output 'WINDOWS_TASK_SID_AND_DEFINITION_GUARDS_PASS'"
        )
        result = subprocess.run(
            [
                executable,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("WINDOWS_TASK_SID_AND_DEFINITION_GUARDS_PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
