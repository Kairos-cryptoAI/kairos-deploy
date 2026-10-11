"""Offline contract tests for the guarded Windows epoch-boot wrapper."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = REPO_ROOT / "scripts" / "Invoke-NonTradingEpochBoot.ps1"
INSTALLER = REPO_ROOT / "scripts" / "Install-NonTradingEpochBootTask.ps1"


class RuntimeEpochBootLauncherTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
