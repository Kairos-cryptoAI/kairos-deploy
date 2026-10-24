"""Static safety contract; actual task registration needs the admitted owner."""

import unittest
from pathlib import Path


class CurrentRuntimeTaskTests(unittest.TestCase):
    def test_hidden_create_only_nontrading_task(self):
        source = (Path(__file__).resolve().parents[1] / "scripts/Install-CurrentRuntimeBootTask.ps1").read_text()
        for token in (
            "[switch]$Execute", "'PLAN_ONLY'", "'ALREADY_RUNNING'", "[IO.FileMode]::CreateNew",
            "pythonw.exe", "-I -B -c", "hashlib.sha256(r).hexdigest()", "set(b['script_hashes'])",
            "-MultipleInstances IgnoreNew -RestartCount 0 -Hidden", "-RunLevel Limited",
            "'INSTALLED_NOT_STARTED'", "$bindingPath", "--receipt-sha256", "--signature",
        ):
            self.assertIn(token, source)
        for forbidden in ("Start-ScheduledTask", "Unregister-ScheduledTask", "Stop-Process", "docker start", "-Force"):
            # Force is permitted only on the read-only regular-file inspection.
            if forbidden == "-Force":
                self.assertEqual(source.count(forbidden), 1)
            else:
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
