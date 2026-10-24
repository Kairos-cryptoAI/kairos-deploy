"""Synthetic diagnostics, no process inventory or runtime access."""
import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

from scripts import runtime_epoch_successor as successor


class InventoryDiagnosticTests(unittest.TestCase):
    def test_unknown_identity_refuses_with_only_pid_and_no_retry(self):
        result = SimpleNamespace(returncode=1, stdout=b"", stderr=(
            b"Exception: PROCESS_COMMAND_IDENTITY_UNKNOWN:12345:python.exe"
        ))
        with mock.patch.object(successor.subprocess, "run", return_value=result) as run, \
             self.assertRaisesRegex(successor.SuccessorRejected, "IDENTITY_UNKNOWN_PID_12345$"):
            successor.assert_no_legacy_runtime_processes()
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.PIPE)
        self.assertEqual(run.call_args.kwargs["timeout"], 30)

    def test_provider_failure_does_not_expose_stderr(self):
        result = SimpleNamespace(returncode=1, stdout=b"", stderr=b"synthetic-private-details")
        with mock.patch.object(successor.subprocess, "run", return_value=result), \
             self.assertRaisesRegex(successor.SuccessorRejected, "^LEGACY_RUNTIME_PROCESS_INVENTORY_FAILED$"):
            successor.assert_no_legacy_runtime_processes()

    def test_bounded_outputs_and_timeout_remain_fail_closed(self):
        result = SimpleNamespace(returncode=0, stdout=b"x" * 65537, stderr=b"")
        with mock.patch.object(successor.subprocess, "run", return_value=result), \
             self.assertRaisesRegex(successor.SuccessorRejected, "INVENTORY_OVERSIZE$"):
            successor.assert_no_legacy_runtime_processes()
        with mock.patch.object(successor.subprocess, "run", side_effect=subprocess.TimeoutExpired("synthetic", 30)), \
             self.assertRaisesRegex(successor.SuccessorRejected, "INVENTORY_TIMEOUT$"):
            successor.assert_no_legacy_runtime_processes()


if __name__ == "__main__":
    unittest.main()
