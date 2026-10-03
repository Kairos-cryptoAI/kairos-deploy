from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import alert_state_gate as gate


class StateGateTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows-only native launcher contract")
    def test_invalid_invocation_owner_never_creates_a_lease(self) -> None:
        with patch.object(gate, "save_new") as save:
            for owner in ("short", "a" * 32, "00000000-0000-4000-8000-000000000000"):
                with self.assertRaises(gate.StateGateError):
                    gate.execute(invocation_owner=owner)
            save.assert_not_called()

    def test_cleanup_has_own_ten_second_cap_and_absolute_window(self) -> None:
        controller = self.controller()
        controller.owned = {}
        controller.volume_intent = False
        controller.cleanup_deadline = 130
        for now, expected in ((1, 11), (125, 130)):
            with patch.object(gate.time, "monotonic", return_value=now):
                controller.cleanup()
            self.assertEqual(controller.deadline, expected)

    def controller(self) -> gate.Native:
        value = gate.Native.__new__(gate.Native)
        value.owner = "a" * 32
        value.volume = "kairos-ops-alerts-state-" + "a" * 16
        value.owned = {"fixture": "sha256:" + "b" * 64}
        value.expected = {
            "fixture": {
                "caps": [],
                "network": "none",
                "user": "10001:10001",
                "entrypoint": ["python"],
                "command": ["/fixture.py", "receiver"],
                "tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=16m"},
                "mounts": [],
            }
        }
        return value

    def view(self) -> dict:
        return {
            "Id": "c" * 64,
            "Name": "/fixture",
            "Image": "sha256:" + "b" * 64,
            "Labels": {gate.LABEL: gate.SCOPE, gate.OWNER: "a" * 32},
            "State": {"Running": True},
            "User": "10001:10001",
            "Entrypoint": ["python"],
            "Command": ["/fixture.py", "receiver"],
            "Mounts": [],
            "Networks": {"none": {}},
            "Host": {
                "Memory": 134_217_728,
                "NanoCpus": 250_000_000,
                "PidsLimit": 64,
                "Privileged": False,
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "CapAdd": None,
                "NetworkMode": "none",
                "IpcMode": "private",
                "SecurityOpt": ["no-new-privileges:true"],
                "PortBindings": {},
                "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=16m"},
                "RestartPolicy": {"Name": "no"},
            },
        }

    def test_plan_only_and_missing_confirmation_never_launch(self) -> None:
        with patch.object(gate, "execute") as native, patch("builtins.print"):
            self.assertEqual(gate.main([]), 0)
            self.assertEqual(gate.main(["--native-synthetic-only"]), 2)
            native.assert_not_called()
        spec = gate.spec()
        for field in (
            "trading_authority",
            "telegram_qualified",
            "exactly_once_delivery",
            "before_checkpoint_crash_qualified",
            "host_loss_qualified",
        ):
            self.assertIs(spec[field], False)

    def test_container_identity_and_capabilities_are_exact(self) -> None:
        controller = self.controller()
        accepted = self.view()
        with patch.object(controller, "inspect", return_value=accepted):
            self.assertEqual(controller.verify("fixture"), accepted)
        for key, bad in (
            ("NetworkMode", "host"),
            ("CapAdd", ["CHOWN"]),
            ("Memory", 0),
            ("PortBindings", {"9093/tcp": []}),
            ("ReadonlyRootfs", False),
            ("Tmpfs", {}),
            ("RestartPolicy", {"Name": "always"}),
            ("PidMode", "host"),
            ("IpcMode", "host"),
            ("Devices", [{"PathOnHost": "/dev/x"}]),
            ("VolumesFrom", ["another"]),
        ):
            changed = copy.deepcopy(accepted)
            changed["Host"][key] = bad
            with (
                patch.object(controller, "inspect", return_value=changed),
                self.assertRaises(gate.StateGateError, msg=key),
            ):
                controller.verify("fixture")
        for key, bad in (
            ("User", "0:0"),
            ("Command", ["other"]),
            ("Labels", {}),
            ("Name", "/another"),
            ("Image", "sha256:" + "d" * 64),
            ("Networks", {"host": {}}),
        ):
            changed = copy.deepcopy(accepted)
            changed[key] = bad
            with (
                patch.object(controller, "inspect", return_value=changed),
                self.assertRaises(gate.StateGateError, msg=key),
            ):
                controller.verify("fixture")

    def test_no_unreviewed_bind_or_extra_mount(self) -> None:
        with self.assertRaises(gate.StateGateError):
            gate.bind(Path("C:/secrets"), "/fixture.py")
        with self.assertRaises(gate.StateGateError):
            gate.bind(Path("D:/Kairos/../outside"), "/fixture.py")
        controller = self.controller()
        changed = self.view()
        changed["Mounts"] = [{"Destination": "/docker.sock"}]
        with (
            patch.object(controller, "inspect", return_value=changed),
            self.assertRaises(gate.StateGateError),
        ):
            controller.verify("fixture")

    def test_source_symlink_is_rejected_before_mount(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("synthetic")
            link = root / "link"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("test host cannot create a symlink")
            with self.assertRaises(gate.StateGateError):
                gate.safe_path(link)

    @unittest.skipUnless(os.name == "nt", "Windows-only native launcher contract")
    def test_initialization_failure_records_unknown_and_retains_lease(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(gate, "PROOF_ROOT", Path(directory)),
        ):
            with patch.object(
                gate,
                "Native",
                side_effect=RuntimeError("synthetic initialization error"),
            ):
                result = gate.execute()
            receipt = json.loads(Path(result["receipt"]).read_text())
            self.assertEqual(receipt["failure_category"], "RuntimeError")
            self.assertIs(receipt["owned_cleanup_verified"], False)
            self.assertTrue((Path(directory) / "execution.lock").exists())
            self.assertEqual(receipt["cli_tree_proofs"], [])

    @unittest.skipUnless(os.name == "nt", "Windows-only native launcher contract")
    def test_interruption_enters_cleanup_without_claiming_pass(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(gate, "PROOF_ROOT", Path(directory)),
        ):
            with patch.object(gate, "Native") as native:
                native.return_value.jobs = []
                native.return_value.run.side_effect = KeyboardInterrupt()
                result = gate.execute()
                native.return_value.cleanup.assert_called_once()
            receipt = json.loads(Path(result["receipt"]).read_text())
            self.assertEqual(receipt["failure_category"], "KeyboardInterrupt")
            self.assertEqual(
                result["result"], "FAILED_NATIVE_SYNTHETIC_NO_DELIVERY_AUTHORITY"
            )
            self.assertFalse((Path(directory) / "execution.lock").exists())

    def test_native_exit_code_and_job_tree_proof_both_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            controller = self.controller()
            controller.directory = Path(directory)
            controller.call_count = 0
            controller.deadline = 100
            controller.jobs = []
            proof = {
                "assigned_before_resume": True,
                "active_owned_processes_after": 0,
                "tree_cleanup_verified": True,
            }
            result = {
                "exit_code": 0,
                "windows_process_tree": proof,
                "failure_category": None,
                "timed_out": False,
                "output_overflow": False,
            }
            (controller.directory / "docker-1.stdout").write_text("synthetic")
            controller.native = lambda *_args, **_kwargs: result
            self.assertEqual(controller.command(["version"]), "synthetic")
            for changed in (
                dict(result, exit_code=2),
                dict(result, timed_out=True),
                dict(result, output_overflow=True),
                dict(result, windows_process_tree={}),
                dict(result, failure_category="unknown"),
            ):
                controller.call_count = 0
                controller.native = lambda *_args, value=changed, **_kwargs: value
                with self.assertRaises(gate.StateGateError):
                    controller.command(["version"])

    def test_checkpoint_receipt_is_never_delivery_qualification(self) -> None:
        self.assertEqual(gate.spec()["maximum_seconds"], 120)
        self.assertEqual(gate.spec()["cleanup_seconds"], 10)
        self.assertNotIn("telegram_bot_token", gate.CONFIG)
        self.assertIn("http://127.0.0.1:19093/receive", gate.CONFIG)


if __name__ == "__main__":
    unittest.main()
