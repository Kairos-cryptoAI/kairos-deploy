from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import runtime_epoch_successor as successor


class SuccessorAdmissionTests(unittest.TestCase):
    def test_baseline_is_explicit_and_not_production_qualification(self):
        baseline = successor.accepted_baseline_projection()
        self.assertEqual(
            baseline["dump_sha256"],
            "2408db1335dc856122750e4604f14a436184f54a7f4ffab22bc35eb69747a7bc",
        )
        self.assertEqual(baseline["history_rows"], 173_164)
        self.assertEqual(baseline["history_last_open_time_ms"], 1_789_832_580_000)
        self.assertFalse(baseline["trading_started"])
        self.assertEqual(baseline["orders_submitted"], 0)
        self.assertEqual(baseline["paid_calls"], 0)

    def test_source_profile_drift_refuses(self):
        with patch.object(successor.epoch, "DUMP_SHA256", "0" * 64):
            with self.assertRaisesRegex(
                successor.SuccessorRejected, "ACCEPTED_BASELINE_PROFILE_CHANGED"
            ):
                successor.validate_source_pins()

    def test_revision_must_be_exact_hex_commit(self):
        successor.validate_expected_revision("a" * 40)
        for invalid in (None, "", "a" * 39, "g" * 40, "A" * 40):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(
                    successor.SuccessorRejected,
                    "EXACT_SIGNED_DEPLOY_REVISION_REQUIRED",
                ),
            ):
                successor.validate_expected_revision(invalid)

    def test_signed_repo_identity_accepts_current_main_and_requires_clean_refs(self):
        calls = []

        def fake_git(_repo, *args, capture=True):
            calls.append((args, capture))
            if args[0] == "log":
                return "G trusted-fingerprint"
            if args[0] == "rev-parse":
                return "a" * 40
            if args[0] == "branch":
                return "main"
            return ""

        with patch.object(successor, "_run_git", side_effect=fake_git):
            with patch.object(successor.epoch, "fresh") as fresh:
                fresh.SIGNER = "trusted-fingerprint"
                current = successor._verify_repo_identity(
                    Path("repo"), allow_untracked=False
                )
        self.assertEqual(current, "a" * 40)
        self.assertEqual(len(calls), 7)

        def dirty_git(_repo, *args, capture=True):
            if args[0] == "log":
                return "G trusted-fingerprint"
            if args[0] == "rev-parse":
                return "a" * 40
            if args[0] == "branch":
                return "main"
            if args[0] == "status":
                return " M source.py"
            return ""

        with patch.object(successor, "_run_git", side_effect=dirty_git):
            with patch.object(successor.epoch, "fresh") as fresh:
                fresh.SIGNER = "trusted-fingerprint"
                with self.assertRaisesRegex(
                    successor.SuccessorRejected, "CLEAN_SIGNED_MAIN_REQUIRED"
                ):
                    successor._verify_repo_identity(Path("repo"), allow_untracked=False)

    def test_historical_signed_commit_does_not_have_to_be_current_head(self):
        repo = Path("repo")
        current = "a" * 40
        historical = "b" * 40
        with (
            patch.object(
                successor, "_verify_repo_identity", return_value=current
            ) as current_check,
            patch.object(successor, "_verify_signed_commit") as signed,
        ):
            with patch.object(successor, "_run_git", return_value="") as git:
                self.assertEqual(
                    successor.validate_source_repo_identity(
                        repo, historical, allow_untracked=True
                    ),
                    current,
                )
        current_check.assert_called_once_with(repo, allow_untracked=True)
        signed.assert_called_once_with(repo, historical)
        git.assert_called_once_with(
            repo, "cat-file", "-e", historical + "^{commit}", capture=False
        )

    def test_current_main_signature_must_be_trusted(self):
        with patch.object(successor, "_run_git") as git:
            git.side_effect = ["a" * 40, None, "B untrusted-fingerprint"]
            with patch.object(successor.epoch, "fresh") as fresh:
                fresh.SIGNER = "trusted-fingerprint"
                with self.assertRaisesRegex(
                    successor.SuccessorRejected, "TRUSTED_SOURCE_SIGNER_REQUIRED"
                ):
                    successor._verify_repo_identity(Path("repo"), allow_untracked=False)

    def test_old_container_inspection_is_allowlisted_and_identity_pinned(self):
        results = []
        for expected in successor.PRESERVED_OLD_CONTAINERS.values():
            mounts = "".join(
                f"{name},{destination},{str(rw).lower()};"
                for name, destination, rw in expected["mounts"]
            )
            results.append(
                Mock(
                    returncode=0,
                    stdout=(
                        f"{expected['id']}|{expected['image']}|{expected['status']}|"
                        f"{expected['exit_code']}|{mounts}"
                    ).encode("ascii"),
                )
            )
        with patch.object(successor.subprocess, "run", side_effect=results) as run:
            snapshot = successor.capture_preserved_old_containers()
        self.assertEqual(snapshot, successor.PRESERVED_OLD_CONTAINERS)
        for call in run.call_args_list:
            command = call.args[0]
            self.assertIn("--format", command)
            self.assertNotIn("--config", command)
            self.assertNotIn("--env", command)
            self.assertIn('eq .Type "volume"', command[3])

    def test_changed_old_container_id_fails_closed(self):
        expected = next(iter(successor.PRESERVED_OLD_CONTAINERS.values()))
        result = Mock(
            returncode=0,
            stdout=(
                "0" * 64
                + f"|{expected['image']}|{expected['status']}|{expected['exit_code']}|"
            ).encode("ascii"),
        )
        with patch.object(successor.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(
                successor.SuccessorRejected,
                "PRESERVED_OLD_CONTAINER_IDENTITY_CHANGED",
            ):
                successor.capture_preserved_old_containers()

    def test_plan_is_inert_and_does_not_create_runtime_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime-root"
            stdout = io.StringIO()
            with patch.object(successor, "SUCCESSOR_ROOT", root):
                with contextlib.redirect_stdout(stdout):
                    self.assertEqual(successor.main([]), 0)
            plan = json.loads(stdout.getvalue())
            self.assertEqual(plan["result"], "PLAN_ONLY")
            self.assertFalse(plan["writes"])
            self.assertFalse(plan["legacy_or_old_epoch_mutation"])
            self.assertFalse(root.exists())

    def test_new_owner_path_is_separate_and_create_only(self):
        owner = "a" * 32
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "successor"
            with patch.object(successor, "SUCCESSOR_ROOT", root):
                path = successor.private_work_path(owner)
                self.assertEqual(path, root / ("run-" + owner))
                self.assertNotEqual(path, successor.epoch.ACTIVE_LEASE.parent)
                successor.validate_successor_root_is_create_only(root)
                root.mkdir()
                (root / "run-old").mkdir()
                with self.assertRaisesRegex(
                    successor.SuccessorRejected,
                    "SUCCESSOR_ROOT_NOT_EMPTY_NO_BLIND_RETRY",
                ):
                    successor.validate_successor_root_is_create_only(root)

    def test_historical_lease_is_hashed_preserved_and_never_adopted(self):
        with tempfile.TemporaryDirectory() as temporary:
            lease = Path(temporary) / "runtime-epoch.active"
            lease.write_text("historical-owner\n", encoding="ascii")
            snapshot = successor.snapshot_historical_lease(lease)
            self.assertTrue(snapshot["present"])
            self.assertEqual(snapshot["size"], len(lease.read_bytes()))
            successor.validate_historical_lease_unchanged(lease, snapshot)
            self.assertEqual(lease.read_text(encoding="ascii"), "historical-owner\n")
            lease.write_text("different-owner\n", encoding="ascii")
            with self.assertRaisesRegex(
                successor.SuccessorRejected,
                "HISTORICAL_LEASE_CHANGED_DURING_SUCCESSOR",
            ):
                successor.validate_historical_lease_unchanged(lease, snapshot)

    def test_historical_lease_link_is_refused(self):
        with patch.object(Path, "is_symlink", return_value=True):
            with self.assertRaisesRegex(
                successor.SuccessorRejected, "HISTORICAL_LEASE_LINK_REJECTED"
            ):
                successor.snapshot_historical_lease(Path("lease"))

    def test_live_legacy_runtime_process_is_refused_but_own_pid_is_excluded(self):
        successor.validate_legacy_process_inventory(
            [{"pid": 10, "legacy_runtime_controller": True}], own_pid=10
        )
        with self.assertRaisesRegex(
            successor.SuccessorRejected, "LEGACY_RUNTIME_CONTROLLER_PROCESS_ACTIVE"
        ):
            successor.validate_legacy_process_inventory(
                [{"pid": 11, "legacy_runtime_controller": True}], own_pid=10
            )

    def test_process_inventory_output_is_sanitized_and_live_old_controller_refuses(
        self,
    ):
        result = Mock(
            returncode=0,
            stdout=b'{"inventory_completed":true,"matches":[{"pid":123,"legacy_runtime_controller":true}]}',
        )
        with patch.object(successor.subprocess, "run", return_value=result) as run:
            with self.assertRaisesRegex(
                successor.SuccessorRejected,
                "LEGACY_RUNTIME_CONTROLLER_PROCESS_ACTIVE",
            ):
                successor.assert_no_legacy_runtime_processes()
        command = run.call_args.args[0]
        self.assertIn("-Command", command)
        self.assertNotIn("CommandLine", run.return_value.stdout.decode("ascii"))

    def test_process_inventory_requires_explicit_success_before_empty_match_acceptance(
        self,
    ):
        for payload in (
            b'{"matches":[]}',
            b'{"inventory_completed":false,"matches":[]}',
        ):
            with self.subTest(payload=payload):
                result = Mock(returncode=0, stdout=payload)
                with patch.object(successor.subprocess, "run", return_value=result):
                    with self.assertRaisesRegex(
                        successor.SuccessorRejected,
                        "LEGACY_RUNTIME_PROCESS_INVENTORY_MALFORMED",
                    ):
                        successor.assert_no_legacy_runtime_processes()
        result = Mock(returncode=1, stdout=b"")
        with patch.object(successor.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(
                successor.SuccessorRejected, "LEGACY_RUNTIME_PROCESS_INVENTORY_FAILED"
            ):
                successor.assert_no_legacy_runtime_processes()

    def test_process_inventory_uses_terminating_cim_errors_and_excludes_successor_host(
        self,
    ):
        result = Mock(returncode=0, stdout=b'{"inventory_completed":true,"matches":[]}')
        with patch.object(successor.subprocess, "run", return_value=result) as run:
            successor.assert_no_legacy_runtime_processes()
        script = run.call_args.args[0][-1]
        self.assertIn("$ErrorActionPreference = 'Stop'", script)
        self.assertIn("Get-CimInstance Win32_Process -ErrorAction Stop", script)
        self.assertIn("PROCESS_COMMAND_IDENTITY_UNKNOWN", script)
        self.assertIn("(?!successor", script)

    def test_reparse_parent_refuses_before_any_directory_creation(self):
        with patch.object(
            successor.epoch.fresh,
            "safe",
            side_effect=successor.epoch.Rejected("REPARSE_PATH_REJECTED"),
        ):
            with patch.object(Path, "mkdir") as mkdir:
                with self.assertRaisesRegex(
                    successor.epoch.Rejected, "REPARSE_PATH_REJECTED"
                ):
                    successor._create_private_work("a" * 32)
        mkdir.assert_not_called()

    def test_any_running_epoch_container_refuses(self):
        successor.validate_no_active_epoch_names([])
        successor.validate_no_active_epoch_names(["ordinary-service"])
        with self.assertRaisesRegex(
            successor.SuccessorRejected, "EXISTING_RUNTIME_EPOCH_MUST_BE_STOPPED"
        ):
            successor.validate_no_active_epoch_names(["kairos-epoch-old-serve"])


class RetentionTests(unittest.TestCase):
    def test_owned_clone_is_stopped_and_retained_without_remove(self):
        controller = object.__new__(successor.RetainOwnedClonesController)
        owner = "b" * 32
        container, volume = "kairos-epoch-bbbbbbbbbbbb-source", "source-volume"
        controller.owner = owner
        controller.names = {"source_pg": container, "restore_pg": "restore"}
        controller.proofs = {}
        controller.inspect_container = Mock(
            side_effect=[
                {
                    "labels": {
                        successor.epoch.EPOCH_LABEL: owner,
                        "com.kairos.runtime-epoch.scope": successor.epoch.EPOCH_SCOPE,
                    },
                    "state": {"Status": "running"},
                },
                {
                    "labels": {
                        successor.epoch.EPOCH_LABEL: owner,
                        "com.kairos.runtime-epoch.scope": successor.epoch.EPOCH_SCOPE,
                    },
                    "state": {"Status": "exited"},
                },
            ]
        )
        controller.docker = Mock(
            return_value=json.dumps(
                {
                    "Name": volume,
                    "Labels": {
                        successor.epoch.EPOCH_LABEL: owner,
                        "com.kairos.runtime-epoch.scope": successor.epoch.EPOCH_SCOPE,
                    },
                }
            )
        )
        controller.remove_owned_clone(container, volume)
        command_args = [call.args[0] for call in controller.docker.call_args_list]
        self.assertEqual(command_args[-1], ["stop", "--time=15", container])
        self.assertFalse(any("rm" in args for args in command_args))
        self.assertTrue(controller.proofs["source_clone_retained_stopped"])

    def test_wrong_owner_clone_refuses_without_cleanup(self):
        controller = object.__new__(successor.RetainOwnedClonesController)
        controller.owner = "c" * 32
        controller.names = {"source_pg": "source", "restore_pg": "restore"}
        controller.docker = Mock()
        controller.inspect_container = Mock(
            return_value={"labels": {}, "state": {"Status": "exited"}}
        )
        with self.assertRaisesRegex(
            successor.epoch.Rejected, "SUCCESSOR_OWNED_CLONE_REQUIRED"
        ):
            controller.remove_owned_clone("source", "volume")
        controller.docker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
