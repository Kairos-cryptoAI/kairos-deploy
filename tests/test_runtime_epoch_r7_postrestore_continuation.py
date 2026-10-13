"""Offline exact post-drain continuation and bounded diagnostics contracts."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts import runtime_epoch_r7_postrestore_continuation as post
from scripts import runtime_epoch_worker as worker
from tests.test_runtime_epoch_clean_queue_recovery import worker_seed


class PostRestoreTests(unittest.TestCase):
    def test_default_plan_does_not_construct_controller(self):
        with (
            mock.patch.object(post, "PostRestoreController") as controller,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(post.main([]), 0)
        controller.assert_not_called()

    def test_all_fixed_input_bindings_are_full_hashes(self):
        for digest in (
            post.FAILURE_SHA256,
            post.DRAIN_SHA256,
            post.STATE_SHA256,
            post.DUMP_SHA256,
            post.CLONE_ID,
            post.UNSTARTED_ID,
        ):
            self.assertRegex(digest, r"\A[0-9a-f]{64}\Z")

    def test_retained_conflict_prevents_any_native_boundary(self):
        with (
            mock.patch.object(post.fresh, "safe", side_effect=lambda path: path),
            mock.patch.object(post.fresh, "sha", return_value="0" * 64),
            self.assertRaises(post.epoch.Rejected),
        ):
            post.retained_evidence()

    def test_transport08_is_fixed_to_owned_boot_restore_in_both_validators(self):
        config = {
            "owner": post.boot.OWNER,
            "database": "kairos_epoch_" + post.boot.OWNER[:12],
            "pg_host": "kairos-epoch-" + post.boot.OWNER[:12] + "-pg",
            "redis_host": "kairos-epoch-" + post.boot.OWNER[:12] + "-redis",
            "admin_password": "a" * 64,
            "restore_host": "kairos-epoch-69893dc7b7c6-restore-transport08",
            "restore_database": "kairos_recovery_69893dc7b7c6_epochrestore",
            "restore_admin_password": "b" * 64,
            "expected_seed": worker_seed(),
        }
        post.epoch.validate_worker_config(config, mode="boot-verify-restore")
        worker.validate_config(config, "boot-verify-restore")
        for invalid in ("primary", "kairos-epoch-69893dc7b7c6-restore-transport09"):
            with self.subTest(host=invalid), self.assertRaises(post.epoch.Rejected):
                post.epoch.validate_worker_config(
                    {**config, "restore_host": invalid}, mode="boot-verify-restore"
                )
            with self.subTest(host=invalid), self.assertRaises(worker.EpochError):
                worker.validate_config(
                    {**config, "restore_host": invalid}, "boot-verify-restore"
                )

    def test_existing_postrestore_claim_cannot_reload_or_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            claim = Path(directory) / "claim"
            claim.mkdir()
            with (
                mock.patch.object(post, "CLAIM", claim),
                mock.patch.object(post.boot, "configure_generation_r6"),
                mock.patch.object(post.boot, "verify_source"),
                mock.patch.object(post, "retained_evidence"),
                mock.patch.object(post, "PostRestoreController") as controller,
                redirect_stdout(io.StringIO()),
            ):
                result = post.main(
                    [
                        "--execute-reviewed-postrestore",
                        "--expected-revision",
                        "a" * 40,
                        "--retained-failure-sha256",
                        post.FAILURE_SHA256,
                    ]
                )
            self.assertEqual(result, 1)
            controller.assert_not_called()

    def test_unstarted_helper_change_blocks_even_clone_stop(self):
        controller = post.PostRestoreController.__new__(post.PostRestoreController)

        def view(identifier, name, image, status):
            return {
                "id": identifier,
                "name": "/" + name,
                "image": image.split("@", 1)[-1],
                "labels": {
                    post.epoch.EPOCH_LABEL: post.boot.OWNER,
                    "com.kairos.runtime-epoch.scope": post.epoch.EPOCH_SCOPE,
                },
                "ports": None,
                "privileged": False,
                "readonly": True,
                "caps": ["ALL"],
                "state": {"Status": status, "StartedAt": "2026-10-13T00:00:00Z"},
            }

        clone = view(
            post.CLONE_ID,
            "kairos-epoch-69893dc7b7c6-restore-transport07",
            post.epoch.PG_IMAGE,
            "running",
        )
        helper = view(
            post.UNSTARTED_ID, post.UNSTARTED_NAME, post.epoch.WORKER_IMAGE, "running"
        )
        with (
            mock.patch.object(
                controller, "inspect_container", side_effect=[clone, helper]
            ),
            mock.patch.object(controller, "docker") as docker,
            self.assertRaises(post.epoch.Rejected),
        ):
            controller.retain_failed_clone_and_helper()
        docker.assert_not_called()

    def test_owned_failed_clone_is_stopped_before_generic_running_admission(self):
        controller = post.PostRestoreController.__new__(post.PostRestoreController)
        ordered = []
        with (
            mock.patch.object(post, "retained_evidence", return_value={}),
            mock.patch.object(post.recovery, "admitted_failure", return_value={}),
            mock.patch.object(post.recovery.clean, "inventory_files", return_value={}),
            mock.patch.object(
                post.recovery.feed.incident, "preserved_inputs", return_value={}
            ),
            mock.patch.object(controller, "assert_legacy_sources_stopped"),
            mock.patch.object(controller, "assert_new_generation_absent"),
            mock.patch.object(
                controller,
                "docker",
                return_value="kairos-epoch-69893dc7b7c6-restore-transport07",
            ),
            mock.patch.object(
                controller,
                "retain_failed_clone_and_helper",
                side_effect=lambda: ordered.append("retain_and_stop"),
            ),
            mock.patch.object(
                controller,
                "validate_resources",
                side_effect=lambda **_kwargs: (
                    ordered.append("generic_admission"),
                    (_ for _ in ()).throw(post.epoch.Rejected("STOP_TEST")),
                ),
            ),
            self.assertRaises(post.epoch.Rejected),
        ):
            controller.run_postrestore()
        self.assertEqual(ordered, ["retain_and_stop", "generic_admission"])

    def test_cli_failure_projection_never_contains_driver_text_or_arguments(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(
                post.fresh,
                "save",
                side_effect=lambda path, value: path.write_text(json.dumps(value)),
            ),
        ):
            native = SimpleNamespace(
                call=mock.Mock(
                    side_effect=RuntimeError("synthetic private driver details")
                ),
                operations=[
                    {
                        "sequence": 12,
                        "exit_code": None,
                        "timed_out": True,
                        "overflow": False,
                        "elapsed_seconds": 20.0,
                        "cli_tree": {"accepted": True},
                    }
                ],
            )
            controller = SimpleNamespace(
                native=native, work=Path(directory), deadline=100.0
            )
            with self.assertRaises(post.epoch.Rejected):
                post.epoch.EpochController.docker(controller, ["private argument"])
            projected = (Path(directory) / "first-cli-failure.json").read_text()
            self.assertNotIn("private driver", projected)
            self.assertNotIn("private argument", projected)
            self.assertTrue(json.loads(projected)["operation"]["timed_out"])


if __name__ == "__main__":
    unittest.main()
