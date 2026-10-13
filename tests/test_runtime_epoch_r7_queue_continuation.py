"""Offline guards and call ordering for the reviewed exact ten-row contour."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts import runtime_epoch_r7_queue_continuation as continuation
from scripts import runtime_epoch_worker as worker
from tests.test_runtime_epoch_r7_read_profile import config, state_fixture


class ReviewedContinuationTests(unittest.TestCase):
    def continuation_fixture(self):
        """Mock native boundaries, but execute the actual orchestration order."""
        calls = mock.Mock()
        resources = {
            "views": {
                "serve": {"state": {"Status": "exited"}},
                "pg": {"state": {"Status": "running"}},
                "redis": {"state": {"Status": "running"}},
            },
            "legacy": {"unchanged": True},
        }
        before = state_fixture()
        drain = {
            "state": "PASS_EXACT_R7_INBOX_RECOVERY",
            "completed_message_ids": sorted(continuation.profile.R7_TARGET_IDS),
            "completed_inbox_increment": 10,
            "published_messages": 0,
            "stream_entries_added": 0,
            "publication_receipts_added": 0,
            "pending_deliveries": 0,
            "audit_history_preserved": True,
            "outbox_and_sequences_preserved": True,
            "trading_started": False,
        }
        controller = SimpleNamespace(
            _admin_password="a" * 64,
            expected_revision="b" * 40,
            proofs={},
        )
        methods = {
            "validate_resources": resources,
            "assert_new_generation_absent": None,
            "docker": json.dumps(
                {
                    "Labels": {
                        continuation.epoch.EPOCH_LABEL: continuation.boot.OWNER,
                        "com.kairos.runtime-epoch.scope": continuation.epoch.EPOCH_SCOPE,
                    }
                }
            ),
            "load_private_inputs": {},
            "prepare_reviewed_snapshots": None,
            "r7_state": before,
            "prepare_boot_restore_volume": None,
            "backup_and_verify": "c" * 64,
            "phase": drain,
            "boot_state": {"queue": {"completed_inbox": 8045}},
            "audit_only_tail": ({"tables": {}}, {}),
            "start_and_restart": {},
            "inspect_container": resources["views"]["serve"],
            "assert_legacy_sources_stopped": resources["legacy"],
        }
        for name, result in methods.items():
            method = mock.Mock(return_value=result)
            setattr(controller, name, method)
            calls.attach_mock(method, name)
        patches = (
            mock.patch.object(
                continuation,
                "retained_evidence",
                return_value={
                    "cold_backups": {"pg": {"retained_volume": "owned-cold-pg"}},
                },
            ),
            mock.patch.object(
                continuation.recovery, "admitted_failure", return_value={}
            ),
            mock.patch.object(
                continuation.recovery.clean, "inventory_files", return_value={}
            ),
            mock.patch.object(
                continuation.recovery.feed.incident, "preserved_inputs", return_value={}
            ),
            mock.patch.object(continuation.recovery, "validate_clean_before_start"),
        )
        return controller, calls, patches

    def test_full_restore_and_unchanged_prestate_precede_exact_drain(self):
        from contextlib import ExitStack

        controller, calls, patches = self.continuation_fixture()
        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            result = continuation.ReviewedQueueController.run_continuation(controller)
        ordered = [call[0] for call in calls.mock_calls]
        self.assertLess(ordered.index("backup_and_verify"), ordered.index("phase"))
        prestate_calls = [call for call in calls.mock_calls if call[0] == "r7_state"]
        self.assertEqual(
            [call.args[-1] for call in prestate_calls], ["before", "pre-drain"]
        )
        first_backup = controller.backup_and_verify.call_args_list[0]
        self.assertEqual(first_backup.kwargs["verification_mode"], "r7-verify-restore")
        self.assertEqual(controller.phase.call_args_list[0].args[0], "r7-drain")
        self.assertEqual(result["exact_nonpublishing_drain"]["published_messages"], 0)

    def test_failed_restore_cannot_reach_drain_or_serve(self):
        from contextlib import ExitStack

        controller, _calls, patches = self.continuation_fixture()
        controller.backup_and_verify.side_effect = continuation.epoch.Rejected(
            "RESTORE_FAILED"
        )
        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            with self.assertRaises(continuation.epoch.Rejected):
                continuation.ReviewedQueueController.run_continuation(controller)
        controller.phase.assert_not_called()
        controller.start_and_restart.assert_not_called()

    def test_state_drift_after_restore_cannot_reach_drain(self):
        from contextlib import ExitStack

        controller, _calls, patches = self.continuation_fixture()
        controller.r7_state.side_effect = [state_fixture(), {"different": True}]
        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            with self.assertRaises(continuation.epoch.Rejected):
                continuation.ReviewedQueueController.run_continuation(controller)
        controller.phase.assert_not_called()
        controller.start_and_restart.assert_not_called()

    def test_plan_never_constructs_native_controller(self):
        with (
            mock.patch.object(continuation, "ReviewedQueueController") as controller,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(continuation.main([]), 0)
        controller.assert_not_called()

    def test_retained_hash_conflict_is_terminal(self):
        with (
            mock.patch.object(continuation.fresh, "sha", return_value="0" * 64),
            self.assertRaises(continuation.epoch.Rejected),
        ):
            continuation.retained_evidence()

    def test_worker_and_controller_validate_the_same_exact_profile(self):
        for mode, extra in (
            ("r7-state", {}),
            ("r7-drain", {"expected_state": state_fixture()}),
            (
                "r7-verify-restore",
                {
                    "expected_seed": state_fixture(),
                    "restore_host": continuation.profile.R7_RESTORE_HOST,
                    "restore_database": continuation.profile.R7_RESTORE_DATABASE,
                    "restore_admin_password": "f" * 64,
                },
            ),
        ):
            with self.subTest(mode=mode):
                valid = config(**extra)
                if mode == "r7-verify-restore":
                    for credential in (
                        "producer_password",
                        "consumer_password",
                        "redis_producer_password",
                        "redis_consumer_password",
                    ):
                        valid.pop(credential)
                worker.validate_config(valid, mode)
                continuation.epoch.validate_worker_config(valid, mode=mode)
                with self.assertRaises(worker.EpochError):
                    worker.validate_config({**valid, "pg_host": "legacy-primary"}, mode)
                with self.assertRaises(continuation.epoch.Rejected):
                    continuation.epoch.validate_worker_config(
                        {**valid, "pg_host": "legacy-primary"}, mode=mode
                    )

    def test_existing_review_claim_does_not_read_or_reuse_private_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            claim = Path(directory) / "claim"
            claim.mkdir()
            with (
                mock.patch.object(continuation, "CLAIM", claim),
                mock.patch.object(continuation.boot, "configure_generation_r6"),
                mock.patch.object(continuation.boot, "verify_source"),
                mock.patch.object(continuation, "retained_evidence"),
                mock.patch.object(
                    continuation, "ReviewedQueueController"
                ) as controller,
                redirect_stdout(io.StringIO()),
            ):
                result = continuation.main(
                    [
                        "--execute-reviewed-ten",
                        "--expected-revision",
                        "a" * 40,
                        "--retained-failure-sha256",
                        continuation.FAILURE_SHA256,
                    ]
                )
            self.assertEqual(result, 1)
            controller.assert_not_called()

    def test_wrong_failure_binding_does_not_create_claim(self):
        with (
            mock.patch.object(continuation.boot, "configure_generation_r6"),
            mock.patch.object(continuation.boot, "verify_source"),
            mock.patch.object(continuation, "retained_evidence") as retained,
            redirect_stdout(io.StringIO()),
        ):
            result = continuation.main(
                [
                    "--execute-reviewed-ten",
                    "--expected-revision",
                    "a" * 40,
                    "--retained-failure-sha256",
                    "b" * 64,
                ]
            )
        self.assertEqual(result, 1)
        retained.assert_not_called()


if __name__ == "__main__":
    unittest.main()
