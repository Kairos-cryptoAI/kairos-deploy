"""Offline R6 boot identity and non-fresh source-pause contracts."""

from __future__ import annotations

import contextlib
import io
import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from scripts import runtime_epoch_boot as boot


def lifecycle(state="RUNNING_NONTRADING"):
    waiting = state == "WAITING_SOURCE_NONTRADING"
    return {
        "state": state,
        "owner": boot.OWNER,
        "watermarks_ms": {symbol: 1_791_830_000_000 for symbol in boot.epoch.SYMBOLS},
        "PAPER_QUALIFIED": False,
        "ALPHA_READY": False,
        "LIVE_READY": False,
        "STRATEGY_POLICY": "REJECT_ALL",
        "pending_outbox": 0,
        "unresolved_inbox": 0,
        "uncompleted_publications": 0,
        "observed_at_utc": datetime.now(UTC).isoformat(),
        "trading_started": False,
        "source_fresh": state == "RUNNING_NONTRADING",
        "source_wait_reason": "OFFICIAL_CLOSED_BAR_FETCH_TIMEOUT" if waiting else None,
        "source_transport": {
            "timeout_rounds": 1 if waiting else 0,
            "recoveries": 0,
            "consecutive_timeout_rounds": 1 if waiting else 0,
        },
    }


class R6BootTests(unittest.TestCase):
    def test_generation_binds_only_accepted_r6_receipt_and_container(self):
        names = (
            "ROOT",
            "SERVE_WORK",
            "SCOPE",
            "GENERATION",
            "RECEIPT_NAME",
            "PARENT_RECEIPT_SHA256",
            "CONTAINERS",
            "LEASE",
        )
        with contextlib.ExitStack() as stack:
            for name in names:
                stack.enter_context(patch.object(boot, name, getattr(boot, name)))
            before = boot.CONTAINERS.copy()
            boot.configure_generation_r6()
            self.assertEqual(boot.GENERATION, "r6")
            self.assertEqual(boot.SCOPE, "kairos-nontrading-runtime-epoch-boot-r6-v1")
            self.assertEqual(boot.CONTAINERS["pg"], before["pg"])
            self.assertEqual(boot.CONTAINERS["redis"], before["redis"])
            self.assertEqual(
                boot.CONTAINERS["serve"],
                "945bb0da557f6a0eb622bd937718259fc506f926077d3c86a63f71e15ad28e59",
            )
            self.assertEqual(
                boot.PARENT_RECEIPT_SHA256,
                "7b794b1f1d938fe10902315941ce4ef93df69d30a581463f84cd095ae7a9cee3",
            )
            self.assertEqual(
                boot.SERVE_WORK.name,
                "read-recovery-r6-feed-cc2bbf275011499a9479b8e029433364",
            )
            self.assertEqual(boot.LEASE, boot.ROOT / "boot.active")

    def test_constructor_uses_only_r6_and_transport06_names(self):
        def initialize(controller, *_args, **_kwargs):
            controller.names = boot.epoch.resource_names(boot.OWNER)

        with (
            patch.object(boot, "GENERATION", "r6"),
            patch.object(boot.epoch.EpochController, "__init__", new=initialize),
        ):
            controller = boot.BootController(boot.OWNER, expected_revision="a" * 40)
        self.assertEqual(
            controller.names["serve"], "kairos-epoch-69893dc7b7c6-serve-r6"
        )
        self.assertTrue(controller.names["restore_pg"].endswith("-transport06"))
        self.assertTrue(controller.names["restore_volume"].endswith("-transport06"))

    def test_known_lifecycle_remains_unmodified_and_never_claims_pause_fresh(self):
        for state in (
            "RUNNING_NONTRADING",
            "WAITING_SOURCE_NONTRADING",
            "CATCHING_UP_NONTRADING",
        ):
            value = lifecycle(state)
            boot.validate_r6_lifecycle_status(value)
            self.assertEqual(value["state"], state)
            self.assertIs(value["source_fresh"], state == "RUNNING_NONTRADING")

    def test_pause_rejects_changed_owner_flags_reason_counters_and_freshness(self):
        changes = (
            ("owner", "wrong"),
            ("trading_started", True),
            ("LIVE_READY", True),
            ("pending_outbox", False),
            ("unresolved_inbox", 1),
            ("source_fresh", True),
            ("source_wait_reason", "INTEGRITY_ERROR"),
            (
                "source_transport",
                {"timeout_rounds": 1, "recoveries": 0, "consecutive_timeout_rounds": 0},
            ),
            ("observed_at_utc", "2020-01-01T00:00:00Z"),
        )
        for key, value in changes:
            with self.subTest(key=key), self.assertRaises(boot.epoch.Rejected):
                boot.validate_r6_lifecycle_status(
                    {**lifecycle("WAITING_SOURCE_NONTRADING"), key: value}
                )
        with self.assertRaises(boot.epoch.Rejected):
            boot.validate_r6_lifecycle_status(lifecycle("FAILED_CLOSED"))

    def test_paused_already_running_path_has_no_docker_mutation_or_restart(self):
        controller = boot.BootController.__new__(boot.BootController)
        controller.proofs = {}
        value = lifecycle("WAITING_SOURCE_NONTRADING")
        resources = {
            "standby": {"left_untouched": True},
            "views": {key: {"state": {"Status": "running"}} for key in boot.CONTAINERS},
        }
        with (
            patch.object(boot, "GENERATION", "r6"),
            patch.object(controller, "validate_resources", return_value=resources),
            patch.object(boot, "read_json", return_value=value),
            patch.object(controller, "docker") as docker,
            patch.object(controller, "phase") as phase,
        ):
            result = controller.run_boot()
        self.assertEqual(result["result"], "ALREADY_RUNNING_SOURCE_PAUSED_NONTRADING")
        self.assertIs(result["status"], value)
        self.assertFalse(result["status"]["source_fresh"])
        docker.assert_not_called()
        phase.assert_not_called()

    def test_explicit_r6_cli_does_not_change_default_generation(self):
        with (
            patch.object(boot, "configure_generation_r6") as configure,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(boot.main([]), 0)
            configure.assert_not_called()
            self.assertEqual(boot.main(["--generation", "r6"]), 0)
            configure.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
