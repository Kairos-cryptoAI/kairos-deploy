"""Offline identity and dispatch contracts for the accepted R7 boot generation."""

from __future__ import annotations

import contextlib
import io
import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from scripts import runtime_epoch_boot as boot


def accepted_status():
    return {
        "state": "RUNNING_NONTRADING",
        "owner": boot.OWNER,
        "watermarks_ms": {symbol: 1_791_894_180_000 for symbol in boot.epoch.SYMBOLS},
        "PAPER_QUALIFIED": False,
        "ALPHA_READY": False,
        "LIVE_READY": False,
        "STRATEGY_POLICY": "REJECT_ALL",
        "pending_outbox": 0,
        "unresolved_inbox": 0,
        "uncompleted_publications": 0,
        "observed_at_utc": datetime.now(UTC).isoformat(),
        "trading_started": False,
        "source_fresh": True,
    }


class R7BootTests(unittest.TestCase):
    def test_generation_binds_only_accepted_r7_receipt_and_container(self):
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
            boot.configure_generation_r7()
            self.assertEqual(boot.GENERATION, "r7")
            self.assertEqual(
                boot.ROOT.as_posix(), "D:/Kairos/runtime/epoch-boot-r7-20261013"
            )
            self.assertEqual(
                boot.SERVE_WORK.as_posix(),
                "D:/Kairos/runtime/runtime-incident-20261013/read-recovery-r7-cb1bc3984d8440aa965af5b928d2b4fa",
            )
            self.assertEqual(boot.SCOPE, "kairos-nontrading-runtime-epoch-boot-r7-v1")
            self.assertEqual(boot.RECEIPT_NAME, "receipt.json")
            self.assertEqual(
                boot.PARENT_RECEIPT_SHA256,
                "03b10208edd5d5d7957ceaf2d38a6d73b7acbef03bfd4f2a87e1fa8ef88cacb0",
            )
            self.assertEqual(boot.CONTAINERS["pg"], before["pg"])
            self.assertEqual(boot.CONTAINERS["redis"], before["redis"])
            self.assertEqual(
                boot.CONTAINERS["serve"],
                "c08f5b667a84febb2dc1639857b44a52208ea29f9836e14c11685d89ccd55ae0",
            )
            self.assertEqual(boot.LEASE, boot.ROOT / "boot.active")

    def test_constructor_uses_only_r7_and_transport08_names(self):
        def initialize(controller, *_args, **_kwargs):
            controller.names = boot.epoch.resource_names(boot.OWNER)

        with (
            patch.object(boot, "GENERATION", "r7"),
            patch.object(boot.epoch.EpochController, "__init__", new=initialize),
        ):
            controller = boot.BootController(boot.OWNER, expected_revision="a" * 40)
        self.assertEqual(
            controller.names["serve"], "kairos-epoch-69893dc7b7c6-serve-r7"
        )
        self.assertTrue(controller.names["restore_pg"].endswith("-transport08"))
        self.assertTrue(controller.names["restore_volume"].endswith("-transport08"))
        self.assertNotIn("transport07", controller.names["restore_pg"])

    def test_r7_lifecycle_requires_the_receipt_proven_source_and_trade_flags(self):
        value = accepted_status()
        self.assertIs(boot.validate_r7_lifecycle_status(value), value)
        for key, invalid in (
            ("trading_started", True),
            ("source_fresh", False),
            ("owner", "wrong-owner"),
        ):
            with self.subTest(key=key), self.assertRaises(boot.epoch.Rejected):
                boot.validate_r7_lifecycle_status({**value, key: invalid})

    def test_r7_accepts_only_the_shared_bounded_source_pause_contract(self):
        waiting = {
            **accepted_status(),
            "state": "WAITING_SOURCE_NONTRADING",
            "source_fresh": False,
            "source_wait_reason": "OFFICIAL_CLOSED_BAR_FETCH_TIMEOUT",
            "source_transport": {
                "timeout_rounds": 1,
                "recoveries": 0,
                "consecutive_timeout_rounds": 1,
            },
        }
        catching_up = {
            **accepted_status(),
            "state": "CATCHING_UP_NONTRADING",
            "source_fresh": False,
            "source_wait_reason": None,
            "source_transport": {
                "timeout_rounds": 1,
                "recoveries": 0,
                "consecutive_timeout_rounds": 0,
            },
        }
        self.assertIs(boot.validate_r7_lifecycle_status(waiting), waiting)
        self.assertIs(boot.validate_r7_lifecycle_status(catching_up), catching_up)
        for key, invalid in (
            ("source_wait_reason", "INTEGRITY_ERROR"),
            ("pending_outbox", 1),
        ):
            with self.subTest(key=key), self.assertRaises(boot.epoch.Rejected):
                boot.validate_r7_lifecycle_status({**waiting, key: invalid})

    def test_already_running_r7_pause_is_reported_without_restart_or_mutation(self):
        controller = boot.BootController.__new__(boot.BootController)
        controller.proofs = {}
        value = {
            **accepted_status(),
            "state": "WAITING_SOURCE_NONTRADING",
            "source_fresh": False,
            "source_wait_reason": "OFFICIAL_CLOSED_BAR_FETCH_TIMEOUT",
            "source_transport": {
                "timeout_rounds": 1,
                "recoveries": 0,
                "consecutive_timeout_rounds": 1,
            },
        }
        resources = {
            "standby": {"left_untouched": True},
            "views": {key: {"state": {"Status": "running"}} for key in boot.CONTAINERS},
        }
        with (
            patch.object(boot, "GENERATION", "r7"),
            patch.object(controller, "validate_resources", return_value=resources),
            patch.object(boot, "read_json", return_value=value),
            patch.object(controller, "docker") as docker,
            patch.object(controller, "phase") as phase,
        ):
            result = controller.run_boot()
        self.assertEqual(result["result"], "ALREADY_RUNNING_SOURCE_PAUSED_NONTRADING")
        self.assertIs(result["status"], value)
        docker.assert_not_called()
        phase.assert_not_called()

    def test_already_running_r7_is_validated_without_restart_or_mutation(self):
        controller = boot.BootController.__new__(boot.BootController)
        controller.proofs = {}
        value = accepted_status()
        resources = {
            "standby": {"left_untouched": True},
            "views": {key: {"state": {"Status": "running"}} for key in boot.CONTAINERS},
        }
        with (
            patch.object(boot, "GENERATION", "r7"),
            patch.object(controller, "validate_resources", return_value=resources),
            patch.object(boot, "read_json", return_value=value),
            patch.object(controller, "docker") as docker,
            patch.object(controller, "phase") as phase,
        ):
            result = controller.run_boot()
        self.assertEqual(result["result"], "ALREADY_RUNNING_NONTRADING")
        self.assertIs(result["status"], value)
        docker.assert_not_called()
        phase.assert_not_called()

    def test_explicit_r7_cli_does_not_change_default_generation(self):
        with (
            patch.object(boot, "configure_generation_r7") as configure,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(boot.main([]), 0)
            configure.assert_not_called()
            self.assertEqual(boot.main(["--generation", "r7"]), 0)
            configure.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
