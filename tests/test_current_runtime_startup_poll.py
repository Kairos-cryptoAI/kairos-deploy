"""Synthetic CURRENT restart polling, never runtime or database operations."""
import copy
import itertools
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import runtime_epoch_current as current
from scripts import runtime_epoch_current_boot as boot

OWNER = "a" * 32
IDENTIFIER = "b" * 64


class CurrentStartupPollingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.path = self.work / "output-serve" / "status.json"
        self.path.parent.mkdir()
        self.now = datetime.now(UTC) - timedelta(seconds=4)
        self.first = {
            "owner": OWNER, "state": "RUNNING_NONTRADING",
            "schema_profile": "current-controlled-v1", "schema_migration_count": 19,
            "schema_public_table_count": 33, "trading_started": False,
            "PAPER_QUALIFIED": False, "ALPHA_READY": False, "LIVE_READY": False,
            "STRATEGY_POLICY": "REJECT_ALL", "pending_outbox": 0,
            "unresolved_inbox": 0, "uncompleted_publications": 0, "cycles": 1,
            "watermarks_ms": dict.fromkeys(current.epoch.SYMBOLS, 1_800_000_000_000),
            "observed_at_utc": self.now.isoformat(),
        }

    def status(self, seconds=1, **changes):
        return {**copy.deepcopy(self.first),
                "observed_at_utc": (self.now + timedelta(seconds=seconds)).isoformat(), **changes}

    def advanced(self):
        return self.status(4, watermarks_ms={s: n + 60000 for s, n in self.first["watermarks_ms"].items()})

    def poll(self, statuses, *, running_check=None):
        values = iter(statuses)
        self.path.write_text(json.dumps(next(values)), encoding="utf-8")

        def step(_seconds):
            value = next(values, None)
            if value is not None:
                self.path.write_text(json.dumps(value), encoding="utf-8")

        with (patch.object(current.time, "sleep", side_effect=step),
              patch.object(current.time, "monotonic", side_effect=itertools.count())):
            return current.wait_for_advanced_status(self.path, OWNER, self.first, deadline=8,
                                                   running_check=running_check or Mock())

    def test_pending_and_zero_bar_cycles_wait_for_real_running_progress(self):
        catching = self.status(1, state="CATCHING_UP_NONTRADING", pending_outbox=7)
        waiting = self.status(2, state="WAITING_SOURCE_NONTRADING")
        zero_bar = self.status(3)
        check = Mock()
        advanced = self.advanced()
        self.assertEqual(self.poll([catching, waiting, zero_bar, advanced], running_check=check), advanced)
        self.assertEqual(check.call_count, 4)

    def test_pending_never_counts_as_healthy_or_retries_forever(self):
        with self.assertRaisesRegex(current.CurrentEpochRejected, "FRESH_ADVANCED_STATUS"):
            self.poll([self.status(state="CATCHING_UP_NONTRADING")])

    def test_pending_wrong_owner_schema_authority_counter_or_clock_refuses(self):
        for changes in (
            {"owner": "c" * 32}, {"schema_public_table_count": 32}, {"LIVE_READY": True},
            {"pending_outbox": -1}, {"cycles": False}, {"watermarks_ms": {}},
            {"observed_at_utc": (self.now - timedelta(hours=1)).isoformat()},
        ):
            with self.subTest(changes=changes), self.assertRaises(current.CurrentEpochRejected):
                self.poll([self.status(state="CATCHING_UP_NONTRADING", **changes)])

    def test_failed_or_unknown_state_still_refuses_immediately(self):
        for state in ("FAILED_CLOSED", "UNKNOWN"):
            with self.subTest(state=state), self.assertRaises(current.epoch.Rejected):
                self.poll([self.status(state=state)])

    def test_running_with_undrained_queue_is_not_startup_success(self):
        with self.assertRaises(current.epoch.Rejected):
            self.poll([self.status(pending_outbox=1)])

    def test_stopped_or_substituted_container_is_not_tolerated(self):
        check = Mock(side_effect=current.CurrentEpochRejected("EXACT_OWNER_STOPPED"))
        with self.assertRaisesRegex(current.CurrentEpochRejected, "EXACT_OWNER_STOPPED"):
            self.poll([self.status(state="CATCHING_UP_NONTRADING")], running_check=check)

    def test_current_restart_uses_exact_container_id_and_shared_poll(self):
        self.path.write_text(json.dumps(self.first), encoding="utf-8")
        controller = object.__new__(current.CurrentEpochController)
        controller.owner, controller.work = OWNER, self.work
        controller.names = current.epoch.resource_names(OWNER)
        controller.deadline = 1000
        controller.build_profile = current.epoch.CurrentEpochBuildProfile(
            "sha256:" + "1" * 64, "2" * 64, "3" * 40, "4" * 40, "5" * 40)
        view = {"id": IDENTIFIER, "image": controller.worker_image,
                "labels": {current.epoch.EPOCH_LABEL: OWNER}, "state": {"Status": "running"}}
        controller.inspect_container = Mock(side_effect=[view, {**view, "state": {"Status": "exited"}}, view])
        controller.docker = Mock()

        def poll(_path, _owner, _first, **kwargs):
            kwargs["running_check"]()
            return self.advanced()

        with patch.object(current, "wait_for_advanced_status", side_effect=poll):
            self.assertEqual(controller.restart_serve_and_validate(self.path, self.first), self.advanced())
        self.assertEqual(controller.docker.call_args_list[0].args[0], ["stop", "--time=15", IDENTIFIER])
        self.assertEqual(controller.docker.call_args_list[1].args[0], ["start", IDENTIFIER])

    def test_boot_uses_same_pending_poll_and_keeps_full_profile_gate(self):
        adapter = object.__new__(boot.CurrentEpochBootAdapter)
        adapter.owner, adapter.status_path = OWNER, self.path
        adapter.names = current.epoch.resource_names(OWNER)
        adapter.container_ids = {adapter.names["serve"]: IDENTIFIER}
        adapter._verify_container_by_id = Mock()
        adapter.controller = Mock()
        adapter.controller.inspect_container.return_value = {"state": {"Status": "running"}}

        def poll(_path, _owner, _first, **kwargs):
            kwargs["running_check"]()
            return self.advanced()

        with patch.object(current, "wait_for_advanced_status", side_effect=poll):
            self.assertEqual(adapter._wait_advanced_status(self.first), self.advanced())
        with (
            patch.object(current, "wait_for_advanced_status", side_effect=current.CurrentEpochRejected("STARTUP_TIMEOUT")),
            self.assertRaisesRegex(boot.CurrentBootRejected, "STARTUP_TIMEOUT"),
        ):
            adapter._wait_advanced_status(self.first)


if __name__ == "__main__":
    unittest.main()
