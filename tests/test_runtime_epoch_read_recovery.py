from __future__ import annotations

import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from scripts import runtime_epoch_read_recovery as recovery


def state(*, drained: bool = False) -> dict:
    tables = {
        name: {"count": 0, "sha256": "a" * 64}
        for name in recovery.read_worker.epoch.CONTROLLED_RUNTIME_PUBLIC_TABLES
    }
    tables.update(
        {
            "event_audit": {"count": 336429, "sha256": "b" * 64},
            "message_outbox": {"count": 5336, "sha256": "c" * 64},
            "message_inbox": {
                "count": 5336 if drained else 5331,
                "sha256": "d" * 64,
            },
        }
    )
    return {
        "state": "PASS_R5_STATE",
        "matched_public_tables": len(tables),
        "tables": tables,
        "sequences": {"event_audit": {"last_value": 1, "is_called": True}},
        "anchors": {"BTCUSDT": {"last_close_time_ms": 100}},
        "original_prefix": {
            "rows": recovery.read_worker.epoch.ORIGINAL_PREFIX_ROWS,
            "audit_table_sha256": recovery.read_worker.epoch.ORIGINAL_PREFIX_TABLE_SHA256,
            "last_open_time_ms": recovery.read_worker.epoch.ORIGINAL_PREFIX_LAST_OPEN_MS,
        },
        "queue": {
            "outbox_rows": 5336,
            "inbox_rows": 5336 if drained else 5331,
            "completed_inbox": 5336 if drained else 5331,
            "pending_outbox": 0,
            "unresolved_inbox": 0,
            "trading_rows": 0,
            "missing_inbox_message_ids": []
            if drained
            else sorted(recovery.read_worker.TARGET_IDS),
        },
        "preserved_queue_prefixes": {
            "message_outbox": {"n": 5331, "sha": "e" * 64},
            "message_inbox": {"n": 5331, "sha": "f" * 64},
        },
        "redis": {
            "stream_entries": 5337,
            "publication_receipts": 5336,
            "stream_sha256": "d" * 64,
            "publication_receipts_sha256": "e" * 64,
            "publication_message_ids_sha256": "f" * 64,
            "stream_last_id": "1-1",
            "consumer_group": "bars",
            "last_delivered_id": "1-1",
            "pending_deliveries": 0,
            "pending_target_message_ids": [],
            "trading_started": False,
        },
        "trading_started": False,
    }


class FakeRecovery(recovery.R5ReadRecoveryController):
    def __init__(self, *, drift_prestate: bool = False, drain_count: int = 5):
        self.expected_revision = "e" * 40
        self.deadline = 1e10
        self.work = mock.Mock()
        self.names = {"target_pg": "target-pg", "redis": "target-redis", "serve": "old"}
        self.proofs = {}
        self.calls = []
        self.drift_prestate = drift_prestate
        self.drain_count = drain_count
        self.input_snapshot = {"preserved": "1" * 64}
        self.r4_snapshot = {"status": "2" * 64}
        self.resources = {
            "views": {
                "pg": {"id": "pg", "state": {"Status": "running"}},
                "redis": {"id": "redis", "state": {"Status": "running"}},
                "serve": {"id": "r2", "state": {"Status": "exited"}},
            },
            "legacy": {"stopped": True},
        }

    def admission_evidence(self, claim=None):
        return {"prior": "admitted"}

    def preserved_recovery_evidence(self):
        return self.r4_snapshot

    def validate_resources(self, *, allow_running=False):
        return self.resources

    def additional_preserved_resources(self):
        return {
            "r3": {"id": "r3", "state": {"Status": "exited"}},
            "r4": {"id": recovery.R4_CONTAINER_ID, "state": {"Status": "exited"}},
        }

    def inspect_container(self, target):
        if target in {"r2", "pg", "redis"}:
            key = {"r2": "serve", "pg": "pg", "redis": "redis"}[target]
            return self.resources["views"][key]
        if target == recovery.clean.R1_NAME:
            return {"id": recovery.clean.R1_ID, "state": {"Status": "exited"}}
        if target == recovery.boot.STANDBY_NAME:
            return {"id": "standby", "state": {"Status": "running"}}
        return {"id": target, "state": {"Status": "exited"}}

    def assert_legacy_sources_stopped(self, *, legacy_redis_id):
        return self.resources["legacy"]

    def load_private_inputs(self):
        self.calls.append("load-inputs")
        return {"producer_password": "a" * 64, "consumer_password": "b" * 64}

    def prepare_reviewed_snapshots(self):
        self.calls.append("prepare-snapshots")

    def _state_config(self, serving):
        return {**serving, "admin_password": "c" * 64}

    def _r5_state(self, suffix, config):
        self.calls.append("state:" + suffix)
        if suffix == "pre-drain" and self.drift_prestate:
            changed = state()
            changed["original_prefix"] = {"rows": 2, "audit_table_sha256": "f" * 64}
            return changed
        return state(drained=suffix == "after-drain")

    def prepare_boot_restore_volume(self, tag):
        self.calls.append("volume:" + tag)

    def backup_and_verify(self, *, seed, restore_password, tag, verification_mode):
        self.calls.append("backup:" + tag + ":" + verification_mode)
        return "a" * 64 if tag == "bootbefore" else "b" * 64

    def phase(self, mode, config, *, suffix=""):
        self.calls.append("phase:" + mode + (":" + suffix if suffix else ""))
        if mode == "r5-drain":
            return {
                "state": "PASS_EXACT_R5_INBOX_RECOVERY",
                "completed_message_ids": sorted(recovery.read_worker.TARGET_IDS),
                "completed_inbox_increment": self.drain_count,
                "published_messages": 0,
                "stream_entries_added": 0,
                "publication_receipts_added": 0,
                "pending_deliveries": 0,
                "audit_history_preserved": True,
                "outbox_and_sequences_preserved": True,
            }
        if mode == "boot-redis-state":
            return {"state": "PASS_BOOT_REDIS_STATE"}
        raise AssertionError("unexpected phase " + mode)

    def boot_state(self, tag):
        self.calls.append("boot-state:" + tag)
        return {
            "state": "PASS_BOOT_STATE",
            "tables": {"event_audit": {"count": 336434}},
            "sequences": {"event_audit": {"last_value": 1, "is_called": True}},
            "queue": {"pending_outbox": 0, "unresolved_inbox": 0},
            "original_prefix": {
                "rows": recovery.read_worker.epoch.ORIGINAL_PREFIX_ROWS,
                "audit_table_sha256": recovery.read_worker.epoch.ORIGINAL_PREFIX_TABLE_SHA256,
                "last_open_time_ms": recovery.read_worker.epoch.ORIGINAL_PREFIX_LAST_OPEN_MS,
            },
            "anchors": {"BTCUSDT": {"last_close_time_ms": 100}},
        }

    def audit_only_tail(self, baseline, suffix):
        self.calls.append("audit-tail:" + suffix)
        return baseline, None

    def _start_r5_and_check_progress(self, serving, baseline):
        self.calls.append("start-r5-and-restart-proof")
        return {
            "name": recovery.R5_NAME,
            "container_id": "new-id",
            "controlled_restart": True,
        }


class ReadRecoveryTests(unittest.TestCase):
    def _patched(self, controller):
        return (
            mock.patch.object(
                recovery.incident,
                "preserved_inputs",
                return_value=controller.input_snapshot,
            ),
            mock.patch.object(
                recovery.boot,
                "CONTAINERS",
                {"pg": "pg", "redis": "redis", "serve": "r2"},
            ),
            mock.patch.object(
                recovery.boot,
                "stable_standby_metadata",
                side_effect=lambda value: value,
            ),
        )

    def test_before_backup_precedes_exact_five_drain_and_no_qualify_phase(self):
        controller = FakeRecovery()
        with (
            self._patched(controller)[0],
            self._patched(controller)[1],
            self._patched(controller)[2],
        ):
            result = controller.run_recovery()
        self.assertEqual(result["result"], "PASS_NEW_NONTRADING_GENERATION")
        self.assertFalse(result["trading_started"])
        self.assertEqual(
            result["r4_failure_cause"],
            "EXPLICIT_REDIS_READ_TIMEOUT_NOT_INFRA_CAUSE_CONFIRMED",
        )
        before = controller.calls.index("backup:bootbefore:r5-verify-restore")
        drain = controller.calls.index("phase:r5-drain")
        after = controller.calls.index("backup:bootafter:boot-verify-restore")
        start = controller.calls.index("start-r5-and-restart-proof")
        self.assertLess(before, drain)
        self.assertLess(drain, after)
        self.assertLess(after, start)
        self.assertFalse(any("qualify" in call for call in controller.calls))

    def test_prestate_drift_blocks_drain_and_start(self):
        controller = FakeRecovery(drift_prestate=True)
        with (
            self._patched(controller)[0],
            self._patched(controller)[1],
            self._patched(controller)[2],
            self.assertRaisesRegex(Exception, "R5_PRESTATE_CHANGED_DURING_BACKUP"),
        ):
            controller.run_recovery()
        self.assertFalse(any("r5-drain" in call for call in controller.calls))
        self.assertFalse(any("start-r5" in call for call in controller.calls))

    def test_nonexact_drain_count_blocks_catchup_and_generation(self):
        controller = FakeRecovery(drain_count=4)
        with (
            self._patched(controller)[0],
            self._patched(controller)[1],
            self._patched(controller)[2],
            self.assertRaisesRegex(Exception, "R5_EXACT_EXISTING_FIVE_DRAIN_REQUIRED"),
        ):
            controller.run_recovery()
        self.assertFalse(any("after-drain" in call for call in controller.calls))
        self.assertFalse(any("start-r5" in call for call in controller.calls))

    def test_invalid_initial_five_ids_rejected(self):
        value = state()
        value["queue"]["missing_inbox_message_ids"] = []
        with self.assertRaisesRegex(
            Exception, "R5_EXACT_FIVE_PUBLISHED_PENDING_REQUIRED"
        ):
            recovery.validate_r5_state(value, stage="before")

    def test_nonzero_trading_rows_rejected(self):
        value = state()
        value["queue"]["trading_rows"] = 1
        with self.assertRaisesRegex(Exception, "R5_TRADING_ROWS_MUST_REMAIN_ZERO"):
            recovery.validate_r5_state(value, stage="before")

    def test_graceful_stop_receipt_must_match_full_clean_status(self):
        status = {
            "state": "RUNNING_NONTRADING",
            "owner": recovery.boot.OWNER,
            "cycles": 9,
            "watermarks_ms": {symbol: 60_000 for symbol in recovery.epoch.SYMBOLS},
            "pending_outbox": 0,
            "unresolved_inbox": 0,
            "completed_inbox": 5336,
            "uncompleted_publications": 0,
            "new_publications": 0,
            "observed_at_utc": datetime.now(UTC).isoformat(),
            "PAPER_QUALIFIED": False,
            "ALPHA_READY": False,
            "LIVE_READY": False,
            "STRATEGY_POLICY": "REJECT_ALL",
        }
        receipt = {
            **status,
            "state": "STOPPED_NONTRADING",
            "mode": "serve",
            "new_epoch_database": "kairos_epoch_" + recovery.boot.OWNER[:12],
            "graceful_shutdown": True,
        }
        recovery.validate_graceful_stop_receipt(receipt, status)
        receipt["pending_outbox"] = 1
        with self.assertRaisesRegex(Exception, "R5_GRACEFUL_STOP_RECEIPT_REQUIRED"):
            recovery.validate_graceful_stop_receipt(receipt, status)

    def test_restart_waits_past_old_status_and_binds_post_stop_cycle(self):
        captured = datetime.now(UTC)

        def running(n):
            return {
                "state": "RUNNING_NONTRADING",
                "owner": recovery.boot.OWNER,
                "cycles": n,
                "completed_inbox": 5336 + 5 * n,
                "watermarks_ms": {s: 60000 * n for s in recovery.epoch.SYMBOLS},
                "pending_outbox": 0,
                "unresolved_inbox": 0,
                "uncompleted_publications": 0,
                "new_publications": 0,
                "observed_at_utc": (captured + timedelta(microseconds=n)).isoformat(),
                "PAPER_QUALIFIED": False,
                "ALPHA_READY": False,
                "LIVE_READY": False,
                "STRATEGY_POLICY": "REJECT_ALL",
            }

        first, advance, stopped, resumed = [running(n) for n in (1, 2, 3, 4)]
        stop_receipt = {
            **stopped,
            "state": "STOPPED_NONTRADING",
            "mode": "serve",
            "graceful_shutdown": True,
            "new_epoch_database": "kairos_epoch_" + recovery.boot.OWNER[:12],
        }
        with TemporaryDirectory() as directory:
            controller = recovery.R5ReadRecoveryController.__new__(
                recovery.R5ReadRecoveryController
            )
            controller.work = Path(directory)
            output = controller.work / "output-serve"
            output.mkdir()
            (output / "status.json").touch()
            (output / "serve-stop-test.json").touch()
            controller.deadline = time.monotonic() + 60
            controller.names, controller.proofs = {}, {}
            controller.phase = mock.Mock()
            controller.docker = mock.Mock(return_value="")
            view = {"id": "a" * 64, "state": {"Status": "running"}}
            stop_view = {
                "id": "a" * 64,
                "state": {"Status": "exited", "ExitCode": 0, "OOMKilled": False},
            }
            controller.inspect_container = mock.Mock(
                side_effect=[view, view, stop_view, view, view]
            )
            with (
                mock.patch.object(
                    recovery.boot,
                    "read_json",
                    side_effect=[
                        first,
                        advance,
                        stop_receipt,
                        stopped,
                        stopped,
                        resumed,
                    ],
                ),
                mock.patch.object(recovery.time, "sleep"),
            ):
                result = controller._start_r5_and_check_progress(
                    {},
                    {
                        "anchors": {
                            s: {"last_close_time_ms": 0} for s in recovery.epoch.SYMBOLS
                        }
                    },
                )
            self.assertTrue(result["controlled_restart"])
            self.assertEqual(result["status"], resumed)


if __name__ == "__main__":
    unittest.main()
