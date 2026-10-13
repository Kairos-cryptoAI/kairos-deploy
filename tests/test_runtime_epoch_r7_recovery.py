"""No-native admission, cold-copy and recovery-order regression checks."""

import copy
import io
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from scripts import runtime_epoch_cold_snapshot as cold
from scripts import runtime_epoch_r7_recovery as recovery
from scripts import runtime_epoch_worker as worker


class ColdSnapshotTests(unittest.TestCase):
    def test_verified_bytes_and_unchanged_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "source", root / "target"
            source.mkdir()
            target.mkdir()
            (source / "sub").mkdir()
            (source / "sub" / "history.bin").write_bytes(b"candle-history\0" * 10)
            before = cold.manifest(source, deadline=time.monotonic() + 10)
            proof = cold.copy_snapshot(source, target, deadline=time.monotonic() + 10)
            self.assertEqual(proof["state"], "PASS_COLD_BYTE_COPY")
            self.assertFalse(proof["restore_proven"])
            self.assertEqual(
                before, cold.manifest(source, deadline=time.monotonic() + 10)
            )
            self.assertEqual(
                before, cold.manifest(target, deadline=time.monotonic() + 10)
            )

    def test_same_or_nonempty_target_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").write_bytes(b"kept")
            with self.assertRaises(cold.SnapshotError):
                cold.copy_snapshot(root, root, deadline=time.monotonic() + 10)
            target = root / "target"
            target.mkdir()
            (target / "existing").write_bytes(b"preserve")
            with self.assertRaises(cold.SnapshotError):
                cold.copy_snapshot(root, target, deadline=time.monotonic() + 10)
            self.assertEqual((target / "existing").read_bytes(), b"preserve")

    def test_bounds_and_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").write_bytes(b"history")
            with (
                mock.patch.object(cold, "MAX_BYTES", 1),
                self.assertRaises(cold.SnapshotError),
            ):
                cold.manifest(root, deadline=time.monotonic() + 10)
            with self.assertRaises(cold.SnapshotError):
                cold.manifest(root, deadline=time.monotonic() - 1)

    def test_link_and_directory_count_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "history").write_bytes(b"kept")
            (root / "one").mkdir()
            (root / "two").mkdir()
            with (
                mock.patch.object(cold, "MAX_FILES", 1),
                self.assertRaises(cold.SnapshotError),
            ):
                cold.manifest(root, deadline=time.monotonic() + 10)
            try:
                (root / "link").symlink_to(root / "history")
            except OSError:
                self.skipTest("host cannot create test symlink")
            with self.assertRaises(cold.SnapshotError):
                cold.manifest(root, deadline=time.monotonic() + 10)

    def test_source_growth_refused_before_target_data_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "source", root / "target"
            source.mkdir()
            target.mkdir()
            file = source / "history"
            file.write_bytes(b"one")
            before = cold.manifest(source, deadline=time.monotonic() + 10)
            file.write_bytes(b"unexpected-growth")
            with (
                mock.patch.object(cold, "manifest", return_value=before),
                self.assertRaises(cold.SnapshotError),
            ):
                cold.copy_snapshot(source, target, deadline=time.monotonic() + 10)
            self.assertFalse((target / "history").exists())


def state():
    return {
        "state": "PASS_BOOT_STATE",
        "matched_public_tables": 32,
        "trading_started": False,
        "anchors": {
            symbol: {"last_close_time_ms": 100} for symbol in recovery.epoch.SYMBOLS
        },
        "queue": {
            "pending_outbox": 0,
            "unresolved_inbox": 0,
            "trading_rows": 0,
            "outbox_rows": 6000,
            "inbox_rows": 6000,
            "completed_inbox": 6000,
        },
    }


class R7RecoveryTests(unittest.TestCase):
    def test_plan_has_no_native_calls(self):
        with (
            mock.patch.object(recovery.boot, "verify_source") as verify,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(recovery.main([]), 0)
        verify.assert_not_called()

    def test_dirty_unknown_or_trade_state_never_admitted(self):
        recovery.validate_clean_before_start(state())
        for path, value in [
            ("pending_outbox", 1),
            ("unresolved_inbox", 1),
            ("trading_rows", 1),
            ("completed_inbox", 5999),
        ]:
            altered = state()
            altered["queue"][path] = value
            with self.subTest(path=path), self.assertRaises(recovery.epoch.Rejected):
                recovery.validate_clean_before_start(altered)
        altered = state()
        altered["trading_started"] = True
        with self.assertRaises(recovery.epoch.Rejected):
            recovery.validate_clean_before_start(altered)

    def test_both_restore_layers_admit_only_fixed_r7_owner(self):
        owner = recovery.boot.OWNER
        value = {
            "owner": owner,
            "database": "kairos_epoch_" + owner[:12],
            "pg_host": "kairos-epoch-" + owner[:12] + "-pg",
            "redis_host": "kairos-epoch-" + owner[:12] + "-redis",
            "admin_password": "a" * 64,
            "restore_admin_password": "b" * 64,
            "restore_host": "kairos-epoch-" + owner[:12] + "-restore-transport07",
            "restore_database": "kairos_recovery_" + owner[:12] + "_epochrestore",
            "expected_seed": state(),
        }
        recovery.epoch.validate_worker_config(value, mode="boot-verify-restore")
        with mock.patch.object(worker, "validate_boot_seed") as seed:
            worker.validate_config(value, "boot-verify-restore")
            seed.assert_called_once()
        for bad_host in (value["restore_host"].replace("07", "08"), "foreign-restore"):
            bad = {**value, "restore_host": bad_host}
            with self.assertRaises(recovery.epoch.Rejected):
                recovery.epoch.validate_worker_config(bad, mode="boot-verify-restore")
            with self.assertRaises(worker.EpochError):
                worker.validate_config(bad, "boot-verify-restore")

    def test_failed_r6_hash_conflict_rejects_before_credentials(self):
        with (
            mock.patch.object(recovery.fresh, "sha", return_value="0" * 64),
            self.assertRaises(recovery.epoch.Rejected),
        ):
            recovery.admitted_failure()

    def test_cold_copies_and_restore_precede_new_producer(self):
        controller = object.__new__(recovery.R7RecoveryController)
        controller.names = recovery.epoch.resource_names(recovery.boot.OWNER)
        controller.work = Path("unused-offline")
        controller.expected_revision = "a" * 40
        steps = []
        resources = {
            "views": {
                k: {"state": {"Status": "exited"}} for k in ("pg", "redis", "serve")
            },
            "legacy": {},
        }
        controller.validate_resources = lambda **_kw: copy.deepcopy(resources)
        controller.assert_new_generation_absent = lambda: steps.append("absent")
        controller.load_private_inputs = dict
        controller.prepare_reviewed_snapshots = lambda: steps.append("snapshots")
        controller.cold_backup = lambda key, **_kw: steps.append("cold-" + key) or {}
        controller.docker = lambda argv, **_kw: (
            steps.append(argv[0] + ":" + argv[-1]) or ""
        )
        controller.wait_postgres = lambda _name: steps.append("ready")
        controller.boot_state = lambda _tag: state()
        controller.prepare_boot_restore_volume = lambda tag: steps.append(
            "clone-" + tag
        )
        controller.backup_and_verify = lambda **kw: (
            steps.append("restore-" + kw["tag"]) or "f" * 64
        )
        controller.phase = lambda *args, **_kw: steps.append(args[0]) or {}
        controller.audit_only_tail = lambda *args: (state(), [])
        controller.start_and_restart = lambda _serving: (
            steps.append("new-producer") or {}
        )
        controller.inspect_container = lambda _id: resources["views"]["serve"]
        controller.assert_legacy_sources_stopped = lambda **_kw: {}
        with (
            mock.patch.object(
                recovery,
                "admitted_failure",
                return_value={
                    "accepted_minimum_completed_inbox": 6000,
                    "accepted_minimum_watermarks_ms": {
                        symbol: 100 for symbol in recovery.epoch.SYMBOLS
                    },
                },
            ),
            mock.patch.object(
                recovery.feed.incident, "preserved_inputs", return_value={}
            ),
            mock.patch.object(recovery.clean, "inventory_files", return_value={}),
        ):
            result = controller.run_recovery()
        self.assertFalse(result["trading_started"])
        self.assertLess(steps.index("cold-pg"), steps.index("ready"))
        self.assertLess(steps.index("cold-redis"), steps.index("ready"))
        self.assertLess(steps.index("restore-bootbefore"), steps.index("new-producer"))
        self.assertLess(steps.index("restore-bootafter"), steps.index("new-producer"))
        self.assertNotIn("start:" + recovery.NAME.replace("r7", "r6"), steps)

    def test_existing_claim_is_not_overwritten_or_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            claim = Path(directory) / "claim"
            claim.mkdir()
            marker = claim / "preserve"
            marker.write_bytes(b"failed-or-active")
            with (
                mock.patch.object(recovery, "CLAIM", claim),
                mock.patch.object(recovery.boot, "configure_generation_r6"),
                mock.patch.object(recovery.boot, "verify_source"),
                mock.patch.object(recovery, "admitted_failure"),
                mock.patch.object(recovery, "R7RecoveryController") as cls,
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    recovery.main(
                        [
                            "--execute",
                            "--expected-revision",
                            "a" * 40,
                            "--failed-r6-status-sha256",
                            recovery.FAILED_STATUS_SHA256,
                        ]
                    ),
                    1,
                )
            cls.assert_not_called()
            self.assertEqual(marker.read_bytes(), b"failed-or-active")


if __name__ == "__main__":
    unittest.main()
