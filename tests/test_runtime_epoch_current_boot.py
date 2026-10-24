from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts import runtime_epoch_current_boot as boot
from scripts import runtime_epoch_worker as worker

OWNER = "0123456789abcdef0123456789abcdef"
EXPECTED = {
    "kairos-epoch-0123456789ab-pg",
    "kairos-epoch-0123456789ab-redis",
    "kairos-epoch-0123456789ab-serve",
}


def status(*, observed_at: datetime | None = None) -> dict:
    return {
        "state": "RUNNING_NONTRADING",
        "owner": OWNER,
        "schema_profile": boot.SCHEMA_PROFILE,
        "schema_migration_count": boot.MIGRATION_COUNT,
        "schema_public_table_count": boot.PUBLIC_TABLE_COUNT,
        "watermarks_ms": {symbol: 1_800_000_000_000 for symbol in worker.SYMBOLS},
        "pending_outbox": 0,
        "unresolved_inbox": 0,
        "uncompleted_publications": 0,
        "PAPER_QUALIFIED": False,
        "ALPHA_READY": False,
        "LIVE_READY": False,
        "STRATEGY_POLICY": "REJECT_ALL",
        "trading_started": False,
        "observed_at_utc": (observed_at or datetime.now(UTC)).isoformat(),
    }


class CurrentBootAdmissionTests(unittest.TestCase):
    def test_restore_name_collision_after_failed_create_never_inspects_or_stops_by_name(self):
        class FailedCreateController:
            def __init__(self):
                self.names = {"restore_pg": "prior-restore", "restore_volume": "prior-volume"}
                self.created = []
                self.inspect_calls = []
                self.docker_calls = []

            def stream_private_pg_dump(self, *, backup, database):
                backup.write_bytes(b"bounded test dump")

            def create_volume(self, volume):
                pass

            def initialize_volume(self, volume, *, uid):
                pass

            def create_database(self, **kwargs):
                raise boot.epoch.Rejected("container name already exists")

            def inspect_container(self, target):
                self.inspect_calls.append(target)
                raise AssertionError("failed create must not be adopted or inspected")

            def docker(self, args, **kwargs):
                self.docker_calls.append(args)
                return ""

        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            adapter = object.__new__(boot.CurrentEpochBootAdapter)
            adapter.owner = OWNER
            adapter.names = boot.epoch.resource_names(OWNER)
            adapter.private = {"restore_admin_password": "r" * 64}
            adapter.container_images = {adapter.names["target_pg"]: "sha256:" + "a" * 64}
            adapter._container_names = lambda *, all_states: set()
            adapter._volume_names = lambda: set()
            controller = FailedCreateController()
            with self.assertRaisesRegex(boot.epoch.Rejected, "already exists"):
                adapter._backup_restore(
                    controller,
                    work,
                    {"database": "history"},
                    {},
                    "1" * 32 + "-01",
                )
            self.assertEqual(controller.inspect_calls, [])
            self.assertFalse(any(call and call[0] == "stop" for call in controller.docker_calls))
            self.assertEqual(controller.names, {"restore_pg": "prior-restore", "restore_volume": "prior-volume"})

    def test_topology_accepts_only_exact_all_running_or_all_stopped(self):
        states = {name: "running" for name in EXPECTED}
        self.assertEqual(boot.classify_topology(states, set(EXPECTED), EXPECTED), "ALREADY_RUNNING")
        stopped = {name: "exited" for name in EXPECTED}
        self.assertEqual(boot.classify_topology(stopped, set(), EXPECTED), "READY_TO_START")

    def test_partial_unknown_or_extra_active_topology_fails_closed(self):
        for states, active in (
            ({next(iter(EXPECTED)): "running"}, set()),
            ({name: "running" for name in EXPECTED} | {"extra": "running"}, set(EXPECTED)),
            ({name: "paused" for name in EXPECTED}, set()),
            ({name: "exited" for name in EXPECTED}, {"kairos-epoch-unknown-pg"}),
            ({name: "running" for name in EXPECTED}, set()),
        ):
            with self.subTest(states=states, active=active), self.assertRaises(
                boot.CurrentBootRejected
            ):
                boot.classify_topology(states, active, EXPECTED)

    def test_current_status_requires_fresh_health_and_all_nontrading_gates(self):
        accepted = status()
        boot.validate_status_profile(accepted, OWNER)
        for key, value in (
            ("schema_profile", "historical-default"),
            ("schema_migration_count", 18),
            ("schema_public_table_count", 32),
            ("trading_started", True),
            ("pending_outbox", 1),
        ):
            rejected = {**accepted, key: value}
            with self.subTest(key=key), self.assertRaises(
                (boot.CurrentBootRejected, boot.epoch.Rejected)
            ):
                boot.validate_status_profile(rejected, OWNER)
        stale = status(observed_at=datetime.now(UTC) - timedelta(minutes=5))
        with self.assertRaises(boot.epoch.Rejected):
            boot.validate_status_profile(stale, OWNER)

    def test_signed_baseline_may_be_old_but_must_be_exact_current_nontrading(self):
        old = status(observed_at=datetime.now(UTC) - timedelta(days=2))
        boot.validate_signed_status_baseline(old, OWNER)
        old["LIVE_READY"] = True
        with self.assertRaises(boot.CurrentBootRejected):
            boot.validate_signed_status_baseline(old, OWNER)

    def test_unique_retained_restore_admission_uses_current_profile(self):
        adapter = object.__new__(boot.CurrentEpochBootAdapter)
        adapter.owner = OWNER
        adapter.names = boot.epoch.resource_names(OWNER)
        adapter._require_unique_restore_host_support()
        value = {
            "owner": OWNER,
            "database": "kairos_epoch_" + OWNER[:12],
            "pg_host": adapter.names["target_pg"],
            "redis_host": adapter.names["redis"],
            "admin_password": "a" * 64,
            "restore_host": "kairos-epoch-0123456789ab-restore-current-aaaaaaaaaaaa01",
            "restore_database": "kairos_recovery_" + OWNER[:12] + "_epochrestore",
            "restore_admin_password": "b" * 64,
            "expected_seed": {},
        }
        boot.epoch.validate_worker_config(
            value,
            mode="boot-verify-restore",
            schema_profile=boot.SCHEMA_PROFILE,
        )
        self.assertEqual(
            value["restore_host"],
            "kairos-epoch-0123456789ab-restore-current-aaaaaaaaaaaa01",
        )

    def test_current_gpg_tools_are_exact_bundled_git_binaries(self):
        self.assertEqual(str(boot.GPG), "C:\\Program Files\\Git\\usr\\bin\\gpg.exe")
        self.assertEqual(str(boot.GPGV), "C:\\Program Files\\Git\\usr\\bin\\gpgv.exe")

    def test_only_exact_current_inprogress_latch_is_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            owner_work = Path(directory) / ("run-" + OWNER)
            owner_work.mkdir()
            adapter = object.__new__(boot.CurrentEpochBootAdapter)
            adapter.owner = OWNER
            adapter.owner_work = owner_work
            adapter.receipt_sha256 = "a" * 64
            adapter.names = boot.epoch.resource_names(OWNER)

            def add_latch(token: str) -> Path:
                work = owner_work / ("boot-" + token)
                work.mkdir()
                (work / "boot-latch.json").write_text(
                    json.dumps(
                        {
                            "schema": "kairos.current-epoch-boot-latch.v1",
                            "owner": OWNER,
                            "receipt_sha256": "a" * 64,
                            "state": "IN_PROGRESS",
                            "planned_starts": [
                                adapter.names["target_pg"],
                                adapter.names["redis"],
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                return work

            current_work = add_latch("1" * 32)
            adapter._check_latches(exclude_current_work=current_work)
            add_latch("2" * 32)
            with self.assertRaisesRegex(
                boot.CurrentBootRejected, "UNKNOWN_OR_FAILED_PRIOR_BOOT_LATCH"
            ):
                adapter._check_latches(exclude_current_work=current_work)
            with self.assertRaisesRegex(
                boot.CurrentBootRejected, "EXACT_CURRENT_BOOT_WORKDIR_REQUIRED"
            ):
                adapter._check_latches(
                    exclude_current_work=owner_work / ("boot-" + "3" * 32)
                )


if __name__ == "__main__":
    unittest.main()
