"""Offline rejection and state-preservation contracts for reboot recovery."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from scripts import runtime_epoch_boot as boot
from scripts import runtime_epoch_controller as epoch


def state() -> dict:
    return {
        "state": "PASS_BOOT_STATE",
        "tables": {
            "event_audit": {"count": 173_164},
            "message_outbox": {"count": 2220},
            "message_inbox": {"count": 2220},
            "source_cursors": {"count": 0},
        },
        "sequences": {"message_outbox_id_seq": {"last_value": 2220}},
        "original_prefix": {"sha256": "a" * 64},
    }


class BootAdmissionTests(unittest.TestCase):
    def test_r2_boot_scope_is_exact_new_container_and_does_not_relabel_original(self):
        keys = (
            "ROOT",
            "SERVE_WORK",
            "SCOPE",
            "GENERATION",
            "RECEIPT_NAME",
            "PARENT_RECEIPT_SHA256",
            "CONTAINERS",
            "LEASE",
        )
        patches = [mock.patch.object(boot, key, getattr(boot, key)) for key in keys]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        original = boot.CONTAINERS.copy()
        boot.configure_generation_r2()
        self.assertEqual(boot.GENERATION, "r2")
        self.assertEqual(boot.RECEIPT_NAME, "receipt.json")
        self.assertEqual(boot.CONTAINERS["pg"], original["pg"])
        self.assertEqual(boot.CONTAINERS["redis"], original["redis"])
        self.assertNotEqual(boot.CONTAINERS["serve"], original["serve"])
        self.assertEqual(
            boot.CONTAINERS["serve"],
            "87b9c085beb1f7666fefc8e3bc2fded72c44397992482fd6efc2a43459a046b0",
        )
        self.assertEqual(boot.LEASE.parent, boot.ROOT)
        self.assertIn("epoch-boot-r2-20261012", boot.ROOT.as_posix())

    def test_r2_constructor_never_adopts_the_retained_unverified_restore_clone(self):
        def initialize(controller, *_args, **_kwargs):
            controller.names = epoch.resource_names(boot.OWNER)

        with (
            mock.patch.object(boot, "GENERATION", "r2"),
            mock.patch.object(epoch.EpochController, "__init__", new=initialize),
        ):
            controller = boot.BootController(boot.OWNER, expected_revision="a" * 40)
        self.assertTrue(controller.names["serve"].endswith("-serve-r2"))
        self.assertTrue(controller.names["restore_pg"].endswith("-restore-incident03"))
        self.assertTrue(
            controller.names["restore_volume"].endswith("-restore-data-incident03")
        )

    def test_r4_boot_scope_is_exact_accepted_receipt_and_new_serve(self):
        keys = (
            "ROOT",
            "SERVE_WORK",
            "SCOPE",
            "GENERATION",
            "RECEIPT_NAME",
            "PARENT_RECEIPT_SHA256",
            "CONTAINERS",
            "LEASE",
        )
        patches = [mock.patch.object(boot, key, getattr(boot, key)) for key in keys]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        original = boot.CONTAINERS.copy()

        boot.configure_generation_r4()

        self.assertEqual(
            boot.ROOT.as_posix(), "D:/Kairos/runtime/epoch-boot-r4-20261012"
        )
        self.assertEqual(
            boot.SERVE_WORK.as_posix(),
            "D:/Kairos/runtime/runtime-incident-20261012/clean-recovery-r4-97469e3b772b4d00b0b531282ba01b55",
        )
        self.assertEqual(boot.SCOPE, "kairos-nontrading-runtime-epoch-boot-r4-v1")
        self.assertEqual(boot.GENERATION, "r4")
        self.assertEqual(boot.RECEIPT_NAME, "receipt.json")
        self.assertEqual(
            boot.PARENT_RECEIPT_SHA256,
            "0a7a621991a328d9fedb8c203cc0da53a835e0a3c02f6549bacf4ef650dba03f",
        )
        self.assertEqual(boot.CONTAINERS["pg"], original["pg"])
        self.assertEqual(boot.CONTAINERS["redis"], original["redis"])
        self.assertEqual(
            boot.CONTAINERS["serve"],
            "1f9da09121bd509c5aa1d1a698c98334bc1e5378ee4978b65d98885cff19e199",
        )
        self.assertEqual(boot.LEASE, boot.ROOT / "boot.active")

    def test_r4_constructor_uses_only_r4_and_transport04_restore_names(self):
        def initialize(controller, *_args, **_kwargs):
            controller.names = epoch.resource_names(boot.OWNER)

        with (
            mock.patch.object(boot, "GENERATION", "r4"),
            mock.patch.object(epoch.EpochController, "__init__", new=initialize),
        ):
            controller = boot.BootController(boot.OWNER, expected_revision="a" * 40)
        self.assertEqual(
            controller.names["serve"], "kairos-epoch-69893dc7b7c6-serve-r4"
        )
        self.assertEqual(
            controller.names["restore_pg"],
            "kairos-epoch-69893dc7b7c6-restore-transport04",
        )
        self.assertEqual(
            controller.names["restore_volume"],
            "kairos-epoch-69893dc7b7c6-restore-data-transport04",
        )

    def test_r5_boot_scope_pins_exact_accepted_receipt_and_container(self):
        keys = (
            "ROOT",
            "SERVE_WORK",
            "SCOPE",
            "GENERATION",
            "RECEIPT_NAME",
            "PARENT_RECEIPT_SHA256",
            "CONTAINERS",
            "LEASE",
        )
        patches = [mock.patch.object(boot, key, getattr(boot, key)) for key in keys]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        original = boot.CONTAINERS.copy()

        boot.configure_generation_r5()

        self.assertEqual(
            boot.ROOT.as_posix(), "D:/Kairos/runtime/epoch-boot-r5-20261012"
        )
        self.assertEqual(
            boot.SERVE_WORK.as_posix(),
            "D:/Kairos/runtime/runtime-incident-20261012/read-recovery-r5-a3badf943e944cc6b53be1a4f7fd1792",
        )
        self.assertEqual(boot.SCOPE, "kairos-nontrading-runtime-epoch-boot-r5-v1")
        self.assertEqual(boot.GENERATION, "r5")
        self.assertEqual(boot.RECEIPT_NAME, "receipt.json")
        self.assertEqual(
            boot.PARENT_RECEIPT_SHA256,
            "a0b16bfc3953b39f63767df228fcae43a0afdc1a70a5ba45973ab4dc4a1c06fd",
        )
        self.assertEqual(boot.CONTAINERS["pg"], original["pg"])
        self.assertEqual(boot.CONTAINERS["redis"], original["redis"])
        self.assertEqual(
            boot.CONTAINERS["serve"],
            "837783acb187510d04f7e33295a6c18e9c31129f4145f434b288c0a88f565d99",
        )
        self.assertEqual(boot.LEASE, boot.ROOT / "boot.active")

    def test_r5_constructor_uses_transport05_and_r5_serve_name(self):
        def initialize(controller, *_args, **_kwargs):
            controller.names = epoch.resource_names(boot.OWNER)

        with (
            mock.patch.object(boot, "GENERATION", "r5"),
            mock.patch.object(epoch.EpochController, "__init__", new=initialize),
        ):
            controller = boot.BootController(boot.OWNER, expected_revision="a" * 40)
        self.assertEqual(
            controller.names["serve"], "kairos-epoch-69893dc7b7c6-serve-r5"
        )
        self.assertEqual(
            controller.names["restore_pg"],
            "kairos-epoch-69893dc7b7c6-restore-transport05",
        )
        self.assertEqual(
            controller.names["restore_volume"],
            "kairos-epoch-69893dc7b7c6-restore-data-transport05",
        )

    def test_r4_binding_rejects_other_generation_receipt_or_serve_identity(self):
        keys = (
            "ROOT",
            "SERVE_WORK",
            "SCOPE",
            "GENERATION",
            "RECEIPT_NAME",
            "PARENT_RECEIPT_SHA256",
            "CONTAINERS",
            "LEASE",
        )
        patches = [mock.patch.object(boot, key, getattr(boot, key)) for key in keys]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        boot.configure_generation_r4()
        valid = {
            "schema_version": 1,
            "owner": boot.OWNER,
            "scope": boot.SCOPE,
            "generation": boot.GENERATION,
            "repo": epoch.REPO.as_posix(),
            "python_path": boot.PYTHON.as_posix(),
            "entry_script": "scripts/runtime_epoch_boot.py",
            "launcher_script": "scripts/Invoke-NonTradingEpochBoot.ps1",
            "containers": boot.CONTAINERS.copy(),
            "parent_receipt_sha256": boot.PARENT_RECEIPT_SHA256,
            "revision": "a" * 40,
        }
        for field, wrong in (
            ("generation", "r2"),
            ("scope", "kairos-nontrading-runtime-epoch-boot-r2-v1"),
            ("parent_receipt_sha256", "b" * 64),
            (
                "containers",
                {**boot.CONTAINERS, "serve": "c" * 64},
            ),
        ):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    epoch.Rejected, "EXACT_SINGLE_NONTRADING_BOOT_BINDING_REQUIRED"
                ),
            ):
                boot.validate_binding({**valid, field: wrong})

    def test_cli_generation_is_explicit_and_original_remains_default(self):
        output = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            mock.patch.object(boot, "configure_generation_r2") as r2,
            mock.patch.object(boot, "configure_generation_r4") as r4,
            mock.patch.object(boot, "configure_generation_r5") as r5,
        ):
            self.assertEqual(boot.main([]), 0)
            r2.assert_not_called()
            r4.assert_not_called()
            r5.assert_not_called()
            self.assertEqual(boot.main(["--generation", "r4"]), 0)
            r4.assert_called_once_with()
            r2.assert_not_called()
            r5.assert_not_called()
            self.assertEqual(boot.main(["--generation", "r5"]), 0)
            r5.assert_called_once_with()
            with self.assertRaises(SystemExit):
                boot.main(["--generation", "r3"])

    def test_stopped_epoch_full_path_requires_two_restores_and_readonly_redis_before_serve(
        self,
    ):
        with TemporaryDirectory() as directory:
            parent = Path(directory)
            (parent / "target-admin-password").write_text("a" * 64)
            controller = boot.BootController.__new__(boot.BootController)
            controller.names = epoch.resource_names(boot.OWNER)
            controller.owner = boot.OWNER
            controller.created, controller.proofs = [], {}
            controller.deadline = time.monotonic() + 600
            resources = {
                "legacy": {"id": "preserved"},
                "standby": {"left_untouched": True},
                "views": {k: {"state": {"Status": "exited"}} for k in boot.CONTAINERS},
            }
            final = copy.deepcopy(resources)
            for view in final["views"].values():
                view["state"]["Status"] = "running"
            controller.validate_resources = mock.Mock(
                side_effect=[resources, resources, resources, final]
            )
            controller.inspect_container = mock.Mock(
                return_value={"state": {"Status": "exited"}}
            )
            calls = []
            controller.docker = mock.Mock(
                side_effect=lambda args: calls.append(tuple(args)) or ""
            )
            controller.prepare_snapshots = mock.Mock()
            controller.wait_postgres = mock.Mock()
            controller.create_volume = mock.Mock(
                side_effect=lambda name: calls.append(("volume-create", name))
            )
            controller.initialize_volume = mock.Mock(
                side_effect=lambda name, **kwargs: calls.append(
                    ("volume-init", name, kwargs["uid"])
                )
            )
            controller.backup_and_verify = mock.Mock(
                side_effect=lambda **kwargs: (
                    calls.append(("restore", kwargs["tag"])) or "b" * 64
                )
            )
            controller.phase = mock.Mock(
                side_effect=lambda mode, config, **kwargs: (
                    calls.append(("phase", mode))
                    or {"state": "AUDIT_ONLY_CATCHUP_COMPLETE"}
                )
            )
            seconds = 1_791_728_765
            end = (seconds * 1000 - 5000) // epoch.MINUTE_MS * epoch.MINUTE_MS
            before = state()
            before["anchors"] = {
                s: {"last_close_time_ms": end - epoch.MINUTE_MS - 1}
                for s in epoch.SYMBOLS
            }
            after = copy.deepcopy(before)
            after["tables"]["event_audit"]["count"] += 5
            after["anchors"] = {
                s: {"last_close_time_ms": end - 1} for s in epoch.SYMBOLS
            }
            controller.boot_state = mock.Mock(
                side_effect=[before, before, after, after, after]
            )
            previous = {
                "state": "RUNNING_NONTRADING",
                "owner": boot.OWNER,
                "observed_at_utc": "2026-10-11T11:19:56Z",
            }
            current = {
                **previous,
                "observed_at_utc": "2026-10-11T14:00:00Z",
                "watermarks_ms": {s: end + epoch.MINUTE_MS for s in epoch.SYMBOLS},
            }
            with (
                mock.patch.object(boot, "PARENT", parent),
                mock.patch.object(
                    boot, "read_json", side_effect=[previous, {}, current]
                ),
                mock.patch.object(boot.time, "time", return_value=seconds),
                mock.patch.object(
                    boot.subprocess, "run", return_value=mock.Mock(stdout=b"locked")
                ),
                mock.patch.object(epoch, "validate_aux_wheelhouse"),
                mock.patch.object(
                    epoch,
                    "read_attempt_04_rotated_history_secret",
                    return_value="h" * 64,
                ),
                mock.patch.object(epoch, "validate_running_status"),
            ):
                result = controller.run_boot()
            self.assertEqual(result["result"], "PASS_NONTRADING_EPOCH_BOOT")
            self.assertEqual(controller.backup_and_verify.call_count, 2)
            restore_volume = controller.names["restore_volume"]
            self.assertEqual(
                [
                    c
                    for c in calls
                    if c[0] in {"volume-create", "volume-init", "restore"}
                ],
                [
                    ("volume-create", restore_volume),
                    ("volume-init", restore_volume, 70),
                    ("restore", "bootbefore"),
                    ("volume-create", restore_volume),
                    ("volume-init", restore_volume, 70),
                    ("restore", "bootafter"),
                ],
            )
            for tag in ("bootbefore", "bootafter"):
                self.assertEqual(controller.proofs[tag + "_backup_sha256"], "b" * 64)
            for call in controller.backup_and_verify.call_args_list:
                self.assertEqual(
                    call.kwargs["verification_mode"], "boot-verify-restore"
                )
            self.assertEqual(controller.phase.call_args_list[0].args[0], "boot-catchup")
            self.assertEqual(
                controller.phase.call_args_list[-1].args[0], "boot-redis-state"
            )
            serve_start = ("start", controller.names["serve"])
            self.assertLess(
                calls.index(("phase", "boot-redis-state")), calls.index(serve_start)
            )
            self.assertNotIn(("start", boot.STANDBY_NAME), calls)
            self.assertTrue(result["legacy_unchanged"])
            self.assertFalse(result["trading_started"])

    def test_boot_restore_volume_requires_absent_resources_before_any_mutation(self):
        for conflict in (None, "volume", "clone"):
            with self.subTest(conflict=conflict):
                controller = boot.BootController.__new__(boot.BootController)
                controller.names = epoch.resource_names(boot.OWNER)
                controller.proofs = {}
                volume = controller.names["restore_volume"]
                clone = controller.names["restore_pg"]
                controller.docker = mock.Mock(
                    side_effect=[
                        volume + "\n" if conflict == "volume" else "",
                        clone + "\n" if conflict == "clone" else "",
                    ]
                )
                events = []
                controller.create_volume = mock.Mock(
                    side_effect=lambda name, events=events: events.append(
                        ("create", name)
                    )
                )
                controller.initialize_volume = mock.Mock(
                    side_effect=lambda name, events=events, **kwargs: events.append(
                        ("initialize", name, kwargs["uid"])
                    )
                )
                if conflict:
                    with self.assertRaisesRegex(
                        epoch.Rejected, "BOOT_RESTORE_RESOURCES_MUST_BE_ABSENT"
                    ):
                        controller.prepare_boot_restore_volume("bootbefore")
                    self.assertEqual(events, [])
                    self.assertEqual(controller.proofs, {})
                else:
                    controller.prepare_boot_restore_volume("bootbefore")
                    self.assertEqual(
                        events, [("create", volume), ("initialize", volume, 70)]
                    )
                    self.assertTrue(
                        controller.proofs["bootbefore_restore_volume"][
                            "fresh_owner_labelled"
                        ]
                    )
                self.assertEqual(
                    controller.docker.call_args_list[-1].args[0],
                    [
                        "ps",
                        "-a",
                        "--filter",
                        "name=^/" + clone + "$",
                        "--format",
                        "{{.Names}}",
                    ],
                )

    def test_boot_restore_volume_rejects_unknown_tag_without_docker(self):
        controller = boot.BootController.__new__(boot.BootController)
        controller.docker = mock.Mock()
        with self.assertRaisesRegex(epoch.Rejected, "EXACT_BOOT_BACKUP_TAG_REQUIRED"):
            controller.prepare_boot_restore_volume("arbitrary")
        controller.docker.assert_not_called()

    @staticmethod
    def _resources():
        names = epoch.resource_names(boot.OWNER)
        views = {}
        for key, name, image, memory, cpus in (
            ("pg", names["target_pg"], epoch.PG_IMAGE, 4 * 1024**3, 1_000_000_000),
            ("redis", names["redis"], epoch.REDIS_IMAGE, 256 * 1024**2, 500_000_000),
            ("serve", names["serve"], epoch.WORKER_IMAGE, 512 * 1024**2, 1_000_000_000),
        ):
            views[name] = {
                "id": boot.CONTAINERS[key],
                "image": image.split("@", 1)[-1],
                "network": names["network"],
                "networks": {names["network"]: {}},
                "ports": None,
                "readonly": True,
                "caps": ["ALL"],
                "privileged": False,
                "memory": memory,
                "swap": memory,
                "cpus": cpus,
                "labels": {
                    epoch.EPOCH_LABEL: boot.OWNER,
                    "com.kairos.runtime-epoch.scope": epoch.EPOCH_SCOPE,
                },
                "state": {"Status": "exited"},
            }
        return views

    def _resource_controller(self, views):
        controller = boot.BootController.__new__(boot.BootController)
        controller.names = epoch.resource_names(boot.OWNER)
        controller.owner = boot.OWNER
        controller.created, controller.proofs = [], {}
        controller.inspect_container = mock.Mock(side_effect=lambda name: views[name])
        controller.assert_legacy_sources_stopped = mock.Mock(
            return_value={"state": "stopped"}
        )
        controller.require_mount_set = mock.Mock()
        controller.docker = mock.Mock(
            side_effect=lambda args: '{"Name":"no"}' if args[0] == "inspect" else ""
        )
        return controller

    def test_exact_original_resources_admitted_without_starting_anything(self):
        controller = self._resource_controller(self._resources())
        controller.validate_resources()
        self.assertEqual(controller.require_mount_set.call_count, 3)
        self.assertTrue(
            all(
                call.args[0][0] in {"inspect", "ps"}
                for call in controller.docker.call_args_list
            )
        )

    def test_resource_id_image_privileges_ports_limits_and_other_network_rejected(self):
        damages = {
            "id": "f" * 64,
            "image": "sha256:" + "f" * 64,
            "network": "host",
            "networks": {"foreign": {}},
            "ports": {"5432": {}},
            "readonly": False,
            "caps": [],
            "privileged": True,
            "memory": 0,
            "swap": 0,
            "cpus": 0,
            "labels": {},
            "state": {"Status": "restarting"},
        }
        for field, damage in damages.items():
            views = self._resources()
            views[epoch.resource_names(boot.OWNER)["target_pg"]][field] = damage
            controller = self._resource_controller(views)
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    epoch.Rejected, "BOOT_EXACT_EXISTING_RESOURCE_REQUIRED"
                ),
            ):
                controller.validate_resources()
            controller.require_mount_set.assert_not_called()

    def test_unconditional_docker_restart_policy_refused(self):
        controller = self._resource_controller(self._resources())
        controller.docker = mock.Mock(return_value='{"Name":"always"}')
        with self.assertRaisesRegex(epoch.Rejected, "ONLY_GUARDED_BOOT_STARTS_ALLOWED"):
            controller.validate_resources()

    def test_foreign_kairos_process_blocks_start(self):
        controller = self._resource_controller(self._resources())
        controller.docker = mock.Mock(
            side_effect=lambda args: (
                '{"Name":"no"}'
                if args[0] == "inspect"
                else "kairos-paper-gate-execution-engine-1"
            )
        )
        with self.assertRaisesRegex(
            epoch.Rejected, "BOOT_OTHER_KAIROS_PROCESS_RUNNING"
        ):
            controller.validate_resources()

    def test_pinned_isolated_standby_is_observed_without_mutation(self):
        views = self._resources()
        views[boot.STANDBY_NAME] = {
            "id": boot.STANDBY_ID,
            "image": epoch.PG_IMAGE.split("@", 1)[-1],
            "labels": {
                "com.docker.compose.project": "kairos-shadow-gate",
                "com.docker.compose.service": "timescaledb",
            },
            "network": boot.STANDBY_NETWORK,
            "networks": {boot.STANDBY_NETWORK: {}},
            "ports": {},
            "privileged": False,
            "state": {
                "Status": "running",
                "Health": {
                    "Status": "healthy",
                    "FailingStreak": 0,
                    "Log": [
                        {
                            "Start": "2026-10-12T01:00:00.000000000Z",
                            "End": "2026-10-12T01:00:01.000000000Z",
                            "ExitCode": 0,
                            "Output": "ready",
                        }
                    ],
                },
            },
            "mounts": [],
        }
        controller = self._resource_controller(views)
        controller.docker = mock.Mock(
            side_effect=lambda args: (
                '{"Name":"no"}' if args[0] == "inspect" else boot.STANDBY_NAME
            )
        )
        result = controller.validate_resources()
        self.assertTrue(result["standby"]["left_untouched"])
        self.assertEqual(
            result["standby"]["metadata"],
            boot.stable_standby_metadata(views[boot.STANDBY_NAME]),
        )
        self.assertTrue(
            all(
                call.args[0][0] in {"inspect", "ps"}
                for call in controller.docker.call_args_list
            )
        )
        for field, damage in (
            ("id", "0" * 64),
            ("network", controller.names["network"]),
            ("networks", {"foreign": {}}),
            ("ports", {"5432": {}}),
        ):
            bad = copy.deepcopy(views)
            bad[boot.STANDBY_NAME][field] = damage
            controller.inspect_container = mock.Mock(
                side_effect=lambda name, snapshot=bad: snapshot[name]
            )
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    epoch.Rejected, "BOOT_STANDBY_DATABASE_ISOLATION_CONFLICT"
                ),
            ):
                controller.validate_resources()

    def test_default_does_not_execute_or_read_private_inputs(self):
        with mock.patch.object(boot.BootController, "run_boot") as run:
            self.assertEqual(boot.main([]), 0)
        run.assert_not_called()

    def test_invalid_boot_id_refused_before_private_files(self):
        with mock.patch.object(boot, "read_json") as read:
            self.assertEqual(boot.main(["--execute", "--boot-id", "unsafe"]), 1)
        read.assert_not_called()

    def test_extra_or_removed_queue_rows_rejected(self):
        for table in ("message_outbox", "message_inbox", "source_cursors"):
            after = copy.deepcopy(state())
            after["tables"][table]["count"] += 1
            with (
                self.subTest(table=table),
                self.assertRaisesRegex(epoch.Rejected, "BOOT_CHANGED_EXISTING_QUEUES"),
            ):
                boot.validate_preserved_state(state(), after)

    def test_sequences_may_not_be_reset_or_incremented_during_history_only_append(self):
        after = copy.deepcopy(state())
        after["sequences"]["message_outbox_id_seq"]["last_value"] += 1
        with self.assertRaisesRegex(epoch.Rejected, "BOOT_CHANGED_EXISTING_SEQUENCES"):
            boot.validate_preserved_state(state(), after)

    def test_only_audit_can_grow(self):
        after = copy.deepcopy(state())
        after["tables"]["event_audit"]["count"] += 100
        boot.validate_preserved_state(state(), after)

    def test_audit_rollback_and_original_prefix_conflict_rejected(self):
        after = copy.deepcopy(state())
        after["tables"]["event_audit"]["count"] -= 1
        with self.assertRaisesRegex(epoch.Rejected, "AUDIT_HISTORY_ROLLBACK"):
            boot.validate_preserved_state(state(), after)
        after = copy.deepcopy(state())
        after["original_prefix"]["sha256"] = "b" * 64
        with self.assertRaisesRegex(epoch.Rejected, "PREFIX_OR_STATE_CONFLICT"):
            boot.validate_preserved_state(state(), after)

    def test_failed_state_cannot_be_promoted(self):
        after = {**state(), "state": "FAILED_CLOSED"}
        with self.assertRaises(epoch.Rejected):
            boot.validate_preserved_state(state(), after)

    def test_native_metadata_not_part_of_comparable_snapshot(self):
        value = {
            **state(),
            "mode": "boot-state",
            "owner": boot.OWNER,
            "new_epoch_database": "test",
        }
        self.assertEqual(boot.core_snapshot(value), state())

    def test_bounded_json_rejects_array_and_oversize(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            with path.open("w") as stream:
                json.dump([], stream)
            with self.assertRaisesRegex(epoch.Rejected, "BOOT_JSON_OBJECT_REQUIRED"):
                boot.read_json(path)
            with self.assertRaisesRegex(epoch.Rejected, "BOUNDED_BOOT_JSON_REQUIRED"):
                boot.read_json(path, limit=1)

    def test_no_docker_policy_update_or_old_queue_start_in_source(self):
        text = Path(boot.__file__).read_text()
        self.assertNotIn('["update"', text)
        self.assertNotIn('["start", fresh.SOURCE', text)
        self.assertNotIn("reset_leases", text)
        self.assertNotIn("--force", text)

    def test_worker_boot_modes_do_not_change_legacy_mode_config(self):
        common = {
            "owner": boot.OWNER,
            "database": "kairos_epoch_" + boot.OWNER[:12],
            "pg_host": epoch.resource_names(boot.OWNER)["target_pg"],
            "redis_host": epoch.resource_names(boot.OWNER)["redis"],
            "admin_password": "a" * 64,
        }
        epoch.validate_worker_config(common, mode="boot-state")
        for mode in (
            "boot-state",
            "boot-catchup",
            "boot-verify-restore",
            "boot-redis-state",
        ):
            epoch.build_worker_argv(
                mode, epoch.CONFIG_PATH_IN_CONTAINER, epoch.OUTPUT_PATH_IN_CONTAINER
            )
        with self.assertRaises(epoch.Rejected):
            epoch.validate_worker_config(
                {**common, "expected_seed": {}}, mode="history-state"
            )

    def test_cleanup_does_not_stop_preexisting_serve_on_admission_rejection(self):
        controller = boot.BootController.__new__(boot.BootController)
        controller.created, controller.proofs = [], {}
        controller.names = epoch.resource_names(boot.OWNER)
        with mock.patch.object(controller, "docker") as docker:
            controller.fail_closed_cleanup()
        docker.assert_not_called()

    def test_failed_or_active_lease_refused_before_controller(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            binding = root / "binding.json"
            with binding.open("w") as stream:
                json.dump({"revision": "a" * 40}, stream)
            lease = root / "boot.active"
            lease.touch()
            with (
                mock.patch.object(boot, "ROOT", root),
                mock.patch.object(boot, "LEASE", lease),
                mock.patch.object(boot, "IS_WINDOWS", True),
                mock.patch.object(boot, "validate_binding"),
                mock.patch.object(boot, "verify_source"),
                mock.patch.object(boot, "BootController") as controller,
            ):
                self.assertEqual(
                    boot.main(
                        [
                            "--execute",
                            "--boot-id",
                            "638957743065000000",
                            "--binding",
                            str(binding),
                            "--binding-sha256",
                            boot.fresh.sha(binding),
                        ]
                    ),
                    1,
                )
            controller.assert_not_called()

    def test_binding_private_directory_is_created_once_and_never_overwritten(self):
        with TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "boot"
            accepted = parent / "accepted"
            accepted.mkdir()
            receipt = accepted / "runtime-epoch-continuation-receipt.json"
            receipt.write_bytes(b"{}")
            with (
                mock.patch.object(boot, "ROOT", root),
                mock.patch.object(boot, "SERVE_WORK", accepted),
                mock.patch.object(
                    boot, "PARENT_RECEIPT_SHA256", boot.fresh.sha(receipt)
                ),
                mock.patch.object(boot, "verify_source"),
                mock.patch.object(boot, "git", return_value=""),
                mock.patch.object(boot, "input_paths", return_value=[]),
                mock.patch.object(boot, "validate_binding"),
                mock.patch.object(
                    epoch,
                    "_private_directory",
                    side_effect=lambda path: path.mkdir(parents=True, exist_ok=False),
                ) as private,
            ):
                binding = boot.create_binding("a" * 40)
                private.assert_called_once_with(root)
                original = binding.read_bytes()
                with self.assertRaises(FileExistsError):
                    boot.create_binding("a" * 40)
                self.assertEqual(binding.read_bytes(), original)

    def test_execute_creates_private_run_once_and_releases_only_successful_lease(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            binding = root / "binding.json"
            binding.write_text(json.dumps({"revision": "a" * 40}))
            lease = root / "boot.active"
            run = "b" * 32
            work = root / "runs" / run
            with (
                mock.patch.object(boot, "ROOT", root),
                mock.patch.object(boot, "LEASE", lease),
                mock.patch.object(boot, "IS_WINDOWS", True),
                mock.patch.object(boot, "validate_binding"),
                mock.patch.object(boot, "verify_source"),
                mock.patch.object(boot.uuid, "uuid4", return_value=mock.Mock(hex=run)),
                mock.patch.object(
                    epoch,
                    "_private_directory",
                    side_effect=lambda path: path.mkdir(parents=True, exist_ok=False),
                ) as private,
                mock.patch.object(boot, "BootController") as controller,
            ):
                controller.return_value.run_boot.return_value = {
                    "result": "PASS_NONTRADING_EPOCH_BOOT",
                    "trading_started": False,
                }
                self.assertEqual(
                    boot.main(
                        [
                            "--execute",
                            "--boot-id",
                            "638957743065000000",
                            "--binding",
                            str(binding),
                            "--binding-sha256",
                            boot.fresh.sha(binding),
                        ]
                    ),
                    0,
                )
                private.assert_called_once_with(work)
                controller.return_value.fail_closed_cleanup.assert_not_called()
            self.assertFalse(lease.exists())
            accepted = json.loads((work / "boot-receipt.json").read_bytes())
            self.assertEqual(accepted["source_revision"], "a" * 40)
            self.assertFalse(accepted["trading_started"])


if __name__ == "__main__":
    unittest.main()
