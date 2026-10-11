from __future__ import annotations

import copy
import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from scripts import runtime_epoch_controller as epoch

OWNER = "0123456789abcdef0123456789abcdef"
HEX_SECRET = "a" * 64
ANCHOR_OPEN = 1_789_832_580_000  # 2026-09-19T15:43:00Z


def seed_receipt(anchor_open: int = ANCHOR_OPEN) -> dict:
    return {
        "anchors": {
            symbol: {
                "count": 34_633 if symbol != "XRPUSDT" else 34_632,
                "first_open_time_ms": anchor_open - 2_078_000_000,
                "last_open_time_ms": anchor_open,
                "last_close_time_ms": anchor_open + epoch.MINUTE_MS - 1,
            }
            for symbol in epoch.SYMBOLS
        }
    }


def config(mode: str, **overrides: object) -> dict:
    common = {
        "owner": OWNER,
        "database": "kairos_epoch_0123456789ab",
        "pg_host": "kairos-epoch-0123456789ab-pg",
        "redis_host": "kairos-epoch-0123456789ab-redis",
    }
    values = {
        "prepare": {
            "admin_password": HEX_SECRET,
            "source_host": "kairos-epoch-0123456789ab-source",
            "source_database": "kairos",
            "source_admin_password": "b" * 64,
            "source_password": "c" * 64,
            "history_password": "d" * 64,
            "producer_password": "e" * 64,
            "consumer_password": "f" * 64,
        },
        "seed": {
            "source_host": "kairos-epoch-0123456789ab-source",
            "source_database": "kairos",
            "source_password": "c" * 64,
            "history_password": "d" * 64,
            "seed_expectation": {"bars": 1},
            "source_dump_sha256": epoch.DUMP_SHA256,
        },
        "catchup": {
            "history_password": "d" * 64,
            "end_exclusive_ms": 1_791_680_280_000,
            "maximum_bars": epoch.MAX_CATCHUP_BARS,
        },
        "rotate-history": {
            "admin_password": HEX_SECRET,
            "history_password": "d" * 64,
        },
        "history-state": {"admin_password": HEX_SECRET},
        "verify-restore": {
            "admin_password": HEX_SECRET,
            "restore_host": "kairos-epoch-0123456789ab-restore",
            "restore_database": "kairos_recovery_0123456789ab_epochrestore",
            "restore_admin_password": "b" * 64,
            "expected_seed": {"bars": 1},
        },
        "qualify": {
            "producer_password": "e" * 64,
            "consumer_password": "f" * 64,
            "redis_producer_password": "1" * 64,
            "redis_consumer_password": "2" * 64,
        },
        "serve": {
            "producer_password": "e" * 64,
            "consumer_password": "f" * 64,
            "redis_producer_password": "1" * 64,
            "redis_consumer_password": "2" * 64,
        },
    }
    return {**common, **values[mode], **overrides}


class RuntimeEpochControllerTests(unittest.TestCase):
    def test_attempt_02_initializer_has_fowner_and_tmpfs_for_image_pg_volume(self):
        controller = epoch.EpochController.__new__(epoch.EpochController)
        controller.owner = OWNER
        controller.names = epoch.resource_names(OWNER)
        controller.continuation_attempt = "02"
        controller.created = []
        commands = []

        def docker(args, **_kwargs):
            commands.append(args)
            if args[:3] == ["inspect", "--format", "{{json .HostConfig.Tmpfs}}"]:
                return json.dumps(
                    {"/var/lib/postgresql/data": "rw,nosuid,nodev,noexec,size=1m"}
                )
            return ""

        controller.docker = docker
        controller.inspect_container = lambda _name: {
            "state": {"ExitCode": 0, "Running": False}
        }
        controller.initialize_volume(controller.names["restore_volume"], uid=70)

        create = commands[0]
        self.assertEqual(
            create[create.index("--cap-add=CHOWN") + 1], "--cap-add=FOWNER"
        )
        self.assertIn("/var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=1m", create)
        self.assertIn(
            "kairos-epoch-" + OWNER[:12] + "-volume-init-70-continue-02", create
        )
        self.assertNotIn(
            "kairos-epoch-" + OWNER[:12] + "-volume-init-70-continue-01", create
        )
        self.assertEqual(
            commands[-1],
            ["rm", "kairos-epoch-" + OWNER[:12] + "-volume-init-70-continue-02"],
        )
        self.assertEqual(controller.created, [])

    def test_attempt_01_failure_admission_requires_exact_frozen_receipt(self):
        with TemporaryDirectory() as directory:
            receipt = Path(directory) / "runtime-epoch-failure.json"
            receipt.write_text(
                json.dumps(
                    {
                        "owner": epoch.CONTINUATION_OWNER,
                        "phase": "ADMISSION",
                        "error_category": "Rejected",
                        "created_resources": [
                            "kairos-epoch-69893dc7b7c6-volume-init-70"
                        ],
                        "active_lease_preserved": True,
                        "trading_started": False,
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(
                epoch, "_sha", return_value=epoch.CONTINUATION_01_FAILURE_SHA256
            ):
                epoch.validate_attempt_01_initializer_failure(
                    owner=epoch.CONTINUATION_OWNER,
                    receipt_path=receipt,
                    expected_sha256=epoch.CONTINUATION_01_FAILURE_SHA256,
                )
                with self.assertRaises(epoch.Rejected):
                    epoch.validate_attempt_01_initializer_failure(
                        owner=epoch.CONTINUATION_OWNER,
                        receipt_path=receipt,
                        expected_sha256="0" * 64,
                    )

    def test_attempt_02_backup_failure_is_bound_to_receipt_stderr_and_cleanup_proof(
        self,
    ):
        owner = epoch.CONTINUATION_OWNER
        with TemporaryDirectory() as directory:
            attempt02 = Path(directory) / "continuation-02"
            attempt02.mkdir()
            failure = attempt02 / "runtime-epoch-failure.json"
            failure.write_text(
                json.dumps(
                    {
                        "owner": owner,
                        "phase": "ADMISSION",
                        "error_category": "Rejected",
                        "created_resources": [],
                        "active_lease_preserved": True,
                        "trading_started": False,
                    }
                ),
                encoding="utf-8",
            )
            stderr = attempt02 / "cli-025.stderr"
            stderr.write_bytes(b"synthetic immutable docker-cp failure\n")
            evidence = attempt02 / "attempt-01-initializer-evidence.json"
            evidence.write_text(
                json.dumps(
                    {
                        "owner": owner,
                        "attempt_01_failure_sha256": epoch.CONTINUATION_01_FAILURE_SHA256,
                        "helper_name": "kairos-epoch-69893dc7b7c6-volume-init-70",
                        "helper_container_id": "1" * 64,
                        "image": epoch.PG_IMAGE,
                        "state": "exited",
                        "exit_code": 1,
                        "cap_add": ["CAP_CHOWN"],
                        "network_mode": "none",
                        "mounts": [
                            [
                                "volume",
                                epoch.CONTINUATION_01_ANONYMOUS_VOLUME,
                                "/var/lib/postgresql/data",
                                True,
                            ],
                            [
                                "volume",
                                epoch.resource_names(owner)["restore_volume"],
                                "/owned",
                                True,
                            ],
                        ],
                        "anonymous_volume": epoch.CONTINUATION_01_ANONYMOUS_VOLUME,
                        "failed_operation": "chmod_owned_volume_permission_denied",
                        "log_sha256": epoch.CONTINUATION_01_LOG_SHA256,
                        "raw_log_preserved": False,
                    }
                ),
                encoding="utf-8",
            )
            hash_by_name = {
                failure.name: epoch.CONTINUATION_02_FAILURE_SHA256,
                stderr.name: epoch.CONTINUATION_02_LOG_SHA256,
                evidence.name: epoch.CONTINUATION_02_ATTEMPT_01_EVIDENCE_SHA256,
            }
            with patch.object(
                epoch, "_sha", side_effect=lambda path: hash_by_name[path.name]
            ):
                result = epoch.validate_attempt_02_backup_failure(
                    owner=owner,
                    attempt02_work=attempt02,
                    expected_sha256=epoch.CONTINUATION_02_FAILURE_SHA256,
                )
                self.assertEqual(
                    result,
                    {
                        "failure_sha256": epoch.CONTINUATION_02_FAILURE_SHA256,
                        "stderr_sha256": epoch.CONTINUATION_02_LOG_SHA256,
                        "attempt_01_initializer_evidence_sha256": epoch.CONTINUATION_02_ATTEMPT_01_EVIDENCE_SHA256,
                    },
                )
                with self.assertRaises(epoch.Rejected):
                    epoch.validate_attempt_02_backup_failure(
                        owner=owner,
                        attempt02_work=attempt02,
                        expected_sha256="0" * 64,
                    )

    def test_binary_pg_dump_stream_is_exclusive_bounded_and_job_assigned(self):
        for backup_name in (
            "epoch-history.dump",
            "epoch-history-precontinuation.dump",
            "epoch-history-postcatchup.dump",
            "epoch-history-bootbefore.dump",
            "epoch-history-bootafter.dump",
        ):
            with self.subTest(backup_name=backup_name):
                self._assert_exclusive_bounded_binary_pg_dump(backup_name)

    def _assert_exclusive_bounded_binary_pg_dump(self, backup_name):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docker-config").mkdir()
            controller = object.__new__(epoch.EpochController)
            controller.owner = OWNER
            controller.names = epoch.resource_names(OWNER)
            controller.work = root
            controller.deadline = epoch.time.monotonic() + 600
            events = []

            class FakeJob:
                creation_flags = 123

                def attach_and_resume(self, process):
                    events.append(("attach", process))

                def close(self):
                    events.append(("close",))

            controller.native = SimpleNamespace(
                work=root,
                sequence=0,
                operations=[],
                module=SimpleNamespace(WindowsProcessJob=FakeJob),
            )

            class FakeProcess:
                returncode = 0

                def poll(self):
                    return self.returncode

            process = FakeProcess()

            def popen(command, **kwargs):
                events.append(("popen", command, kwargs["creationflags"]))
                kwargs["stdout"].write(b"PGDMP\x00binary")
                kwargs["stderr"].write(b"diagnostic\n")
                return process

            def finish(job, actual_process, _deadline, *, cancel):
                self.assertEqual(events[0], ("popen", events[0][1], 123))
                self.assertEqual(events[1], ("attach", process))
                self.assertIs(actual_process, process)
                self.assertFalse(cancel)
                return {"assigned_before_resume": True, "active_processes_after": 0}

            backup = root / backup_name
            with (
                patch.object(
                    epoch.subprocess, "Popen", side_effect=popen
                ) as popen_mock,
                patch.object(epoch.fresh.bounded, "bounded_finish", side_effect=finish),
            ):
                result = controller.stream_private_pg_dump(
                    backup=backup, database="kairos_epoch_0123456789ab"
                )
            self.assertEqual(backup.read_bytes(), b"PGDMP\x00binary")
            self.assertEqual(result["binary_stdout_bytes"], len(b"PGDMP\x00binary"))
            self.assertEqual(
                result["sha256"], epoch.hashlib.sha256(b"PGDMP\x00binary").hexdigest()
            )
            command = popen_mock.call_args.args[0]
            self.assertEqual(
                command[command.index("exec") + 1], controller.names["target_pg"]
            )
            timeout_index = command.index("exec") + 2
            self.assertEqual(
                command[timeout_index : timeout_index + 4],
                [
                    "/usr/bin/timeout",
                    "-s",
                    "KILL",
                    str(epoch.EPOCH_DUMP_TIMEOUT_SECONDS - 5),
                ],
            )
            self.assertNotIn("-t", command)
            self.assertNotIn("--interactive", command)
            self.assertEqual(command[-1], "--dbname=kairos_epoch_0123456789ab")
            self.assertFalse(any("--file=" in item or item == "cp" for item in command))
            self.assertIn(("close",), events)
            self.assertEqual(
                controller.native.operations[0]["sha256"], result["sha256"]
            )
            with (
                patch.object(epoch.subprocess, "Popen") as duplicate_mock,
                self.assertRaisesRegex(
                    epoch.Rejected, "PRIVATE_CREATE_ONLY_EPOCH_DUMP_REQUIRED"
                ),
            ):
                controller.stream_private_pg_dump(
                    backup=backup, database="kairos_epoch_0123456789ab"
                )
            duplicate_mock.assert_not_called()
            self.assertEqual(backup.read_bytes(), b"PGDMP\x00binary")

    def test_binary_pg_dump_rejects_unbound_names_database_and_directory(self):
        for case in ("unknown_name", "foreign_database", "foreign_directory"):
            with self.subTest(case=case), TemporaryDirectory() as directory:
                root = Path(directory)
                foreign = root / "foreign"
                foreign.mkdir()
                controller = object.__new__(epoch.EpochController)
                controller.owner = OWNER
                controller.work = root
                controller.native = SimpleNamespace(work=root)
                backup = root / "epoch-history-bootbefore.dump"
                database = "kairos_epoch_0123456789ab"
                if case == "unknown_name":
                    backup = root / "epoch-history-arbitrary.dump"
                elif case == "foreign_database":
                    database = "kairos_epoch_ffffffffffff"
                else:
                    backup = foreign / backup.name
                with (
                    patch.object(epoch.subprocess, "Popen") as popen_mock,
                    self.assertRaisesRegex(
                        epoch.Rejected, "PRIVATE_CREATE_ONLY_EPOCH_DUMP_REQUIRED"
                    ),
                ):
                    controller.stream_private_pg_dump(backup=backup, database=database)
                popen_mock.assert_not_called()
                self.assertFalse(backup.exists())

    def test_binary_pg_dump_failure_keeps_partial_archive_without_echoing_stderr(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docker-config").mkdir()
            controller = object.__new__(epoch.EpochController)
            controller.owner = OWNER
            controller.names = epoch.resource_names(OWNER)
            controller.work = root
            controller.deadline = epoch.time.monotonic() + 600

            class FakeJob:
                creation_flags = 0

                def attach_and_resume(self, _process):
                    pass

                def close(self):
                    pass

            controller.native = SimpleNamespace(
                work=root,
                sequence=0,
                operations=[],
                module=SimpleNamespace(WindowsProcessJob=FakeJob),
            )

            class FailedProcess:
                returncode = 1

                def poll(self):
                    return self.returncode

            def popen(_command, **kwargs):
                kwargs["stdout"].write(b"partial-PGDMP")
                kwargs["stderr"].write(b"private driver message")
                return FailedProcess()

            backup = root / "epoch-history.dump"
            with (
                patch.object(epoch.subprocess, "Popen", side_effect=popen),
                patch.object(
                    epoch.fresh.bounded,
                    "bounded_finish",
                    return_value={
                        "assigned_before_resume": True,
                        "active_processes_after": 0,
                    },
                ),
                self.assertRaisesRegex(
                    epoch.Rejected, "BOUNDED_BINARY_EPOCH_DUMP_FAILED"
                ),
            ):
                controller.stream_private_pg_dump(
                    backup=backup, database="kairos_epoch_0123456789ab"
                )
            self.assertEqual(backup.read_bytes(), b"partial-PGDMP")
            self.assertNotIn(
                "private driver message", str(controller.native.operations)
            )

    def test_binary_pg_dump_cancels_job_for_stream_bounds_and_timeout(self):
        for case in ("stdout", "stderr", "timeout"):
            with self.subTest(case=case), TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "docker-config").mkdir()
                controller = object.__new__(epoch.EpochController)
                controller.owner = OWNER
                controller.names = epoch.resource_names(OWNER)
                controller.work = root
                controller.deadline = 10_000
                events = []

                class FakeJob:
                    creation_flags = 0

                    def attach_and_resume(self, _process, event_log=events):
                        event_log.append("assigned-and-resumed")

                    def close(self, event_log=events):
                        event_log.append("closed")

                controller.native = SimpleNamespace(
                    work=root,
                    sequence=0,
                    operations=[],
                    module=SimpleNamespace(WindowsProcessJob=FakeJob),
                )

                class RunningProcess:
                    returncode = None

                    def poll(self):
                        return None

                process = RunningProcess()

                def popen(_command, _case=case, _process=process, **kwargs):
                    if _case == "stdout":
                        kwargs["stdout"].write(b"exceeds")
                        kwargs["stdout"].flush()
                    elif _case == "stderr":
                        kwargs["stderr"].write(b"exceeds")
                        kwargs["stderr"].flush()
                    return _process

                def finish(
                    _job, actual_process, _deadline, *, cancel, expected_process=process
                ):
                    self.assertIs(actual_process, expected_process)
                    self.assertTrue(cancel)
                    return {
                        "assigned_before_resume": True,
                        "active_processes_after": 0,
                    }

                tick = iter((100.0, 100.0, 106.0, 106.0, 106.0, 106.0))
                with (
                    patch.object(epoch.subprocess, "Popen", side_effect=popen),
                    patch.object(
                        epoch.fresh.bounded, "bounded_finish", side_effect=finish
                    ),
                    patch.object(
                        epoch,
                        "MAX_EPOCH_DUMP_BYTES",
                        3 if case == "stdout" else epoch.MAX_EPOCH_DUMP_BYTES,
                    ),
                    patch.object(
                        epoch,
                        "MAX_EPOCH_DUMP_STDERR_BYTES",
                        3 if case == "stderr" else epoch.MAX_EPOCH_DUMP_STDERR_BYTES,
                    ),
                    patch.object(
                        epoch,
                        "EPOCH_DUMP_TIMEOUT_SECONDS",
                        5 if case == "timeout" else epoch.EPOCH_DUMP_TIMEOUT_SECONDS,
                    ),
                    patch.object(
                        epoch.time,
                        "monotonic",
                        side_effect=lambda values=tick: next(values, 106.0),
                    ),
                    self.assertRaisesRegex(
                        epoch.Rejected, "BOUNDED_BINARY_EPOCH_DUMP_FAILED"
                    ),
                ):
                    controller.stream_private_pg_dump(
                        backup=root / "epoch-history.dump",
                        database="kairos_epoch_0123456789ab",
                    )
                self.assertIn("assigned-and-resumed", events)
                self.assertIn("closed", events)
                self.assertTrue((root / "epoch-history.dump").exists())
                self.assertTrue((root / "cli-001.stderr").exists())

    def test_owner_names_are_exact_and_resources_are_separate(self):
        names = epoch.resource_names(OWNER)
        self.assertNotEqual(names["target_volume"], names["source_volume"])
        self.assertNotEqual(names["target_volume"], names["redis_volume"])
        self.assertTrue(
            all(
                name.startswith("kairos-epoch-0123456789ab-") for name in names.values()
            )
        )
        for invalid in ("../x", OWNER.upper(), "1" * 31, None):
            with self.assertRaises(epoch.Rejected):
                epoch.owner_name(invalid)  # type: ignore[arg-type]

    def test_phase_config_is_exact_and_secret_bearing_fields_are_hex(self):
        for mode in (
            "prepare",
            "seed",
            "catchup",
            "rotate-history",
            "history-state",
            "verify-restore",
            "qualify",
            "serve",
        ):
            with self.subTest(mode=mode):
                checked = epoch.validate_worker_config(config(mode), mode=mode)
                self.assertEqual(checked["owner"], OWNER)
                with self.assertRaises(epoch.Rejected):
                    epoch.validate_worker_config(
                        {**config(mode), "unexpected": "secret"}, mode=mode
                    )

    def test_attempt_04_history_state_requires_exact_prefix_queues_and_anchor_totals(
        self,
    ):
        last_open = epoch.CONTINUATION_04_ORIGINAL_LAST_OPEN_MS + 600 * epoch.MINUTE_MS
        first_open = last_open - 10_000 * epoch.MINUTE_MS
        anchors = {
            symbol: {
                "count": 35_270 if symbol != "XRPUSDT" else 35_268,
                "first_open_time_ms": first_open,
                "last_open_time_ms": last_open,
                "last_close_time_ms": last_open + epoch.MINUTE_MS - 1,
            }
            for symbol in epoch.SYMBOLS
        }
        value = {
            "owner": epoch.CONTINUATION_OWNER,
            "mode": "history-state",
            "new_epoch_database": "kairos_epoch_" + epoch.CONTINUATION_OWNER[:12],
            "state": "VERIFIED_AUDIT_ONLY_HISTORY_STATE",
            "rows": epoch.CONTINUATION_04_CURRENT_AUDIT_ROWS,
            "audit_table_sha256": "a" * 64,
            "anchors": anchors,
            "original_prefix": {
                "rows": epoch.CONTINUATION_04_ORIGINAL_PREFIX_ROWS,
                "audit_table_sha256": epoch.CONTINUATION_04_ORIGINAL_PREFIX_TABLE_SHA256,
                "last_open_time_ms": epoch.CONTINUATION_04_ORIGINAL_LAST_OPEN_MS,
            },
            "outbox_rows": 0,
            "inbox_rows": 0,
            "orders_rows": 0,
            "effects_rows": 0,
            "matched_public_tables": 32,
            "trading_started": False,
        }
        with (
            patch.object(epoch, "CONTINUATION_04_CURRENT_AUDIT_SHA256", "a" * 64),
            patch.object(epoch, "CONTINUATION_04_CURRENT_ANCHORS", anchors),
        ):
            self.assertEqual(
                epoch.validate_attempt_04_history_state(
                    value, owner=epoch.CONTINUATION_OWNER
                ),
                value,
            )
            for invalid in (
                {**value, "outbox_rows": 1},
                {**value, "matched_public_tables": 39},
                {**value, "original_prefix": {**value["original_prefix"], "rows": 1}},
                {
                    **value,
                    "anchors": {
                        **anchors,
                        "BTCUSDT": {**anchors["BTCUSDT"], "count": 35_269},
                    },
                },
            ):
                with self.assertRaises(epoch.Rejected):
                    epoch.validate_attempt_04_history_state(
                        invalid, owner=epoch.CONTINUATION_OWNER
                    )

    def test_attempt_04_failure_validator_pins_receipts_worker_config_and_dump(self):
        with TemporaryDirectory() as directory:
            attempt04 = Path(directory) / "continuation-04"
            paths = {
                "failure": attempt04 / "runtime-epoch-failure.json",
                "operator": attempt04 / "operator.zip",
                "dump": attempt04 / "epoch-history-precontinuation.dump",
                "verify": attempt04
                / "output-verify-restore-precontinuation"
                / "verify-restore.json",
                "rotation": attempt04
                / "output-rotate-history-history-credential"
                / "rotate-history.json",
                "status": attempt04 / "output-catchup-continue-01" / "status.json",
                "config": attempt04 / "config-catchup-continue-01.json",
            }
            for key in ("verify", "rotation", "status"):
                paths[key].parent.mkdir(parents=True, exist_ok=True)
            failure_value = {
                "owner": epoch.CONTINUATION_OWNER,
                "phase": "catchup-continue-01",
                "error_category": "WORKER_MODE_FAILED_CATCHUP",
                "active_lease_preserved": True,
                "trading_started": False,
            }
            rotation_value = {
                "owner": epoch.CONTINUATION_OWNER,
                "state": "HISTORY_CREDENTIAL_ROTATED",
                "credential_rotated": True,
            }
            for path, value, size in (
                (paths["failure"], failure_value, 1_162),
                (paths["rotation"], rotation_value, 258),
            ):
                payload = json.dumps(value, sort_keys=True).encode("utf-8")
                self.assertLess(len(payload), size)
                path.write_bytes(payload + b" " * (size - len(payload)))
            paths["operator"].write_bytes(b"x" * 37_039)
            with paths["dump"].open("wb") as stream:
                stream.truncate(20_692_780)
            paths["verify"].write_bytes(b"v" * 4_675)
            paths["status"].write_bytes(b"s" * 204)
            paths["config"].write_bytes(b"c" * 342)
            hashes = {
                paths["failure"]: epoch.CONTINUATION_04_FAILURE_SHA256,
                paths["operator"]: epoch.CONTINUATION_04_OPERATOR_SHA256,
                paths["dump"]: epoch.CONTINUATION_04_PREBACKUP_DUMP_SHA256,
                paths["verify"]: epoch.CONTINUATION_04_PREBACKUP_VERIFY_SHA256,
                paths["rotation"]: epoch.CONTINUATION_04_ROTATION_RECEIPT_SHA256,
                paths["status"]: epoch.CONTINUATION_04_CATCHUP_STATUS_SHA256,
                paths["config"]: epoch.CONTINUATION_04_CATCHUP_CONFIG_SHA256,
            }
            with patch.object(epoch, "_sha", side_effect=lambda path: hashes[path]):
                result = epoch.validate_attempt_04_partial_catchup_failure(
                    owner=epoch.CONTINUATION_OWNER,
                    attempt04_work=attempt04,
                    expected_sha256=epoch.CONTINUATION_04_FAILURE_SHA256,
                )
                self.assertEqual(result["worker_id"], epoch.CONTINUATION_04_WORKER_ID)
                with self.assertRaises(epoch.Rejected):
                    epoch.validate_attempt_04_partial_catchup_failure(
                        owner=epoch.CONTINUATION_OWNER,
                        attempt04_work=attempt04,
                        expected_sha256="0" * 64,
                    )

    def test_attempt_05_prebackup_failure_never_repeats_rotation_or_catchup(self):
        with TemporaryDirectory() as directory:
            controller, seed, old_private = self._continuation_fixture(directory)
            controller.continuation_attempt = "05"
            controller.work = Path(directory) / "continuation-05"
            controller.work.mkdir()
            attempt01 = Path(directory) / "continuation-01"
            attempt02 = Path(directory) / "continuation-02"
            attempt03 = Path(directory) / "continuation-03"
            attempt04 = Path(directory) / "continuation-04"
            for path in (attempt01, attempt02, attempt03, attempt04):
                path.mkdir()
            history_state = {
                "owner": controller.owner,
                "mode": "history-state",
                "new_epoch_database": old_private["database"],
                "state": "VERIFIED_AUDIT_ONLY_HISTORY_STATE",
                "rows": epoch.CONTINUATION_04_CURRENT_AUDIT_ROWS,
                "audit_table_sha256": epoch.CONTINUATION_04_CURRENT_AUDIT_SHA256,
                "anchors": epoch.CONTINUATION_04_CURRENT_ANCHORS,
                "original_prefix": {
                    "rows": epoch.CONTINUATION_04_ORIGINAL_PREFIX_ROWS,
                    "audit_table_sha256": epoch.CONTINUATION_04_ORIGINAL_PREFIX_TABLE_SHA256,
                    "last_open_time_ms": epoch.CONTINUATION_04_ORIGINAL_LAST_OPEN_MS,
                },
                "outbox_rows": 0,
                "inbox_rows": 0,
                "orders_rows": 0,
                "effects_rows": 0,
                "matched_public_tables": 32,
                "trading_started": False,
            }
            events = []
            controller.assert_existing_epoch = lambda **_kwargs: (
                events.append("existing-resources") or {"state": "verified"}
            )
            controller.phase = lambda mode, _config, *, suffix="": (
                events.append(mode + ":" + suffix) or history_state
            )
            controller.create_volume = lambda _name: events.append("new-restore-volume")
            controller.initialize_volume = lambda *_args, **_kwargs: events.append(
                "initialize-restore-volume"
            )

            def fail_backup(**kwargs):
                events.append("prebackup-" + kwargs["tag"])
                raise epoch.Rejected("PREBACKUP_RESTORE_FAILED")

            controller.backup_and_verify = fail_backup
            with (
                patch.object(
                    epoch,
                    "validate_attempt_02_backup_failure",
                    return_value={
                        "failure_sha256": epoch.CONTINUATION_02_FAILURE_SHA256
                    },
                ),
                patch.object(
                    epoch,
                    "validate_attempt_03_fresh_schema_failure",
                    return_value={
                        "failure_sha256": epoch.CONTINUATION_03_FAILURE_SHA256
                    },
                ),
                patch.object(
                    epoch,
                    "validate_attempt_04_partial_catchup_failure",
                    return_value={
                        "failure_sha256": epoch.CONTINUATION_04_FAILURE_SHA256
                    },
                ),
                patch.object(
                    epoch,
                    "read_attempt_04_rotated_history_secret",
                    return_value="f" * 64,
                ),
                patch.object(
                    epoch,
                    "_sha",
                    return_value="a" * 64,
                ),
                patch.object(
                    epoch,
                    "validate_attempt_04_history_state",
                    return_value=history_state,
                ),
                self.assertRaisesRegex(epoch.Rejected, "PREBACKUP_RESTORE_FAILED"),
            ):
                controller.run_continuation(
                    seed=seed,
                    old_private=old_private,
                    rotated_history="f" * 64,
                    attempt01_work=attempt01,
                    attempt02_work=attempt02,
                    attempt03_work=attempt03,
                    attempt04_work=attempt04,
                )
            self.assertEqual(
                events,
                [
                    "existing-resources",
                    "history-state:partial04",
                    "new-restore-volume",
                    "initialize-restore-volume",
                    "prebackup-precontinuation",
                ],
            )

    def test_attempt_05_final_tail_updates_rows_before_postcatchup_snapshot(self):
        with TemporaryDirectory() as directory:
            controller, seed, old_private = self._continuation_fixture(directory)
            controller.continuation_attempt = "05"
            root = Path(directory) / "epoch-root"
            controller.work = root / "continuation-05"
            controller.work.mkdir(parents=True)
            attempt01 = root / "continuation-01"
            attempt02 = root / "continuation-02"
            attempt03 = root / "continuation-03"
            attempt04 = root / "continuation-04"
            for path in (attempt01, attempt02, attempt03, attempt04):
                path.mkdir(parents=True)
            attempt04_private = attempt04 / "continuation-private.json"
            attempt04_private.write_text("{}", encoding="utf-8")

            source_work = root / ("run-" + controller.owner)
            (source_work / "output-seed").mkdir(parents=True)
            source_operator = source_work / "operator.zip"
            source_failure = source_work / "runtime-epoch-failure.json"
            source_seed = source_work / "output-seed" / "seed.json"
            source_operator.write_bytes(b"operator")
            source_failure.write_bytes(b"failure")
            source_seed.write_bytes(b"seed")
            attempt01_failure = attempt01 / "runtime-epoch-failure.json"
            attempt01_stderr = attempt01 / "cli-017.stderr"
            attempt01_failure.write_bytes(b"attempt01")
            attempt01_stderr.write_bytes(b"attempt01 stderr")
            lease = root / "runtime-epoch.active"
            lease.write_text(controller.owner + "\n", encoding="ascii")
            expected_hashes = {
                source_operator: epoch.CONTINUATION_PARENT_OPERATOR_SHA256,
                source_failure: epoch.CONTINUATION_FAILURE_SHA256,
                source_seed: epoch.CONTINUATION_SEED_SHA256,
                attempt01_failure: epoch.CONTINUATION_01_FAILURE_SHA256,
                attempt01_stderr: epoch.CONTINUATION_01_LOG_SHA256,
                attempt04_private: "b" * 64,
            }

            history_state = {
                "owner": controller.owner,
                "mode": "history-state",
                "new_epoch_database": old_private["database"],
                "state": "VERIFIED_AUDIT_ONLY_HISTORY_STATE",
                "rows": seed["rows"],
                "audit_table_sha256": epoch.CONTINUATION_04_CURRENT_AUDIT_SHA256,
                "anchors": copy.deepcopy(seed["anchors"]),
                "original_prefix": {
                    "rows": epoch.CONTINUATION_04_ORIGINAL_PREFIX_ROWS,
                    "audit_table_sha256": epoch.CONTINUATION_04_ORIGINAL_PREFIX_TABLE_SHA256,
                    "last_open_time_ms": epoch.CONTINUATION_04_ORIGINAL_LAST_OPEN_MS,
                },
                "outbox_rows": 0,
                "inbox_rows": 0,
                "orders_rows": 0,
                "effects_rows": 0,
                "matched_public_tables": 32,
                "trading_started": False,
            }
            current_legacy = {"state": "stopped", "metadata_sha256": {"source": "same"}}
            controller.assert_existing_epoch = lambda **_kwargs: current_legacy
            controller.assert_legacy_sources_stopped = lambda **_kwargs: current_legacy
            controller.create_volume = lambda *_args, **_kwargs: None
            controller.initialize_volume = lambda *_args, **_kwargs: None
            controller.backup_and_verify = lambda **kwargs: "backup-" + kwargs["tag"]
            controller.restart_serve_and_validate = lambda *_args: {
                "state": "RUNNING_NONTRADING"
            }

            def phase(mode, _config, *, suffix=""):
                if mode == "history-state" and suffix == "partial04":
                    return history_state
                if mode == "catchup":
                    self.assertEqual(suffix, "continue-final-01")
                    return {"appended": dict.fromkeys(epoch.SYMBOLS, 1)}
                if mode == "history-state" and suffix == "postcatchup":
                    return {"post": True}
                if mode == "qualify":
                    return {"state": "NONTRADING_RUNTIME_QUALIFIED"}
                if mode == "serve":
                    status_path = controller.work / "output-serve" / "status.json"
                    status_path.parent.mkdir()
                    status_path.write_text(
                        json.dumps({"state": "RUNNING_NONTRADING"}), encoding="utf-8"
                    )
                    return {"state": "RUNNING_NONTRADING"}
                self.fail(f"unexpected worker phase {mode}:{suffix}")

            controller.phase = phase
            checked_post_snapshot = []
            validators = (
                patch.object(
                    epoch,
                    "validate_attempt_02_backup_failure",
                    return_value={
                        "failure_sha256": epoch.CONTINUATION_02_FAILURE_SHA256
                    },
                ),
                patch.object(
                    epoch,
                    "validate_attempt_03_fresh_schema_failure",
                    return_value={
                        "failure_sha256": epoch.CONTINUATION_03_FAILURE_SHA256
                    },
                ),
                patch.object(
                    epoch,
                    "validate_attempt_04_partial_catchup_failure",
                    return_value={
                        "failure_sha256": epoch.CONTINUATION_04_FAILURE_SHA256
                    },
                ),
                patch.object(
                    epoch,
                    "read_attempt_04_rotated_history_secret",
                    return_value="f" * 64,
                ),
                patch.object(
                    epoch,
                    "validate_attempt_04_history_state",
                    return_value=history_state,
                ),
                patch.object(
                    epoch,
                    "validate_history_state",
                    side_effect=lambda value, **kwargs: (
                        checked_post_snapshot.append(
                            (
                                value,
                                kwargs["expected_rows"],
                                copy.deepcopy(kwargs["expected_anchors"]),
                            )
                        )
                        or value
                    ),
                ),
                patch.object(
                    epoch,
                    "validate_running_status",
                    side_effect=lambda value, *_a, **_kw: value,
                ),
                patch.object(epoch, "ROOT", root),
                patch.object(epoch, "ACTIVE_LEASE", lease),
                patch.object(
                    epoch.time, "time", side_effect=(1_800_000_305.0, 1_800_000_425.0)
                ),
                patch.object(
                    epoch, "_sha", side_effect=lambda path: expected_hashes[Path(path)]
                ),
            )
            with (
                validators[0],
                validators[1],
                validators[2],
                validators[3],
                validators[4],
                validators[5],
                validators[6],
                validators[7],
                validators[8],
                validators[9],
                validators[10],
            ):
                result = controller.run_continuation(
                    seed=seed,
                    old_private=old_private,
                    rotated_history="f" * 64,
                    attempt01_work=attempt01,
                    attempt02_work=attempt02,
                    attempt03_work=attempt03,
                    attempt04_work=attempt04,
                )

            self.assertEqual(
                result["result"], "PASS_NONTRADING_RUNTIME_EPOCH_CONTINUATION"
            )
            self.assertEqual(len(checked_post_snapshot), 1)
            _snapshot, rows, anchors = checked_post_snapshot[0]
            self.assertEqual(rows, seed["rows"] + len(epoch.SYMBOLS))
            self.assertEqual(
                {symbol: anchor["count"] for symbol, anchor in anchors.items()},
                {
                    symbol: seed["anchors"][symbol]["count"] + 1
                    for symbol in epoch.SYMBOLS
                },
            )

    def test_consumer_phase_config_does_not_include_admin_or_history_credentials(self):
        value = config("serve")
        projection = epoch.private_worker_projection(OWNER, "serve", value)
        self.assertEqual(set(projection), set(value))
        self.assertFalse(
            {
                "admin_password",
                "source_admin_password",
                "source_password",
                "history_password",
                "restore_admin_password",
            }
            & set(projection)
        )

    def test_worker_arguments_contain_no_secret_and_only_fixed_mount_paths(self):
        argv = epoch.build_worker_argv(
            "serve", epoch.CONFIG_PATH_IN_CONTAINER, epoch.OUTPUT_PATH_IN_CONTAINER
        )
        self.assertEqual(
            argv,
            [
                "python",
                "-B",
                epoch.WORKER_PATH_IN_IMAGE,
                "--mode",
                "serve",
                "--config",
                "/config/epoch.json",
                "--output",
                "/output",
            ],
        )
        self.assertTrue(all("password" not in arg.lower() for arg in argv))
        with self.assertRaises(epoch.Rejected):
            epoch.build_worker_argv("serve", "/tmp/secret.json", "/tmp/output")

    def test_worker_tmpfs_keeps_only_runtime_libraries_executable(self):
        options = {
            "/tmp": "rw,nosuid,nodev,noexec,size=64m",
            "/runtime-libs": "rw,nosuid,nodev,exec,size=128m",
        }
        self.assertEqual(epoch.validate_worker_tmpfs(options), options)
        with self.assertRaises(epoch.Rejected):
            epoch.validate_worker_tmpfs(
                {**options, "/tmp": "rw,nosuid,nodev,exec,size=64m"}
            )
        with self.assertRaises(epoch.Rejected):
            epoch.validate_worker_tmpfs(
                {**options, "/runtime-libs": "rw,nosuid,nodev,noexec,size=128m"}
            )
        with self.assertRaises(epoch.Rejected):
            epoch.validate_worker_tmpfs({**options, "/extra": "rw,exec"})
        with self.assertRaises(epoch.Rejected):
            epoch.validate_worker_config(
                {**config("rotate-history"), "history_password": "x" * 40},
                mode="rotate-history",
            )

    def test_continuation_is_bound_to_exact_failed_epoch_artifacts(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            parent_operator = root / "operator.zip"
            lease = root / "runtime-epoch.active"
            failure = root / "runtime-epoch-failure.json"
            seed = root / "seed.json"
            private = root / "epoch-private.json"
            config_path = root / "config-catchup-01.json"
            parent_operator.write_bytes(b"archive")
            lease.write_text(epoch.CONTINUATION_OWNER + "\n", encoding="ascii")
            failure.write_text(
                json.dumps(
                    {
                        "owner": epoch.CONTINUATION_OWNER,
                        "phase": "catchup-01",
                        "error_category": "WORKER_MODE_FAILED_CATCHUP",
                        "preserved_forensics": True,
                        "active_lease_preserved": True,
                        "trading_started": False,
                    }
                ),
                encoding="utf-8",
            )
            seed_value = {
                "owner": epoch.CONTINUATION_OWNER,
                "state": "VERIFIED_HISTORY_SEEDED_AUDIT_ONLY",
                "rows": 173_164,
                "ordered_digest_sha256": epoch.CONTINUATION_SEED_DIGEST,
                "target_outbox_rows_after": 0,
                "anchors": {},
            }
            seed.write_text(json.dumps(seed_value), encoding="utf-8")
            secret_fields = {
                "admin_password": "a" * 64,
                "source_admin_password": "b" * 64,
                "restore_admin_password": "c" * 64,
                "source_password": "d" * 64,
                "history_password": "e" * 64,
                "producer_password": "f" * 64,
                "consumer_password": "1" * 64,
                "redis_admin_password": "2" * 64,
                "redis_producer_password": "3" * 64,
                "redis_consumer_password": "4" * 64,
            }
            private_value = {
                "owner": epoch.CONTINUATION_OWNER,
                "database": "kairos_epoch_" + epoch.CONTINUATION_OWNER[:12],
                **secret_fields,
            }
            private.write_text(json.dumps(private_value), encoding="utf-8")
            prior_config = {
                "owner": epoch.CONTINUATION_OWNER,
                "database": private_value["database"],
                "pg_host": "kairos-epoch-" + epoch.CONTINUATION_OWNER[:12] + "-pg",
                "redis_host": "kairos-epoch-"
                + epoch.CONTINUATION_OWNER[:12]
                + "-redis",
                "history_password": secret_fields["history_password"],
                "end_exclusive_ms": 1_791_680_280_000,
                "maximum_bars": epoch.MAX_CATCHUP_BARS,
            }
            config_path.write_text(json.dumps(prior_config), encoding="utf-8")
            hashes = {
                parent_operator: epoch.CONTINUATION_PARENT_OPERATOR_SHA256,
                failure: epoch.CONTINUATION_FAILURE_SHA256,
                seed: epoch.CONTINUATION_SEED_SHA256,
            }
            with patch.object(epoch, "_sha", side_effect=lambda path: hashes[path]):
                checked_seed, checked_private, checked_config = (
                    epoch.validate_continuation_artifacts(
                        owner=epoch.CONTINUATION_OWNER,
                        parent_revision=epoch.CONTINUATION_PARENT_REVISION,
                        parent_operator_sha256=epoch.CONTINUATION_PARENT_OPERATOR_SHA256,
                        parent_operator=parent_operator,
                        lease=lease,
                        failure=failure,
                        seed=seed,
                        original_private=private,
                        original_catchup_config=config_path,
                    )
                )
            self.assertEqual(checked_seed, seed_value)
            self.assertEqual(checked_private["owner"], epoch.CONTINUATION_OWNER)
            self.assertEqual(checked_config, prior_config)
            with self.assertRaises(epoch.Rejected):
                epoch.validate_continuation_artifacts(
                    owner=epoch.CONTINUATION_OWNER,
                    parent_revision="0" * 40,
                    parent_operator_sha256=epoch.CONTINUATION_PARENT_OPERATOR_SHA256,
                    parent_operator=parent_operator,
                    lease=lease,
                    failure=failure,
                    seed=seed,
                    original_private=private,
                    original_catchup_config=config_path,
                )

    def _continuation_fixture(self, directory: str):
        controller = object.__new__(epoch.EpochController)
        controller.owner = epoch.CONTINUATION_OWNER
        controller.names = epoch.resource_names(controller.owner)
        controller.work = Path(directory)
        controller.continuation_attempt = "01"
        controller.proofs = {}
        controller.deadline = epoch.time.monotonic() + 300
        last_close = 1_800_000_359_999
        seed = {
            "owner": controller.owner,
            "rows": 5,
            "anchors": {
                symbol: {
                    "count": 1,
                    "first_open_time_ms": last_close - epoch.MINUTE_MS + 1,
                    "last_open_time_ms": last_close - epoch.MINUTE_MS + 1,
                    "last_close_time_ms": last_close,
                }
                for symbol in epoch.SYMBOLS
            },
        }
        old_private = {
            "database": "kairos_epoch_" + controller.owner[:12],
            "admin_password": "a" * 64,
            "producer_password": "b" * 64,
            "consumer_password": "c" * 64,
            "redis_producer_password": "d" * 64,
            "redis_consumer_password": "e" * 64,
        }
        return controller, seed, old_private

    def test_continuation_runs_only_in_reviewed_phase_order(self):
        with TemporaryDirectory() as directory:
            controller, seed, old_private = self._continuation_fixture(directory)
            root = Path(directory) / "epoch-root"
            source_work = root / ("run-" + controller.owner)
            (source_work / "output-seed").mkdir(parents=True)
            parent_operator = source_work / "operator.zip"
            failure = source_work / "runtime-epoch-failure.json"
            seed_path = source_work / "output-seed" / "seed.json"
            parent_operator.write_bytes(b"parent archive")
            failure.write_bytes(b"frozen failed receipt")
            seed_path.write_bytes(b"frozen seed receipt")
            lease = root / "runtime-epoch.active"
            lease.write_text(controller.owner + "\n", encoding="ascii")
            hash_values = {
                parent_operator: epoch.CONTINUATION_PARENT_OPERATOR_SHA256,
                failure: epoch.CONTINUATION_FAILURE_SHA256,
                seed_path: epoch.CONTINUATION_SEED_SHA256,
            }
            events = []
            legacy = {"state": "stopped", "metadata_sha256": {"source": "same"}}
            controller.assert_existing_epoch = lambda **_kwargs: (
                events.append("existing") or legacy
            )
            controller.initialize_volume = lambda *_args, **_kwargs: events.append(
                "initialize-restore"
            )
            controller.create_volume = lambda *_args, **_kwargs: events.append(
                "create-restore"
            )
            backups = iter(("pre-backup-sha", "post-backup-sha"))

            def backup_and_verify(**kwargs):
                events.append("backup-" + kwargs["tag"])
                if kwargs["tag"] == "precontinuation":
                    self.assertEqual(kwargs["seed"], seed)
                else:
                    self.assertGreater(
                        kwargs["seed"]["anchors"][epoch.SYMBOLS[0]]["count"], 1
                    )
                return next(backups)

            controller.backup_and_verify = backup_and_verify
            phase_receipts = {
                "rotate-history": {"credential_rotated": True},
                "catchup": {"appended": dict.fromkeys(epoch.SYMBOLS, 1)},
                "qualify": {"state": "NONTRADING_RUNTIME_QUALIFIED"},
                "serve": {"state": "RUNNING_NONTRADING"},
            }

            def phase(mode, _config, *, suffix=""):
                events.append(mode + (":" + suffix if suffix else ""))
                if mode == "catchup":
                    count = 3 if suffix == "continue-01" else 1
                    receipt = {"appended": dict.fromkeys(epoch.SYMBOLS, count)}
                else:
                    receipt = phase_receipts[mode]
                if mode == "serve":
                    status_path = controller.work / "output-serve" / "status.json"
                    status_path.parent.mkdir()
                    status_path.write_text(
                        json.dumps({"state": "RUNNING_NONTRADING"}),
                        encoding="utf-8",
                    )
                return receipt

            controller.phase = phase
            controller.restart_serve_and_validate = lambda *_args: (
                events.append("restart-serve") or {"state": "RUNNING_NONTRADING"}
            )
            controller.assert_legacy_sources_stopped = lambda **_kwargs: (
                events.append("legacy-check") or legacy
            )
            times = iter((1_800_000_600.0, 1_800_000_660.0))
            with (
                patch.object(epoch.time, "time", side_effect=lambda: next(times)),
                patch.object(
                    epoch,
                    "validate_running_status",
                    side_effect=lambda value, *_a, **_kw: value,
                ),
                patch.object(epoch, "ROOT", root),
                patch.object(epoch, "ACTIVE_LEASE", lease),
                patch.object(epoch, "_sha", side_effect=lambda path: hash_values[path]),
            ):
                result = controller.run_continuation(
                    seed=seed,
                    old_private=old_private,
                    rotated_history="f" * 64,
                )
            self.assertEqual(
                events,
                [
                    "existing",
                    "initialize-restore",
                    "backup-precontinuation",
                    "rotate-history:history-credential",
                    "catchup:continue-01",
                    "create-restore",
                    "initialize-restore",
                    "backup-postcatchup",
                    "catchup:continue-final-01",
                    "qualify:continuation",
                    "serve",
                    "restart-serve",
                    "legacy-check",
                ],
            )
            self.assertEqual(
                result["result"], "PASS_NONTRADING_RUNTIME_EPOCH_CONTINUATION"
            )
            self.assertEqual(result["proofs"]["legacy_after"], legacy)
            self.assertTrue(result["proofs"]["source_failure_preserved"])

    def test_continuation_prebackup_failure_prevents_rotation_and_catchup(self):
        with TemporaryDirectory() as directory:
            controller, seed, old_private = self._continuation_fixture(directory)
            events = []
            controller.assert_existing_epoch = lambda **_kwargs: (
                events.append("existing") or {"state": "stopped"}
            )
            controller.initialize_volume = lambda *_args, **_kwargs: events.append(
                "initialize"
            )

            def fail_backup(**_kwargs):
                events.append("prebackup")
                raise epoch.Rejected("PREBACKUP_PROOF_FAILED")

            controller.backup_and_verify = fail_backup
            controller.phase = lambda *args, **_kwargs: events.append(args[0])
            with self.assertRaisesRegex(epoch.Rejected, "PREBACKUP_PROOF_FAILED"):
                controller.run_continuation(
                    seed=seed,
                    old_private=old_private,
                    rotated_history="f" * 64,
                )
            self.assertEqual(events, ["existing", "initialize", "prebackup"])

    def test_continuation_rotation_failure_prevents_catchup(self):
        with TemporaryDirectory() as directory:
            controller, seed, old_private = self._continuation_fixture(directory)
            events = []
            controller.assert_existing_epoch = lambda **_kwargs: (
                events.append("existing") or {"state": "stopped"}
            )
            controller.initialize_volume = lambda *_args, **_kwargs: events.append(
                "initialize"
            )
            controller.backup_and_verify = lambda **_kwargs: (
                events.append("prebackup") or "backup-sha"
            )

            def phase(mode, _config, **_kwargs):
                events.append(mode)
                return {"credential_rotated": False}

            controller.phase = phase
            with self.assertRaisesRegex(
                epoch.Rejected, "HISTORY_ROLE_ROTATION_PROOF_REQUIRED"
            ):
                controller.run_continuation(
                    seed=seed,
                    old_private=old_private,
                    rotated_history="f" * 64,
                )
            self.assertEqual(
                events, ["existing", "initialize", "prebackup", "rotate-history"]
            )

    def test_attempt_03_skips_old_initializer_cleanup_and_volume_initialization(self):
        with TemporaryDirectory() as directory:
            controller, seed, old_private = self._continuation_fixture(directory)
            controller.continuation_attempt = "03"
            attempt01 = Path(directory) / "continuation-01"
            attempt02 = Path(directory) / "continuation-02"
            attempt01.mkdir()
            attempt02.mkdir()
            failure = attempt02 / "runtime-epoch-failure.json"
            failure.write_text(
                json.dumps(
                    {
                        "owner": controller.owner,
                        "phase": "ADMISSION",
                        "error_category": "Rejected",
                        "created_resources": [],
                        "active_lease_preserved": True,
                        "trading_started": False,
                    }
                ),
                encoding="utf-8",
            )
            stderr = attempt02 / "cli-025.stderr"
            stderr.write_bytes(b"synthetic attempt02 stderr")
            evidence = attempt02 / "attempt-01-initializer-evidence.json"
            evidence.write_text(
                json.dumps(
                    {
                        "owner": controller.owner,
                        "attempt_01_failure_sha256": epoch.CONTINUATION_01_FAILURE_SHA256,
                        "helper_name": "kairos-epoch-69893dc7b7c6-volume-init-70",
                        "helper_container_id": "1" * 64,
                        "image": epoch.PG_IMAGE,
                        "state": "exited",
                        "exit_code": 1,
                        "cap_add": ["CAP_CHOWN"],
                        "network_mode": "none",
                        "mounts": [
                            [
                                "volume",
                                epoch.CONTINUATION_01_ANONYMOUS_VOLUME,
                                "/var/lib/postgresql/data",
                                True,
                            ],
                            [
                                "volume",
                                controller.names["restore_volume"],
                                "/owned",
                                True,
                            ],
                        ],
                        "anonymous_volume": epoch.CONTINUATION_01_ANONYMOUS_VOLUME,
                        "failed_operation": "chmod_owned_volume_permission_denied",
                        "log_sha256": epoch.CONTINUATION_01_LOG_SHA256,
                        "raw_log_preserved": False,
                    }
                ),
                encoding="utf-8",
            )
            hashes = {
                failure: epoch.CONTINUATION_02_FAILURE_SHA256,
                stderr: epoch.CONTINUATION_02_LOG_SHA256,
                evidence: epoch.CONTINUATION_02_ATTEMPT_01_EVIDENCE_SHA256,
            }
            events = []
            controller.assert_existing_epoch = lambda **_kwargs: (
                events.append("existing") or {"state": "stopped"}
            )
            controller.initialize_volume = lambda *_args, **_kwargs: events.append(
                "unexpected-initialize"
            )
            controller.archive_and_remove_attempt_01_initializer = lambda **_kwargs: (
                events.append("unexpected-cleanup")
            )

            def fail_backup(**_kwargs):
                events.append("prebackup")
                raise epoch.Rejected("EXPECTED_STOP_BEFORE_DATABASE_MUTATION")

            controller.backup_and_verify = fail_backup
            root = Path(directory) / "epoch-root"
            with (
                patch.object(epoch, "ROOT", root),
                patch.object(epoch, "_sha", side_effect=lambda path: hashes[path]),
                self.assertRaisesRegex(
                    epoch.Rejected, "EXPECTED_STOP_BEFORE_DATABASE_MUTATION"
                ),
            ):
                controller.run_continuation(
                    seed=seed,
                    old_private=old_private,
                    rotated_history="f" * 64,
                    attempt01_work=attempt01,
                    attempt02_work=attempt02,
                )
            self.assertEqual(events, ["existing", "prebackup"])

    def test_attempt_03_inventory_failure_is_pinned_to_exact_status_dump_and_archive(
        self,
    ):
        with TemporaryDirectory() as directory:
            attempt03 = Path(directory) / "continuation-03"
            status_dir = attempt03 / "output-verify-restore-precontinuation"
            status_dir.mkdir(parents=True)
            failure = attempt03 / "runtime-epoch-failure.json"
            dump = attempt03 / "epoch-history-precontinuation.dump"
            status = status_dir / "status.json"
            operator = attempt03 / "operator.zip"
            for path in (failure, status, operator):
                path.write_bytes(b"synthetic evidence")
            with dump.open("wb") as stream:
                stream.truncate(20_692_780)
            hashes = {
                failure: epoch.CONTINUATION_03_FAILURE_SHA256,
                dump: epoch.CONTINUATION_03_DUMP_SHA256,
                status: epoch.CONTINUATION_03_STATUS_SHA256,
                operator: epoch.CONTINUATION_03_OPERATOR_SHA256,
            }
            with patch.object(epoch, "_sha", side_effect=lambda path: hashes[path]):
                result = epoch.validate_attempt_03_fresh_schema_failure(
                    owner=epoch.CONTINUATION_OWNER,
                    attempt03_work=attempt03,
                    expected_sha256=epoch.CONTINUATION_03_FAILURE_SHA256,
                )
                self.assertEqual(result["precontinuation_dump_bytes"], 20_692_780)
                with self.assertRaisesRegex(
                    epoch.Rejected, "EXACT_ATTEMPT_03_FRESH_SCHEMA_FAILURE_REQUIRED"
                ):
                    epoch.validate_attempt_03_fresh_schema_failure(
                        owner=epoch.CONTINUATION_OWNER,
                        attempt03_work=attempt03,
                        expected_sha256="0" * 64,
                    )

    def test_attempt_04_restore_cleanup_archives_then_removes_only_pinned_clone(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            attempt03 = root / "continuation-03"
            attempt03.mkdir()
            secret = attempt03 / "restore-admin-password-precontinuation"
            dump = attempt03 / "epoch-history-precontinuation.dump"
            secret.write_text("synthetic", encoding="ascii")
            with dump.open("wb") as stream:
                stream.truncate(20_692_780)
            controller = object.__new__(epoch.EpochController)
            controller.owner = epoch.CONTINUATION_OWNER
            controller.names = epoch.resource_names(controller.owner)
            controller.work = root / "continuation-04"
            controller.work.mkdir()
            controller.proofs = {}
            events = []
            view = {
                "id": epoch.CONTINUATION_03_RESTORE_CONTAINER_ID,
                "name": "/" + controller.names["restore_pg"],
                "image": epoch.PG_IMAGE,
                "state": {"Status": "exited", "ExitCode": 0},
                "network": controller.names["network"],
                "ports": [],
                "readonly": True,
                "caps": ["ALL"],
                "privileged": False,
                "memory": 4 * 1024**3,
                "swap": 4 * 1024**3,
                "cpus": 1_000_000_000,
                "labels": {
                    epoch.EPOCH_LABEL: controller.owner,
                    "com.kairos.runtime-epoch.scope": epoch.EPOCH_SCOPE,
                },
            }
            controller.inspect_container = lambda _name: view
            controller.require_mount_set = lambda *_args: None

            def docker(args, **_kwargs):
                events.append(tuple(args))
                if args[0] == "volume" and args[1] == "inspect":
                    return json.dumps(
                        {
                            "Name": controller.names["restore_volume"],
                            "Labels": {
                                epoch.EPOCH_LABEL: controller.owner,
                                "com.kairos.runtime-epoch.scope": epoch.EPOCH_SCOPE,
                            },
                        }
                    )
                return ""

            controller.docker = docker
            controller.create_volume = lambda _name: events.append("create-volume")
            controller.initialize_volume = lambda *_args, **_kwargs: events.append(
                "initialize-volume"
            )
            with patch.object(
                epoch,
                "_sha",
                side_effect=lambda path: (
                    epoch.CONTINUATION_03_DUMP_SHA256 if path == dump else "a" * 64
                ),
            ):
                proof = controller.archive_and_remove_attempt_03_restore_clone(
                    source_work=root
                )
            self.assertEqual(
                events[-5:],
                [
                    (
                        "volume",
                        "inspect",
                        "--format",
                        "{{json .}}",
                        controller.names["restore_volume"],
                    ),
                    ("rm", controller.names["restore_pg"]),
                    ("volume", "rm", controller.names["restore_volume"]),
                    "create-volume",
                    "initialize-volume",
                ],
            )
            self.assertEqual(events[-1], "initialize-volume")
            self.assertTrue(proof["removed_only_after_exact_metadata"])
            self.assertTrue(proof["replacement_volume_uid70_initialized"])

    def test_attempt_04_restore_cleanup_rejects_wrong_clone_before_delete(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            attempt03 = root / "continuation-03"
            attempt03.mkdir()
            (attempt03 / "restore-admin-password-precontinuation").write_text(
                "synthetic", encoding="ascii"
            )
            (attempt03 / "epoch-history-precontinuation.dump").write_bytes(b"x")
            controller = object.__new__(epoch.EpochController)
            controller.owner = epoch.CONTINUATION_OWNER
            controller.names = epoch.resource_names(controller.owner)
            controller.work = root / "continuation-04"
            controller.work.mkdir()
            events = []
            controller.inspect_container = lambda _name: {
                "id": "0" * 64,
                "name": "/" + controller.names["restore_pg"],
            }
            controller.docker = lambda args, **_kwargs: events.append(args)
            with self.assertRaisesRegex(
                epoch.Rejected, "EXACT_STOPPED_ATTEMPT_03_RESTORE_CLONE_REQUIRED"
            ):
                controller.archive_and_remove_attempt_03_restore_clone(source_work=root)
            self.assertEqual(events, [])

    def test_attempt_04_prebackup_failure_stops_before_history_rotation(self):
        with TemporaryDirectory() as directory:
            controller, seed, old_private = self._continuation_fixture(directory)
            controller.continuation_attempt = "04"
            controller.work = Path(directory) / "continuation-04"
            controller.work.mkdir()
            attempt01 = Path(directory) / "continuation-01"
            attempt02 = Path(directory) / "continuation-02"
            attempt03 = Path(directory) / "continuation-03"
            for path in (attempt01, attempt02, attempt03):
                path.mkdir()
            events = []
            controller.assert_existing_epoch = lambda **_kwargs: (
                events.append("existing-resources") or {"state": "verified"}
            )
            controller.archive_and_remove_attempt_03_restore_clone = lambda **_kwargs: (
                events.append("archive-and-clean-exact-clone")
                or {"removed_only_after_exact_metadata": True}
            )

            def fail_backup(**_kwargs):
                events.append("fresh-precontinuation-backup")
                raise epoch.Rejected("BACKUP_PROOF_MISMATCH")

            controller.backup_and_verify = fail_backup
            with (
                patch.object(
                    epoch,
                    "validate_attempt_02_backup_failure",
                    return_value={
                        "failure_sha256": epoch.CONTINUATION_02_FAILURE_SHA256
                    },
                ),
                patch.object(
                    epoch,
                    "validate_attempt_03_fresh_schema_failure",
                    return_value={
                        "failure_sha256": epoch.CONTINUATION_03_FAILURE_SHA256
                    },
                ),
                self.assertRaisesRegex(epoch.Rejected, "BACKUP_PROOF_MISMATCH"),
            ):
                controller.run_continuation(
                    seed=seed,
                    old_private=old_private,
                    rotated_history="f" * 64,
                    attempt01_work=attempt01,
                    attempt02_work=attempt02,
                    attempt03_work=attempt03,
                )
            self.assertEqual(
                events,
                [
                    "existing-resources",
                    "archive-and-clean-exact-clone",
                    "fresh-precontinuation-backup",
                ],
            )

    def test_catchup_end_is_global_cap_safe_for_five_symbols_and_exact_resume(self):
        seed = seed_receipt()
        target = 1_791_680_280_000
        first = epoch.catchup_end_exclusive_ms(seed, target)
        self.assertEqual(first, 1_791_632_640_000)
        first_count = sum(
            (first - item["last_close_time_ms"] - 1) // epoch.MINUTE_MS
            for item in seed["anchors"].values()
        )
        self.assertEqual(first_count, epoch.MAX_CATCHUP_BARS)
        next_seed = seed_receipt(first - epoch.MINUTE_MS)
        second = epoch.catchup_end_exclusive_ms(next_seed, target)
        self.assertEqual(second, target)
        second_count = sum(
            (second - item["last_close_time_ms"] - 1) // epoch.MINUTE_MS
            for item in next_seed["anchors"].values()
        )
        self.assertEqual(second_count, 3_970)
        self.assertLessEqual(second_count, epoch.MAX_CATCHUP_BARS)

    def test_catchup_uses_smaller_exact_budget_when_anchors_differ(self):
        seed = seed_receipt()
        seed["anchors"]["XRPUSDT"]["last_open_time_ms"] -= epoch.MINUTE_MS
        seed["anchors"]["XRPUSDT"]["last_close_time_ms"] -= epoch.MINUTE_MS
        end = epoch.catchup_end_exclusive_ms(
            seed, ANCHOR_OPEN + 30_001 * epoch.MINUTE_MS
        )
        count = sum(
            (end - row["last_close_time_ms"] - 1) // epoch.MINUTE_MS
            for row in seed["anchors"].values()
        )
        self.assertLessEqual(count, epoch.MAX_CATCHUP_BARS)
        self.assertEqual(end % epoch.MINUTE_MS, 0)

    def test_redis_acl_disables_default_and_denies_xadd_to_consumer(self):
        acl = epoch.redis_acl_text(
            OWNER,
            admin_password="a" * 64,
            producer_password="b" * 64,
            consumer_password="c" * 64,
        )
        self.assertEqual(acl.splitlines()[0], epoch.replay_default_acl(OWNER))
        self.assertIn(" off ", acl.splitlines()[0])
        self.assertNotIn("+@all", acl.splitlines()[0])
        self.assertNotIn("~*", acl.splitlines()[0])
        producer, consumer = acl.splitlines()[2:]
        self.assertTrue(producer.startswith("user kairos_epoch_producer on #"))
        self.assertIn("~" + epoch.CLOSED_BAR_TOPIC, producer)
        self.assertIn(
            "~" + epoch.PUBLICATION_KEY_PREFIX + OWNER + ".publication", producer
        )
        self.assertIn("+xadd", producer)
        self.assertIn("+xinfo|groups", producer)
        self.assertTrue(consumer.startswith("user kairos_epoch_consumer on #"))
        self.assertIn("+xreadgroup", consumer)
        self.assertIn("+xack", consumer)
        self.assertIn("+hello", consumer)
        self.assertNotIn("+xadd", consumer)
        self.assertNotIn("+eval", consumer)
        self.assertNotIn("~*", consumer)
        self.assertNotIn("a" * 64, acl)
        self.assertNotIn("b" * 64, acl)
        self.assertNotIn("c" * 64, acl)

    def test_redis_acl_rejects_reused_or_non_hex_credentials(self):
        with self.assertRaises(epoch.Rejected):
            epoch.redis_acl_text(
                OWNER,
                admin_password="a" * 64,
                producer_password="a" * 64,
                consumer_password="c" * 64,
            )
        with self.assertRaises(epoch.Rejected):
            epoch.redis_acl_text(
                OWNER,
                admin_password="not-secret",
                producer_password="b" * 64,
                consumer_password="c" * 64,
            )

    def test_plan_cli_is_read_only_and_does_not_print_secrets(self):
        from contextlib import redirect_stdout
        from io import StringIO

        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(epoch.main([]), 0)
        data = json.loads(output.getvalue())
        self.assertEqual(data["result"], "PLAN_ONLY")
        self.assertFalse(data["writes"])
        self.assertFalse(data["legacy_source_start"])
        self.assertNotIn(HEX_SECRET, output.getvalue())

    def test_failure_receipt_is_sanitized_and_create_only(self):
        with TemporaryDirectory() as directory:
            work = Path(directory)
            calls = []
            controller = SimpleNamespace(
                current_phase="catchup-02",
                created=[
                    epoch.resource_names(OWNER)["target_pg"],
                    "kairos-epoch-0123456789ab-catchup",
                ],
                stop_owned_after_failure=lambda: calls.append("stopped-owned-runtime"),
            )
            path = epoch._persist_failure_receipt(
                work,
                OWNER,
                controller,
                OSError("password=do-not-leak"),
                private_ready=True,
            )
            self.assertEqual(path, work / "runtime-epoch-failure.json")
            receipt_text = path.read_text(encoding="utf-8")
            receipt = json.loads(receipt_text)
            self.assertEqual(receipt["result"], "FAILED_CLOSED")
            self.assertEqual(receipt["phase"], "catchup-02")
            self.assertEqual(receipt["error_category"], "OSERROR")
            self.assertIn(
                "kairos-epoch-0123456789ab-catchup", receipt["created_resources"]
            )
            self.assertNotIn("do-not-leak", receipt_text)
            self.assertEqual(calls, ["stopped-owned-runtime"])
            self.assertIsNone(
                epoch._persist_failure_receipt(
                    work, OWNER, controller, OSError("second"), private_ready=True
                )
            )
            self.assertNotIn("second", path.read_text(encoding="utf-8"))

    def test_failure_receipt_is_skipped_before_private_directory_admission(self):
        with TemporaryDirectory() as directory:
            self.assertIsNone(
                epoch._persist_failure_receipt(
                    Path(directory), OWNER, None, OSError("x"), private_ready=False
                )
            )

    def test_worker_phase_progress_is_immutable_and_secret_free(self):
        with TemporaryDirectory() as directory:
            controller = object.__new__(epoch.EpochController)
            controller.owner = OWNER
            controller.work = Path(directory)
            controller.phase_index = 0
            controller.current_phase = "ADMISSION"
            controller.run_worker = lambda **_kwargs: {
                "state": "PREPARED_EMPTY_NONTRADING_EPOCH"
            }
            result = controller.phase("prepare", config("prepare"))
            self.assertEqual(result["state"], "PREPARED_EMPTY_NONTRADING_EPOCH")
            progress = json.loads(
                (Path(directory) / "phase-001.json").read_text(encoding="utf-8")
            )
            complete = json.loads(
                (Path(directory) / "phase-001-complete.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(progress["state"], "IN_PROGRESS")
            self.assertEqual(complete["state"], "COMPLETE")
            self.assertNotIn(HEX_SECRET, json.dumps(progress))

    def test_container_create_arguments_put_image_before_command(self):
        controller = object.__new__(epoch.EpochController)
        controller.owner = OWNER
        controller.names = epoch.resource_names(OWNER)
        controller.created = []
        controller.inspect_container = lambda _name: {
            "name": "/kairos-epoch-0123456789ab-redis",
            "image": "sha256:" + epoch.REDIS_IMAGE.rsplit("sha256:", 1)[-1],
            "ports": {},
            "network": controller.names["network"],
            "memory": 2 * 1024**3,
            "swap": 2 * 1024**3,
            "cpus": 1_000_000_000,
            "readonly": True,
            "caps": ["ALL"],
            "privileged": False,
            "labels": {
                epoch.EPOCH_LABEL: OWNER,
                "com.kairos.runtime-epoch.scope": epoch.EPOCH_SCOPE,
            },
        }
        calls = []
        controller.docker = lambda args, **_kwargs: calls.append(args) or ""
        controller._create_container(
            "kairos-epoch-0123456789ab-redis",
            epoch.REDIS_IMAGE,
            ["--mount", "type=volume,src=x,dst=/data"],
            command=["redis-server", "--appendonly", "yes"],
            start=False,
        )
        command = calls[0]
        image_index = command.index(epoch.REDIS_IMAGE)
        assert command[image_index + 1 :] == ["redis-server", "--appendonly", "yes"]
        assert not any(arg == "-p" or arg.startswith("--publish") for arg in command)

    def test_running_status_requires_all_fresh_nontrading_watermarks(self):
        now = datetime.now(UTC).isoformat()
        prior = {
            "state": "RUNNING_NONTRADING",
            "owner": OWNER,
            "watermarks_ms": {symbol: 1_800_000_000_000 for symbol in epoch.SYMBOLS},
            "observed_at_utc": now,
            "PAPER_QUALIFIED": False,
            "ALPHA_READY": False,
            "LIVE_READY": False,
            "STRATEGY_POLICY": "REJECT_ALL",
            "pending_outbox": 0,
            "unresolved_inbox": 0,
            "uncompleted_publications": 0,
        }
        checked = {
            **prior,
            "watermarks_ms": {
                symbol: value + epoch.MINUTE_MS
                for symbol, value in prior["watermarks_ms"].items()
            },
            "observed_at_utc": (datetime.now(UTC) + timedelta(seconds=1)).isoformat(),
        }
        self.assertEqual(
            epoch.validate_running_status(checked, OWNER, previous=prior)["state"],
            "RUNNING_NONTRADING",
        )
        stalled = {
            **checked,
            "watermarks_ms": {
                **checked["watermarks_ms"],
                "XRPUSDT": prior["watermarks_ms"]["XRPUSDT"],
            },
        }
        with self.assertRaises(epoch.Rejected):
            epoch.validate_running_status(stalled, OWNER, previous=prior)
        with self.assertRaises(epoch.Rejected):
            epoch.validate_running_status({**checked, "pending_outbox": 1}, OWNER)
        with self.assertRaises(epoch.Rejected):
            epoch.validate_running_status(
                {**checked, "uncompleted_publications": 1}, OWNER
            )

    def test_restart_waits_for_natural_closed_minute_progress(self):
        first = {
            "state": "RUNNING_NONTRADING",
            "owner": OWNER,
            "watermarks_ms": {symbol: 1_800_000_000_000 for symbol in epoch.SYMBOLS},
            "observed_at_utc": datetime.now(UTC).isoformat(),
            "PAPER_QUALIFIED": False,
            "ALPHA_READY": False,
            "LIVE_READY": False,
            "STRATEGY_POLICY": "REJECT_ALL",
            "pending_outbox": 0,
            "unresolved_inbox": 0,
            "uncompleted_publications": 0,
        }
        stalled = {
            **first,
            "observed_at_utc": (datetime.now(UTC) + timedelta(seconds=1)).isoformat(),
        }
        advanced = {
            **stalled,
            "watermarks_ms": {
                symbol: value + epoch.MINUTE_MS
                for symbol, value in first["watermarks_ms"].items()
            },
            "observed_at_utc": (datetime.now(UTC) + timedelta(seconds=2)).isoformat(),
        }
        with TemporaryDirectory() as directory:
            status = Path(directory) / "status.json"
            epoch.fresh.save(status, first)
            controller = object.__new__(epoch.EpochController)
            controller.owner = OWNER
            controller.names = epoch.resource_names(OWNER)
            controller.deadline = epoch.time.monotonic() + 300
            calls = []
            controller.docker = lambda args, **_kwargs: calls.append(args) or ""
            states = iter(("exited", "running"))
            controller.inspect_container = lambda _name: {
                "state": {"Status": next(states)}
            }
            with (
                patch.object(
                    Path,
                    "read_text",
                    side_effect=[json.dumps(stalled), json.dumps(advanced)],
                ),
                patch.object(epoch.time, "sleep"),
            ):
                self.assertEqual(
                    controller.restart_serve_and_validate(status, first), advanced
                )
            self.assertEqual([call[0] for call in calls], ["stop", "start"])

    def test_private_acl_process_does_not_inherit_powershell_module_path(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "owned"
            with (
                patch.dict(epoch.os.environ, {"PSModulePath": "untrusted-module-path"}),
                patch.object(
                    epoch.subprocess, "run", return_value=SimpleNamespace(returncode=0)
                ) as run,
            ):
                epoch._private_directory(path)
            self.assertNotIn("PSModulePath", run.call_args.kwargs["env"])
            self.assertEqual(run.call_args.args[0][0], str(epoch.PS))
            self.assertTrue(path.is_dir())

    def test_private_wheel_snapshot_requires_exact_manifest_and_two_packages(self):
        self.assertEqual(
            epoch.PERSISTENCE_REVISION, "11df49ce455b89fd252d5f3d948099a8e9211cb3"
        )
        self.assertEqual(
            epoch.QUANT_REVISION, "77c3d3e813faeb042661dacecd148226d8a25834"
        )
        self.assertEqual(epoch.MAX_CATCHUP_BARS, 150_000)
        self.assertEqual(
            epoch.AUX_NUMPY_SHA256,
            "89cd468399cfd2504718f0ba50e410dca55a170b61a02ad92bb18c8a65186e93",
        )
