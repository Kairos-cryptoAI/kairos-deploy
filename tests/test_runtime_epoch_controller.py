from __future__ import annotations

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
        self.assertTrue(acl.startswith("user default off\n"))
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
            self.assertEqual(receipt["error_category"], "OSError")
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
