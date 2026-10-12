"""Offline admission and orchestration tests for the clean-queue R3 path."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from scripts import runtime_epoch_clean_queue_recovery as recovery
from scripts import runtime_epoch_worker as worker

boot = recovery.boot
epoch = recovery.epoch


def clean_state(
    *,
    pending: int = 0,
    audit: int = recovery.BASE_AUDIT_ROWS,
    queue_rows: int = recovery.BASE_QUEUE_ROWS,
) -> dict:
    return {
        "state": "PASS_BOOT_STATE",
        "matched_public_tables": len(worker.CONTROLLED_RUNTIME_PUBLIC_TABLES),
        "tables": {
            table: {
                "count": (
                    audit
                    if table == "event_audit"
                    else queue_rows
                    if table in {"message_outbox", "message_inbox"}
                    else worker.BOOT_DATABASE_IDENTITY["count"]
                    if table == "paper_canary_database_identity"
                    else 1
                    if table == "schema_migrations"
                    else 0
                ),
                "sha256": "a" * 64,
            }
            for table in worker.CONTROLLED_RUNTIME_PUBLIC_TABLES
        },
        "sequences": {
            "message_outbox_id_seq": {"last_value": recovery.BASE_QUEUE_ROWS}
        },
        "anchors": {symbol: {"count": 1} for symbol in epoch.SYMBOLS},
        "original_prefix": {
            "rows": worker.ORIGINAL_PREFIX_ROWS,
            "audit_table_sha256": worker.ORIGINAL_PREFIX_TABLE_SHA256,
            "last_open_time_ms": worker.ORIGINAL_PREFIX_LAST_OPEN_MS,
        },
        "queue": {
            "outbox_rows": queue_rows,
            "inbox_rows": queue_rows,
            "completed_inbox": queue_rows,
            "pending_outbox": pending,
            "unresolved_inbox": 0,
            "trading_rows": 0,
        },
        "trading_started": False,
    }


def serving_config() -> dict:
    return {
        "owner": boot.OWNER,
        "database": "kairos_epoch_" + boot.OWNER[:12],
        "pg_host": "kairos-epoch-" + boot.OWNER[:12] + "-pg",
        "redis_host": "kairos-epoch-" + boot.OWNER[:12] + "-redis",
        "producer_password": "a" * 64,
        "consumer_password": "b" * 64,
        "redis_producer_password": "c" * 64,
        "redis_consumer_password": "d" * 64,
    }


def worker_seed() -> dict:
    from scripts import runtime_epoch_controller as controller

    anchors = copy.deepcopy(controller.CONTINUATION_04_CURRENT_ANCHORS)
    count = controller.CONTINUATION_04_CURRENT_AUDIT_ROWS
    tables = {
        table: {"count": 0, "sha256": "a" * 64}
        for table in worker.CONTROLLED_RUNTIME_PUBLIC_TABLES
    }
    tables.update(
        {
            "schema_migrations": {"count": 1, "sha256": "b" * 64},
            "event_audit": {"count": count, "sha256": "c" * 64},
            "message_outbox": {"count": recovery.BASE_QUEUE_ROWS, "sha256": "d" * 64},
            "message_inbox": {"count": recovery.BASE_QUEUE_ROWS, "sha256": "e" * 64},
            "paper_canary_database_identity": worker.BOOT_DATABASE_IDENTITY,
        }
    )
    return {
        "state": "PASS_BOOT_STATE",
        "matched_public_tables": len(worker.CONTROLLED_RUNTIME_PUBLIC_TABLES),
        "tables": tables,
        "sequences": {},
        "anchors": anchors,
        "original_prefix": {
            "rows": worker.ORIGINAL_PREFIX_ROWS,
            "audit_table_sha256": worker.ORIGINAL_PREFIX_TABLE_SHA256,
            "last_open_time_ms": worker.ORIGINAL_PREFIX_LAST_OPEN_MS,
        },
        "queue": {
            "outbox_rows": recovery.BASE_QUEUE_ROWS,
            "inbox_rows": recovery.BASE_QUEUE_ROWS,
            "completed_inbox": recovery.BASE_QUEUE_ROWS,
            "pending_outbox": 0,
            "unresolved_inbox": 0,
            "trading_rows": 0,
        },
        "trading_started": False,
    }


class CleanQueueRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.boot_globals = {
            name: getattr(boot, name)
            for name in (
                "ROOT",
                "SERVE_WORK",
                "SCOPE",
                "GENERATION",
                "RECEIPT_NAME",
                "PARENT_RECEIPT_SHA256",
                "CONTAINERS",
                "LEASE",
            )
        }
        self.addCleanup(
            lambda: [
                setattr(boot, name, value) for name, value in self.boot_globals.items()
            ]
        )
        boot.configure_generation_r2()

    def _attempt_reviewed_r3_admission(
        self,
        *,
        claim=recovery.R3_FAILURE_SHA256,
        source=None,
        failure_sha=None,
        failed_status_sha=None,
        operator_sha=None,
        r2_status=None,
        receipt=None,
        latch_changes=None,
    ):
        """Exercise admission with exact synthetic evidence, never host files."""
        controller = recovery.ReviewedR3SupplementController.__new__(
            recovery.ReviewedR3SupplementController
        )
        controller.reviewed_r3_standby_views = mock.Mock(return_value={"proof": 1})
        latch = {
            "state": "IN_PROGRESS",
            "run": recovery.R3_FAILED_RUN,
            "owner": boot.OWNER,
            "source_revision": recovery.R3_SOURCE_REVISION,
            "failed_status_sha256": recovery.FAILED_STATUS_SHA256,
            "accepted_r2_receipt_sha256": recovery.ACCEPTED_RECEIPT_SHA256,
            "automatic_retry": False,
        }
        if source is not None:
            latch["source_revision"] = source
        if latch_changes:
            latch.update(latch_changes)

        latch_path = recovery.LEASE_DIR / "latch.json"
        hashes = {
            recovery.R3_FAILED_WORK / "failure.json": (
                recovery.R3_FAILURE_SHA256 if failure_sha is None else failure_sha
            ),
            recovery.R3_FAILED_WORK / "output-serve/status.json": (
                recovery.R3_FAILED_STATUS_SHA256
                if failed_status_sha is None
                else failed_status_sha
            ),
            recovery.R3_FAILED_WORK / "operator.zip": (
                recovery.R3_OPERATOR_ZIP_SHA256
                if operator_sha is None
                else operator_sha
            ),
            boot.SERVE_WORK / "output-serve/status.json": (
                recovery.FAILED_STATUS_SHA256 if r2_status is None else r2_status
            ),
            boot.SERVE_WORK / boot.RECEIPT_NAME: (
                recovery.ACCEPTED_RECEIPT_SHA256 if receipt is None else receipt
            ),
        }

        def require_latch_path(path):
            if Path(path) != latch_path:
                raise AssertionError("unexpected admission file check")

        def latch_is_symlink(path):
            require_latch_path(path)
            return False

        def latch_is_file(path):
            require_latch_path(path)
            return True

        def hash_for(path):
            normalized = Path(path)
            if normalized not in hashes:
                raise AssertionError("unexpected admission hash path")
            return hashes[normalized]

        def read_active_lease(path, *args, **kwargs):
            if Path(path) != epoch.ACTIVE_LEASE:
                raise AssertionError("unexpected active-lease path")
            return boot.OWNER + "\n"

        with (
            mock.patch.object(
                Path,
                "is_symlink",
                new=latch_is_symlink,
            ),
            mock.patch.object(
                Path,
                "is_file",
                new=latch_is_file,
            ),
            mock.patch.object(
                recovery.boot, "read_json", return_value=latch
            ) as read_json,
            mock.patch.object(recovery.fresh, "sha", side_effect=hash_for),
            mock.patch.object(
                type(epoch.ACTIVE_LEASE), "read_text", new=read_active_lease
            ),
            mock.patch.object(recovery.boot.subprocess, "run") as subprocess_run,
        ):
            try:
                return controller.admission_evidence(claim)
            finally:
                read_json.assert_called_once_with(latch_path)
                subprocess_run.assert_not_called()

    def test_restore_transport03_is_exact_owner_only(self):
        self._assert_restore_suffix_allowed("transport03")

    def test_restore_transport04_is_exact_owner_only(self):
        self._assert_restore_suffix_allowed("transport04")

    def test_standby_projection_ignores_only_health_timestamps(self):
        metadata = {
            "id": boot.STANDBY_ID,
            "image": "sha256:image",
            "network": "shadow-net",
            "mounts": [
                {"Destination": "/data", "Source": "volume-a", "RW": True},
                {"Destination": "/config", "Source": "bind-a", "RW": False},
            ],
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
                            "Output": "ok",
                        },
                        {
                            "Start": "2026-10-12T01:01:00.000000000Z",
                            "End": "2026-10-12T01:01:01.000000000Z",
                            "ExitCode": 0,
                            "Output": "still ready",
                        },
                    ],
                },
            },
        }
        natural = copy.deepcopy(metadata)
        for index, row in enumerate(natural["state"]["Health"]["Log"]):
            row["Start"] = f"2026-10-12T01:0{index + 2}:00.000000000Z"
            row["End"] = f"2026-10-12T01:0{index + 2}:01.000000000Z"
        self.assertEqual(
            boot.stable_standby_metadata(metadata),
            boot.stable_standby_metadata(natural),
        )
        reordered = copy.deepcopy(metadata)
        reordered["mounts"].reverse()
        self.assertEqual(
            boot.stable_standby_metadata(metadata),
            boot.stable_standby_metadata(reordered),
        )
        reversed_log = copy.deepcopy(metadata)
        reversed_log["state"]["Health"]["Log"].reverse()
        self.assertNotEqual(
            boot.stable_standby_metadata(metadata),
            boot.stable_standby_metadata(reversed_log),
        )
        shortened_log = copy.deepcopy(metadata)
        shortened_log["state"]["Health"]["Log"].pop()
        self.assertNotEqual(
            boot.stable_standby_metadata(metadata),
            boot.stable_standby_metadata(shortened_log),
        )
        for mutation in (
            (
                "state",
                {
                    "Status": "running",
                    "Health": {
                        "Status": "unhealthy",
                        "FailingStreak": 0,
                        "Log": metadata["state"]["Health"]["Log"],
                    },
                },
            ),
            (
                "state",
                {
                    "Status": "running",
                    "Health": {
                        "Status": "healthy",
                        "FailingStreak": 1,
                        "Log": metadata["state"]["Health"]["Log"],
                    },
                },
            ),
            ("network", "other-net"),
            (
                "mounts",
                [{"Destination": "/data", "Source": "other-volume", "RW": True}],
            ),
        ):
            changed = copy.deepcopy(metadata)
            field, value = mutation
            changed[field] = value
            with self.subTest(mutation=mutation):
                if field == "state":
                    with self.assertRaisesRegex(
                        epoch.Rejected, "BOOT_STANDBY_HEALTH_METADATA_CONFLICT"
                    ):
                        boot.stable_standby_metadata(changed)
                else:
                    self.assertNotEqual(
                        boot.stable_standby_metadata(metadata),
                        boot.stable_standby_metadata(changed),
                    )

        for changed_row in ("ExitCode", "Output"):
            changed = copy.deepcopy(metadata)
            changed["state"]["Health"]["Log"][0][changed_row] = (
                17 if changed_row == "ExitCode" else "changed"
            )
            self.assertNotEqual(
                boot.stable_standby_metadata(metadata),
                boot.stable_standby_metadata(changed),
            )
        malformed = copy.deepcopy(metadata)
        malformed["state"]["Health"]["Log"][0]["Output"] = "x" * 4097
        with self.assertRaisesRegex(
            epoch.Rejected, "BOOT_STANDBY_HEALTH_LOG_SHAPE_CONFLICT"
        ):
            boot.stable_standby_metadata(malformed)

    def test_reviewed_r3_failure_requires_exact_claim_status_and_operator_hashes(self):
        for kwargs in (
            {"claim": "0" * 64},
            {"failed_status_sha": "0" * 64},
            {"operator_sha": "0" * 64},
        ):
            with (
                self.subTest(kwargs=kwargs),
                self.assertRaisesRegex(
                    epoch.Rejected, "EXACT_REVIEWED_R3_FAILURE_EVIDENCE_REQUIRED"
                ),
            ):
                self._attempt_reviewed_r3_admission(**kwargs)

    def test_reviewed_r3_failure_rejects_a_mismatched_failure_sha(self):
        with self.assertRaisesRegex(
            epoch.Rejected, "EXACT_REVIEWED_R3_FAILURE_EVIDENCE_REQUIRED"
        ):
            self._attempt_reviewed_r3_admission(failure_sha="0" * 64)

    def test_reviewed_r3_standby_views_prove_only_health_timestamp_churn(self):
        def view(minute: str, *, output: str = "ready"):
            return {
                "id": boot.STANDBY_ID,
                "name": "/" + boot.STANDBY_NAME,
                "image": "sha256:fixture",
                "state": {
                    "Status": "running",
                    "Health": {
                        "Status": "healthy",
                        "FailingStreak": 0,
                        "Log": [
                            {
                                "Start": f"2026-10-12T01:{minute}:00.000000000Z",
                                "End": f"2026-10-12T01:{minute}:01.000000000Z",
                                "ExitCode": 0,
                                "Output": output,
                            }
                        ],
                    },
                    "ExitCode": 0,
                    "Running": True,
                },
                "labels": {},
                "mounts": [
                    {"Destination": "/data", "Source": "data", "RW": True},
                    {"Destination": "/config", "Source": "config", "RW": False},
                ],
                "network": "shadow-net",
                "networks": {"shadow-net": {}},
                "privileged": False,
                "ports": {},
                "memory": 0,
                "swap": 0,
                "cpus": 0,
                "readonly": False,
                "caps": None,
            }

        first = view("00")
        second = view("10")
        read_paths = []

        def read_view(path, **_kwargs):
            read_paths.append(Path(path).name)
            return first if Path(path).name == "cli-010.stdout" else second

        with mock.patch.object(
            recovery.boot,
            "read_json",
            side_effect=read_view,
        ):
            evidence = (
                recovery.ReviewedR3SupplementController.reviewed_r3_standby_views()
            )
        self.assertEqual(read_paths, ["cli-010.stdout", "cli-190.stdout"])
        self.assertEqual(evidence["cli010"], evidence["cli190"])

        mount_only = view("00")
        mount_only["mounts"].reverse()
        with (
            mock.patch.object(
                recovery.boot,
                "read_json",
                side_effect=lambda path, **_kwargs: (
                    first if Path(path).name == "cli-010.stdout" else mount_only
                ),
            ),
            self.assertRaisesRegex(
                epoch.Rejected, "R3_STANDBY_REFUSAL_CLOCK_CHANGE_NOT_OBSERVED"
            ),
        ):
            recovery.ReviewedR3SupplementController.reviewed_r3_standby_views()

        for mutation in (
            lambda v: v["state"]["Health"]["Log"][0].update(ExitCode=1),
            lambda v: v["state"]["Health"]["Log"][0].update(Output="changed"),
            lambda v: v["mounts"].append({"Destination": "/other", "Source": "x"}),
            lambda v: v.update(id="f" * 64),
            lambda v: v["state"]["Health"]["Log"][0].update(Start="not-a-timestamp"),
        ):
            changed = view("10")
            mutation(changed)

            def read_changed(path, changed_view=changed, **_kwargs):
                return first if Path(path).name == "cli-010.stdout" else changed_view

            with (
                mock.patch.object(
                    recovery.boot,
                    "read_json",
                    side_effect=read_changed,
                ),
                self.assertRaises(epoch.Rejected),
            ):
                recovery.ReviewedR3SupplementController.reviewed_r3_standby_views()

    def test_reviewed_r3_admission_rechecks_exact_source_and_r2_hashes(self):
        accepted = self._attempt_reviewed_r3_admission()
        self.assertEqual(
            accepted["failure_cause"],
            "VERIFIED_PASSIVE_HEALTH_TIMESTAMP_GUARD_REFUSAL",
        )
        self.assertEqual(accepted["failure_json_sha256"], recovery.R3_FAILURE_SHA256)
        self.assertEqual(
            accepted["failed_status_sha256"], recovery.R3_FAILED_STATUS_SHA256
        )
        self.assertEqual(
            accepted["operator_zip_sha256"], recovery.R3_OPERATOR_ZIP_SHA256
        )
        for kwargs in (
            {"source": "a" * 40},
            {"r2_status": "0" * 64},
            {"receipt": "0" * 64},
            {"latch_changes": {"run": "wrong-run"}},
        ):
            with (
                self.subTest(kwargs=kwargs),
                self.assertRaisesRegex(
                    epoch.Rejected, "EXACT_REVIEWED_R3_FAILURE_EVIDENCE_REQUIRED"
                ),
            ):
                self._attempt_reviewed_r3_admission(**kwargs)

    def test_reviewed_r3_failure_requires_exact_stopped_container_id(self):
        controller = recovery.ReviewedR3SupplementController.__new__(
            recovery.ReviewedR3SupplementController
        )
        controller.inspect_container = mock.Mock(
            return_value={"id": "f" * 64, "state": {"Status": "exited"}}
        )
        with self.assertRaisesRegex(epoch.Rejected, "EXACT_STOPPED_FAILED_R3"):
            controller.additional_preserved_resources()

    def test_reviewed_r3_failure_requires_exact_exit_137(self):
        controller = recovery.ReviewedR3SupplementController.__new__(
            recovery.ReviewedR3SupplementController
        )
        controller.inspect_container = mock.Mock(
            return_value={
                "id": recovery.R3_CONTAINER_ID,
                "state": {"Status": "exited", "ExitCode": 0},
            }
        )
        with self.assertRaisesRegex(epoch.Rejected, "EXACT_STOPPED_FAILED_R3"):
            controller.additional_preserved_resources()

    def _assert_restore_suffix_allowed(self, suffix: str):
        config = {
            "owner": boot.OWNER,
            "database": "kairos_epoch_" + boot.OWNER[:12],
            "pg_host": "kairos-epoch-" + boot.OWNER[:12] + "-pg",
            "redis_host": "kairos-epoch-" + boot.OWNER[:12] + "-redis",
            "admin_password": "a" * 64,
            "restore_host": "kairos-epoch-" + boot.OWNER[:12] + "-restore-" + suffix,
            "restore_database": "kairos_recovery_" + boot.OWNER[:12] + "_epochrestore",
            "restore_admin_password": "b" * 64,
            "expected_seed": worker_seed(),
        }
        epoch.validate_worker_config(config, mode="boot-verify-restore")
        worker.validate_config(config, "boot-verify-restore")
        for mutation in (
            {"owner": "f" * 32},
            {"restore_host": config["restore_host"].replace(suffix, "arbitrary")},
        ):
            bad = {**config, **mutation}
            with self.subTest(mutation=mutation), self.assertRaises(epoch.Rejected):
                epoch.validate_worker_config(bad, mode="boot-verify-restore")
            with (
                self.subTest(worker_mutation=mutation),
                self.assertRaises(worker.EpochError),
            ):
                worker.validate_config(bad, "boot-verify-restore")

    def _flow(
        self,
        root: Path,
        *,
        controller_class=recovery.CleanQueueController,
        audit_rows=recovery.BASE_AUDIT_ROWS,
        queue_rows=recovery.BASE_QUEUE_ROWS,
    ):
        controller = controller_class.__new__(controller_class)
        names = epoch.resource_names(boot.OWNER)
        controller.names = {
            **names,
            "restore_pg": names["restore_pg"] + controller_class.restore_suffix,
            "restore_volume": names["restore_volume"] + controller_class.restore_suffix,
        }
        controller.expected_revision = "a" * 40
        controller.proofs = {}
        controller.work = root
        controller.deadline = 100
        calls = []
        resources = {
            "legacy": {"state": "stopped", "proof": "legacy"},
            "views": {
                key: {
                    "id": identifier,
                    "state": {"Status": "exited" if key == "serve" else "running"},
                }
                for key, identifier in boot.CONTAINERS.items()
            },
        }
        resources["views"]["r1"] = {
            "id": recovery.R1_ID,
            "state": {"Status": "exited"},
        }
        resources["views"]["standby"] = {
            "id": boot.STANDBY_ID,
            "mounts": [],
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
        }
        resources["views"]["r3"] = {
            "id": recovery.R3_CONTAINER_ID,
            "state": {"Status": "exited", "ExitCode": 137},
        }
        observed_views = copy.deepcopy(resources["views"])
        controller._observed_views = observed_views

        def inspect(identifier):
            if identifier == recovery.R1_NAME:
                return copy.deepcopy(observed_views["r1"])
            if identifier == boot.STANDBY_NAME:
                return copy.deepcopy(observed_views["standby"])
            if identifier == recovery.R3_NAME:
                return copy.deepcopy(observed_views["r3"])
            return copy.deepcopy(
                next(
                    view for view in observed_views.values() if view["id"] == identifier
                )
            )

        controller.validate_resources = mock.Mock(return_value=resources)
        controller.inspect_container = mock.Mock(side_effect=inspect)
        controller.assert_legacy_sources_stopped = mock.Mock(
            return_value=resources["legacy"]
        )
        controller.load_private_inputs = mock.Mock(return_value=serving_config())
        controller.prepare_reviewed_snapshots = mock.Mock(
            side_effect=lambda: calls.append("snapshots")
        )
        controller._admin_password = "a" * 64
        controller._history_password = "b" * 64
        controller.boot_state = mock.Mock(
            side_effect=lambda _tag: copy.deepcopy(
                clean_state(audit=audit_rows, queue_rows=queue_rows)
            )
        )
        controller.phase = mock.Mock(
            side_effect=lambda mode, _config, **_kwargs: (
                calls.append("phase-" + mode)
                or {"state": "PASS_BOOT_REDIS_STATE", "outbox_rows": queue_rows}
            )
        )
        controller.prepare_boot_restore_volume = mock.Mock(
            side_effect=lambda tag: calls.append("volume-" + tag)
        )
        controller.backup_and_verify = mock.Mock(
            side_effect=lambda **kwargs: (
                calls.append("restore-" + kwargs["tag"])
                or ("d" if kwargs["tag"] == "bootbefore" else "e") * 64
            )
        )
        controller.audit_only_tail = mock.Mock(
            side_effect=lambda baseline, suffix: (
                calls.append("audit-" + suffix),
                copy.deepcopy(baseline),
                {"state": "AUDIT_ONLY_CATCHUP_COMPLETE", "trading_started": False},
            )[1:]
        )
        controller.start_new_generation = mock.Mock(
            side_effect=lambda _serving: (
                calls.append("start-" + controller_class.generation_label)
                or {"name": controller_class.generation_name}
            )
        )
        patches = (
            mock.patch.object(
                recovery,
                "admitted_failure",
                return_value={
                    "failed_status_sha256": recovery.FAILED_STATUS_SHA256,
                    "accepted_r2_receipt_sha256": recovery.ACCEPTED_RECEIPT_SHA256,
                    "failure_cause": "UNCONFIRMED_GENERIC_TIMEOUT",
                },
            ),
            mock.patch.object(
                recovery.incident, "preserved_inputs", return_value={"fixture": "same"}
            ),
            mock.patch.object(
                recovery.fresh,
                "sha",
                side_effect=lambda path: (
                    recovery.ACCEPTED_RECEIPT_SHA256
                    if Path(path).name == boot.RECEIPT_NAME
                    else controller_class.failed_status_sha256
                ),
            ),
            mock.patch.object(
                recovery,
                "preserved_native_evidence",
                return_value={"fixture": "same"},
            ),
        )
        if controller_class is recovery.ReviewedR3SupplementController:
            controller.reviewed_failure_claim = recovery.R3_FAILURE_SHA256
            controller.admission_evidence = mock.Mock(
                return_value={
                    "failed_status_sha256": recovery.R3_FAILED_STATUS_SHA256,
                    "accepted_r2_receipt_sha256": recovery.ACCEPTED_RECEIPT_SHA256,
                    "failure_cause": "UNCONFIRMED_R3_FAILURE",
                }
            )
            controller.preserved_recovery_evidence = mock.Mock(
                return_value={"r1_r2_r3": "same"}
            )
        return controller, calls, patches

    def test_clean_full_path_uses_two_restores_and_no_queue_mutation_phase(self):
        with TemporaryDirectory() as directory:
            controller, calls, patches = self._flow(Path(directory))
            with patches[0], patches[1], patches[2], patches[3]:
                result = controller.run_clean_recovery()
        self.assertEqual(result["result"], "PASS_NEW_NONTRADING_GENERATION")
        self.assertFalse(result["trading_started"])
        self.assertFalse(result["LIVE_READY"])
        self.assertEqual(calls.count("restore-bootbefore"), 1)
        self.assertEqual(calls.count("restore-bootafter"), 1)
        self.assertEqual(calls.count("start-r3"), 1)
        self.assertNotIn("phase-incident-drain", calls)
        self.assertEqual(calls.count("phase-boot-redis-state"), 2)
        self.assertLess(
            calls.index("restore-bootbefore"), calls.index("audit-clean-r3-initial")
        )
        self.assertLess(calls.index("restore-bootafter"), calls.index("start-r3"))
        self.assertEqual(
            controller.names["restore_pg"],
            "kairos-epoch-69893dc7b7c6-restore-transport03",
        )
        self.assertEqual(
            controller.names["restore_volume"],
            "kairos-epoch-69893dc7b7c6-restore-data-transport03",
        )

    def test_reviewed_r3_supplement_uses_clean_baseline_transport04_and_r4_only(self):
        with TemporaryDirectory() as directory:
            controller, calls, patches = self._flow(
                Path(directory),
                controller_class=recovery.ReviewedR3SupplementController,
                audit_rows=recovery.R4_BASE_AUDIT_ROWS,
                queue_rows=recovery.R4_BASE_QUEUE_ROWS,
            )
            with patches[0], patches[1], patches[2], patches[3]:
                result = controller.run_clean_recovery()
        self.assertEqual(result["result"], "PASS_NEW_NONTRADING_GENERATION")
        self.assertEqual(result["generation"]["name"], recovery.R4_NAME)
        self.assertFalse(result["trading_started"])
        self.assertEqual(calls.count("restore-bootbefore"), 1)
        self.assertEqual(calls.count("restore-bootafter"), 1)
        self.assertEqual(calls.count("start-r4"), 1)
        self.assertNotIn("start-r3", calls)
        self.assertNotIn("phase-incident-drain", calls)
        self.assertEqual(
            controller.names["restore_pg"],
            "kairos-epoch-69893dc7b7c6-restore-transport04",
        )
        self.assertEqual(
            controller.names["restore_volume"],
            "kairos-epoch-69893dc7b7c6-restore-data-transport04",
        )

    def test_reviewed_r3_supplement_dirty_queue_blocks_before_restore_or_r4(self):
        with TemporaryDirectory() as directory:
            controller, _calls, patches = self._flow(
                Path(directory),
                controller_class=recovery.ReviewedR3SupplementController,
                audit_rows=recovery.R4_BASE_AUDIT_ROWS,
                queue_rows=recovery.R4_BASE_QUEUE_ROWS,
            )
            controller.boot_state.side_effect = None
            controller.boot_state.return_value = clean_state(
                pending=1,
                audit=recovery.R4_BASE_AUDIT_ROWS,
                queue_rows=recovery.R4_BASE_QUEUE_ROWS,
            )
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                self.assertRaisesRegex(epoch.Rejected, "EXACT_CLEAN_QUEUE"),
            ):
                controller.run_clean_recovery()
        controller.backup_and_verify.assert_not_called()
        controller.start_new_generation.assert_not_called()

    def test_dirty_queue_blocks_before_redis_restore_catchup_or_generation(self):
        with TemporaryDirectory() as directory:
            controller, calls, patches = self._flow(Path(directory))
            controller.boot_state.side_effect = None
            controller.boot_state.return_value = clean_state(pending=1)
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                self.assertRaisesRegex(epoch.Rejected, "EXACT_CLEAN_QUEUE"),
            ):
                controller.run_clean_recovery()
        self.assertNotIn("phase-boot-redis-state", calls)
        controller.prepare_boot_restore_volume.assert_not_called()
        controller.backup_and_verify.assert_not_called()
        controller.start_new_generation.assert_not_called()

    def test_state_change_after_first_restore_blocks_catchup_and_generation(self):
        with TemporaryDirectory() as directory:
            controller, calls, patches = self._flow(Path(directory))
            changed = clean_state(audit=recovery.BASE_AUDIT_ROWS + 1)
            controller.boot_state.side_effect = [clean_state(), changed]
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                self.assertRaisesRegex(epoch.Rejected, "STATE_CHANGED_DURING_BACKUP"),
            ):
                controller.run_clean_recovery()
        self.assertNotIn("audit-clean-r3-initial", calls)
        controller.start_new_generation.assert_not_called()

    def test_wrong_original_serve_state_blocks_before_private_inputs(self):
        with TemporaryDirectory() as directory:
            controller, _calls, patches = self._flow(Path(directory))
            controller.validate_resources.return_value["views"]["serve"]["state"][
                "Status"
            ] = "running"
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                self.assertRaisesRegex(epoch.Rejected, "R2_FAILED_SERVE"),
            ):
                controller.run_clean_recovery()
        controller.load_private_inputs.assert_not_called()
        controller.phase.assert_not_called()

    def test_r2_resource_id_or_failure_state_change_after_start_blocks_receipt(self):
        with TemporaryDirectory() as directory:
            controller, calls, patches = self._flow(Path(directory))

            def start(_serving):
                calls.append("start-r3")
                controller._observed_views["serve"]["state"]["Status"] = "running"
                return {"name": recovery.R3_NAME}

            controller.start_new_generation.side_effect = start
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                self.assertRaisesRegex(
                    epoch.Rejected, "R2_RESOURCE_METADATA_OR_FAILURE_STATE_CHANGED"
                ),
            ):
                controller.run_clean_recovery()
        self.assertEqual(calls.count("start-r3"), 1)
        self.assertNotIn("incident-drain", calls)

    def test_original_failure_and_inputs_must_remain_unchanged_after_start(self):
        with TemporaryDirectory() as directory:
            controller, _calls, patches = self._flow(Path(directory))
            patches = list(patches)
            patches[1] = mock.patch.object(
                recovery.incident,
                "preserved_inputs",
                side_effect=[{"fixture": "before"}, {"fixture": "changed"}],
            )
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                self.assertRaisesRegex(
                    epoch.Rejected, "R2_FAILURE_OR_ACCEPTED_INPUTS_CHANGED"
                ),
            ):
                controller.run_clean_recovery()
        controller.start_new_generation.assert_called_once()

    def test_original_r1_and_standby_full_metadata_must_remain_unchanged(self):
        for resource in ("r1", "standby"):
            with TemporaryDirectory() as directory:
                controller, _calls, patches = self._flow(Path(directory))

                def start(_serving, _controller=controller, _resource=resource):
                    _controller._observed_views[_resource]["labels"] = {
                        "changed": "true"
                    }
                    return {"name": recovery.R3_NAME}

                controller.start_new_generation.side_effect = start
                with (
                    self.subTest(resource=resource),
                    patches[0],
                    patches[1],
                    patches[2],
                    patches[3],
                    self.assertRaisesRegex(
                        epoch.Rejected, "ORIGINAL_R1_OR_STANDBY_METADATA_CHANGED"
                    ),
                ):
                    controller.run_clean_recovery()


if __name__ == "__main__":
    unittest.main()
