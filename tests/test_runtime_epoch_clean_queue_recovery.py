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


def clean_state(*, pending: int = 0, audit: int = recovery.BASE_AUDIT_ROWS) -> dict:
    return {
        "state": "PASS_BOOT_STATE",
        "matched_public_tables": len(worker.CONTROLLED_RUNTIME_PUBLIC_TABLES),
        "tables": {
            table: {
                "count": (
                    audit
                    if table == "event_audit"
                    else recovery.BASE_QUEUE_ROWS
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
            "outbox_rows": recovery.BASE_QUEUE_ROWS,
            "inbox_rows": recovery.BASE_QUEUE_ROWS,
            "completed_inbox": recovery.BASE_QUEUE_ROWS,
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

    def test_restore_transport03_is_exact_owner_only(self):
        config = {
            "owner": boot.OWNER,
            "database": "kairos_epoch_" + boot.OWNER[:12],
            "pg_host": "kairos-epoch-" + boot.OWNER[:12] + "-pg",
            "redis_host": "kairos-epoch-" + boot.OWNER[:12] + "-redis",
            "admin_password": "a" * 64,
            "restore_host": "kairos-epoch-" + boot.OWNER[:12] + "-restore-transport03",
            "restore_database": "kairos_recovery_" + boot.OWNER[:12] + "_epochrestore",
            "restore_admin_password": "b" * 64,
            "expected_seed": worker_seed(),
        }
        epoch.validate_worker_config(config, mode="boot-verify-restore")
        worker.validate_config(config, "boot-verify-restore")
        for mutation in (
            {"owner": "f" * 32},
            {
                "restore_host": config["restore_host"].replace(
                    "transport03", "arbitrary"
                )
            },
        ):
            bad = {**config, **mutation}
            with self.subTest(mutation=mutation), self.assertRaises(epoch.Rejected):
                epoch.validate_worker_config(bad, mode="boot-verify-restore")
            with (
                self.subTest(worker_mutation=mutation),
                self.assertRaises(worker.EpochError),
            ):
                worker.validate_config(bad, "boot-verify-restore")

    def _flow(self, root: Path):
        controller = recovery.CleanQueueController.__new__(
            recovery.CleanQueueController
        )
        names = epoch.resource_names(boot.OWNER)
        controller.names = {
            **names,
            "restore_pg": names["restore_pg"] + "-transport03",
            "restore_volume": names["restore_volume"] + "-transport03",
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
            "state": {"Status": "running"},
        }
        observed_views = copy.deepcopy(resources["views"])
        controller._observed_views = observed_views

        def inspect(identifier):
            if identifier == recovery.R1_NAME:
                return copy.deepcopy(observed_views["r1"])
            if identifier == boot.STANDBY_NAME:
                return copy.deepcopy(observed_views["standby"])
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
            side_effect=lambda _tag: copy.deepcopy(clean_state())
        )
        controller.phase = mock.Mock(
            side_effect=lambda mode, _config, **_kwargs: (
                calls.append("phase-" + mode)
                or {"state": "PASS_BOOT_REDIS_STATE", "outbox_rows": 4626}
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
                calls.append("start-r3") or {"name": recovery.R3_NAME}
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
                    else recovery.FAILED_STATUS_SHA256
                ),
            ),
            mock.patch.object(
                recovery,
                "preserved_native_evidence",
                return_value={"fixture": "same"},
            ),
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
